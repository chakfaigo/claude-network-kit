"""Root-owned supervisor. PF stays installed when this process/core exits."""
from pathlib import Path
import importlib.util
import fcntl
import hashlib
import ipaddress
import json
import math
import os
import re
import signal
import stat
import subprocess
import tempfile
import time

ROOT = Path('/Library/Application Support/ClaudeResidential')
PRIVATE = ROOT / 'private'
STATUS = ROOT / 'public/status.json'
PF = '/sbin/pfctl'
LABEL = 'local.claude.residential'
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/var/root', 'LANG': 'C', 'LC_ALL': 'C'}
PROBE_METRICS = '\nGUARD_METRICS %{http_code} %{http_connect} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total}'
PROBE_LOG_LIMIT = 1024 * 1024


def trusted(path, directory=False):
    s = path.lstat()
    if s.st_uid != 0 or s.st_mode & 0o022 or stat.S_ISLNK(s.st_mode):
        raise RuntimeError('服务文件权限不安全：' + path.name)
    if (directory and not stat.S_ISDIR(s.st_mode)) or (not directory and not stat.S_ISREG(s.st_mode)):
        raise RuntimeError('服务文件类型错误：' + path.name)


def module(name):
    path = ROOT / (name + '.py')
    trusted(ROOT, True)
    trusted(path)
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


def atomic_json(path, value, mode=0o600):
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=False, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def command(args, check=True, timeout=20):
    result = subprocess.run([str(x) for x in args], capture_output=True, text=True,
                            env=ENV, timeout=timeout)
    if check and result.returncode:
        # Never echo command arguments/output: they may include sensitive data.
        raise RuntimeError(Path(str(args[0])).name + ' 操作未成功')
    return result


def pf_enabled():
    return re.search(r'^Status:\s+Enabled\b', command([PF, '-s', 'info']).stdout, re.M) is not None


def no_interface_skip():
    text = command([PF, '-s', 'Interfaces', '-v']).stdout
    for line in text.splitlines():
        if 'skip' in line.lower() and not re.match(r'^\s*lo0(?:\s|$)', line):
            raise RuntimeError('物理接口存在 PF skip，保持封锁')


def anchor_digest(pfmod):
    active = command([PF, '-a', pfmod.ANCHOR_NAME, '-sr']).stdout.strip()
    if not active or not re.search(r'^block drop out quick all', active, re.M):
        raise RuntimeError('PF 阻断规则未加载')
    return hashlib.sha256(active.encode()).hexdigest()


def guard_ok(pfmod):
    try:
        if not pf_enabled():
            return False
        pfmod.validate_runtime_main_filter(command([PF, '-sr']).stdout)
        no_interface_skip()
        return anchor_digest(pfmod) == json.loads((PRIVATE / 'pf-active.json').read_text())['digest']
    except Exception:
        return False


def ensure_pf(pfmod, initial=False):
    # Installer and live supervisor share PF rules, tokens and pending-state files.
    # Serialize the whole transaction, including failures and state-cache updates.
    lock = os.open(PRIVATE / 'pf.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _ensure_pf_locked(pfmod, initial)
    finally:
        os.close(lock)


def _ensure_pf_locked(pfmod, initial=False):
    needs_flush = initial or not guard_ok(pfmod)
    trusted(Path('/etc/pf.conf'))
    trusted(Path(pfmod.ANCHOR_FILE))
    pfmod.validate_pf_conf(Path('/etc/pf.conf').read_text())
    pfmod.validate_anchor(Path(pfmod.ANCHOR_FILE).read_text())
    if needs_flush:
        # Do not let an interrupted/failed flush look healthy on the next retry.
        atomic_json(PRIVATE / 'pf-active.json', {'digest': None, 'states_pending': True})
    active = command([PF, '-sr']).stdout
    try:
        pfmod.validate_runtime_main_filter(active)
    except ValueError:
        if active.strip():
            pfmod.validate_runtime_main_filter(active, require_guard=False)
        elif pf_enabled():
            raise RuntimeError('PF 已启用但主规则缺失，停止自动接管')
        command([PF, '-f', '/etc/pf.conf'])
    pfmod.validate_runtime_main_filter(command([PF, '-sr']).stdout)
    no_interface_skip()
    # Reload only our anchor; Apple's dynamic subanchors are retained.
    command([PF, '-a', pfmod.ANCHOR_NAME, '-f', pfmod.ANCHOR_FILE])
    digest = anchor_digest(pfmod)
    references = command([PF, '-s', 'References']).stdout
    token_path = PRIVATE / 'pf-token.json'
    saved = ''
    try:
        cached = json.loads(token_path.read_text())
        value = cached.get('token') if isinstance(cached, dict) else None
        if isinstance(value, str) and re.fullmatch(r'[0-9]+', value):
            saved = value
    except (OSError, ValueError):
        pass  # This is a disposable cache; reacquire our own PF reference.
    if not saved or not re.search(r'(?<![0-9])' + re.escape(saved) + r'(?![0-9])', references):
        result = command([PF, '-E'])
        token = re.search(r'Token\s*:\s*(\d+)', result.stdout + result.stderr)
        if not token:
            raise RuntimeError('PF 启用引用未返回，停止启动代理')
        atomic_json(token_path, {'token': token.group(1)})
    if not pf_enabled():
        raise RuntimeError('PF 未启用，禁止启动代理')
    if needs_flush:
        command([PF, '-F', 'states'])
    atomic_json(PRIVATE / 'pf-active.json', {'digest': digest})


def parse_probe(text):
    matches = re.findall(r'^ip=([^\r\n]+)', text, re.M)
    if len(matches) != 1:
        return None
    try:
        return str(ipaddress.ip_address(matches[0]))
    except ValueError:
        return None


def probe_metrics(output):
    body, marker, tail = output.rpartition('\nGUARD_METRICS ')
    fields = tail.strip().split() if marker else []
    if len(fields) != 6 or not all(re.fullmatch(r'[0-9]{3}', x) for x in fields[:2]):
        return output, {}
    try:
        times = [float(x) for x in fields[2:]]
        if not all(math.isfinite(x) and 0 <= x <= 600 for x in times):
            return output, {}
    except ValueError:
        return output, {}
    return body, dict(zip(('http_status', 'proxy_connect_status', 'local_connect_s',
                          'tls_ready_s', 'first_byte_s', 'total_s'),
                         [int(x) for x in fields[:2]] + times))


def log_probe_round(started, checks):
    # Diagnostic failure must neither authorize access nor interrupt networking.
    # Only fixed labels, exit codes, numeric timings and parsed IPs are retained.
    # Never log curl stdout/stderr, which could contain unrelated response data.
    try:
        path = PRIVATE / 'health-probes.jsonl'
        if path.is_symlink():
            return False
        if path.exists() and path.stat().st_size >= PROBE_LOG_LIMIT:
            os.replace(path, PRIVATE / 'health-probes.previous.jsonl')
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(json.dumps({'supervisor_pid': os.getpid(),
                                     'started_at': started, 'finished_at': time.time(),
                                     'checks': checks}, allow_nan=False) + '\n')
        return True
    except OSError:
        return False


def probe():
    started = time.time()
    results = []
    checks = []
    for label, url in (('ip_trace', 'https://1.1.1.1/cdn-cgi/trace'),
                       ('host_trace', 'https://www.cloudflare.com/cdn-cgi/trace')):
        check = {'target': label, 'started_at': time.time()}
        try:
            r = command(['/usr/bin/curl', '-q', '--silent', '--show-error', '--fail',
                         '--proxy', 'http://127.0.0.1:10808', '--noproxy', '',
                         '-4',
                         '--connect-timeout', '3', '--max-time', '5', '--max-filesize', '8192',
                         '--write-out', PROBE_METRICS, url],
                        check=False, timeout=7)
            body, metrics = probe_metrics(r.stdout)
            result = parse_probe(body) if r.returncode == 0 else None
            results.append(result)
            check.update(metrics, curl_exit=r.returncode, result_ip=result)
        except subprocess.TimeoutExpired:
            results.append(None)
            check['error'] = 'command_timeout'
        except OSError:
            results.append(None)
            check['error'] = 'command_unavailable'
        check['finished_at'] = time.time()
        checks.append(check)
    log_probe_round(started, checks)
    return results


class Supervisor:
    def __init__(self, health, pfmod, bundle, runner=command, probe_fn=probe, popen=subprocess.Popen):
        self.health, self.pfmod, self.bundle = health, pfmod, bundle
        if 'node' in bundle:
            self.health.EXPECTED_IP = bundle['node']['expected_ip']
        self.runner, self.probe_fn, self.popen = runner, probe_fn, popen
        self.child = None
        self.current = None
        self.state = None
        self.intent = None
        self.choice = 'direct'
        self.startup_failures = 0
        self.selecting = False
        self.log = None
        self.ready = False

    def stop(self):
        self.ready = False
        if self.child is not None:
            if self.child.poll() is None:
                self.child.terminate()
                try:
                    self.child.wait(timeout=6)
                except subprocess.TimeoutExpired:
                    self.child.kill()
                    self.child.wait(timeout=3)
            self.child = None
        if self.log is not None:
            self.log.close()
            self.log = None
        self.current = None

    def apply(self, config_name):
        if self.current == config_name and self.ready and self.child is not None and self.child.poll() is None:
            return
        # A failed check cannot leave an old permissive core running.
        self.stop()
        ensure_pf(self.pfmod)
        config = PRIVATE / (config_name + '.json')
        trusted(config)
        if json.loads(config.read_text()) != self.bundle['configs'][config_name]:
            raise RuntimeError('已安装配置被改变，保持封锁')
        self.runner([ROOT / 'sing-box', 'check', '-c', config])
        self.log = open(PRIVATE / 'core.log', 'ab', buffering=0)
        try:
            self.child = self.popen([str(ROOT / 'sing-box'), 'run', '-c', str(config), '--disable-color'],
                                    cwd=str(PRIVATE), env=ENV, stdout=self.log, stderr=subprocess.STDOUT)
            self.wait_ready()
            self.current = config_name
            self.ready = True
        except Exception:
            self.stop()
            raise

    def ready_now(self, timeout=2):
        if self.child is None or self.child.poll() is not None:
            return False
        deadline = time.monotonic() + timeout
        try:
            listeners = self.runner(['/usr/sbin/lsof', '-a', '-p', str(self.child.pid),
                                     '-iTCP:10808', '-sTCP:LISTEN', '-t'],
                                    check=False, timeout=timeout)
            pids = {line.strip() for line in listeners.stdout.splitlines() if line.strip()}
            remaining = deadline - time.monotonic()
            if listeners.returncode == 0 and pids == {str(self.child.pid)} and remaining > 0:
                route = self.runner(['/sbin/route', '-n', 'get', '1.1.1.1'],
                                    check=False, timeout=remaining)
                return (route.returncode == 0
                        and re.search(r'^\s*interface:\s*utun99\s*$', route.stdout, re.M) is not None
                        and self.child.poll() is None)
        except (subprocess.TimeoutExpired, OSError):
            pass
        return False

    def wait_ready(self):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.child is None or self.child.poll() is not None:
                raise RuntimeError('代理核心在就绪前退出')
            if self.ready_now(timeout=min(2, max(0.01, deadline - time.monotonic()))):
                return
            time.sleep(min(0.25, max(0, deadline - time.monotonic())))
        raise RuntimeError('代理核心未在 10 秒内准备好固定监听与 TUN')

    def publish(self, reason=None):
        value = dict(self.state or self.health.decide_health(None, 'home', None))
        expected = 'original' if value['mode'] == 'original' else 'home_' + self.choice + (
            '' if value['phase'] == 'healthy' else '_blocked')
        running = self.ready and self.current == expected and self.child is not None and self.child.poll() is None
        if not running and not reason:
            reason = 'core_not_ready'
        if reason:
            value.update(phase='blocked', policy='home_blocked' if value['mode'] == 'home' else 'original_blocked',
                         reason=reason, successes=0, notice='fault')
        value.update(updated_at=time.time(), request_id=(self.intent or {}).get('id'),
                     core_running=bool(running),
                     route=self.choice)
        atomic_json(STATUS, value, 0o644)

    def read_intent(self):
        path = PRIVATE / 'intent.json'
        trusted(path)
        value = json.loads(path.read_text())
        if set(value) != {'id', 'mode'} or value['mode'] not in ('home', 'original') or not isinstance(value['id'], str):
            raise RuntimeError('模式文件无效')
        return value

    def begin(self, intent):
        self.stop()
        self.intent = intent
        self.choice = 'direct'
        self.selecting = intent['mode'] == 'home'
        self.startup_failures = 0
        selected = PRIVATE / 'selection.json'
        if selected.exists():
            trusted(selected)
            try:
                saved = json.loads(selected.read_text())
                if not isinstance(saved, dict):
                    saved = {}
            except (OSError, ValueError):
                saved = {}
            if saved.get('id') == intent['id'] and saved.get('choice') in (('direct', 'relay', 'original') if self.bundle.get('has_relay', True) else ('direct', 'original')):
                self.choice = saved['choice']
                self.selecting = False
        mode = 'original' if intent['mode'] == 'original' or self.choice == 'original' else 'home'
        self.state = self.health.decide_health(None, mode, [])
        self.apply('original' if mode == 'original' else 'home_' + self.choice + '_blocked')
        self.publish()

    def round(self):
        try:
            self._round()
        except Exception:
            # No failing guard/probe/config path may leave an old open core.
            try:
                self.stop()
            finally:
                mode = self.state['mode'] if self.state else 'home'
                self.state = self.health.decide_health(self.state, mode, None)
                self.publish('monitor_error')
            raise

    def _round(self):
        # Fixed choice is persisted only for this explicit manual request.
        mode = self.state['mode']
        if self.child is None or self.child.poll() is not None:
            self.state = self.health.decide_health(self.state, mode, None)
            self.apply('original' if mode == 'original' else 'home_' + self.choice + '_blocked')
            self.publish('core_restart')
            return
        if not guard_ok(self.pfmod):
            self.stop()
            self.state = self.health.decide_health(self.state, mode, None)
            self.publish('firewall_error')
            ensure_pf(self.pfmod, initial=True)
            return
        if not self.ready_now():
            # Explicit proxy probes can succeed after the TUN route has vanished.
            # Stop before publishing failure; the next round rebuilds a blocked core.
            self.stop()
            self.state = self.health.decide_health(self.state, mode, None)
            self.publish('network_not_ready')
            return
        probes = []
        if mode == 'home':
            started = time.time()
            probes = self.probe_fn()
            elapsed = time.time() - started
            # Two probe commands each have a 7s outer timeout. A round spanning
            # a longer pause (e.g. sleep inside curl) must not authorize opening.
            if elapsed < 0 or elapsed > 15:
                self.resume_home()
                return
        new_state = self.health.decide_health(self.state, mode, probes)
        self.state = new_state
        if self.selecting and mode == 'home':
            if new_state['phase'] == 'healthy':
                self.selecting = False
                atomic_json(PRIVATE / 'selection.json', {'id': self.intent['id'], 'choice': self.choice})
            elif new_state['reason'] in ('unreachable', 'wrong_exit', 'monitor_error'):
                self.startup_failures += 1
                if self.startup_failures >= 2:
                    self.startup_failures = 0
                    self.choice = 'relay' if self.choice == 'direct' and self.bundle.get('has_relay', True) else 'original'
                    self.state = self.health.decide_health(None, 'original' if self.choice == 'original' else 'home', [])
                    if self.choice == 'original':
                        self.selecting = False
                        atomic_json(PRIVATE / 'selection.json', {'id': self.intent['id'], 'choice': 'original'})
        name = 'original' if self.state['mode'] == 'original' else 'home_' + self.choice + (
            '' if self.state['phase'] == 'healthy' else '_blocked')
        self.apply(name)
        self.publish()

    def resume_home(self):
        # Pre-sleep connections and validation progress are no longer evidence
        # of a usable Home path. Retain the chosen route and request identity.
        self.stop()
        self.state = self.health.decide_health(self.state, 'home', [])
        self.state['reason'] = 'starting'
        self.startup_failures = 0
        try:
            self.apply('home_' + self.choice + '_blocked')
        except Exception:
            self.stop()
            self.publish('monitor_error')
            raise
        self.publish()

    def round_interval(self):
        # Only explicit initial selection uses the fast verification cadence.
        # Automatic recovery must remain blocked across a normal check interval
        # before reopening, to avoid rebuilding the core on brief recoveries.
        return 2 if not self.ready or (self.selecting and self.state['reason'] in (
            'starting', 'verifying')) else 20

    def run(self):
        next_round = 0
        idle_since = None
        while True:
            # Wall time includes macOS sleep. Measure only the idle sleep, not
            # synchronous probes/PF/core startup, which may legitimately be slow.
            idle_gap = time.time() - idle_since if idle_since is not None else 0
            intent = self.read_intent()
            if intent != self.intent:
                self.begin(intent)
                next_round = time.monotonic() + 2
            elif abs(idle_gap) >= 10 and self.state['mode'] == 'home':
                self.resume_home()
                next_round = time.monotonic() + 2
            if time.monotonic() >= next_round:
                self.round()
                next_round = time.monotonic() + self.round_interval()
            if self.child is not None and self.child.poll() is not None:
                next_round = 0
            idle_since = time.time()
            time.sleep(1)


def main():
    if os.geteuid() != 0:
        raise RuntimeError('只能由系统服务启动')
    supervisor = None
    try:
        pfmod = module('guard_pf')
        trusted(PRIVATE, True)
        # Establish kernel blocking before reading optional health/config code
        # or any bundle/core data that could be missing or corrupt at boot.
        ensure_pf(pfmod)
        health, configs = module('guard_health'), module('guard_config')
        trusted(PRIVATE / 'bundle.json')
        bundle = json.loads((PRIVATE / 'bundle.json').read_text())
        configs.validate_bundle(bundle)
        for asset in ('sing-box',):
            trusted(ROOT / asset)
        for rule in bundle['configs']['home_direct']['route']['rule_set']:
            trusted(Path(rule['path']))
        supervisor = Supervisor(health, pfmod, bundle)
        def interrupted(signum, frame):
            raise SystemExit(0)
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, interrupted)
        supervisor.run()
    finally:
        if supervisor is not None:
            try:
                supervisor.stop()
            finally:
                supervisor.publish('supervisor_stopped')
        else:
            # Startup can fail before health code is available. Publish a
            # literal blocked status when the public directory is usable.
            try:
                atomic_json(STATUS, {'version': 1, 'mode': 'home', 'phase': 'blocked',
                            'policy': 'home_blocked', 'reason': 'startup_error',
                            'successes': 0, 'event_id': 1, 'notice': 'fault',
                            'updated_at': time.time(), 'core_running': False}, 0o644)
            except Exception:
                pass
        # Deliberately retain PF and its loaded blocking rules on every exit.


if __name__ == '__main__':
    main()
