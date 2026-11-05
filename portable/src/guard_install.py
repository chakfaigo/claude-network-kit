"""Manual privileged installation/switch. Never invoked by tests without mocks."""
from pathlib import Path
import fcntl
import hashlib
import importlib.util
import json
import math
import os
import plistlib
import re
import shutil
import sqlite3
import sys
import tempfile
import time
import uuid

ROOT = Path('/Library/Application Support/ClaudeResidential')
PRIVATE = ROOT / 'private'
PLIST = Path('/Library/LaunchDaemons/local.claude.residential.plist')
PF_CONF = Path('/etc/pf.conf')
LABEL = 'local.claude.residential'
PACKAGE = Path(__file__).resolve().parent
DELIVERY = PACKAGE.parent
PYTHON = ROOT / 'python/bin/python3.12'
RUNTIME_FILES = ('guard_runtime.py', 'guard_config.py', 'guard_health.py', 'guard_pf.py', 'guard_install.py', 'controller.py', 'guard_notify.py')
FLAVOR = 'fresh-mac-upstream-v2'


def load(name):
    spec = importlib.util.spec_from_file_location(name, PACKAGE / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


runtime, config, pf = load('guard_runtime'), load('guard_config'), load('guard_pf')
run = runtime.command


def atomic_bytes(path, content, mode=0o600):
    temp = path.with_name(path.name + '.new')
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temp, mode)
    os.replace(temp, path)


def safe_copy(source, target, mode=0o600):
    if source.is_symlink() or not source.is_file():
        raise RuntimeError('安装源文件类型无效：' + source.name)
    atomic_bytes(target, source.read_bytes(), mode)


def job():
    return {'Label': LABEL,
            'ProgramArguments': [str(PYTHON), '-I', '-B', str(ROOT / 'guard_runtime.py')],
            'WorkingDirectory': str(ROOT), 'UserName': 'root', 'RunAtLoad': True,
            'KeepAlive': True, 'ThrottleInterval': 10, 'Umask': 0o077,
            'StandardOutPath': str(PRIVATE / 'service.log'),
            'StandardErrorPath': str(PRIVATE / 'service.log')}


def backup_directory():
    return PRIVATE / 'before-guard'


def require_portable():
    marker = PRIVATE / 'installed.json'
    runtime.trusted(ROOT, True)
    runtime.trusted(PRIVATE, True)
    runtime.trusted(marker)
    value = json.loads(marker.read_text())
    if value.get('flavor') != FLAVOR:
        raise RuntimeError('此电脑已有其他版本保护，不能用新机安装器覆盖')


def physical_interface():
    # default remains the physical route; auto_route installs more-specific TUN routes.
    result = run(['/sbin/route', '-n', 'get', 'default']).stdout
    found = re.search(r'^\s*interface:\s*([a-zA-Z][\w-]*)\s*$', result, re.M)
    if not found or found.group(1).startswith('utun'):
        raise RuntimeError('无法识别物理网络接口；保持现有连接')
    return found.group(1)


def stage_payload(stage, node, interface):
    for asset in ('sing-box', 'geosite-cn.srs', 'geoip-cn.srs'):
        safe_copy(DELIVERY / 'assets' / asset, stage / asset, 0o755 if asset == 'sing-box' else 0o600)
    bundle = config.build_bundle(node, interface, str(stage))
    config.validate_bundle(bundle)
    for name, document in bundle['configs'].items():
        runtime.atomic_json(stage / (name + '.json'), document)
        run([stage / 'sing-box', 'check', '-c', stage / (name + '.json')])
    return config.build_bundle(node, interface, str(PRIVATE))


def precheck_pf():
    original = PF_CONF.read_text()
    prepared = pf.prepare_pf_conf(original)
    live = run(['/sbin/pfctl', '-sr']).stdout
    if live.strip():
        pf.validate_runtime_main_filter(live, require_guard=pf.ANCHOR_NAME in live)
    elif runtime.pf_enabled():
        raise RuntimeError('PF 已启用但主规则未知，保持现有连接')
    runtime.no_interface_skip()
    return original, prepared


def listener_pids():
    result = run(['/usr/sbin/lsof', '-t', '-nP', '-iTCP:10808', '-sTCP:LISTEN'], check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError('无法识别10808的TCP监听者，保持当前连接')
    values = result.stdout.split()
    if any(not item.isdigit() for item in values):
        raise RuntimeError('10808监听者输出无法识别，保持当前连接')
    pids = {int(item) for item in values}
    result = run(['/usr/sbin/lsof', '-nP', '-F', 'pn', '-iUDP:10808'], check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError('无法识别10808的UDP绑定，保持当前连接')
    pid = None
    for line in result.stdout.splitlines():
        if line.startswith('p') and line[1:].isdigit():
            pid = int(line[1:])
        elif line.startswith('n') and pid is not None:
            local = line[1:].split('->', 1)[0]
            if re.search(r':10808$', local):
                pids.add(pid)
    return pids


def save_install_backup(original_pf, state, destination=None):
    saved = (destination if destination is not None else PRIVATE) / 'before-guard'
    if saved.exists():
        raise RuntimeError('已有原网络备份，不能当全新安装覆盖')
    with tempfile.TemporaryDirectory(prefix='.backup-stage-', dir=saved.parent) as folder:
        stage = Path(folder)
        atomic_bytes(stage / 'pf.conf', original_pf.encode())
        runtime.atomic_json(stage / 'network.json', state)
        files = {x.name: hashlib.sha256(x.read_bytes()).hexdigest() for x in stage.iterdir()}
        runtime.atomic_json(stage / 'manifest.json', {'version': 1, 'files': files})
        os.replace(stage, saved)


def snapshot_network():
    services = []
    names = run(['/usr/sbin/networksetup', '-listallnetworkservices']).stdout.splitlines()[1:]
    for name in names:
        if name.startswith('*'): continue
        item = {'name': name}
        for key in ('webproxy','securewebproxy','socksfirewallproxy','autoproxyurl','proxyautodiscovery','dnsservers','info','proxybypassdomains'):
            item[key] = run(['/usr/sbin/networksetup', '-get' + key, name]).stdout
        if any(re.search(r'^(?:Enabled: Yes|Auto Proxy Discovery: On)', item[k], re.M) for k in ('webproxy','securewebproxy','socksfirewallproxy','autoproxyurl','proxyautodiscovery')):
            raise RuntimeError('检测到已有代理设置；新机版不会覆盖，请先核对')
        if re.search(r'^IPv6: Manual', item['info'], re.M):
            raise RuntimeError('IPv6已有手工配置；新机版不会覆盖')
        services.append(item)
    if not services or not any(re.search(r'^IP address: (?!none|0\.0\.0\.0)\d+\.', x['info'], re.M) for x in services): raise RuntimeError('没有可备份的活动网络服务')
    return {'version': 1, 'services': services}


def start_service():
    run(['/bin/launchctl', 'enable', 'system/' + LABEL])
    status = run(['/bin/launchctl', 'print', 'system/' + LABEL], check=False)
    if status.returncode:
        run(['/bin/launchctl', 'bootstrap', 'system', PLIST])


def network_settings(state):
    active = [x['name'] for x in state['services'] if re.search(r'^IP address: (?!none|0\.0\.0\.0)\d+\.', x['info'], re.M)]
    if not active: raise RuntimeError('没有活动网络服务，未修改设置')
    for name in active:
        run(['/usr/sbin/networksetup', '-setv6off', name])
        run(['/usr/sbin/networksetup', '-setdnsservers', name, '1.1.1.1', '8.8.8.8'])


def switch(mode):
    if os.geteuid() != 0 or mode not in ('home','original'):
        raise RuntimeError('切换需管理员授权')
    require_portable()
    lock = os.open(PRIVATE / 'install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        runtime.trusted(PRIVATE / 'bundle.json')
        config.validate_bundle(json.loads((PRIVATE / 'bundle.json').read_text()))
        if not runtime.guard_ok(pf):
            original, prepared = precheck_pf()
            atomic_bytes(Path(pf.ANCHOR_FILE),pf.render_anchor().encode(),0o600)
            atomic_bytes(PF_CONF,prepared.encode(),0o644)
            runtime.ensure_pf(pf)
        if not PLIST.exists(): atomic_bytes(PLIST,plistlib.dumps(job()),0o644)
        request_id = uuid.uuid4().hex
        runtime.atomic_json(PRIVATE / 'intent.json', {'id':request_id,'mode':mode})
        start_service()
        network_settings(snapshot_network())
        return {'request_id':request_id,'mode':mode}
    finally: os.close(lock)


def copy_runtime(destination=None):
    source = DELIVERY / 'python'
    if source.is_symlink() or not source.is_dir(): raise RuntimeError('缺少自带运行环境')
    target = (destination if destination is not None else ROOT) / 'python'
    shutil.copytree(source, target, symlinks=True)
    for folder, dirs, files in os.walk(target):
        os.chmod(folder, 0o755)
        for name in files:
            file = Path(folder) / name
            if file.is_symlink():
                if target.resolve() not in file.resolve().parents: raise RuntimeError('运行环境链接越界')
                continue
            file.chmod(0o755 if os.access(file, os.X_OK) else 0o644)
    runtime.trusted(target / 'bin/python3.12')


def install(node_path, initial_route=None):
    if os.geteuid() != 0: raise RuntimeError('安装需管理员授权')
    os.umask(0o077)
    if ROOT.exists() or ROOT.is_symlink() or PLIST.exists():
        raise RuntimeError('此电脑已有保护目录或服务，不能用全新安装覆盖；已有便携版请运行Home/Origin入口')
    node_path = Path(node_path)
    if node_path.is_symlink() or not node_path.is_file(): raise RuntimeError('节点文件无效')
    node = config.validate_node(json.loads(node_path.read_text()))
    if initial_route not in (None, 'direct', 'relay') or (initial_route == 'relay' and 'upstream' not in node):
        raise RuntimeError('安装选路参数无效，未修改网络')
    interface = physical_interface()
    state = snapshot_network()
    original_pf, prepared_pf = precheck_pf()
    if listener_pids(): raise RuntimeError('10808端口被占用，未修改网络')
    if run(['/sbin/ifconfig','utun99'], check=False).returncode == 0:
        raise RuntimeError('utun99已存在，未修改网络')
    # Complete config/parser checks before creating the system install directory.
    with tempfile.TemporaryDirectory(prefix='home-stage-') as folder:
        stage = Path(folder)
        bundle = stage_payload(stage, node, interface)
        config.validate_bundle(bundle)
        atomic_bytes(stage / 'anchor', pf.render_anchor().encode())
        atomic_bytes(stage / 'pf.conf', prepared_pf.replace(pf.ANCHOR_FILE,str(stage / 'anchor')).encode())
        run(['/sbin/pfctl','-n','-f',stage / 'pf.conf'])
        atomic_bytes(stage / 'job.plist', plistlib.dumps(job()))
        run(['/usr/bin/plutil','-lint',stage / 'job.plist'])
        with tempfile.TemporaryDirectory(prefix='.home-install-', dir=ROOT.parent) as ready_folder:
            ready = Path(ready_folder) / 'prepared'
            ready.mkdir(mode=0o755)
            ready.chmod(0o755)
            (ready / 'private').mkdir(mode=0o700)
            runtime.trusted(ready,True);runtime.trusted(ready / 'private',True)
            save_install_backup(original_pf, state, ready / 'private')
            # All required disk payloads are installed before establishing blocking.
            copy_runtime(ready)
            menu_source = DELIVERY / 'menu/build/家宽状态.app'
            run(['/usr/bin/codesign','--verify','--strict',menu_source])
            shutil.copytree(menu_source, ready / 'Home状态.app')
            for name, mode in [('Home.command','home'),('Origin.command','original'),('导出诊断.command','diagnostics')]:
                text = '#!/bin/zsh\n' + '"/Library/Application Support/ClaudeResidential/python/bin/python3.12" -I -B "/Library/Application Support/ClaudeResidential/controller.py" ' + mode + '\nresult=$?\nprint \"按回车关闭窗口。\"\nread -r\nexit \"$result\"\n'
                atomic_bytes(ready / name, text.encode(), 0o755)
            for name in RUNTIME_FILES: safe_copy(PACKAGE / name, ready / name, 0o644)
            safe_copy(stage / 'sing-box', ready / 'sing-box', 0o755)
            for name in ('geosite-cn.srs','geoip-cn.srs'): safe_copy(stage / name, ready / 'private' / name)
            runtime.atomic_json(ready / 'private' / 'bundle.json', bundle)
            for name, document in bundle['configs'].items(): runtime.atomic_json(ready / 'private' / (name+'.json'),document)
            (ready / 'public').mkdir(mode=0o755)
            (ready / 'public').chmod(0o755)
            
            request_id=uuid.uuid4().hex
            runtime.atomic_json(ready / 'private' / 'intent.json',{'id':request_id,'mode':'home'})
            if initial_route is not None:
                runtime.atomic_json(ready / 'private' / 'selection.json',{'id':request_id,'choice':initial_route})
            runtime.atomic_json(ready / 'private' / 'installed.json',{'version':1,'flavor':FLAVOR,'backup':str(backup_directory())})
            if ROOT.exists(): raise RuntimeError('安装目标已变化，未修改网络')
            os.rename(ready, ROOT)
        safe_copy(stage / 'job.plist',PLIST,0o644)
        atomic_bytes(Path(pf.ANCHOR_FILE),pf.render_anchor().encode(),0o600)
        atomic_bytes(PF_CONF,prepared_pf.encode(),0o644)
        runtime.ensure_pf(pf,initial=True)
        start_service()
        network_settings(state)
        return {'request_id':request_id,'mode':'home'}


def diagnostics():
    if os.geteuid()!=0: raise RuntimeError('读取私有诊断需管理员授权')
    require_portable()
    result={'status':json.loads((ROOT/'public/status.json').read_text()),'probe_rounds':[],'log_files':[]}
    keys={'target','started_at','finished_at','curl_exit','result_ip','error','http_status','proxy_connect_status','local_connect_s','tls_ready_s','first_byte_s','total_s'}
    for name in ('health-probes.previous.jsonl','health-probes.jsonl'):
        path=PRIVATE/name
        if not path.exists():continue
        runtime.trusted(path)
        info=path.stat()
        result['log_files'].append({'name':name,'uid':info.st_uid,'mode':info.st_mode & 0o777,'bytes':info.st_size})
        for line in path.read_text().splitlines()[-120:]:
            try:
                row=json.loads(line)
                result['probe_rounds'].append({k:row.get(k) for k in ('started_at','finished_at','supervisor_pid')})
                result['probe_rounds'][-1]['checks']=[{k:v for k,v in c.items() if k in keys} for c in row.get('checks',[])]
            except (ValueError,TypeError,AttributeError):continue
    result['probe_rounds']=result['probe_rounds'][-120:]
    return result


def main():
    if len(sys.argv)==2 and sys.argv[1]=='--diagnostics': result=diagnostics()
    elif len(sys.argv)==5 and sys.argv[1]=='--install' and sys.argv[3]=='--initial-route': result=install(sys.argv[2],sys.argv[4])
    elif len(sys.argv)==3 and sys.argv[1]=='--install': result=install(sys.argv[2])
    elif len(sys.argv)==2 and sys.argv[1] in ('home','original'): result=switch(sys.argv[1])
    else: raise RuntimeError('安装参数无效')
    print('RESULT '+json.dumps(result),flush=True)


if __name__=='__main__':
    try: main()
    except Exception as exc:
        print('操作未完成：'+str(exc),file=sys.stderr,flush=True)
        print('请保留日志。已建立的保护不会自动撤销；已安装版本可通过Origin入口恢复普通流量。',file=sys.stderr,flush=True)
        raise SystemExit(1)
