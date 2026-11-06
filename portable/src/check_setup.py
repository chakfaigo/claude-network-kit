"""Selected read-only checks; never installs, probes the network, or reads node credentials."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import plistlib
import re
import subprocess
import sys
import time
from urllib.parse import urlsplit

PACKAGE = Path(__file__).resolve().parent.parent
ROOT = Path('/Library/Application Support/ClaudeResidential')
POLICIES = {'QuicAllowed': False, 'DnsOverHttpsMode': 'off',
            'WebRtcIPHandling': 'disable_non_proxied_udp'}


def read_json(path):
    if path.is_symlink() or path.stat().st_size > 2_000_000:
        raise ValueError('Unsupported file')
    return json.loads(path.read_text())


def run(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=6)
        return p.returncode, p.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None, ''


def package_check(package):
    try:
        manifest = read_json(package / 'manifest.json')
        files = manifest['files']
        if not isinstance(files, dict) or not files:
            raise ValueError('Empty manifest')
        for rel, digest in files.items():
            path = package / rel
            if (Path(rel).is_absolute() or '..' in Path(rel).parts or 'private' in Path(rel).parts
                    or Path(rel).name == 'node.json' or path.is_symlink()
                    or package.resolve() not in path.resolve().parents):
                raise ValueError('Invalid manifest path')
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                return 'needs_action', '包内文件与清单不一致；重新取得完整Release，不继续安装。'
        return 'baseline_match', '包内文件与清单一致；还需对照Release的ZIP摘要确认来源。'
    except (OSError, ValueError, TypeError, KeyError):
        return 'needs_action', '无法校验完整包；不要把学习资料或局部源码当安装包。'


def proxy_summary(env):
    if not isinstance(env, dict):
        return {'valid_object': False}, False
    result = {}; good = True
    for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'NO_PROXY', 'no_proxy'):
        value = env.get(key)
        if key.lower() == 'no_proxy':
            tokens = value.split(',') if isinstance(value, str) else []
            ok = bool(tokens) and all(x.strip() in ('localhost', '127.0.0.1', '::1', '[::1]') for x in tokens)
        else:
            try:
                parsed = urlsplit(value) if isinstance(value, str) else None
                ok = bool(parsed and parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost', '::1')
                          and parsed.port == 10808 and not parsed.username and not parsed.password
                          and parsed.path in ('', '/') and not parsed.query and not parsed.fragment)
            except ValueError:
                ok = False
        result[key] = {'present': key in env, 'matches_baseline': ok}; good &= ok
    for key in ('ALL_PROXY', 'all_proxy'):
        value = env.get(key)
        try:
            parsed = urlsplit(value) if isinstance(value, str) else None
            ok = bool(parsed and parsed.scheme in ('socks5', 'socks5h')
                      and parsed.hostname in ('127.0.0.1', 'localhost', '::1') and parsed.port == 10808
                      and not parsed.username and not parsed.password
                      and parsed.path in ('', '/') and not parsed.query and not parsed.fragment)
        except ValueError:
            ok = False
        result[key] = {'present': key in env, 'matches_baseline': ok if key in env else None}
        if key in env: good &= ok
    return result, bool(good)


def summarize_status(status, now):
    if not isinstance(status, dict):
        return 'pending', '无法解释状态文件，需核对服务。', {}
    stamp = status.get('updated_at')
    fresh = type(stamp) in (int, float) and math.isfinite(stamp) and -5 <= now - stamp <= 120
    summary = {'fresh_within_120_seconds': fresh,
               'mode': status.get('mode') if status.get('mode') in ('home', 'original') else 'unknown',
               'core_reported_running': status.get('core_running') is True}
    valid = status.get('version') == 1 and fresh and summary['core_reported_running']
    if valid and status.get('mode') == 'home' and status.get('phase') == 'healthy' and status.get('policy') == 'home_open' and status.get('successes') == 2:
        return 'baseline_match', '最新状态报告Home开放；仍需核对活动PF、真实出口和各客户端请求。', summary
    if valid and status.get('mode') == 'original' and status.get('phase') == 'blocked' and status.get('policy') == 'original_blocked' and status.get('successes') == 0:
        return 'pending', 'Origin正按设计阻断Claude；准备使用前通过Home入口重新验证。', summary
    return 'needs_action', '状态过期、阻断或不完整；先查本次状态与日志，不关闭保护试通。', summary


def collect(package=PACKAGE, root=ROOT, home=None, env=None, runner=run, now=None, policy_paths=None):
    home = Path.home() if home is None else home
    env = os.environ if env is None else env
    now = time.time() if now is None else now
    installed = root.exists() or root.is_symlink()
    valid_root = root.is_dir() and not root.is_symlink()
    report = {'schema_version': 1, 'checked_at': now, 'scope': 'selected_read_only_checks',
              'stage': 'existing_installation' if installed else 'before_installation',
              'acceptance_complete': False, 'checks': []}
    def add(key, state, message, details=None):
        row = {'id': key, 'state': state, 'message': message}
        if details is not None: row['details'] = details
        report['checks'].append(row)
    add('package_integrity', *package_check(package))
    try:
        version_file = package / 'VERSION'
        if version_file.is_symlink() or version_file.stat().st_size > 100: raise ValueError('Invalid version file')
        version = version_file.read_text().strip()
        report['package_version'] = version if re.fullmatch(r'v\d{4}\.\d{2}\.\d{2}\.\d+', version) else 'unknown'
    except (OSError, ValueError):
        report['package_version'] = 'unknown'
    mac = platform.system() == 'Darwin'
    try: supported = mac and platform.machine() == 'arm64' and int(platform.mac_ver()[0].split('.')[0]) >= 13
    except ValueError: supported = False
    add('platform', 'baseline_match' if supported else 'needs_action',
        '适用平台：Apple Silicon、macOS 13+。' if supported else '此包只适用于Apple Silicon、macOS 13+。')
    add('installation_stage', 'pending', '已存在安装目录；禁止用首次安装覆盖，先核对已安装源版本。' if installed else '未发现安装目录；配置自己的线路并完成预检后，才能安装。')
    if installed and not valid_root:
        add('installed_path', 'needs_action', '安装路径不是正常目录或为符号链接；停止安装，先核对来源，未读取其内容。')
    if installed and valid_root:
        matched = []
        try:
            for name in ('controller.py', 'guard_config.py'):
                path = root / name
                if path.is_symlink(): raise ValueError('Symlink')
                matched.append(hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256((package / 'src' / name).read_bytes()).digest())
            add('installed_sources', 'baseline_match' if all(matched) else 'needs_action',
                '已安装控制器/生成器与本包一致；不代表全部安装数据已验收。' if all(matched) else '已安装控制器/生成器与本包不同；请按旧机维护流程处理，下载或点Home不会升级。')
        except (OSError, ValueError):
            add('installed_sources', 'pending', '无法只读核对已安装源码；需要维护者确认。')
        try: add('home_status', *summarize_status(read_json(root / 'public/status.json'), now))
        except (OSError, ValueError): add('home_status', 'pending', '无法读取有效公开状态；不能据此判为已保护。')
    if mac:
        rc, text = runner(['/usr/sbin/scutil', '--proxy'])
        flags = re.findall(r'\b(?:HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable|ProxyAutoDiscoveryEnable)\s*:\s*(\d+)', text)
        known = rc == 0 and '<dictionary>' in text
        add('system_proxy', 'pending' if not known else ('needs_action' if any(x != '0' for x in flags) else 'baseline_match'),
            '核对当前系统代理；基线为全部关闭。这不是所有休眠网络服务/扩展的检查。',
            {'readable': known, 'enabled_flag_seen': any(x != '0' for x in flags) if known else None})
        rc, _ = runner(['/sbin/ifconfig', 'utun99'])
        add('tun_presence', ('pending' if rc not in (0, 1) else ('baseline_match' if (rc == 0) == installed else 'needs_action')),
            '只检查utun99是否存在，不证明其归属、活动路由或PF已正确。', {'present': rc == 0 if rc in (0, 1) else None})
        for label, key in [('local.claude.residential.status', 'menu_registration'), ('local.claude.residential.watch', 'notification_registration')]:
            rc, text = runner(['/bin/launchctl', 'print', 'gui/' + str(os.getuid()) + '/' + label])
            registered = rc == 0
            add(key, 'baseline_match' if installed and registered else 'pending',
                '仅检查服务登记；周期提醒可以空闲，通知是否送达必须实际验收。', {'registered': registered, 'running': bool(re.search(r'^\s*pid = \d+', text, re.M)) if registered else None})
    else:
        add('system_checks', 'pending', '未运行macOS系统检查。')
    try:
        settings = home / '.claude/settings.json'
        data = read_json(settings)
        if not isinstance(data, dict): raise ValueError('Invalid settings')
        app_env = data.get('env', {})
        summary, good = proxy_summary(app_env)
        add('cli_global_file', 'baseline_match' if good and settings.stat().st_mode & 0o777 == 0o600 else 'needs_action',
            '只核对默认全局文件；实际CLI、项目/托管配置和其他客户端仍需独立验收。', summary)
    except (OSError, ValueError, TypeError):
        add('cli_global_file', 'pending', '默认全局设置缺失或无法解释；安装会合并代理设置，不能覆盖未知旧配置。')
    current, _ = proxy_summary(dict(env))
    review_keys = ('ANTHROPIC_BASE_URL', 'CLAUDE_CONFIG_DIR', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_EXTRA_CA_CERTS')
    add('checker_environment', 'pending', '这里只是检查脚本自身环境，不代表其他程序最终生效环境；仅报告存在性。',
        {'proxy': current, 'review_keys_present': {key: key in env for key in review_keys}})
    # Local plist is an optional clue. A profile/MDM may use another source;
    # absence or a matching file can never replace chrome://policy acceptance.
    candidates = policy_paths if policy_paths is not None else [Path('/Library/Managed Preferences') / home.name / 'com.google.Chrome.plist',
                  Path('/Library/Managed Preferences/com.google.Chrome.plist')]
    clues = []
    for path in candidates:
        try:
            if path.is_symlink() or path.stat().st_size > 2_000_000: continue
            data = plistlib.loads(path.read_bytes())
            if isinstance(data, dict): clues.append({key: {'present': key in data, 'matches': type(data.get(key)) is type(value) and data.get(key) == value} for key, value in POLICIES.items()})
        except (OSError, ValueError, plistlib.InvalidFileException): pass
    add('chrome_policy', 'pending', '必须在日常Chrome的chrome://policy核验三项值与状态；文件线索不代表已加载。', {'local_file_clues': clues})
    report['manual_checks'] = ['Chrome实际策略/扩展/网页请求', '所有代理后台和登录项',
        '活动PF与实际DNS/出口/国内分流', 'CLI/桌面/VS Code各自的真实请求和配置覆盖',
        '维护窗口的故障阻断/恢复/唤醒/换网/整机重启', '通知实际送达', '用户决定时机的登录后业务与最终签收']
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true', help='Print selected fields as JSON')
    parser.add_argument('--output', type=Path, help='Create a new private JSON report; never overwrite')
    args = parser.parse_args()
    if os.geteuid() == 0: parser.error('请以普通用户运行，不要sudo。')
    report = collect(); text = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream: stream.write(text)
    if args.json: print(text, end='')
    else:
        names = {'baseline_match': '符合所查基线', 'needs_action': '需要处理', 'pending': '待核验'}
        print('接入检查：只读、不联网；此报告不会判定整机验收完成。')
        print('安装包版本：' + report['package_version'])
        for row in report['checks']: print('[' + names[row['state']] + '] ' + row['message'])
        print('下一步：按 docs/新机快速接入.md 处理缺项，再按强制流程逐项签收。')
    return 2 if any(x['state'] == 'needs_action' for x in report['checks']) else 0


if __name__ == '__main__':
    raise SystemExit(main())
