"""Collect this Mac owner's connection details locally; never changes networking."""
import getpass
import importlib.util
import json
import os
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent


def validator():
    spec = importlib.util.spec_from_file_location('home_config', PACKAGE / 'src/guard_config.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.validate_node


def save_node(package, node):
    checked = validator()(node)
    folder = package / 'private'
    if folder.is_symlink():
        raise ValueError('private 不能是符号链接')
    folder.mkdir(mode=0o700, exist_ok=True)
    os.chmod(folder, 0o700)
    path = folder / 'node.json'
    # O_EXCL refuses existing files and symlinks; credentials never overwrite a setup.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(checked, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path


def main():
    if os.geteuid() == 0:
        raise ValueError('请以普通用户打开配置入口，不要使用 sudo')
    if (PACKAGE / 'private/node.json').exists():
        raise ValueError('已有本地线路配置；本工具不会覆盖。要重新配置，请使用全新解压的副本')
    print('仅保存到本机 private/node.json，不连接服务器、不修改系统网络。')
    print('需要自己的 SOCKS5 家宽账号，以及供应商提供的固定出口 IPv4。')
    print('请勿填写 Claude 登录密码；下列用户名和密码是家宽代理凭据。')
    node = {
        'server': input('家宽 SOCKS5 主机：').strip(),
        'port': int(input('家宽 SOCKS5 端口：').strip()),
        'username': getpass.getpass('家宽用户名（隐藏输入）：'),
        'password': getpass.getpass('家宽密码（隐藏输入）：'),
        'expected_ip': input('预期固定出口 IPv4：').strip(),
    }
    print('可选普通代理：当前只支持美国出口的 VMess over WebSocket，无 TLS 配置。')
    print('如需分流或前置，按 examples/upstream.example.json 准备自己的文件。')
    upstream = input('该 JSON 文件路径（留空表示仅使用家宽）：').strip()
    if upstream:
        path = Path(upstream).expanduser()
        if path.stat().st_size > 16384:
            raise ValueError('普通代理配置文件过大')
        node['upstream'] = json.loads(path.read_text())
    save_node(PACKAGE, node)
    print('本地配置已保存。现在可双击“安装.command”。不要上传 private 目录。')


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print('\n已取消；没有修改系统网络。')
        raise SystemExit(1)
    except (OSError, ValueError):
        # Never echo raw input or parser diagnostics that could contain credentials.
        print('未完成：请核对字段、文件权限和是否已有配置；已有配置不会被覆盖。')
        raise SystemExit(1)
