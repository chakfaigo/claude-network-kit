#!/usr/bin/env python3
"""Build only the menu-bar app; never touches network services or settings."""
from pathlib import Path
import plistlib
import subprocess

ROOT = Path(__file__).resolve().parent
APP = ROOT / 'build/家宽状态.app'
BIN = APP / 'Contents/MacOS'
RESOURCES = APP / 'Contents/Resources'
BIN.mkdir(parents=True, exist_ok=True)
RESOURCES.mkdir(parents=True, exist_ok=True)
metadata = {
    'CFBundleIdentifier': 'local.claude.residential.status',
    'CFBundleName': '家宽状态', 'CFBundleDisplayName': '家宽状态',
    'CFBundleExecutable': 'ResidentialStatus', 'CFBundlePackageType': 'APPL',
    'CFBundleShortVersionString': '1.1.3', 'CFBundleVersion': '5',
    'LSUIElement': True, 'LSMinimumSystemVersion': '13.0',
    'NSHighResolutionCapable': True, 'NSPrincipalClass': 'NSApplication',
}
(APP / 'Contents/Info.plist').write_bytes(plistlib.dumps(metadata))
subprocess.run(['/usr/bin/xcrun', 'swiftc', '-swift-version', '5', '-O',
                '-target', 'arm64-apple-macosx13.0', '-module-cache-path', str(ROOT / '.module-cache'),
                str(ROOT / 'StatusModel.swift'), str(ROOT / 'ActivityLog.swift'), str(ROOT / 'Main.swift'),
                '-o', str(BIN / 'ResidentialStatus')], check=True)
(RESOURCES / '使用说明.html').write_bytes((ROOT / '使用说明.html').read_bytes())
subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', str(APP)], check=True)
subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(APP)], check=True)
print(APP)
