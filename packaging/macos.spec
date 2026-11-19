# -*- mode: python ; coding: utf-8 -*-
# macOS 双击包。在项目根目录执行：
#   pyinstaller --noconfirm packaging/macos.spec

from pathlib import Path

from PyInstaller.utils.hooks import collect_all

ROOT = Path(SPECPATH).resolve().parent
datas = [
    (str(ROOT / "assets"), "assets"),
    (str(ROOT / "wxwatch" / "scan_imgkey_mac.c"), "wxwatch"),
]
binaries = []
hiddenimports = [
    "cccryptor_probe",
    "read_wechat_conversation",
    "wxwatch",
    "wxwatch.imagedat",
    "wxwatch.imagekey",
    "wxwatch.decryptor",
]
for package in ("sqlcipher3", "zstandard", "Crypto", "fpdf", "PIL"):
    package_datas, package_binaries, package_hidden = collect_all(package)
    datas += package_datas
    binaries += package_binaries
    hiddenimports += package_hidden

a = Analysis(
    [str(ROOT / "app.py")],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["PySide6", "PyQt5", "PyQt6", "PySide2", "watchdog"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="WeChatExport",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / "assets" / "wechat_export.icns"),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="WeChatExport",
)
app = BUNDLE(
    coll,
    name="WeChatExport.app",
    icon=str(ROOT / "assets" / "wechat_export.icns"),
    bundle_identifier="local.wechatexport.macos",
    info_plist={
        "CFBundleName": "WeChatExport",
        "CFBundleDisplayName": "微信聊天记录导出",
        "CFBundleShortVersionString": "1.0.0",
        "NSHighResolutionCapable": True,
        "LSMinimumSystemVersion": "12.0",
    },
)
