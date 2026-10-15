# -*- mode: python ; coding: utf-8 -*-
# PyInstaller 打包配置：单文件 wxwatch 可执行程序（Windows exe / Linux 通用）。
# 构建：pyinstaller --noconfirm wxwatch.spec
# Windows 产物带 UAC 管理员清单（uac_admin），双击自动提权——等价 Linux 的 root 要求。

import sys as _sys
from pathlib import Path as _Path

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=['tkinter', 'PyQt5', 'PyQt6', 'PySide2'],
    noarchive=False,
)
if _sys.platform == 'win32':
    # Windows 用标准库 sqlite3 + 捆绑的 SQLCipher 版 sqlite3.dll（构建环境 python
    # 目录里的 sqlite3.dll 已被替换为该版本，会随 _sqlite3.pyd 自动收集）；
    # 其 OpenSSL 依赖需显式带上。
    _pydir = _Path(_sys.executable).parent
    a.binaries += [('libcrypto-3-x64.dll',
                    str(_pydir / 'libcrypto-3-x64.dll'), 'BINARY')]
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='wxwatch',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,          # 不用 UPX：杀软误报高、启动还要先解压
    console=True,       # 保留控制台：CLI 子命令（extract-keys 等）输出可见
    uac_admin=True,     # Windows：双击自动请求管理员（读取进程内存必需）
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
