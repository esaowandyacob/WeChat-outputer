"""GUI 提取密钥的平台分发与权限检测。

GUI 一律以提权身份运行（Linux: sudo ./run_gui.sh 自动提权；Windows: 右键
「以管理员身份运行」），因此本模块没有任何密码弹窗/密码保存逻辑：
Windows 下用 IsUserAnAdmin 检测权限后在 GUI 进程内直接调用 keyscan_win 提取；
Linux 下子进程本来就是 root，直接执行。
"""

from __future__ import annotations

import contextlib
import io
import sys
from pathlib import Path
from typing import Callable


def _config_file() -> Path:
    from wxwatch.gui.backend import CONFIG_FILE
    return CONFIG_FILE


def is_admin() -> bool:
    """当前进程是否具备提取密钥所需的权限（Windows 管理员 / POSIX root）。"""
    if sys.platform == "win32":
        import ctypes
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    import os
    return hasattr(os, "geteuid") and os.geteuid() == 0


def chown_to_real_user(*paths) -> None:
    """sudo 启动时把产物（keys.json/config.json/output/mirror）还给真实用户，
    避免之后以普通用户运行时读不到（如 0600 的 root 文件）。仅 Linux 需要。"""
    import os
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user or sys.platform == "win32" or not is_admin():
        return
    import pwd
    try:
        pw = pwd.getpwnam(sudo_user)
    except KeyError:
        return
    for p in paths:
        p = Path(p)
        if not p.exists():
            continue
        targets = [p]
        if p.is_dir():
            targets += list(p.rglob("*"))
        for f in targets:
            with contextlib.suppress(OSError):
                os.chown(f, pw.pw_uid, pw.pw_gid)


def find_wechat_pid_safe() -> int | None:
    """平台分发版的微信进程检测（GUI 状态显示用，不抛异常）。"""
    try:
        if sys.platform == "win32":
            from wxwatch.keyscan_win import find_wechat_pid
        else:
            from wxwatch.keyscan import find_wechat_pid
        with contextlib.redirect_stdout(io.StringIO()):
            return find_wechat_pid()
    except Exception:
        return None


def extract_keys_gui(db_storage: Path, out_file: Path,
                     log_cb: Callable[[str], None]) -> bool:
    """Windows 下在 GUI 进程内提取密钥（GUI 需已以管理员身份运行）。

    返回 True 表示提取成功。仅 Windows 使用；Linux 请走 sudo 子进程。
    注意：扫描期间阻塞调用线程，GUI 会短暂无响应（一次性操作，可接受）。
    """
    if not is_admin():
        log_cb("[ERR] 当前不是管理员权限，无法读取微信进程内存。")
        log_cb("      请退出本程序，右键「以管理员身份运行」后重试。")
        return False
    from wxwatch.keyscan_win import extract_keys_win
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            extract_keys_win(db_storage, out_file)
    except Exception as e:
        for line in buf.getvalue().rstrip().splitlines():
            log_cb(line)
        log_cb(f"[ERR] 提取失败: {e}")
        return False
    for line in buf.getvalue().rstrip().splitlines():
        log_cb(line)
    return True
