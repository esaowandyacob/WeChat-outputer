"""定位微信 4.x 的 xwechat_files / db_storage。

macOS 数据在容器目录里，Windows 把保存位置写在
``%APPDATA%\\Tencent\\xwechat\\config\\51a1fffea11325a1e4104c6b3de47af7.ini``
（内容是 ``MyDocument:`` 或一个绝对路径）。两边的账号目录结构相同：
``xwechat_files/<账号>/db_storage/message/message_N.db``。
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

# 微信 4.x 用来记录“文件管理 → 文件管理路径”的配置文件名。内容是纯文本路径。
_FILE_SAVE_INI = "51a1fffea11325a1e4104c6b3de47af7.ini"
_SKIP_ACCOUNT_DIRS = {"all_users", "backup", "applet", "wmpf"}
_HEX4 = re.compile(r"[0-9a-fA-F]{4}")


def _dedupe(paths: list[Path]) -> list[Path]:
    result: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        expanded = path.expanduser()
        try:
            key = str(expanded.resolve()).casefold()
        except OSError:
            key = str(expanded).casefold()
        if key in seen:
            continue
        seen.add(key)
        result.append(expanded)
    return result


def _default_home() -> Path:
    """sudo 时用真实用户的家目录；Windows 提升权限后家目录不变。"""
    if sys.platform != "win32":
        sudo_user = os.environ.get("SUDO_USER", "").strip()
        if sudo_user:
            try:
                import pwd

                return Path(pwd.getpwnam(sudo_user).pw_dir)
            except (ImportError, KeyError):
                pass
    return Path.home()


def _appdata(home: Path | None) -> Path:
    if home is not None:
        return home / "AppData" / "Roaming"
    env = os.environ.get("APPDATA", "").strip()
    if env:
        return Path(env)
    return Path.home() / "AppData" / "Roaming"


def _windows_known_documents() -> Path | None:
    """用户可能把“文档”重定向到 OneDrive，不能写死 ~/Documents。"""
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", ctypes.c_ulong),
                ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        ole32 = ctypes.WinDLL("ole32", use_last_error=True)
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        ole32.CLSIDFromString.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(GUID)]
        ole32.CLSIDFromString.restype = ctypes.HRESULT
        shell32.SHGetKnownFolderPath.argtypes = [
            ctypes.POINTER(GUID),
            wintypes.DWORD,
            wintypes.HANDLE,
            ctypes.POINTER(ctypes.c_wchar_p),
        ]
        shell32.SHGetKnownFolderPath.restype = ctypes.HRESULT
        ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
        guid = GUID()
        if ole32.CLSIDFromString("{FDD39AD0-238F-46AF-ADB4-6C85480369C7}", ctypes.byref(guid)) != 0:
            return None
        pointer = ctypes.c_wchar_p()
        if shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(pointer)) != 0:
            return None
        value = pointer.value
        ole32.CoTaskMemFree(ctypes.cast(pointer, ctypes.c_void_p))
        return Path(value) if value else None
    except (OSError, AttributeError):
        return None


def documents_dir(home: Path | None = None) -> Path:
    if home is None:
        known = _windows_known_documents()
        if known is not None:
            return known
    base = home if home is not None else _default_home()
    return base / "Documents"


def _read_config_text(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    if b"\x00" in data:
        try:
            text = data.decode("utf-16-le")
        except UnicodeError:
            text = ""
    else:
        text = data.decode("utf-8", errors="replace")
    return text.strip("\x00 \r\n\t\"'")


def windows_file_save_root(home: Path | None = None) -> Path | None:
    """读取微信 4.x 文件保存根目录。未配置时返回 None，调用方再走默认位置。"""
    ini = _appdata(home) / "Tencent" / "xwechat" / "config" / _FILE_SAVE_INI
    text = _read_config_text(ini) if ini.is_file() else ""
    if not text:
        return None
    if text.casefold().startswith("mydocument"):
        return documents_dir(home)
    return Path(text)


def xwechat_file_roots(home: Path | None = None) -> list[Path]:
    """Mac 容器目录、Windows 配置目录、以及 ~/Documents、~/ 下的 xwechat_files。"""
    base = home if home is not None else _default_home()
    roots: list[Path] = []
    save_root = windows_file_save_root(home)
    if save_root is not None:
        roots.append(save_root / "xwechat_files")
    roots.extend(
        [
            documents_dir(home) / "xwechat_files",
            base / "xwechat_files",
            base / "Documents" / "xwechat_files",
            base
            / "Library"
            / "Containers"
            / "com.tencent.xinWeChat"
            / "Data"
            / "Documents"
            / "xwechat_files",
        ]
    )
    return _dedupe(roots)


def login_directories(home: Path | None = None) -> list[Path]:
    """各平台“当前登录账号”标记所在目录。"""
    base = home if home is not None else _default_home()
    directories = [root / "all_users" / "login" for root in xwechat_file_roots(home)]
    directories.append(
        base
        / "Library"
        / "Containers"
        / "com.tencent.xinWeChat"
        / "Data"
        / "Documents"
        / "app_data"
        / "login"
    )
    directories.append(_appdata(home) / "Tencent" / "xwechat" / "login")
    return _dedupe(directories)


def account_folder_key(name: str) -> str | None:
    """``wxid_xxx_a9d3`` 与登录目录 ``wxid_xxx`` 合成同一个账号键。"""
    if not str(name).startswith("wxid_"):
        return None
    short, separator, tail = str(name).rpartition("_")
    if separator and short.startswith("wxid_") and _HEX4.fullmatch(tail):
        return short
    return str(name)


def _entry_mtime(path: Path) -> float:
    """目录自身的 mtime 在 Windows 上不会随内部文件改写更新，要看直接子文件。"""
    stamps: list[float] = []
    try:
        stamps.append(path.stat().st_mtime)
    except OSError:
        return -1.0
    if path.is_dir():
        try:
            children = list(path.iterdir())
        except OSError:
            children = []
        for child in children:
            try:
                stamps.append(child.stat().st_mtime)
            except OSError:
                continue
    return max(stamps, default=-1.0)


def current_account_key(home: Path | None = None) -> str | None:
    best_key: str | None = None
    best_mtime = -1.0
    for directory in login_directories(home):
        if not directory.is_dir():
            continue
        try:
            children = list(directory.iterdir())
        except OSError:
            continue
        for child in children:
            if not child.is_dir():
                continue
            key = account_folder_key(child.name)
            if key is None:
                continue
            mtime = _entry_mtime(child)
            if mtime > best_mtime:
                best_mtime = mtime
                best_key = key
    return best_key


def _has_message_db(storage: Path) -> bool:
    message = storage / "message"
    if not message.is_dir():
        return False
    try:
        for item in message.iterdir():
            if item.is_file() and item.suffix.casefold() == ".db":
                return True
    except OSError:
        return False
    return False


def _message_mtime(storage: Path) -> float:
    message = storage / "message"
    latest = 0.0
    try:
        for item in message.iterdir():
            if not item.is_file():
                continue
            if item.suffix.casefold() != ".db" or not item.name.casefold().startswith("message_"):
                continue
            try:
                latest = max(latest, item.stat().st_mtime)
            except OSError:
                continue
    except OSError:
        return latest
    return latest


def _db_in_use(path: Path) -> bool:
    """微信打开着的库无法独占打开。用来区分当前登录账号和其他历史账号。"""
    if sys.platform != "win32" or not path.is_file():
        return False
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel32.CreateFileW(str(path), 0x80000000, 0, None, 3, 0, None)
    invalid = wintypes.HANDLE(-1).value
    if handle and handle != invalid:
        kernel32.CloseHandle(handle)
        return False
    return ctypes.get_last_error() in (32, 33)


def _storage_in_use(storage: Path) -> bool:
    message = storage / "message"
    try:
        candidates = [
            item
            for item in message.iterdir()
            if item.is_file()
            and item.suffix.casefold() == ".db"
            and item.name.casefold().startswith("message_")
        ]
    except OSError:
        return False
    candidates.sort(key=lambda item: (item.name.casefold() != "message_0.db", item.name.casefold()))
    return any(_db_in_use(item) for item in candidates[:3])


def configured_xwechat_root(home: Path | None = None) -> Path | None:
    save_root = windows_file_save_root(home)
    if save_root is None:
        return None
    return save_root / "xwechat_files"


def _under(root: Path, paths: list[Path]) -> list[Path]:
    try:
        root_resolved = root.resolve()
    except OSError:
        root_resolved = root
    kept: list[Path] = []
    for path in paths:
        try:
            path.resolve().relative_to(root_resolved)
        except (OSError, ValueError):
            continue
        kept.append(path)
    return kept


def locate_db_storages(home: Path | None = None) -> list[Path]:
    found: list[Path] = []
    seen: set[str] = set()
    for root in xwechat_file_roots(home):
        if not root.is_dir():
            continue
        try:
            children = list(root.iterdir())
        except OSError:
            continue
        for child in children:
            if not child.is_dir() or child.name.casefold() in _SKIP_ACCOUNT_DIRS:
                continue
            storage = child / "db_storage"
            if not _has_message_db(storage):
                continue
            try:
                key = str(storage.resolve()).casefold()
            except OSError:
                key = str(storage).casefold()
            if key in seen:
                continue
            seen.add(key)
            found.append(storage)
    return found


def locate_db_storage(home: Path | None = None) -> Path | None:
    """返回当前账号的 db_storage。多个账号时优先微信正打开的库，其次登录标记。"""
    storages = locate_db_storages(home)
    if not storages:
        return None
    in_use = [item for item in storages if _storage_in_use(item)]
    if in_use:
        pool = in_use
    else:
        configured = configured_xwechat_root(home)
        pool = _under(configured, storages) if configured is not None else []
        pool = pool or storages
    current = current_account_key(home)
    if current:
        matched = [item for item in pool if account_folder_key(item.parent.name) == current]
        if matched:
            pool = matched
    return max(pool, key=_message_mtime)
