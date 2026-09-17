"""Windows 微信 4.x 进程检测与只读内存密钥扫描。

本模块不修改微信进程或数据库文件。密钥候选来自进程内存中 WCDB 常见的
``x'<64 hex>'`` / ``x'<64 hex><32 hex salt>'`` 文本（ASCII 或 UTF-16LE），
最终是否保存仍由调用方用 SQLCipher 验证。
"""

from __future__ import annotations

import ctypes
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


WECHAT_PROCESS_NAMES = ("Weixin.exe", "WeChat.exe")
HEX_KEY_RE = re.compile(r"^[0-9a-fA-F]{64}$")
ASCII_KEY_RE = re.compile(rb"x'([0-9a-fA-F]{64})([0-9a-fA-F]{32})?'")
ASCII_DATA_DIR_RE = re.compile(
    rb"[A-Za-z]:\\(?:[^\\\x00]{1,80}\\)*xwechat_files\\[0-9A-Za-z_-]{4,80}(?:\\db_storage)?",
    re.IGNORECASE,
)
UTF16_DATA_DIR_RE = re.compile(
    r"[A-Za-z]:\\(?:[^\\]{1,80}\\)*xwechat_files\\[0-9A-Za-z_-]{4,80}(?:\\db_storage)?",
    re.IGNORECASE,
)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
TH32CS_SNAPPROCESS = 0x00000002
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_GUARD = 0x100
READABLE_PROTECT = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
CHUNK_SIZE = 4 * 1024 * 1024
CHUNK_OVERLAP = 256
MAX_REGION_SIZE = 256 * 1024 * 1024


class WindowsProbeError(RuntimeError):
    """Windows 进程检测或内存读取错误。"""


@dataclass(frozen=True)
class WindowsProcessInfo:
    """一个疑似微信主进程。"""

    pid: int
    name: str
    executable: str
    version: str | None = None
    working_set: int = 0


# 从一段内存中提取 32 字节 AES 密钥的十六进制文本。
def extract_hex_keys_from_bytes(data: bytes | bytearray | memoryview) -> list[str]:
    raw = bytes(data)
    found: list[str] = []
    seen: set[str] = set()

    # 记录一个已规范化的 64 位十六进制密钥，忽略重复项。
    def add(value: str) -> None:
        key = value.strip().lower()
        if HEX_KEY_RE.fullmatch(key) and key not in seen:
            seen.add(key)
            found.append(key)

    for match in ASCII_KEY_RE.finditer(raw):
        add(match.group(1).decode("ascii"))
    marker = b"x\x00'\x00"
    start = 0
    while True:
        index = raw.find(marker, start)
        if index < 0:
            break
        position = index + len(marker)
        hex_chars: list[str] = []
        while position + 1 < len(raw) and len(hex_chars) < 96:
            character, zero = raw[position], raw[position + 1]
            if zero != 0 or chr(character) not in "0123456789abcdefABCDEF":
                break
            hex_chars.append(chr(character))
            position += 2
        if len(hex_chars) >= 64:
            add("".join(hex_chars[:64]))
        start = index + 2
    return found


# 从一段内存中提取 xwechat_files 数据目录路径。
def extract_data_dirs_from_bytes(data: bytes | bytearray | memoryview) -> list[str]:
    raw = bytes(data)
    found: list[str] = []
    seen: set[str] = set()

    # 规范化 Windows 路径并去重，目录不存在时仍保留供后续扫描。
    def add(value: str) -> None:
        text = value.replace("/", "\\").rstrip("\\")
        if not text or text.casefold() in seen:
            return
        seen.add(text.casefold())
        found.append(text)

    for match in ASCII_DATA_DIR_RE.finditer(raw):
        add(match.group(0).decode("ascii", errors="ignore"))
    try:
        utf16_text = raw.decode("utf-16le", errors="ignore")
    except Exception:
        utf16_text = ""
    for match in UTF16_DATA_DIR_RE.finditer(utf16_text):
        add(match.group(0))
    return found


# 当前进程是否以管理员令牌运行；无法判断时返回 None。
def is_current_user_admin() -> bool | None:
    if sys.platform != "win32":
        return None
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return None


# 通过 Known Folder 读取“文档”目录，失败时回退到 ~/Documents。
def windows_documents_dir(home: Path | None = None) -> Path:
    if home is not None:
        return Path(home) / "Documents"
    if sys.platform == "win32":
        try:
            buffer = ctypes.create_unicode_buffer(512)
            result = ctypes.windll.shell32.SHGetFolderPathW(None, 5, None, 0, buffer)
            if result == 0 and buffer.value:
                return Path(buffer.value)
        except Exception:
            pass
        user_profile = os.environ.get("USERPROFILE", "").strip()
        if user_profile:
            return Path(user_profile) / "Documents"
    return Path.home() / "Documents"


# 读取微信文件管理目录相关注册表值。
def windows_registry_file_save_paths() -> list[str]:
    if sys.platform != "win32":
        return []
    try:
        import winreg
    except ImportError:
        return []
    values: list[str] = []
    key_specs = (
        (r"Software\Tencent\WeChat", "FileSavePath"),
        (r"Software\Tencent\Weixin", "FileSavePath"),
        (r"Software\Tencent\xwechat", "FileSavePath"),
        (r"Software\Tencent\WeChat", "FilePath"),
        (r"Software\Tencent\Weixin", "DataPath"),
    )
    for subkey, name in key_specs:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey) as handle:
                value, _kind = winreg.QueryValueEx(handle, name)
        except OSError:
            continue
        text = str(value or "").strip()
        if text:
            values.append(text)
    return values


# 把注册表或界面里的文件保存路径转换成 xwechat_files 根目录。
def normalize_windows_data_root(raw: str, documents: Path) -> Path | None:
    text = str(raw or "").strip().strip('"')
    if not text or text.casefold() in {"mydocument:", "my documents:", "document:", "documents:"}:
        return documents / "xwechat_files"
    path = Path(os.path.expandvars(text)).expanduser()
    if path.name.casefold() == "xwechat_files":
        return path
    if path.name.casefold() == "db_storage":
        return path
    nested = path / "xwechat_files"
    return nested


# 枚举本机常见的微信 4.x 数据根目录，供读取器扫描 message_N.db。
def list_windows_data_root_candidates(
    home: Path | None = None,
    *,
    include_system_folders: bool = True,
) -> list[Path]:
    documents = windows_documents_dir(home)
    candidates: list[Path] = [documents / "xwechat_files"]
    if home is not None:
        candidates.append(Path(home) / "xwechat_files")
    if include_system_folders:
        for raw in windows_registry_file_save_paths():
            normalized = normalize_windows_data_root(raw, documents)
            if normalized is not None:
                candidates.append(normalized)
        user_profile = Path(os.environ.get("USERPROFILE", str(Path.home())))
        candidates.extend(
            [
                user_profile / "Documents" / "xwechat_files",
                user_profile / "OneDrive" / "Documents" / "xwechat_files",
                user_profile / "xwechat_files",
            ]
        )
        for letter in "CDEFGHI":
            candidates.append(Path(f"{letter}:/xwechat_files"))
    unique: list[Path] = []
    seen: set[str] = set()
    for item in candidates:
        try:
            key = str(item).casefold()
        except Exception:
            continue
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


# 常见微信 4.x / 3.x 安装位置，供启动客户端。
def windows_wechat_executable_candidates() -> list[Path]:
    program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    program_files_x86 = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    local_app_data = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    names = (
        program_files / "Tencent" / "Weixin" / "Weixin.exe",
        program_files / "Tencent" / "WeChat" / "Weixin.exe",
        program_files / "Tencent" / "WeChat" / "WeChat.exe",
        program_files_x86 / "Tencent" / "Weixin" / "Weixin.exe",
        program_files_x86 / "Tencent" / "WeChat" / "WeChat.exe",
        local_app_data / "Tencent" / "Weixin" / "Weixin.exe",
        local_app_data / "Programs" / "Tencent" / "Weixin" / "Weixin.exe",
    )
    found: list[Path] = []
    seen: set[str] = set()
    for path in names:
        key = str(path).casefold()
        if key in seen:
            continue
        seen.add(key)
        found.append(path)
    if sys.platform == "win32":
        try:
            import winreg

            install_keys = (
                (r"Software\Tencent\Weixin", "InstallPath"),
                (r"Software\Tencent\WeChat", "InstallPath"),
                (r"Software\Tencent\Weixin", "Install"),
            )
            for subkey, name in install_keys:
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey) as handle:
                        value, _kind = winreg.QueryValueEx(handle, name)
                except OSError:
                    continue
                install = Path(str(value or "").strip())
                if not str(install):
                    continue
                extras = [install] if install.suffix.casefold() == ".exe" else [install / "Weixin.exe", install / "WeChat.exe"]
                for candidate in extras:
                    key = str(candidate).casefold()
                    if key not in seen:
                        seen.add(key)
                        found.append(candidate)
        except Exception:
            pass
    return found


# 仅在 Windows 上加载 kernel32。
def _kernel32() -> ctypes.WinDLL:
    if sys.platform != "win32":
        raise WindowsProbeError("仅 Windows 支持进程内存读取")
    return ctypes.WinDLL("kernel32", use_last_error=True)


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_uint32),
        ("cntUsage", ctypes.c_uint32),
        ("th32ProcessID", ctypes.c_uint32),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", ctypes.c_uint32),
        ("cntThreads", ctypes.c_uint32),
        ("th32ParentProcessID", ctypes.c_uint32),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.c_uint32),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


class _MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_uint32),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_uint32),
        ("Protect", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
    ]


class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_uint32),
        ("PageFaultCount", ctypes.c_uint32),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


# 打开带查询/读内存权限的进程句柄。
def _open_process(pid: int, access: int) -> int | None:
    kernel32 = _kernel32()
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    handle = kernel32.OpenProcess(access, False, int(pid))
    return int(handle) if handle else None


# 关闭 Win32 句柄。
def _close_handle(handle: int | None) -> None:
    if not handle:
        return
    try:
        _kernel32().CloseHandle(ctypes.c_void_p(handle))
    except Exception:
        pass


# 读取进程对应的可执行文件完整路径。
def _query_process_executable(pid: int) -> str:
    access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION
    handle = _open_process(pid, access)
    if handle is None:
        return ""
    try:
        kernel32 = _kernel32()
        kernel32.QueryFullProcessImageNameW.restype = ctypes.c_int
        length = ctypes.c_uint32(32768)
        buffer = ctypes.create_unicode_buffer(32768)
        if kernel32.QueryFullProcessImageNameW(ctypes.c_void_p(handle), 0, buffer, ctypes.byref(length)):
            return buffer.value
    except Exception:
        return ""
    finally:
        _close_handle(handle)
    return ""


# 读取 PE 文件的 FileVersion 字符串。
def read_windows_file_version(path: Path | str) -> str | None:
    if sys.platform != "win32":
        return None
    executable = Path(path)
    if not executable.is_file():
        return None
    try:
        version_dll = ctypes.WinDLL("version")
        size = version_dll.GetFileVersionInfoSizeW(str(executable), None)
        if not size:
            return None
        buffer = ctypes.create_string_buffer(size)
        if not version_dll.GetFileVersionInfoW(str(executable), 0, size, buffer):
            return None
        value = ctypes.c_void_p()
        length = ctypes.c_uint
        length_value = length(0)
        if not version_dll.VerQueryValueW(buffer, r"\\", ctypes.byref(value), ctypes.byref(length_value)):
            return None

        class _VS_FIXEDFILEINFO(ctypes.Structure):
            _fields_ = [
                ("dwSignature", ctypes.c_uint32),
                ("dwStrucVersion", ctypes.c_uint32),
                ("dwFileVersionMS", ctypes.c_uint32),
                ("dwFileVersionLS", ctypes.c_uint32),
                ("dwProductVersionMS", ctypes.c_uint32),
                ("dwProductVersionLS", ctypes.c_uint32),
            ]

        info = ctypes.cast(value, ctypes.POINTER(_VS_FIXEDFILEINFO)).contents
        major = (info.dwFileVersionMS >> 16) & 0xFFFF
        minor = info.dwFileVersionMS & 0xFFFF
        build = (info.dwFileVersionLS >> 16) & 0xFFFF
        revision = info.dwFileVersionLS & 0xFFFF
        return f"{major}.{minor}.{build}.{revision}"
    except Exception:
        return None


# 读取工作集大小，用于在多个 Weixin.exe 中挑选主进程。
def _process_working_set(pid: int) -> int:
    handle = _open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION)
    if handle is None:
        return 0
    try:
        psapi = ctypes.WinDLL("psapi")
        counters = _PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(counters)
        if psapi.GetProcessMemoryInfo(ctypes.c_void_p(handle), ctypes.byref(counters), ctypes.sizeof(counters)):
            return int(counters.WorkingSetSize)
    except Exception:
        return 0
    finally:
        _close_handle(handle)
    return 0


# 枚举本机正在运行的微信相关进程。
def list_windows_wechat_processes() -> list[WindowsProcessInfo]:
    if sys.platform != "win32":
        return []
    kernel32 = _kernel32()
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == ctypes.c_void_p(-1).value:
        return []
    wanted = {name.casefold() for name in WECHAT_PROCESS_NAMES}
    results: list[WindowsProcessInfo] = []
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)]
        kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)]
        more = kernel32.Process32FirstW(ctypes.c_void_p(snapshot), ctypes.byref(entry))
        while more:
            name = str(entry.szExeFile or "")
            if name.casefold() in wanted:
                pid = int(entry.th32ProcessID)
                executable = _query_process_executable(pid) or name
                results.append(
                    WindowsProcessInfo(
                        pid=pid,
                        name=name,
                        executable=executable,
                        version=read_windows_file_version(executable),
                        working_set=_process_working_set(pid),
                    )
                )
            more = kernel32.Process32NextW(ctypes.c_void_p(snapshot), ctypes.byref(entry))
    finally:
        _close_handle(int(snapshot))
    results.sort(key=lambda item: (0 if item.name.casefold() == "weixin.exe" else 1, -item.working_set, item.pid))
    return results


# 选择最可能的微信主进程 PID。
def find_windows_wechat_pid() -> int | None:
    processes = list_windows_wechat_processes()
    return processes[0].pid if processes else None


# 读取当前检测到的微信版本号。
def find_windows_wechat_version() -> str | None:
    processes = list_windows_wechat_processes()
    for item in processes:
        if item.version:
            return item.version
    for candidate in windows_wechat_executable_candidates():
        version = read_windows_file_version(candidate)
        if version:
            return version
    return None


# 检查是否能对目标 PID 做只读内存访问。
def check_process_memory_access(pid: int) -> tuple[bool, str]:
    if sys.platform != "win32":
        return False, "当前系统不是 Windows"
    handle = _open_process(int(pid), PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
    if handle is None:
        error = ctypes.get_last_error()
        if error == 5:
            return False, "无法读取微信进程内存，请以管理员身份运行本工具"
        return False, "无法打开微信进程"
    _close_handle(handle)
    return True, "可以读取微信进程内存"


# 判断内存保护属性是否允许 ReadProcessMemory。
def _is_readable_protect(protect: int) -> bool:
    if protect & PAGE_GUARD:
        return False
    return (protect & 0xFF) in READABLE_PROTECT


# 扫描一个已打开进程的可读内存，提取密钥或数据目录。
def _scan_process_regions(
    pid: int,
    extractor: Callable[[bytes], Iterable[str]],
    *,
    private_only: bool,
    on_status: Callable[[str], object] | None = None,
    stop_event: object | None = None,
) -> list[str]:
    handle = _open_process(int(pid), PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
    if handle is None:
        error = ctypes.get_last_error()
        if error == 5:
            raise WindowsProbeError("无法读取微信进程内存，请以管理员身份运行本工具")
        raise WindowsProbeError("无法打开微信进程")
    kernel32 = _kernel32()
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.ReadProcessMemory.restype = ctypes.c_int
    found: list[str] = []
    seen: set[str] = set()
    address = 0
    max_address = (1 << 48) - 1
    try:
        while address < max_address:
            if getattr(stop_event, "is_set", lambda: False)():
                break
            info = _MEMORY_BASIC_INFORMATION()
            result = kernel32.VirtualQueryEx(
                ctypes.c_void_p(handle),
                ctypes.c_void_p(address),
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if not result:
                break
            base = int(info.BaseAddress or 0)
            size = int(info.RegionSize or 0)
            next_address = base + size if size else address + 0x10000
            if next_address <= address:
                break
            readable = (
                info.State == MEM_COMMIT
                and _is_readable_protect(int(info.Protect or 0))
                and size > 0
                and size <= MAX_REGION_SIZE
                and (not private_only or int(info.Type or 0) == MEM_PRIVATE)
            )
            if readable:
                overlap = b""
                offset = 0
                while offset < size:
                    if getattr(stop_event, "is_set", lambda: False)():
                        break
                    request = min(CHUNK_SIZE, size - offset)
                    buffer = ctypes.create_string_buffer(request)
                    read = ctypes.c_size_t(0)
                    ok = kernel32.ReadProcessMemory(
                        ctypes.c_void_p(handle),
                        ctypes.c_void_p(base + offset),
                        buffer,
                        request,
                        ctypes.byref(read),
                    )
                    chunk = buffer.raw[: int(read.value)] if ok and read.value else b""
                    payload = overlap + chunk
                    if payload:
                        for item in extractor(payload):
                            if item not in seen:
                                seen.add(item)
                                found.append(item)
                    overlap = payload[-CHUNK_OVERLAP:] if payload else b""
                    offset += request
            address = next_address
    finally:
        _close_handle(handle)
    return found


# 从微信进程内存中收集候选 32 字节密钥。
def scan_process_memory_keys(
    pid: int,
    *,
    on_status: Callable[[str], object] | None = None,
    stop_event: object | None = None,
) -> list[str]:
    keys = _scan_process_regions(
        pid,
        extract_hex_keys_from_bytes,
        private_only=True,
        on_status=on_status,
        stop_event=stop_event,
    )
    if keys or getattr(stop_event, "is_set", lambda: False)():
        return keys
    if on_status is not None:
        try:
            on_status("私有内存未找到密钥，继续扫描全部可读区域")
        except Exception:
            pass
    return _scan_process_regions(
        pid,
        extract_hex_keys_from_bytes,
        private_only=False,
        on_status=on_status,
        stop_event=stop_event,
    )


# 从正在运行的微信进程内存中收集数据目录路径。
def list_running_wechat_data_dirs(
    pid: int | None = None,
    *,
    on_status: Callable[[str], object] | None = None,
    stop_event: object | None = None,
) -> list[Path]:
    target = pid if pid is not None else find_windows_wechat_pid()
    if target is None:
        return []
    values = _scan_process_regions(
        target,
        extract_data_dirs_from_bytes,
        private_only=True,
        on_status=on_status,
        stop_event=stop_event,
    )
    paths: list[Path] = []
    seen: set[str] = set()
    for item in values:
        path = Path(item)
        if path.name.casefold() == "db_storage":
            path = path.parent.parent if path.parent.name else path
        elif path.parent.name.casefold() == "xwechat_files":
            path = path.parent
        key = str(path).casefold()
        if key in seen:
            continue
        seen.add(key)
        paths.append(path)
    return paths


# 请求启动本机已安装的微信客户端。
def launch_windows_wechat() -> tuple[bool, str]:
    processes = list_windows_wechat_processes()
    if processes:
        return True, "微信客户端已在运行"
    for candidate in windows_wechat_executable_candidates():
        if not candidate.is_file():
            continue
        try:
            os.startfile(str(candidate))  # type: ignore[attr-defined]
            return True, "已请求启动微信客户端"
        except OSError:
            continue
    return False, "未找到 Weixin.exe，请先手动启动微信 4.x"


__all__ = [
    "WECHAT_PROCESS_NAMES",
    "WindowsProbeError",
    "WindowsProcessInfo",
    "check_process_memory_access",
    "extract_data_dirs_from_bytes",
    "extract_hex_keys_from_bytes",
    "find_windows_wechat_pid",
    "find_windows_wechat_version",
    "is_current_user_admin",
    "launch_windows_wechat",
    "list_running_wechat_data_dirs",
    "list_windows_data_root_candidates",
    "list_windows_wechat_processes",
    "normalize_windows_data_root",
    "read_windows_file_version",
    "scan_process_memory_keys",
    "windows_documents_dir",
    "windows_registry_file_save_paths",
    "windows_wechat_executable_candidates",
]
