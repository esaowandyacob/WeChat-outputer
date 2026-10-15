"""Windows 版密钥提取：枚举 Weixin.exe 进程并用 ReadProcessMemory 扫描内存。

与 Linux 版（wxwatch/keyscan.py）共用密钥正则、salt 收集与 page-1 HMAC 校验，
仅进程枚举与内存读取走 Win32 API。ctypes.windll 只在本模块的函数内访问，
因此在 Linux 上 import 本模块不会报错，仅真正调用时会得到清晰的平台错误。

需要「以管理员身份运行」（OpenProcess(PROCESS_VM_READ) 读其他进程内存，
普通权限会被拒绝）。微信 4.x 进程名为 Weixin.exe，旧版为 WeChat.exe，都尝试。
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from pathlib import Path

from wxwatch.keyscan import (_scan_chunk, collect_db_salts, match_keys_to_dbs,
                             write_keys_file)

# ---- Win32 常量 ----
TH32CS_SNAPPROCESS = 0x00000002
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_GUARD = 0x100
# 所有"含读权限"的页保护属性
_READABLE_PROTECTS = frozenset({
    0x02,  # PAGE_READONLY
    0x04,  # PAGE_READWRITE
    0x08,  # PAGE_WRITECOPY
    0x20,  # PAGE_EXECUTE_READ
    0x40,  # PAGE_EXECUTE_READWRITE
    0x80,  # PAGE_EXECUTE_WRITECOPY
})
# 可写区域（堆，密钥字符串最可能出现）作为第一梯队优先扫
_RW_PROTECTS = frozenset({0x04, 0x08, 0x40, 0x80})

# 单次 ReadProcessMemory 的上限，避免一次性吃掉过多内存
_CHUNK = 16 * 1024 * 1024
# 单块区域超 2GB 跳过（与 Linux 版一致）
_MAX_REGION = 2 * 1024 * 1024 * 1024
# 64 位用户态地址上限
_MAX_ADDR = 0x7FFFFFFFFFFF

_INVALID_HANDLE = ctypes.c_void_p(-1).value  # INVALID_HANDLE_VALUE


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),  # ULONG_PTR
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),  # MAX_PATH
    ]


class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    """64 位进程的 MEMORY_BASIC_INFORMATION（含对齐填充，共 48 字节）。

    微信 4.x 为 64 位进程；本工具也只支持 64 位 Windows + 64 位 Python。
    """
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", wintypes.DWORD),
        ("__alignment1", wintypes.DWORD),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("__alignment2", wintypes.DWORD),
    ]


def _win32():
    """延迟获取绑定好原型的 kernel32；非 Windows 平台给出明确错误而非 AttributeError。"""
    if sys.platform != "win32":
        raise RuntimeError("keyscan_win 仅支持 Windows；Linux 请使用 wxwatch.keyscan")
    k = ctypes.windll.kernel32
    # Win64 下 HANDLE 是 64 位指针，必须显式声明 restype，否则被截断为 int
    k.OpenProcess.restype = wintypes.HANDLE
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k.VirtualQueryEx.restype = ctypes.c_size_t
    k.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                 ctypes.POINTER(MEMORY_BASIC_INFORMATION64),
                                 ctypes.c_size_t]
    k.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    return k


def _find_pids_by_name(exe_name: str) -> list[int]:
    """用 CreateToolhelp32Snapshot 枚举进程，返回 exe 名匹配（不区分大小写）的 pid。"""
    k = _win32()
    snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == _INVALID_HANDLE:
        raise OSError(f"CreateToolhelp32Snapshot 失败: {ctypes.get_last_error()}")
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        pids: list[int] = []
        ok = k.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.lower() == exe_name.lower():
                pids.append(entry.th32ProcessID)
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)  # 防御：每轮重置 dwSize
            ok = k.Process32NextW(snap, ctypes.byref(entry))
        return pids
    finally:
        k.CloseHandle(snap)


def find_wechat_pids() -> list[int]:
    """定位微信进程 pid 列表：先找 Weixin.exe（4.x），找不到再试 WeChat.exe（旧版）。"""
    for exe in ("Weixin.exe", "WeChat.exe"):
        pids = _find_pids_by_name(exe)
        if pids:
            for pid in pids:
                print(f"  发现微信进程: {exe} pid={pid}")
            return pids
    raise RuntimeError("未找到运行中的微信进程（Weixin.exe / WeChat.exe）。"
                       "请先启动并登录微信。")


def find_wechat_pid() -> int:
    """与 Linux 版 keyscan.find_wechat_pid 对应的单 pid 接口（status/GUI 检测用）。"""
    return find_wechat_pids()[0]


class _ProcessMemory:
    """打开的进程句柄 + 绑定好原型的 kernel32，避免每个读块重复绑定。"""

    def __init__(self, pid: int):
        self.k = _win32()
        self.handle = self.k.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not self.handle:
            err = ctypes.get_last_error()
            raise PermissionError(f"OpenProcess(pid={pid}) 失败，Win32 错误码 {err}"
                                  "（5=拒绝访问，需以管理员身份运行）")

    def close(self):
        if self.handle:
            self.k.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def regions(self) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
        """VirtualQueryEx 枚举内存区域，返回 (可写区域, 其他可读区域)。

        只保留 MEM_PRIVATE 且已提交（MEM_COMMIT）、含读权限、非 PAGE_GUARD 的区域；
        单块超 2GB 跳过。可写区域（堆）是第一梯队，与 Linux 版的分层策略一致。
        """
        rw: list[tuple[int, int]] = []
        other: list[tuple[int, int]] = []
        mbi = MEMORY_BASIC_INFORMATION64()
        addr = 0
        while addr < _MAX_ADDR:
            n = self.k.VirtualQueryEx(self.handle, ctypes.c_void_p(addr),
                                      ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not n:
                break  # 到达地址空间顶部
            base, size = int(mbi.BaseAddress), int(mbi.RegionSize)
            protect = mbi.Protect
            if (mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE
                    and protect in _READABLE_PROTECTS and not protect & PAGE_GUARD
                    and 0 < size <= _MAX_REGION):
                (rw if protect in _RW_PROTECTS else other).append((base, size))
            if size == 0:
                break  # 防御：RegionSize 异常时避免死循环
            addr = base + size
        return rw, other

    def read_chunk(self, addr: int, size: int) -> bytes:
        """ReadProcessMemory 读一块内存；失败（页被释放等）返回空字节串。"""
        buf = (ctypes.c_char * size)()
        read = ctypes.c_size_t(0)
        ok = self.k.ReadProcessMemory(self.handle, ctypes.c_void_p(addr), buf,
                                      size, ctypes.byref(read))
        return buf.raw[: read.value] if ok else b""

    def scan(self, regions: list[tuple[int, int]]) -> dict[bytes, bytes]:
        """扫描给定区域列表，返回 {salt: key} 候选（匹配复用 keyscan._scan_chunk）。"""
        found: dict[bytes, bytes] = {}
        for base, size in regions:
            pos = 0
            while pos < size:
                data = self.read_chunk(base + pos, min(_CHUNK, size - pos))
                if not data:
                    break  # 区域被释放或部分页不可读，跳过剩余部分
                _scan_chunk(data, found)
                # 重叠 100 字节防止跨块边界漏匹配（密钥串 99 字节，与 Linux 版一致）
                pos += max(1, len(data) - 100)
        return found


def extract_keys_win(db_storage: Path, out_file: Path) -> dict:
    """主流程：枚举 Weixin.exe → 扫内存 → 匹配 salt → 验证 → 写 keys.json。

    输出格式与 Linux 版完全一致：{rel_db_path(POSIX 分隔符): {"key","salt"}}。
    文件权限：Windows 无 POSIX 权限位，keys.json 依赖用户目录 ACL（默认仅本人）。
    """
    pids = find_wechat_pids()
    db_salts = collect_db_salts(db_storage)
    print(f"[*] 在 {db_storage} 下发现 {len(db_salts)} 个加密数据库")

    candidates: dict[bytes, bytes] = {}
    for pid in pids:
        try:
            mem = _ProcessMemory(pid)
        except PermissionError as e:
            print(f"  [跳过] {e}")
            continue
        print(f"[*] 扫描进程 {pid} 内存 ...")
        with mem:
            rw, other = mem.regions()
            found = mem.scan(rw)
            print(f"[*] 可写区域扫描得到 {len(found)} 个候选密钥")
            if not found:
                print("[*] 未找到，扩大范围扫描其余可读区域（较慢）...")
                found = mem.scan(other)
                print(f"[*] 全量扫描得到 {len(found)} 个候选密钥")
        for salt, key in found.items():
            candidates.setdefault(salt, key)
        if db_salts and all(s in candidates for s in db_salts):
            break  # 已覆盖全部本地库，不必再扫其他微信子进程

    if not candidates:
        raise RuntimeError("内存中未找到密钥字符串。微信是否已登录？")

    keys = match_keys_to_dbs(candidates, db_salts, db_storage)
    write_keys_file(keys, out_file)
    return keys


def main(argv=None):
    import argparse

    p = argparse.ArgumentParser(description="从微信进程内存提取数据库密钥（Windows，需管理员）")
    p.add_argument("--db-storage", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args(argv)
    try:
        extract_keys_win(args.db_storage, args.out)
    except PermissionError as e:
        print(f"[ERR] 权限不足: {e}\n      请右键「以管理员身份运行」终端后重试",
              file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
