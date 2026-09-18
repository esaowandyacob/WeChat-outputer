"""Windows 微信 4.x 动态下断：默认用调试器硬件断点，不注入 DLL。

微信会把 frida-agent.dll 当成故障模块直接崩溃，因此默认不用 Frida。

管理员 PowerShell：

    python windows_key_hook.py

附加后去微信里登录或打开会话。Ctrl+C 结束，且不会杀掉微信。
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import os
import signal
import struct
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path

from cccryptor_probe import default_key_path, mask_key, save_validated_key
from read_wechat_conversation import (
    discover_message_databases,
    read_sqlcipher_salt,
    sqlcipher4_raw_key_matches,
)
from windows_memory_probe import (
    list_windows_wechat_processes,
    python_pointer_bits,
    windows_wechat_executable_candidates,
)


HOOK_JS = Path(__file__).resolve().parent / "windows_key_hook.js"

PROCESS_ALL_ACCESS = 0x1F0FFF
THREAD_ALL_ACCESS = 0x1F03FF
DEBUG_PROCESS = 0x00000001
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9
CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x2
CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10
CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
TH32CS_SNAPTHREAD = 0x00000004
NEEDLES = (
    b"sqlite3_key\x00",
    b"sqlite3_key_v2\x00",
    b"sqlite3_rekey\x00",
    b"SetDBKey",
    b"setCipherKey",
    b"sqlcipher_codec_ctx_set_pass\x00",
    b"sqlcipher_codec_ctx_set_kdf\x00",
)


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True) if sys.platform == "win32" else None


class M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_uint64), ("High", ctypes.c_int64)]


class XMM_SAVE_AREA32(ctypes.Structure):
    _fields_ = [
        ("ControlWord", ctypes.c_uint16),
        ("StatusWord", ctypes.c_uint16),
        ("TagWord", ctypes.c_byte),
        ("Reserved1", ctypes.c_byte),
        ("ErrorOpcode", ctypes.c_uint16),
        ("ErrorOffset", ctypes.c_uint32),
        ("ErrorSelector", ctypes.c_uint16),
        ("Reserved2", ctypes.c_uint16),
        ("DataOffset", ctypes.c_uint32),
        ("DataSelector", ctypes.c_uint16),
        ("Reserved3", ctypes.c_uint16),
        ("MxCsr", ctypes.c_uint32),
        ("MxCsr_Mask", ctypes.c_uint32),
        ("FloatRegisters", M128A * 8),
        ("XmmRegisters", M128A * 16),
        ("Reserved4", ctypes.c_byte * 96),
    ]


class CONTEXT64(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_uint64),
        ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64),
        ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64),
        ("P6Home", ctypes.c_uint64),
        ("ContextFlags", ctypes.c_uint32),
        ("MxCsr", ctypes.c_uint32),
        ("SegCs", ctypes.c_uint16),
        ("SegDs", ctypes.c_uint16),
        ("SegEs", ctypes.c_uint16),
        ("SegFs", ctypes.c_uint16),
        ("SegGs", ctypes.c_uint16),
        ("SegSs", ctypes.c_uint16),
        ("EFlags", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint64),
        ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64),
        ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64),
        ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64),
        ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64),
        ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64),
        ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64),
        ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64),
        ("R9", ctypes.c_uint64),
        ("R10", ctypes.c_uint64),
        ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64),
        ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64),
        ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
        ("FltSave", XMM_SAVE_AREA32),
        ("VectorRegister", M128A * 26),
        ("VectorControl", ctypes.c_uint64),
        ("DebugControl", ctypes.c_uint64),
        ("LastBranchToRip", ctypes.c_uint64),
        ("LastBranchFromRip", ctypes.c_uint64),
        ("LastExceptionToRip", ctypes.c_uint64),
        ("LastExceptionFromRip", ctypes.c_uint64),
    ]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ("u", ctypes.c_byte * 176),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * 260),
    ]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
    ]


# 从下断读到的缓冲区生成待验密钥（raw 32 字节或 16 字节口令派生）。
def iter_hook_key_candidates(key_hex: str, nkey: int | None = None) -> list[str]:
    text = "".join(character for character in (key_hex or "") if character in "0123456789abcdefABCDEF").lower()
    if len(text) < 32:
        return []
    found: list[str] = []
    if len(text) >= 64:
        found.append(text[:64])
    unique: list[str] = []
    seen: set[str] = set()
    for item in found:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


# 把 16 字节材料按 SQLCipher 4 口令对每个库做 PBKDF2。
def iter_passphrase_candidates(raw16_hex: str, salts: dict[str, bytes]) -> list[str]:
    text = (raw16_hex or "").lower()
    if len(text) < 32:
        return []
    material = bytes.fromhex(text[:32])
    derived: list[str] = []
    for salt in salts.values():
        derived.append(hashlib.pbkdf2_hmac("sha512", material, salt, 256000, dklen=32).hex())
        derived.append(hashlib.pbkdf2_hmac("sha512", text[:32].encode("ascii"), salt, 256000, dklen=32).hex())
    unique: list[str] = []
    seen: set[str] = set()
    for item in derived:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def validate_against_pages(key_hex: str, pages: dict[str, tuple[Path, bytes]]) -> list[str]:
    matched: list[str] = []
    try:
        raw = bytes.fromhex(key_hex)
    except ValueError:
        return []
    if len(raw) != 32:
        return []
    for _salt_hex, (path, page) in pages.items():
        if sqlcipher4_raw_key_matches(page, raw):
            matched.append(path.name)
    return matched


def load_pages(data_root: Path | None = None) -> dict[str, tuple[Path, bytes]]:
    pages: dict[str, tuple[Path, bytes]] = {}
    for path in discover_message_databases(data_root):
        salt = read_sqlcipher_salt(path)
        if salt is None:
            continue
        try:
            pages[salt.hex()] = (path, path.read_bytes()[:4096])
        except OSError:
            continue
    return pages


def select_targets(all_processes: bool) -> list[int]:
    processes = list_windows_wechat_processes()
    if not processes:
        return []
    ordered = sorted(processes, key=lambda item: -item.working_set)
    if all_processes:
        return [item.pid for item in ordered]
    return [ordered[0].pid]


def _read_process_memory(handle: int, address: int, size: int) -> bytes:
    buffer = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    kernel32.ReadProcessMemory.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    if not kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(read)):
        return b""
    return buffer.raw[: int(read.value)]


def list_modules(pid: int) -> list[tuple[str, int, int]]:
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snapshot in (0, ctypes.c_void_p(-1).value):
        return []
    entry = MODULEENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    modules: list[tuple[str, int, int]] = []
    kernel32.Module32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(MODULEENTRY32W)]
    more = kernel32.Module32FirstW(ctypes.c_void_p(snapshot), ctypes.byref(entry))
    while more:
        base = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0
        modules.append((str(entry.szModule), int(base), int(entry.modBaseSize)))
        more = kernel32.Module32NextW(ctypes.c_void_p(snapshot), ctypes.byref(entry))
    kernel32.CloseHandle(ctypes.c_void_p(snapshot))
    return modules


def list_threads(pid: int) -> list[int]:
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snapshot in (0, ctypes.c_void_p(-1).value):
        return []
    entry = THREADENTRY32()
    entry.dwSize = ctypes.sizeof(entry)
    threads: list[int] = []
    kernel32.Thread32First.argtypes = [ctypes.c_void_p, ctypes.POINTER(THREADENTRY32)]
    kernel32.Thread32Next.argtypes = [ctypes.c_void_p, ctypes.POINTER(THREADENTRY32)]
    more = kernel32.Thread32First(ctypes.c_void_p(snapshot), ctypes.byref(entry))
    while more:
        if int(entry.th32OwnerProcessID) == pid:
            threads.append(int(entry.th32ThreadID))
        more = kernel32.Thread32Next(ctypes.c_void_p(snapshot), ctypes.byref(entry))
    kernel32.CloseHandle(ctypes.c_void_p(snapshot))
    return threads


def parse_exports(handle: int, base: int) -> list[str]:
    header = _read_process_memory(handle, base, 4096)
    if len(header) < 64 or header[:2] != b"MZ":
        return []
    e_lfanew = int.from_bytes(header[60:64], "little")
    pe = _read_process_memory(handle, base + e_lfanew, 512)
    if pe[:4] != b"PE\x00\x00":
        return []
    magic = int.from_bytes(pe[24:26], "little")
    if magic == 0x20B:
        export_rva = int.from_bytes(pe[24 + 112 : 24 + 116], "little")
    else:
        export_rva = int.from_bytes(pe[24 + 96 : 24 + 100], "little")
    if not export_rva:
        return []
    directory = _read_process_memory(handle, base + export_rva, 40)
    if len(directory) < 40:
        return []
    names_rva = int.from_bytes(directory[32:36], "little")
    count = int.from_bytes(directory[24:28], "little")
    count = min(count, 512)
    names: list[str] = []
    table = _read_process_memory(handle, base + names_rva, count * 4)
    for index in range(count):
        rva = int.from_bytes(table[index * 4 : index * 4 + 4], "little")
        raw = _read_process_memory(handle, base + rva, 128)
        name = raw.split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        if name:
            names.append(name)
    return names


def find_bytes(blob: bytes, needle: bytes) -> list[int]:
    hits: list[int] = []
    start = 0
    while True:
        index = blob.find(needle, start)
        if index < 0:
            return hits
        hits.append(index)
        start = index + 1


def find_rip_leas(code: bytes, code_base: int, target: int) -> list[int]:
    hits: list[int] = []
    for index in range(0, max(0, len(code) - 7)):
        prefix = code[index]
        if prefix not in (0x48, 0x4C, 0x4A, 0x49) or code[index + 1] != 0x8D:
            continue
        if (code[index + 2] & 0xC7) != 0x05:
            continue
        rel = int.from_bytes(code[index + 3 : index + 7], "little", signed=True)
        if code_base + index + 7 + rel == target:
            hits.append(code_base + index)
    return hits


def apply_hardware_breakpoints(tids: list[int], addresses: list[int]) -> int:
    applied = 0
    addrs = addresses[:4]
    for tid in tids:
        handle = kernel32.OpenThread(THREAD_ALL_ACCESS, False, tid)
        if not handle:
            continue
        context = CONTEXT64()
        context.ContextFlags = CONTEXT_FULL
        if kernel32.GetThreadContext(handle, ctypes.byref(context)):
            regs = [0, 0, 0, 0]
            for index, address in enumerate(addrs):
                regs[index] = address
            context.Dr0, context.Dr1, context.Dr2, context.Dr3 = regs
            enable = 0
            for index, address in enumerate(addrs):
                if address:
                    enable |= 1 << (index * 2)
            context.Dr7 = enable
            if kernel32.SetThreadContext(handle, ctypes.byref(context)):
                applied += 1
        kernel32.CloseHandle(handle)
    return applied


def read_pointer_block(process: int, address: int, size: int = 32) -> str:
    if address < 0x10000:
        return ""
    data = _read_process_memory(process, address, size)
    return data.hex()


def handle_hit(
    process: int,
    context: CONTEXT64,
    pages: dict[str, tuple[Path, bytes]],
    key_path: Path,
    log_lines: list[str],
) -> int:
    blobs = [
        ("rdx", context.Rdx, context.R8 if context.R8 < 128 else 32),
        ("r8", context.R8, context.R9 if context.R9 < 128 else 32),
        ("rcx", context.Rcx, 32),
        ("r9", context.R9, 32),
    ]
    line = (
        f"命中 RIP=0x{context.Rip:x} rcx=0x{context.Rcx:x} rdx=0x{context.Rdx:x} "
        f"r8=0x{context.R8:x} r9=0x{context.R9:x}"
    )
    print(line)
    log_lines.append(line)
    saved = 0
    candidates: list[str] = []
    for name, address, length in blobs:
        length = int(length) if 8 <= int(length) <= 64 else 32
        hex_blob = read_pointer_block(process, int(address), length)
        if not hex_blob:
            continue
        shown = mask_key(hex_blob) if len(hex_blob) >= 16 else hex_blob
        log_lines.append(f"  {name}@0x{address:x} len={length} {shown}")
        candidates.extend(iter_hook_key_candidates(hex_blob, length))
        if length == 16:
            salts = {salt: page[:16] for salt, (_path, page) in pages.items()}
            candidates.extend(iter_passphrase_candidates(hex_blob, salts))
    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        matched = validate_against_pages(candidate, pages)
        if not matched:
            continue
        record = save_validated_key(candidate, matched, key_path)
        saved += 1
        ok = f"已验证并保存 {record.masked} -> {','.join(matched)}"
        print(ok)
        log_lines.append(ok)
    if saved == 0:
        log_lines.append("  本次命中未通过 HMAC")
    return saved


def run_debugger(pid: int, pages: dict[str, tuple[Path, bytes]], key_path: Path, timeout: int, log_lines: list[str]) -> int:
    kernel32.DebugActiveProcess.argtypes = [wintypes.DWORD]
    kernel32.DebugActiveProcess.restype = wintypes.BOOL
    kernel32.DebugSetProcessKillOnExit.argtypes = [wintypes.BOOL]
    kernel32.DebugActiveProcessStop.argtypes = [wintypes.DWORD]
    if not kernel32.DebugActiveProcess(pid):
        error = ctypes.get_last_error()
        print(f"DebugActiveProcess 失败 GetLastError={error}。请用管理员运行，并确认没有其它调试器。")
        return 1
    kernel32.DebugSetProcessKillOnExit(False)
    process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process:
        kernel32.DebugActiveProcessStop(pid)
        print("OpenProcess 失败。")
        return 1
    print(f"已调试附加 PID {pid}（不会在退出时杀掉微信）")
    log_lines.append(f"DebugActiveProcess PID {pid}")
    modules = list_modules(pid)
    weixin = next((item for item in modules if item[0].lower() == "weixin.dll"), None)
    if weixin is None:
        print("未找到 Weixin.dll")
        kernel32.DebugActiveProcessStop(pid)
        return 1
    name, base, size = weixin
    print(f"{name} base=0x{base:x} size={size}")
    log_lines.append(f"{name} base=0x{base:x} size={size}")
    exports = parse_exports(process, base)
    interesting = [item for item in exports if any(token in item.lower() for token in ("key", "cipher", "codec", "sql", "wcdb"))]
    log_lines.append(f"Weixin.dll 导出 {len(exports)} 个：{','.join(exports[:120])}")
    log_lines.append(f"相关导出：{interesting[:40]}")
    print(f"Weixin.dll 导出 {len(exports)} 个，名称含 key/cipher 的：{interesting[:20]}")
    read_size = min(size, 256 * 1024 * 1024)
    print(f"正在扫描 Weixin.dll {read_size // (1024 * 1024)} MB 字符串…")
    parts = bytearray()
    offset = 0
    while offset < read_size:
        chunk = _read_process_memory(process, base + offset, min(8 * 1024 * 1024, read_size - offset))
        if not chunk:
            break
        parts.extend(chunk)
        offset += len(chunk)
    blob = bytes(parts)
    log_lines.append(f"实际读到 {len(blob)} 字节")
    bp_addrs: list[int] = []
    for needle in NEEDLES:
        offsets = find_bytes(blob, needle)
        label = needle.split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        log_lines.append(f"字符串 {label!r} 命中 {len(offsets)} 次")
        print(f"字符串 {label!r} 命中 {len(offsets)} 次")
        for offset in offsets[:3]:
            target = base + offset
            xrefs = find_rip_leas(blob, base, target)
            log_lines.append(f"  VA 0x{target:x} RIP-LEA xref {len(xrefs)}：{[hex(item) for item in xrefs[:8]]}")
            for xref in xrefs[:2]:
                if xref not in bp_addrs:
                    bp_addrs.append(xref)
    if not bp_addrs:
        print("没有找到可用的 RIP 引用，无法下硬件断点。导出名和字符串结果已写入日志。")
    else:
        bp_addrs = bp_addrs[:4]
        tids = list_threads(pid)
        applied = apply_hardware_breakpoints(tids, bp_addrs)
        print(f"硬件断点 {len(bp_addrs)} 个，应用到 {applied}/{len(tids)} 个线程：{[hex(item) for item in bp_addrs]}")
        log_lines.append(f"硬件断点 {[hex(item) for item in bp_addrs]} threads={applied}")
    stop = threading.Event()

    def request_stop(_signum: int | None = None, _frame: object | None = None) -> None:
        print("\n正在停止调试…")
        stop.set()
        threading.Timer(3.0, lambda: os._exit(1)).start()

    signal.signal(signal.SIGINT, request_stop)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, request_stop)
    print("请在微信中登录或打开会话。Ctrl+C / Ctrl+Break 结束。")
    saved = 0
    started = time.monotonic()
    event = DEBUG_EVENT()
    kernel32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), wintypes.DWORD]
    kernel32.ContinueDebugEvent.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
    try:
        while not stop.is_set():
            if timeout and time.monotonic() - started >= timeout:
                print("已到超时时间。")
                break
            if not kernel32.WaitForDebugEvent(ctypes.byref(event), 500):
                continue
            code = int(event.dwDebugEventCode)
            continue_status = DBG_CONTINUE
            if code == EXCEPTION_DEBUG_EVENT:
                exc_code = int.from_bytes(bytes(event.u[0:4]), "little")
                if exc_code == EXCEPTION_SINGLE_STEP:
                    thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, event.dwThreadId)
                    if thread:
                        context = CONTEXT64()
                        context.ContextFlags = CONTEXT_FULL
                        if kernel32.GetThreadContext(thread, ctypes.byref(context)):
                            if context.Dr6 & 0x0F:
                                saved += handle_hit(int(process), context, pages, key_path, log_lines)
                        kernel32.CloseHandle(thread)
                    if saved:
                        print("已捕获可用密钥，准备退出。")
                        kernel32.ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE)
                        break
                elif exc_code != EXCEPTION_BREAKPOINT:
                    continue_status = DBG_EXCEPTION_NOT_HANDLED
            elif code == CREATE_THREAD_DEBUG_EVENT and bp_addrs:
                apply_hardware_breakpoints([int(event.dwThreadId)], bp_addrs)
            elif code == EXIT_PROCESS_DEBUG_EVENT:
                print("目标进程已退出。")
                kernel32.ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE)
                break
            kernel32.ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continue_status)
    finally:
        kernel32.DebugSetProcessKillOnExit(False)
        kernel32.DebugActiveProcessStop(pid)
        kernel32.CloseHandle(process)
    return saved


def run_frida(pid: int, pages: dict[str, tuple[Path, bytes]], key_path: Path, timeout: int, log_lines: list[str]) -> int:
    import frida

    print("警告：Frida 会注入 frida-agent.dll，微信 4.1 可能直接崩溃。")
    device = frida.get_local_device()
    session = device.attach(pid)
    source = HOOK_JS.read_text(encoding="utf-8")
    saved = 0

    def on_message(message: dict, _data: bytes | None) -> None:
        nonlocal saved
        if message.get("type") == "error":
            print("脚本错误：", message.get("description") or message.get("stack"))
            return
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return
        kind = payload.get("type")
        if kind in {"module", "hook", "ready"}:
            print(payload)
            log_lines.append(str(payload))
            return
        if kind != "call":
            return
        hex_blob = str(payload.get("hex") or payload.get("extra32") or "")
        nkey = int(payload.get("nKey") or 32)
        print(f"命中 {payload.get('name')} nKey={nkey} {mask_key(hex_blob) if len(hex_blob) >= 16 else hex_blob}")
        for candidate in iter_hook_key_candidates(hex_blob, nkey):
            matched = validate_against_pages(candidate, pages)
            if matched:
                record = save_validated_key(candidate, matched, key_path)
                saved += 1
                print(f"已验证并保存 {record.masked}")

    script = session.create_script(source)
    script.on("message", on_message)
    script.load()
    print("Frida 钩子已安装。Ctrl+C 结束。")
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    started = time.monotonic()
    while not stop.is_set() and not (timeout and time.monotonic() - started >= timeout):
        stop.wait(0.5)
    try:
        script.unload()
        session.detach()
    except Exception:
        pass
    return saved


def main() -> int:
    parser = argparse.ArgumentParser(description="微信 sqlite3_key 动态下断（默认硬件断点，不注入 DLL）")
    parser.add_argument("--pid", type=int, default=0)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--data-root", default="")
    parser.add_argument("--frida", action="store_true", help="改用 Frida（可能导致微信崩溃）")
    args = parser.parse_args()
    log_lines = ["=== Windows sqlite3_key 动态下断 ==="]
    if sys.platform != "win32":
        print("请在 Windows 上运行。")
        return 2
    if python_pointer_bits() < 64:
        print("请使用 64 位 Python。")
        return 2
    pages = load_pages(Path(args.data_root).expanduser() if args.data_root.strip() else None)
    print(f"已加载 {len(pages)} 个加密 message_N.db 用于 HMAC。")
    log_lines.append(f"加密库第一页：{len(pages)} 个")
    key_path = default_key_path()
    pids = [args.pid] if args.pid else select_targets(False)
    if not pids:
        print("未找到 Weixin.exe。")
        return 1
    pid = pids[0]
    saved = 0
    try:
        if args.frida:
            saved = run_frida(pid, pages, key_path, args.timeout, log_lines)
        else:
            saved = run_debugger(pid, pages, key_path, args.timeout, log_lines)
    finally:
        log_lines.append(f"保存成功 {saved} 个，密钥文件 {key_path}")
        try:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            (key_path.parent / "last_key_hook.txt").write_text("\n".join(log_lines) + "\n", encoding="utf-8")
            print(f"探针日志：{key_path.parent / 'last_key_hook.txt'}")
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
