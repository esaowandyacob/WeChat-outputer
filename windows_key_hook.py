"""Windows 微信 4.x 动态下断：在 sqlite3_key / setCipherKey 上抓密钥参数。

用法（管理员 PowerShell，微信已启动或即将扫码登录）：

    python -m pip install frida
    python windows_key_hook.py

然后在微信里登录或打开几个会话。命中后会用 SQLCipher HMAC 校验并写入密钥文件。
Ctrl+C 结束。需要 64 位 Python + 管理员权限。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

from cccryptor_probe import default_key_path, mask_key, save_validated_key
from read_wechat_conversation import (
    discover_message_databases,
    read_sqlcipher_salt,
    sqlcipher4_raw_key_matches,
)
from windows_memory_probe import list_windows_wechat_processes, python_pointer_bits, windows_wechat_executable_candidates


HOOK_JS = Path(__file__).resolve().parent / "windows_key_hook.js"


# 从下断读到的缓冲区生成待验密钥（raw 32 字节或 16 字节口令派生）。
def iter_hook_key_candidates(key_hex: str, nkey: int | None = None) -> list[str]:
    text = "".join(character for character in (key_hex or "") if character in "0123456789abcdefABCDEF").lower()
    if len(text) < 32:
        return []
    found: list[str] = []
    if len(text) >= 64:
        found.append(text[:64])
    if len(text) >= 96:
        found.append(text[:64])
    if nkey == 32 and len(text) >= 64:
        found.append(text[:64])
    if nkey == 48 and len(text) >= 96:
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
        key = hashlib.pbkdf2_hmac("sha512", material, salt, 256000, dklen=32)
        derived.append(key.hex())
        key_text = hashlib.pbkdf2_hmac("sha512", text[:32].encode("ascii"), salt, 256000, dklen=32)
        derived.append(key_text.hex())
    unique: list[str] = []
    seen: set[str] = set()
    for item in derived:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


# 用各库第一页 HMAC 验证候选，返回命中的数据库文件名。
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


# 加载本机加密库第一页，供 HMAC 校验。
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


# 选择要附加的微信 PID：默认工作集最大的主进程。
def select_targets(all_processes: bool) -> list[int]:
    processes = list_windows_wechat_processes()
    if not processes:
        return []
    ordered = sorted(processes, key=lambda item: -item.working_set)
    if all_processes:
        return [item.pid for item in ordered]
    return [ordered[0].pid]


# 处理 Frida 回调：打印探针并尝试验证保存。
def handle_payload(
    payload: dict,
    pages: dict[str, tuple[Path, bytes]],
    key_path: Path,
    log_lines: list[str],
) -> int:
    kind = payload.get("type")
    if kind == "ready":
        line = f"钩子已就绪，已下断 {payload.get('hooked', 0)} 处。请在微信中登录或打开会话。"
        print(line)
        log_lines.append(line)
        return 0
    if kind == "module":
        line = f"模块 {payload.get('name')} base={payload.get('base')} size={payload.get('size')} exports={payload.get('exports')}"
        print(line)
        log_lines.append(line)
        return 0
    if kind == "hook":
        line = f"下断 {payload.get('name')} @ {payload.get('address')} variant={payload.get('variant')}"
        print(line)
        log_lines.append(line)
        return 0
    if kind != "call":
        line = f"其它消息：{json.dumps(payload, ensure_ascii=False)[:300]}"
        print(line)
        log_lines.append(line)
        return 0
    nkey = int(payload.get("nKey") or 0)
    hex_blob = str(payload.get("hex") or payload.get("extra32") or "")
    line = (
        f"命中 {payload.get('name')} nKey={nkey} db={payload.get('dbName')!r} "
        f"hex={mask_key(hex_blob) if len(hex_blob) >= 16 else hex_blob[:32]}"
    )
    print(line)
    log_lines.append(line)
    saved = 0
    candidates = iter_hook_key_candidates(hex_blob, nkey)
    if nkey == 16 or (len(hex_blob) >= 32 and nkey not in {32, 48, 64}):
        salts = {salt: page[:16] for salt, (_path, page) in pages.items()}
        candidates.extend(iter_passphrase_candidates(hex_blob, salts))
    regs = payload.get("regs") or {}
    for name in ("rdx_hex32", "r8_hex32", "rcx_hex32", "r9_hex32"):
        extra = str(regs.get(name) or "")
        candidates.extend(iter_hook_key_candidates(extra, 32))
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
        log_lines.append("  本次命中未通过 HMAC（参数已记录，密钥可能在其它寄存器或已派生）")
    return saved


def main() -> int:
    parser = argparse.ArgumentParser(description="对微信 sqlite3_key / setCipherKey 动态下断")
    parser.add_argument("--pid", type=int, default=0, help="指定 PID，默认附加工作集最大的 Weixin.exe")
    parser.add_argument("--all", action="store_true", help="附加所有 Weixin.exe")
    parser.add_argument("--spawn", action="store_true", help="由脚本启动微信再附加（部分反调试有效）")
    parser.add_argument("--timeout", type=int, default=0, help="秒后自动结束，0 表示直到 Ctrl+C")
    parser.add_argument("--data-root", default="", help="微信数据目录，默认自动检测")
    args = parser.parse_args()
    log_lines = ["=== Windows sqlite3_key 动态下断 ==="]
    if sys.platform != "win32":
        print("请在 Windows 上运行本脚本。")
        return 2
    if python_pointer_bits() < 64:
        print("请使用 64 位 Python。")
        return 2
    try:
        import frida
    except ImportError:
        print("未安装 frida。请先：python -m pip install frida")
        return 2
    if not HOOK_JS.is_file():
        print(f"找不到 {HOOK_JS}")
        return 2
    source = HOOK_JS.read_text(encoding="utf-8")
    data_root = Path(args.data_root).expanduser() if args.data_root.strip() else None
    pages = load_pages(data_root)
    log_lines.append(f"加密库第一页：{len(pages)} 个")
    print(f"已加载 {len(pages)} 个加密 message_N.db 用于 HMAC。")
    key_path = default_key_path()
    device = frida.get_local_device()
    sessions = []
    pids: list[int] = []
    if args.spawn:
        exe = next((item for item in windows_wechat_executable_candidates() if item.is_file()), None)
        if exe is None:
            print("找不到 Weixin.exe，请先手动启动微信。")
            return 1
        print(f"spawn {exe}")
        pid = device.spawn([str(exe)])
        pids = [pid]
        session = device.attach(pid)
        sessions.append(session)
        device.resume(pid)
        log_lines.append(f"spawn PID {pid}")
    else:
        pids = [args.pid] if args.pid else select_targets(args.all)
        if not pids:
            print("未找到 Weixin.exe。请先启动微信，或以管理员运行本脚本。")
            return 1
        for pid in pids:
            try:
                session = device.attach(pid)
                sessions.append(session)
                log_lines.append(f"已附加 PID {pid}")
                print(f"已附加 PID {pid}")
            except Exception as exc:
                line = f"附加 PID {pid} 失败：{type(exc).__name__}: {exc}"
                print(line)
                log_lines.append(line)
    if not sessions:
        print("没有任何进程附加成功。")
        return 1
    saved_total = 0

    def on_message(message: dict, _data: bytes | None) -> None:
        nonlocal saved_total
        if message.get("type") == "error":
            line = f"脚本错误：{message.get('stack') or message.get('description')}"
            print(line)
            log_lines.append(line)
            return
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return
        saved_total += handle_payload(payload, pages, key_path, log_lines)

    scripts = []
    for session in sessions:
        script = session.create_script(source)
        script.on("message", on_message)
        script.load()
        scripts.append(script)
    print("下断已安装。请切换到微信：登录或打开几个聊天窗口。Ctrl+C 结束。")
    started = time.monotonic()
    try:
        while True:
            if args.timeout and time.monotonic() - started >= args.timeout:
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n结束下断。")
    finally:
        for script in scripts:
            try:
                script.unload()
            except Exception:
                pass
        for session in sessions:
            try:
                session.detach()
            except Exception:
                pass
        log_lines.append(f"保存成功 {saved_total} 个，密钥文件 {key_path}")
        try:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            (key_path.parent / "last_key_hook.txt").write_text("\n".join(log_lines) + "\n", encoding="utf-8")
            print(f"探针日志：{key_path.parent / 'last_key_hook.txt'}")
        except OSError:
            pass
    return 0 if saved_total else 1


if __name__ == "__main__":
    raise SystemExit(main())
