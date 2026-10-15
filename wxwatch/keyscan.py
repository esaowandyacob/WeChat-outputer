"""从运行中的微信进程内存提取 SQLCipher 4 密钥。

原理：WCDB 会在进程内存里缓存 `x'<64hex enc_key><32hex salt>'` 形式的
密钥字符串。扫描 /proc/<pid>/mem，按 salt（各加密 db 文件头 16 字节）
归类候选，再用 sqlcipher3 实际打开验证。

需要 root（ptrace_scope=1 时读 /proc/pid/mem 必须有 CAP_SYS_PTRACE）。
用法：sudo .venv/bin/python main.py extract-keys
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from pathlib import Path

KEY_PATTERN = re.compile(rb"x'([0-9a-fA-F]{64})([0-9a-fA-F]{32})'")
# 单次读取的内存块上限，避免一次性吃掉过多内存
_CHUNK = 64 * 1024 * 1024


def find_wechat_pid() -> int:
    """定位微信主进程 pid（/usr/bin/wechat 或进程名 wechat）。"""
    candidates: list[tuple[int, str]] = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().split(b"\0")[0].decode(errors="replace")
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            continue
        base = os.path.basename(cmdline)
        if base == "wechat":  # 主进程，排除 WeChatAppEx / crashpad
            candidates.append((pid, cmdline))
    if not candidates:
        raise RuntimeError("未找到运行中的微信进程（wechat）。请先启动并登录微信。")
    # 主进程一般是最小的 pid；返回第一个并打印全部供排查
    for pid, cmd in candidates:
        print(f"  发现微信进程: pid={pid} cmd={cmd}")
    return candidates[0][0]


def _iter_memory_regions(pid: int):
    """按 maps 遍历进程内存区域。

    第一梯队：匿名 rw 页（堆，密钥字符串最可能在这里）。
    兜底梯队：其余匿名可读页（r--/r-x 的 brk/mmap 匿名段）。
    文件映射与设备映射（/dev/*）一律不读：密钥不可能在其中，
    且读设备映射在部分系统上有副作用 —— 这是刻意的安全收窄。
    """
    rw_anon, other_anon = [], []
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 2 or "r" not in parts[1]:
                continue
            path = parts[5] if len(parts) >= 6 else ""
            # 只保留匿名映射（无路径）与 [heap]/[stack]/[anon:*] 等特殊匿名段；
            # 文件映射与设备映射（/dev/*）一律不读：密钥不可能在其中，
            # 且读设备映射在部分系统上有副作用 —— 这是刻意的安全收窄。
            if path and not path.startswith("["):
                continue
            start_s, end_s = parts[0].split("-")
            start, end = int(start_s, 16), int(end_s, 16)
            if end - start > 2 * 1024 * 1024 * 1024:  # 单区域超 2GB 跳过
                continue
            if parts[1].startswith("rw"):
                rw_anon.append((start, end))
            else:
                other_anon.append((start, end))
    return rw_anon, other_anon


def _scan_chunk(data: bytes, found: dict[bytes, bytes]) -> None:
    """在单块内存数据中匹配密钥字符串，累积到 found（同一 salt 先到先赢）。

    Windows 版（keyscan_win）复用本函数，保证两端匹配行为完全一致。
    """
    for m in KEY_PATTERN.finditer(data):
        key = bytes.fromhex(m.group(1).decode())
        salt = bytes.fromhex(m.group(2).decode())
        found.setdefault(salt, key)


def _scan_regions(pid: int, regions) -> dict[bytes, bytes]:
    """扫描指定内存区域，返回 {salt_bytes: key_bytes} 候选。"""
    found: dict[bytes, bytes] = {}
    mem = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    try:
        for start, end in regions:
            pos = start
            while pos < end:
                size = min(_CHUNK, end - pos)
                try:
                    os.lseek(mem, pos, os.SEEK_SET)
                    data = os.read(mem, size)
                except OSError:
                    break  # 区域不可读（可能已 unmap），跳过
                if not data:
                    break
                _scan_chunk(data, found)
                # 重叠 100 字节防止跨块边界漏匹配
                pos += max(1, len(data) - 100)
    finally:
        os.close(mem)
    return found


def collect_db_salts(db_storage: Path) -> dict[bytes, Path]:
    """读取 db_storage 下所有 .db 文件头 16 字节 salt。"""
    salts: dict[bytes, Path] = {}
    for db in sorted(db_storage.rglob("*.db")):
        try:
            with open(db, "rb") as f:
                head = f.read(16)
        except OSError:
            continue
        if len(head) == 16 and head != b"SQLite format 3":
            salts[head] = db
    return salts


def verify_key(db_path: Path, key: bytes) -> bool:
    """手工校验 page 1 HMAC（标准 SQLCipher 4 布局）：

    HMAC key = PBKDF2-HMAC-SHA512(raw_key, salt ^ 0x3a, 2, 32)
    HMAC 输入 = 密文页内容(16..4016) + IV(4016..4032) + pgno(4B LE)
    只需读文件头 4KB，不用拷贝整库，避免大库截断导致的误判。
    """
    import hashlib
    import hmac as hmac_mod

    try:
        with open(db_path, "rb") as f:
            page = f.read(4096)
    except OSError:
        return False
    if len(page) < 4096:
        return False
    salt = page[:16]
    masked_salt = bytes(b ^ 0x3A for b in salt)
    hmac_key = hashlib.pbkdf2_hmac("sha512", key, masked_salt, 2, 32)
    content = page[16:4032]  # 密文 + IV，salt 不参与 HMAC
    stored_mac = page[4032:4096]
    mac = hmac_mod.new(hmac_key, content + (1).to_bytes(4, "little"),
                       hashlib.sha512).digest()
    return hmac_mod.compare_digest(mac, stored_mac)


def match_keys_to_dbs(candidates: dict[bytes, bytes], db_salts: dict[bytes, Path],
                      db_storage: Path) -> dict:
    """把内存候选按 salt 匹配到本地库并逐一 HMAC 验证，返回 keys 字典。

    rel 路径统一用 POSIX 分隔符，保证 Windows 产出的 keys.json 与 Linux 格式一致
    （Linux 上 as_posix() 与 str() 等价，行为不变）。
    """
    keys: dict[str, dict] = {}
    unmatched = dict(candidates)
    for salt, db_path in db_salts.items():
        key = candidates.get(salt)
        if key is None:
            continue
        unmatched.pop(salt, None)
        rel = db_path.relative_to(db_storage).as_posix()
        if verify_key(db_path, key):
            keys[rel] = {"key": key.hex(), "salt": salt.hex()}
            print(f"  [OK] {rel}")
        else:
            print(f"  [FAIL] {rel} salt 匹配但验证失败")
    if unmatched:
        print(f"[*] {len(unmatched)} 个候选未匹配到本地数据库（可能属于其他库）")
    if not keys:
        raise RuntimeError("没有找到任何可用密钥。")
    return keys


def write_keys_file(keys: dict, out_file: Path) -> None:
    """写 keys.json；POSIX 下收窄为 0600，sudo 场景把文件还给真实用户。

    Windows 没有 POSIX 权限位：os.chmod 仅影响只读标志，0600 在其上近乎无操作，
    文件安全依赖用户目录 ACL（默认仅本人可读，勿共享该文件）。
    """
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=2)
    os.chmod(out_file, stat.S_IRUSR | stat.S_IWUSR)
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and hasattr(os, "chown"):  # sudo 运行时把文件还给真实用户（仅 POSIX）
        import pwd
        pw = pwd.getpwnam(sudo_user)
        os.chown(out_file, pw.pw_uid, pw.pw_gid)
    print(f"[*] 已写入 {out_file}（{len(keys)} 个密钥，权限 0600）")


def extract_keys(db_storage: Path, out_file: Path) -> dict:
    """主流程：扫内存 → 匹配 salt → 验证 → 写 keys.json。"""
    pid = find_wechat_pid()
    print(f"[*] 扫描进程 {pid} 内存 ...")
    db_salts = collect_db_salts(db_storage)
    print(f"[*] 在 {db_storage} 下发现 {len(db_salts)} 个加密数据库")

    rw_anon, readable = _iter_memory_regions(pid)
    candidates = _scan_regions(pid, rw_anon)
    print(f"[*] 堆内存扫描得到 {len(candidates)} 个候选密钥")
    if not candidates:
        print("[*] 堆中未找到，扩大范围扫描全部可读区域（较慢）...")
        candidates = _scan_regions(pid, readable)
        print(f"[*] 全量扫描得到 {len(candidates)} 个候选密钥")

    if not candidates:
        raise RuntimeError("内存中未找到密钥字符串。微信是否已登录？")

    keys = match_keys_to_dbs(candidates, db_salts, db_storage)
    write_keys_file(keys, out_file)
    return keys


def main(argv=None):
    import argparse

    p = argparse.ArgumentParser(description="从微信进程内存提取数据库密钥")
    p.add_argument("--db-storage", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args(argv)
    try:
        extract_keys(args.db_storage, args.out)
    except PermissionError as e:
        print(f"[ERR] 权限不足: {e}\n      请用 sudo 运行: sudo {sys.executable} main.py extract-keys",
              file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
