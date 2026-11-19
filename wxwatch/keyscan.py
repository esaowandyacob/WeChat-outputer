"""从运行中的微信进程内存提取 SQLCipher 4 密钥。

已登录进程里不保留明文 ``x'...'``。WCDB 的 cipher 记录被一段固定 32 字节
异或掩码盖住，相位相对每条记录自己的起点。扫描时按全部相位解开，带 salt
的候选按 salt 归类，其余候选再对每个库做 page-1 HMAC 校验。

需要 root（ptrace_scope=1 时读 /proc/pid/mem 必须有 CAP_SYS_PTRACE）。
用法：sudo .venv/bin/python main.py extract-keys
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

# 固定异或掩码。微信把 ``x'<64hex key>[32hex salt]'`` 按这条记录自己的下标
# 与掩码逐字节异或后放在进程内存里；掩码长度就是周期，不跟虚拟地址对齐。
CIPHER_XOR_MASK = bytes.fromhex(
    "d2c7442458020000004889442450488b450048844c2448488944254048584c24"
)
# x' + 最多 192 个 hex + 结束引号。跨块重叠必须盖住一整条记录。
_MAX_RECORD = 2 + 192 + 1
_CHUNK_OVERLAP = _MAX_RECORD - 1
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


def mask_cipher_blob(plain: bytes, phase: int = 0) -> bytes:
    """用固定掩码盖住一段 cipher 记录。phase 是这条记录自己的起点相位。"""
    size = len(CIPHER_XOR_MASK)
    phase %= size
    return bytes(byte ^ CIPHER_XOR_MASK[(phase + index) % size] for index, byte in enumerate(plain))


def _is_hex_byte(value: int) -> bool:
    return (0x30 <= value <= 0x39) or (0x61 <= value <= 0x66) or (0x41 <= value <= 0x46)


def _accept_key(found: dict[bytes, bytes], unbound: set[bytes] | None,
                key: bytes, salt: bytes | None) -> None:
    """带 salt 的记录先按 salt 归类；对不上或没有 salt 的留给 HMAC。"""
    if salt is not None:
        previous = found.get(salt)
        if previous is None:
            found[salt] = key
            return
        if previous == key or unbound is None:
            return
        unbound.add(key)
        return
    if unbound is not None:
        unbound.add(key)


def _accept_decoded(decoded: bytes, found: dict[bytes, bytes],
                    unbound: set[bytes] | None) -> None:
    """从解开后的 ``x'<hex>'`` 里取出 32 字节密钥和可选的 16 字节 salt。"""
    if len(decoded) < 67 or decoded[0] not in (0x78, 0x58) or decoded[1] != 0x27 or decoded[-1] != 0x27:
        return
    run = decoded[2:-1]
    if len(run) < 64 or len(run) > 192 or any(not _is_hex_byte(byte) for byte in run):
        return
    starts = [0]
    if len(run) > 96:
        starts.extend(range(0, len(run) - 63, 32))
        tail = len(run) - 64
        if tail not in starts:
            starts.append(tail)
    for start in starts:
        if start + 64 > len(run):
            continue
        try:
            key = bytes.fromhex(run[start:start + 64].decode("ascii"))
        except ValueError:
            continue
        salt = None
        if len(run) >= start + 96:
            try:
                salt = bytes.fromhex(run[start + 64:start + 96].decode("ascii"))
            except ValueError:
                salt = None
        _accept_key(found, unbound, key, salt)


def _scan_chunk(data: bytes, found: dict[bytes, bytes],
                unbound: set[bytes] | None = None) -> None:
    """在单块内存里找被固定异或掩码盖住的 cipher 记录。

    不搜索明文 ``x'...'``。掩码相位是每条记录自己的，32 种对齐都要试。
    Windows 版复用本函数，保证两端匹配行为一致。
    """
    mask = CIPHER_XOR_MASK
    size = len(mask)
    limit = len(data)
    for phase in range(size):
        prefix = bytes((0x78 ^ mask[phase], 0x27 ^ mask[(phase + 1) % size]))
        start = 0
        while True:
            index = data.find(prefix, start)
            if index < 0:
                break
            start = index + 1
            decoded = bytearray()
            max_len = min(_MAX_RECORD, limit - index)
            for length in range(max_len):
                value = data[index + length] ^ mask[(phase + length) % size]
                decoded.append(value)
                if length < 2:
                    continue
                if value == 0x27:
                    if length >= 66:
                        _accept_decoded(bytes(decoded), found, unbound)
                    break
                if not _is_hex_byte(value):
                    break


def _scan_regions(pid: int, regions) -> tuple[dict[bytes, bytes], set[bytes]]:
    """扫描指定内存区域，返回 ({salt: key}，不含 salt 的密钥集合)。"""
    found: dict[bytes, bytes] = {}
    unbound: set[bytes] = set()
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
                _scan_chunk(data, found, unbound)
                # 重叠一整条记录，避免密钥被切在两块内存的边界上
                pos += max(1, len(data) - _CHUNK_OVERLAP)
    finally:
        os.close(mem)
    return found, unbound


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
                      db_storage: Path, unbound: set[bytes] | None = None) -> dict:
    """把内存候选匹配到本地库并逐一 HMAC 验证，返回 keys 字典。

    旧格式候选已带 salt。新格式只有密钥，要对每个尚未配对的库试 HMAC。
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
    unbound_left = 0
    for key in unbound or ():
        hit = False
        for salt, db_path in db_salts.items():
            rel = db_path.relative_to(db_storage).as_posix()
            if rel in keys:
                continue
            if not verify_key(db_path, key):
                continue
            keys[rel] = {"key": key.hex(), "salt": salt.hex()}
            print(f"  [OK] {rel}")
            hit = True
        if not hit:
            unbound_left += 1
    if unmatched or unbound_left:
        print(f"[*] {len(unmatched) + unbound_left} 个候选未匹配到本地数据库（可能属于其他库）")
    missing = len(db_salts) - len(keys)
    if missing:
        print(f"[*] 还有 {missing} 个库没有通过 page-1 HMAC。"
              "这些库的密钥不在当前进程的异或掩码记录里。")
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
    candidates, unbound = _scan_regions(pid, rw_anon)
    print(f"[*] 堆内存扫描得到 {len(candidates) + len(unbound)} 个候选密钥")
    if not candidates and not unbound:
        print("[*] 堆中未找到，扩大范围扫描全部可读区域（较慢）...")
        candidates, unbound = _scan_regions(pid, readable)
        print(f"[*] 全量扫描得到 {len(candidates) + len(unbound)} 个候选密钥")

    if not candidates and not unbound:
        raise RuntimeError("内存中未找到异或掩码下的密钥记录。微信是否已登录？")

    keys = match_keys_to_dbs(candidates, db_salts, db_storage, unbound)
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
