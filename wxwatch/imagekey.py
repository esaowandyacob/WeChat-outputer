"""V2 图片 AES 密钥提取（Linux）。

原理：微信只在「正在查看图片」时把 V2 密钥加载进内存，用完即释放。
密钥形态是 16/32 字符的 ASCII 字符串（参考实现同款结论），
因此用正则扫内存中的 ASCII 字符串并 AES 试解验证即可，无需逐字节暴破。

流程：先在微信里连续点开 2-3 张图片（全屏查看）→ 立即运行本命令。
"""

from __future__ import annotations

import json
import os
import re
import struct
import subprocess
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
CONFIG_FILE = PROJECT / "config.json"


def _chown_user(path: Path):
    """sudo 运行时把产物还给真实用户，避免 GUI（普通用户）读不到。"""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and os.geteuid() == 0:
        import pwd
        pw = pwd.getpwnam(sudo_user)
        os.chown(path, pw.pw_uid, pw.pw_gid)


def _pick_v2_sample(db_storage: Path) -> Path | None:
    """在 msg/attach 下挑一个 V2 全尺寸 .dat。"""
    attach = db_storage.parent / "msg" / "attach"
    if not attach.exists():
        return None
    for p in sorted(attach.rglob("*.dat"), key=lambda p: -p.stat().st_mtime):
        if p.name.endswith("_t.dat"):
            continue
        try:
            with open(p, "rb") as f:
                if f.read(6) == b"\x07\x08V2\x08\x07":
                    return p
        except OSError:
            continue
    return None


def _jpeg_walk_ok(pt: bytes) -> bool:
    """JPEG 段结构走查：FFD8 后连续 10 个段都能解析才算真。"""
    if pt[:2] != b"\xff\xd8":
        return False
    i = 2
    for _ in range(10):
        if i + 4 > len(pt) or pt[i] != 0xFF:
            return False
        marker = pt[i + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        ln = (pt[i + 2] << 8) | pt[i + 3]
        if ln < 2 or i + 2 + ln > len(pt):
            return False
        i += 2 + ln
    return True


def _try_key(key: bytes, ct0: bytes) -> bool:
    """强校验：JPEG 段走查 / PNG 完整签名 / GIF / RIFF / wxgf。"""
    if len(key) not in (16, 24, 32):
        return False
    from Crypto.Cipher import AES
    pt = AES.new(key, AES.MODE_ECB).decrypt(ct0)
    if pt[:2] == b"\xff\xd8":
        return _jpeg_walk_ok(pt)
    return (pt[:8] == b"\x89PNG\r\n\x1a\n" or pt[:4] == b"GIF8"
            or pt[:4] == b"RIFF" or pt[:4] == b"wxgf")


def _verify(sample: Path, key_hex: str) -> bool:
    """候选密钥最终验证：完整解密样本文件并检查图片结构。"""
    key = bytes.fromhex(key_hex) if re.fullmatch(r"[0-9a-f]+", key_hex) else key_hex.encode()
    data = sample.read_bytes()
    aes_size = struct.unpack("<I", data[6:10])[0]
    aligned = aes_size + (16 - aes_size % 16)
    return _try_key(key, data[15:15 + aligned])


_RE_KEY = re.compile(rb"(?<![A-Za-z0-9])([A-Za-z0-9]{32}|[A-Za-z0-9]{16})(?![A-Za-z0-9])")


def _scan_pid_for_key(pid: int, ct_aes: bytes, seen: set, log=print) -> str | None:
    """在单个进程的可读写匿名内存里搜 ASCII 密钥字符串并试解。seen 跨进程去重。"""
    try:
        maps = open(f"/proc/{pid}/maps")
        mem = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    except OSError:
        return None
    tested = 0
    try:
        for line in maps:
            p = line.split()
            path = p[5] if len(p) >= 6 else ""
            perms = p[1]
            if "r" not in perms or "w" not in perms:
                continue
            if path and not path.startswith("["):
                continue
            s, e = (int(x, 16) for x in p[0].split("-"))
            if e - s > 2 * 1024 * 1024 * 1024:
                continue
            pos = s
            while pos < e:
                size = min(64 * 1024 * 1024, e - pos)
                try:
                    os.lseek(mem, pos, os.SEEK_SET)
                    data = os.read(mem, size)
                except OSError:
                    break
                if not data:
                    break
                for m in _RE_KEY.finditer(data):
                    cand = m.group(1)
                    if cand in seen:
                        continue
                    seen.add(cand)
                    variants = [cand] if len(cand) == 16 else [cand[:16], cand]
                    for k in variants:
                        tested += 1
                        if _try_key(k, ct_aes):
                            return k.decode()
                pos += max(1, len(data) - 64)  # 重叠防跨块
    finally:
        maps.close()
        os.close(mem)
        log(f"    pid {pid}: 新测试 {tested} 个候选（累计去重 {len(seen)}）")
    return None


def _wechat_pids() -> list[int]:
    out = []
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                comm = Path(f"/proc/{entry}/comm").read_text().strip()
            except OSError:
                continue
            if comm in ("wechat", "WeChatAppEx", "wxplayer", "wxutility", "wxocr"):
                out.append(int(entry))
    return out


# ---------- 零操作方案：监听解码缓存目录，微信一旦解码新图立刻扫内存 ----------

_SCANNER2 = PROJECT / "tools" / "scan_imgkey2"


def _find_dat_for_md5(db_storage: Path, md5_hex: str) -> Path | None:
    attach = db_storage.parent / "msg" / "attach"
    for p in attach.glob(f"*/*/Img/{md5_hex}.dat"):
        return p
    return None


def _scan_once_with_pair(dat: Path, jpg: Path, log=print) -> str | None:
    """用明文对（缓存解码图 + .dat）对所有微信进程做一轮精确扫描。"""
    if not _SCANNER2.exists():
        subprocess.run(["gcc", "-O3", "-maes", "-msse4.1", "-fopenmp",
                        "-o", str(_SCANNER2), str(_SCANNER2.with_suffix(".c"))],
                       check=True)
        _chown_user(_SCANNER2)
    for pid in _wechat_pids():
        try:
            r = subprocess.run([str(_SCANNER2), str(pid), str(dat), str(jpg)],
                               capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired:
            continue
        m = re.search(r"(?:RAW128|SCHED) addr=\w+ (?:key|rk0)=([0-9a-f]{32})", r.stdout)
        if m:
            return m.group(1)
    return None


def _save_image_key(key_hex: str, log=print):
    # 规范化为可直接使用的形态：16 字节密钥若是可打印 ASCII（V2 实际形态），
    # 存 ASCII 字符串本身，避免 parse_image_key 对 32 位 hex 的歧义误判。
    store = key_hex
    try:
        raw = bytes.fromhex(key_hex)
        if len(raw) in (16, 24, 32) and all(0x20 <= b < 0x7F for b in raw):
            store = raw.decode("ascii")
    except ValueError:
        pass
    cfg = {}
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text())
        except json.JSONDecodeError:
            pass
    cfg["image_key"] = store
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    os.chmod(CONFIG_FILE, 0o600)
    _chown_user(CONFIG_FILE)
    log(f"[✅] V2 图片密钥已写入 config.json: {store}")


def watch_and_extract(db_storage: Path, log=print) -> str | None:
    """监听 ImageUtils 缓存目录：微信每次首次解码图片都会写新缓存文件，
    此时密钥刚在内存中使用过 —— 立即扫内存抓 key。全程无需用户配合。

    返回 key 或超时返回 None。"""
    import threading
    import time as _time

    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    cache_dir = db_storage.parent / "temp" / "ImageUtils"
    cache_dir.mkdir(parents=True, exist_ok=True)
    attach = db_storage.parent / "msg" / "attach"

    def _saved_key() -> str | None:
        """config.json 里已有的图片密钥（本进程或其他进程写入）。"""
        try:
            return json.loads(CONFIG_FILE.read_text()).get("image_key") or None
        except (OSError, json.JSONDecodeError):
            return None

    existing = _saved_key()
    if existing:
        log("[✅] 图片密钥已获取，无需监听，守护退出")
        return existing

    state = {"key": None, "scanning": False, "last_scan": 0.0,
             "seen": set(cache_dir.glob("*.jpg")), "last_poll": 0.0}

    def do_scan(new_jpg: Path):
        if state["key"] or state["scanning"]:
            return
        # 等文件写完
        _time.sleep(0.5)
        md5_hex = new_jpg.name.split(".")[0].replace("_h", "")
        dat = _find_dat_for_md5(db_storage, md5_hex)
        if not dat or dat.read_bytes()[:6] != b"\x07\x08V2\x08\x07":
            return  # 非 V2（V1/XOR 本来就能解），无需抓 key
        state["scanning"] = True
        log(f"[*] 检测到新解码图片 {new_jpg.name}，立即扫描内存…")
        t0 = _time.time()
        try:
            key = _scan_once_with_pair(dat, new_jpg, log)
            if key:
                _save_image_key(key, log)
                state["key"] = key
            else:
                log(f"[*] 本轮未抓到（耗时 {_time.time()-t0:.1f}s），继续监听")
        finally:
            state["scanning"] = False

    def kick(path_str: str):
        """新缓存文件入口：inotify 三种事件 + 轮询兜底都走这里，按路径去重。"""
        if state["key"] or not path_str.endswith(".jpg"):
            return
        p = Path(path_str)
        if p in state["seen"]:
            return
        state["seen"].add(p)
        log(f"[*] 捕获到新缓存文件: {p.name}")
        threading.Thread(target=do_scan, args=(p,), daemon=True).start()

    class _H(FileSystemEventHandler):
        # 微信先写临时文件再 rename → 只产生 on_moved；
        # 直接创建写入 → on_created + on_modified。三种都接。
        def on_created(self, event):
            if not event.is_directory:
                kick(event.src_path)

        def on_modified(self, event):
            if not event.is_directory:
                kick(event.src_path)

        def on_moved(self, event):
            if not event.is_directory:
                kick(event.dest_path)

    obs = Observer()
    obs.schedule(_H(), str(cache_dir), recursive=False)
    obs.start()
    log(f"[*] 已监听 {cache_dir}（微信每次首次解码新图都会触发扫描，无需任何操作）")
    try:
        while state["key"] is None:
            _time.sleep(1)
            saved = _saved_key()
            if saved:  # 其他途径（GUI 手动提取等）已抓到 → 守护退出
                log("[✅] 图片密钥已获取，守护退出")
                state["key"] = saved
                break
            # 轮询兜底：inotify 事件语义之外的新文件（3s 一次）
            now = _time.time()
            if now - state["last_poll"] >= 3:
                state["last_poll"] = now
                for p in cache_dir.glob("*.jpg"):
                    kick(str(p))
    except KeyboardInterrupt:
        pass
    finally:
        obs.stop()
        obs.join(timeout=5)
    return state["key"]


def extract_image_key(db_storage: Path, passes: int = 3, log=print) -> str | None:
    """扫描微信进程内存提取 V2 图片密钥（ASCII 字符串形式）。

    密钥是 16/32 字符的 ASCII 字符串，只在微信查看图片时加载进堆内存。
    参考实现同款方法：正则扫字符串 + AES 试解验证。"""
    sample = _pick_v2_sample(db_storage)
    if not sample:
        log("[ERR] 未找到 V2 格式 .dat 样本")
        return None
    data = sample.read_bytes()
    aes_size = struct.unpack("<I", data[6:10])[0]
    aligned = aes_size + (16 - aes_size % 16)
    ct_aes = data[15:15 + aligned]
    pids = _wechat_pids()
    if not pids:
        log("[ERR] 未找到运行中的微信进程")
        return None
    log(f"[*] 样本 {sample.name}，扫描 {len(pids)} 个进程（{passes} 轮）…")
    seen: set = set()
    for rd in range(1, passes + 1):
        for pid in pids:
            key = _scan_pid_for_key(pid, ct_aes, seen, log)
            if key:
                cfg = {}
                if CONFIG_FILE.exists():
                    try:
                        cfg = json.loads(CONFIG_FILE.read_text())
                    except json.JSONDecodeError:
                        pass
                cfg["image_key"] = key  # ASCII 字符串形式
                CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
                os.chmod(CONFIG_FILE, 0o600)
                _chown_user(CONFIG_FILE)
                log(f"[✅] V2 图片密钥已写入 config.json: {key}")
                return key
        if rd < passes:
            log(f"  第 {rd} 轮未命中，1s 后重试…（此刻在微信里翻看图片）")
            import time as _time
            _time.sleep(1)
    log("[✗] 未找到。密钥只在微信「正在查看图片」时加载进内存——"
        "请在微信里连续点开 2-3 张图片（全屏查看），然后立即重跑。")
    return None


def main():
    import argparse
    import sys

    sys.path.insert(0, str(PROJECT))
    ap = argparse.ArgumentParser()
    ap.add_argument("--db-storage", type=Path, default=None)
    args = ap.parse_args()
    ds = args.db_storage
    if ds is None:
        ds = sorted(Path.home().glob("Documents/xwechat_files/wxid_*/db_storage"))[0]
    extract_image_key(ds)


if __name__ == "__main__":
    main()
