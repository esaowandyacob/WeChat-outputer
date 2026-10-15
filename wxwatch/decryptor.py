"""加密数据库的镜像与解密打开。

微信 db 使用 WAL 模式，WAL 预分配固定 4MB（大小不变，只能看 mtime）。
策略：把 db+wal 镜像到本地副本，用 sqlcipher3 以 raw key 打开副本查询，
WAL 的 salt/校验和验证由 SQLite 原生完成，拷贝时的尾部坏帧会被自动丢弃。

主 db 仅在 size/mtime 变化时重拷（checkpoint 才变），WAL 每次触发重拷。
"""

from __future__ import annotations

import contextlib
import os
import shutil
import sys
import time
from pathlib import Path

try:
    from sqlcipher3 import dbapi2 as sqlite
except ImportError:
    # Windows（PyInstaller 包）：无 sqlcipher3 轮子，回退标准库 sqlite3——
    # 其底层加载的是随包捆绑的 SQLCipher 版 sqlite3.dll（msys2 预编译），
    # PRAGMA key / cipher_compatibility / sqlcipher_export 均可用。
    import sqlite3 as sqlite  # type: ignore[no-redef]


@contextlib.contextmanager
def mute_c_stderr():
    """屏蔽 C 层（sqlcipher/sqlite）直接写到 fd 2 的 ERROR CORE 日志。
    这些瞬时错误（撕裂镜像的 HMAC 校验失败等）上层会重试/容错，
    Python 自己的异常不受影响（traceback 走 sys.stderr 对象时除外）。"""
    try:
        fd = sys.stderr.fileno()
    except (AttributeError, ValueError, OSError):
        yield
        return
    sys.stderr.flush()
    saved = os.dup(fd)
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, fd)
        os.close(devnull)
        yield
    finally:
        os.dup2(saved, fd)
        os.close(saved)


def _atomic_copy(src: Path, dst: Path):
    """先拷临时文件再 rename：读者永远拿到完整文件，不会读到写一半的镜像。"""
    tmp = dst.with_name(f"{dst.name}.tmp{os.getpid()}")
    shutil.copyfile(src, tmp)
    os.replace(tmp, dst)


class Decryptor:
    def __init__(self, db_storage: Path, keys: dict, mirror_dir: Path):
        self.db_storage = Path(db_storage)
        self.keys = keys  # {rel_path: {"key": hex, "salt": hex}}
        self.mirror_dir = Path(mirror_dir)
        self.mirror_dir.mkdir(parents=True, exist_ok=True)
        self._state: dict[str, tuple[int, float]] = {}  # rel -> (size, mtime) of main db

    def _key_for(self, rel: str) -> str:
        if rel not in self.keys:
            raise KeyError(f"keys.json 中没有 {rel} 的密钥")
        return self.keys[rel]["key"]

    def mirror_path(self, rel: str) -> Path:
        return self.mirror_dir / rel

    def refresh(self, rel: str, copy_main: bool | None = None) -> Path:
        """刷新单个 db 的镜像（db + wal）。返回镜像 db 路径。"""
        src = self.db_storage / rel
        dst = self.mirror_path(rel)
        dst.parent.mkdir(parents=True, exist_ok=True)

        st = src.stat()
        sig = (st.st_size, st.st_mtime)
        if copy_main is None:
            copy_main = self._state.get(rel) != sig or not dst.exists()
        if copy_main:
            _atomic_copy(src, dst)
            self._state[rel] = sig
        wal = src.with_name(src.name + "-wal")
        if wal.exists():
            # WAL 未变化时不重拷（大库 WAL 可达数百 MB，每次刷新都拷会拖垮轮询）
            wst = wal.stat()
            wsig = (wst.st_size, wst.st_mtime)
            wdst = dst.with_name(dst.name + "-wal")
            if self._state.get(rel + "-wal") != wsig or not wdst.exists():
                _atomic_copy(wal, wdst)
                self._state[rel + "-wal"] = wsig
        # 旧 shm 会让 SQLite 走 wal-index 恢复，删掉避免读到过期索引
        shm = dst.with_name(dst.name + "-shm")
        if shm.exists():
            shm.unlink()
        return dst

    def connect(self, rel: str, refresh: bool = True) -> sqlite.Connection:
        """打开镜像后的加密库（只读语义，但连接本身可读写镜像副本）。

        微信可能在拷贝瞬间 checkpoint/写入 → 镜像撕裂（HMAC 校验失败/库损坏）。
        这里先做一次轻量完整性探测，失败则强制重拷主库重试（线性退避）。
        """
        last_err: Exception | None = None
        for attempt in range(3):
            dst = self.refresh(rel, copy_main=True if attempt else None) if refresh \
                else self.mirror_path(rel)
            conn = sqlite.connect(str(dst), timeout=10)
            try:
                with mute_c_stderr():
                    conn.execute(f"PRAGMA key=\"x'{self._key_for(rel)}'\"")
                    conn.execute("PRAGMA cipher_compatibility = 4")
                    conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
                return conn
            except sqlite.DatabaseError as e:
                last_err = e
                conn.close()
                time.sleep(0.3 * (attempt + 1))
        raise last_err  # type: ignore[misc]

    def sanity_check(self, rel: str) -> bool:
        try:
            conn = self.connect(rel)
            try:
                conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
                return True
            finally:
                conn.close()
        except Exception:
            return False

    def export_plaintext(self, rel: str, out_path: Path) -> Path:
        """把某个加密库完整导出为明文 sqlite（含 WAL 内容）。"""
        dst = self.refresh(rel, copy_main=True)
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if out_path.exists():
            out_path.unlink()
        conn = sqlite.connect(str(dst), timeout=30)
        try:
            conn.execute(f"PRAGMA key=\"x'{self._key_for(rel)}'\"")
            conn.execute(f"ATTACH DATABASE '{out_path}' AS plaintext KEY ''")
            conn.execute("SELECT sqlcipher_export('plaintext')")
            conn.execute("DETACH DATABASE plaintext")
        finally:
            conn.close()
        return out_path

    def export_all(self, out_dir: Path) -> list[Path]:
        outs = []
        for rel in sorted(self.keys):
            src = self.db_storage / rel
            if not src.exists():
                continue
            t0 = time.time()
            try:
                out = self.export_plaintext(rel, Path(out_dir) / rel)
                outs.append(out)
                print(f"  [OK] {rel} -> {out} ({time.time()-t0:.1f}s)")
            except Exception as e:
                print(f"  [FAIL] {rel}: {e}")
        return outs
