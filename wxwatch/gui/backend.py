"""GUI 与 CLI 共享的数据后端：密钥/解密器/解析器的装配，会话/消息/搜索/统计查询。"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from wxwatch.decryptor import Decryptor, mute_c_stderr
from wxwatch.parser import Parser

if getattr(sys, "frozen", False):
    # PyInstaller 打包：keys.json/config.json/mirror/output 一律放 exe 旁边
    PROJECT = Path(sys.executable).resolve().parent
else:
    PROJECT = Path(__file__).resolve().parent.parent.parent
KEYS_FILE = PROJECT / "keys.json"
CONFIG_FILE = PROJECT / "config.json"
MIRROR_DIR = PROJECT / "mirror"
OUTPUT_DIR = PROJECT / "output"
THUMB_CACHE = OUTPUT_DIR / ".thumbcache"


def cli_invocation(args: list[str]) -> tuple[str, list[str]]:
    """GUI 内调用 CLI 子命令的统一入口（可执行文件, 完整参数）。

    冻结（PyInstaller）时 exe 自身即 CLI：wxwatch.exe extract-keys …"""
    if getattr(sys, "frozen", False):
        return sys.executable, list(args)
    py = (PROJECT / ".venv" / "Scripts" / "python.exe" if sys.platform == "win32"
          else PROJECT / ".venv" / "bin" / "python")
    return str(py), [str(PROJECT / "main.py"), *args]


class Backend:
    def __init__(self, db_storage: Path | None = None):
        if not KEYS_FILE.exists():
            raise RuntimeError("缺少 keys.json，请先运行: sudo .venv/bin/python main.py extract-keys")
        keys = json.loads(KEYS_FILE.read_text())
        if db_storage is None:
            import os
            if sys.platform == "win32":
                home = Path.home()
            else:
                import pwd
                user = os.environ.get("SUDO_USER") or os.environ.get("USER") or ""
                home = Path(pwd.getpwnam(user).pw_dir) if user else Path.home()
            root = home / "Documents" / "xwechat_files"
            cands = sorted(p for p in root.glob("*/db_storage") if p.parent.name.startswith("wxid_"))
            if not cands:
                raise RuntimeError(f"未在 {root} 找到微信数据目录")
            db_storage = cands[0]
        self.db_storage = db_storage
        self.dec = Decryptor(db_storage, keys, MIRROR_DIR)
        self.parser = Parser(self.dec, db_storage.parent)
        self._sessions: list[dict] | None = None

    # ---------- 会话 ----------

    def sessions(self, refresh: bool = False) -> list[dict]:
        if self._sessions is None or refresh:
            self._sessions = self.parser.sessions()
        return self._sessions

    def session_msg_present(self) -> set[str]:
        """有消息的会话 username 集合（每张表 EXISTS 探测，远快于 COUNT(*)；带缓存）。"""
        if getattr(self, "_present", None) is not None:
            return self._present
        present: set[str] = set()
        by_db: dict[str, list[tuple[str, str]]] = {}
        for rel, table, talker in self.parser._resolve_msg_tables():
            by_db.setdefault(rel, []).append((table, talker))
        for rel, items in by_db.items():
            try:
                conn = self.dec.connect(rel)
            except Exception:
                continue  # 镜像瞬时不可用，下次刷新自愈
            try:
                for table, talker in items:
                    try:
                        with mute_c_stderr():
                            row = conn.execute(f'SELECT 1 FROM "{table}" LIMIT 1').fetchone()
                        if row:
                            present.add(talker)
                    except Exception:
                        continue
            finally:
                conn.close()
        self._present = present
        return present

    # ---------- 媒体解码 ----------

    def image_key(self) -> bytes | None:
        if getattr(self, "_img_key", None) is None:
            self._img_key = b""
            try:
                from wxwatch.imagedat import parse_image_key
                cfg = json.loads(CONFIG_FILE.read_text())
                self._img_key = parse_image_key(cfg.get("image_key")) or b""
            except Exception:
                pass
        return self._img_key or None

    def media_preview(self, path: str) -> str | None:
        """把 .dat 图片解密并转成缩略缓存 jpg，返回缓存路径（可直接显示）。"""
        from wxwatch.imagedat import decode_dat

        p = Path(path)
        THUMB_CACHE.mkdir(parents=True, exist_ok=True)
        cache = THUMB_CACHE / (p.stem + ".img")
        if cache.exists():
            return str(cache)
        raw = decode_dat(p, self.image_key())
        if raw is None:
            return None
        cache.write_bytes(raw)
        return str(cache)

    def media_preview_for(self, msg: dict) -> tuple[str | None, str | None]:
        """返回 (预览路径, 点击打开路径)。

        优先级：微信自身的解码缓存 temp/ImageUtils/<md5>{_h,}.jpg（看过就有，明文）
        → 视频 _thumb.jpg → 解密 .dat（需对应格式密钥）。"""
        cache_dir = self.db_storage.parent / "temp" / "ImageUtils"
        md5v = msg.get("media_md5")
        if md5v:
            for name in (f"{md5v}_h.jpg", f"{md5v}.jpg"):
                p = cache_dir / name
                if p.exists():
                    return str(p), str(p)
        files = msg.get("media_files") or []
        if msg.get("type") == "video":
            thumb = next((f for f in files if f.endswith("_thumb.jpg")), None)
            mp4 = next((f for f in files if f.lower().endswith(".mp4")), None)
            return thumb, mp4 or thumb
        if files:
            p = self.media_preview(files[0])
            return p, p
        return None, None

    # ---------- 消息（按会话，直接查镜像库） ----------

    def messages_for(self, talker: str, limit: int = 300,
                     before: tuple[str, int] | None = None) -> list[dict]:
        """取某会话最近 limit 条消息（跨分片合并）。
        before: (db_rel, local_id) 分页上界，取更早的消息。"""
        tables = [(rel, t) for rel, t, u in self.parser._resolve_msg_tables()
                  if u == talker]
        out: list[dict] = []
        for rel, table in tables:
            try:
                conn = self.dec.connect(rel)
            except Exception:
                continue  # 镜像瞬时不可用，跳过该分片
            try:
                n2i = self.parser.name2id(rel, conn)
                sql = (f'SELECT local_id, server_id, local_type, sort_seq, real_sender_id,'
                       f' create_time, message_content, packed_info_data FROM "{table}"')
                params: tuple = ()
                if before and before[0] == rel:
                    sql += " WHERE local_id < ?"
                    params = (before[1],)
                sql += " ORDER BY local_id DESC LIMIT ?"
                params += (limit,)
                try:
                    with mute_c_stderr():
                        rows = conn.execute(sql, params).fetchall()
                except Exception:
                    continue  # 撕裂镜像：跳过该分片，下次刷新自愈
                for row in rows:
                    try:
                        out.append(self.parser._normalize(rel, table, talker, row, n2i))
                    except Exception:
                        continue
            finally:
                conn.close()
        out.sort(key=lambda m: m.get("sort_seq") or 0)
        return out[-limit:]

    # ---------- 搜索（扫解析产物 messages.jsonl） ----------

    def search(self, keyword: str | None = None, talker: str | None = None,
               type_filter: str | None = None, limit: int = 500,
               cancel=None, progress=None):
        """在 messages.jsonl 中检索。keyword 为空 = 浏览模式（只按会话/类型过滤）。
        cancel: callable->bool；progress: callable(行数)。"""
        path = OUTPUT_DIR / "messages.jsonl"
        if not path.exists():
            return
        kw = (keyword or "").lower()
        seen = set()
        count = 0
        scanned = 0
        browse: list[dict] | None = [] if not kw else None
        with open(path, encoding="utf-8") as f:
            for line in f:
                scanned += 1
                if cancel and cancel():
                    return
                if progress and scanned % 20000 == 0:
                    progress(scanned)
                if kw and kw not in line.lower():
                    continue
                # 无关键词时的行级粗筛（避免 json 解析全部行）
                if not kw:
                    if type_filter and f'"type": "{type_filter}' not in line:
                        continue
                    if talker and f'"talker": "{talker}"' not in line:
                        continue
                try:
                    m = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if talker and m.get("talker") != talker:
                    continue
                if type_filter and not str(m.get("type", "")).startswith(type_filter):
                    continue
                if kw:
                    text = " ".join(str(m.get(k) or "") for k in
                                    ("content", "title", "sender_name", "talker_name")).lower()
                    if kw not in text:
                        continue
                key = (m.get("table"), m.get("local_id"))
                if key in seen:
                    continue
                seen.add(key)
                if browse is not None:
                    browse.append(m)
                else:
                    yield m
                count += 1
                if browse is None and count >= limit:
                    return
        if browse is not None:
            # 浏览模式：按时间倒序，取最近 limit 条
            browse.sort(key=lambda m: m.get("timestamp") or 0, reverse=True)
            for m in browse[:limit]:
                if cancel and cancel():
                    return
                yield m

    # ---------- 实时 ----------

    def make_watcher(self, on_message):
        from wxwatch.watcher import MessageWatcher

        return MessageWatcher(self.dec, self.parser, OUTPUT_DIR,
                              verbose=False, persist=False, on_message=on_message)


def fmt_ts(ts) -> str:
    if not ts:
        return "-"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(ts)))
    except (ValueError, OverflowError, OSError):
        return str(ts)


def msg_preview(msg: dict, maxlen: int = 60) -> str:
    if msg.get("content"):
        p = str(msg["content"])
        # voip/系统消息是 XML，提取 CDATA 里的可读文本
        if p.startswith("<"):
            import re as _re
            m = _re.search(r"<!\[CDATA\[(.*?)\]\]>", p, _re.S)
            if m:
                p = m.group(1)
            elif p.lstrip().startswith(("<voipmsg", "<sysmsg")):
                p = f"[{msg.get('type', '系统')}]"
    elif msg.get("title"):
        p = f"[{msg['type'].split('/')[-1]}] {msg['title']}"
    elif msg.get("file"):
        p = f"[文件] {msg['file'].get('name')}"
    elif msg.get("quote"):
        p = f"[引用] {msg['quote'].get('content')}"
    else:
        p = f"[{msg.get('type', '?')}]"
    p = " ".join(str(p).split())
    return p[:maxlen] + "…" if len(p) > maxlen else p
