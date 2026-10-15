"""把解密后的微信数据库解析为结构化消息（按微信 4.x Linux 真实 schema）。

数据源与关联关系：
- session/session.db   SessionTable    会话列表（username、摘要、last_timestamp）
- contact/contact.db   contact         username → 昵称/备注；chatroom_member 群成员
- message/message_*.db Msg_<md5(talker)> 消息表（按时间分片，local_id 片内自增）
  - local_type 64 位：低 32 位基础类型(1/3/34/43/47/49/10000…)，高 32 位子类型(appmsg 5/6/19/33/36/57…)
  - message_content：文本为明文；富媒体为 zstd 压缩的 "发送者:\\n<xml>"
  - packed_info_data：40B，内含 32hex 的媒体文件 md5
  - real_sender_id → 本库 Name2Id.rowid = 发言人 username
- 媒体文件：msg/attach/<md5(talker)>/<yyyy-mm>/Img/<md5>{,_t}.dat
           msg/video/<yyyy-mm>/<md5>{.mp4,_thumb.jpg}
           msg/file/<yyyy-mm>/<文件名>
"""

from __future__ import annotations

import hashlib
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

import zstandard as zstd

from wxwatch.decryptor import mute_c_stderr

# 基础类型（低 32 位）
MSG_TYPES = {
    1: "text",
    3: "image",
    34: "voice",
    42: "card",
    43: "video",
    47: "emoji",
    48: "location",
    49: "appmsg",
    50: "voip",
    10000: "system",
    244: "pat",
}

# appmsg 子类型（高 32 位）
APPMSG_TYPES = {
    2: "emoji",
    4: "image_forward",
    5: "link",
    6: "file",
    8: "game",
    19: "chat_history",
    24: "note",
    33: "miniapp",
    36: "miniapp",
    44: "channels_live",  # 视频号直播
    51: "channels",       # 视频号
    57: "quote",
    63: "courses",
    74: "file_forward",
    2000: "transfer",
    2001: "redpacket",
    285212721: "announcement",
}

_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_SENDER_RE = re.compile(r"^([A-Za-z0-9_-]+):\n(.*)$", re.S)
_MD5_RE = re.compile(rb"[0-9a-f]{32}")
_XML_ILLEGAL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def _int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _fmt_time(ts) -> str | None:
    ts = _int(ts)
    if not ts:
        return None
    if ts > 10**12:
        ts //= 1000
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return str(ts)


class Parser:
    def __init__(self, decryptor, wechat_root: Path):
        self.dec = decryptor
        self.root = Path(wechat_root)
        # 自己的 username：目录名 wxid_xxx_ab12 → wxid_xxx
        self.self_username = self.root.name.rsplit("_", 1)[0]
        self._contacts: dict[str, dict] | None = None
        self._msg_tables: list[tuple[str, str, str]] | None = None
        self._name2id: dict[str, dict[int, str]] = {}  # db_rel -> {rowid: username}
        self._dctx = zstd.ZstdDecompressor()

    # ---------- 联系人 / 会话 ----------

    def contacts(self) -> dict[str, dict]:
        if self._contacts is not None:
            return self._contacts
        out: dict[str, dict] = {}
        try:
            conn = self.dec.connect("contact/contact.db")
        except Exception as e:
            print(f"  [WARN] 打开 contact.db 失败: {e}")
            self._contacts = out
            return out
        try:
            with mute_c_stderr():
                cols = [r[1] for r in conn.execute('PRAGMA table_info("contact")')]
                for row in conn.execute("SELECT * FROM contact"):
                    rec = dict(zip(cols, row))
                    username = rec.get("username")
                    if not username:
                        continue
                    out[username] = {
                        "username": username,
                        "nickname": rec.get("nick_name"),
                        "remark": rec.get("remark"),
                        "alias": rec.get("alias"),
                        "is_group": str(username).endswith("@chatroom"),
                    }
        finally:
            conn.close()
        self._contacts = out
        return out

    def sessions(self) -> list[dict]:
        conn = self.dec.connect("session/session.db")
        sessions: list[dict] = []
        try:
            with mute_c_stderr():
                cols = [r[1] for r in conn.execute('PRAGMA table_info("SessionTable")')]
                for row in conn.execute("SELECT * FROM SessionTable"):
                    rec = dict(zip(cols, row))
                    username = rec.get("username")
                    if not username:
                        continue
                    sessions.append({
                        "username": username,
                        "display_name": self.display_name(username),
                        "type": "group" if username.endswith("@chatroom") else "single",
                        "unread_count": rec.get("unread_count"),
                        "is_hidden": rec.get("is_hidden"),
                        "last_time": _fmt_time(rec.get("last_timestamp")),
                        "last_msg_type": rec.get("last_msg_type"),
                        "last_sender": rec.get("last_msg_sender"),
                        "last_sender_name": rec.get("last_sender_display_name"),
                        "last_msg_preview": rec.get("summary"),
                    })
        finally:
            conn.close()
        sessions.sort(key=lambda s: s["last_time"] or "", reverse=True)
        return sessions

    def display_name(self, username: str | None) -> str | None:
        if not username:
            return None
        c = self.contacts().get(username)
        if c:
            return c.get("remark") or c.get("nickname") or username
        return username

    # ---------- 消息表发现 ----------

    def message_dbs(self) -> list[str]:
        return [rel for rel in sorted(self.dec.keys)
                if rel.startswith("message/message_") and rel.endswith(".db")]

    def name2id(self, db_rel: str, conn=None) -> dict[int, str]:
        """message 库内 Name2Id：rowid → username（real_sender_id 的解析表）。"""
        if db_rel in self._name2id:
            return self._name2id[db_rel]
        own = conn is None
        conn = conn or self.dec.connect(db_rel)
        mapping: dict[int, str] = {}
        try:
            cols = [r[1] for r in conn.execute('PRAGMA table_info("Name2Id")')]
            name_col = next((c for c in ("user_name", "username", "userName")
                             if c in cols), cols[0] if cols else None)
            if name_col:
                mapping = {r[0]: r[1] for r in conn.execute(
                    f'SELECT rowid, "{name_col}" FROM Name2Id')}
        except Exception:
            pass
        finally:
            if own:
                conn.close()
        self._name2id[db_rel] = mapping
        return mapping

    def _resolve_msg_tables(self) -> list[tuple[str, str, str]]:
        """找出所有 Msg_<md5> 表并解析 talker username。"""
        if self._msg_tables is not None:
            return self._msg_tables
        known = {md5(u): u for u in self.contacts()}
        try:
            for s in self.sessions():
                known.setdefault(md5(s["username"]), s["username"])
        except Exception:
            pass
        tables: list[tuple[str, str, str]] = []
        for rel in self.message_dbs():
            try:
                conn = self.dec.connect(rel)
            except Exception:
                continue  # 镜像瞬时不可用（撕裂/重拷中），下一轮再发现
            try:
                with mute_c_stderr():
                    # Name2Id 里的 username 也加入候选
                    for u in self.name2id(rel, conn).values():
                        known.setdefault(md5(u), u)
                    for (t,) in conn.execute(
                            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg\\_%' ESCAPE '\\'"):
                        suffix = t[4:]
                        if not re.fullmatch(r"[0-9a-fA-F]{32}", suffix):
                            continue
                        username = known.get(suffix.lower(), f"unknown:{suffix}")
                        tables.append((rel, t, username))
            except Exception:
                pass  # 撕裂镜像：本轮跳过该库，下一轮自愈
            finally:
                conn.close()
        self._msg_tables = tables
        return tables

    # ---------- 内容解码 ----------

    def _decode_content(self, v) -> str | None:
        """message_content 解码：str 原样；bytes 按 zstd 解压或 utf-8。"""
        if v is None:
            return None
        if isinstance(v, str):
            return v
        if isinstance(v, bytes):
            if v.startswith(_ZSTD_MAGIC):
                try:
                    v = self._dctx.stream_reader(v).read(1 << 22)
                except zstd.ZstdError:
                    return f"<zstd 解压失败 {len(v)}B>"
            try:
                return v.decode("utf-8")
            except UnicodeDecodeError:
                return f"<{len(v)}B 二进制>"
        return str(v)

    # ---------- 消息遍历 ----------

    def iter_messages(self, since: dict[str, int] | None = None):
        """遍历消息。since: {'<db_rel>:<table>': max_local_id} 增量游标。"""
        since = since or {}
        for rel, table, talker in self._resolve_msg_tables():
            try:
                conn = self.dec.connect(rel)
            except Exception:
                continue  # 镜像撕裂等瞬时错误，下一轮再试
            try:
                n2i = self.name2id(rel, conn)
                cursor = since.get(f"{rel}:{table}", 0)
                sql = (f'SELECT local_id, server_id, local_type, sort_seq, real_sender_id,'
                       f' create_time, message_content, packed_info_data'
                       f' FROM "{table}" WHERE local_id > ? ORDER BY local_id')
                try:
                    with mute_c_stderr():
                        rows = conn.execute(sql, (cursor,))
                        for row in rows:
                            try:
                                yield self._normalize(rel, table, talker, row, n2i)
                            except Exception as e:
                                yield {
                                    "local_id": row[0], "db": rel, "table": f"{rel}:{table}",
                                    "talker": talker, "type": "parse_error",
                                    "error": str(e), "timestamp": row[5],
                                    "time": _fmt_time(row[5]),
                                }
                except Exception:
                    continue  # 单表读取失败（撕裂镜像/表未落盘）不拖垮整轮
            finally:
                conn.close()

    def _normalize(self, rel, table, talker, row, n2i) -> dict:
        (local_id, server_id, local_type, sort_seq, real_sender_id,
         create_time, raw_content, packed_info) = row

        local_type = _int(local_type) or 0
        base_type = local_type & 0xFFFFFFFF
        sub_type = local_type >> 32

        text = self._decode_content(raw_content)
        # 群消息发言人：优先 real_sender_id → Name2Id；兜底内容前缀 "user:\n"
        sender = n2i.get(real_sender_id) if real_sender_id else None
        if not sender:
            sender = None
        if text and not sender:
            m = _SENDER_RE.match(text)
            if m and talker.endswith("@chatroom"):
                sender, text = m.group(1), m.group(2)
        elif text and sender:
            m = _SENDER_RE.match(text)
            if m:
                text = m.group(2)

        if base_type == 49:
            type_name = f"appmsg/{APPMSG_TYPES.get(sub_type, sub_type)}"
        else:
            type_name = MSG_TYPES.get(base_type, f"type_{base_type}")

        msg = {
            "local_id": local_id,
            "server_id": server_id,
            "db": rel,
            "table": f"{rel}:{table}",
            "talker": talker,
            "talker_name": self.display_name(talker) if not talker.startswith("unknown:") else talker,
            "chat_type": "group" if talker.endswith("@chatroom") else "single",
            "sender": sender,
            "sender_name": self.display_name(sender) if sender else None,
            "direction": "sent" if sender == self.self_username else "recv",
            "time": _fmt_time(create_time),
            "timestamp": create_time,
            "sort_seq": sort_seq,
            "type": type_name,
            "local_type": local_type,
            "base_type": base_type,
            "sub_type": sub_type,
        }
        if not sender and not talker.endswith("@chatroom"):
            msg["direction"] = "recv"

        # 类型相关内容
        if base_type == 1 or base_type == 10000 or base_type == 244:
            msg["content"] = text
        elif base_type == 49:
            msg.update(self._parse_appmsg(text, sub_type))
            self._attach_file_paths(msg, talker, create_time)
        elif base_type in (3, 43, 47, 34, 48, 42):
            msg.update(self._parse_media_xml(text, base_type))
            md5_hex = self._media_md5(packed_info)
            if md5_hex:
                msg["media_md5"] = md5_hex
                paths = self._media_paths(base_type, talker, create_time, md5_hex)
                if paths:
                    msg["media_files"] = paths
        else:
            msg["content"] = text
        return msg

    # ---------- 富文本 / 媒体解析 ----------

    @staticmethod
    def _media_md5(packed_info) -> str | None:
        if isinstance(packed_info, bytes):
            m = _MD5_RE.search(packed_info)
            if m:
                return m.group(0).decode()
        return None

    def _media_paths(self, base_type, talker, create_time, md5_hex) -> list[str]:
        """按媒体 md5 + 消息月份推断本地文件路径，只返回存在的。"""
        ym = datetime.fromtimestamp(create_time).strftime("%Y-%m") if create_time else None
        if not ym:
            return []
        tdir = md5(talker)
        candidates: list[Path] = []
        if base_type == 3:  # 图片
            img = self.root / "msg" / "attach" / tdir / ym / "Img"
            candidates = [img / f"{md5_hex}_t.dat", img / f"{md5_hex}.dat"]
        elif base_type == 43:  # 视频
            vd = self.root / "msg" / "video" / ym
            candidates = [vd / f"{md5_hex}.mp4", vd / f"{md5_hex}_thumb.jpg"]
        elif base_type == 34:  # 语音
            vd = self.root / "msg" / "voice" / ym
            candidates = [vd / f"{md5_hex}.aud", vd / f"{md5_hex}.silk"]
        return [str(p) for p in candidates if p.exists()]

    def _parse_media_xml(self, text, base_type) -> dict:
        """解析图片/视频/表情等消息的 XML，提取 CDN 与 md5 属性。"""
        out: dict = {}
        if not text or "<" not in text:
            if text:
                out["content"] = text
            return out
        try:
            root = ET.fromstring(_XML_ILLEGAL_RE.sub("", text))
        except ET.ParseError:
            out["content"] = text[:500]
            return out
        node = root if root.tag != "msg" else (root[0] if len(root) else root)
        attrs = {k: v for k, v in node.attrib.items()
                 if k in ("md5", "aeskey", "cdnurl", "length", "hdlength",
                          "playlength", "voicelength", "format", "fromusername")}
        if attrs:
            out["media_attrs"] = attrs
        return out

    def _parse_appmsg(self, text, sub_type) -> dict:
        out: dict = {"content": None}
        if not text:
            return out
        clean = _XML_ILLEGAL_RE.sub("", text)
        # 去掉可能的发言人前缀已在外层处理
        try:
            root = ET.fromstring(clean)
        except ET.ParseError:
            out["content"] = text[:500]
            return out
        if root.tag != "msg":
            out["content"] = text[:500]
            return out
        app = root.find("appmsg")
        if app is None:
            return out
        xml_type = _int(app.findtext("type"))
        # 高 32 位子类型优先，XML type 兜底
        sub = sub_type if sub_type in APPMSG_TYPES else (xml_type or sub_type)
        out["sub_type"] = sub
        out["type"] = f"appmsg/{APPMSG_TYPES.get(sub, sub)}"
        title = app.findtext("title")
        if title:
            out["title"] = title
        des = app.findtext("des")
        if des and sub in (5, 33, 36, 51):
            out["desc"] = des
        if sub == 6 or sub == 74:  # 文件
            attach = app.find("appattach")
            if attach is not None:
                out["file"] = {
                    "name": attach.findtext("filename") or title,
                    "size": _int(attach.findtext("totallen")),
                    "ext": attach.findtext("fileext"),
                }
        elif sub == 57:  # 引用回复
            ref = app.find("refermsg")
            if ref is not None:
                out["quote"] = {
                    "from": ref.findtext("fromusr"),
                    "from_name": self.display_name(ref.findtext("fromusr")),
                    "content": ref.findtext("content"),
                }
        elif sub == 5:  # 链接
            out["link"] = {"title": title, "url": app.findtext("url"), "desc": des}
        elif sub in (33, 36):  # 小程序
            out["miniapp"] = {"title": title, "appid": app.findtext("appid"),
                              "sourcedisplayname": app.findtext("sourcedisplayname")}
        return out

    def _attach_file_paths(self, msg, talker, create_time):
        """文件类消息：尝试定位 msg/file/<yyyy-mm>/<文件名>。"""
        f = msg.get("file")
        if not f or not f.get("name") or not create_time:
            return
        ym = datetime.fromtimestamp(create_time).strftime("%Y-%m")
        p = self.root / "msg" / "file" / ym / f["name"]
        if p.exists():
            f["path"] = str(p)

    # ---------- schema 导出（调试用） ----------

    def schema_dump(self) -> dict:
        dump: dict = {}
        for rel in sorted(self.dec.keys):
            src = self.dec.db_storage / rel
            if not src.exists():
                continue
            try:
                conn = self.dec.connect(rel)
            except Exception as e:
                dump[rel] = {"error": str(e)}
                continue
            try:
                tables = {}
                for (t,) in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"):
                    cols = [(r[1], r[2]) for r in conn.execute(f'PRAGMA table_info("{t}")')]
                    try:
                        n = conn.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                    except Exception:
                        n = None
                    tables[t] = {"columns": cols, "rows": n}
                dump[rel] = tables
            finally:
                conn.close()
        return dump
