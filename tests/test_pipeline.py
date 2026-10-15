"""合成数据端到端测试：按微信 4.x 真实 schema 自建 SQLCipher 加密库，
验证 keyscan 校验、decryptor 镜像、parser 解析（zstd/媒体 md5/发言人）、watcher 增量。
"""

import json
import shutil
import struct
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import zstandard as zstd
from Crypto.Cipher import AES
from Crypto.Util import Padding
from sqlcipher3 import dbapi2 as sqlite

from wxwatch import keyscan
from wxwatch.decryptor import Decryptor
from wxwatch.imagedat import V1_KEY, V1_MAGIC, decode_dat
from wxwatch.parser import Parser, md5
from wxwatch.watcher import MessageWatcher

KEY = "00" * 31 + "ff"
GROUP = "test123@chatroom"
ALICE = "wxid_alice"
ME = "wxid_me0000000001"
MEDIA_MD5 = "00aa42b8f9de082512e0a9ecd955a620"
JPEG_BYTES = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + b"wxwatch-fake-jpeg-body"
PDF_BYTES = b"%PDF-1.4 wxwatch fake pdf body"


def encode_v1(plain: bytes) -> bytes:
    """按 V1 .dat 结构编码（固定密钥 AES-128-ECB + 无尾段），用于造测试图片文件。"""
    return (V1_MAGIC + struct.pack("<II", len(plain), 0) + b"\x00"
            + AES.new(V1_KEY, AES.MODE_ECB).encrypt(Padding.pad(plain, 16)))


def make_enc_db(path: Path, stmts):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    conn = sqlite.connect(str(path))
    conn.execute(f"PRAGMA key=\"x'{KEY}'\"")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    for sql, params in stmts:
        conn.execute(sql, params)
    conn.commit()
    conn.close()


def build_fake_storage(base: Path) -> dict:
    ds = base / "db_storage"
    now = int(time.time())

    make_enc_db(ds / "contact" / "contact.db", [
        ("CREATE TABLE contact (id INTEGER PRIMARY KEY, username TEXT, alias TEXT,"
         " remark TEXT, nick_name TEXT)", ()),
        ("INSERT INTO contact VALUES (1,?,?,?,?)", (ALICE, "alice", "爱丽丝", "Alice")),
        ("INSERT INTO contact VALUES (2,?,?,?,?)", (GROUP, None, None, "测试群")),
        ("INSERT INTO contact VALUES (3,?,?,?,?)", (ME, None, None, "我")),
    ])
    make_enc_db(ds / "session" / "session.db", [
        ("CREATE TABLE SessionTable (username TEXT, type INTEGER, unread_count INTEGER,"
         " summary TEXT, last_timestamp INTEGER, last_msg_sender TEXT,"
         " last_sender_display_name TEXT, is_hidden INTEGER)", ()),
        ("INSERT INTO SessionTable VALUES (?,0,2,'你好',?,?,?,0)", (ALICE, now, ALICE, "Alice")),
        ("INSERT INTO SessionTable VALUES (?,0,0,'群消息',?,?,?,0)", (GROUP, now, ALICE, "Alice")),
    ])

    t_group = f"Msg_{md5(GROUP)}"
    t_alice = f"Msg_{md5(ALICE)}"
    z = zstd.ZstdCompressor(level=3)
    img_xml = (ALICE + ':\n<?xml version="1.0"?><msg><img aeskey="aabbccddeeff00112233445566778899"'
               f' md5="{MEDIA_MD5}" length="12345"/></msg>')
    packed = b"\x00\x00\x00\x00" + MEDIA_MD5.encode() + b"\x00\x00\x00\x00"

    make_enc_db(ds / "message" / "message_0.db", [
        ("CREATE TABLE Name2Id (user_name TEXT)", ()),
        ("INSERT INTO Name2Id VALUES (?)", (GROUP,)),      # rowid 1
        ("INSERT INTO Name2Id VALUES (?)", (ALICE,)),      # rowid 2
        ("INSERT INTO Name2Id VALUES (?)", (ME,)),         # rowid 3
        (f'CREATE TABLE "{t_group}" (local_id INTEGER PRIMARY KEY, server_id INTEGER,'
         ' local_type INTEGER, sort_seq INTEGER, real_sender_id INTEGER, create_time INTEGER,'
         ' status INTEGER, upload_status INTEGER, download_status INTEGER, server_seq INTEGER,'
         ' origin_source INTEGER, source TEXT, message_content TEXT, compress_content TEXT,'
         ' packed_info_data BLOB)', ()),
        # 文本（群，带发言人 id）
        (f'INSERT INTO "{t_group}" (local_id, local_type, sort_seq, real_sender_id,'
         ' create_time, message_content) VALUES (1,1,?,2,?,?)',
         (now*1000, now-100, f"{ALICE}:\n大家好")),
        # 我发的文本
        (f'INSERT INTO "{t_group}" (local_id, local_type, sort_seq, real_sender_id,'
         ' create_time, message_content) VALUES (2,1,?,3,?,?)',
         (now*1000, now-90, "我自己发的")),
        # 图片（zstd 压缩 XML + packed_info 媒体 md5）
        (f'INSERT INTO "{t_group}" (local_id, local_type, sort_seq, real_sender_id,'
         ' create_time, message_content, packed_info_data) VALUES (3,3,?,2,?,?,?)',
         (now*1000, now-80, z.compress(img_xml.encode()), packed)),
        # 文件 appmsg（sub_type=6 → 6<<32|49）
        (f'INSERT INTO "{t_group}" (local_id, local_type, sort_seq, real_sender_id,'
         ' create_time, message_content) VALUES (4,?,?,2,?,?)',
         ((6 << 32) | 49, now*1000, now-70,
          f'{ALICE}:\n<msg><appmsg><title>报告.pdf</title><type>6</type>'
          '<appattach><totallen>1024</totallen><filename>报告.pdf</filename>'
          '<fileext>pdf</fileext></appattach></appmsg></msg>')),
        # 私聊表
        (f'CREATE TABLE "{t_alice}" (local_id INTEGER PRIMARY KEY, server_id INTEGER,'
         ' local_type INTEGER, sort_seq INTEGER, real_sender_id INTEGER, create_time INTEGER,'
         ' status INTEGER, upload_status INTEGER, download_status INTEGER, server_seq INTEGER,'
         ' origin_source INTEGER, source TEXT, message_content TEXT, compress_content TEXT,'
         ' packed_info_data BLOB)', ()),
        (f'INSERT INTO "{t_alice}" (local_id, local_type, sort_seq, real_sender_id,'
         ' create_time, message_content) VALUES (1,1,?,2,?,?)',
         (now*1000, now-60, "私聊消息")),
    ])
    # 消息引用的媒体文件实体：图片 .dat（V1 编码）与文件本体，供"检测+读内容"断言
    ym = time.strftime("%Y-%m", time.localtime(now))
    img = base / "msg" / "attach" / md5(GROUP) / ym / "Img"
    img.mkdir(parents=True)
    (img / f"{MEDIA_MD5}_t.dat").write_bytes(encode_v1(JPEG_BYTES))
    fdir = base / "msg" / "file" / ym
    fdir.mkdir(parents=True)
    (fdir / "报告.pdf").write_bytes(PDF_BYTES)

    return {str(p.relative_to(ds)): {"key": KEY, "salt": p.read_bytes()[:16].hex()}
            for p in ds.rglob("*.db")}


def main():
    base = Path(tempfile.mkdtemp(prefix="wxwatch_test_"))
    try:
        ds = base / "db_storage"
        keys = build_fake_storage(base)

        # 1) keyscan
        salts = keyscan.collect_db_salts(ds)
        assert len(salts) == 3, f"期望 3 个加密库，实际 {len(salts)}"
        assert keyscan.verify_key(ds / "message" / "message_0.db", bytes.fromhex(KEY))
        assert not keyscan.verify_key(ds / "message" / "message_0.db", b"\x11" * 32)
        print("[PASS] keyscan")

        # 2) decryptor
        dec = Decryptor(ds, keys, base / "mirror")
        assert dec.sanity_check("message/message_0.db")
        out = dec.export_plaintext("contact/contact.db", base / "plain" / "contact.db")
        plain = sqlite.connect(str(out))
        assert plain.execute("SELECT COUNT(*) FROM contact").fetchone()[0] == 3
        plain.close()
        print("[PASS] decryptor")

        # 3) parser
        parser = Parser(dec, base)  # base 即模拟的微信账号根目录（含 db_storage）
        parser.self_username = ME
        contacts = parser.contacts()
        assert contacts[ALICE]["remark"] == "爱丽丝"
        sessions = parser.sessions()
        assert {s["username"] for s in sessions} == {ALICE, GROUP}
        assert sessions[0]["display_name"] in ("测试群", "爱丽丝")

        msgs = list(parser.iter_messages())
        assert len(msgs) == 5, f"期望 5 条，实际 {len(msgs)}"
        g = {m["local_id"]: m for m in msgs if m["talker"] == GROUP}

        m1 = g[1]
        assert m1["type"] == "text" and m1["content"] == "大家好"
        assert m1["sender"] == ALICE and m1["sender_name"] == "爱丽丝"
        assert m1["direction"] == "recv" and m1["chat_type"] == "group"

        m2 = g[2]
        assert m2["direction"] == "sent" and m2["sender"] == ME

        m3 = g[3]  # 图片：zstd 解压 + 媒体 md5
        assert m3["type"] == "image", m3
        assert m3["media_md5"] == MEDIA_MD5
        assert m3["media_attrs"]["md5"] == MEDIA_MD5
        # 检测到本地图片文件，且能读出（解密）内容
        assert m3.get("media_files"), m3
        img_path = Path(m3["media_files"][0])
        assert img_path.name == f"{MEDIA_MD5}_t.dat" and img_path.is_file()
        assert decode_dat(img_path) == JPEG_BYTES

        m4 = g[4]  # 文件
        assert m4["type"] == "appmsg/file", m4
        assert m4["file"]["name"] == "报告.pdf" and m4["file"]["size"] == 1024
        # 检测到本地文件，且能读出内容
        file_path = Path(m4["file"].get("path") or "")
        assert file_path.is_file(), m4
        assert file_path.read_bytes() == PDF_BYTES

        a1 = [m for m in msgs if m["talker"] == ALICE][0]
        assert a1["chat_type"] == "single" and a1["content"] == "私聊消息"
        print("[PASS] parser（文本/发言人/方向/zstd图片/文件/媒体文件检测与读内容）")

        # 4) watcher 全量 + 增量
        w = MessageWatcher(dec, parser, base / "output", verbose=False)
        assert w.parse_once() == 5
        assert w.parse_once() == 0
        t_alice = f"Msg_{md5(ALICE)}"
        conn = sqlite.connect(str(ds / "message" / "message_0.db"))
        conn.execute(f"PRAGMA key=\"x'{KEY}'\"")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute(f'INSERT INTO "{t_alice}" (local_id, local_type, real_sender_id,'
                     ' create_time, message_content) VALUES (2,1,2,?,?)',
                     (int(time.time()), "新消息"))
        conn.commit()
        conn.close()
        parser._msg_tables = None
        assert w.parse_once() == 1
        lines = (base / "output" / "messages.jsonl").read_text().strip().splitlines()
        assert len(lines) == 6
        last = json.loads(lines[-1])
        assert last["content"] == "新消息" and last["talker_name"] == "爱丽丝"
        print("[PASS] watcher 全量/增量")

        print("\n全部测试通过 ✔")
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_pipeline() -> None:
    main()


if __name__ == "__main__":
    main()
