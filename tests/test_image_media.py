"""V2 图片密钥推导、尾段 XOR 和表情下载的单元测试。全部用临时文件，不读真实微信数据。"""

import hashlib
import io
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from Crypto.Cipher import AES
from Crypto.Util import Padding

import read_wechat_conversation as reader
from wxwatch.imagedat import V2_MAGIC, decode_dat
from wxwatch.imagekey import derive_image_key_macos

JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + b"body" * 20 + b"\xff\xd9"


def encode_v2(plain: bytes, key: bytes, xor_key: int, xor_size: int = 8) -> bytes:
    head, tail = plain[:-xor_size], plain[-xor_size:]
    return (
        V2_MAGIC
        + struct.pack("<II", len(head), xor_size)
        + b"\x01"
        + AES.new(key, AES.MODE_ECB).encrypt(Padding.pad(head, 16))
        + bytes(b ^ xor_key for b in tail)
    )


def make_account(tmp_path: Path, code: int) -> tuple[Path, str]:
    documents = tmp_path / "Documents"
    kvcomm = documents / "app_data" / "net" / "kvcomm"
    kvcomm.mkdir(parents=True)
    (kvcomm / f"key_{code}_1_2_3_4_input.statistic").write_bytes(b"")
    (kvcomm / "key_0_1_2_3_4_input.statistic").write_bytes(b"")
    account = documents / "xwechat_files" / "wxid_test123_ab12"
    (account / "db_storage").mkdir(parents=True)
    key = hashlib.md5(f"{code}wxid_test123".encode()).hexdigest()[:16]
    return account, key


def test_decode_v2_uses_given_xor_key(tmp_path):
    path = tmp_path / "a.dat"
    path.write_bytes(encode_v2(JPEG, b"k" * 16, 0xAA))
    assert decode_dat(path, b"k" * 16, 0xAA) == JPEG
    # 不给 XOR key 时按 JPEG 结尾 FF D9 反推。
    assert decode_dat(path, b"k" * 16) == JPEG


def test_derive_image_key_macos(tmp_path):
    account, key = make_account(tmp_path, 123456789)
    image = account / "msg" / "attach" / "talker" / "2026-01" / "Img" / "x_t.dat"
    image.parent.mkdir(parents=True)
    image.write_bytes(encode_v2(JPEG, key.encode(), 123456789 & 0xFF))
    assert derive_image_key_macos(account) == (key, 123456789 & 0xFF)


def test_derive_image_key_macos_rejects_wrong_key(tmp_path):
    account, _key = make_account(tmp_path, 42)
    image = account / "msg" / "attach" / "t" / "2026-01" / "Img" / "x.dat"
    image.parent.mkdir(parents=True)
    image.write_bytes(encode_v2(JPEG, b"0123456789abcdef", 0x88))
    assert derive_image_key_macos(account) is None


def test_emoji_url_allowlist():
    assert reader._emoji_url_allowed("http://vweixinf.tc.qq.com/110/20401/stodownload?m=1")
    assert reader._emoji_url_allowed("https://wxapp.tc.qq.com/x")
    assert not reader._emoji_url_allowed("http://evil.example/qq.com")
    assert not reader._emoji_url_allowed("file:///etc/passwd")
    assert not reader._emoji_url_allowed("http://notqq.com/x")


def test_fetch_emoji_decrypts_encrypturl_and_caches(tmp_path, monkeypatch):
    gif = b"GIF89a" + b"\x00" * 30
    aes_key = bytes(range(16))
    encrypted = AES.new(aes_key, AES.MODE_CBC, aes_key).encrypt(Padding.pad(gif, 16))
    md5_hex = "ab" * 16
    content = (
        f'<msg><emoji md5="{md5_hex}" cdnurl="http://evil.example/a.gif" '
        f'encrypturl="http://vweixinf.tc.qq.com/enc?a=1&amp;b=2" aeskey="{aes_key.hex()}" /></msg>'
    )
    requested: list[str] = []

    def fake_urlopen(url, timeout=0):
        requested.append(url)
        return io.BytesIO(encrypted)

    monkeypatch.delenv("WECHAT_EXPORT_OFFLINE", raising=False)
    monkeypatch.setattr(reader, "_emoji_cache_dir", lambda: tmp_path / "emoji")
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    path = reader.fetch_emoji(content, md5_hex)
    assert path is not None and path.read_bytes() == gif and path.suffix == ".gif"
    # 白名单外的 cdnurl 不请求；HTML 实体按原样还原。
    assert requested == ["http://vweixinf.tc.qq.com/enc?a=1&b=2"]
    assert reader.fetch_emoji(content, md5_hex) == path
    assert len(requested) == 1


def test_fetch_emoji_offline(tmp_path, monkeypatch):
    monkeypatch.setenv("WECHAT_EXPORT_OFFLINE", "1")
    monkeypatch.setattr(reader, "_emoji_cache_dir", lambda: tmp_path / "emoji")
    assert reader.fetch_emoji('<emoji cdnurl="http://a.qq.com/x" />', "cd" * 16) is None


def test_fetch_emoji_uses_emoticon_db_fallback(tmp_path, monkeypatch):
    gif = b"GIF89a" + b"\x01" * 10
    md5_hex = "ef" * 16
    cache = tmp_path / "emoji"
    cache.mkdir()
    # 早先因为 XML 没地址而记下的失败，有了 emoticon.db 的地址后要重试。
    (cache / f"{md5_hex}.miss").touch()
    monkeypatch.delenv("WECHAT_EXPORT_OFFLINE", raising=False)
    monkeypatch.setattr(reader, "_emoji_cache_dir", lambda: cache)
    monkeypatch.setattr("urllib.request.urlopen", lambda url, timeout=0: io.BytesIO(gif))
    content = f'<msg><emoji md5="{md5_hex}" productid="" /></msg>'
    assert reader.fetch_emoji(content, md5_hex) is None
    path = reader.fetch_emoji(content, md5_hex, {"cdnurl": "http://vweixinf.tc.qq.com/x", "encrypturl": "", "aeskey": ""})
    assert path is not None and path.read_bytes() == gif
    assert not (cache / f"{md5_hex}.miss").exists()


def test_load_emoticon_index(tmp_path):
    import sqlite3

    path = tmp_path / "emoticon.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE kNonStoreEmoticonTable(md5 TEXT, cdn_url TEXT, encrypt_url TEXT, aes_key TEXT)")
        connection.execute("INSERT INTO kNonStoreEmoticonTable VALUES (?, 'http://a.qq.com/x', '', '')", ("AB" * 16,))
    backend = reader.SQLiteBackend(path)
    try:
        index = reader.load_emoticon_index([backend])
    finally:
        backend.close()
    assert index == {"ab" * 16: {"cdnurl": "http://a.qq.com/x", "encrypturl": "", "aeskey": ""}}


def test_store_emoticon_package_roundtrip() -> None:
    from Crypto.Cipher import AES
    from Crypto.Util import Padding

    gif = b"GIF89a" + b"\x02" * 20
    key = b"0123456789abcdef"
    package = AES.new(key, AES.MODE_ECB).encrypt(Padding.pad(gif, 16))
    assert reader.decrypt_emoticon_package(package, key) == gif


def test_emoticon_dtrace_listens_for_16_byte_keys() -> None:
    from cccryptor_probe import build_emoticon_dtrace_program

    program = build_emoticon_dtrace_program()
    probes = [line for line in program.splitlines() if line.startswith("pid$")]
    assert probes == ["pid$target:*:CCCrypt:entry", "pid$target:*:CCCrypt:entry", "pid$target:*:CCCryptorCreate:entry", "pid$target:*:CCCryptorCreate:entry"]
    assert all(line.count(":") == 3 for line in probes)
    assert "arg4 == 16" in program and "arg4 == 32" in program
    assert program.count("%02x") == 96


SYSMSG_INVITE = """55934890424@chatroom:
<sysmsg type="sysmsgtemplate">
<sysmsgtemplate>
<content_template type="tmpl_type_profile">
<plain><![CDATA[]]></plain>
<template><![CDATA["$username$"邀请你加入了群聊，群聊参与人还有：$others$]]></template>
<link_list>
<link name="username" type="link_profile">
<memberlist><member><username><![CDATA[wxid_a]]></username><nickname><![CDATA[沈易 ]]></nickname></member></memberlist>
</link>
<link name="others" type="link_plain"><plain><![CDATA[🐶、伟伟]]></plain></link>
</link_list>
</content_template>
</sysmsgtemplate>
</sysmsg>"""


def test_system_message_template():
    assert reader.system_message_text(SYSMSG_INVITE) == '"沈易"邀请你加入了群聊，群聊参与人还有：🐶、伟伟'


def test_system_message_custom_link():
    text = '马钰支付了沈易 发起的<_wc_custom_link_ color="#576B95" href="weixin://x?billno=1">群收款</_wc_custom_link_>'
    assert reader.system_message_text(text) == "马钰支付了沈易 发起的群收款"


def test_system_message_revoke_and_pat():
    revoke = '<sysmsg type="revokemsg"><revokemsg><session>a</session><replacemsg><![CDATA["张三" 撤回了一条消息]]></replacemsg></revokemsg></sysmsg>'
    assert reader.system_message_text(revoke) == '"张三" 撤回了一条消息'
    row = {
        "local_id": 1,
        "local_type": 10002,
        "create_time": 1_700_000_000,
        "message_content": '<sysmsg type="pat"><pat><template><![CDATA["${wxid_a}" 拍了拍 "${wxid_b}"]]></template></pat></sysmsg>',
    }
    contacts = {"wxid_a": {"nick_name": "甲"}, "wxid_b": {"nick_name": "乙"}}
    message = reader.parse_message_row(row, "g@chatroom", contacts=contacts)
    assert message.content == '[系统消息] "甲" 拍了拍 "乙"'


def test_emoji_message_has_no_link():
    row = {
        "local_id": 1,
        "local_type": 47,
        "create_time": 1_700_000_000,
        "message_content": 'wxid_x:\n<msg><emoji md5="aa" cdnurl="http://vweixinf.tc.qq.com/110/x?m=1&amp;a=2" /></msg>',
    }
    message = reader.parse_message_row(row, "g@chatroom")
    assert message.content == "[表情]"
    assert message.link_url is None and message.link_title is None


def test_system_message_hongbao_placeholder():
    row = {
        "local_id": 1,
        "local_type": 10000,
        "create_time": 1_700_000_000,
        "message_content": '<img src="SystemMessages_HongbaoIcon.png"/>  你领取了$wxid_a$的<_wc_custom_link_ color="#FD9931" href="weixin://x">红包</_wc_custom_link_>',
    }
    message = reader.parse_message_row(row, "g@chatroom", contacts={"wxid_a": {"nick_name": "甲"}})
    assert message.content == "[系统消息] 你领取了甲的红包"


def test_empty_name2id_uses_xml_fromusername():
    row = {
        "local_id": 1,
        "local_type": 43,
        "create_time": 1_700_000_000,
        "real_sender_id": 7,
        "message_content": '<msg><videomsg aeskey="x" fromusername="wxid_real" /></msg>',
    }
    # 本库 Name2Id 的 7 号名字为空，不能落到别人身上。
    message = reader.parse_message_row(row, "g@chatroom", sender_resource={7: "", 8: "wxid_other"})
    assert message.sender_wxid == "wxid_real"


def test_empty_name2id_system_message():
    row = {"local_id": 1, "local_type": 10000, "create_time": 1_700_000_000, "real_sender_id": 7, "message_content": "你已添加了甲"}
    message = reader.parse_message_row(row, "g@chatroom", sender_resource={7: ""})
    assert message.sender_name == "系统"
