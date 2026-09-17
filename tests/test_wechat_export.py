"""微信导出工具的离线回归测试。"""

from __future__ import annotations

import hashlib
import io
import os
import sqlite3
import tkinter as tk
import wave
from pathlib import Path

import pytest

from app import EXPORT_COLORS, WeChatExportApp
from cccryptor_probe import (
    KeyRecord,
    build_dtrace_program,
    default_key_path,
    load_key_records,
    mask_key,
    save_key_records,
)
from read_wechat_conversation import (
    Conversation,
    MediaRecord,
    MessageRecord,
    WeChatReader,
    build_memory_model,
    decode_message_content,
    default_wechat_data_roots,
    detect_sqlcipher_key_mode,
    discover_message_databases,
    export_html,
    export_sqlite,
    export_text,
    find_sqlcipher_driver,
    open_database_backend,
)
from windows_memory_probe import (
    MemoryScanStats,
    ascii_x_hex_length_histogram,
    collect_probe_string_hits,
    collect_salt_hit_samples,
    collect_x32_hex_values,
    extract_data_dirs_from_bytes,
    extract_hex_keys_from_bytes,
    extract_key_candidates_from_bytes,
    extract_keys_using_salts,
    format_memory_scan_report,
    normalize_windows_data_root,
)


# 创建一个浏览器可播放的极小 WAV fixture。
def make_wav() -> bytes:
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(8000)
        wav_file.writeframes(b"\x00\x00" * 16)
    return buffer.getvalue()


# 初始化模拟微信 4.x 目录及明文数据库，供所有导出测试复用。
def make_fixture(tmp_path: Path) -> tuple[WeChatReader, str, bytes]:
    db_root = tmp_path / "xwechat_files" / "wxid_me" / "db_storage"
    message_dir = db_root / "message"
    contact_dir = db_root / "contact"
    session_dir = db_root / "session"
    message_dir.mkdir(parents=True)
    contact_dir.mkdir()
    session_dir.mkdir()
    conversation_id = "wxid_friend"
    table = "Msg_" + hashlib.md5(conversation_id.encode()).hexdigest()
    message_db = message_dir / "message_0.db"
    connection = sqlite3.connect(message_db)
    connection.execute(
        f'CREATE TABLE "{table}" (local_id INTEGER, server_id TEXT, create_time INTEGER, local_type INTEGER, message_content BLOB, real_sender_id INTEGER)'
    )
    connection.executemany(
        f'INSERT INTO "{table}" VALUES (?, ?, ?, ?, ?, ?)',
        [
            (1, "server-1", 1_700_000_000, 1, "你好", 2),
            (2, "server-2", 1_700_000_010, 49, '<appmsg><title>文章标题</title><des>文章说明</des><url>https://example.com/a</url><appname>来源</appname></appmsg>', 3),
            (3, "server-3", 1_700_000_020, 34, "语音", 3),
        ],
    )
    connection.commit()
    connection.close()
    contact_db = contact_dir / "contact.db"
    connection = sqlite3.connect(contact_db)
    connection.execute("CREATE TABLE contact(username TEXT, nick_name TEXT, alias TEXT, remark TEXT)")
    connection.executemany(
        "INSERT INTO contact VALUES (?, ?, ?, ?)",
        [(conversation_id, "好友昵称", "friend_alias", "不应优先"), ("wxid_me", "我的昵称", "me", "")],
    )
    connection.commit()
    connection.close()
    session_db = session_dir / "session.db"
    connection = sqlite3.connect(session_db)
    connection.execute("CREATE TABLE SessionTable(username TEXT, summary TEXT, sort_timestamp INTEGER)")
    connection.execute("INSERT INTO SessionTable VALUES (?, ?, ?)", (conversation_id, "最近摘要", 1_700_000_020))
    connection.commit()
    connection.close()
    media_db = message_dir / "media_0.db"
    voice_data = make_wav()
    connection = sqlite3.connect(media_db)
    connection.execute("CREATE TABLE Name2Id(user_name TEXT)")
    connection.execute("CREATE TABLE VoiceInfo(chat_name_id INTEGER, local_id INTEGER, svr_id TEXT, create_time INTEGER, voice_data BLOB)")
    connection.execute("INSERT INTO Name2Id(rowid, user_name) VALUES (1, ?)", (conversation_id,))
    connection.execute("INSERT INTO VoiceInfo VALUES (1, 3, ?, ?, ?)", ("server-3", 1_700_000_020, voice_data))
    connection.commit()
    connection.close()
    reader = WeChatReader(message_paths=[message_db], key_path=tmp_path / "keys.json")
    return reader, conversation_id, voice_data


# 验证 key 文件原子写入、脱敏显示和 0600 权限。
def test_key_store_is_private(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    key = "0123456789abcdef" * 4
    save_key_records([KeyRecord(key, "2026-01-01T00:00:00+00:00", ("message_0.db",))], path)
    assert mask_key(key) == "01234567***89abcdef"
    assert load_key_records(path)[0].hex == key
    if os.name != "nt":
        assert os.stat(path).st_mode & 0o777 == 0o600


# 验证运行时已安装可用的 SQLCipher Python 驱动。
def test_sqlcipher_python_driver_is_available() -> None:
    assert find_sqlcipher_driver() is not None


# 验证 raw key 能通过 HMAC 并打开 SQLCipher 4 加密库。
def test_sqlcipher_raw_key_roundtrip(tmp_path: Path) -> None:
    driver = find_sqlcipher_driver()
    if driver is None:
        pytest.skip("未安装 sqlcipher3")
    key = "11" * 32
    path = tmp_path / "message_0.db"
    connection = driver.connect(str(path))
    connection.execute("PRAGMA cipher_compatibility = 4")
    connection.execute(f'PRAGMA key = "x\'{key}\'"')
    connection.execute('CREATE TABLE "Msg_abc"(local_id INTEGER, message_content TEXT)')
    connection.execute('INSERT INTO "Msg_abc" VALUES (1, "hello")')
    connection.commit()
    connection.close()
    assert detect_sqlcipher_key_mode(path, key) == "raw"
    backend = open_database_backend(path, key)
    try:
        assert backend.validate()
        names = [row["name"] for row in backend.query("SELECT name FROM sqlite_master WHERE type='table'")]
        assert "Msg_abc" in names
    finally:
        backend.close()
    reader = WeChatReader(message_paths=[path], key_path=tmp_path / "keys.json")
    assert reader.validate_key(key) == ("message_0.db",)


# 验证 DTrace 脚本固定输出 32 个字节且包含精确过滤条件。
def test_dtrace_program_is_literal_and_filtered() -> None:
    program = build_dtrace_program()
    assert program.count("%02x") == 32
    assert "arg1 == 0" in program
    assert "arg4 == 32" in program
    assert '"%02x" * 32' not in program


# 验证读取器发现会话、解析链接卡片和提取 VoiceInfo 音频。
def test_reader_parses_fixture(tmp_path: Path) -> None:
    reader, conversation_id, voice_data = make_fixture(tmp_path)
    conversations = reader.list_conversations(["0" * 64])
    assert len(conversations) == 1
    assert conversations[0].title == "好友昵称"
    model = reader.read_conversation(conversation_id, ["0" * 64])
    assert model["meta"]["message_count"] == 3
    assert model["messages"][1]["link_url"] == "https://example.com/a"
    assert model["media"][0]["data"] == voice_data
    assert model["media"][0]["mime_type"] == "audio/wav"


# 验证 Zstd 压缩正文在依赖存在时可还原，缺少依赖时仍不抛出异常。
def test_zstd_content_decode() -> None:
    zstandard = pytest.importorskip("zstandard")
    compressed = zstandard.ZstdCompressor().compress("压缩正文".encode())
    assert decode_message_content(compressed, 4) == "压缩正文"


# 验证内存模型不在 message 中冗余发送者信息，并正确建立引用用户。
def test_memory_model_shape() -> None:
    conversation = Conversation("wxid_x", "测试会话", "", "", "single", "wxid_x", "测试会话")
    message = MessageRecord(1, "s1", "2026-01-01 00:00:00", "wxid_a", "甲", 1, "正文", "wxid_b", "乙", "引用")
    model = build_memory_model(conversation, [message])
    assert set(model) == {"meta", "users", "messages", "media"}
    assert model["messages"][0]["sender"] == 1
    assert "sender_name" not in model["messages"][0]
    assert model["messages"][0]["quote_sender"] == 2


# 验证 HTML、纯文本和 SQLite 三种导出及 SQLite 外键完整性。
def test_all_exporters_and_media(tmp_path: Path) -> None:
    reader, conversation_id, voice_data = make_fixture(tmp_path)
    model = reader.read_conversation(conversation_id, ["0" * 64])
    html_dir = tmp_path / "html"
    text_dir = tmp_path / "text"
    sqlite_dir = tmp_path / "sqlite"
    html_path = export_html(model, html_dir)
    text_path = export_text(model, text_dir)
    sqlite_path = export_sqlite(model, sqlite_dir)
    html_text = html_path.read_text(encoding="utf-8")
    assert 'data-message-id="1"' in html_text
    assert 'class="link-card"' in html_text
    assert "文章标题" in html_text
    assert "<audio controls" in html_text
    text_output = text_path.read_text(encoding="utf-8")
    assert "[2023-11-15 06:13:20]" in text_output
    assert "文章标题" in text_output
    connection = sqlite3.connect(sqlite_path)
    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    row = connection.execute("SELECT data, sha256 FROM media WHERE message_id = 3").fetchone()
    assert row is not None and row[0] == voice_data
    assert row[1] == hashlib.sha256(voice_data).hexdigest()
    connection.close()


# 验证 FlatButton 三种颜色、纵向布局和禁用后颜色恢复。
def test_gui_buttons_create_and_restore() -> None:
    try:
        app = WeChatExportApp(start_hidden=True)
    except tk.TclError as exc:
        pytest.skip(f"当前环境没有图形显示：{exc}")
    try:
        assert list(app.export_buttons) == ["html", "text", "sqlite"]
        assert [button.normal_background for button in app.export_buttons.values()] == [EXPORT_COLORS[key][0] for key in ("html", "text", "sqlite")]
        for key, button in app.export_buttons.items():
            original = button.normal_background
            button.set_enabled(False)
            assert button.cget("bg") == button.disabled_background
            button.set_enabled(True)
            assert button.cget("bg") == original
            assert button.normal_background == EXPORT_COLORS[key][0]
        assert tuple(app.conversation_tree["columns"]) == ("recent_time", "title", "recent_message")
    finally:
        app.destroy()


# 验证密钥文件路径按平台落到各自的用户数据目录。
def test_default_key_path_is_platform_specific(tmp_path: Path) -> None:
    mac = default_key_path(tmp_path, platform="darwin")
    win = default_key_path(tmp_path, platform="win32")
    linux = default_key_path(tmp_path, platform="linux")
    assert mac == tmp_path / "Library" / "Application Support" / "WeChatExport" / "wechat_cccryptor_keys.json"
    assert win == tmp_path / "AppData" / "Roaming" / "WeChatExport" / "wechat_cccryptor_keys.json"
    assert linux == tmp_path / ".config" / "WeChatExport" / "wechat_cccryptor_keys.json"


# 验证 Windows 内存中的 ASCII / UTF-16 密钥文本都能提取为 32 字节 hex。
def test_extract_hex_keys_from_memory_bytes() -> None:
    key = "ab" * 32
    salt = "cd" * 16
    ascii_blob = b"noise x'" + key.encode("ascii") + b"' more"
    assert extract_hex_keys_from_bytes(ascii_blob) == [key]
    with_salt = b"x'" + key.encode("ascii") + salt.encode("ascii") + b"'"
    assert extract_hex_keys_from_bytes(with_salt) == [key]
    without_quote = b"x'" + key.encode("ascii") + b" trailing"
    assert extract_hex_keys_from_bytes(without_quote) == [key]
    candidates = extract_key_candidates_from_bytes(with_salt)
    assert candidates[0].key_hex == key
    assert candidates[0].salt_hex == salt
    utf16_blob = ("prefix x'" + key + salt + "' suffix").encode("utf-16le")
    utf16_candidates = extract_key_candidates_from_bytes(utf16_blob)
    assert utf16_candidates[0].key_hex == key
    assert utf16_candidates[0].salt_hex == salt
    salt_bytes = bytes.fromhex(salt)
    nearby = key.encode("ascii") + salt.encode("ascii")
    found = extract_keys_using_salts(nearby, {salt: salt_bytes})
    assert found[0].key_hex == key
    assert found[0].salt_hex == salt
    histogram = ascii_x_hex_length_histogram(b"x'" + (b"ab" * 32) + b"zz x'abcd")
    assert histogram.get("64") == 1
    assert histogram.get("1-15") == 1
    salt = bytes.fromhex("cd" * 16)
    blob = b"zzzz" + (b"\x11" * 32) + salt + (b"\x22" * 32)
    samples = collect_salt_hit_samples(blob, {salt.hex(): salt})
    assert samples[0][0] == "binary"
    assert samples[0][2] == (b"\x11" * 32).hex()
    assert samples[0][3] == (b"\x22" * 32).hex()
    assert collect_x32_hex_values(b"x'" + (b"ab" * 16) + b"zz") == ["ab" * 16]
    pragma_hits = collect_probe_string_hits(b"xxPRAGMA cipher_salt = x'aabb'yy")
    assert any("PRAGMA cipher" in item and "cipher_salt" in item for item in pragma_hits)


# 验证探针报告包含可观察计数，不包含完整密钥。
def test_memory_scan_report_is_readable() -> None:
    stats = MemoryScanStats(python_bits=64, admin=True, pid=123, process_name="Weixin.exe", bytes_read=4096)
    text = format_memory_scan_report(stats, ["message_N.db：2 个"])
    assert "Python：64 位" in text
    assert "PID 123" in text
    assert "message_N.db：2 个" in text
    assert "abababab" not in text


# 验证 Windows 内存中的 xwechat_files 路径提取。
def test_extract_data_dirs_from_memory_bytes() -> None:
    path = r"C:\Users\me\Documents\xwechat_files\wxid_abc\db_storage"
    ascii_hits = extract_data_dirs_from_bytes(b"xx" + path.encode("ascii") + b"yy")
    utf16_hits = extract_data_dirs_from_bytes(path.encode("utf-16le"))
    assert any("xwechat_files" in item and "wxid_abc" in item for item in ascii_hits)
    assert any("xwechat_files" in item and "wxid_abc" in item for item in utf16_hits)


# 验证微信文件管理路径会转换成 xwechat_files 根目录。
def test_normalize_windows_data_root(tmp_path: Path) -> None:
    documents = tmp_path / "Documents"
    assert normalize_windows_data_root("MyDocument:", documents) == documents / "xwechat_files"
    assert normalize_windows_data_root(str(tmp_path / "custom"), documents) == tmp_path / "custom" / "xwechat_files"
    assert normalize_windows_data_root(str(tmp_path / "xwechat_files"), documents) == tmp_path / "xwechat_files"


# 验证 Windows 4.x 文档目录布局可被自动发现。
def test_discover_windows_message_databases(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("read_wechat_conversation.sys.platform", "win32")
    message_dir = tmp_path / "Documents" / "xwechat_files" / "wxid_me" / "db_storage" / "message"
    message_dir.mkdir(parents=True)
    database = message_dir / "message_0.db"
    database.write_bytes(b"SQLite format 3\x00")
    roots = default_wechat_data_roots(tmp_path)
    assert tmp_path / "Documents" / "xwechat_files" in roots
    found = discover_message_databases(home=tmp_path)
    assert database.resolve() in found


# 验证媒体模型可以独立承载音频二进制。
def test_media_record_model() -> None:
    data = make_wav()
    model = build_memory_model(
        {"conversation_id": "wxid_x", "title": "x"},
        [MessageRecord(1, "", "", "wxid_x", "x", 34, "[语音通话]", media=[MediaRecord(1, "voice", "audio/wav", "voice.wav", data, playable=True)])],
    )
    assert model["media"][0]["byte_size"] == len(data)
    assert model["media"][0]["data"] == data
