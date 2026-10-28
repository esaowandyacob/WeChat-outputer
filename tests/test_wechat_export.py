"""微信导出工具的离线回归测试。"""

from __future__ import annotations

import datetime
import hashlib
import io
import os
import sqlite3
import subprocess
import sys
import tkinter as tk
import wave
from pathlib import Path

import pytest

from app import (
    EXPORT_COLORS,
    WeChatExportApp,
    dependency_report,
    install_missing_dependencies,
)
from cccryptor_probe import (
    PROBE_SPEC,
    KeyRecord,
    build_dtrace_program,
    default_key_path,
    ensure_sudo_askpass,
    ensure_sudo_credentials,
    load_key_records,
    mask_key,
    save_key_records,
    sudo_environment,
)
from read_wechat_conversation import (
    Conversation,
    MediaRecord,
    MessageRecord,
    WeChatReader,
    build_memory_model,
    current_wechat_account_key,
    decode_message_content,
    detect_sqlcipher_key_mode,
    discover_message_databases,
    export_html,
    export_model,
    export_sqlite,
    export_text,
    plan_export_concurrency,
    parse_message_row,
    find_sqlcipher_driver,
    local_media_files,
    local_media_path,
    open_database_backend,
    preferred_display_name,
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


# 验证图形密码助手只存在于用户目录，并且不会把密码写进脚本。
def test_sudo_askpass_script_is_private(tmp_path: Path) -> None:
    path = ensure_sudo_askpass(tmp_path)
    text = path.read_text(encoding="utf-8")
    assert path.stat().st_mode & 0o777 == 0o700
    assert "display dialog" in text
    assert "with hidden answer" in text
    assert "password" not in text.lower()
    env = sudo_environment(tmp_path)
    assert env["SUDO_ASKPASS"] == str(path)


# 验证 DTrace 脚本固定输出 32 个字节且包含精确过滤条件。
def test_dtrace_program_is_literal_and_filtered() -> None:
    program = build_dtrace_program()
    description = program.splitlines()[0]
    assert description == PROBE_SPEC
    assert description.count(":") == 3
    assert program.count("%02x") == 32
    assert "arg1 == 0" in program
    assert "arg4 == 32" in program
    assert '"%02x" * 32' not in program


# 验证管理员密码只在 sudo 缓存失效时询问一次。
def test_sudo_credentials_reuse_timestamp(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []
    cache_ready = {"value": False}

    # 用假的 sudo 记录命令，并在第一次 -v 之后把缓存标记为可用。
    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(list(command))
        if command == ["sudo", "-n", "true"]:
            code = 0 if cache_ready["value"] else 1
            return subprocess.CompletedProcess(command, code, b"", b"" if code == 0 else b"a password is required")
        if command == ["sudo", "-A", "-v"]:
            assert kwargs.get("env", {}).get("SUDO_ASKPASS") == str(tmp_path / "askpass")
            cache_ready["value"] = True
            return subprocess.CompletedProcess(command, 0, b"", b"")
        raise AssertionError(command)

    monkeypatch.setattr("cccryptor_probe.subprocess.run", fake_run)
    monkeypatch.setattr("cccryptor_probe.sudo_environment", lambda directory=None: {"SUDO_ASKPASS": str(tmp_path / "askpass")})
    assert ensure_sudo_credentials() is None
    assert ensure_sudo_credentials() is None
    assert calls == [
        ["sudo", "-n", "true"],
        ["sudo", "-A", "-v"],
        ["sudo", "-n", "true"],
        ["sudo", "-n", "true"],
    ]
    assert calls.count(["sudo", "-A", "-v"]) == 1


# 验证超长的伪路径不会报错，真实媒体按 md5 路径读出。
def test_local_media_path_skips_overlong_names(tmp_path: Path) -> None:
    note = tmp_path / "note.txt"
    note.write_text("hi", encoding="utf-8")
    assert local_media_path({"media_path": "note.txt"}, tmp_path) == note.resolve()
    assert local_media_path({"media_path": "a" * 300}, tmp_path) is None
    assert local_media_path({"message_content": f"<cdnthumburl>{'ab' * 200}</cdnthumburl>"}, tmp_path) is None
    media_md5 = "ab" * 16
    talker = "wxid_friend"
    month = datetime.datetime.fromtimestamp(1_700_000_000).strftime("%Y-%m")
    image = tmp_path / "msg" / "attach" / hashlib.md5(talker.encode()).hexdigest() / month / "Img" / f"{media_md5}.dat"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"\xff\xd8\xff\xd9")
    found = local_media_files(
        {"local_type": 3, "create_time": 1_700_000_000, "packed_info_data": media_md5.encode()},
        tmp_path,
        talker,
    )
    assert found == [image.resolve()]
    media_md5 = "cd" * 16
    month = datetime.datetime.fromtimestamp(1_700_000_000).strftime("%Y-%m")
    video_dir = tmp_path / "msg" / "video" / month
    video_dir.mkdir(parents=True)
    movie = video_dir / f"{media_md5}.mp4"
    thumb = video_dir / f"{media_md5}_thumb.jpg"
    movie.write_bytes(b"mp4")
    thumb.write_bytes(b"jpg")
    videos = local_media_files(
        {"local_type": 43, "create_time": 1_700_000_000, "packed_info_data": media_md5.encode()},
        tmp_path,
        talker,
    )
    assert videos == [movie.resolve()]
    emoji_md5 = "ef" * 16
    emoji = tmp_path / "cache" / "2024-01" / emoji_md5
    emoji.parent.mkdir(parents=True)
    emoji.write_bytes(b"GIF89a")
    emojis = local_media_files(
        {
            "local_type": 47,
            "create_time": 1_700_000_000,
            "message_content": f'<emoji md5="{emoji_md5}"></emoji>',
        },
        tmp_path,
        talker,
    )
    assert emojis == [emoji.resolve()]


# 验证账号自己显示为“我”，对方仍用当前库的 Name2Id，而不是别的库里的同号发送者。
def test_account_owner_is_me_and_peer_uses_local_name2id() -> None:
    contacts = {
        "wxid_eahb9kfz0eaq22": {"nick_name": "夜航星"},
        "wxid_friend": {"nick_name": "BOOK", "remark": "宇文"},
    }
    mine = parse_message_row(
        {"real_sender_id": 3, "local_id": 1, "create_time": 1_700_000_000, "local_type": 1, "message_content": "你好"},
        "wxid_friend",
        contacts=contacts,
        sender_resource={3: "wxid_eahb9kfz0eaq22"},
        self_wxid="wxid_eahb9kfz0eaq22_a9d3",
    )
    peer = parse_message_row(
        {"real_sender_id": 27, "local_id": 2, "create_time": 1_700_000_010, "local_type": 1, "message_content": "在吗"},
        "wxid_friend",
        contacts=contacts,
        sender_resource={27: "wxid_friend"},
        self_wxid="wxid_eahb9kfz0eaq22_a9d3",
    )
    assert mine.sender_name == "我"
    assert peer.sender_name == "BOOK（宇文）"
    # 正文里偶然出现的“名字:”不能把发送者改成别人。
    mistaken = parse_message_row(
        {
            "real_sender_id": 27,
            "local_id": 3,
            "create_time": 1_700_000_020,
            "local_type": 1,
            "message_content": "wxid_other:\n这不是那个人发的",
        },
        "wxid_friend",
        contacts=contacts,
        sender_resource={27: "wxid_friend"},
        self_wxid="wxid_eahb9kfz0eaq22_a9d3",
    )
    assert mistaken.sender_wxid == "wxid_friend"
    assert mistaken.content == "wxid_other:\n这不是那个人发的"


# 验证再次导出 HTML 会换掉目录里上一次的页面和 media。
def test_html_export_overwrites_previous_files(tmp_path: Path) -> None:
    media = tmp_path / "media"
    media.mkdir()
    (media / "old.png").write_bytes(b"old")
    (tmp_path / "index.html").write_text("old", encoding="utf-8")
    conversation = Conversation("wxid_friend", "好友", "", "", "single", "wxid_friend", "好友")
    message = MessageRecord(1, "s1", "2026-01-01 00:00:00", "wxid_friend", "好友", 1, "你好")
    export_html(build_memory_model(conversation, [message]), tmp_path)
    text = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "你好" in text
    assert not (media / "old.png").exists()


# 验证显示名保留原名，并在有不同备注时追加括号。
def test_display_name_appends_remark() -> None:
    assert preferred_display_name("wxid_a", {"nick_name": "张三", "remark": "同事"}) == "张三（同事）"
    assert preferred_display_name("wxid_a", {"nick_name": "张三", "remark": "张三"}) == "张三"
    assert preferred_display_name("wxid_a", {"nick_name": "张三", "remark": ""}) == "张三"
    assert preferred_display_name(
        "123@chatroom",
        {"nick_name": "项目群", "remark": "工作"},
        {},
    ) == "项目群（工作）"


# 在一个账号目录里放一张只含一条文本的明文消息表。
def _write_account_message(account_dir: Path, conversation_id: str, server_id: str, sent_at: int, text: str) -> None:
    message_dir = account_dir / "db_storage" / "message"
    message_dir.mkdir(parents=True)
    table = "Msg_" + hashlib.md5(conversation_id.encode()).hexdigest()
    connection = sqlite3.connect(message_dir / "message_0.db")
    connection.execute(
        f'CREATE TABLE "{table}" (local_id INTEGER, server_id TEXT, create_time INTEGER, local_type INTEGER, message_content BLOB, real_sender_id INTEGER)'
    )
    connection.execute(
        f'INSERT INTO "{table}" VALUES (1, ?, ?, 1, ?, 1)',
        (server_id, sent_at, text),
    )
    connection.commit()
    connection.close()


# 自动扫描多个微信号时，只读取最近登录的那个号，不把其他号的同群历史拼进来。
def test_reader_keeps_current_account_messages(tmp_path: Path) -> None:
    conversation_id = "44550358316@chatroom"
    files = tmp_path / "xwechat_files"
    current_dir = files / "wxid_current_aa11"
    previous_dir = files / "wxid_previous_bb22"
    _write_account_message(current_dir, conversation_id, "current-only", 1_720_000_000, "当前账号的消息")
    _write_account_message(previous_dir, conversation_id, "previous-only", 1_700_000_000, "其他账号的旧消息")
    home = tmp_path / "home"
    login = home / "Library" / "Containers" / "com.tencent.xinWeChat" / "Data" / "Documents" / "xwechat_files" / "all_users" / "login"
    (login / "wxid_current").mkdir(parents=True)
    (login / "wxid_previous").mkdir(parents=True)
    os.utime(login / "wxid_previous", (1_700_000_000, 1_700_000_000))
    os.utime(login / "wxid_current", (1_720_000_000, 1_720_000_000))
    assert current_wechat_account_key(home) == "wxid_current"
    discovered = discover_message_databases(files, home)
    assert [path.parent.parent.parent.name for path in discovered] == ["wxid_current_aa11"]
    reader = WeChatReader(data_root=files, key_path=tmp_path / "keys.json", home=home)
    model = reader.read_conversation(conversation_id, ["0" * 64], media_mode="serial")
    contents = [item["content"] for item in model["messages"]]
    assert contents == ["当前账号的消息"]
    explicit = WeChatReader(data_root=previous_dir, key_path=tmp_path / "keys.json", home=home)
    previous_model = explicit.read_conversation(conversation_id, ["0" * 64], media_mode="serial")
    assert [item["content"] for item in previous_model["messages"]] == ["其他账号的旧消息"]


# 验证没有联系人库时，会话列表仍能用 Name2Id 显示微信 ID、时间和最新消息。
def test_conversation_list_resolves_name2id_preview(tmp_path: Path) -> None:
    conversation_id = "wxid_friend"
    table = "Msg_" + hashlib.md5(conversation_id.encode()).hexdigest()
    message_dir = tmp_path / "message"
    message_dir.mkdir()
    message_db = message_dir / "message_0.db"
    connection = sqlite3.connect(message_db)
    connection.execute(
        f'CREATE TABLE "{table}" (local_id INTEGER, create_time INTEGER, sort_seq INTEGER, local_type INTEGER, message_content TEXT)'
    )
    connection.execute(f'INSERT INTO "{table}" VALUES (1, 1700000000, 1, 1, ?)', ("第一条",))
    connection.execute(f'INSERT INTO "{table}" VALUES (2, 1700000090, 2, 1, ?)', ("最新一条",))
    connection.execute("CREATE TABLE Name2Id(user_name TEXT)")
    connection.execute("INSERT INTO Name2Id(user_name) VALUES (?)", (conversation_id,))
    connection.commit()
    connection.close()
    reader = WeChatReader(message_paths=[message_db], key_path=tmp_path / "keys.json")
    conversations = reader.list_conversations(["0" * 64])
    assert [item.conversation_id for item in conversations] == [conversation_id]
    assert conversations[0].title == conversation_id
    assert conversations[0].recent_message == "最新一条"
    assert conversations[0].recent_time
    assert reader.names_resolved is False


# 验证读取器发现会话、解析链接卡片和提取 VoiceInfo 音频。
def test_reader_parses_fixture(tmp_path: Path) -> None:
    reader, conversation_id, voice_data = make_fixture(tmp_path)
    conversations = reader.list_conversations(["0" * 64])
    assert len(conversations) == 1
    assert conversations[0].title == "好友昵称（不应优先）"
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


def test_plan_export_concurrency(monkeypatch: pytest.MonkeyPatch) -> None:
    import read_wechat_conversation as conversation_reader

    monkeypatch.setattr(conversation_reader.os, "cpu_count", lambda: 8)
    assert plan_export_concurrency(1) == (1, 8)
    assert plan_export_concurrency(3) == (3, 2)
    assert plan_export_concurrency(10) == (4, 2)
    monkeypatch.setattr(conversation_reader.os, "cpu_count", lambda: 1)
    assert plan_export_concurrency(5) == (1, 1)
    monkeypatch.setattr(conversation_reader.os, "cpu_count", lambda: None)
    assert plan_export_concurrency(1) == (1, 1)


def _tiny_png() -> bytes:
    import struct
    import zlib

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    raw = b"\x00\xff\x00\x00"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


# 验证 PDF 带上正文，TXT 仍走原来的纯文本导出。
def test_export_pdf_and_txt(tmp_path: Path) -> None:
    pytest.importorskip("fpdf")
    reader, conversation_id, _voice_data = make_fixture(tmp_path)
    model = reader.read_conversation(conversation_id, ["0" * 64])
    model["media"].append(
        {
            "message_id": model["messages"][0]["local_id"],
            "media_type": "image",
            "mime_type": "image/png",
            "filename": "pic.png",
            "data": _tiny_png(),
        }
    )
    pdf_path = export_model(model, "pdf", tmp_path / "pdf")
    assert pdf_path.name == "chat.pdf"
    assert pdf_path.read_bytes().startswith(b"%PDF")
    text_path = export_model(model, "txt", tmp_path / "txt")
    assert text_path.name == "chat.txt"
    assert "文章标题" in text_path.read_text(encoding="utf-8")
    extracted = subprocess.run(["pdftotext", str(pdf_path), "-"], capture_output=True, text=True)
    if extracted.returncode == 0:
        assert "文章标题" in extracted.stdout
        assert "2023-11-15 06:13:20" in extracted.stdout


def test_dependency_report_lists_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    import app as app_module

    monkeypatch.setattr(app_module, "missing_python_packages", lambda: ["fpdf2"])
    monkeypatch.setattr(app_module, "ffmpeg_available", lambda: False)
    text, kind = dependency_report()
    assert kind == "idle"
    assert "fpdf2" in text
    assert "ffmpeg" in text
    monkeypatch.setattr(app_module, "missing_python_packages", lambda: [])
    monkeypatch.setattr(app_module, "ffmpeg_available", lambda: True)
    ready_text, ready_kind = dependency_report()
    assert ready_kind == "ok"
    assert ready_text == "依赖已就绪"


def test_install_dependencies_invokes_pip_and_brew(monkeypatch: pytest.MonkeyPatch) -> None:
    import app as app_module

    calls: list[list[str]] = []
    monkeypatch.setattr(app_module, "missing_python_packages", lambda: ["fpdf2"])
    monkeypatch.setattr(app_module, "ffmpeg_available", lambda: False)
    monkeypatch.setattr(app_module, "_find_brew", lambda: "/opt/homebrew/bin/brew")

    def fake_run(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(list(cmd))
        if "fpdf2" in cmd:
            monkeypatch.setattr(app_module, "missing_python_packages", lambda: [])
        if cmd[-2:] == ["install", "ffmpeg"]:
            monkeypatch.setattr(app_module, "ffmpeg_available", lambda: True)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(app_module.subprocess, "run", fake_run)
    ok, detail = install_missing_dependencies()
    assert ok, detail
    assert calls[0][0] == sys.executable
    assert "fpdf2" in calls[0]
    assert calls[1] == ["/opt/homebrew/bin/brew", "install", "ffmpeg"]

    monkeypatch.setattr(app_module, "missing_python_packages", lambda: [])
    monkeypatch.setattr(app_module, "ffmpeg_available", lambda: False)
    monkeypatch.setattr(app_module, "_find_brew", lambda: None)
    failed, message = install_missing_dependencies()
    assert not failed
    assert "Homebrew" in message


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
        assert list(app.export_buttons) == ["html", "txt", "pdf", "sqlite"]
        assert [button.normal_background for button in app.export_buttons.values()] == [
            EXPORT_COLORS[key][0] for key in ("html", "txt", "pdf", "sqlite")
        ]
        assert app.dependency_button.cget("text") == "一键设置依赖"
        assert not hasattr(app, "media_mode_var")
        assert "核" in app.concurrency_var.get()
        for key, button in app.export_buttons.items():
            original = button.normal_background
            button.set_enabled(False)
            assert button.cget("bg") == button.disabled_background
            button.set_enabled(True)
            assert button.cget("bg") == original
            assert button.normal_background == EXPORT_COLORS[key][0]
        assert tuple(app.conversation_tree["columns"]) == ("recent_time", "title", "recent_message")
        assert str(app.conversation_tree["selectmode"]) == "extended"
        app._conversations_loaded(
            [
                Conversation("wxid_a", "甲", "t1", "m1"),
                Conversation("wxid_b", "乙", "t2", "m2"),
            ],
            None,
        )
        app._select_all_conversations()
        assert [item.conversation_id for item in app._selected_conversations()] == ["wxid_a", "wxid_b"]
        app._clear_conversation_selection()
        assert app._selected_conversations() == []
        dialog = app._show_copyable_dialog("采集失败", "Overspecified probe description")
        assert dialog.title() == "采集失败"
        assert "Overspecified probe description" in dialog.result_text.get("1.0", "end")
        dialog.copy_button.invoke()
        assert app.clipboard_get() == "Overspecified probe description"
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


# 验证媒体模型可以独立承载音频二进制。
def test_media_record_model() -> None:
    data = make_wav()
    model = build_memory_model(
        {"conversation_id": "wxid_x", "title": "x"},
        [MessageRecord(1, "", "", "wxid_x", "x", 34, "[语音通话]", media=[MediaRecord(1, "voice", "audio/wav", "voice.wav", data, playable=True)])],
    )
    assert model["media"][0]["byte_size"] == len(data)
    assert model["media"][0]["data"] == data
