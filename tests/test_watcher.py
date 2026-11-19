"""验证实时预览与持久化导出的隔离，以及重启后的会话文件归属。"""

import json
from pathlib import Path

import pytest

from wxwatch.watcher import MessageWatcher


class FakeParser:
    # 用合成消息模拟按游标读取，避免访问真实微信数据库。
    def __init__(self):
        self.messages = [
            {"table": "test:messages", "local_id": local_id,
             "talker": "wxid_test", "talker_name": "测试会话"}
            for local_id in (1, 2)
        ]

    # 只返回当前游标之后的消息，以验证重启和增量读取。
    def iter_messages(self, since):
        for message in self.messages:
            if message["local_id"] > since.get(message["table"], 0):
                yield message

    # 返回合成会话列表，用于检查预览模式不会写会话清单。
    def sessions(self):
        return [{"username": "wxid_test"}]


# 预览生命周期不得创建输出目录，也不得阻止后续完整持久化。
def test_preview_does_not_create_output_or_advance_export(tmp_path: Path):
    output = tmp_path / "output"
    received = []
    preview = MessageWatcher(None, FakeParser(), output, verbose=False,
                             persist=False, on_message=received.append)
    assert preview.parse_once() == 2
    assert preview.parse_once() == 0
    preview.refresh_conversations()
    preview.stop()
    assert len(received) == 2
    assert not output.exists()

    persistent = MessageWatcher(None, FakeParser(), output, verbose=False)
    assert persistent.parse_once() == 2
    persistent.refresh_conversations()
    persistent.stop()
    assert (output / "conversations.json").exists()
    assert len((output / "messages.jsonl").read_text().splitlines()) == 2
    assert MessageWatcher(None, FakeParser(), output, verbose=False).parse_once() == 0


# 已有导出游标和会话清单不得影响预览，也不得被预览停止覆盖。
def test_preview_preserves_existing_export_state(tmp_path: Path):
    state = tmp_path / "state.json"
    state.write_text('{"test:messages": 1}\n', encoding="utf-8")
    conversations = tmp_path / "conversations.json"
    conversations.write_text('[{"username": "previous"}]\n', encoding="utf-8")
    original = {path.name: path.read_bytes() for path in tmp_path.iterdir()}

    preview = MessageWatcher(None, FakeParser(), tmp_path, verbose=False, persist=False)
    assert preview.parse_once() == 2
    preview.refresh_conversations()
    preview.stop()
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == original

    persistent = MessageWatcher(None, FakeParser(), tmp_path, verbose=False)
    assert persistent.parse_once() == 1
    exported = json.loads((tmp_path / "messages.jsonl").read_text())
    assert exported["local_id"] == 2


# 同名、文件名清洗碰撞和截断碰撞都必须跨重启保持独立文件。
@pytest.mark.parametrize("names", [
    ("同名会话", "同名会话"),
    ("会话/名称", "会话?名称"),
    ("长" * 64 + "甲", "长" * 64 + "乙"),
])
def test_chat_files_stay_separate_across_restarts(tmp_path: Path, names):
    messages = [
        {"talker": "wxid_first", "talker_name": names[0]},
        {"talker": "wxid_second", "talker_name": names[1]},
    ]
    # 每次只收到一位联系人的消息；重启后再按相反顺序接收。
    for message in [*messages, *reversed(messages)]:
        watcher = MessageWatcher(None, None, tmp_path, verbose=False)
        watcher._emit(message)
        watcher.stop()

    files = list((tmp_path / "chats").glob("*.jsonl"))
    assert len(files) == 2
    owners = set()
    for path in files:
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        assert len(rows) == 2
        assert len({row["talker"] for row in rows}) == 1
        owners.add(rows[0]["talker"])
    assert owners == {message["talker"] for message in messages}


# 新版追加必须保留旧版无摘要文件，避免继续向归属不明的旧文件混写。
def test_legacy_chat_file_is_preserved(tmp_path: Path):
    chats = tmp_path / "chats"
    chats.mkdir()
    legacy = chats / "同名会话.jsonl"
    legacy.write_text('{"talker": "legacy_owner"}\n', encoding="utf-8")
    original = legacy.read_bytes()
    watcher = MessageWatcher(None, None, tmp_path, verbose=False)
    watcher._emit({"talker": "wxid_new", "talker_name": "同名会话"})
    assert legacy.read_bytes() == original
    assert len(list(chats.glob("*.jsonl"))) == 2
