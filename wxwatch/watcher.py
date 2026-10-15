"""文件变化监听 + 增量解析。

微信 db 用 WAL 模式且 WAL 预分配固定 4MB，文件大小不变，
因此监听 mtime（watchdog modified 事件，匹配 .db / .db-wal）。
事件去抖后：重拷 WAL 镜像 → 按游标增量解析新消息 → 追加 JSONL 输出。
"""

from __future__ import annotations

import json
import threading
import time
from hashlib import md5 as _md5
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


def md5(s: str) -> str:
    return _md5(s.encode()).hexdigest()

# 监听这些目录（相对 db_storage）
WATCH_DIRS = ["message", "session", "contact"]
WATCH_SUFFIXES = (".db", ".db-wal")
DEBOUNCE_SEC = 1.0


class _TriggerHandler(FileSystemEventHandler):
    """把相关文件事件转换为去抖后的触发信号。"""

    def __init__(self, trigger):
        self._trigger = trigger
        self._timer: threading.Timer | None = None
        self._lock = threading.Lock()

    def on_modified(self, event):
        self._maybe(event)

    def on_created(self, event):
        self._maybe(event)

    def _maybe(self, event):
        if event.is_directory:
            return
        if not event.src_path.endswith(WATCH_SUFFIXES):
            return
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(DEBOUNCE_SEC, self._trigger)
            self._timer.daemon = True
            self._timer.start()


class MessageWatcher:
    def __init__(self, decryptor, parser, out_dir: Path, verbose: bool = True,
                 persist: bool = True, on_message=None):
        """persist=False 时只解析不落盘（GUI 实时预览用）；
        on_message: 每条新消息的回调（在解析线程中调用）。"""
        self.dec = decryptor
        self.parser = parser
        self.out_dir = Path(out_dir)
        (self.out_dir / "chats").mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        self.persist = persist
        self.on_message = on_message
        self._state_file = self.out_dir / "state.json"
        self._cursors: dict[str, int] = self._load_state()
        self._observer: Observer | None = None
        self._running = False
        self._lock = threading.Lock()
        self._file_names: dict[str, str] = {}  # safe_name -> username（撞名检测）

    def _load_state(self) -> dict[str, int]:
        if self._state_file.exists():
            try:
                return json.loads(self._state_file.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _save_state(self):
        self._state_file.write_text(json.dumps(self._cursors), encoding="utf-8")

    # ---------- 输出 ----------

    def _emit(self, msg: dict):
        if self.on_message is not None:
            try:
                self.on_message(msg)
            except Exception:
                pass
        if not self.persist:
            return
        line = json.dumps(msg, ensure_ascii=False)
        # 全局流（显式 UTF-8：Windows 控制台区域写入不能依赖默认编码）
        with open(self.out_dir / "messages.jsonl", "a", encoding="utf-8") as f:
            f.write(line + "\n")
        # 每会话流（同名会话用 username 的 md5 后缀区分，避免互相覆盖）
        name = msg.get("talker_name") or msg["talker"]
        safe = "".join(c if c.isalnum() or c in " _-@" else "_" for c in name)[:64].strip()
        prev = self._file_names.get(safe)
        suffix = md5(msg["talker"])[:6]
        if prev is not None and prev != msg["talker"]:
            safe = f"{safe}__{suffix}"
        else:
            self._file_names.setdefault(safe, msg["talker"])
        with open(self.out_dir / "chats" / f"{safe}.jsonl", "a", encoding="utf-8") as f:
            f.write(line + "\n")
        if self.verbose:
            t = msg.get("time") or "??:??"
            who = msg.get("sender_name") or msg.get("talker_name") or msg["talker"]
            preview = self._preview(msg)
            print(f"[{t}] {msg.get('talker_name','?')}"
                  + (f" | {who}" if msg.get("sender") else "")
                  + f": {preview}")

    @staticmethod
    def _preview(msg: dict) -> str:
        if msg.get("content"):
            p = str(msg["content"])
        elif msg.get("title"):
            p = f"[{msg['type'].split('/')[-1]}] {msg['title']}"
        elif msg.get("file"):
            p = f"[文件] {msg['file'].get('name')}"
        elif msg.get("media_files"):
            p = f"[{msg['type']}] {msg['media_files'][0]}"
        else:
            p = f"[{msg.get('type','?')}]"
        p = p.splitlines()[0]
        return p[:80] + "…" if len(p) > 80 else p

    # ---------- 增量解析 ----------

    def parse_once(self) -> int:
        """执行一轮增量解析，返回新消息数。"""
        with self._lock:
            count = 0
            try:
                for msg in self.parser.iter_messages(since=self._cursors):
                    self._emit(msg)
                    lid = msg.get("local_id")
                    if isinstance(lid, int):
                        self._cursors[msg["table"]] = max(
                            self._cursors.get(msg["table"], 0), lid)
                    count += 1
            except Exception as e:
                print(f"[WARN] 解析出错: {e}")
            if count and self.persist:
                self._save_state()
            return count

    def refresh_conversations(self):
        try:
            sessions = self.parser.sessions()
            with open(self.out_dir / "conversations.json", "w", encoding="utf-8") as f:
                json.dump(sessions, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[WARN] 会话列表更新失败: {e}")

    # ---------- 监听 ----------

    def start(self):
        handler = _TriggerHandler(self._on_trigger)
        self._observer = Observer()
        for d in WATCH_DIRS:
            path = self.dec.db_storage / d
            if path.exists():
                self._observer.schedule(handler, str(path), recursive=False)
        self._observer.start()
        self._running = True
        print(f"[*] 初始全量解析 ...")
        n = self.parse_once()
        self.refresh_conversations()
        print(f"[*] 完成，{n} 条消息。开始监听文件变化 (Ctrl+C 退出)")
        try:
            while self._running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def _on_trigger(self):
        # 文件变化可能带来新联系人/新会话表，清缓存重新发现
        self.parser._contacts = None
        self.parser._msg_tables = None
        n = self.parse_once()
        if n:
            self.refresh_conversations()
            print(f"[*] +{n} 条新消息 ({time.strftime('%H:%M:%S')})")

    def stop(self):
        self._running = False
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
        self._save_state()
