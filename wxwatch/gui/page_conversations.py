"""会话页：左侧会话列表（可过滤），右侧聊天气泡视图。"""

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QPushButton, QSplitter,
                               QVBoxLayout, QWidget, QScrollArea)

from wxwatch.gui.backend import fmt_ts, msg_preview
from wxwatch.gui.widgets import Avatar, BubbleMessage, make_button


class _LoadWorker(QThread):
    done = Signal(str, list)  # talker, messages

    def __init__(self, backend, talker, limit):
        super().__init__()
        self.backend, self.talker, self.limit = backend, talker, limit

    def run(self):
        try:
            msgs = self.backend.messages_for(self.talker, limit=self.limit)
        except Exception:
            msgs = []
        self._resolve_media(msgs)
        self.done.emit(self.talker, msgs)

    def _resolve_media(self, msgs: list[dict]):
        """在 worker 线程里把媒体消息的预览路径解析好（.dat 解密较慢，不能卡 UI）。
        结果写入 msg["_preview_path"]（缩略图）与 msg["_open_path"]（点击打开）。"""
        for m in msgs:
            if m.get("type") not in ("image", "video", "emoji"):
                continue
            try:
                preview, open_path = self.backend.media_preview_for(m)
                if preview:
                    m["_preview_path"] = preview
                if open_path:
                    m["_open_path"] = open_path
            except Exception:
                continue


class _SessionsWorker(QThread):
    """后台加载会话列表 + 有消息会话集合（镜像拷贝/探测很慢，不能卡 UI）。"""
    done = Signal(list, object)  # sessions, present（None=探测失败不筛）

    def __init__(self, backend):
        super().__init__()
        self.backend = backend

    def run(self):
        try:
            sessions = self.backend.sessions(refresh=True)
        except Exception:
            sessions = []
        try:
            present = self.backend.session_msg_present()
        except Exception:
            present = None
        self.done.emit(sessions, present)


class ConversationsPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        self._sessions: list[dict] = []
        self._worker: _LoadWorker | None = None
        self._sess_worker: _SessionsWorker | None = None
        self._current: str | None = None
        self._limit = 100

        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        split = QSplitter()
        lay.addWidget(split)

        # 左：会话列表
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        self.filter_edit = QLineEdit(placeholderText="搜索会话名称…")
        self.filter_edit.textChanged.connect(self._render_list)
        btn_refresh = make_button("刷新", "secondary")
        btn_refresh.clicked.connect(self.refresh)
        row.addWidget(self.filter_edit, 1)
        row.addWidget(btn_refresh)
        ll.addLayout(row)
        self.list = QListWidget()
        self.list.setUniformItemSizes(True)  # 行高一致，跳过逐项测高（自定义行控件多时为性能瓶颈）
        self.list.currentRowChanged.connect(self._on_select)
        ll.addWidget(self.list, 1)
        split.addWidget(left)

        # 右：消息视图
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(8, 0, 0, 0)
        top = QHBoxLayout()
        self.chat_title = QLabel("选择左侧会话查看消息")
        self.chat_title.setStyleSheet("font-size:15px; font-weight:600;")
        self.btn_more = make_button("加载更早", "secondary")
        self.btn_more.setVisible(False)
        self.btn_more.clicked.connect(self._load_more)
        top.addWidget(self.chat_title, 1)
        top.addWidget(self.btn_more)
        rl.addLayout(top)
        self.msg_area = QScrollArea(widgetResizable=True)
        self.msg_area.setStyleSheet("QScrollArea{background:#F5F6F7; border:1px solid #E4E6EB; border-radius:8px;}")
        self.msg_box = QWidget()
        self.msg_lay = QVBoxLayout(self.msg_box)
        self.msg_lay.setContentsMargins(4, 8, 4, 8)
        self.msg_lay.setSpacing(2)
        self.msg_lay.addStretch(1)
        self.msg_area.setWidget(self.msg_box)
        rl.addWidget(self.msg_area, 1)
        split.addWidget(right)
        split.setSizes([360, 880])

    # ---------- 数据 ----------

    def on_show(self):
        if not self._sessions:
            self.refresh()

    def on_backend_changed(self):
        self._sessions = []
        self.refresh()

    def refresh(self):
        b = self.main.backend
        if not b:
            return
        if self._sess_worker and self._sess_worker.isRunning():
            return
        self.filter_edit.setPlaceholderText("正在加载会话…")
        self._sess_worker = _SessionsWorker(b)
        self._sess_worker.done.connect(self._on_sessions)
        self._sess_worker.start()

    def _on_sessions(self, sessions: list, present):
        # 隐藏 0 消息会话（session 表里有很多从未聊过的联系人）；探测失败则不筛
        if present is not None:
            sessions = [s for s in sessions if s["username"] in present]
        self._sessions = sessions
        self.filter_edit.setPlaceholderText("搜索会话名称…")
        self._render_list()

    def _render_list(self):
        self.list.setUpdatesEnabled(False)
        self.list.clear()
        kw = self.filter_edit.text().strip().lower()
        try:
            for s in self._sessions:
                name = s.get("display_name") or s["username"]
                if kw and kw not in name.lower():
                    continue
                item = QListWidgetItem()
                item.setData(Qt.ItemDataRole.UserRole, s["username"])
                w = QWidget()
                h = QHBoxLayout(w)
                h.setContentsMargins(6, 6, 6, 6)
                h.addWidget(Avatar(name, 40))
                box = QVBoxLayout()
                box.setSpacing(2)
                top = QHBoxLayout()
                title = QLabel(name)
                title.setStyleSheet("font-weight:600;")
                t = QLabel((s.get("last_time") or "")[5:16])
                t.setStyleSheet("color:#8A8F99; font-size:11px;")
                top.addWidget(title, 1)
                top.addWidget(t)
                preview = QLabel(msg_preview({"content": s.get("last_msg_preview")}, 36))
                preview.setStyleSheet("color:#8A8F99; font-size:12px;")
                box.addLayout(top)
                box.addWidget(preview)
                h.addLayout(box, 1)
                badge = QLabel("群" if s["type"] == "group" else "")
                badge.setStyleSheet("color:#07C160; font-size:11px;")
                h.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)
                item.setSizeHint(w.sizeHint())
                self.list.addItem(item)
                self.list.setItemWidget(item, w)
        finally:
            self.list.setUpdatesEnabled(True)

    def _on_select(self, row: int):
        if row < 0:
            return
        item = self.list.item(row)
        talker = item.data(Qt.ItemDataRole.UserRole)
        self._current = talker
        self._limit = 100
        self._load()

    def _load_more(self):
        self._limit += 300
        self._load()

    def _load(self):
        b = self.main.backend
        if not b or not self._current:
            return
        self.chat_title.setText("加载中…")
        if self._worker and self._worker.isRunning():
            self._worker.terminate()
        self._worker = _LoadWorker(b, self._current, self._limit)
        self._worker.done.connect(self._render_msgs)
        self._worker.start()

    def _render_msgs(self, talker: str, msgs: list[dict]):
        if talker != self._current:
            return
        name = None
        for s in self._sessions:
            if s["username"] == talker:
                name = s.get("display_name")
                break
        self.chat_title.setText(f"{name or talker}（{len(msgs)} 条）")
        self.btn_more.setVisible(len(msgs) >= self._limit)
        # 清空旧气泡
        while self.msg_lay.count() > 1:
            item = self.msg_lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        is_group = talker.endswith("@chatroom")
        for m in msgs:
            self.msg_lay.insertWidget(
                self.msg_lay.count() - 1,
                BubbleMessage(m, show_sender=is_group, backend=self.main.backend))
        # 显式设定内容最小高度，触发 ScrollArea 滚动（布局压缩的已知问题）
        self.msg_box.setMinimumHeight(0)
        self.msg_box.setMinimumHeight(self.msg_lay.sizeHint().height())
        # 滚到底部（等布局完成后再滚，否则停在旧位置）
        QTimer.singleShot(0, self._scroll_bottom)

    def _scroll_bottom(self):
        sb = self.msg_area.verticalScrollBar()
        sb.setValue(sb.maximum())
