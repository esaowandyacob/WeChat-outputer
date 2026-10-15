"""实时监听页：嵌入式 watcher，新消息实时上屏；支持按会话/发言人过滤（默认全部）。"""

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (QComboBox, QFrame, QHBoxLayout, QLabel,
                               QLineEdit, QPushButton, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from wxwatch.gui import logbus
from wxwatch.gui.backend import msg_preview
from wxwatch.gui.widgets import TypeBadge, make_table

MAX_ROWS = 500


class _LiveWorker(QThread):
    new_msg = Signal(dict)
    error = Signal(str)

    def __init__(self, backend):
        super().__init__()
        self.backend = backend
        self.watcher = None

    def run(self):
        try:
            self.watcher = self.backend.make_watcher(
                on_message=lambda m: self.new_msg.emit(m))
            self.watcher.start()  # 阻塞循环，直到 stop()
        except Exception as e:
            self.error.emit(str(e))

    def stop(self):
        if self.watcher:
            self.watcher.stop()


class LivePage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        self._worker: _LiveWorker | None = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)

        card = QFrame(objectName="card")
        cl = QHBoxLayout(card)
        cl.setContentsMargins(16, 12, 16, 12)
        self.dot = QLabel("●")
        self.dot.setStyleSheet("color:#B7BCC4; font-size:16px;")
        self.status = QLabel("未启动")
        self.status.setStyleSheet("font-weight:600;")
        self.btn = QPushButton("开始监听")
        self.btn.clicked.connect(self.toggle)
        self.count_label = QLabel("0 条新消息")
        self.count_label.setProperty("muted", True)
        cl.addWidget(self.dot)
        cl.addWidget(self.status)
        cl.addStretch(1)
        cl.addWidget(self.count_label)
        cl.addWidget(self.btn)
        lay.addWidget(card)

        # 过滤条：按会话或发言人过滤（默认全部；只影响上屏，不影响底层监听）
        frow = QHBoxLayout()
        frow.addWidget(QLabel("会话"))
        self.chat_combo = QComboBox()
        self.chat_combo.setMinimumWidth(220)
        frow.addWidget(self.chat_combo, 1)
        frow.addWidget(QLabel("发言人"))
        self.sender_edit = QLineEdit(placeholderText="留空 = 全部（按昵称/微信号模糊匹配）")
        frow.addWidget(self.sender_edit, 1)
        lay.addLayout(frow)

        tip = QLabel("监听微信数据库文件变化，新消息实时显示在这里（同时由命令行 watch 持久化到 output/）。保持微信运行即可。")
        tip.setProperty("muted", True)
        tip.setWordWrap(True)
        lay.addWidget(tip)

        self.table = make_table(["时间", "会话", "发言人", "类型", "内容"])
        self.table.setColumnWidth(3, 70)
        lay.addWidget(self.table, 1)
        self._count = 0
        self._filtered = 0

    # ---------- 会话下拉 ----------

    def on_show(self):
        if self.chat_combo.count() == 0:
            self._fill_chats()

    def on_backend_changed(self):
        cur = self.chat_combo.currentData()
        self.chat_combo.clear()
        self._fill_chats()
        i = self.chat_combo.findData(cur)
        if i >= 0:
            self.chat_combo.setCurrentIndex(i)

    def _fill_chats(self):
        self.chat_combo.addItem("全部会话", None)
        b = self.main.backend
        if not b:
            return
        try:
            for s in b.sessions()[:500]:
                self.chat_combo.addItem(s.get("display_name") or s["username"],
                                        s["username"])
        except Exception:
            pass

    # ---------- 监听控制 ----------

    def toggle(self):
        if self._worker and self._worker.isRunning():
            self.stop()
        else:
            self.start()

    def start(self):
        b = self.main.backend
        if not b:
            self.status.setText("后端未就绪（先到 设置/密钥 页检查）")
            return
        self._worker = _LiveWorker(b)
        self._worker.new_msg.connect(self._add)
        self._worker.error.connect(self._on_error)
        self._worker.start()
        self.dot.setStyleSheet("color:#07C160; font-size:16px;")
        self.status.setText("监听中")
        self.btn.setText("停止监听")
        self.btn.setProperty("danger", True)
        self.btn.setStyleSheet("")
        logbus.log("实时监听已启动")

    def stop(self):
        if self._worker:
            self._worker.stop()
            self._worker.wait(5000)
            self._worker = None
        self.dot.setStyleSheet("color:#B7BCC4; font-size:16px;")
        self.status.setText("已停止")
        self.btn.setText("开始监听")
        self.btn.setProperty("danger", False)
        logbus.log(f"实时监听已停止（本次上屏 {self._count} 条）")

    def _match(self, m: dict) -> bool:
        """会话/发言人过滤；都在变化时立即生效，无需重启监听。"""
        talker = self.chat_combo.currentData()
        if talker and m.get("talker") != talker:
            return False
        kw = self.sender_edit.text().strip().lower()
        if kw:
            sender = (m.get("sender_name") or m.get("sender") or "").lower()
            if kw not in sender:
                return False
        return True

    def _add(self, m: dict):
        if not self._match(m):
            self._filtered += 1
            self._sync_count()
            return
        self.table.insertRow(0)
        def cell(c, w):
            if isinstance(w, QWidget):
                self.table.setCellWidget(0, c, w)
            else:
                self.table.setItem(0, c, QTableWidgetItem(w))
        cell(0, (m.get("time") or "")[5:])
        cell(1, m.get("talker_name") or m.get("talker") or "")
        cell(2, m.get("sender_name") or m.get("sender") or "")
        badge_cell = QWidget()
        h = QHBoxLayout(badge_cell)
        h.setContentsMargins(6, 2, 6, 2)
        h.addWidget(TypeBadge(m.get("type") or ""))
        h.addStretch(1)
        cell(3, badge_cell)
        cell(4, self._content_cell(m))
        while self.table.rowCount() > MAX_ROWS:
            self.table.removeRow(self.table.rowCount() - 1)
        self._count += 1
        self._sync_count()

    def _sync_count(self):
        txt = f"{self._count} 条新消息"
        if self._filtered:
            txt += f"（已过滤 {self._filtered} 条）"
        self.count_label.setText(txt)

    def _content_cell(self, m: dict):
        """图片消息尽量显示缩略图 + 文字预览；任一环节失败静默回退纯文字。"""
        if m.get("type") == "image":
            try:
                backend = self.main.backend
                preview = backend.media_preview_for(m)[0] if backend else None
                pm = QPixmap(preview) if preview else QPixmap()
                if not pm.isNull():
                    if pm.height() > 56:
                        pm = pm.scaledToHeight(56, Qt.TransformationMode.SmoothTransformation)
                    thumb = QLabel()
                    thumb.setPixmap(pm)
                    w = QWidget()
                    h = QHBoxLayout(w)
                    h.setContentsMargins(6, 2, 6, 2)
                    h.addWidget(thumb)
                    h.addWidget(QLabel(msg_preview(m, 100)))
                    h.addStretch(1)
                    self.table.setRowHeight(0, 64)
                    return w
            except Exception:
                pass
        return msg_preview(m, 100)

    def _on_error(self, e: str):
        self.status.setText(f"出错: {e}")
        logbus.log(f"实时监听出错：{e}")
        self.stop()

    def on_close(self):
        self.stop()
