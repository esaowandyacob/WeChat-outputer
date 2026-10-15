"""消息查询页：关键词 + 会话/类型过滤，结果表格；支持空关键词浏览模式（含媒体缩略图）。"""

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QDesktopServices, QPixmap
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (QComboBox, QFrame, QHBoxLayout, QLabel,
                               QLineEdit, QPushButton, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from wxwatch.gui.backend import msg_preview
from wxwatch.gui.widgets import TypeBadge, make_button, make_table

_TYPES = ["全部", "text", "image", "video", "voice", "emoji",
          "appmsg/file", "appmsg/link", "appmsg/quote", "appmsg/miniapp",
          "appmsg/channels", "system", "location"]
_TYPE_NAMES = {"全部": "全部类型", "text": "文字", "image": "图片", "video": "视频",
               "voice": "语音", "emoji": "表情", "appmsg/file": "文件",
               "appmsg/link": "链接", "appmsg/quote": "引用", "appmsg/miniapp": "小程序",
               "appmsg/channels": "视频号", "system": "系统", "location": "位置"}
_MEDIA_TYPES = ("image", "video", "emoji")


class _SearchWorker(QThread):
    hit = Signal(dict)
    progressed = Signal(int)
    finished_all = Signal(int)

    def __init__(self, backend, keyword, talker, type_filter):
        super().__init__()
        self.backend = backend
        self.kw, self.talker, self.type_filter = keyword, talker, type_filter
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        n = 0
        try:
            for m in self.backend.search(self.kw, self.talker, self.type_filter,
                                         cancel=lambda: self._cancel,
                                         progress=lambda c: self.progressed.emit(c)):
                # 媒体消息在 worker 线程预解密出缩略图路径
                if m.get("type") in _MEDIA_TYPES:
                    try:
                        preview, open_path = self.backend.media_preview_for(m)
                        if preview:
                            m["_preview_path"] = preview
                    except Exception:
                        pass
                self.hit.emit(m)
                n += 1
        except Exception:
            pass
        finally:
            self.finished_all.emit(n)


class SearchPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        self._worker: _SearchWorker | None = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)

        # 过滤卡片
        card = QFrame(objectName="card")
        cl = QHBoxLayout(card)
        cl.setContentsMargins(16, 12, 16, 12)
        self.kw_edit = QLineEdit(placeholderText="关键词（留空 = 浏览最近消息）…")
        self.kw_edit.returnPressed.connect(self.start_search)
        self.chat_combo = QComboBox()
        self.chat_combo.setMinimumWidth(200)
        self.type_combo = QComboBox()
        for t in _TYPES:
            self.type_combo.addItem(_TYPE_NAMES[t], None if t == "全部" else t)
        self.btn = QPushButton("搜索")
        self.btn.clicked.connect(self.start_search)
        self.btn_cancel = make_button("停止", "secondary")
        self.btn_cancel.setVisible(False)
        self.btn_cancel.clicked.connect(self._cancel)
        cl.addWidget(self.kw_edit, 2)
        cl.addWidget(QLabel("会话"))
        cl.addWidget(self.chat_combo, 1)
        cl.addWidget(QLabel("类型"))
        cl.addWidget(self.type_combo)
        cl.addWidget(self.btn)
        cl.addWidget(self.btn_cancel)
        lay.addWidget(card)

        self.status = QLabel("输入关键词搜索，或留空关键词 + 选类型（如「图片」）浏览最近内容")
        self.status.setProperty("muted", True)
        lay.addWidget(self.status)

        self.table = make_table(["时间", "会话", "发言人", "类型", "内容"])
        self.table.setColumnWidth(3, 70)
        lay.addWidget(self.table, 1)

    def on_show(self):
        if self.chat_combo.count() == 0:
            self._fill_chats()

    def on_backend_changed(self):
        self.chat_combo.clear()
        self._fill_chats()

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

    def start_search(self):
        b = self.main.backend
        if not b:
            return
        kw = self.kw_edit.text().strip()
        self._cancel()
        self.table.setRowCount(0)
        self._worker = _SearchWorker(b, kw,
                                     self.chat_combo.currentData(),
                                     self.type_combo.currentData())
        self._worker.hit.connect(self._add_row)
        self._worker.progressed.connect(
            lambda c: self.status.setText(f"已扫描 {c} 行…"))
        self._worker.finished_all.connect(self._done)
        self.btn.setEnabled(False)
        self.btn_cancel.setVisible(True)
        self.status.setText("搜索中…" if kw else "浏览最近消息…")
        self._worker.start()

    def _cancel(self):
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(5000)
        self._worker = None

    def _add_row(self, m: dict):
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setItem(r, 0, QTableWidgetItem(m.get("time") or ""))
        self.table.setItem(r, 1, QTableWidgetItem(m.get("talker_name") or m.get("talker") or ""))
        self.table.setItem(r, 2, QTableWidgetItem(m.get("sender_name") or m.get("sender") or ""))
        cell = QWidget()
        h = QHBoxLayout(cell)
        h.setContentsMargins(6, 2, 6, 2)
        h.addWidget(TypeBadge(m.get("type") or ""))
        h.addStretch(1)
        self.table.setCellWidget(r, 3, cell)
        # 媒体消息显示缩略图，点击打开
        preview = m.get("_preview_path")
        if preview:
            pm = QPixmap(preview)
            if not pm.isNull():
                pm = pm.scaledToHeight(72, Qt.TransformationMode.SmoothTransformation)
                lab = QLabel()
                lab.setPixmap(pm)
                lab.setFixedSize(pm.size())
                lab.setCursor(Qt.CursorShape.PointingHandCursor)
                lab.setToolTip(preview)
                lab.mousePressEvent = lambda _e, p=preview: QDesktopServices.openUrl(
                    QUrl.fromLocalFile(p))
                self.table.setCellWidget(r, 4, lab)
                self.table.setRowHeight(r, max(28, pm.height() + 6))
                return
        self.table.setItem(r, 4, QTableWidgetItem(msg_preview(m, 120)))

    def _done(self, n: int):
        self.btn.setEnabled(True)
        self.btn_cancel.setVisible(False)
        self.status.setText(f"完成：{n} 条（最多显示 500 条）")

    def on_close(self):
        self._cancel()
