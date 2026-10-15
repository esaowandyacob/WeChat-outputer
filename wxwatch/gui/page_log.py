"""运行日志页：显示本进程内的关键运行事件（密钥提取/解析/监听/抓取等）。"""

from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QPlainTextEdit,
                               QVBoxLayout, QWidget)

from wxwatch.gui import logbus
from wxwatch.gui.widgets import make_button


class LogPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main

        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)

        card = QFrame(objectName="card")
        cl = QHBoxLayout(card)
        cl.setContentsMargins(16, 12, 16, 12)
        self.count_label = QLabel("")
        self.count_label.setProperty("muted", True)
        btn_clear = make_button("清空", "secondary")
        btn_clear.clicked.connect(self._clear)
        cl.addWidget(QLabel("应用运行期间的关键事件（仅保存在内存中，关闭程序即清除）"))
        cl.addStretch(1)
        cl.addWidget(self.count_label)
        cl.addWidget(btn_clear)
        lay.addWidget(card)

        self.view = QPlainTextEdit(readOnly=True)
        self.view.setMaximumBlockCount(5000)
        lay.addWidget(self.view, 1)

        # 构建前已产生的日志直接回填；之后的由信号追加
        if logbus.history():
            self.view.setPlainText("\n".join(logbus.history()))
        self._sync_count()
        logbus.BUS.appended.connect(self._append)

    def _append(self, line: str):
        self.view.appendPlainText(line)
        self._sync_count()
        sb = self.view.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _clear(self):
        logbus.clear()
        self.view.clear()
        self._sync_count()

    def _sync_count(self):
        self.count_label.setText(f"{len(logbus.history())} 条")
