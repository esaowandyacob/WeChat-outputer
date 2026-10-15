"""入口向导：无有效密钥时的一页式首次设置。

流程：确认/手动选择微信数据目录 → 开始扫描（extract-keys → parse）→ 进入主界面。
本程序需 root 运行（sudo ./run_gui.sh 会自动提权），全程无密码输入。
"""

from pathlib import Path

from PySide6.QtCore import QProcess, Qt
from PySide6.QtWidgets import (QFileDialog, QFrame, QHBoxLayout, QLabel,
                               QLineEdit, QPlainTextEdit, QProgressBar,
                               QVBoxLayout, QWidget)

from wxwatch.gui.backend import cli_invocation
from wxwatch.gui.page_home import check_db_storage, detect_db_storage
from wxwatch.gui.widgets import make_button


class WizardPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        self._proc: QProcess | None = None
        self._queue: list[list[str]] = []

        outer = QVBoxLayout(self)
        outer.addStretch(1)
        mid = QHBoxLayout()
        mid.addStretch(1)
        card = QFrame(objectName="card")
        card.setFixedWidth(540)
        mid.addWidget(card)
        mid.addStretch(1)
        outer.addLayout(mid)
        outer.addStretch(2)
        lay = QVBoxLayout(card)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(10)

        title = QLabel("欢迎使用 wxwatch")
        title.setStyleSheet("font-size:20px; font-weight:600;")
        lay.addWidget(title)
        sub = QLabel("未检测到有效密钥。将从运行中的微信进程提取密钥并解析消息。")
        sub.setProperty("muted", True)
        sub.setWordWrap(True)
        lay.addWidget(sub)

        # ① 数据目录
        lay.addWidget(QLabel("① 微信数据目录"))
        self.dir_label = QLabel("检测中…")
        self.dir_label.setWordWrap(True)
        lay.addWidget(self.dir_label)
        self.dir_row = QWidget()
        dr = QHBoxLayout(self.dir_row)
        dr.setContentsMargins(0, 0, 0, 0)
        self.dir_edit = QLineEdit()
        self.dir_edit.setPlaceholderText(
            "db_storage 目录，如 ~/Documents/xwechat_files/wxid_xxx/db_storage")
        btn_browse = make_button("浏览…", "secondary")
        btn_browse.clicked.connect(self._browse)
        dr.addWidget(self.dir_edit, 1)
        dr.addWidget(btn_browse)
        lay.addWidget(self.dir_row)

        # ③ 开始扫描
        row = QHBoxLayout()
        self.btn_start = make_button("开始扫描")
        self.btn_start.clicked.connect(self._start)
        self.bar = QProgressBar()
        self.bar.setRange(0, 0)  # 不确定进度
        self.bar.setVisible(False)
        row.addWidget(self.btn_start)
        row.addWidget(self.bar, 1)
        lay.addLayout(row)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)
        self.log = QPlainTextEdit(readOnly=True)
        self.log.setMaximumBlockCount(500)
        self.log.setFixedHeight(6 * (self.log.fontMetrics().lineSpacing() + 3))
        self.log.setVisible(False)
        lay.addWidget(self.log)

        self._detect_dir()

    # ---------- 目录检测 ----------

    def _detect_dir(self):
        p = detect_db_storage()
        if p:
            ok, detail = check_db_storage(p)
            if ok:
                self._dir = str(p)
                self.dir_label.setText(f"✅ 已自动检测到：{p}（{detail}）")
                self.dir_label.setStyleSheet("color:#07C160;")
                self.dir_row.setVisible(False)
                return
            # 检测到目录但文件读不到 → 降级为手动选择
            self._dir = ""
            self.dir_label.setText(f"⚠️ 检测到 {p}，但{detail}。请手动选择：")
        else:
            self._dir = ""
            self.dir_label.setText("⚠️ 未自动检测到微信数据目录，请手动选择：")
        self.dir_label.setStyleSheet("color:#E6A23C;")
        self.dir_row.setVisible(True)

    def _browse(self):
        d = QFileDialog.getExistingDirectory(
            self, "选择 db_storage 目录",
            str(Path.home() / "Documents" / "xwechat_files"))
        if d:
            self.dir_edit.setText(d)

    # ---------- 扫描流程 ----------

    def _set_busy(self, busy: bool):
        self.btn_start.setEnabled(not busy)
        self.dir_edit.setEnabled(not busy)
        self.bar.setVisible(busy)

    def _start(self):
        ds = self._dir or self.dir_edit.text().strip()
        ok, detail = check_db_storage(ds) if ds else (False, "未选择目录")
        if not ok:
            self.status.setText(f"❌ 微信数据目录不可用：{detail}")
            self.status.setStyleSheet("color:#E64545;")
            return
        self._queue = [["extract-keys", "--db-storage", ds],
                       ["extract-image-key"],  # 可选（失败不影响主流程）
                       ["parse"]]
        from wxwatch.gui import logbus
        logbus.log("开始首次扫描（提取密钥 → 解析）")
        self.log.clear()
        self.log.setVisible(True)
        self.status.setText("")
        self._set_busy(True)
        self._run_next()

    def _run_next(self):
        if not self._queue:
            self._finish()
            return
        args = self._queue.pop(0)
        self._current = args[0]
        if self._current == "extract-image-key":
            self.log.appendPlainText(
                "[*] 图片密钥（可选）：请在微信里点开 2-3 张图片保持查看…")
        self.log.appendPlainText(f"$ wxwatch {' '.join(args)}")
        exe, argv = cli_invocation(args)
        self._proc = QProcess(self)
        self._proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._proc.readyReadStandardOutput.connect(self._on_output)
        self._proc.finished.connect(self._on_finished)
        self._proc.start(exe, argv)

    def _on_output(self):
        data = bytes(self._proc.readAllStandardOutput()).decode(errors="replace")
        for line in data.rstrip().splitlines():
            if line:
                self.log.appendPlainText(line)

    def _on_finished(self, code, _status):
        self._proc = None
        if code != 0:
            if getattr(self, "_current", "") == "extract-image-key":
                # 图片密钥可选：失败后随时可在 设置页 重试
                self.log.appendPlainText(
                    "[i] 图片密钥未提取（不影响使用），可稍后在 设置/密钥 页重试")
                self._run_next()
                return
            self._set_busy(False)
            self.status.setText(
                f"❌ 执行失败（退出码 {code}）。请确认以 root 运行、微信已登录。")
            self.status.setStyleSheet("color:#E64545;")
            return
        self._run_next()

    def _finish(self):
        self._set_busy(False)
        self.main.reload_backend()
        from wxwatch.gui import logbus
        if self.main.backend:
            self.status.setText("✅ 完成")
            logbus.log("首次扫描完成，进入主界面")
            self.main.show_main()
        else:
            err = self.main.backend_error or "未知错误"
            logbus.log(f"首次扫描失败：{err}")
            self.status.setText(f"❌ 密钥仍不可用：{err}")
            self.status.setStyleSheet("color:#E64545;")
