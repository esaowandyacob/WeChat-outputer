"""主窗口：左侧导航 + 页面堆栈。"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QListWidget,
                               QListWidgetItem, QMainWindow, QStackedWidget,
                               QVBoxLayout, QWidget)

from wxwatch.gui.backend import Backend
from wxwatch.gui.style import STYLESHEET


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("wxwatch · 微信消息解析与监听")
        self.resize(1280, 800)
        self.setStyleSheet(STYLESHEET)

        self._backend: Backend | None = None
        self._backend_error: str | None = None
        try:
            self._backend = Backend()
        except Exception as e:
            self._backend_error = str(e)
        from wxwatch.gui import logbus
        if self._backend:
            logbus.log(f"后端就绪：{self._backend.db_storage.parent.name}")
        else:
            logbus.log(f"后端未就绪：{self._backend_error}")

        # 中央堆栈：第 0 页入口向导（无有效密钥时），第 1 页主界面
        self._root_stack = QStackedWidget()
        self.setCentralWidget(self._root_stack)

        main_ui = QWidget()
        lay = QHBoxLayout(main_ui)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # 侧边栏（窗口标题已带名称，不再放 logo，避免多层样式冲突）
        side = QFrame(objectName="sidebar")
        side.setFixedWidth(190)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(0, 8, 0, 8)
        nav = QListWidget(objectName="navList")
        sl.addWidget(nav, 1)
        self._nav = nav

        # 右侧
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(0)
        header = QFrame(objectName="header")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(0, 0, 0, 0)
        self._title = QLabel("会话", objectName="headerTitle")
        self._status = QLabel("", objectName="headerStatus")
        hl.addWidget(self._title, 1)
        hl.addWidget(self._status)
        rl.addWidget(header)
        self._stack = QStackedWidget()
        rl.addWidget(self._stack, 1)
        lay.addWidget(side)
        lay.addWidget(right, 1)

        # 页面
        from wxwatch.gui.page_home import HomePage
        from wxwatch.gui.page_conversations import ConversationsPage
        from wxwatch.gui.page_search import SearchPage
        from wxwatch.gui.page_live import LivePage
        from wxwatch.gui.page_log import LogPage

        self._imgkey_proc = None  # 需在页面前初始化：HomePage 构建时会查询守护状态
        self._pages = [
            ("主页", HomePage(self)),
            ("会话", ConversationsPage(self)),
            ("消息查询", SearchPage(self)),
            ("实时监听", LivePage(self)),
            ("运行日志", LogPage(self)),
        ]
        for name, page in self._pages:
            QListWidgetItem(name, nav)
            self._stack.addWidget(page)
        nav.currentRowChanged.connect(self._on_nav)
        nav.setCurrentRow(0)

        from wxwatch.gui.page_wizard import WizardPage
        self._wizard = WizardPage(self)
        self._root_stack.addWidget(self._wizard)  # 0：向导
        self._root_stack.addWidget(main_ui)       # 1：主界面
        self._root_stack.setCurrentIndex(1 if self._backend else 0)

        self._update_status()
        self._maybe_autostart_imgkey_watch()

    # ---------- 图片密钥自动抓取守护 ----------

    def _maybe_autostart_imgkey_watch(self):
        """Linux + 尚无图片密钥 → 静默启动自动抓取守护（GUI 入口已保证 root，免密码）。
        微信首次解码新图时自动捕获，抓到后守护自动退出。"""
        import sys
        if sys.platform != "linux" or not self._backend:
            return
        if self._backend.image_key():
            return
        from PySide6.QtCore import QProcess
        from wxwatch.gui.backend import cli_invocation
        exe, argv = cli_invocation(["watch-image-key"])
        self._imgkey_proc = QProcess(self)
        self._imgkey_proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._imgkey_proc.finished.connect(self._on_imgkey_done)
        self._imgkey_proc.start(exe, argv)
        self._imgkey_proc.waitForStarted(3000)
        logbus.log("图片密钥自动抓取守护已启动（微信里看图时自动捕获）")
        self._update_status()

    def _on_imgkey_done(self, code, _status):
        self._imgkey_proc = None
        if code == 0:  # 抓到密钥：重载后端 + 顶栏标记 + 设置页状态联动
            logbus.log("✅ 图片密钥已获取，守护自动退出")
            self.reload_backend()
            self._status.setText("● 已就绪 · ✅ 图片密钥已获取")
            self._status.setStyleSheet("color:#07C160; padding-right:16px;")
            for _, page in self._pages:
                if hasattr(page, "check_image_key"):
                    page.check_image_key()
        else:
            self._update_status()

    def imgkey_watch_running(self) -> bool:
        return self._imgkey_proc is not None

    def start_imgkey_watch(self) -> bool:
        """设置页手动启动入口（root 直启，无需密码）。返回是否成功启动。"""
        if self._imgkey_proc is not None:
            return True
        self._maybe_autostart_imgkey_watch()
        return self._imgkey_proc is not None

    # ---------- 共享 ----------

    @property
    def backend(self) -> Backend | None:
        return self._backend

    @property
    def backend_error(self) -> str | None:
        return self._backend_error

    def show_main(self):
        """向导完成后切到主界面。"""
        self._root_stack.setCurrentIndex(1)
        self._on_nav(self._nav.currentRow())

    def reload_backend(self):
        try:
            self._backend = Backend()
            self._backend_error = None
        except Exception as e:
            self._backend = None
            self._backend_error = str(e)
        logbus.log("后端已重新加载" if self._backend
                   else f"后端重载失败：{self._backend_error}")
        self._update_status()
        # 通知各页面后端已变化
        for _, page in self._pages:
            hook = getattr(page, "on_backend_changed", None)
            if hook:
                hook()

    def backend_or_warn(self) -> Backend | None:
        return self._backend

    def _update_status(self):
        if self._backend:
            txt = f"● 已就绪 · {self._backend.db_storage.parent.name}"
            if self._backend.image_key():
                txt += " · 图片密钥已获取"
            elif self._imgkey_proc is not None:
                txt += " · 图片密钥抓取中"
            self._status.setText(txt)
            self._status.setStyleSheet("color:#07C160; padding-right:16px;")
        else:
            self._status.setText("● 未就绪")
            self._status.setStyleSheet("color:#E64545; padding-right:16px;")

    def _on_nav(self, row: int):
        if row < 0:
            return
        self._stack.setCurrentIndex(row)
        name, page = self._pages[row]
        self._title.setText(name)
        hook = getattr(page, "on_show", None)
        if hook:
            hook()

    def closeEvent(self, event):
        if self._imgkey_proc is not None:
            self._imgkey_proc.terminate()
        for _, page in self._pages:
            hook = getattr(page, "on_close", None)
            if hook:
                hook()
        super().closeEvent(event)
