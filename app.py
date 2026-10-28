"""微信本地聊天记录导出工具的 Tkinter 界面。"""

from __future__ import annotations

import contextlib
import importlib
import os
import shutil
import subprocess
import sys
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable

from cccryptor_probe import (
    DEFAULT_KEY_PATH,
    CaptureResult,
    KeyStoreError,
    capture_keys,
    check_capture_probe,
    detect_wechat,
    ensure_key_path_outside_export,
    get_capture_prerequisite,
    launch_wechat,
    load_key_records,
    redact_output,
    reset_key_file,
)
from read_wechat_conversation import (
    Conversation,
    ReaderError,
    WeChatReader,
    export_model,
    parse_recent_days,
    plan_export_concurrency,
    safe_filename,
)


ASSET_DIR = Path(__file__).resolve().parent / "assets"
UI_FONT = "Microsoft YaHei UI" if sys.platform == "win32" else "PingFang SC"

# 石灰岩底、暖白卡片、一种墨色。状态靠图标形状，不靠额外颜色。
BG = "#F3F1ED"
SURFACE = "#FBF9F6"
INK = "#1C1B19"
MUTED = "#6F6A63"
LINE = "#E4DFD6"
ACCENT = "#1F2A26"
ACCENT_HOVER = "#141C19"
PAPER = "#F7F4EF"
GHOST_HOVER = "#EFEAE3"
DISABLED_BG = "#D9D4CC"
DISABLED_FG = "#F7F5F2"

EXPORT_COLORS = {
    "html": (ACCENT, ACCENT_HOVER),
    "txt": (ACCENT, ACCENT_HOVER),
    "pdf": (ACCENT, ACCENT_HOVER),
    "sqlite": (ACCENT, ACCENT_HOVER),
}

# macOS 导出实际用到的包。PySide6 和 watchdog 只给 Linux / Windows 界面，一键设置不装它们。
PYTHON_DEPENDENCIES = (
    ("zstandard", "zstandard"),
    ("sqlcipher3", "sqlcipher3"),
    ("Crypto", "pycryptodome"),
    ("fpdf", "fpdf2"),
)


# 返回当前平台默认的导出目录。
def _image_key_status() -> tuple[str, str]:
    """图片密钥文案和状态图标：ok 已保存，idle 尚未采集。"""
    config_path = Path(__file__).resolve().parent / "config.json"
    if not config_path.is_file():
        return "尚未采集图片密钥", "idle"
    try:
        import json
        saved = json.loads(config_path.read_text(encoding="utf-8")).get("image_key")
    except (OSError, json.JSONDecodeError):
        return "尚未采集图片密钥", "idle"
    return ("已保存图片密钥", "ok") if saved else ("尚未采集图片密钥", "idle")


class Mark(tk.Canvas):
    """16 像素状态图标：对勾、叉、圆环、短横。只用墨色描边。"""

    def __init__(self, master: tk.Misc, kind: str = "idle", *, size: int = 16, background: str = SURFACE) -> None:
        super().__init__(master, width=size, height=size, bg=background, highlightthickness=0, bd=0)
        self._size = size
        self.set_kind(kind)

    def set_kind(self, kind: str) -> None:
        self.delete("all")
        size = self._size
        color = INK if kind != "idle" else MUTED
        stroke = 1.6
        if kind == "ok":
            self.create_line(
                size * 0.22, size * 0.52, size * 0.42, size * 0.74, size * 0.80, size * 0.28,
                fill=color, width=stroke, capstyle="round", joinstyle="round",
            )
        elif kind == "err":
            self.create_line(size * 0.28, size * 0.28, size * 0.72, size * 0.72, fill=color, width=stroke, capstyle="round")
            self.create_line(size * 0.72, size * 0.28, size * 0.28, size * 0.72, fill=color, width=stroke, capstyle="round")
        elif kind == "pending":
            self.create_oval(size * 0.20, size * 0.20, size * 0.80, size * 0.80, outline=color, width=stroke)
            self.create_arc(
                size * 0.20, size * 0.20, size * 0.80, size * 0.80,
                start=300, extent=110, style="arc", outline=color, width=stroke,
            )
        else:
            self.create_line(size * 0.28, size * 0.50, size * 0.72, size * 0.50, fill=color, width=stroke, capstyle="round")


class IconButton(tk.Canvas):
    """顶栏刷新：圆弧加箭头，不用字符充当图标。"""

    def __init__(self, master: tk.Misc, command: Callable[[], object], *, size: int = 32) -> None:
        super().__init__(
            master, width=size, height=size, bg=SURFACE, highlightthickness=0, bd=0, cursor="hand2",
        )
        self.command = command
        self._size = size
        self._draw(INK)
        self.bind("<Button-1>", self._handle_click)
        self.bind("<Enter>", lambda _event: self.configure(bg=GHOST_HOVER))
        self.bind("<Leave>", lambda _event: self.configure(bg=SURFACE))

    def _handle_click(self, _event: tk.Event[tk.Misc]) -> str:
        self.command()
        return "break"

    def _draw(self, color: str) -> None:
        import math

        size = self._size
        pad = max(6, round(size * 0.22))
        radius = size / 2 - pad
        center = size / 2
        # 从 1 点钟顺时针画到 11 点钟，箭头停在缺口里。
        self.create_arc(
            pad, pad, size - pad, size - pad,
            start=60, extent=-300, style="arc", outline=color, width=max(1.4, size / 18),
        )
        theta = math.radians(120)
        x = center + radius * math.cos(theta)
        y = center - radius * math.sin(theta)
        tangent_x, tangent_y = math.sin(theta), math.cos(theta)
        normal_x, normal_y = -tangent_y, tangent_x
        reach = radius * 0.55
        half = radius * 0.34
        tip = (x + tangent_x * reach, y + tangent_y * reach)
        left = (x + normal_x * half, y + normal_y * half)
        right = (x - normal_x * half, y - normal_y * half)
        self.create_polygon(*tip, *left, *right, fill=color, outline=color, joinstyle="round")


def _default_export_dir() -> Path:
    desktop = Path.home() / "Desktop"
    if desktop.is_dir():
        return desktop / "WeChatExport"
    return Path.home() / "WeChatExport"


# 第一步采集说明：macOS 需要关闭 SIP 才能用 DTrace 取密钥。
def _capture_hint_text() -> str:
    return (
        "SIP 关闭说明：请在 macOS 恢复模式打开“终端”，执行 csrutil disable，重启后回到此页刷新。"
        "程序不会自动修改 SIP；完成采集后可自行重新启用。"
    )


def _module_importable(name: str) -> bool:
    try:
        importlib.import_module(name)
    except Exception:
        sys.modules.pop(name, None)
        return False
    return True


def missing_python_packages() -> list[str]:
    return [package for module, package in PYTHON_DEPENDENCIES if not _module_importable(module)]


def ffmpeg_available() -> bool:
    from wxwatch.imagedat import _ffmpeg_path, _ffprobe_path

    return _ffmpeg_path() is not None and _ffprobe_path() is not None


def dependency_report() -> tuple[str, str]:
    """依赖状态文案和图标：ok 已就绪，idle 还有缺项。"""
    missing = missing_python_packages()
    if not ffmpeg_available():
        missing.append("ffmpeg")
    if not missing:
        return "依赖已就绪", "ok"
    return "缺少 " + "、".join(missing), "idle"


def _find_brew() -> str | None:
    for candidate in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew"):
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return shutil.which("brew")


def _command_tail(completed: subprocess.CompletedProcess[str]) -> str:
    detail = (completed.stderr or completed.stdout or "").strip()
    return detail[-2000:]


# 安装当前解释器缺少的 Python 包，以及 Homebrew 下的 ffmpeg。
def install_missing_dependencies(progress: Callable[[str], None] | None = None) -> tuple[bool, str]:
    def say(text: str) -> None:
        if progress is not None:
            progress(text)

    packages = missing_python_packages()
    if packages:
        say("正在安装 " + "、".join(packages) + "…")
        completed = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--no-input", *packages],
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            return False, "安装 Python 依赖失败。\n" + _command_tail(completed)
        importlib.invalidate_caches()
        still = missing_python_packages()
        if still:
            return False, "安装后仍无法导入：" + "、".join(still)
    if not ffmpeg_available():
        brew = _find_brew()
        if brew is None:
            return False, "未找到 Homebrew。请先安装 Homebrew，或在终端执行 brew install ffmpeg。"
        say("正在安装 ffmpeg，可能需要几分钟…")
        env = os.environ.copy()
        env["HOMEBREW_NO_AUTO_UPDATE"] = "1"
        env["HOMEBREW_NO_ENV_HINTS"] = "1"
        completed = subprocess.run([brew, "install", "ffmpeg"], capture_output=True, text=True, env=env)
        if completed.returncode != 0 or not ffmpeg_available():
            return False, "安装 ffmpeg 失败。\n" + _command_tail(completed)
    say("依赖已就绪")
    return True, "依赖已就绪"


# 将后台异常转换为不会回显完整密钥的 GUI 文本。
def _safe_error_message(error: Exception) -> str:
    detail = redact_output(str(error)).strip()
    return detail or "操作失败，请检查权限和本地配置"


class FlatButton(tk.Label):
    """用 Label 模拟跨平台稳定着色的按钮。"""

    # 创建一个支持 hover、禁用和 invoke 的扁平按钮。
    def __init__(
        self,
        master: tk.Misc,
        text: str,
        command: Callable[[], object] | None = None,
        *,
        background: str = ACCENT,
        hover_background: str | None = None,
        disabled_background: str = DISABLED_BG,
        foreground: str = PAPER,
        hairline: bool = False,
        **kwargs: Any,
    ) -> None:
        self.command = command
        self.normal_background = background
        self.hover_background = hover_background or background
        self.disabled_background = disabled_background
        self.normal_foreground = foreground
        self.disabled_foreground = DISABLED_FG
        self.enabled = True
        kwargs.setdefault("font", (UI_FONT, 13))
        super().__init__(
            master,
            text=text,
            bg=background,
            fg=foreground,
            activebackground=background,
            activeforeground=foreground,
            padx=14,
            pady=7,
            cursor="hand2",
            relief="flat",
            bd=0,
            highlightthickness=1 if hairline else 0,
            highlightbackground=LINE,
            highlightcolor=LINE,
            **kwargs,
        )
        self.bind("<Button-1>", self._handle_click)
        self.bind("<Enter>", self._handle_enter)
        self.bind("<Leave>", self._handle_leave)

    # 处理鼠标点击，仅在按钮启用时执行命令。
    def _handle_click(self, _event: tk.Event[tk.Misc]) -> str:
        if self.enabled:
            self.invoke()
        return "break"

    # 处理鼠标进入时的 hover 背景。
    def _handle_enter(self, _event: tk.Event[tk.Misc]) -> None:
        if self.enabled:
            self.configure(bg=self.hover_background, activebackground=self.hover_background)

    # 处理鼠标离开时恢复正常背景。
    def _handle_leave(self, _event: tk.Event[tk.Misc]) -> None:
        if self.enabled:
            self.configure(bg=self.normal_background, activebackground=self.normal_background)

    # 切换按钮启用状态，并确保重新启用后恢复原始颜色。
    def set_enabled(self, enabled: bool) -> None:
        self.enabled = bool(enabled)
        if self.enabled:
            self.configure(
                bg=self.normal_background,
                fg=self.normal_foreground,
                activebackground=self.normal_background,
                activeforeground=self.normal_foreground,
                cursor="hand2",
            )
            super().configure(state="normal")
        else:
            self.configure(
                bg=self.disabled_background,
                fg=self.disabled_foreground,
                activebackground=self.disabled_background,
                activeforeground=self.disabled_foreground,
                cursor="arrow",
            )
            super().configure(state="disabled")

    # 兼容 Tk 原生 state 配置，同时同步自定义按钮的颜色和点击状态。
    def configure(self, cnf: Any | None = None, **kwargs: Any) -> Any:
        options = dict(cnf) if isinstance(cnf, dict) else {}
        options.update(kwargs)
        state = options.pop("state", None)
        if state is not None and hasattr(self, "enabled"):
            self.set_enabled(str(state) != "disabled")
            options["state"] = "disabled" if str(state) == "disabled" else "normal"
        return super().configure(**options)

    # 提供 config 别名，使测试和调用方使用 Tk 惯用 API 时行为一致。
    def config(self, cnf: Any | None = None, **kwargs: Any) -> Any:
        return self.configure(cnf, **kwargs)

    # 以编程方式触发按钮命令，便于测试和键盘操作。
    def invoke(self) -> object | None:
        if self.enabled and self.command is not None:
            return self.command()
        return None


def _ghost_button(master: tk.Misc, text: str, command: Callable[[], object] | None) -> FlatButton:
    return FlatButton(
        master, text, command,
        background=SURFACE, hover_background=GHOST_HOVER, foreground=INK, hairline=True,
    )


def _primary_button(master: tk.Misc, text: str, command: Callable[[], object] | None) -> FlatButton:
    return FlatButton(
        master, text, command,
        background=ACCENT, hover_background=ACCENT_HOVER, foreground=PAPER,
    )


def _card(parent: tk.Misc) -> tk.Frame:
    return tk.Frame(
        parent, bg=SURFACE, padx=16, pady=14,
        highlightthickness=1, highlightbackground=LINE, highlightcolor=LINE,
    )


def _plain_entry(master: tk.Misc, **kwargs: Any) -> tk.Entry:
    return tk.Entry(
        master,
        relief="flat",
        bd=0,
        highlightthickness=0,
        bg=SURFACE,
        fg=INK,
        readonlybackground=SURFACE,
        insertbackground=INK,
        font=(UI_FONT, 13),
        **kwargs,
    )


def _lined_entry(master: tk.Misc, **kwargs: Any) -> tk.Entry:
    return tk.Entry(
        master,
        relief="flat",
        bd=0,
        highlightthickness=1,
        highlightbackground=LINE,
        highlightcolor=INK,
        bg=SURFACE,
        fg=INK,
        insertbackground=INK,
        readonlybackground=SURFACE,
        font=(UI_FONT, 13),
        **kwargs,
    )


class WeChatExportApp(tk.Tk):
    """三步式微信聊天记录导出 GUI。"""

    # 初始化窗口、状态变量、读取器和三个步骤页面。
    def __init__(
        self,
        reader: WeChatReader | None = None,
        *,
        key_path: Path | str = DEFAULT_KEY_PATH,
        start_hidden: bool = False,
    ) -> None:
        super().__init__()
        self.title("微信聊天记录导出")
        self.geometry("1120x760")
        self.minsize(920, 700)
        self.configure(bg=BG)
        env_root = os.environ.get("WECHAT_DATA_ROOT", "").strip()
        self.data_root = Path(env_root).expanduser() if env_root else None
        self.reader = reader or WeChatReader(data_root=self.data_root, key_path=key_path)
        self.key_path = Path(key_path).expanduser()
        self.key_records = []
        self._captured_masks: list[str] = []
        self.conversations: list[Conversation] = []
        self.selected_conversation: Conversation | None = None
        self.selected_conversations: list[Conversation] = []
        self._status_after_id: str | None = None
        self._delayed_status_id: str | None = None
        self._worker_busy = False
        self._deps_busy = False
        self._icon_image: tk.PhotoImage | None = None
        self._build_icon()
        self._build_style()
        self._build_shell()
        self._build_key_step()
        self._build_conversation_step()
        self._build_export_step()
        self._show_step(0)
        self._reload_keys()
        self.refresh_status()
        if start_hidden:
            self.withdraw()

    # 设置 Tk 控件字体和 Treeview 样式。
    def _build_style(self) -> None:
        style = ttk.Style(self)
        with contextlib.suppress(tk.TclError):
            style.theme_use("clam")
        style.configure(
            "WeChat.Treeview",
            rowheight=40,
            font=(UI_FONT, 13),
            background=SURFACE,
            fieldbackground=SURFACE,
            foreground=INK,
            borderwidth=0,
            relief="flat",
        )
        style.configure(
            "WeChat.Treeview.Heading",
            font=(UI_FONT, 12),
            background=BG,
            foreground=MUTED,
            relief="flat",
            borderwidth=0,
            padding=(12, 8),
        )
        style.map(
            "WeChat.Treeview",
            background=[("selected", "#E7E2DA")],
            foreground=[("selected", INK)],
        )
        style.layout("WeChat.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        style.configure(
            "Vertical.TScrollbar",
            background=LINE,
            troughcolor=BG,
            borderwidth=0,
            arrowsize=12,
            relief="flat",
        )

    # 尝试加载 PNG 与 ICNS 图标；任何平台不支持时都静默回退。
    def _build_icon(self) -> None:
        png_path = ASSET_DIR / "wechat_export.png"
        icns_path = ASSET_DIR / "wechat_export.icns"
        if png_path.exists():
            with contextlib.suppress(tk.TclError, OSError):
                self._icon_image = tk.PhotoImage(file=str(png_path))
                self.iconphoto(True, self._icon_image)
        if icns_path.exists():
            with contextlib.suppress(tk.TclError, OSError):
                self.iconbitmap(str(icns_path))

    # 创建统一的页面容器和标题栏。
    def _build_shell(self) -> None:
        self._wrap_labels: list[tk.Label] = []
        self.header = tk.Frame(self, bg=SURFACE, height=52)
        self.header.pack(fill="x")
        self.header.pack_propagate(False)
        tk.Label(
            self.header,
            text="微信聊天记录",
            bg=SURFACE,
            fg=INK,
            font=(UI_FONT, 15),
        ).pack(side="left", padx=28)
        self.refresh_button = IconButton(self.header, self.refresh_status)
        self.refresh_button.pack(side="right", padx=(8, 24))
        self._step_labels: list[tk.Label] = []
        for name in ("导出", "会话", "密钥"):
            label = tk.Label(self.header, text=name, bg=SURFACE, fg=MUTED, font=(UI_FONT, 12))
            label.pack(side="right", padx=(0, 18))
            self._step_labels.append(label)
        self._step_labels.reverse()
        tk.Frame(self, bg=LINE, height=1).pack(fill="x")
        self.body = tk.Frame(self, bg=BG)
        self.body.pack(fill="both", expand=True, padx=28, pady=20)
        self.body.bind("<Configure>", self._sync_wrap)
        self.step_frames: list[tk.Frame] = []

    def _track_wrap(self, label: tk.Label) -> tk.Label:
        label.configure(wraplength=760)
        self._wrap_labels.append(label)
        return label

    def _sync_wrap(self, _event: tk.Event[tk.Misc] | None = None) -> None:
        width = max(320, self.body.winfo_width() - 4)
        for label in self._wrap_labels:
            with contextlib.suppress(tk.TclError):
                label.configure(wraplength=width)

    def _set_status(self, variable: tk.StringVar, mark: Mark, kind: str, text: str) -> None:
        variable.set(text)
        mark.set_kind(kind)

    def _scrolling_page(self, host: tk.Frame) -> tk.Frame:
        """内容高于窗口时滚动，避免把最后一张卡片压成一条线。"""
        scroll = ttk.Scrollbar(host, orient="vertical")
        canvas = tk.Canvas(host, bg=BG, highlightthickness=0, bd=0, yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        page = tk.Frame(canvas, bg=BG)
        window = canvas.create_window((0, 0), window=page, anchor="nw")

        def fit(event: tk.Event[tk.Misc]) -> None:
            canvas.itemconfigure(window, width=event.width)

        def region(_event: tk.Event[tk.Misc]) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def show_scroll(first: str, last: str) -> None:
            scroll.set(first, last)
            needed = float(last) - float(first) < 0.999
            mapped = bool(scroll.winfo_ismapped())
            if needed and not mapped:
                scroll.pack(side="right", fill="y", before=canvas)
            elif mapped and not needed:
                scroll.pack_forget()

        canvas.bind("<Configure>", fit)
        page.bind("<Configure>", region)
        scroll.configure(command=canvas.yview)
        canvas.configure(yscrollcommand=show_scroll)
        self._key_canvas = canvas
        return page

    def _key_wheel(self, event: tk.Event[tk.Misc]) -> None:
        canvas = self._key_canvas
        bbox = canvas.bbox("all")
        if not bbox or bbox[3] <= canvas.winfo_height() + 1:
            return
        canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")

    # 创建三行状态卡片和第一步操作控件。
    def _build_key_step(self) -> None:
        frame = tk.Frame(self.body, bg=BG)
        self.step_frames.append(frame)
        # 先占住底部，窗口较矮时「进入会话选择」也不会被上面的卡片挤出屏幕。
        bottom = tk.Frame(frame, bg=BG)
        bottom.pack(fill="x", side="bottom", pady=(12, 0))
        frame = self._scrolling_page(frame)
        tk.Label(frame, text="获取密钥", bg=BG, fg=INK, font=(UI_FONT, 16)).pack(anchor="w")
        tk.Label(
            frame,
            text="数据只在本机读取。密钥不会写入导出目录。",
            bg=BG,
            fg=MUTED,
            font=(UI_FONT, 12),
        ).pack(anchor="w", pady=(6, 0))
        self._track_wrap(tk.Label(
            frame,
            text=_capture_hint_text(),
            bg=BG,
            fg=MUTED,
            justify="left",
            anchor="w",
            font=(UI_FONT, 12),
        )).pack(fill="x", pady=(8, 16))
        self.deps_var = tk.StringVar(value="正在检查依赖")
        deps_row = self._status_row(
            frame,
            self.deps_var,
            tk.StringVar(value=""),
            button_text="一键设置依赖",
            command=self._setup_dependencies,
        )
        self.deps_mark = deps_row.mark
        self.dependency_button = deps_row.winfo_children()[-1]
        self.sip_var = tk.StringVar(value="正在检测采集条件")
        self.wechat_var = tk.StringVar(value="正在检测微信")
        self.capture_var = tk.StringVar(value="尚未开始采集")
        self.sip_detail_var = tk.StringVar(value="")
        sip_row = self._status_row(frame, self.sip_var, self.sip_detail_var)
        self.sip_mark = sip_row.mark
        wechat_row = self._status_row(
            frame, self.wechat_var, tk.StringVar(value=""),
            button_text="启动微信", command=self._launch_wechat,
        )
        self.wechat_mark = wechat_row.mark
        self.capture_row = self._status_row(
            frame,
            self.capture_var,
            tk.StringVar(value=""),
            button_text="启动采集",
            command=self._start_capture,
            primary=True,
        )
        self.capture_mark = self.capture_row.mark
        self.capture_button = self.capture_row.winfo_children()[-1]
        self.image_key_var = tk.StringVar(value="")
        self.image_key_row = self._status_row(
            frame,
            self.image_key_var,
            tk.StringVar(value=""),
            button_text="采集图片密钥",
            command=self._start_image_key_capture,
        )
        self.image_key_mark = self.image_key_row.mark
        image_text, image_kind = _image_key_status()
        self._set_status(self.image_key_var, self.image_key_mark, image_kind, image_text)

        path_box = _card(frame)
        path_box.pack(fill="x", pady=(10, 8))
        tk.Label(path_box, text="密钥文件", bg=SURFACE, fg=MUTED, font=(UI_FONT, 12)).pack(anchor="w")
        path_line = tk.Frame(path_box, bg=SURFACE)
        path_line.pack(fill="x", pady=(8, 0))
        self.key_path_var = tk.StringVar(value=str(self.key_path))
        _plain_entry(path_line, textvariable=self.key_path_var, state="readonly").pack(side="left", fill="x", expand=True, padx=(0, 12))
        _ghost_button(path_line, "选择路径", self._choose_key_path).pack(side="right")

        data_box = _card(frame)
        data_box.pack(fill="x")
        tk.Label(data_box, text="微信数据目录", bg=SURFACE, fg=MUTED, font=(UI_FONT, 12)).pack(anchor="w")
        data_line = tk.Frame(data_box, bg=SURFACE)
        data_line.pack(fill="x", pady=(8, 0))
        self.data_root_var = tk.StringVar(value=str(self.data_root) if self.data_root else "自动检测")
        _plain_entry(data_line, textvariable=self.data_root_var, state="readonly").pack(side="left", fill="x", expand=True, padx=(0, 12))
        _ghost_button(data_line, "选择目录", self._choose_data_root).pack(side="right")
        _ghost_button(data_line, "自动检测", self._clear_data_root).pack(side="right", padx=(0, 8))

        captured = _card(frame)
        captured.pack(fill="x", pady=(12, 0))
        tk.Label(captured, text="本次捕获，已脱敏", bg=SURFACE, fg=MUTED, font=(UI_FONT, 12)).pack(anchor="w")
        self.captured_list_var = tk.StringVar(value="暂无")
        self._track_wrap(tk.Label(
            captured,
            textvariable=self.captured_list_var,
            bg=SURFACE,
            fg=INK,
            justify="left",
            anchor="w",
            font=(UI_FONT, 13),
        )).pack(fill="x", pady=(8, 0))

        actions = tk.Frame(bottom, bg=BG)
        actions.pack(side="right")
        self.key_count_var = tk.StringVar(value="已保存密钥：0 个")
        tk.Label(actions, textvariable=self.key_count_var, bg=BG, fg=MUTED, font=(UI_FONT, 12)).pack(side="right", padx=(0, 16))
        _ghost_button(actions, "重置已保存密钥", self._reset_keys).pack(side="right", padx=(0, 8))
        self.to_conversations_button = _primary_button(actions, "进入会话选择", self._enter_conversations)
        self.to_conversations_button.pack(side="right")

    # 创建一行带可选操作按钮的状态卡片。按钮必须是最后一个子控件。
    def _status_row(
        self,
        parent: tk.Misc,
        variable: tk.StringVar,
        detail_variable: tk.StringVar,
        *,
        button_text: str | None = None,
        command: Callable[[], object] | None = None,
        primary: bool = False,
    ) -> tk.Frame:
        row = tk.Frame(
            parent,
            bg=SURFACE,
            padx=16,
            pady=8,
            highlightthickness=1,
            highlightbackground=LINE,
            highlightcolor=LINE,
        )
        row.pack(fill="x", pady=(0, 6))
        mark = Mark(row, "idle", background=SURFACE)
        mark.pack(side="left")
        row.mark = mark
        tk.Label(
            row, textvariable=variable, bg=SURFACE, fg=INK, font=(UI_FONT, 13),
            justify="left", anchor="w", wraplength=640,
        ).pack(side="left", padx=(10, 12), fill="x", expand=True)
        tk.Label(row, textvariable=detail_variable, bg=SURFACE, fg=MUTED, font=(UI_FONT, 12)).pack(side="left", padx=(12, 0))
        if button_text:
            button = _primary_button(row, button_text, command) if primary else _ghost_button(row, button_text, command)
            button.pack(side="right")
        return row

    # 创建会话树表格和第二步导航控件。
    def _build_conversation_step(self) -> None:
        frame = tk.Frame(self.body, bg=BG)
        self.step_frames.append(frame)
        top = tk.Frame(frame, bg=BG)
        top.pack(fill="x")
        tk.Label(top, text="选择会话", bg=BG, fg=INK, font=(UI_FONT, 16)).pack(side="left")
        _ghost_button(top, "刷新", self._load_conversations).pack(side="right")
        _ghost_button(top, "取消全选", self._clear_conversation_selection).pack(side="right", padx=(0, 8))
        _ghost_button(top, "全选", self._select_all_conversations).pack(side="right", padx=(0, 8))
        self.conversation_hint_var = tk.StringVar(value="公众号、服务通知和系统会话已隐藏。按住 Command 点选可多选，Shift 可连选。")
        self._track_wrap(tk.Label(
            frame,
            textvariable=self.conversation_hint_var,
            bg=BG,
            fg=MUTED,
            justify="left",
            anchor="w",
            font=(UI_FONT, 12),
        )).pack(anchor="w", fill="x", pady=(8, 16))
        table_frame = tk.Frame(
            frame, bg=SURFACE, highlightthickness=1, highlightbackground=LINE, highlightcolor=LINE,
        )
        table_frame.pack(fill="both", expand=True)
        self.conversation_tree = ttk.Treeview(
            table_frame,
            columns=("recent_time", "title", "recent_message"),
            show="headings",
            style="WeChat.Treeview",
            selectmode="extended",
        )
        self.conversation_tree.heading("recent_time", text="最近时间")
        self.conversation_tree.heading("title", text="会话")
        self.conversation_tree.heading("recent_message", text="最近消息")
        self.conversation_tree.column("recent_time", width=168, minwidth=140, anchor="w", stretch=False)
        self.conversation_tree.column("title", width=240, minwidth=160, anchor="w", stretch=True)
        self.conversation_tree.column("recent_message", width=420, minwidth=200, anchor="w", stretch=True)
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.conversation_tree.yview)
        self.conversation_tree.configure(yscrollcommand=scrollbar.set)
        self.conversation_tree.pack(side="left", fill="both", expand=True, padx=(1, 0), pady=1)
        scrollbar.pack(side="right", fill="y", padx=(0, 1), pady=1)
        self.conversation_tree.bind("<<TreeviewSelect>>", self._conversation_selected)
        self.selected_var = tk.StringVar(value="未选择会话")
        tk.Label(frame, textvariable=self.selected_var, bg=BG, fg=INK, anchor="w", font=(UI_FONT, 13)).pack(fill="x", pady=(12, 12))
        nav = tk.Frame(frame, bg=BG)
        nav.pack(fill="x")
        _ghost_button(nav, "返回", lambda: self._show_step(0)).pack(side="left")
        self.to_export_button = _primary_button(nav, "进入导出", self._show_export_step)
        self.to_export_button.set_enabled(False)
        self.to_export_button.pack(side="right")

    # 创建导出选项，以及同一墨色的三个导出按钮。
    def _build_export_step(self) -> None:
        frame = tk.Frame(self.body, bg=BG)
        self.step_frames.append(frame)
        tk.Label(frame, text="导出", bg=BG, fg=INK, font=(UI_FONT, 16)).pack(anchor="w")
        self.export_conversation_var = tk.StringVar(value="")
        self._track_wrap(tk.Label(
            frame,
            textvariable=self.export_conversation_var,
            bg=BG,
            fg=MUTED,
            justify="left",
            anchor="w",
            font=(UI_FONT, 12),
        )).pack(anchor="w", fill="x", pady=(6, 16))
        options = _card(frame)
        options.pack(fill="x")
        options.columnconfigure(1, weight=1)

        def form_label(row: int, text: str, last: bool = False) -> None:
            tk.Label(options, text=text, bg=SURFACE, fg=MUTED, font=(UI_FONT, 13), anchor="w").grid(
                row=row, column=0, sticky="w", padx=(0, 20), pady=(0, 0 if last else 12),
            )

        form_label(0, "最近天数")
        days_line = tk.Frame(options, bg=SURFACE)
        days_line.grid(row=0, column=1, sticky="w", pady=(0, 12))
        self.recent_days_entry = _lined_entry(days_line, width=8)
        self.recent_days_entry.pack(side="left")
        tk.Label(days_line, text="留空为全部", bg=SURFACE, fg=MUTED, font=(UI_FONT, 12)).pack(side="left", padx=(10, 0))
        form_label(1, "并发")
        self.concurrency_var = tk.StringVar(value=self._concurrency_caption(1))
        tk.Label(
            options,
            textvariable=self.concurrency_var,
            bg=SURFACE,
            fg=MUTED,
            font=(UI_FONT, 13),
            anchor="w",
        ).grid(row=1, column=1, sticky="ew", pady=(0, 12))

        form_label(2, "导出目录", last=True)
        dest = tk.Frame(options, bg=SURFACE)
        dest.grid(row=2, column=1, sticky="ew")
        self.export_dir_var = tk.StringVar(value=str(_default_export_dir()))
        _lined_entry(dest, textvariable=self.export_dir_var).pack(side="left", fill="x", expand=True, padx=(0, 8))
        _ghost_button(dest, "选择目录", self._choose_export_dir).pack(side="right")

        button_box = tk.Frame(frame, bg=BG)
        button_box.pack(anchor="w", pady=(16, 0))
        self.export_buttons: dict[str, FlatButton] = {}
        for index, (fmt, label) in enumerate(
            (("html", "导出 HTML"), ("txt", "导出 TXT"), ("pdf", "导出 PDF"), ("sqlite", "导出 SQLite"))
        ):
            normal, hover = EXPORT_COLORS[fmt]
            button = FlatButton(
                button_box, label, lambda fmt=fmt: self._export(fmt),
                background=normal, hover_background=hover, foreground=PAPER,
            )
            button.pack(side="left", padx=(0 if index == 0 else 8, 0))
            self.export_buttons[fmt] = button
        self._export_note = tk.Frame(frame, bg=BG)
        self.export_status_var = tk.StringVar(value="")
        self._track_wrap(tk.Label(
            self._export_note,
            textvariable=self.export_status_var,
            bg=BG,
            fg=MUTED,
            justify="left",
            anchor="w",
            font=(UI_FONT, 12),
        )).pack(anchor="w", fill="x")
        self.last_file_label = tk.Label(
            self._export_note, text="", bg=BG, fg=INK, cursor="hand2", font=(UI_FONT, 12, "underline"),
        )
        self.last_file_label.pack(anchor="w", pady=(4, 0))
        self.last_file_path: Path | None = None
        self.last_file_label.bind("<Button-1>", self._open_last_file)
        self._export_back = _ghost_button(frame, "返回会话列表", lambda: self._show_step(1))
        self._export_back.pack(anchor="w", pady=(16, 0))

    # 显示指定步骤页面并隐藏其他页面。
    def _show_step(self, index: int) -> None:
        for frame in self.step_frames:
            frame.pack_forget()
        if 0 <= index < len(self.step_frames):
            self.step_frames[index].pack(fill="both", expand=True)
        if index == 0:
            self.bind_all("<MouseWheel>", self._key_wheel)
        else:
            self.unbind_all("<MouseWheel>")
        for step_index, label in enumerate(self._step_labels):
            current = step_index == index
            label.configure(
                fg=INK if current else MUTED,
                font=(UI_FONT, 13 if current else 12, "bold" if current else "normal"),
            )

    # 读取密钥文件并更新右下角计数。
    def _reload_keys(self) -> None:
        try:
            self.key_records = load_key_records(self.key_path)
        except KeyStoreError:
            self.key_records = []
        self.key_count_var.set(f"已保存密钥：{len(self.key_records)} 个")

    # 定时刷新采集前置条件和微信进程状态。
    def refresh_status(self) -> None:
        if not self._deps_busy:
            deps_text, deps_kind = dependency_report()
            self._set_status(self.deps_var, self.deps_mark, deps_kind, deps_text)
        ready, headline, detail = get_capture_prerequisite()
        if ready is True:
            sip_kind = "ok"
        elif ready is None:
            sip_kind = "pending"
        else:
            sip_kind = "err"
        self._set_status(self.sip_var, self.sip_mark, sip_kind, headline)
        self.sip_detail_var.set(detail)
        status = detect_wechat()
        if status.running:
            version = status.version or "未知版本"
            self._set_status(self.wechat_var, self.wechat_mark, "ok", f"微信运行中 · PID {status.pid} · {version}")
        else:
            self._set_status(self.wechat_var, self.wechat_mark, "err", "未检测到微信")
        self._schedule_status_refresh()

    # 只保留一个 SIP/微信状态定时器，避免重复刷新。
    def _schedule_status_refresh(self) -> None:
        if self._status_after_id is not None:
            with contextlib.suppress(tk.TclError):
                self.after_cancel(self._status_after_id)
        with contextlib.suppress(tk.TclError):
            self._status_after_id = self.after(5000, self.refresh_status)

    # 请求启动微信并在稍后刷新进程状态。
    def _launch_wechat(self) -> None:
        ok, detail = launch_wechat()
        self._set_status(self.wechat_var, self.wechat_mark, "ok" if ok else "err", detail)
        if self._delayed_status_id is not None:
            with contextlib.suppress(tk.TclError):
                self.after_cancel(self._delayed_status_id)
        with contextlib.suppress(tk.TclError):
            self._delayed_status_id = self.after(1200, self.refresh_status)

    # 选择自定义 key 文件路径并刷新显示。
    def _choose_key_path(self) -> None:
        selected = filedialog.asksaveasfilename(
            title="选择密钥文件路径",
            initialfile=self.key_path.name,
            initialdir=str(self.key_path.parent),
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("所有文件", "*")],
        )
        if selected:
            self.key_path = Path(selected).expanduser()
            self.key_path_var.set(str(self.key_path))
            self.reader.key_path = self.key_path
            self._reload_keys()

    # 手动指定微信 4.x 的 xwechat_files 或 db_storage 目录。
    def _choose_data_root(self) -> None:
        initial = str(self.data_root) if self.data_root is not None else str(Path.home())
        selected = filedialog.askdirectory(title="选择微信数据目录", initialdir=initial)
        if selected:
            self.data_root = Path(selected).expanduser()
            self.data_root_var.set(str(self.data_root))
            self.reader.data_root = self.data_root

    # 恢复按当前用户目录自动发现微信数据库。
    def _clear_data_root(self) -> None:
        self.data_root = None
        self.data_root_var.set("自动检测")
        self.reader.data_root = None

    # 二次确认后只删除本工具创建的密钥文件。
    def _reset_keys(self) -> None:
        if not messagebox.askyesno("确认重置", "确定删除本工具保存的全部密钥吗？此操作不可恢复。"):
            return
        try:
            reset_key_file(self.key_path)
        except KeyStoreError as exc:
            messagebox.showerror("无法重置", str(exc))
            return
        self.captured_list_var.set("暂无")
        self._reload_keys()

    # 在后台线程执行 DTrace 采集，GUI 只接收脱敏状态。
    def _start_capture(self) -> None:
        status = detect_wechat()
        if not status.running or status.pid is None:
            messagebox.showwarning("需要启动微信", "请先启动并登录微信客户端。")
            return
        if self._worker_busy:
            return
        self._worker_busy = True
        capture_button = self.capture_row.winfo_children()[-1]
        if isinstance(capture_button, FlatButton):
            capture_button.set_enabled(False)
        duration = 60
        self._set_status(self.capture_var, self.capture_mark, "pending", "正在检查采集条件。需要授权时只会弹出一次密码框。")
        self._captured_masks = []
        listening_hint = "授权后会监听约 60 秒，请在微信中打开几个会话。"
        self.captured_list_var.set(listening_hint)

        # 把采集倒计时安全地投递到 Tk 主线程。
        def on_tick(remaining: int) -> None:
            self._post_ui(lambda remaining=remaining: self._set_status(
                self.capture_var, self.capture_mark, "pending", f"正在采集 · 剩余 {remaining} 秒",
            ))

        # 把已经脱敏的候选 key 投递到界面。
        def on_candidate(masked: str) -> None:
            self._captured_masks.append(masked)
            display = "\n".join(self._captured_masks)
            self._post_ui(lambda: self.captured_list_var.set(display))

        # 把不含完整 key 的采集状态投递到界面。
        def on_status(detail: str) -> None:
            self._post_ui(lambda text=detail: self._set_status(self.capture_var, self.capture_mark, "pending", text))

        # 在后台线程先检查 DTrace probe，再开始 60 秒监听。
        def worker() -> None:
            try:
                probe_ok, probe_detail = check_capture_probe(status.pid or 0)
                if not probe_ok:
                    self._post_ui(
                        lambda: self._capture_finished(
                            CaptureResult((), (), 0.0, None, probe_detail or "密钥采集不可用"),
                            capture_button,
                        )
                    )
                    return
                result = capture_keys(
                    status.pid or 0,
                    self.reader.validate_candidate_key,
                    duration=duration,
                    key_path=self.key_path,
                    on_tick=on_tick,
                    on_candidate=on_candidate,
                    on_status=on_status,
                )
                self._post_ui(lambda: self._capture_finished(result, capture_button))
            except Exception as exc:
                safe_detail = _safe_error_message(exc)
                self._post_ui(
                    lambda detail=safe_detail: self._capture_finished(
                        CaptureResult((), (), 0.0, None, detail), capture_button
                    )
                )

        threading.Thread(target=worker, name="wechat-capture", daemon=True).start()

    # 采集 V2 图片密钥。先按本机微信配置推导，推导不出再从内存里找（需全屏看图）。
    def _start_image_key_capture(self) -> None:
        if self._worker_busy:
            return
        status = detect_wechat()
        if not status.running or status.pid is None:
            messagebox.showwarning("需要启动微信", "请先启动并登录微信。")
            return
        account_root = self.reader.catalog().account_root
        if account_root is None:
            self._show_copyable_dialog("采集失败", "没有找到微信数据目录，无法验证图片密钥。")
            return
        self._worker_busy = True
        self._set_status(self.image_key_var, self.image_key_mark, "pending", "正在推导图片密钥")

        def worker() -> None:
            try:
                from wxwatch.imagekey import capture_image_key_macos

                found = capture_image_key_macos(
                    status.pid or 0,
                    account_root,
                    on_status=lambda detail: self._post_ui(
                        lambda text=detail: self._set_status(self.image_key_var, self.image_key_mark, "pending", text)
                    ),
                )
            except Exception as exc:
                detail = _safe_error_message(exc)
                self._post_ui(lambda: self._image_key_finished(False, detail))
                return
            self._post_ui(lambda: self._image_key_finished(bool(found), ""))

        threading.Thread(target=worker, name="wechat-image-key", daemon=True).start()

    # 更新图片密钥采集结果。界面不显示密钥本身。
    def _image_key_finished(self, found: bool, detail: str) -> None:
        self._worker_busy = False
        if found:
            text, kind = _image_key_status()
        else:
            text, kind = "没有采到图片密钥", "err"
        self._set_status(self.image_key_var, self.image_key_mark, kind, text)
        if found:
            self._show_copyable_dialog("图片密钥已保存", "图片密钥已写入 config.json。请重新导出，照片会解密后显示。")
            return
        message = detail or "没有验证通过。请在采集开始后，立刻在微信里全屏打开 2 到 3 张普通照片，不要只发表情。"
        self._show_copyable_dialog("图片密钥未采到", message)

    # 处理采集线程结束结果并恢复按钮颜色。
    def _capture_finished(self, result: CaptureResult, capture_button: tk.Misc) -> None:
        self._worker_busy = False
        if isinstance(capture_button, FlatButton):
            capture_button.set_enabled(True)
        self._reload_keys()
        if result.error:
            self._set_status(self.capture_var, self.capture_mark, "err", result.error)
        elif result.validated_keys:
            self._set_status(
                self.capture_var, self.capture_mark, "ok",
                f"采集完成 · 验证成功 {len(result.validated_keys)} 个",
            )
        else:
            self._set_status(self.capture_var, self.capture_mark, "err", "采集完成，但没有候选通过验证")
        if result.report:
            self.captured_list_var.set(result.report)
        title, message = self._capture_result_message(result)
        self._show_copyable_dialog(title, message)

    # 生成采集结果的标题和可复制正文，不包含完整密钥。
    def _capture_result_message(self, result: CaptureResult) -> tuple[str, str]:
        if result.error:
            return "采集失败", result.error
        if result.validated_keys:
            lines = [
                f"密钥采集完成，验证成功 {len(result.validated_keys)} 个。",
                f"已保存到：{self.key_path}",
            ]
            if result.report:
                lines.extend(["", result.report])
            return "采集成功", "\n".join(lines)
        lines = ["密钥采集完成，但没有候选通过验证。请在监听的 60 秒内打开几个微信会话。"]
        if result.report:
            lines.extend(["", result.report])
        return "采集未验证通过", "\n".join(lines)

    # 弹出可选中的结果窗口，并用按钮把全文放进剪贴板。
    def _show_copyable_dialog(self, title: str, message: str) -> tk.Toplevel:
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.geometry("720x380")
        dialog.minsize(520, 260)
        dialog.transient(self)
        dialog.configure(bg=BG)
        body = tk.Frame(dialog, bg=SURFACE, highlightthickness=1, highlightbackground=LINE, highlightcolor=LINE)
        body.pack(fill="both", expand=True, padx=20, pady=(20, 12))
        text = tk.Text(
            body,
            wrap="word",
            font=(UI_FONT, 13),
            bg=SURFACE,
            fg=INK,
            relief="flat",
            padx=14,
            pady=12,
            highlightthickness=0,
            insertbackground=INK,
        )
        scrollbar = ttk.Scrollbar(body, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        text.insert("1.0", message)
        text.tag_add("sel", "1.0", "end-1c")
        text.focus_set()

        # 保留方向键、全选和复制，其余按键不改文本。
        def ignore_edit(event: tk.Event[tk.Misc]) -> str | None:
            key = str(event.keysym).lower()
            navigation = {
                "left",
                "right",
                "up",
                "down",
                "home",
                "end",
                "prior",
                "next",
                "shift_l",
                "shift_r",
                "control_l",
                "control_r",
                "meta_l",
                "meta_r",
                "alt_l",
                "alt_r",
                "super_l",
                "super_r",
            }
            if key in navigation:
                return None
            if event.state & (0x4 | 0x8 | 0x10 | 0x100000) and key in {"c", "a", "insert"}:
                return None
            return "break"

        text.bind("<Key>", ignore_edit)
        buttons = tk.Frame(dialog, bg=BG)
        buttons.pack(fill="x", padx=20, pady=(0, 20))

        # 把结果全文写入剪贴板，方便粘贴到终端或聊天里。
        def copy_message() -> None:
            self.clipboard_clear()
            self.clipboard_append(message)
            self.update_idletasks()
            copy_button.configure(text="已复制")

        _ghost_button(buttons, "关闭", dialog.destroy).pack(side="right")
        copy_button = _primary_button(buttons, "复制全部", copy_message)
        copy_button.pack(side="right", padx=(0, 8))
        dialog.copy_button = copy_button
        dialog.result_text = text
        dialog.lift()
        return dialog

    # 进入会话选择页并在后台读取会话列表。
    def _enter_conversations(self) -> None:
        self._show_step(1)
        self._load_conversations()

    # 读取并显示会话列表，避免阻塞 Tk 主线程。
    def _load_conversations(self) -> None:
        if self._worker_busy:
            return
        self._worker_busy = True
        self.selected_var.set("正在读取会话…")

        # 在后台线程读取会话数据库，完成后回到 Tk 主线程。
        def worker() -> None:
            try:
                conversations = self.reader.list_conversations(self.key_records)
                account_label = None
                if self.data_root is None:
                    account = self.reader.catalog().account_root
                    account_label = f"当前账号 {account.name}" if account is not None else "自动检测"
                self._post_ui(lambda: self._conversations_loaded(conversations, None, account_label))
            except Exception as exc:
                self._post_ui(lambda error=exc: self._conversations_loaded([], error))

        threading.Thread(target=worker, name="wechat-session-reader", daemon=True).start()

    # 将会话读取结果填入三列表格。
    def _conversations_loaded(
        self,
        conversations: list[Conversation],
        error: Exception | None,
        account_label: str | None = None,
    ) -> None:
        self._worker_busy = False
        if account_label and self.data_root is None:
            self.data_root_var.set(account_label)
        for item in self.conversation_tree.get_children():
            self.conversation_tree.delete(item)
        self.conversations = conversations
        self.selected_conversation = None
        self.selected_conversations = []
        self.to_export_button.set_enabled(False)
        if error is not None:
            self.selected_var.set(f"读取失败：{_safe_error_message(error)}")
            return
        if getattr(self.reader, "names_resolved", False):
            self.conversation_hint_var.set("公众号、服务通知和系统会话已隐藏。按住 Command 点选可多选，Shift 可连选。")
        else:
            self.conversation_hint_var.set(
                "当前显示的是微信 ID，不是昵称。昵称在 contact.db，它的密钥和消息库不是同一把。"
                "请回到上一步再点“启动采集”，并在 60 秒内完全退出微信后重新打开。按住 Command 可多选。"
            )
        for index, conversation in enumerate(conversations):
            self.conversation_tree.insert("", "end", iid=str(index), values=(conversation.recent_time, conversation.title, conversation.recent_message))
        self.selected_var.set(f"共发现 {len(conversations)} 个可导出会话")

    # 返回当前表格里选中的会话，保持列表中的原有顺序。
    def _selected_conversations(self) -> list[Conversation]:
        chosen: list[Conversation] = []
        for item in self.conversation_tree.selection():
            try:
                chosen.append(self.conversations[int(item)])
            except (IndexError, ValueError):
                continue
        return chosen

    # 选中表格中的全部会话。
    def _select_all_conversations(self) -> None:
        children = self.conversation_tree.get_children()
        if children:
            self.conversation_tree.selection_set(children)
        self._conversation_selected(None)

    # 清除会话表格的选择。
    def _clear_conversation_selection(self) -> None:
        self.conversation_tree.selection_remove(self.conversation_tree.selection())
        self._conversation_selected(None)

    # 更新当前选中的会话及底部确认文本。
    def _conversation_selected(self, _event: tk.Event[tk.Misc] | None) -> None:
        chosen = self._selected_conversations()
        self.selected_conversations = chosen
        self.selected_conversation = chosen[0] if len(chosen) == 1 else None
        self.to_export_button.set_enabled(bool(chosen))
        if not chosen:
            self.selected_var.set(f"共 {len(self.conversations)} 个会话，未选择")
            return
        preview = "、".join(item.title for item in chosen[:3])
        if len(chosen) > 3:
            preview = f"{preview} 等 {len(chosen)} 个"
        self.selected_var.set(f"已选择 {len(chosen)} 个：{preview}")

    # 进入第三步并显示当前选中的会话。
    def _show_export_step(self) -> None:
        selected = self._selected_conversations()
        if not selected:
            return
        self.selected_conversations = selected
        self.selected_conversation = selected[0] if len(selected) == 1 else None
        if len(selected) == 1:
            self.export_conversation_var.set(f"已选择：{selected[0].title}（{selected[0].conversation_id}）")
        else:
            preview = "、".join(item.title for item in selected[:4])
            suffix = f" 等 {len(selected)} 个会话" if len(selected) > 4 else f"（共 {len(selected)} 个）"
            self.export_conversation_var.set(f"已选择：{preview}{suffix}")
        self.concurrency_var.set(self._concurrency_caption(len(selected)))
        self.last_file_path = None
        self._show_export_note("", "")
        self._show_step(2)

    def _show_export_note(self, status: str | None = None, filename: str | None = None) -> None:
        if status is not None:
            self.export_status_var.set(status)
        if filename is not None:
            self.last_file_label.configure(text=filename)
        has_file = bool(self.last_file_label.cget("text"))
        if has_file:
            self.last_file_label.pack(anchor="w", pady=(4, 0))
        else:
            self.last_file_label.pack_forget()
        if self.export_status_var.get() or has_file:
            self._export_note.pack(anchor="w", fill="x", pady=(12, 0), before=self._export_back)
        else:
            self._export_note.pack_forget()

    # 选择导出目录。
    def _choose_export_dir(self) -> None:
        selected = filedialog.askdirectory(title="选择导出目录", initialdir=self.export_dir_var.get() or str(Path.home()))
        if selected:
            self.export_dir_var.set(selected)

    # 多个会话时各自使用子目录，避免 index.html 互相覆盖。
    def _export_directory(self, conversation: Conversation, root: Path, multiple: bool) -> Path:
        if not multiple:
            return root
        folder = safe_filename(conversation.title or conversation.conversation_id, "chat")
        suffix = safe_filename(conversation.conversation_id, "id")[-12:]
        return root / f"{folder}_{suffix}"

    # 按当前选中的会话数说明自动并发。
    def _concurrency_caption(self, count: int) -> str:
        cpu = os.cpu_count() or 1
        conversations, media = plan_export_concurrency(count)
        if count <= 1:
            return f"按本机 {cpu} 核自动使用 {media} 路并发"
        return f"按本机 {cpu} 核同时导出 {conversations} 个会话，每个会话 {media} 路媒体"

    # 二次确认后在后台读取模型并执行指定格式导出。
    def _export(self, fmt: str) -> None:
        selected = list(self.selected_conversations)
        if not selected or self._worker_busy:
            return
        try:
            days = parse_recent_days(self.recent_days_entry.get())
        except ReaderError as exc:
            self._show_copyable_dialog("输入无效", str(exc))
            return
        destination = Path(self.export_dir_var.get()).expanduser()
        try:
            ensure_key_path_outside_export(self.key_path, destination)
        except KeyStoreError as exc:
            self._show_copyable_dialog("目录不安全", str(exc))
            return
        if len(selected) == 1:
            confirm = f"确定将“{selected[0].title}”导出到\n{destination} 吗？该目录里已有的同名导出文件会被覆盖。"
        else:
            confirm = f"确定将 {len(selected)} 个会话导出到\n{destination} 吗？每个会话单独放在一个子目录，已有的同名导出文件会被覆盖。"
        if not messagebox.askyesno("确认导出", confirm):
            return
        conversation_workers, media_workers = plan_export_concurrency(len(selected))
        self.concurrency_var.set(self._concurrency_caption(len(selected)))
        self._worker_busy = True
        self._set_export_buttons(False)
        self._show_export_note("正在读取消息并生成导出文件…", "")
        multiple = len(selected) > 1

        # 多个会话并行读取。每个会话内部再用媒体线程做解密和转码。
        def worker() -> None:
            exported: list[Path | None] = [None] * len(selected)
            failures: list[str] = []
            failure_lock = threading.Lock()
            started = 0
            started_lock = threading.Lock()
            total = len(selected)

            def export_one(index: int, conversation: Conversation) -> None:
                nonlocal started
                title = conversation.title
                with started_lock:
                    started += 1
                    current = started
                self._post_ui(lambda i=current, name=title, count=total: self._show_export_note(f"正在导出 {i}/{count}：{name}"))
                try:
                    model = self.reader.read_conversation(
                        conversation.conversation_id,
                        self.key_records,
                        recent_days=days,
                        media_mode="thread",
                        media_workers=media_workers,
                    )
                    exported[index] = export_model(model, fmt, self._export_directory(conversation, destination, multiple))
                except Exception as exc:
                    with failure_lock:
                        failures.append(f"{title}：{_safe_error_message(exc)}")

            try:
                with ThreadPoolExecutor(max_workers=conversation_workers, thread_name_prefix="wechat-conversation") as pool:
                    futures = [pool.submit(export_one, index, conversation) for index, conversation in enumerate(selected)]
                    for future in futures:
                        future.result()
            except Exception as exc:
                with failure_lock:
                    failures.append(_safe_error_message(exc))
            finished = [path for path in exported if path is not None]
            self._post_ui(lambda finished=finished, failures=list(failures): self._export_batch_finished(finished, failures))

        threading.Thread(target=worker, name="wechat-export", daemon=True).start()

    # 在后台安装缺失的 Python 包和 ffmpeg，界面只显示进度。
    def _setup_dependencies(self) -> None:
        if self._deps_busy:
            return
        self._deps_busy = True
        if isinstance(self.dependency_button, FlatButton):
            self.dependency_button.set_enabled(False)
        self._set_status(self.deps_var, self.deps_mark, "pending", "正在安装依赖…")

        def worker() -> None:
            try:
                ok, detail = install_missing_dependencies(
                    lambda text: self._post_ui(
                        lambda text=text: self._set_status(self.deps_var, self.deps_mark, "pending", text)
                    )
                )
            except Exception as exc:
                ok, detail = False, _safe_error_message(exc)
            self._post_ui(lambda ok=ok, detail=detail: self._dependencies_finished(ok, detail))

        threading.Thread(target=worker, name="wechat-deps", daemon=True).start()

    def _dependencies_finished(self, ok: bool, detail: str) -> None:
        self._deps_busy = False
        if isinstance(self.dependency_button, FlatButton):
            self.dependency_button.set_enabled(True)
        if ok:
            self._set_status(self.deps_var, self.deps_mark, "ok", "依赖已就绪")
            return
        self._set_status(self.deps_var, self.deps_mark, "err", "依赖安装失败")
        self._show_copyable_dialog("依赖安装失败", detail)

    # 汇总批量导出的成功路径和失败原因。
    def _export_batch_finished(self, exported: list[Path], failures: list[str]) -> None:
        self._worker_busy = False
        self._set_export_buttons(True)
        if exported:
            self.last_file_path = exported[-1]
            self._show_export_note(filename=exported[-1].name)
        lines = [f"成功 {len(exported)} 个，失败 {len(failures)} 个。"]
        if exported:
            lines.append("")
            lines.extend(str(path) for path in exported)
        if failures:
            lines.append("")
            lines.append("失败：")
            lines.extend(failures)
        message = "\n".join(lines)
        if failures and not exported:
            self._show_export_note("导出失败")
            self._show_copyable_dialog("导出失败", message)
            return
        self._show_export_note("导出完成" if not failures else "部分导出完成")
        self._show_copyable_dialog("导出完成" if not failures else "部分导出完成", message)

    # 恢复三个导出按钮颜色并展示成功文件链接或错误。
    def _export_finished(self, path: Path | None, error: Exception | None) -> None:
        self._worker_busy = False
        self._set_export_buttons(True)
        if error is not None:
            message = f"导出失败：{_safe_error_message(error)}"
            self._show_export_note(message)
            self._show_copyable_dialog("导出失败", message)
            return
        if path is None:
            return
        self.last_file_path = path
        self._show_export_note("导出完成", path.name)
        self._show_copyable_dialog("导出成功", f"已导出到：\n{path}")

    # 批量禁用或启用导出按钮，启用时恢复各自原始颜色。
    def _set_export_buttons(self, enabled: bool) -> None:
        for button in self.export_buttons.values():
            button.set_enabled(enabled)

    # 用系统默认方式打开最近生成的导出文件。
    def _open_last_file(self, _event: tk.Event[tk.Misc]) -> None:
        if self.last_file_path is None or not self.last_file_path.exists():
            return
        try:
            if sys.platform == "win32":
                os.startfile(self.last_file_path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(self.last_file_path)])
            else:
                subprocess.Popen(["xdg-open", str(self.last_file_path)])
        except OSError:
            return

    # 把后台线程回调安全地排入 Tk 主线程。
    def _post_ui(self, callback: Callable[[], object]) -> None:
        with contextlib.suppress(tk.TclError):
            self.after(0, callback)

    # 窗口销毁前取消状态定时器，避免回调访问已销毁控件。
    def destroy(self) -> None:
        if self._status_after_id is not None:
            with contextlib.suppress(tk.TclError):
                self.after_cancel(self._status_after_id)
        if self._delayed_status_id is not None:
            with contextlib.suppress(tk.TclError):
                self.after_cancel(self._delayed_status_id)
        with contextlib.suppress(tk.TclError):
            self.unbind_all("<MouseWheel>")
        super().destroy()


# 启动桌面应用主循环。
def main() -> None:
    # 进程模式用 spawn 启动子进程。打包成单文件程序后必须先调用它，否则子进程会再开一个界面。
    import multiprocessing

    multiprocessing.freeze_support()
    if sys.platform != "darwin":
        print(
            "macOS 导出界面只在 Mac 上运行。\n"
            "Linux / Windows 请运行：python main.py gui",
            file=sys.stderr,
        )
        raise SystemExit(2)
    app = WeChatExportApp()
    app.mainloop()


if __name__ == "__main__":
    main()
