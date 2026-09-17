"""微信本地聊天记录导出工具的 Tkinter 界面。"""

from __future__ import annotations

import contextlib
import os
import threading
import subprocess
import sys
import tkinter as tk
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
)


ASSET_DIR = Path(__file__).resolve().parent / "assets"
UI_FONT = "Microsoft YaHei UI" if sys.platform == "win32" else "PingFang SC"
EXPORT_COLORS = {
    "html": ("#07C160", "#06AD56"),
    "text": ("#2787F5", "#1677E6"),
    "sqlite": ("#8B5CF6", "#7546DD"),
}


# 返回当前平台默认的导出目录。
def _default_export_dir() -> Path:
    desktop = Path.home() / "Desktop"
    if desktop.is_dir():
        return desktop / "WeChatExport"
    return Path.home() / "WeChatExport"


# 第一步采集说明：macOS 需要关闭 SIP，Windows 需要可读进程内存。
def _capture_hint_text() -> str:
    if sys.platform == "win32":
        return (
            "请先启动并登录微信 4.x（进程名为 Weixin.exe）。采集会只读扫描当前用户的微信进程内存以寻找"
            "数据库密钥，不会修改微信文件。若提示拒绝访问，请以管理员身份重新运行本工具。"
        )
    return (
        "SIP 关闭说明：请在 macOS 恢复模式打开“终端”，执行 csrutil disable，重启后回到此页刷新。"
        "程序不会自动修改 SIP；完成采集后可自行重新启用。"
    )


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
        background: str = "#07C160",
        hover_background: str | None = None,
        disabled_background: str = "#B9C2C8",
        foreground: str = "white",
        **kwargs: Any,
    ) -> None:
        self.command = command
        self.normal_background = background
        self.hover_background = hover_background or background
        self.disabled_background = disabled_background
        self.normal_foreground = foreground
        self.disabled_foreground = "#F3F5F6"
        self.enabled = True
        super().__init__(
            master,
            text=text,
            bg=background,
            fg=foreground,
            activebackground=background,
            activeforeground=foreground,
            padx=16,
            pady=9,
            cursor="hand2",
            relief="flat",
            bd=0,
            highlightthickness=0,
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
        self.geometry("900x650")
        self.minsize(760, 540)
        self.configure(bg="#F5F6F7")
        env_root = os.environ.get("WECHAT_DATA_ROOT", "").strip()
        self.data_root = Path(env_root).expanduser() if env_root else None
        self.reader = reader or WeChatReader(data_root=self.data_root, key_path=key_path)
        self.key_path = Path(key_path).expanduser()
        self.key_records = []
        self._captured_masks: list[str] = []
        self.conversations: list[Conversation] = []
        self.selected_conversation: Conversation | None = None
        self._status_after_id: str | None = None
        self._delayed_status_id: str | None = None
        self._worker_busy = False
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
        style.configure("WeChat.Treeview", rowheight=34, font=(UI_FONT, 13))
        style.configure("WeChat.Treeview.Heading", font=(UI_FONT, 12, "bold"))

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
        self.header = tk.Frame(self, bg="#FFFFFF", height=64)
        self.header.pack(fill="x")
        self.header.pack_propagate(False)
        tk.Label(
            self.header,
            text="微信聊天记录导出",
            bg="#FFFFFF",
            fg="#1F2329",
            font=(UI_FONT, 18, "bold"),
        ).pack(side="left", padx=24)
        self.refresh_button = tk.Label(
            self.header,
            text="⟳",
            bg="#FFFFFF",
            fg="#07C160",
            font=("Arial", 22),
            cursor="hand2",
        )
        self.refresh_button.pack(side="right", padx=24)
        self.refresh_button.bind("<Button-1>", lambda _event: self.refresh_status())
        self.body = tk.Frame(self, bg="#F5F6F7")
        self.body.pack(fill="both", expand=True, padx=24, pady=20)
        self.step_frames: list[tk.Frame] = []

    # 创建三行状态卡片和第一步操作控件。
    def _build_key_step(self) -> None:
        frame = tk.Frame(self.body, bg="#F5F6F7")
        self.step_frames.append(frame)
        tk.Label(frame, text="第一步：获取密钥", bg="#F5F6F7", fg="#1F2329", font=(UI_FONT, 17, "bold")).pack(anchor="w")
        tk.Label(
            frame,
            text="所有数据只在本机读取；密钥不会写入导出目录。",
            bg="#F5F6F7",
            fg="#737A81",
            font=(UI_FONT, 11),
        ).pack(anchor="w", pady=(5, 18))
        tk.Label(
            frame,
            text=_capture_hint_text(),
            bg="#FFF8E6",
            fg="#795548",
            justify="left",
            anchor="w",
            wraplength=780,
            padx=12,
            pady=9,
        ).pack(fill="x", pady=(0, 12))
        self.sip_var = tk.StringVar(value="正在检测采集条件…")
        self.wechat_var = tk.StringVar(value="正在检测微信客户端…")
        self.capture_var = tk.StringVar(value="尚未启动密钥采集")
        self.sip_detail_var = tk.StringVar(value="")
        self._status_row(frame, self.sip_var, self.sip_detail_var)
        self._status_row(frame, self.wechat_var, tk.StringVar(value=""), button_text="启动微信", command=self._launch_wechat)
        self.capture_row = self._status_row(
            frame,
            self.capture_var,
            tk.StringVar(value=""),
            button_text="启动采集",
            command=self._start_capture,
        )
        self.capture_button = self.capture_row.winfo_children()[-1]
        path_box = tk.Frame(frame, bg="#FFFFFF", padx=14, pady=12)
        path_box.pack(fill="x", pady=(22, 10))
        tk.Label(path_box, text="密钥文件路径", bg="#FFFFFF", fg="#56606A", font=(UI_FONT, 11)).pack(anchor="w")
        path_line = tk.Frame(path_box, bg="#FFFFFF")
        path_line.pack(fill="x", pady=(5, 0))
        self.key_path_var = tk.StringVar(value=str(self.key_path))
        tk.Entry(path_line, textvariable=self.key_path_var, state="readonly", relief="flat", readonlybackground="#FFFFFF", fg="#30363B").pack(side="left", fill="x", expand=True)
        FlatButton(path_line, "选择路径", self._choose_key_path, background="#E8F8EF", hover_background="#D7F3E4", foreground="#078A4A").pack(side="right")
        data_box = tk.Frame(frame, bg="#FFFFFF", padx=14, pady=12)
        data_box.pack(fill="x", pady=(0, 10))
        tk.Label(data_box, text="微信数据目录（可留空自动检测）", bg="#FFFFFF", fg="#56606A", font=(UI_FONT, 11)).pack(anchor="w")
        data_line = tk.Frame(data_box, bg="#FFFFFF")
        data_line.pack(fill="x", pady=(5, 0))
        self.data_root_var = tk.StringVar(value=str(self.data_root) if self.data_root else "自动检测")
        tk.Entry(data_line, textvariable=self.data_root_var, state="readonly", relief="flat", readonlybackground="#FFFFFF", fg="#30363B").pack(side="left", fill="x", expand=True)
        FlatButton(data_line, "自动检测", self._clear_data_root, background="#EEF1F3", hover_background="#E1E6E9", foreground="#56606A").pack(side="right", padx=(8, 0))
        FlatButton(data_line, "选择目录", self._choose_data_root, background="#E8F8EF", hover_background="#D7F3E4", foreground="#078A4A").pack(side="right")
        tk.Label(frame, text="本次运行捕获的密钥（已脱敏）", bg="#F5F6F7", fg="#56606A", font=(UI_FONT, 11)).pack(anchor="w", pady=(10, 4))
        self.captured_list_var = tk.StringVar(value="暂无")
        tk.Label(frame, textvariable=self.captured_list_var, bg="#F5F6F7", fg="#30363B", justify="left", anchor="w", wraplength=760).pack(fill="x")
        bottom = tk.Frame(frame, bg="#F5F6F7")
        bottom.pack(fill="x", side="bottom", pady=(22, 0))
        actions = tk.Frame(bottom, bg="#F5F6F7")
        actions.pack(side="right")
        self.key_count_var = tk.StringVar(value="已保存密钥：0 个")
        tk.Label(actions, textvariable=self.key_count_var, bg="#F5F6F7", fg="#56606A").pack(side="right", padx=(0, 14))
        FlatButton(actions, "重置已保存密钥", self._reset_keys, background="#FDECEC", hover_background="#FAD7D7", foreground="#B42318").pack(side="right", padx=(0, 14))
        self.to_conversations_button = FlatButton(actions, "进入会话选择", self._enter_conversations, background="#07C160", hover_background="#06AD56")
        self.to_conversations_button.pack(side="right")

    # 创建一行带可选操作按钮的状态卡片。
    def _status_row(
        self,
        parent: tk.Misc,
        variable: tk.StringVar,
        detail_variable: tk.StringVar,
        *,
        button_text: str | None = None,
        command: Callable[[], object] | None = None,
    ) -> tk.Frame:
        row = tk.Frame(parent, bg="#FFFFFF", padx=14, pady=13)
        row.pack(fill="x", pady=4)
        tk.Label(row, textvariable=variable, bg="#FFFFFF", fg="#1F2329", font=(UI_FONT, 12)).pack(side="left")
        tk.Label(row, textvariable=detail_variable, bg="#FFFFFF", fg="#737A81", font=(UI_FONT, 10)).pack(side="left", padx=12)
        if button_text:
            FlatButton(row, button_text, command, background="#E8F8EF", hover_background="#D7F3E4", foreground="#078A4A").pack(side="right")
        return row

    # 创建会话树表格和第二步导航控件。
    def _build_conversation_step(self) -> None:
        frame = tk.Frame(self.body, bg="#F5F6F7")
        self.step_frames.append(frame)
        top = tk.Frame(frame, bg="#F5F6F7")
        top.pack(fill="x")
        tk.Label(top, text="第二步：选择会话", bg="#F5F6F7", fg="#1F2329", font=(UI_FONT, 17, "bold")).pack(side="left")
        FlatButton(top, "刷新", self._load_conversations, background="#E8F8EF", hover_background="#D7F3E4", foreground="#078A4A").pack(side="right")
        tk.Label(frame, text="公众号、服务通知和系统会话已隐藏。", bg="#F5F6F7", fg="#737A81").pack(anchor="w", pady=(5, 13))
        table_frame = tk.Frame(frame, bg="#FFFFFF")
        table_frame.pack(fill="both", expand=True)
        self.conversation_tree = ttk.Treeview(table_frame, columns=("recent_time", "title", "recent_message"), show="headings", style="WeChat.Treeview", selectmode="browse")
        self.conversation_tree.heading("recent_time", text="最近时间")
        self.conversation_tree.heading("title", text="会话标题")
        self.conversation_tree.heading("recent_message", text="最近消息摘要")
        self.conversation_tree.column("recent_time", width=160, anchor="w")
        self.conversation_tree.column("title", width=220, anchor="w")
        self.conversation_tree.column("recent_message", width=450, anchor="w")
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.conversation_tree.yview)
        self.conversation_tree.configure(yscrollcommand=scrollbar.set)
        self.conversation_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.conversation_tree.bind("<<TreeviewSelect>>", self._conversation_selected)
        self.selected_var = tk.StringVar(value="未选择会话")
        tk.Label(frame, textvariable=self.selected_var, bg="#F5F6F7", fg="#078A4A", anchor="w").pack(fill="x", pady=(12, 6))
        nav = tk.Frame(frame, bg="#F5F6F7")
        nav.pack(fill="x")
        FlatButton(nav, "返回获取密钥", lambda: self._show_step(0), background="#E8ECEF", hover_background="#DDE3E7", foreground="#56606A").pack(side="left")
        self.to_export_button = FlatButton(nav, "进入导出", self._show_export_step, background="#07C160", hover_background="#06AD56")
        self.to_export_button.set_enabled(False)
        self.to_export_button.pack(side="right")

    # 创建导出目录、最近天数和三个纵向彩色按钮。
    def _build_export_step(self) -> None:
        frame = tk.Frame(self.body, bg="#F5F6F7")
        self.step_frames.append(frame)
        tk.Label(frame, text="第三步：导出", bg="#F5F6F7", fg="#1F2329", font=(UI_FONT, 17, "bold")).pack(anchor="w")
        self.export_conversation_var = tk.StringVar(value="")
        tk.Label(frame, textvariable=self.export_conversation_var, bg="#F5F6F7", fg="#078A4A", font=(UI_FONT, 12)).pack(anchor="w", pady=(5, 18))
        options = tk.Frame(frame, bg="#FFFFFF", padx=16, pady=14)
        options.pack(fill="x")
        row = tk.Frame(options, bg="#FFFFFF")
        row.pack(fill="x", pady=3)
        tk.Label(row, text="最近天数（留空为全部）", bg="#FFFFFF", fg="#56606A").pack(side="left")
        self.recent_days_entry = tk.Entry(row, width=15, relief="solid", bd=1)
        self.recent_days_entry.pack(side="left", padx=14)
        row2 = tk.Frame(options, bg="#FFFFFF")
        row2.pack(fill="x", pady=(10, 3))
        tk.Label(row2, text="导出目录", bg="#FFFFFF", fg="#56606A").pack(side="left")
        self.export_dir_var = tk.StringVar(value=str(_default_export_dir()))
        tk.Entry(row2, textvariable=self.export_dir_var, relief="solid", bd=1).pack(side="left", fill="x", expand=True, padx=14)
        FlatButton(row2, "选择目录", self._choose_export_dir, background="#EEF1F3", hover_background="#E1E6E9", foreground="#56606A").pack(side="right")
        button_box = tk.Frame(frame, bg="#F5F6F7")
        button_box.pack(anchor="center", pady=28)
        self.export_buttons: dict[str, FlatButton] = {}
        for fmt, label in (("html", "导出 HTML"), ("text", "导出纯文本"), ("sqlite", "导出 SQLite")):
            normal, hover = EXPORT_COLORS[fmt]
            button = FlatButton(button_box, label, lambda fmt=fmt: self._export(fmt), background=normal, hover_background=hover)
            button.pack(fill="x", pady=7)
            self.export_buttons[fmt] = button
        self.export_status_var = tk.StringVar(value="")
        tk.Label(frame, textvariable=self.export_status_var, bg="#F5F6F7", fg="#56606A", wraplength=760).pack(anchor="center", pady=(0, 8))
        self.last_file_label = tk.Label(frame, text="", bg="#F5F6F7", fg="#078A4A", cursor="hand2", font=(UI_FONT, 11, "underline"))
        self.last_file_label.pack(anchor="center")
        self.last_file_path: Path | None = None
        self.last_file_label.bind("<Button-1>", self._open_last_file)
        FlatButton(frame, "返回会话列表", lambda: self._show_step(1), background="#E8ECEF", hover_background="#DDE3E7", foreground="#56606A").pack(anchor="w", pady=(20, 0))

    # 显示指定步骤页面并隐藏其他页面。
    def _show_step(self, index: int) -> None:
        for frame in self.step_frames:
            frame.pack_forget()
        if 0 <= index < len(self.step_frames):
            self.step_frames[index].pack(fill="both", expand=True)

    # 读取密钥文件并更新右下角计数。
    def _reload_keys(self) -> None:
        try:
            self.key_records = load_key_records(self.key_path)
        except KeyStoreError:
            self.key_records = []
        self.key_count_var.set(f"已保存密钥：{len(self.key_records)} 个")

    # 定时刷新采集前置条件和微信进程状态。
    def refresh_status(self) -> None:
        ready, headline, detail = get_capture_prerequisite()
        self.sip_var.set(("✅ " if ready is True else "❌ ") + headline)
        self.sip_detail_var.set(detail)
        status = detect_wechat()
        if status.running:
            self.wechat_var.set(f"✅ 启动微信客户端（已检测到 PID {status.pid}，版本 {status.version or '未知'}）")
        else:
            self.wechat_var.set("❌ 启动微信客户端（当前未检测到）")
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
        self.wechat_var.set(("✅ " if ok else "❌ ") + detail)
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
        self.capture_var.set("⏳ 启动密钥采集（剩余 60 秒）")
        self._captured_masks = []
        listening_hint = (
            "正在扫描微信进程内存，请保持微信已登录…"
            if sys.platform == "win32"
            else "正在监听，请在微信中登录并打开几个会话…"
        )
        self.captured_list_var.set(listening_hint)

        # 把采集倒计时安全地投递到 Tk 主线程。
        def on_tick(remaining: int) -> None:
            self._post_ui(lambda: self.capture_var.set(f"⏳ 启动密钥采集（剩余 {remaining} 秒）"))

        # 把已经脱敏的候选 key 投递到界面。
        def on_candidate(masked: str) -> None:
            self._captured_masks.append(masked)
            display = "\n".join(self._captured_masks)
            self._post_ui(lambda: self.captured_list_var.set(display))

        # 把不含完整 key 的采集状态投递到界面。
        def on_status(detail: str) -> None:
            self._post_ui(lambda: self.capture_var.set(f"⏳ {detail}"))

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
                    duration=60,
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

    # 处理采集线程结束结果并恢复按钮颜色。
    def _capture_finished(self, result: CaptureResult, capture_button: tk.Misc) -> None:
        self._worker_busy = False
        if isinstance(capture_button, FlatButton):
            capture_button.set_enabled(True)
        self._reload_keys()
        if result.error:
            self.capture_var.set(f"❌ {result.error}")
        elif result.validated_keys:
            self.capture_var.set(f"✅ 密钥采集完成（验证成功 {len(result.validated_keys)} 个）")
        else:
            self.capture_var.set("❌ 密钥采集完成，但没有候选通过验证")
        if result.report:
            self.captured_list_var.set(result.report)

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
                self._post_ui(lambda: self._conversations_loaded(conversations, None))
            except Exception as exc:
                self._post_ui(lambda error=exc: self._conversations_loaded([], error))

        threading.Thread(target=worker, name="wechat-session-reader", daemon=True).start()

    # 将会话读取结果填入三列表格。
    def _conversations_loaded(self, conversations: list[Conversation], error: Exception | None) -> None:
        self._worker_busy = False
        for item in self.conversation_tree.get_children():
            self.conversation_tree.delete(item)
        self.conversations = conversations
        self.selected_conversation = None
        self.to_export_button.set_enabled(False)
        if error is not None:
            self.selected_var.set(f"读取失败：{_safe_error_message(error)}")
            return
        for index, conversation in enumerate(conversations):
            self.conversation_tree.insert("", "end", iid=str(index), values=(conversation.recent_time, conversation.title, conversation.recent_message))
        self.selected_var.set(f"共发现 {len(conversations)} 个可导出会话")

    # 更新当前选中的会话及底部确认文本。
    def _conversation_selected(self, _event: tk.Event[tk.Misc]) -> None:
        selection = self.conversation_tree.selection()
        if not selection:
            self.selected_conversation = None
            self.to_export_button.set_enabled(False)
            return
        try:
            selected = self.conversations[int(selection[0])]
        except (IndexError, ValueError):
            return
        self.selected_conversation = selected
        self.selected_var.set(f"已选择：{selected.title}（{selected.conversation_id}）")
        self.to_export_button.set_enabled(True)

    # 进入第三步并显示当前会话标题及 ID。
    def _show_export_step(self) -> None:
        if self.selected_conversation is None:
            return
        selected = self.selected_conversation
        self.export_conversation_var.set(f"已选择：{selected.title}（{selected.conversation_id}）")
        self.export_status_var.set("")
        self.last_file_label.configure(text="")
        self.last_file_path = None
        self._show_step(2)

    # 选择导出目录。
    def _choose_export_dir(self) -> None:
        selected = filedialog.askdirectory(title="选择导出目录", initialdir=self.export_dir_var.get() or str(Path.home()))
        if selected:
            self.export_dir_var.set(selected)

    # 二次确认后在后台读取模型并执行指定格式导出。
    def _export(self, fmt: str) -> None:
        if self.selected_conversation is None or self._worker_busy:
            return
        try:
            days = parse_recent_days(self.recent_days_entry.get())
        except ReaderError as exc:
            messagebox.showerror("输入无效", str(exc))
            return
        destination = Path(self.export_dir_var.get()).expanduser()
        try:
            ensure_key_path_outside_export(self.key_path, destination)
        except KeyStoreError as exc:
            messagebox.showerror("目录不安全", str(exc))
            return
        if not messagebox.askyesno("确认导出", f"确定将“{self.selected_conversation.title}”导出到\n{destination} 吗？"):
            return
        self._worker_busy = True
        self._set_export_buttons(False)
        self.export_status_var.set("正在读取消息并生成导出文件…")
        self.last_file_label.configure(text="")
        selected_id = self.selected_conversation.conversation_id

        # 在后台线程读取消息并写入用户选择的导出格式。
        def worker() -> None:
            try:
                model = self.reader.read_conversation(selected_id, self.key_records, recent_days=days)
                path = export_model(model, fmt, destination)
                self._post_ui(lambda: self._export_finished(path, None))
            except Exception as exc:
                self._post_ui(lambda error=exc: self._export_finished(None, error))

        threading.Thread(target=worker, name="wechat-export", daemon=True).start()

    # 恢复三个导出按钮颜色并展示成功文件链接或错误。
    def _export_finished(self, path: Path | None, error: Exception | None) -> None:
        self._worker_busy = False
        self._set_export_buttons(True)
        if error is not None:
            self.export_status_var.set(f"导出失败：{_safe_error_message(error)}")
            return
        if path is None:
            return
        self.last_file_path = path
        self.export_status_var.set("导出完成：")
        self.last_file_label.configure(text=path.name)

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
        super().destroy()


# 启动桌面应用主循环。
def main() -> None:
    app = WeChatExportApp()
    app.mainloop()


if __name__ == "__main__":
    main()
