"""主页：设置 / 密钥（进程、数据目录、密钥状态与提取）+ 导出（会话 → JSON/CSV/HTML）。"""

import csv
import html
import json
import os
import shutil
import sys
from pathlib import Path

from PySide6.QtCore import QProcess, QThread, Signal
from PySide6.QtWidgets import (QButtonGroup, QCheckBox, QComboBox, QFileDialog,
                               QFormLayout, QFrame, QHBoxLayout, QLabel,
                               QLineEdit, QMessageBox, QPlainTextEdit,
                               QProgressBar, QPushButton, QRadioButton,
                               QScrollArea, QVBoxLayout, QWidget)

from wxwatch.gui.backend import KEYS_FILE, PROJECT, cli_invocation
from wxwatch.gui.privilege import extract_keys_gui, find_wechat_pid_safe
from wxwatch.gui.style import ACCENT
from wxwatch.gui.widgets import make_button


def detect_db_storage() -> Path | None:
    """自动检测微信 db_storage 目录（sudo 运行时定位真实用户的 home）。"""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sys.platform != "win32":
        import pwd
        try:
            home = Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            home = Path.home()
    else:
        home = Path.home()
    root = home / "Documents" / "xwechat_files"
    cands = sorted(p for p in root.glob("*/db_storage") if p.parent.name.startswith("wxid_"))
    return cands[0] if cands else None


def check_db_storage(path: str | Path) -> tuple[bool, str]:
    """校验 db_storage 目录：存在、含微信消息数据库、且文件实际可读取。

    返回 (是否可用, 描述信息)。检测到目录但读不到文件时同样判失败。"""
    p = Path(path).expanduser()
    if not p.is_dir():
        return False, "目录不存在"
    # 必须以微信的 message/ 子库为准，避免误选普通目录（里面恰好有 .db 也算不出消息）
    dbs = sorted(p.glob("message/*.db"))
    if not dbs:
        return False, "未找到微信消息数据库 message/*.db（应选择 db_storage 目录）"
    for db in dbs[:3]:  # 抽查前几个，确认真能读
        try:
            with open(db, "rb") as f:
                if not f.read(16):
                    return False, f"{db.name} 是空文件"
        except OSError as e:
            return False, f"{db.name} 读取失败: {e.strerror or e}"
    total = sum(1 for _ in p.rglob("*.db"))
    return True, f"消息库 {len(dbs)} 个（共 {total} 个数据库文件），可读取"


def detect_wechat_pid() -> int | None:
    """平台分发在 wxwatch.gui.privilege（Windows 走 Weixin.exe 枚举）。"""
    return find_wechat_pid_safe()


class _KeyCheckWorker(QThread):
    """后台校验密钥（含镜像拷贝 + 解密探测，大库耗时数秒，不能卡 UI）。"""
    done = Signal(str, str)  # 显示文本, 状态类别 ok|warn|err

    def __init__(self, db_storage: str):
        super().__init__()
        self.db_storage = db_storage

    def run(self):
        self.done.emit(*self._check())

    def _check(self) -> tuple[str, str]:
        if not KEYS_FILE.exists():
            return "❌ keys.json 不存在，请先提取密钥", "err"
        try:
            keys = json.loads(KEYS_FILE.read_text())
        except Exception as e:
            return f"❌ keys.json 损坏: {e}", "err"
        if not self.db_storage:
            return "❌ 未选择数据目录", "err"
        # 实际打开验证一个库
        try:
            from wxwatch.decryptor import Decryptor
            dec = Decryptor(Path(self.db_storage), keys, PROJECT / "mirror")
            probe = next((r for r in keys if r.startswith("message/message_")),
                         next(iter(keys)))
            ok = dec.sanity_check(probe)
        except Exception as e:
            return f"⚠️ 校验出错: {e}", "warn"
        if ok:
            return f"✅ {len(keys)} 个密钥，校验通过", "ok"
        return f"⚠️ {len(keys)} 个密钥但校验失败（微信可能已重启，需重新提取）", "warn"


class _ExportWorker(QThread):
    progressed = Signal(int)
    done = Signal(str, int, str)  # out_path, count, error

    def __init__(self, backend, talker, name, fmt, out_dir, copy_media):
        super().__init__()
        self.backend, self.talker, self.name = backend, talker, name
        self.fmt, self.out_dir, self.copy_media = fmt, out_dir, copy_media

    def run(self):
        try:
            msgs = self.backend.messages_for(self.talker, limit=2**31 - 1)
            n_media = 0
            if self.copy_media:
                mdir = self.out_dir / "media"
                for m in msgs:
                    for p in list(m.get("media_files") or []):
                        fp = Path(p)
                        if fp.exists():
                            mdir.mkdir(exist_ok=True)
                            dst = mdir / fp.name
                            if not dst.exists():
                                shutil.copy2(fp, dst)
                                n_media += 1
                    f = m.get("file") or {}
                    if f.get("path") and Path(f["path"]).exists():
                        mdir.mkdir(exist_ok=True)
                        dst = mdir / Path(f["path"]).name
                        if not dst.exists():
                            shutil.copy2(f["path"], dst)
                            n_media += 1
            out = self.out_dir / f"{self.name}.{self.fmt}"
            getattr(self, f"_write_{self.fmt}")(msgs, out)
            self.done.emit(str(out), len(msgs),
                           f"（另拷贝媒体 {n_media} 个）" if self.copy_media else "")
        except Exception as e:
            self.done.emit("", 0, f"导出失败: {e}")

    # ---------- 各格式 ----------

    @staticmethod
    def _rows(msgs):
        for m in msgs:
            yield {
                "time": m.get("time"), "chat": m.get("talker_name"),
                "sender": m.get("sender_name") or m.get("sender"),
                "type": m.get("type"),
                "content": m.get("content") or m.get("title") or "",
                "file": (m.get("file") or {}).get("name"),
                "media": "; ".join(m.get("media_files") or []),
                "raw": m,
            }

    def _write_json(self, msgs, out: Path):
        rows = [r["raw"] for r in self._rows(msgs)]
        out.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")

    def _write_csv(self, msgs, out: Path):
        with open(out, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["时间", "会话", "发言人", "类型", "内容", "文件名", "媒体路径"])
            for r in self._rows(msgs):
                w.writerow([r["time"], r["chat"], r["sender"], r["type"],
                            r["content"], r["file"], r["media"]])

    def _write_html(self, msgs, out: Path):
        parts = ["<!doctype html><meta charset='utf-8'><title>聊天记录</title>",
                 "<style>body{font-family:sans-serif;max-width:860px;margin:24px auto;"
                 "background:#f5f6f7;color:#1f2329}h1{font-size:20px}"
                 ".m{background:#fff;border-radius:10px;padding:10px 14px;margin:8px 0;"
                 "box-shadow:0 1px 2px rgba(0,0,0,.06)}.meta{color:#8a8f99;font-size:12px;"
                 "margin-bottom:4px}.t{color:#07c160;font-size:12px}</style>",
                 f"<h1>{html.escape(self.name)}（{len(msgs)} 条）</h1>"]
        for r in self._rows(msgs):
            body = html.escape(str(r["content"] or r["file"] or ""))
            media = f"<div class='t'>📎 {html.escape(r['media'])}</div>" if r["media"] else ""
            parts.append(
                f"<div class='m'><div class='meta'>{r['time']} · "
                f"{html.escape(str(r['sender'] or r['chat'] or ''))} · {r['type']}</div>"
                f"<div>{body}</div>{media}</div>")
        out.write_text("\n".join(parts), encoding="utf-8")


class HomePage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        self._proc: QProcess | None = None
        self._worker: _ExportWorker | None = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea(widgetResizable=True)
        outer.addWidget(scroll)
        body = QWidget()
        scroll.setWidget(body)
        lay = QVBoxLayout(body)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(16)

        lay.addWidget(self._build_setup_card())
        lay.addWidget(self._build_export_card())
        lay.addStretch(1)

        self._key_worker: _KeyCheckWorker | None = None
        self.refresh_pid()
        self.refresh_dir()
        self.check_keys()
        self.check_image_key()

    # ---------- 界面构建 ----------

    def _build_setup_card(self) -> QFrame:
        card = QFrame(objectName="card")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(12)

        title = QLabel("设置 / 密钥")
        title.setStyleSheet("font-weight:600;")
        lay.addWidget(title)

        form = QFormLayout()
        form.setSpacing(10)

        # 微信进程
        self.pid_label = QLabel("检测中…")
        form.addRow("微信进程", self.pid_label)

        # 数据目录
        row = QHBoxLayout()
        self.dir_edit = QLineEdit()
        self.dir_edit.setPlaceholderText("db_storage 目录，如 ~/Documents/xwechat_files/wxid_xxx/db_storage")
        btn_dir = make_button("浏览…", "secondary")
        btn_dir.clicked.connect(self._browse_db_dir)
        row.addWidget(self.dir_edit, 1)
        row.addWidget(btn_dir)
        form.addRow("数据目录", row)

        # 密钥状态：数据库密钥 + 图片密钥（V2 图片 .dat 解密用）同行显示
        self.keys_label = QLabel("检测中…")
        self.imgkey_label = QLabel("检测中…")
        key_row = QHBoxLayout()
        key_row.setContentsMargins(0, 0, 0, 0)
        key_row.setSpacing(8)
        sep = QLabel("·")
        sep.setProperty("muted", True)
        key_row.addWidget(self.keys_label)
        key_row.addWidget(sep)
        key_row.addWidget(self.imgkey_label)
        key_row.addStretch(1)
        form.addRow("密钥状态", key_row)

        lay.addLayout(form)

        # 操作按钮
        row = QHBoxLayout()
        self.btn_extract = QPushButton("重新提取密钥")
        self.btn_extract.clicked.connect(self.extract_keys)
        btn_imgkey = make_button("自动抓取图片密钥", "secondary")
        btn_imgkey.clicked.connect(self.extract_image_key)
        btn_parse = make_button("全量解析", "secondary")
        btn_parse.clicked.connect(self.run_parse)
        btn_reload = make_button("重新加载", "secondary")
        btn_reload.clicked.connect(self.main.reload_backend)
        row.addWidget(self.btn_extract)
        row.addWidget(btn_imgkey)
        row.addWidget(btn_parse)
        row.addWidget(btn_reload)
        row.addStretch(1)
        lay.addLayout(row)

        self.log = QPlainTextEdit(readOnly=True)
        self.log.setMaximumBlockCount(2000)
        self.log.setFixedHeight(6 * (self.log.fontMetrics().lineSpacing() + 3))
        self.log.setVisible(False)  # 默认隐藏，有日志输出时才显示
        lay.addWidget(self.log)

        if sys.platform == "win32":
            tip_text = ("提示：提取密钥需要读取微信进程内存（ReadProcessMemory），"
                        "Windows 下必须右键「以管理员身份运行」本程序后再点击提取。"
                        "微信重启后密钥会变化，需要重新提取。")
        else:
            tip_text = ("提示：当前以 root 运行，提取密钥/自动抓取均无需密码。"
                        "微信重启后密钥会变化，需要重新提取。"
                        "\n图片密钥（V2）为自动抓取：后台守护监听微信的解码缓存，"
                        "你在微信里正常看图（尤其是没看过的新图）时自动捕获，无需任何额外操作。")
        tip = QLabel(tip_text)
        tip.setProperty("muted", True)
        tip.setWordWrap(True)
        lay.addWidget(tip)
        return card

    def _build_export_card(self) -> QFrame:
        card = QFrame(objectName="card")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(12)

        title = QLabel("导出")
        title.setStyleSheet("font-weight:600;")
        lay.addWidget(title)

        form = QFormLayout()
        form.setSpacing(12)

        self.combo = QComboBox()
        self.combo.setMinimumWidth(320)
        form.addRow("会话", self.combo)

        fmt_row = QHBoxLayout()
        self.fmt_group = QButtonGroup(self)
        self.fmts = {}
        for f, label in (("json", "JSON（完整结构）"), ("csv", "CSV（表格）"),
                         ("html", "HTML（可读页面）")):
            rb = QRadioButton(label)
            self.fmt_group.addButton(rb)
            self.fmts[rb] = f
            fmt_row.addWidget(rb)
        self.fmt_group.buttons()[0].setChecked(True)
        fmt_row.addStretch(1)
        fw = QWidget()
        fw.setLayout(fmt_row)
        form.addRow("格式", fw)

        dir_row = QHBoxLayout()
        self.out_dir_edit = QLineEdit(str(Path.home() / "Desktop"))
        btn_dir = make_button("浏览…", "secondary")
        btn_dir.clicked.connect(self._browse_out_dir)
        dir_row.addWidget(self.out_dir_edit, 1)
        dir_row.addWidget(btn_dir)
        dw = QWidget()
        dw.setLayout(dir_row)
        form.addRow("输出目录", dw)

        self.media_check = QCheckBox("同时拷贝图片/视频/文件等到 media/ 子目录")
        form.addRow("媒体文件", self.media_check)

        lay.addLayout(form)

        row = QHBoxLayout()
        self.btn = QPushButton("开始导出")
        self.btn.clicked.connect(self.start_export)
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        row.addWidget(self.btn)
        row.addWidget(self.progress, 1)
        lay.addLayout(row)

        self.status = QLabel("")
        self.status.setProperty("muted", True)
        self.status.setWordWrap(True)
        lay.addWidget(self.status)
        return card

    # ---------- 设置 / 密钥：检测 ----------

    def refresh_pid(self):
        pid = detect_wechat_pid()
        if pid:
            self.pid_label.setText(f"✅ 运行中 (pid={pid})")
            self.pid_label.setStyleSheet(f"color:{ACCENT};")
        else:
            self.pid_label.setText("❌ 未检测到微信进程，请先启动并登录微信")
            self.pid_label.setStyleSheet("color:#E64545;")

    def refresh_dir(self):
        p = detect_db_storage()
        if p:
            self.dir_edit.setText(str(p))

    def _browse_db_dir(self):
        d = QFileDialog.getExistingDirectory(self, "选择 db_storage 目录",
                                             str(Path.home() / "Documents" / "xwechat_files"))
        if d:
            self.dir_edit.setText(d)

    def check_keys(self):
        if self._key_worker and self._key_worker.isRunning():
            return
        self.keys_label.setText("检测中…")
        self.keys_label.setStyleSheet("")
        self._key_worker = _KeyCheckWorker(self.dir_edit.text().strip())
        self._key_worker.done.connect(self._on_keys_checked)
        self._key_worker.start()

    def _on_keys_checked(self, text: str, kind: str):
        colors = {"ok": ACCENT, "warn": "#E6A23C", "err": "#E64545"}
        self.keys_label.setText(text)
        self.keys_label.setStyleSheet(f"color:{colors.get(kind, ACCENT)};")

    # ---------- 设置 / 密钥：提权执行 ----------

    def _sudo_run(self, args: list[str]):
        """需要 root 的子进程统一入口（GUI 入口已保证 root，这里直接执行）。"""
        if self._proc is not None:
            QMessageBox.information(self, "提示", "已有任务在运行")
            return
        self._direct_run(args)

    def _log(self, line: str):
        self.log.setVisible(True)
        self.log.appendPlainText(line)

    def _on_output(self):
        data = bytes(self._proc.readAllStandardOutput()).decode(errors="replace")
        for line in data.rstrip().splitlines():
            self._log(line)

    def _on_finished(self, code, _status):
        self._log(f"[退出码 {code}]")
        from wxwatch.gui import logbus
        logbus.log(f"执行结束（退出码 {code}）：wxwatch {' '.join(getattr(self, '_proc_args', []))}")
        self._proc = None
        self.check_keys()
        self.check_image_key()
        if code == 0:
            self.main.reload_backend()

    def extract_keys(self):
        ds = self.dir_edit.text().strip()
        if sys.platform == "win32":
            # Windows 无 sudo：权限检测与提取逻辑在 wxwatch.gui.privilege
            target = Path(ds) if ds else detect_db_storage()
            if target is None:
                QMessageBox.warning(self, "提示", "请先选择 db_storage 目录")
                return
            self._log("[*] Windows 进程内提取（需以管理员身份运行本程序）…")
            if extract_keys_gui(target, KEYS_FILE, self._log):
                self.check_keys()
                self.main.reload_backend()
            return
        args = ["extract-keys"]
        if ds:
            args += ["--db-storage", ds]
        self._sudo_run(args)

    def run_parse(self):
        self._direct_run(["parse"])  # parse 纯磁盘分析（GUI 入口已保证 root）

    def _direct_run(self, args: list[str]):
        if self._proc is not None:
            return
        from wxwatch.gui import logbus
        self._proc_args = args
        logbus.log(f"开始执行：wxwatch {' '.join(args)}")
        exe, argv = cli_invocation(args)
        self._proc = QProcess(self)
        self._proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._proc.readyReadStandardOutput.connect(self._on_output)
        self._proc.finished.connect(self._on_finished)
        self._proc.start(exe, argv)

    def check_image_key(self):
        from wxwatch.gui.backend import CONFIG_FILE
        has = False
        try:
            has = bool(json.loads(CONFIG_FILE.read_text()).get("image_key"))
        except Exception:
            pass
        if has:
            self.imgkey_label.setText("✅ 已提取（V2 图片可显示缩略图）")
            self.imgkey_label.setStyleSheet(f"color:{ACCENT};")
        elif self.main.imgkey_watch_running():
            self.imgkey_label.setText("🔄 自动抓取监听中（微信里看图时自动捕获，无需操作）")
            self.imgkey_label.setStyleSheet(f"color:{ACCENT};")
        else:
            self.imgkey_label.setText("❌ 未提取（看过的图走缓存可显示；未看过的需密钥）")
            self.imgkey_label.setStyleSheet("color:#E6A23C;")

    def extract_image_key(self):
        if sys.platform == "win32":
            QMessageBox.information(self, "提示", "图片密钥提取目前仅支持 Linux")
            return
        if self.main.backend and self.main.backend.image_key():
            QMessageBox.information(self, "提示", "图片密钥已获取，无需再次抓取")
            return
        if self.main.imgkey_watch_running():
            QMessageBox.information(self, "提示", "自动抓取已在后台监听中，正常使用微信看图即可")
            return
        if self.main.start_imgkey_watch():
            self.check_image_key()
            self._log("[*] 已启动图片密钥自动抓取守护（监听解码缓存，零操作）")
        else:
            self._log("[!] 守护启动失败（本功能仅 Linux 可用）")

    # ---------- 导出 ----------

    def _fill(self):
        b = self.main.backend
        if not b:
            return
        try:
            for s in b.sessions():
                self.combo.addItem(s.get("display_name") or s["username"],
                                   s["username"])
        except Exception:
            pass

    def _browse_out_dir(self):
        d = QFileDialog.getExistingDirectory(self, "选择输出目录", self.out_dir_edit.text())
        if d:
            self.out_dir_edit.setText(d)

    def start_export(self):
        b = self.main.backend
        talker = self.combo.currentData()
        if not b or not talker:
            self.status.setText("后端未就绪或未选择会话")
            return
        fmt = self.fmts[self.fmt_group.checkedButton()]
        name = self.combo.currentText().replace("/", "_")[:60]
        out_dir = Path(self.out_dir_edit.text())
        out_dir.mkdir(parents=True, exist_ok=True)
        self.btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.status.setText("导出中…")
        self._worker = _ExportWorker(b, talker, name, fmt, out_dir,
                                     self.media_check.isChecked())
        self._worker.done.connect(self._done)
        self._worker.start()

    def _done(self, out_path: str, count: int, extra: str):
        self.btn.setEnabled(True)
        self.progress.setVisible(False)
        if out_path:
            self.status.setText(f"✅ 已导出 {count} 条消息 {extra}\n→ {out_path}")
        else:
            self.status.setText(f"❌ {extra}")

    # ---------- 页面生命周期 ----------

    def on_show(self):
        self.refresh_pid()
        self.check_keys()
        self.check_image_key()
        if self.combo.count() == 0:
            self._fill()

    def on_backend_changed(self):
        self.combo.clear()
        self._fill()

    def on_close(self):
        if self._worker and self._worker.isRunning():
            self._worker.terminate()
        if self._key_worker and self._key_worker.isRunning():
            self._key_worker.terminate()
