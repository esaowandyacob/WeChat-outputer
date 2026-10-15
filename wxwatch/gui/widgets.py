"""共享 UI 组件：头像、聊天气泡、统计卡片、条形图行。"""

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QColor, QDesktopServices, QPainter, QPainterPath, QPixmap
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QSizePolicy,
                               QVBoxLayout, QWidget)

from wxwatch.gui.backend import msg_preview

_AVATAR_COLORS = ["#07C160", "#3B82F6", "#F59E0B", "#EF4444", "#8B5CF6",
                  "#EC4899", "#14B8A6", "#F97316", "#6366F1", "#84CC16"]


class Avatar(QLabel):
    """圆形头像：名字首字符 + 稳定配色。"""

    def __init__(self, name: str, size: int = 36):
        super().__init__()
        self.setFixedSize(size, size)
        ch = (name or "?").strip()
        ch = ch[0].upper() if ch else "?"
        color = _AVATAR_COLORS[hash(name or "?") % len(_AVATAR_COLORS)]
        self.setText(ch)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(
            f"background:{color}; color:white; border-radius:{size//2}px;"
            f"font-weight:600; font-size:{size//2 - 4}px;")


_TYPE_META = {
    "text": ("文字", "#3B82F6"), "image": ("图片", "#F59E0B"),
    "video": ("视频", "#EF4444"), "voice": ("语音", "#14B8A6"),
    "emoji": ("表情", "#F97316"), "system": ("系统", "#8A8F99"),
    "voip": ("通话", "#8A8F99"), "location": ("位置", "#84CC16"),
    "card": ("名片", "#6366F1"), "pat": ("拍一拍", "#8A8F99"),
}


def type_meta(t: str) -> tuple[str, str]:
    """消息类型 → (中文名, 颜色)。"""
    if not t:
        return ("其他", "#8A8F99")
    if t.startswith("appmsg/"):
        sub = t.split("/", 1)[1]
        return {
            "file": ("文件", "#6366F1"), "link": ("链接", "#3B82F6"),
            "quote": ("引用", "#8B5CF6"), "miniapp": ("小程序", "#EC4899"),
            "chat_history": ("聊天记录", "#F59E0B"),
            "channels": ("视频号", "#EF4444"),
            "transfer": ("转账", "#F59E0B"), "redpacket": ("红包", "#EF4444"),
        }.get(sub, ("分享", "#3B82F6"))
    return _TYPE_META.get(t, (t, "#8A8F99"))


class TypeBadge(QLabel):
    def __init__(self, msg_type: str):
        name, color = type_meta(msg_type)
        super().__init__(name)
        self.setStyleSheet(
            f"color:{color}; background:{color}1A; border-radius:4px;"
            f"padding:1px 6px; font-size:11px;")


class BubbleMessage(QWidget):
    """聊天气泡：头像 + 名字 + 时间 + 内容气泡（我方右侧绿色）。

    图片/视频/表情消息：若加载线程已把解密后的预览路径放进 msg["_preview_path"]，
    则显示缩略图（视频带 ▶ 角标），点击用系统程序打开 msg["_open_path"]。
    backend 仅作签名保留（媒体解码在 worker 线程完成，UI 线程只加载 QPixmap）。
    """

    MAX_IMG_W = 240

    def __init__(self, msg: dict, show_sender: bool = True, backend=None):
        super().__init__()
        # Minimum: 布局不得压缩到 sizeHint 以下，保证 ScrollArea 出滚动条
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self._backend = backend
        sent = msg.get("direction") == "sent"
        name = msg.get("sender_name") or msg.get("talker_name") or "?"
        if sent:
            name = "我"

        outer = QHBoxLayout(self)
        outer.setContentsMargins(10, 4, 10, 4)
        outer.setSpacing(8)

        avatar = Avatar(name, 32)
        box = QVBoxLayout()
        box.setSpacing(2)
        meta = QLabel()
        meta_text = (f"{name} · {msg.get('time','')}" if show_sender
                     else msg.get("time", ""))
        meta.setText(meta_text)
        meta.setStyleSheet("color:#8A8F99; font-size:11px;")

        content = self._make_content(msg, sent)

        box.addWidget(meta, 0,
                      Qt.AlignmentFlag.AlignRight if sent else Qt.AlignmentFlag.AlignLeft)
        box.addWidget(content, 0,
                      Qt.AlignmentFlag.AlignRight if sent else Qt.AlignmentFlag.AlignLeft)

        if sent:
            outer.addLayout(box, 1)
            outer.addWidget(avatar, 0, Qt.AlignmentFlag.AlignTop)
        else:
            outer.addWidget(avatar, 0, Qt.AlignmentFlag.AlignTop)
            outer.addLayout(box, 1)

    # ---------- 内容 ----------

    def _make_content(self, msg: dict, sent: bool) -> QWidget:
        preview = msg.get("_preview_path")
        if preview:
            w = self._make_image(msg, preview)
            if w is not None:
                return w
        return self._make_text(msg, sent)

    def _make_text(self, msg: dict, sent: bool) -> QLabel:
        content = QLabel(msg_preview(msg, 400))
        content.setWordWrap(True)
        content.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        if sent:
            content.setStyleSheet(
                "background:#95EC69; color:#1F2329; border-radius:10px; padding:8px 12px;")
        else:
            content.setStyleSheet(
                "background:#FFFFFF; color:#1F2329; border-radius:10px; padding:8px 12px;"
                "border:1px solid #E4E6EB;")
        content.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        return content

    def _make_image(self, msg: dict, path: str) -> QLabel | None:
        pm = QPixmap(path)
        if pm.isNull():
            return None
        if pm.width() > self.MAX_IMG_W:
            pm = pm.scaledToWidth(self.MAX_IMG_W,
                                  Qt.TransformationMode.SmoothTransformation)
        lab = QLabel()
        lab.setPixmap(pm)
        lab.setFixedSize(pm.size())
        lab.setStyleSheet("background:#FFFFFF; border:1px solid #E4E6EB; border-radius:8px;")
        if msg.get("type") == "video":
            badge = QLabel("▶", lab)
            badge.setStyleSheet(
                "color:white; background:rgba(0,0,0,150); border-radius:11px;"
                "padding:2px 7px; font-size:12px;")
            badge.adjustSize()
            badge.move(pm.width() - badge.width() - 6, pm.height() - badge.height() - 6)
        open_path = msg.get("_open_path") or path
        lab.setToolTip(open_path)
        lab.setCursor(Qt.CursorShape.PointingHandCursor)
        lab.mousePressEvent = lambda _e, p=open_path: QDesktopServices.openUrl(
            QUrl.fromLocalFile(p))
        return lab


def make_table(headers: list[str]):
    from PySide6.QtWidgets import QHeaderView, QTableWidget

    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    t.verticalHeader().setVisible(False)
    t.setAlternatingRowColors(True)
    t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    return t


def make_button(text: str, kind: str | None = None):
    """创建按钮，kind: 'secondary' / 'danger' 样式变体。"""
    from PySide6.QtWidgets import QPushButton

    b = QPushButton(text)
    if kind:
        b.setProperty(kind, True)
    return b
