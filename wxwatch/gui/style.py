"""GUI 样式：简洁专业的浅色主题（微信绿点缀）。"""

ACCENT = "#07C160"
ACCENT_DARK = "#06AD56"
BG = "#F5F6F7"
CARD = "#FFFFFF"
TEXT = "#1F2329"
SUBTEXT = "#8A8F99"
BORDER = "#E4E6EB"

STYLESHEET = f"""
* {{ font-family: "PingFang SC", "Noto Sans CJK SC", "Microsoft YaHei", sans-serif; }}
QMainWindow, QWidget {{ background: {BG}; color: {TEXT}; font-size: 13px; }}

#sidebar {{ background: #2B2D31; }}
#navList {{ background: transparent; border: none; outline: 0; }}
#navList::item {{ color: #C9CDD4; padding: 11px 18px; border-left: 3px solid transparent; }}
#navList::item:selected {{ color: #fff; background: #3A3D42; border-left: 3px solid {ACCENT}; }}
#navList::item:hover {{ color: #fff; }}

#header {{ background: {CARD}; border-bottom: 1px solid {BORDER}; }}
#headerTitle {{ font-size: 16px; font-weight: 600; padding: 12px 16px; }}
#headerStatus {{ color: {SUBTEXT}; padding-right: 16px; }}

QLineEdit, QComboBox, QDateEdit {{
  background: {CARD}; border: 1px solid {BORDER}; border-radius: 6px;
  padding: 7px 10px; selection-background-color: {ACCENT};
}}
QLineEdit:focus, QComboBox:focus {{ border: 1px solid {ACCENT}; }}
QComboBox QAbstractItemView {{ background: {CARD}; border: 1px solid {BORDER}; }}

QPushButton {{
  background: {ACCENT}; color: white; border: none; border-radius: 6px;
  padding: 8px 18px; font-weight: 500;
}}
QPushButton:hover {{ background: {ACCENT_DARK}; }}
QPushButton:disabled {{ background: #B7BCC4; }}
QPushButton[secondary="true"] {{
  background: {CARD}; color: {TEXT}; border: 1px solid {BORDER};
}}
QPushButton[secondary="true"]:hover {{ background: #F0F1F2; }}
QPushButton[danger="true"] {{ background: #E64545; }}

QTableWidget, QListWidget, QTableView {{
  background: {CARD}; border: 1px solid {BORDER}; border-radius: 8px;
  gridline-color: #F0F1F2; selection-background-color: #E8F7EE;
  selection-color: {TEXT}; alternate-background-color: #FAFBFC;
}}
QHeaderView::section {{
  background: #FAFBFC; border: none; border-bottom: 1px solid {BORDER};
  padding: 8px; color: {SUBTEXT}; font-weight: 500;
}}
QTableCornerButton::section {{ background: #FAFBFC; border: none; }}

#card {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 8px; }}
#statValue {{ font-size: 24px; font-weight: 600; color: {ACCENT}; }}
#statLabel {{ color: {SUBTEXT}; font-size: 12px; }}

QProgressBar {{
  background: #EDEFF2; border: none; border-radius: 4px; height: 8px; text-align: center;
}}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 4px; }}

QSplitter::handle {{ background: {BORDER}; width: 1px; }}
QRadioButton, QCheckBox {{ spacing: 6px; }}
QLabel[muted="true"] {{ color: {SUBTEXT}; }}
"""
