"""运行日志总线：全局环形缓冲 + Qt 信号，供「运行日志」页订阅。

任何模块（含工作线程）都可调用 log()；信号按 Qt 队列连接投递到 GUI 线程。
"""

import time
from collections import deque

from PySide6.QtCore import QObject, Signal

_MAX = 2000


class _LogBus(QObject):
    appended = Signal(str)


BUS = _LogBus()
_BUFFER: deque[str] = deque(maxlen=_MAX)


def log(msg: str):
    line = f"{time.strftime('%H:%M:%S')}  {msg}"
    _BUFFER.append(line)
    BUS.appended.emit(line)


def history() -> list[str]:
    return list(_BUFFER)


def clear():
    _BUFFER.clear()
