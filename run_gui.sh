#!/usr/bin/env bash
# Linux 上的 PySide6 界面。自动提权，并避开系统 Qt 与 PySide6 的库冲突。
# macOS 导出界面是 python app.py，不要跑这个脚本。
if [ "$(uname -s)" = "Darwin" ]; then
  echo "macOS 请在项目目录运行: python app.py"
  echo "run_gui.sh 只启动 Linux 上的界面。"
  exit 1
fi
cd "$(dirname "$(readlink -f "$0")")"
QT_LIB=$(dirname "$(find .venv -name 'libQt6Core.so.6' | head -1)")
export LD_LIBRARY_PATH="$QT_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
if [ "$(id -u)" -ne 0 ]; then
  # 非 root：自动 sudo 提权（终端里输一次密码），并带上 X11 显示授权
  exec sudo env DISPLAY="${DISPLAY:-:0}" \
       XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
       LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
       .venv/bin/python main.py gui "$@"
fi
# 已是 root（sudo 直启）：补真实用户的 X11 授权
if [ -n "$SUDO_USER" ]; then
  export XAUTHORITY="${XAUTHORITY:-/home/$SUDO_USER/.Xauthority}"
fi
exec .venv/bin/python main.py gui "$@"
