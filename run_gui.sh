#!/usr/bin/env bash
# wxwatch GUI 启动脚本（自动提权，全程免应用内密码）
# 解决 PySide6 自带 Qt 与系统 Qt 库冲突（libQt6DBus 符号错误）
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
