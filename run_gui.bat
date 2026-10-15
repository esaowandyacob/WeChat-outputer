@echo off
REM wxwatch GUI 启动脚本（Windows）—— 自动请求管理员权限，等价于 Linux 的 run_gui.sh
REM 读取微信进程内存（提取密钥）需要管理员身份运行。
cd /d "%~dp0"

REM 检查是否已是管理员；不是则用 PowerShell 自提权重启本脚本
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] 需要管理员权限，正在请求提权...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs -WorkingDirectory '%~dp0'"
    exit /b
)

REM 优先使用项目 venv 里的 Python
set "PY=.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

"%PY%" main.py gui %*
if %errorlevel% neq 0 pause
