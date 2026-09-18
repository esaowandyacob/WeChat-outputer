# 微信本地聊天记录导出工具

这是一个仅在本机运行的 Tkinter 工具，面向 **微信 4.x**（macOS 与 Windows）。
已按 4.1.x 的 `xwechat_files/<账号>/db_storage` 布局实现。它不会上传聊天
记录、数据库或密钥，也不会调用网络 API。

不支持旧版 Windows 微信 3.x（`WeChat Files/<wxid>/Msg`）。

## 功能

- 检测微信进程和版本。macOS 额外检测 SIP；Windows 检测能否读取进程内存。
- **macOS**：通过 `sudo dtrace` 监听 `CCCryptorCreate`，只接受 AES（`arg1 == 0`）和
  32 字节 key（`arg4 == 32`）。候选 key 会立即用 SQLCipher 验证。
- **Windows**：只读扫描 `Weixin.exe` 进程内存中的 WCDB 密钥文本
  （`x'<64 hex>'` 或带 salt 的 96 hex），验证成功才保存。
- 只扫描 `message_0.db`、`message_1.db` …；读取前复制主库以及可用的
  `-wal`/`-shm`，不会改写微信原始文件。
- 运行时探测 `Msg_<md5>`、`SessionTable`、`contact`、`VoiceInfo` 等表，
  解析文本、Zstd 文本、图片/视频/表情/文件/位置/名片、appmsg 链接、
  引用和系统消息。
- 在 Python 内存中建立统一模型，支持 HTML、纯文本和用户明确选择的
  SQLite 导出。规范化模型本身不是落盘 SQLite。

## 安装与启动

macOS 和 Windows 使用同一份依赖。需要 **64 位 Python 3.10+**（推荐 3.12 或 3.14）。
32 位 Python 无法读取 64 位 `Weixin.exe` 的进程内存。`sqlcipher3` 已包含预编译
wheel，不必再装 brew / conda 的 SQLCipher。

**pip / venv（两边通用）**

```bash
python -m venv .venv
```

```bash
# macOS / Linux
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

```bat
REM Windows
.venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py
```

**conda（两边通用）**

```bash
conda env create -f environment.yml
conda activate wechat_sqlite
python app.py
```

已有 conda 环境时，也可以只装依赖：

```bash
conda activate wechat_sqlite
python -m pip install -r requirements.txt
```

开发测试再加：

```bash
python -m pip install -r requirements-dev.txt
```

Windows 若采集时提示无法读取进程内存，请用“以管理员身份运行”的终端再启动。

静态扫内存拿不到 key 时（微信 4.1.x 常见），用动态下断。默认走 Windows 调试器硬件断点，**不注入 DLL**（Frida 的 `frida-agent.dll` 会让微信崩溃）：

```bat
python windows_key_hook.py
```

管理员运行。附加成功后在微信里登录或打开几个会话。命中并通过 HMAC 的密钥写入 `%APPDATA%\WeChatExport\wechat_cccryptor_keys.json`。日志在同目录 `last_key_hook.txt`。Ctrl+C 结束，默认不会杀掉微信。

程序只把完整 key 写入：

```text
macOS:    ~/Library/Application Support/WeChatExport/wechat_cccryptor_keys.json
Windows:  %APPDATA%\WeChatExport\wechat_cccryptor_keys.json
```

该文件由工具原子写入；在 Unix 权限可用时设置为 `0600`。界面和错误信息只显示前 8 位、后
8 位，中间为 `***`。重置按钮只删除带有 `WeChatExport` 标记的工具文件；
默认路径上的早期无标记文件仅作为兼容格式处理。

## 第一次使用

### 共同步骤

1. 启动并登录 **微信 4.x**。Windows 主进程名为 `Weixin.exe`。
2. 点击“启动采集”。每个候选 key 会先验证 `sqlite_master`，验证成功才保存。
3. 进入会话选择，选择会话、可选填写最近天数并选择导出目录。
4. 导出前会二次确认。HTML 生成 `index.html`、`manifest.json` 和同目录
   `media/`；纯文本生成 `chat.txt`；SQLite 仅在点击“导出 SQLite”时生成
   `chat.sqlite`。

若自动找不到数据库，可在第一步选择“微信数据目录”，或设置环境变量
`WECHAT_DATA_ROOT` 指向 `xwechat_files`（或其上级目录）。

### macOS 额外准备

1. 在“系统设置 → 隐私与安全性 → 完全磁盘访问权限”中，给运行本工具的
   Terminal/Python 授权；否则容器目录或 DTrace 可能被 macOS TCC 拒绝。
2. 在恢复模式的“终端”执行 `csrutil disable`，重启后回到程序刷新。
   关闭 SIP 会降低 macOS 系统安全性；程序不会自动关闭 SIP，导出完成后可在恢复模式执行
   `csrutil enable` 自行重新启用。
3. 若从 Finder 启动导致 `sudo` 没有可用终端，请先在“终端”执行一次
   `sudo -v`，或从终端运行 `python app.py`。
4. 点击“启动采集”后，在 60 秒内登录微信或打开几个会话。

### Windows 额外准备

1. 使用微信 4.x（设置里可查看版本）。数据目录默认为
   `%USERPROFILE%\Documents\xwechat_files\<账号>\db_storage`，
   也可在微信「设置 → 文件管理」中查看或修改。
2. 保持微信已登录后再采集。程序只读进程内存，不会注入 DLL、也不会改微信文件。
3. 若 OpenProcess 被拒绝，以管理员身份重新运行本工具。

## 隐私和权限边界

- 数据库副本在系统临时目录中使用完即删除；不会写入 key 文件或导出目录。
- `media.data` 只包含用户选择导出的媒体。HTML 链接仅接受 `http/https`，
  正文始终 HTML 转义。
- macOS TCC、微信代码签名和 SIP 可能阻止 DTrace `task_for_pid`。Windows
  的进程保护可能阻止 `ReadProcessMemory`。这类拒绝会显示为采集失败，
  不会尝试绕过系统保护。
- 不要把导出目录放在 key 文件所在目录；GUI 会拒绝这种配置。

## 已知限制

- 微信 4.x 数据库使用 SQLCipher 4 参数（通常 page size 4096、
  PBKDF2-HMAC-SHA512 迭代 256000、reserve 80）。微信升级或不同账号可能
  改变表列名；读取器会探测列名，但无法保证未知 schema 的全部字段都能还原。
- 加密库依赖 `requirements.txt` 里的 `sqlcipher3`（预编译 wheel）。系统自带
  `sqlite3` 只能读取测试用的明文副本，不能打开加密库。
- VoiceInfo 中常见的是 `0x02#!SILK_V3`。若安装 `pysilk` 或可处理 SILK
  的 `ffmpeg`，会尝试转换为 WAV 并在 HTML 使用 `<audio controls>`；无法
  解码时保留 SILK/二进制并显示 `[语音不可播放]`。微信加密 `.dat` 图片、
  未在数据库中留下本地路径的附件只显示占位符。
- macOS 的 DTrace 只能捕获采集期间实际经过 `CCCryptorCreate` 的 key。
  Windows 内存扫描只能找到当前仍留在进程中的密钥文本；微信长时间运行后
  可能清掉内存中的 key，此时请重新登录后再采集。
- 已保存 key 与本次运行候选分开显示。不同数据库可能使用不同 key，程序按分片逐个
  验证。
- 程序只针对当前登录用户自己的数据路径，不扫描其他用户或远程主机。

## 开发检查

```bash
python -m py_compile app.py cccryptor_probe.py read_wechat_conversation.py windows_memory_probe.py
python -m pytest -q
```

测试使用临时明文 SQLite fixture，不会访问真实微信数据。
