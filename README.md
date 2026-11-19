# 微信本地聊天记录工具

本机工具，面向微信 4.x。不上传聊天记录、数据库或密钥。

仓库：<https://github.com/esaowandyacob/WeChat-outputer>

| 系统 | 入口 | 能力 |
| --- | --- | --- |
| macOS | `python app.py` | DTrace 采集密钥，导出 HTML / 纯文本 / PDF / SQLite |
| Linux、Windows | `python main.py` | 从进程内存提取 SQLCipher 密钥，解析、监听、图形界面 |

不支持旧版 Windows 微信 3.x（`WeChat Files/<wxid>/Msg`）。

## 小白：macOS 从零跑起来

需要 64 位 Python 3.11 或更新。先看版本：

```bash
python3 --version
```

在项目目录里：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -r requirements-macos.txt
python -c "import tkinter, zstandard, sqlcipher3, Crypto, fpdf; print('依赖已就绪')"
python app.py
```

最后一行会打开标题为「微信聊天记录导出」的窗口。看到窗口就说明程序能跑。微信还没登录、还没采到密钥时，窗口里会提示下一步，这是正常的。

确认测试也通过：

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

不要在 macOS 上运行 `python main.py` 或 `./run_gui.sh`。前者会退出并告诉你改跑 `python app.py`，后者是 Linux 界面。

装不上依赖时：

- `python3` 若是 python.org 安装的 3.10，pip 可能报 `CERTIFICATE_VERIFY_FAILED`。双击 `/Applications/Python 3.10/Install Certificates.command`。仍然失败就改用 Python 3.12 或 3.13。
- 不要用 `requirements.txt` 当 macOS 的第一步。那个文件会再装 PySide6，体积大约 1GB，macOS 界面用不到。
- 窗口能开、但图片或视频是空的：密钥页点「一键设置依赖」，它会补 ffmpeg。只有文字导出时可以先不装。

## 安装

### macOS

用上面的 `requirements-macos.txt`。

### Linux、Windows

```bash
python -m venv .venv
```

```bash
# Linux
source .venv/bin/activate
python -m pip install -r requirements.txt
```

```bat
REM Windows
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

`environment.yml` 是可选的 conda 测试环境，不是小白路径。Linux / Windows 界面仍要再装 `requirements.txt`。

## macOS

1. 在“系统设置 → 隐私与安全性 → 完全磁盘访问权限”中给 Terminal 或 Python 授权。
2. DTrace 需要关闭 SIP：恢复模式终端执行 `csrutil disable` 后重启。程序不会改 SIP。
3. 启动并登录微信，然后运行 `python app.py`。
4. 点击“启动采集”。弹出密码框时输入一次开机密码，同一终端里短时间内会复用 sudo 缓存。60 秒内登录或打开几个会话。验证通过的密钥写入
   `~/Library/Application Support/WeChatExport/wechat_cccryptor_keys.json`。
5. 选择会话后导出。HTML 生成 `index.html` 和 `media/`，TXT 生成 `chat.txt`，
   PDF 生成 `chat.pdf`，SQLite 仅在点击“导出 SQLite”时生成 `chat.sqlite`。
   密钥页的“一键设置依赖”会安装缺失的 Python 包，并在没有 ffmpeg 时执行 `brew install ffmpeg`。

找不到数据库时，在界面选择数据目录，或设置 `WECHAT_DATA_ROOT`。

导出并发按本机 CPU 自动计算，不用再选线程或进程数。
单个会话把核数用于媒体解密和转码，最多 16 路。一次导出多个会话时，同时读取的会话不超过 4 个，
每个会话再分到剩余的媒体线程。媒体处理大部分时间在等 ffmpeg，所以用线程。
HEVC 视频转成 H.264、wxgf 图片转成 JPEG 的结果缓存在 `~/Library/Application Support/WeChatExport/media_cache/`，
再次导出同一会话时直接复用；占用空间过大时可以整个删掉。

图片和表情：

- V2 图片密钥由 `Documents/app_data/**/kvcomm/key_<code>_*.statistic` 里的 code 和 wxid 推导：
  `md5(code + wxid)` 前 16 位十六进制字符为 AES 密钥，`code & 0xFF` 为尾段 XOR 密钥。导出时自动推导并写入
  `config.json`，也可以点“采集图片密钥”。推导结果会先用本地图片验证。
- 部分图片是微信的 `wxgf`（HEVC）格式，语音 SILK 和 HEVC 视频也需要 ffmpeg。
  密钥页“一键设置依赖”会安装它。从 Finder 启动时，还会查找 `/opt/homebrew/bin`、`/usr/local/bin` 和 `/opt/local/bin`。
- 本地表情缓存用的是另一把未公开的密钥。导出时按消息里的 `cdnurl` / `encrypturl` 从微信 CDN
  下载表情，缓存到 `~/Library/Application Support/WeChatExport/emoji_cache/`。只请求 `*.qq.com`、
  `*.qpic.cn` 地址。不想联网时设置 `WECHAT_EXPORT_OFFLINE=1`，表情只显示 `[表情]`。

## Linux / Windows

密钥按各库文件头 salt 在进程内存里匹配，并用 page-1 HMAC 校验。Linux 读
`/proc/<pid>/mem`，Windows 对 `Weixin.exe` 调用 `ReadProcessMemory`。

```bash
# Linux：提取密钥需要 root
sudo .venv/bin/python main.py extract-keys
.venv/bin/python main.py status
.venv/bin/python main.py parse
.venv/bin/python main.py watch
./run_gui.sh
```

```bat
REM Windows：提取密钥需要管理员
.venv\Scripts\python.exe main.py extract-keys
.venv\Scripts\python.exe main.py status
run_gui.bat
```

常用子命令：`extract-keys`、`status`、`parse`、`watch`、`gui`、`decrypt`、
`collect-media`、`extract-image-key`（图片密钥目前仅 Linux）。

数据目录默认是 `~/Documents/xwechat_files/wxid_*/db_storage`。
`keys.json`、`output/`、`mirror/`、`decrypted/` 在程序目录，里面是明文聊天，不要提交。

实时预览仅维护内存游标，不读写命令行导出的进度文件。命令行每会话 JSONL 文件名固定为
`会话名__会话ID的完整MD5.jsonl`，避免同名会话在重启后混写。旧版本生成的文件原样保留，
后续增量消息写入新命名文件；不会自动合并或修复旧文件中已经混入的消息。

Windows 上若 `sqlcipher3` 轮子不可用，打包时改用 SQLCipher 版 `sqlite3.dll`，
`wxwatch.decryptor` 会回退到标准库 `sqlite3`。单文件构建：

```bash
pip install pyinstaller
pyinstaller --noconfirm wxwatch.spec
```

## 开发检查

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

测试使用临时数据库，不会读取真实微信数据。2026-11-19 在一台新的 Python 3.13 虚拟环境里，只装 `requirements-dev.txt`（没有 PySide6），49 项测试通过，隐藏窗口能创建，依赖检查显示「依赖已就绪」（本机已有 ffmpeg）。

参与改动见 [CONTRIBUTING.md](CONTRIBUTING.md)。不要把密钥和聊天记录提交上来，说明见 [SECURITY.md](SECURITY.md)。
