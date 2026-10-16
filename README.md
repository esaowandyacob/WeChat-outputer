# 微信本地聊天记录工具

本机工具，面向微信 4.x。不上传聊天记录、数据库或密钥。

| 系统 | 入口 | 能力 |
| --- | --- | --- |
| macOS | `python app.py` | DTrace 采集密钥，导出 HTML / 纯文本 / SQLite |
| Linux、Windows | `python main.py` | 从进程内存提取 SQLCipher 密钥，解析、监听、图形界面 |

不支持旧版 Windows 微信 3.x（`WeChat Files/<wxid>/Msg`）。

## 安装

需要 64 位 Python 3.10+。

```bash
python -m venv .venv
```

```bash
# macOS / Linux
source .venv/bin/activate
python -m pip install -r requirements.txt
```

```bat
REM Windows
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

已有 conda 环境时：

```bash
conda activate wechat_sqlite
python -m pip install -r requirements.txt
```

## macOS

1. 在“系统设置 → 隐私与安全性 → 完全磁盘访问权限”中给 Terminal 或 Python 授权。
2. DTrace 需要关闭 SIP：恢复模式终端执行 `csrutil disable` 后重启。程序不会改 SIP。
3. 启动并登录微信，然后运行 `python app.py`。
4. 点击“启动采集”。弹出密码框时输入一次开机密码，同一终端里短时间内会复用 sudo 缓存。60 秒内登录或打开几个会话。验证通过的密钥写入
   `~/Library/Application Support/WeChatExport/wechat_cccryptor_keys.json`。
5. 选择会话后导出。HTML 生成 `index.html` 和 `media/`，纯文本生成 `chat.txt`，
   SQLite 仅在点击“导出 SQLite”时生成 `chat.sqlite`。

找不到数据库时，在界面选择数据目录，或设置 `WECHAT_DATA_ROOT`。

导出时“并发方式”控制媒体解密和转码：多线程（默认，上限 16）、多进程（上限为 CPU 核数，最多 8）、单线程。
HEVC 视频转成 H.264、wxgf 图片转成 JPEG 的结果缓存在 `~/Library/Application Support/WeChatExport/media_cache/`，
再次导出同一会话时直接复用；占用空间过大时可以整个删掉。

图片和表情：

- V2 图片密钥由 `Documents/app_data/**/kvcomm/key_<code>_*.statistic` 里的 code 和 wxid 推导：
  `md5(code + wxid)` 前 16 位十六进制字符为 AES 密钥，`code & 0xFF` 为尾段 XOR 密钥。导出时自动推导并写入
  `config.json`，也可以点“采集图片密钥”。推导结果会先用本地图片验证。
- 部分图片是微信的 `wxgf`（HEVC）格式，需要 `ffmpeg` 转成 JPEG：`brew install ffmpeg`。
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

测试使用临时数据库，不会读取真实微信数据。
