# 参与贡献

## 环境

64 位 Python 3.11 或更新。macOS 用系统自带的 Tk。

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Windows 把 `source .venv/bin/activate` 换成 `.venv\Scripts\activate`。

Linux / Windows 要改图形界面时，再安装 `requirements.txt`（含 PySide6）。

## 提交前

- 测试使用临时数据库，不要把真实微信目录指进测试。
- 不要提交 `keys.json`、`config.json`、`output/`、`mirror/`、`decrypted/`、`.venv/`、`.idea/`。
- Issue 和 Pull Request 里不要贴密钥、数据库或聊天正文。

## 改动范围

macOS 导出在 `app.py`、`read_wechat_conversation.py`、`cccryptor_probe.py`。
Linux / Windows 的密钥、解密和界面在 `main.py` 和 `wxwatch/`。
一边的入口不要调用另一边：在 macOS 上 `python main.py` 会直接退出并提示改跑 `python app.py`。
