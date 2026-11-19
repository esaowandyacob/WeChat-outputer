# 安全

这个工具只在本机读微信 4.x 的数据库和进程内存。它不上传聊天记录、数据库或密钥。

请不要把下面这些发到 Issue、Pull Request、聊天或截图里：

- `keys.json`、`config.json`、`wechat_cccryptor_keys.json`
- 解密后的数据库、`output/`、`mirror/`、`decrypted/`、导出的 HTML / PDF / SQLite
- 微信账号目录名以外的消息正文

密钥在微信重启后会变。如果曾经把密钥文件提交过，先把该文件从仓库删掉，再重启微信重新提取。已经推到公开历史里的内容，删掉最新提交清不掉，需要另做历史清理。

发现项目自身的漏洞时，用 GitHub 的 [Security Advisories](https://github.com/esaowandyacob/WeChat-outputer/security/advisories/new) 私下报告，不要开公开 Issue 贴利用细节和本机数据。
