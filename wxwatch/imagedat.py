"""微信 4.x 图片 .dat 解密：老 XOR / V1 / V2 三种格式。

V2 结构（实测）：[6B 签名 07 08 V2 08 07][4B aes_size LE][4B xor_size LE][1B pad]
                [aes_size 字节 AES-128-ECB][xor_size 字节 单字节 XOR][16B 尾部]
V1 相同结构，固定密钥 cfcd208495d565ef；V2 密钥需从进程内存提取（find_image_key）。
老 XOR：整个文件与单字节异或。
"""

from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
from pathlib import Path

# 调用方可设置一个目录缓存 wxgf 转码结果。ffmpeg 每张要几十毫秒，重复导出时直接复用。
CONVERT_CACHE_DIR: Path | None = None

V1_KEY = b"cfcd208495d565ef"
V1_MAGIC = b"\x07\x08V1\x08\x07"
V2_MAGIC = b"\x07\x08V2\x08\x07"


def parse_image_key(s) -> bytes | None:
    """image_key 统一解析。

    参考实现确认 V2 key 是 16/32 字符的 ASCII 字符串（直接用其字节作 AES key），
    因此字符串一律按 ASCII 编码；仅对明显是 hex 记录的（全 hex 且 32/64 长）
    做 fromhex 兼容。注意纯 hex 字符的 ASCII key 恰好 16 字符时不受影响。
    """
    import re as _re

    if s is None:
        return None
    if isinstance(s, bytes):
        return s
    s = str(s).strip()
    if not s:
        return None
    if _re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{64}", s):
        # 歧义：可能是 hex 记录（旧版 C 扫描器产出），也可能是纯 hex 字符的 ASCII key。
        # 旧记录是 16 字节密钥的 hex（32 字符）；ASCII key 为 16/32 字符。
        # 32 字符全 hex 时两种解释冲突，优先 ASCII（参考实现的形态）。
        if len(s) == 32:
            return s.encode("ascii")
        return bytes.fromhex(s)
    return s.encode("ascii", errors="ignore") or None

_MAGICS = [
    b"\xff\xd8\xff",          # JPEG
    b"\x89PNG\r\n\x1a\n",     # PNG
    b"GIF8",                  # GIF
    b"RIFF",                  # WEBP
    b"BM",                    # BMP
]


def _looks_image(data: bytes) -> bool:
    return any(data.startswith(m) for m in _MAGICS)


def _xor_single(data: bytes, k: int) -> bytes:
    return bytes(b ^ k for b in data)


def _decode_xor(data: bytes) -> bytes | None:
    """老格式：全文单字节 XOR，暴破 key。"""
    for k in range(256):
        if _looks_image(_xor_single(data[:16], k)):
            return _xor_single(data, k)
    return None


def _decode_v12(data: bytes, key: bytes, xor_key: int | None = None) -> bytes | None:
    from Crypto.Cipher import AES
    from Crypto.Util import Padding

    if len(data) < 31:
        return None
    aes_size, xor_size = struct.unpack("<II", data[6:14])
    # 密文长度 = aes_size 向上对齐到 16；恰为倍数时再加一个完整填充块（PKCS#7）
    aligned = aes_size + (16 - aes_size % 16)
    offset = 15
    if offset + aligned > len(data):
        return None
    try:
        dec_aes = Padding.unpad(
            AES.new(key[:16], AES.MODE_ECB).decrypt(data[offset:offset + aligned]),
            AES.block_size)
    except (ValueError, KeyError):
        return None
    if not _looks_image(dec_aes) and dec_aes[:4] != b"wxgf":
        return None
    offset += aligned
    # 中段 raw（不加密），末尾 xor_size 字节单字节 XOR。
    # XOR key 因账号而异（macOS 上等于 kvcomm code 的低 8 位）。没给时按 JPEG 结尾 FF D9 反推。
    raw_end = len(data) - xor_size
    raw_data = data[offset:raw_end] if offset < raw_end else b""
    xor_seg = data[raw_end:]
    if xor_key is None:
        xor_key = 0x88
        if xor_seg and dec_aes[:2] == b"\xff\xd8":
            xor_key = xor_seg[-1] ^ 0xD9
    dec_xor = bytes(b ^ xor_key for b in xor_seg)
    return dec_aes + raw_data + dec_xor


def _ffmpeg_path() -> str | None:
    found = shutil.which("ffmpeg")
    if found:
        return found
    # 从 Finder 或 IDE 启动时 PATH 里通常没有 Homebrew / MacPorts 目录。
    for folder in ("/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin"):
        candidate = Path(folder) / "ffmpeg"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def wxgf_to_jpeg(data: bytes) -> bytes | None:
    """wxgf 是微信的 HEVC 封装，浏览器不能显示。用 ffmpeg 取第一帧转成 JPEG。"""
    if not data.startswith(b"wxgf"):
        return None
    # 码流从 VPS（NAL 头 40 01）开始。头部可能带 ICC 色彩配置，里面会出现假的起始码。
    start = data.find(b"\x00\x00\x00\x01\x40\x01")
    if start < 0:
        start = data.find(b"\x00\x00\x00\x01")
    ffmpeg = _ffmpeg_path()
    if start < 0 or ffmpeg is None:
        return None
    cached: Path | None = None
    if CONVERT_CACHE_DIR is not None:
        import hashlib

        cached = Path(CONVERT_CACHE_DIR) / f"wxgf_{hashlib.sha256(data).hexdigest()}.jpg"
        try:
            return cached.read_bytes()
        except OSError:
            pass
    try:
        completed = subprocess.run(
            [ffmpeg, "-loglevel", "error", "-f", "hevc", "-i", "-", "-frames:v", "1",
             "-f", "image2", "-c:v", "mjpeg", "-q:v", "2", "-"],
            input=data[start:],
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if not completed.stdout.startswith(b"\xff\xd8"):
        return None
    if cached is not None:
        _write_atomic(cached, completed.stdout)
    return completed.stdout


def _write_atomic(path: Path, data: bytes) -> None:
    """并行导出时多个线程可能写同一个缓存文件，先写临时文件再改名。"""
    import tempfile

    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
            handle.write(data)
        os.replace(handle.name, path)
    except OSError:
        pass


def load_image_keys(config_path: str | Path) -> tuple[bytes | None, int | None]:
    """从 config.json 读取 V2 图片的 AES 密钥和尾段 XOR 密钥。"""
    try:
        cfg = json.loads(Path(config_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, None
    xor_key = cfg.get("image_xor_key")
    if not isinstance(xor_key, int) or not 0 <= xor_key <= 0xFF:
        xor_key = None
    return parse_image_key(cfg.get("image_key")), xor_key


def decode_dat(path: str | Path, image_key: bytes | None = None, xor_key: int | None = None) -> bytes | None:
    """解密 .dat 图片，返回图片字节；wxgf 会转成 JPEG。失败返回 None。"""
    try:
        data = open(path, "rb").read()
    except OSError:
        return None
    if not data:
        return None
    if _looks_image(data):
        return data  # 未加密
    if data[:6] == V1_MAGIC:
        decoded = _decode_v12(data, V1_KEY, xor_key)
    elif data[:6] == V2_MAGIC:
        if image_key is None:
            return None
        decoded = _decode_v12(data, image_key, xor_key)
    else:
        return _decode_xor(data)
    if decoded is not None and decoded.startswith(b"wxgf"):
        return wxgf_to_jpeg(decoded)
    return decoded
