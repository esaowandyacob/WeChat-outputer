"""微信 4.x 图片 .dat 解密：老 XOR / V1 / V2 三种格式。

V2 结构（实测）：[6B 签名 07 08 V2 08 07][4B aes_size LE][4B xor_size LE][1B pad]
                [aes_size 字节 AES-128-ECB][xor_size 字节 单字节 XOR][16B 尾部]
V1 相同结构，固定密钥 cfcd208495d565ef；V2 密钥需从进程内存提取（find_image_key）。
老 XOR：整个文件与单字节异或。
"""

from __future__ import annotations

import struct
from pathlib import Path

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


def _decode_v12(data: bytes, key: bytes) -> bytes | None:
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
    # 中段 raw（不加密），末尾 xor_size 字节单字节 XOR
    # key 本机实测为 0x8b（参考实现默认 0x88），按 JPEG 尾部特征自动校正
    raw_end = len(data) - xor_size
    raw_data = data[offset:raw_end] if offset < raw_end else b""
    xor_seg = data[raw_end:]
    xor_key = 0x8B
    if xor_seg and dec_aes[:2] == b"\xff\xd8":
        # JPEG 应以 FF D9 结尾；若不匹配则尝试其他常见 key
        for cand in (0x8B, 0x88):
            if (xor_seg[-1] ^ cand) == 0xD9:
                xor_key = cand
                break
    dec_xor = bytes(b ^ xor_key for b in xor_seg)
    return dec_aes + raw_data + dec_xor


def decode_dat(path: str | Path, image_key: bytes | None = None) -> bytes | None:
    """解密 .dat 图片，返回图片字节；失败返回 None。"""
    try:
        data = open(path, "rb").read()
    except OSError:
        return None
    if not data:
        return None
    if _looks_image(data):
        return data  # 未加密
    if data[:6] == V1_MAGIC:
        return _decode_v12(data, V1_KEY)
    if data[:6] == V2_MAGIC:
        if image_key is None:
            return None
        return _decode_v12(data, image_key)
    return _decode_xor(data)
