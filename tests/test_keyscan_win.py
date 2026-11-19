"""keyscan_win 的平台安全性与掩码解码测试。

覆盖：
- 非 Windows 上 import keyscan_win 不崩；调用 Win32 入口给出清晰平台错误
- 被固定异或掩码盖住的 x'<64hex key><32hex salt>' 能被扫描函数解开
- 明文 x'...' 不会被当成密钥
- 缩小小块大小制造跨块边界，验证重叠一整条记录的防漏逻辑
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wxwatch import keyscan, keyscan_win

KEY1, SALT1 = "ab" * 32, "cd" * 16
KEY2, SALT2 = "01" * 32, "ef" * 16
KEY3, SALT3 = "22" * 32, "33" * 16


def make_blob() -> bytes:
    # 两条记录用不同相位盖住。旁边放一条明文，扫描必须忽略它。
    s1 = keyscan.mask_cipher_blob(f"x'{KEY1}{SALT1}'".encode(), 0)
    s2 = keyscan.mask_cipher_blob(f"x'{KEY2}{SALT2}'".encode(), 17)
    plain = f"x'{KEY3}{SALT3}'".encode()
    assert len(s1) == 99  # x' + 96hex + '
    return b"\x00" * 37 + b"junk" + s1 + plain + b"\xff" * 91 + s2 + b"\x00" * 37


def fake_memory(data: bytes):
    """不碰 Win32 的 _ProcessMemory 实例：read_chunk 返回 data 的切片。"""
    mem = object.__new__(keyscan_win._ProcessMemory)
    mem.read_chunk = lambda addr, size: data[addr:addr + size]
    return mem


def _assert_straddle() -> None:
    # 记录横跨块边界。块长大于重叠，步长不会退化成 1。
    # 没有整条记录的重叠时，这条 99 字节记录会被切成两半。
    record = keyscan.mask_cipher_blob(f"x'{KEY1}{SALT1}'".encode(), 5)
    straddling = b"\x00" * 200 + record + b"\x00" * 40
    old_chunk = keyscan_win._CHUNK
    try:
        keyscan_win._CHUNK = 250
        got = fake_memory(straddling).scan([(0, len(straddling))])
        assert got == {bytes.fromhex(SALT1): bytes.fromhex(KEY1)}, f"跨块匹配丢失: {got}"
    finally:
        keyscan_win._CHUNK = old_chunk


def test_scan_chunk_accepts_key_without_embedded_salt() -> None:
    found: dict[bytes, bytes] = {}
    unbound: set[bytes] = set()
    keyscan._scan_chunk(keyscan.mask_cipher_blob(f"x'{KEY1}'".encode(), 31), found, unbound)
    assert found == {}
    assert unbound == {bytes.fromhex(KEY1)}
    keyscan._scan_chunk(keyscan.mask_cipher_blob(f"x'{KEY1}{SALT1}'".encode(), 8), found, unbound)
    assert found == {bytes.fromhex(SALT1): bytes.fromhex(KEY1)}


def test_scan_chunk_ignores_plaintext_record() -> None:
    found: dict[bytes, bytes] = {}
    unbound: set[bytes] = set()
    keyscan._scan_chunk(f"x'{KEY3}{SALT3}'".encode(), found, unbound)
    assert found == {}
    assert unbound == set()


def test_keyscan_win_matching() -> None:
    if sys.platform != "win32":
        # 平台门禁只在非 Windows 上有意义：Win32 入口应当拒绝，而不是 AttributeError。
        for fn in (keyscan_win.find_wechat_pids, keyscan_win.find_wechat_pid):
            try:
                fn()
                raise AssertionError(f"{fn.__name__} 在非 Windows 上应当抛 RuntimeError")
            except RuntimeError as exc:
                assert "Windows" in str(exc), exc
        try:
            keyscan_win._ProcessMemory(1234)
            raise AssertionError("_ProcessMemory 在非 Windows 上应当抛 RuntimeError")
        except RuntimeError as exc:
            assert "Windows" in str(exc), exc
    blob = make_blob()
    expect = {bytes.fromhex(SALT1): bytes.fromhex(KEY1),
              bytes.fromhex(SALT2): bytes.fromhex(KEY2)}
    found: dict[bytes, bytes] = {}
    keyscan._scan_chunk(blob, found)
    assert found == expect, found
    keyscan._scan_chunk(blob, found)
    assert len(found) == 2
    keyscan._scan_chunk(b"no key here", found)
    assert len(found) == 2
    assert bytes.fromhex(KEY3) not in found.values()
    assert fake_memory(blob).scan([(0, len(blob))]) == expect
    assert fake_memory(b"").scan([(0, 0)]) == {}
    assert fake_memory(blob).scan([]) == {}
    _assert_straddle()


def main():
    if sys.platform != "win32":
        # 平台门禁：非 Windows 上 import 成功，调 Win32 函数抛 RuntimeError 而非 AttributeError
        for fn in (keyscan_win.find_wechat_pids, keyscan_win.find_wechat_pid):
            try:
                fn()
                raise AssertionError(f"{fn.__name__} 在非 Windows 上应当抛 RuntimeError")
            except RuntimeError as exc:
                assert "Windows" in str(exc), exc
        try:
            keyscan_win._ProcessMemory(1234)
            raise AssertionError("_ProcessMemory 在非 Windows 上应当抛 RuntimeError")
        except RuntimeError as exc:
            assert "Windows" in str(exc), exc
        print("[PASS] 平台门禁（非 Windows import 安全 / Win32 调用报错清晰）")
    test_scan_chunk_accepts_key_without_embedded_salt()
    test_scan_chunk_ignores_plaintext_record()
    test_keyscan_win_matching()
    print("[PASS] 掩码解码、忽略明文、跨块重叠")
    print("\n全部测试通过 ✔")


if __name__ == "__main__":
    main()
