"""keyscan_win 的平台安全性与匹配逻辑测试（Linux 上运行，mock 掉 Win32 内存读取）。

覆盖：
- Linux 上 import keyscan_win 不崩；调用 Win32 入口给出清晰平台错误而非 AttributeError
- 含 x'<64hex key><32hex salt>' 的字节串能被扫描函数正确提取（共享 _scan_chunk）
- 缩小小块大小制造跨块边界，验证重叠 100 字节的防漏逻辑
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wxwatch import keyscan, keyscan_win

KEY1, SALT1 = "ab" * 32, "cd" * 16
KEY2, SALT2 = "01" * 32, "ef" * 16


def make_blob() -> bytes:
    s1 = f"x'{KEY1}{SALT1}'".encode()
    s2 = f"x'{KEY2}{SALT2}'".encode()
    assert len(s1) == 99  # x' + 96hex + '
    return b"\x00" * 37 + b"junk" + s1 + b"\xff" * 91 + s2 + b"\x00" * 37


def fake_memory(data: bytes):
    """不碰 Win32 的 _ProcessMemory 实例：read_chunk 返回 data 的切片。"""
    mem = object.__new__(keyscan_win._ProcessMemory)
    mem.read_chunk = lambda addr, size: data[addr:addr + size]
    return mem


def main():
    # 1) 平台门禁：Linux 上 import 成功，调 Win32 函数抛 RuntimeError 而非 AttributeError
    for fn in (keyscan_win.find_wechat_pids, keyscan_win.find_wechat_pid):
        try:
            fn()
            raise AssertionError(f"{fn.__name__} 在 Linux 上应当抛 RuntimeError")
        except RuntimeError as e:
            assert "Windows" in str(e), e
    try:
        keyscan_win._ProcessMemory(1234)
        raise AssertionError("_ProcessMemory 在 Linux 上应当抛 RuntimeError")
    except RuntimeError as e:
        assert "Windows" in str(e), e
    print("[PASS] 平台门禁（Linux import 安全 / Win32 调用报错清晰）")

    blob = make_blob()
    expect = {bytes.fromhex(SALT1): bytes.fromhex(KEY1),
              bytes.fromhex(SALT2): bytes.fromhex(KEY2)}

    # 2) 共享匹配函数：提取 + setdefault 去重
    found: dict[bytes, bytes] = {}
    keyscan._scan_chunk(blob, found)
    assert found == expect, found
    keyscan._scan_chunk(blob, found)
    assert len(found) == 2
    keyscan._scan_chunk(b"no key here", found)  # 无匹配不炸
    assert len(found) == 2
    print("[PASS] _scan_chunk 匹配 + 去重")

    # 3) 模拟 ReadProcessMemory 扫描单个区域
    assert fake_memory(blob).scan([(0, len(blob))]) == expect
    assert fake_memory(b"").scan([(0, 0)]) == {}
    assert fake_memory(blob).scan([]) == {}
    print("[PASS] scan 区域扫描（含空区域）")

    # 4) 缩小小块制造跨块边界：块 150 字节 > 密钥串 99 字节，
    #    重叠 100 字节保证任何 99 字节串都完整落在某一块内
    old_chunk = keyscan_win._CHUNK
    try:
        keyscan_win._CHUNK = 150
        got = fake_memory(blob).scan([(0, len(blob))])
        assert got == expect, f"跨块匹配丢失: {got}"
    finally:
        keyscan_win._CHUNK = old_chunk
    print("[PASS] 跨块边界（重叠 100 字节）不丢匹配")

    print("\n全部测试通过 ✔")


def test_keyscan_win_matching() -> None:
    main()


if __name__ == "__main__":
    main()
