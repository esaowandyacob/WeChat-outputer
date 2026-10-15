#!/usr/bin/env python3
"""wxwatch - 微信 4.x (Linux / Windows) 消息解析与文件变化监听工具

用法（Linux；Windows 见 README「Windows 使用」，命令一致、无需 sudo 但要管理员终端）：
  sudo .venv/bin/python main.py extract-keys   # 一次性：从进程内存提取密钥（需 root）
  .venv/bin/python main.py decrypt             # 全量解密所有数据库到 decrypted/
  .venv/bin/python main.py schema-dump         # 导出各库表结构（调试用）
  .venv/bin/python main.py parse               # 一次性全量解析到 output/
  .venv/bin/python main.py watch               # 常驻监听文件变化，增量解析
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

PROJECT = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) \
    else Path(__file__).resolve().parent
KEYS_FILE = PROJECT / "keys.json"
MIRROR_DIR = PROJECT / "mirror"
OUTPUT_DIR = PROJECT / "output"
DECRYPTED_DIR = PROJECT / "decrypted"


def find_db_storage() -> Path:
    if sys.platform == "win32":
        home = Path.home()
    else:
        import pwd

        user = os.environ.get("SUDO_USER") or os.environ.get("USER") or ""
        home = Path(pwd.getpwnam(user).pw_dir) if user else Path.home()
    root = home / "Documents" / "xwechat_files"
    candidates = sorted(root.glob("wxid_*_*/db_storage")) + \
        sorted(p for p in root.glob("*/db_storage") if p.parent.name.startswith("wxid_"))
    if not candidates:
        sys.exit(f"[ERR] 未在 {root} 下找到 wxid_*/db_storage，请确认微信已登录过")
    return candidates[0]


def _keyscan_module():
    """按平台返回密钥扫描模块（两个模块在对方平台上均可安全 import）。"""
    if sys.platform == "win32":
        from wxwatch import keyscan_win
        return keyscan_win
    from wxwatch import keyscan
    return keyscan


def load_keys() -> dict:
    if not KEYS_FILE.exists():
        sys.exit("[ERR] 缺少 keys.json。先运行: sudo .venv/bin/python main.py extract-keys")
    return json.loads(KEYS_FILE.read_text())


def make_decryptor(keys: dict):
    from wxwatch.decryptor import Decryptor

    dec = Decryptor(find_db_storage(), keys, MIRROR_DIR)
    # 验证密钥仍然有效（微信重启后密钥会变化）
    probe = next((r for r in keys if r.startswith("message/message_")), None) \
        or next(iter(keys), None)
    if probe and not dec.sanity_check(probe):
        sys.exit(f"[ERR] 密钥验证失败（{probe}）。微信可能已重启，"
                 "请重新运行: sudo .venv/bin/python main.py extract-keys")
    return dec


def cmd_extract_keys(args):
    if sys.platform == "win32":
        import ctypes

        if not ctypes.windll.shell32.IsUserAnAdmin():
            sys.exit("[ERR] 读取进程内存需要管理员权限。\n"
                     "      请右键「以管理员身份运行」命令提示符/PowerShell 后重试：\n"
                     "      .venv\\Scripts\\python.exe main.py extract-keys")
        from wxwatch.keyscan_win import extract_keys_win

        db_storage = Path(args.db_storage) if getattr(args, "db_storage", None) else find_db_storage()
        extract_keys_win(db_storage, KEYS_FILE)
        return
    from wxwatch.keyscan import extract_keys

    if os.geteuid() != 0:
        sys.exit("[ERR] 读取进程内存需要 root，请用 sudo 运行：\n"
                 "      sudo .venv/bin/python main.py extract-keys")
    db_storage = Path(args.db_storage) if getattr(args, "db_storage", None) else find_db_storage()
    extract_keys(db_storage, KEYS_FILE)
    from wxwatch.imagekey import _chown_user
    _chown_user(KEYS_FILE)  # sudo 运行时还给真实用户，GUI（普通用户）才能读


def cmd_decrypt(_args):
    dec = make_decryptor(load_keys())
    print(f"[*] 解密全部数据库到 {DECRYPTED_DIR}/")
    dec.export_all(DECRYPTED_DIR)


def cmd_schema_dump(_args):
    dec = make_decryptor(load_keys())
    from wxwatch.parser import Parser

    dump = Parser(dec, find_db_storage().parent).schema_dump()
    out = OUTPUT_DIR / "schema.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dump, ensure_ascii=False, indent=2, default=str),
                   encoding="utf-8")
    print(f"[*] 表结构已写入 {out}")
    for rel, tables in dump.items():
        if isinstance(tables, dict) and "error" not in tables:
            print(f"  {rel}: {len(tables)} 张表")


def cmd_parse(_args):
    from wxwatch.parser import Parser
    from wxwatch.watcher import MessageWatcher

    dec = make_decryptor(load_keys())
    parser = Parser(dec, find_db_storage().parent)
    w = MessageWatcher(dec, parser, OUTPUT_DIR, verbose=False)
    n = w.parse_once()
    w.refresh_conversations()
    print(f"[*] 完成，共 {n} 条消息，输出在 {OUTPUT_DIR}/")


def cmd_watch(_args):
    from wxwatch.parser import Parser
    from wxwatch.watcher import MessageWatcher

    dec = make_decryptor(load_keys())
    parser = Parser(dec, find_db_storage().parent)
    MessageWatcher(dec, parser, OUTPUT_DIR).start()


def cmd_gui(_args):
    from wxwatch.gui.app import run

    run()


def cmd_extract_image_key(_args):
    """提取 V2 图片密钥（需 sudo；密钥仅在微信查看图片时加载进内存）。"""
    if sys.platform == "win32":
        sys.exit("[ERR] extract-image-key 目前仅支持 Linux")
    if os.geteuid() != 0:
        sys.exit("[ERR] 需要 root：sudo .venv/bin/python main.py extract-image-key\n"
                 "      注意：先在微信里点开一张图片，再立即运行本命令")
    from wxwatch.imagekey import extract_image_key

    extract_image_key(find_db_storage())


def cmd_watch_image_key(_args):
    """图片密钥自动抓取守护：监听 ImageUtils 缓存目录，微信一旦解码新图立即扫内存。"""
    if sys.platform == "win32":
        sys.exit("[ERR] watch-image-key 目前仅支持 Linux")
    if os.geteuid() != 0:
        sys.exit("[ERR] 需要 root：sudo .venv/bin/python main.py watch-image-key")
    from wxwatch.imagekey import watch_and_extract

    watch_and_extract(find_db_storage())


def cmd_collect_media(args):
    from wxwatch.decryptor import Decryptor
    from wxwatch.mediacollect import MediaCollector
    from wxwatch.parser import Parser

    ds = find_db_storage()
    dec = Decryptor(ds, load_keys(), MIRROR_DIR)
    parser = Parser(dec, ds.parent)
    image_key = None
    cfg = PROJECT / "config.json"
    if cfg.exists():
        try:
            ik = json.loads(cfg.read_text()).get("image_key")
            from wxwatch.imagedat import parse_image_key
            image_key = parse_image_key(ik)
        except Exception:
            pass
    if not image_key:
        print("[i] 无 V2 图片密钥（extract-image-key），V2 图片将保留 .dat 原样")
    mc = MediaCollector(ds.parent, parser, image_key=image_key, copy=args.copy)
    print("[*] 构建会话/媒体映射…")
    mc.build_maps(OUTPUT_DIR / "messages.jsonl")
    print(f"    已知会话 {len(mc._names)} 个，媒体映射 {len(mc._media_map)} 条")
    print(f"[*] 收集到 {args.out} …")
    stats = mc.collect(args.out)
    for kind, s in stats.items():
        print(f"  {kind}: 共 {sum(s.values())} 个  明细 {s}")
    print("[*] 完成")


def cmd_status(_args):
    """检查运行环境：微信进程 / 数据目录 / 密钥有效性（不读进程内存）。"""
    import contextlib
    import io

    print("[微信进程]")
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            pid = _keyscan_module().find_wechat_pid()
        print(f"  运行中, pid={pid}")
    except Exception as e:
        print(f"  未运行（{e}）")
    print("[数据目录]")
    try:
        ds = find_db_storage()
        n = len(list(ds.rglob("*.db")))
        print(f"  {ds}（{n} 个 .db）")
    except SystemExit:
        print("  未找到 ~/Documents/xwechat_files/wxid_*/db_storage")
        return
    print("[密钥]")
    if not KEYS_FILE.exists():
        print("  keys.json 不存在 → 需要一次性提取: sudo .venv/bin/python main.py extract-keys")
        return
    keys = json.loads(KEYS_FILE.read_text())
    print(f"  keys.json: {len(keys)} 个密钥")
    from wxwatch.decryptor import Decryptor

    dec = Decryptor(ds, keys, MIRROR_DIR)
    ok = bad = 0
    for rel in sorted(keys):
        if not (ds / rel).exists():
            continue
        if dec.sanity_check(rel):
            ok += 1
        else:
            bad += 1
    if bad == 0:
        print(f"  校验: {ok} 个库全部通过 ✅  可以直接 parse / watch / gui（纯磁盘，不读内存）")
    else:
        print(f"  校验: {ok} 通过 / {bad} 失败 ⚠️  密钥可能已变化，重新提取: sudo .venv/bin/python main.py extract-keys")


def main():
    if sys.platform == "darwin":
        sys.exit("macOS 请运行 python app.py。main.py 是 Linux / Windows 入口。")
    if sys.platform == "win32":
        # 控制台代码页（如 cp1252）无法输出中文 → 强制 UTF-8 容错，避免 print 崩溃
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_keys = sub.add_parser("extract-keys",
                            help="从微信进程内存提取密钥（Linux 需 sudo / Windows 需管理员）")
    p_keys.add_argument("--db-storage", help="微信 db_storage 目录（默认自动检测）")
    for name in ("decrypt", "schema-dump", "parse", "watch", "status"):
        sub.add_parser(name)
    sub.add_parser("gui", help="启动图形界面")
    sub.add_parser("extract-image-key",
                   help="提取 V2 图片密钥（sudo；需先在微信中查看图片）")
    sub.add_parser("watch-image-key",
                   help="图片密钥自动抓取守护（sudo；监听解码缓存自动触发）")
    p_col = sub.add_parser("collect-media",
                           help="收集历史图片/视频/文件，按会话分目录")
    p_col.add_argument("--out", required=True, type=Path, help="输出目录")
    p_col.add_argument("--copy", action="store_true", help="复制而非硬链接（默认）")
    argv = sys.argv[1:]
    if getattr(sys, "frozen", False) and not argv:
        argv = ["gui"]  # 双击打包的 exe（无参数）→ 直接启动 GUI，而不是打印用法退出
    args = ap.parse_args(argv)
    {
        "extract-keys": cmd_extract_keys,
        "decrypt": cmd_decrypt,
        "schema-dump": cmd_schema_dump,
        "parse": cmd_parse,
        "watch": cmd_watch,
        "gui": cmd_gui,
        "status": cmd_status,
        "extract-image-key": cmd_extract_image_key,
        "watch-image-key": cmd_watch_image_key,
        "collect-media": cmd_collect_media,
    }[args.cmd](args)


if __name__ == "__main__":
    main()
