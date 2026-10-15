"""历史媒体收集：把 msg/ 下的图片/视频/文件按会话组织到输出目录。

关联策略：
- 图片：msg/attach/<md5(talker)>/<yyyy-mm>/Img/* —— 目录名即会话 md5，直接反解
- 视频：msg/video/<yyyy-mm>/<md5>.mp4 —— 用解析产物里的 media_md5→会话 映射
- 文件：msg/file/<yyyy-mm>/<文件名> —— 明文文件，按消息里的文件名映射
- 关联不上的归入 _unknown/

处理：图片 .dat 能解密（旧 XOR / V1 / 已有 V2 image_key）则解密为图片字节，
否则原样保留 .dat。默认硬链接（同分区零拷贝），--copy 强制复制。
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from wxwatch.imagedat import decode_dat
from wxwatch.parser import md5


def _safe_name(name: str) -> str:
    s = "".join(c if c.isalnum() or c in " _-@." else "_" for c in name).strip()
    return s[:64] or "_"


class MediaCollector:
    def __init__(self, wechat_root: Path, parser, image_key: bytes | None = None,
                 copy: bool = False):
        self.root = Path(wechat_root)
        self.parser = parser
        self.image_key = image_key
        self.copy = copy
        # 会话 username -> 显示名（remark/nickname 优先）
        self._names: dict[str, str] = {}
        # 全部已知 username 的 md5 -> username（attach 目录反解用）
        self._md5map: dict[str, str] = {}
        # 媒体 md5 -> (talker, ts)（视频/文件关联用）
        self._media_map: dict[str, tuple[str, int]] = {}

    # ---------- 映射构建 ----------

    def build_maps(self, messages_jsonl: Path | None = None):
        contacts = self.parser.contacts()
        for u, c in contacts.items():
            self._md5map[md5(u)] = u
            self._names[u] = c.get("remark") or c.get("nickname") or u
        try:
            for s in self.parser.sessions():
                self._md5map.setdefault(md5(s["username"]), s["username"])
                self._names.setdefault(s["username"], s.get("display_name") or s["username"])
        except Exception:
            pass
        # Name2Id 里的 username 也加入
        for rel in self.parser.message_dbs():
            try:
                for u in self.parser.name2id(rel).values():
                    self._md5map.setdefault(md5(u), u)
            except Exception:
                continue
        # 从解析产物建 media_md5 -> talker 映射
        if messages_jsonl and messages_jsonl.exists():
            with open(messages_jsonl, encoding="utf-8") as f:
                for line in f:
                    try:
                        m = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    mm = m.get("media_md5")
                    if mm and m.get("talker"):
                        self._media_map[mm] = (m["talker"], m.get("timestamp") or 0)
                    f_ = m.get("file") or {}
                    if f_.get("name") and m.get("talker"):
                        # 文件按 文件名+月份 关联（文件名可能重复，带月份更准）
                        self._media_map[f"file:{f_['name']}"] = (
                            m["talker"], m.get("timestamp") or 0)

    def _talker_dir(self, talker: str | None, fallback: str) -> str:
        if talker and talker in self._names:
            return _safe_name(self._names[talker])
        if talker:
            return f"_unknown/{_safe_name(talker)}"
        return f"_unknown/{fallback}"

    def _place(self, src: Path, dst_dir: Path, decode_image: bool) -> str:
        """放一个文件，返回处置方式。"""
        dst_dir.mkdir(parents=True, exist_ok=True)
        if decode_image:
            raw = decode_dat(src, self.image_key)
            if raw is not None:
                ext = ".jpg"
                if raw[:4] == b"\x89PNG": ext = ".png"
                elif raw[:3] == b"GIF": ext = ".gif"
                elif raw[:4] == b"RIFF": ext = ".webp"
                dst = dst_dir / (src.stem.replace("_t", "") + ext)
                if not dst.exists():
                    dst.write_bytes(raw)
                return "decoded"
        dst = dst_dir / src.name
        if dst.exists():
            return "skip"
        if self.copy:
            import shutil
            shutil.copy2(src, dst)
            return "copied"
        try:
            os.link(src, dst)
            return "linked"
        except OSError:
            import shutil
            shutil.copy2(src, dst)
            return "copied"

    # ---------- 收集 ----------

    def collect(self, out_dir: Path) -> dict:
        stats: dict[str, dict[str, int]] = {"images": {}, "videos": {}, "files": {}}
        out_dir = Path(out_dir)

        # 图片：msg/attach/<md5(talker)>/<yyyy-mm>/Img/*
        attach = self.root / "msg" / "attach"
        if attach.exists():
            for talker_dir in sorted(attach.iterdir()):
                if not talker_dir.is_dir():
                    continue
                talker = self._md5map.get(talker_dir.name)
                for dat in talker_dir.rglob("*.dat"):
                    ym = dat.parent.parent.name  # <md5>/<yyyy-mm>/Img/xx.dat
                    base = self._talker_dir(talker, talker_dir.name)
                    dst_dir = out_dir / "images" / base / ym
                    kind = self._place(dat, dst_dir, decode_image=True)
                    stats["images"][kind] = stats["images"].get(kind, 0) + 1

        # 视频：msg/video/<yyyy-mm>/<md5>.mp4 与 _thumb.jpg
        vdir = self.root / "msg" / "video"
        if vdir.exists():
            for f in sorted(vdir.rglob("*")):
                if not f.is_file() or not (f.name.endswith(".mp4") or f.name.endswith("_thumb.jpg")):
                    continue
                ym = f.parent.name
                md5hex = f.name.split("_")[0].split(".")[0]
                assoc = self._media_map.get(md5hex)
                base = self._talker_dir(assoc[0] if assoc else None, md5hex)
                dst_dir = out_dir / "videos" / base / ym
                kind = self._place(f, dst_dir, decode_image=False)
                stats["videos"][kind] = stats["videos"].get(kind, 0) + 1

        # 文件：msg/file/<yyyy-mm>/<文件名>（明文）
        fdir = self.root / "msg" / "file"
        if fdir.exists():
            for f in sorted(fdir.rglob("*")):
                if not f.is_file():
                    continue
                ym = f.parent.name
                assoc = self._media_map.get(f"file:{f.name}")
                base = self._talker_dir(assoc[0] if assoc else None, ym)
                dst_dir = out_dir / "files" / base / ym
                kind = self._place(f, dst_dir, decode_image=False)
                stats["files"][kind] = stats["files"].get(kind, 0) + 1

        return stats


def main(argv=None):
    import argparse

    ap = argparse.ArgumentParser(description="收集历史图片/视频/文件，按会话组织")
    ap.add_argument("--out", required=True, type=Path, help="输出目录")
    ap.add_argument("--copy", action="store_true", help="复制而非硬链接")
    ap.add_argument("--db-storage", type=Path, default=None)
    args = ap.parse_args(argv)

    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from wxwatch.decryptor import Decryptor
    from wxwatch.parser import Parser

    project = Path(__file__).resolve().parent.parent
    keys = json.loads((project / "keys.json").read_text())
    ds = args.db_storage or sorted(
        Path.home().glob("Documents/xwechat_files/wxid_*/db_storage"))[0]
    dec = Decryptor(ds, keys, project / "mirror")
    parser = Parser(dec, ds.parent)

    image_key = None
    cfg = project / "config.json"
    if cfg.exists():
        try:
            ik = json.loads(cfg.read_text()).get("image_key")
            from wxwatch.imagedat import parse_image_key
            image_key = parse_image_key(ik)
        except Exception:
            pass

    mc = MediaCollector(ds.parent, parser, image_key=image_key, copy=args.copy)
    print("[*] 构建会话/媒体映射…")
    mc.build_maps(project / "output" / "messages.jsonl")
    print(f"    已知会话 {len(mc._names)} 个，媒体映射 {len(mc._media_map)} 条")
    print(f"[*] 收集到 {args.out} …")
    stats = mc.collect(args.out)
    for kind, s in stats.items():
        total = sum(s.values())
        print(f"  {kind}: 共 {total} 个  明细 {s}")
    print("[*] 完成")


if __name__ == "__main__":
    main()
