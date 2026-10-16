"""macOS 微信进程密钥采集与本地密钥文件管理。

本模块检测微信状态、用 DTrace 监听 ``CCCryptorCreate`` 采集候选密钥，
以及把已经验证过的密钥保存到本机。Linux / Windows 的内存密钥提取在
``wxwatch.keyscan`` / ``wxwatch.keyscan_win``，入口是 ``main.py``。
数据库读取和导出位于 ``read_wechat_conversation.py``。
"""

from __future__ import annotations

import datetime as _dt
import contextlib
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable


WECHAT_EXECUTABLE = Path("/Applications/WeChat.app/Contents/MacOS/WeChat")
WECHAT_INFO_PLIST = Path("/Applications/WeChat.app/Contents/Info.plist")
PROBE_SPEC = "pid$target:*:CCCryptorCreate:entry"
KEY_LINE_RE = re.compile(r"^WXKEY\s+([0-9a-fA-F]{64})\s*$")
HEX_KEY_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# DTrace 的 printf 格式必须是固定字面量，不能在 DTrace 脚本中动态拼接。
DTRACE_FORMAT = (
    "WXKEY %02x%02x%02x%02x%02x%02x%02x%02x"
    "%02x%02x%02x%02x%02x%02x%02x%02x"
    "%02x%02x%02x%02x%02x%02x%02x%02x"
    "%02x%02x%02x%02x%02x%02x%02x%02x\\n"
)


class KeyStoreError(RuntimeError):
    """密钥文件格式或权限错误。"""


class CaptureError(RuntimeError):
    """密钥采集启动或运行错误。"""


class DTraceError(CaptureError):
    """DTrace 探针启动或运行错误。"""


@dataclass(frozen=True)
class KeyRecord:
    """一个已在至少一个聊天数据库上验证过的密钥记录。"""

    hex: str
    captured_at: str
    validated_databases: tuple[str, ...] = field(default_factory=tuple)

    # 生成仅供界面显示的脱敏值，不把完整密钥暴露给调用方。
    @property
    # 返回密钥脱敏后的显示文本。
    def masked(self) -> str:
        return mask_key(self.hex)

    # 把内部记录转换成 key 文件中的 JSON 对象。
    def to_dict(self) -> dict[str, object]:
        return {
            "hex": self.hex,
            "captured_at": self.captured_at,
            "validated_databases": list(self.validated_databases),
        }

    # 覆盖默认 repr，调试输出也只显示脱敏后的 key。
    def __repr__(self) -> str:
        return (
            "KeyRecord("
            f"hex={self.masked!r}, captured_at={self.captured_at!r}, "
            f"validated_databases={self.validated_databases!r})"
        )


@dataclass(frozen=True)
class WeChatStatus:
    """微信进程检测结果。"""

    running: bool
    pid: int | None
    version: str | None
    executable: str
    detail: str = ""


@dataclass(frozen=True)
class CaptureResult:
    """一次 DTrace 运行的结果；完整密钥只在进程内短暂保留。"""

    captured_keys: tuple[str, ...]
    validated_keys: tuple[KeyRecord, ...]
    elapsed_seconds: float
    returncode: int | None
    error: str | None = None
    report: str = ""

    # 返回本次捕获候选的脱敏视图，供 GUI 使用。
    @property
    # 返回本次运行捕获候选的脱敏列表。
    def masked_captured_keys(self) -> tuple[str, ...]:
        return tuple(mask_key(value) for value in self.captured_keys)

    # 覆盖默认 repr，避免日志或异常格式化时意外显示完整候选 key。
    def __repr__(self) -> str:
        masked_validated = tuple(
            item.masked if isinstance(item, KeyRecord) else mask_key(str(item))
            for item in self.validated_keys
        )
        return (
            "CaptureResult("
            f"captured_keys={self.masked_captured_keys!r}, "
            f"validated_keys={masked_validated!r}, "
            f"elapsed_seconds={self.elapsed_seconds!r}, returncode={self.returncode!r}, "
            f"error={self.error!r}, report={self.report!r})"
        )


# 将任意时间转换为可写入 key 文件的 UTC ISO-8601 字符串。
def utc_now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


# 校验并标准化 32 字节 AES-256 十六进制密钥；错误信息不回显密钥。
def normalize_key_hex(value: str) -> str:
    if not isinstance(value, str) or not HEX_KEY_RE.fullmatch(value.strip()):
        raise KeyStoreError("密钥格式无效：需要 64 位十六进制文本")
    return value.strip().lower()


# 生成符合界面安全要求的密钥脱敏文本。
def mask_key(value: str) -> str:
    if not isinstance(value, str) or len(value) < 17:
        return "***"
    return f"{value[:8]}***{value[-8:]}"


# 对命令输出做通用脱敏，避免意外的 64 位十六进制串进入日志或异常。
def redact_output(value: str | bytes) -> str:
    text = value.decode(errors="replace") if isinstance(value, bytes) else str(value)
    return re.sub(r"[0-9a-fA-F]{64}", "***", text)


# 返回当前平台用于存放密钥文件的应用数据目录。
def default_app_support_dir(home: Path | None = None, *, platform: str | None = None) -> Path:
    return default_key_path(home, platform=platform).parent


# 返回默认密钥文件路径，可在测试中注入不同 home 目录或平台。
def default_key_path(home: Path | None = None, *, platform: str | None = None) -> Path:
    system = platform or sys.platform
    base = home if home is not None else Path.home()
    filename = "wechat_cccryptor_keys.json"
    if system == "win32":
        if home is None:
            appdata = os.environ.get("APPDATA", "").strip()
            if appdata:
                return Path(appdata) / "WeChatExport" / filename
        return base / "AppData" / "Roaming" / "WeChatExport" / filename
    if system == "darwin":
        return base / "Library" / "Application Support" / "WeChatExport" / filename
    return base / ".config" / "WeChatExport" / filename


APP_SUPPORT_DIR = default_app_support_dir()
DEFAULT_KEY_PATH = default_key_path()
PROBE_CHECK_TIMEOUT = 120.0

# 图形密码框脚本。密码只从对话框交给 sudo，不写入这个文件。
ASKPASS_SCRIPT = """#!/bin/sh
/usr/bin/osascript <<'EOF'
set dialogResult to display dialog "采集微信密钥需要管理员密码来运行 DTrace。" default answer "" with hidden answer with title "微信聊天记录导出" buttons {"取消", "确定"} default button "确定"
text returned of dialogResult
EOF
"""


# 确保父目录由当前用户创建并尽量限制为仅用户可读写。
def ensure_private_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass


# 解析 key 文件中的单条记录并丢弃不可信的附加字段。
def _record_from_dict(item: object) -> KeyRecord:
    if not isinstance(item, dict):
        raise KeyStoreError("密钥文件格式无效")
    key = normalize_key_hex(str(item.get("hex", "")))
    captured_at = str(item.get("captured_at") or utc_now_iso())
    raw_databases = item.get("validated_databases", [])
    if not isinstance(raw_databases, list):
        raw_databases = []
    databases = tuple(sorted({Path(str(name)).name for name in raw_databases if str(name).strip()}))
    return KeyRecord(key, captured_at, databases)


# 从本地 key 文件读取记录；不存在时返回空列表。
def load_key_records(path: Path | str = DEFAULT_KEY_PATH) -> list[KeyRecord]:
    key_path = Path(path).expanduser()
    if not key_path.exists():
        return []
    if key_path.is_symlink():
        raise KeyStoreError("拒绝读取符号链接形式的密钥文件")
    try:
        file_stat = key_path.stat()
        if hasattr(os, "getuid") and file_stat.st_uid != os.getuid():
            raise KeyStoreError("密钥文件不属于当前用户")
        if file_stat.st_mode & 0o077:
            os.chmod(key_path, 0o600)
    except KeyStoreError:
        raise
    except OSError as exc:
        raise KeyStoreError("无法检查密钥文件权限") from exc
    try:
        with key_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        raise KeyStoreError("无法读取本工具的密钥文件") from None
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise KeyStoreError("密钥文件版本不受支持")
    raw_keys = payload.get("keys", [])
    if not isinstance(raw_keys, list):
        raise KeyStoreError("密钥文件格式无效")
    records: list[KeyRecord] = []
    seen: set[str] = set()
    for item in raw_keys:
        record = _record_from_dict(item)
        if record.hex not in seen:
            records.append(record)
            seen.add(record.hex)
    return records


# 原子写入 key 文件，并在写入后强制设置 0600 权限。
def save_key_records(records: Iterable[KeyRecord], path: Path | str = DEFAULT_KEY_PATH) -> Path:
    key_path = Path(path).expanduser()
    if key_path.is_symlink():
        raise KeyStoreError("拒绝覆盖符号链接形式的密钥文件")
    ensure_private_parent(key_path)
    clean_records: list[KeyRecord] = []
    seen: set[str] = set()
    for record in records:
        normalized = normalize_key_hex(record.hex)
        if normalized in seen:
            continue
        clean_records.append(
            KeyRecord(
                normalized,
                record.captured_at or utc_now_iso(),
                tuple(sorted({Path(str(name)).name for name in record.validated_databases if str(name).strip()})),
            )
        )
        seen.add(normalized)
    payload = {
        "version": 1,
        "tool": "WeChatExport",
        "keys": [record.to_dict() for record in clean_records],
    }
    fd, temporary_name = tempfile.mkstemp(prefix=f".{key_path.name}.", dir=str(key_path.parent))
    temporary_path = Path(temporary_name)
    try:
        if hasattr(os, "fchmod"):
            with contextlib.suppress(OSError, NotImplementedError):
                os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, key_path)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
    except Exception:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return key_path


# 保存一条刚刚验证成功的密钥，并合并其验证过的数据库名称。
def save_validated_key(
    key_hex: str,
    validated_databases: Iterable[str] | str | os.PathLike[str],
    path: Path | str = DEFAULT_KEY_PATH,
) -> KeyRecord:
    normalized = normalize_key_hex(key_hex)
    existing = load_key_records(path)
    raw_names: Iterable[object]
    if isinstance(validated_databases, (str, os.PathLike)):
        raw_names = (validated_databases,)
    else:
        raw_names = validated_databases
    database_names = {Path(str(name)).name for name in raw_names if str(name).strip()}
    merged: list[KeyRecord] = []
    found = False
    for record in existing:
        if record.hex == normalized:
            merged.append(
                KeyRecord(
                    record.hex,
                    record.captured_at,
                    tuple(sorted(set(record.validated_databases) | database_names)),
                )
            )
            found = True
        else:
            merged.append(record)
    result = KeyRecord(normalized, utc_now_iso(), tuple(sorted(database_names)))
    if not found:
        merged.append(result)
    else:
        result = next(item for item in merged if item.hex == normalized)
    save_key_records(merged, path)
    return result


# 仅删除由本工具写入且带有工具标记的 key 文件。
def reset_key_file(path: Path | str = DEFAULT_KEY_PATH) -> bool:
    key_path = Path(path).expanduser()
    if key_path.is_symlink():
        raise KeyStoreError("拒绝删除符号链接形式的文件")
    if not key_path.exists():
        return False
    try:
        with key_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        raise KeyStoreError("目标不是本工具可识别的密钥文件") from None
    is_default_tool_file = key_path == default_key_path()
    if not isinstance(payload, dict) or payload.get("version") != 1 or (
        payload.get("tool") != "WeChatExport" and not is_default_tool_file
    ):
        raise KeyStoreError("目标不是本工具创建的密钥文件")
    try:
        key_path.unlink()
    except OSError as exc:
        raise KeyStoreError("无法删除本工具的密钥文件") from exc
    return True


# 判断密钥文件是否落在导出目录中，防止密钥随导出物泄露。
def ensure_key_path_outside_export(key_path: Path | str, export_dir: Path | str) -> None:
    key_resolved = Path(key_path).expanduser().resolve()
    export_resolved = Path(export_dir).expanduser().resolve()
    try:
        key_resolved.relative_to(export_resolved)
    except ValueError:
        return
    raise KeyStoreError("密钥文件不能位于导出目录中")


# 构造固定格式的 DTrace 脚本，只读取 AES-256 的 32 字节 key 参数。
def build_dtrace_program() -> str:
    expressions = ",\n        ".join(
        f"*(uint8_t *)copyin(arg3 + {index}, 1)" for index in range(32)
    )
    # 探针描述只有 provider:module:function:name 四段，必须和 PROBE_SPEC 一致。
    # pid$target::*:CCCryptorCreate:entry 多出一段，dtrace 会报 Overspecified probe description。
    return (
        f"{PROBE_SPEC}\n"
        "/arg1 == 0 && arg4 == 32 && arg3 != 0/\n"
        "{\n"
        f'    printf("{DTRACE_FORMAT}",\n'
        f"        {expressions});\n"
        "}\n"
    )


# 表情包不经过数据库那条 32 字节校验。16 和 32 字节的 AES 都抓下来，直接拿安装包试解。
def build_emoticon_dtrace_program() -> str:
    def clause(function: str, size: int) -> str:
        expressions = ",\n        ".join(f"*(uint8_t *)copyin(arg3 + {index}, 1)" for index in range(size))
        return (
            f"pid$target:*:{function}:entry\n"
            f"/arg1 == 0 && arg4 == {size} && arg3 != 0/\n"
            "{\n"
            f'    printf("EMK {("%02x" * size)}\\n",\n'
            f"        {expressions});\n"
            "}\n"
        )

    parts = []
    for function in ("CCCrypt", "CCCryptorCreate"):
        for size in (16, 32):
            parts.append(clause(function, size))
    return "\n".join(parts)


def _emoticon_pids(preferred: int) -> list[int]:
    """表情解密可能在主进程或辅助进程，不只盯一个 PID。"""
    found: list[int] = []
    try:
        listing = subprocess.check_output(["ps", "-ax", "-o", "pid=,command="], text=True)
    except (OSError, subprocess.CalledProcessError):
        return [preferred] if preferred else []
    for line in listing.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        pid_text, _, command = stripped.partition(" ")
        name = Path(command.split(" --", 1)[0]).name
        if name in {"WeChat", "WeChatHelper", "wxplayer", "wxutility"}:
            try:
                found.append(int(pid_text))
            except ValueError:
                continue
    if preferred and preferred not in found:
        found.insert(0, preferred)
    return found


# 监听 16 字节 AES 密钥，并用一整个商店表情包验证。成功后写入 config.json 的 emoticon_key。
def capture_emoticon_key(pid: int, sample: bytes, duration: float = 60, on_status: Callable[..., object] | None = None) -> bytes | None:
    import pty
    import select

    from read_wechat_conversation import decrypt_emoticon_package

    if len(sample) < 16 or len(sample) % 16:
        raise DTraceError("表情包样本长度不是 16 的倍数")
    credential_error = ensure_sudo_credentials()
    if credential_error:
        raise DTraceError(credential_error)
    _notify(on_status, "正在监听 16 字节密钥。请打开微信表情面板，点开一套商店表情")
    seen: set[bytes] = set()
    deadline = time.monotonic() + duration
    found: bytes | None = None
    readers: list[tuple[int, subprocess.Popen[bytes], bytes]] = []
    errors: list[str] = []
    for target in _emoticon_pids(pid):
        master, slave = pty.openpty()
        process = subprocess.Popen(
            ["sudo", "-n", "dtrace", "-q", "-n", build_emoticon_dtrace_program(), "-p", str(target)],
            stdin=subprocess.DEVNULL,
            stdout=slave,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        os.close(slave)
        readers.append((master, process, b""))
    try:
        while time.monotonic() < deadline and found is None:
            alive = [(master, process, pending) for master, process, pending in readers if process.poll() is None or pending]
            if not alive:
                break
            ready, _, _ = select.select([item[0] for item in alive], [], [], 0.5)
            next_readers: list[tuple[int, subprocess.Popen[bytes], bytes]] = []
            for master, process, pending in readers:
                if master not in ready:
                    next_readers.append((master, process, pending))
                    continue
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    chunk = b""
                pending += chunk
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    text = line.decode("utf-8", errors="replace").strip()
                    match = re.fullmatch(r"EMK ([0-9a-fA-F]{32}|[0-9a-fA-F]{64})", text)
                    if not match:
                        continue
                    candidate = bytes.fromhex(match.group(1))
                    if candidate in seen:
                        continue
                    seen.add(candidate)
                    if decrypt_emoticon_package(sample, candidate) is not None:
                        found = candidate
                        break
                next_readers.append((master, process, pending))
                if found is not None:
                    break
            readers = next_readers
    finally:
        for master, process, _pending in readers:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
            if process.stderr is not None:
                detail = process.stderr.read().decode("utf-8", errors="replace").strip()
                if detail:
                    errors.append(detail[:300])
            os.close(master)
    if found is None and not seen and errors:
        raise DTraceError(errors[0])
    if found is None:
        raise DTraceError(f"看到 {len(seen)} 个 16 字节候选，没有一把能解开商店表情包。请在采集过程中打开表情面板。")
    config_path = Path(__file__).resolve().parent / "config.json"
    payload: dict[str, object] = {}
    if config_path.is_file():
        try:
            loaded = json.loads(config_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                payload = loaded
        except json.JSONDecodeError:
            payload = {}
    payload["emoticon_key"] = found.hex()
    config_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.chmod(config_path, 0o600)
    return found


# 写入仅当前用户可执行的 sudo 密码助手，供没有终端时弹出密码框。
def ensure_sudo_askpass(directory: Path | None = None) -> Path:
    folder = directory if directory is not None else default_app_support_dir()
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(folder, 0o700)
    except OSError:
        pass
    path = folder / "sudo-askpass.sh"
    path.write_text(ASKPASS_SCRIPT, encoding="utf-8")
    os.chmod(path, 0o700)
    return path


# 让 sudo 在需要密码时调用图形密码框，而不是等待一个可能不存在的终端。
def sudo_environment(directory: Path | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env["SUDO_ASKPASS"] = str(ensure_sudo_askpass(directory))
    return env


# 读取子进程输出并脱敏，避免把脚本或异常里的密钥带回界面。
def _completed_detail(completed: subprocess.CompletedProcess[bytes]) -> str:
    stdout = completed.stdout.decode(errors="replace") if isinstance(completed.stdout, bytes) else str(completed.stdout or "")
    stderr = completed.stderr.decode(errors="replace") if isinstance(completed.stderr, bytes) else str(completed.stderr or "")
    return redact_output((stdout + "\n" + stderr).strip())


# 判断当前终端上的 sudo 时间戳是否仍可复用。
def sudo_timestamp_ready() -> bool:
    try:
        completed = subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


# 只在缓存失效时询问一次管理员密码。sudo 的凭证按终端保存，后续命令必须留在同一终端会话里。
def ensure_sudo_credentials() -> str | None:
    if sudo_timestamp_ready():
        return None
    try:
        completed = subprocess.run(
            ["sudo", "-A", "-v"],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            env=sudo_environment(),
            timeout=PROBE_CHECK_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "等待管理员密码超时。请在弹出的密码框中输入开机密码后重试。"
    except OSError:
        return "无法启动 sudo"
    if completed.returncode != 0:
        return _completed_detail(completed) or "管理员密码未通过"
    if not sudo_timestamp_ready():
        return "管理员密码已输入，但 sudo 没有留下可复用的凭证。请在启动本程序的终端执行 sudo -v 后重试。"
    return None


# 检查当前平台是否具备采集密钥的进程访问条件。
def check_capture_probe(pid: int, timeout: float = PROBE_CHECK_TIMEOUT) -> tuple[bool, str]:
    if sys.platform == "darwin":
        return check_dtrace_probe(pid, timeout)
    return False, "macOS 以外请使用 python main.py extract-keys"


# 运行 DTrace probe 列表检查，并返回脱敏后的诊断文本。
def check_dtrace_probe(pid: int, timeout: float = PROBE_CHECK_TIMEOUT) -> tuple[bool, str]:
    credential_error = ensure_sudo_credentials()
    if credential_error:
        return False, credential_error
    command = ["sudo", "-n", "dtrace", "-l", "-n", PROBE_SPEC, "-p", str(int(pid))]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return False, "DTrace 检查超时。请在弹出的密码框中输入开机密码；如果没有密码框，请在启动本程序的终端执行 sudo -v 后重试。"
    except OSError:
        return False, "无法启动 DTrace probe 检查"
    stdout = completed.stdout.decode(errors="replace") if isinstance(completed.stdout, bytes) else str(completed.stdout)
    stderr = completed.stderr.decode(errors="replace") if isinstance(completed.stderr, bytes) else str(completed.stderr)
    detail = redact_output((stdout + "\n" + stderr).strip())
    if completed.returncode != 0:
        return False, detail or "DTrace probe 不可用"
    return True, detail or "DTrace probe 可用"


# 调用可选回调时吞掉 GUI 回调异常，避免中断底层采集清理。
def _notify(callback: Callable[..., object] | None, *args: object) -> None:
    if callback is None:
        return
    try:
        callback(*args)
    except Exception:
        pass


# 列出某个进程的全部后代，不包含调用方自己的进程组。
def _descendant_pids(pid: int) -> list[int]:
    try:
        completed = subprocess.run(
            ["pgrep", "-P", str(pid)],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    descendants: list[int] = []
    for token in completed.stdout.split():
        try:
            child = int(token)
        except ValueError:
            continue
        descendants.extend(_descendant_pids(child))
        descendants.append(child)
    return descendants


# 向一个进程发信号，进程已经退出时忽略错误。
def _signal_pid(pid: int, sig: int) -> None:
    try:
        os.kill(pid, sig)
    except OSError:
        pass


# 终止 sudo 和它启动的 dtrace，不能新建会话，否则 sudo 凭证缓存会失效。
def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    descendants = _descendant_pids(process.pid)
    for pid in descendants:
        _signal_pid(pid, signal.SIGINT)
    _signal_pid(process.pid, signal.SIGINT)
    try:
        process.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        pass
    for pid in descendants:
        _signal_pid(pid, signal.SIGTERM)
    try:
        process.terminate()
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        for pid in descendants:
            _signal_pid(pid, signal.SIGKILL)
        try:
            process.kill()
        except OSError:
            pass


# macOS 用 DTrace 采集密钥。Linux / Windows 走 main.py。
def capture_keys(
    pid: int,
    validator: Callable[[str], Iterable[str]],
    *,
    duration: int = 60,
    key_path: Path | str = DEFAULT_KEY_PATH,
    on_tick: Callable[[int], object] | None = None,
    on_candidate: Callable[[str], object] | None = None,
    on_status: Callable[[str], object] | None = None,
    stop_event: object | None = None,
) -> CaptureResult:
    if sys.platform == "darwin":
        return _capture_keys_dtrace(
            pid,
            validator,
            duration=duration,
            key_path=key_path,
            on_tick=on_tick,
            on_candidate=on_candidate,
            on_status=on_status,
            stop_event=stop_event,
        )
    return CaptureResult((), (), 0.0, None, "当前系统不支持自动采集密钥")


# 在指定微信 PID 上监听固定前缀的 key 行，并逐个调用验证器。
def _capture_keys_dtrace(
    pid: int,
    validator: Callable[[str], Iterable[str]],
    *,
    duration: int = 60,
    key_path: Path | str = DEFAULT_KEY_PATH,
    on_tick: Callable[[int], object] | None = None,
    on_candidate: Callable[[str], object] | None = None,
    on_status: Callable[[str], object] | None = None,
    stop_event: object | None = None,
) -> CaptureResult:
    started = time.monotonic()
    candidates: list[str] = []
    seen: set[str] = set()
    validated_records: list[KeyRecord] = []
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    stderr_details: list[str] = []
    process_exited_early = False
    error: str | None = None
    returncode: int | None = None
    credential_error = ensure_sudo_credentials()
    if credential_error:
        return CaptureResult((), (), 0.0, None, credential_error)
    try:
        # 不使用 start_new_session。sudo 默认按终端缓存密码，新会话没有终端，会再次弹出密码框。
        command = ["sudo", "-n", "dtrace", "-q", "-n", build_dtrace_program(), "-p", str(int(pid))]
        _notify(on_status, "正在启动 DTrace 密钥采集")
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.stdout is None or process.stderr is None:
            raise DTraceError("DTrace 输出通道不可用")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        deadline = started + max(0, int(duration))
        while time.monotonic() < deadline:
            if getattr(stop_event, "is_set", lambda: False)():
                break
            remaining = max(0, int(deadline - time.monotonic() + 0.999))
            _notify(on_tick, remaining)
            events = selector.select(timeout=min(0.5, max(0.05, deadline - time.monotonic())))
            for key, _ in events:
                raw_line = key.fileobj.readline()
                if not raw_line:
                    try:
                        selector.unregister(key.fileobj)
                    except Exception:
                        pass
                    continue
                line = raw_line.decode(errors="replace").strip()
                match = KEY_LINE_RE.fullmatch(line)
                if not match:
                    if key.data == "stderr" and line:
                        safe_line = redact_output(line)
                        stderr_details.append(safe_line)
                        del stderr_details[:-20]
                        _notify(on_status, safe_line)
                    continue
                candidate = match.group(1).lower()
                if candidate in seen:
                    continue
                seen.add(candidate)
                candidates.append(candidate)
                masked = mask_key(candidate)
                _notify(on_candidate, masked)
                try:
                    validated_names = validator(candidate)
                    if isinstance(validated_names, (str, os.PathLike)):
                        validated_names = (validated_names,)
                    database_names = tuple(sorted({Path(str(item)).name for item in validated_names if str(item).strip()}))
                except Exception:
                    database_names = tuple()
                if not database_names:
                    _notify(on_status, f"候选密钥 {masked} 未通过数据库验证")
                    continue
                record = save_validated_key(candidate, database_names, key_path)
                validated_records.append(record)
                _notify(on_status, f"候选密钥 {masked} 已验证并保存")
            if process.poll() is not None and not events:
                process_exited_early = True
                break
    except (OSError, DTraceError, KeyStoreError) as exc:
        error = redact_output(str(exc))
    except Exception:
        # 不把底层异常文本直接交给 GUI，避免意外回显密钥或本机路径细节。
        error = "密钥采集过程中发生未预期错误"
    finally:
        if selector is not None:
            with contextlib.suppress(Exception):
                selector.close()
        if process is not None:
            _stop_process(process)
            returncode = process.returncode
            if error is None and process_exited_early and returncode not in (None, 0):
                error = "\n".join(stderr_details) or "DTrace 密钥采集进程异常退出"
        _notify(on_tick, 0)
    elapsed = time.monotonic() - started
    return CaptureResult(tuple(candidates), tuple(validated_records), elapsed, returncode, error)


# 返回采集前需要满足的环境条件，供界面展示。
def get_capture_prerequisite() -> tuple[bool | None, str, str]:
    sip_disabled, detail = get_sip_status()
    if sip_disabled is True:
        return True, "关闭 macOS SIP", "可进行 DTrace 采集"
    if sip_disabled is False:
        return False, "关闭 macOS SIP", "需在恢复模式手动关闭"
    return None, "关闭 macOS SIP", detail or "请在终端检查 csrutil status"


# 检查 macOS SIP 状态；返回值 True 表示已关闭，False 表示已开启。
def get_sip_status() -> tuple[bool | None, str]:
    try:
        completed = subprocess.run(
            ["csrutil", "status"],
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, "无法执行 csrutil status"
    stdout = completed.stdout.decode(errors="replace") if isinstance(completed.stdout, bytes) else str(completed.stdout)
    stderr = completed.stderr.decode(errors="replace") if isinstance(completed.stderr, bytes) else str(completed.stderr)
    text = (stdout + "\n" + stderr).strip()
    lowered = text.lower()
    if "disabled" in lowered:
        return True, text
    if "enabled" in lowered:
        return False, text
    return None, text or "无法识别 csrutil 输出"


# 从 ps 输出中查找精确的微信主程序 PID，避免误匹配辅助进程。
def find_wechat_pid(executable: Path | str | None = None) -> int | None:
    executable_text = str(executable or WECHAT_EXECUTABLE)
    try:
        completed = subprocess.run(
            ["ps", "-ax", "-o", "pid=,command="],
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = completed.stdout.decode(errors="replace") if isinstance(completed.stdout, bytes) else str(completed.stdout)
    for line in output.splitlines():
        match = re.match(r"\s*(\d+)\s+(.*)$", line)
        if not match:
            continue
        command = match.group(2).strip()
        if command == executable_text or re.match(rf"^{re.escape(executable_text)}(?:\s|$)", command):
            try:
                return int(match.group(1))
            except ValueError:
                continue
    return None


# 读取微信 Info.plist 中的短版本号，读取失败时返回 None。
def read_wechat_version(info_plist: Path | str | None = None) -> str | None:
    plist_path = Path(info_plist or WECHAT_INFO_PLIST)
    if not plist_path.exists():
        return None
    try:
        import plistlib

        with plist_path.open("rb") as handle:
            payload = plistlib.load(handle)
    except (OSError, ValueError, plistlib.InvalidFileException):
        return None
    value = payload.get("CFBundleShortVersionString") if isinstance(payload, dict) else None
    return str(value) if value else None


# 汇总微信是否运行、PID 和版本状态，供 GUI 定时刷新。
def detect_wechat(
    executable: Path | str | None = None,
    info_plist: Path | str | None = None,
) -> WeChatStatus:
    target = Path(executable or WECHAT_EXECUTABLE)
    pid = find_wechat_pid(target)
    version = read_wechat_version(info_plist or WECHAT_INFO_PLIST)
    if pid is None:
        return WeChatStatus(False, None, version, str(target), "未检测到微信主进程")
    return WeChatStatus(True, pid, version, str(target), "已检测到微信主进程")


# 请求启动本机微信客户端。
def launch_wechat() -> tuple[bool, str]:
    try:
        completed = subprocess.run(["open", "-a", "WeChat"], capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False, "无法执行 open -a WeChat"
    if completed.returncode != 0:
        return False, "无法启动微信客户端"
    return True, "已请求启动微信客户端"


# 兼容调用方常用命名：获取微信主进程 PID。
def get_wechat_pid(executable: Path | str | None = None) -> int | None:
    return find_wechat_pid(executable)


# 兼容调用方常用命名：读取微信短版本号。
def get_wechat_version(info_plist: Path | str | None = None) -> str | None:
    return read_wechat_version(info_plist)


__all__ = [
    "APP_SUPPORT_DIR",
    "CaptureError",
    "CaptureResult",
    "DEFAULT_KEY_PATH",
    "DTraceError",
    "KeyRecord",
    "KeyStoreError",
    "PROBE_SPEC",
    "WECHAT_EXECUTABLE",
    "WECHAT_INFO_PLIST",
    "WeChatStatus",
    "build_dtrace_program",
    "capture_keys",
    "check_capture_probe",
    "check_dtrace_probe",
    "default_app_support_dir",
    "default_key_path",
    "detect_wechat",
    "ensure_key_path_outside_export",
    "ensure_sudo_askpass",
    "ensure_sudo_credentials",
    "find_wechat_pid",
    "get_capture_prerequisite",
    "get_wechat_pid",
    "get_sip_status",
    "get_wechat_version",
    "launch_wechat",
    "load_key_records",
    "mask_key",
    "normalize_key_hex",
    "read_wechat_version",
    "redact_output",
    "reset_key_file",
    "save_key_records",
    "save_validated_key",
]
