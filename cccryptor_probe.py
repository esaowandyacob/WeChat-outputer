"""微信进程密钥采集与本地密钥文件管理。

本模块只负责三件事：检测系统/微信状态、采集候选密钥、以及把已经验证
过的密钥安全地保存到本机。macOS 使用 DTrace 监听 ``CCCryptorCreate``；
Windows 只读扫描 ``Weixin.exe`` 进程内存中的 WCDB 密钥文本。数据库读取
和业务解析位于 ``read_wechat_conversation.py``，这样即使密钥采集失败也
不会影响导出器的测试和离线使用。
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
    return (
        "pid$target::*:CCCryptorCreate:entry\n"
        "/arg1 == 0 && arg4 == 32 && arg3 != 0/\n"
        "{\n"
        f'    printf("{DTRACE_FORMAT}",\n'
        f"        {expressions});\n"
        "}\n"
    )


# 检查当前平台是否具备采集密钥的进程访问条件。
def check_capture_probe(pid: int, timeout: float = 8.0) -> tuple[bool, str]:
    if sys.platform == "win32":
        from windows_memory_probe import check_process_memory_access

        return check_process_memory_access(int(pid))
    if sys.platform == "darwin":
        return check_dtrace_probe(pid, timeout)
    return False, "当前系统不支持自动采集密钥"


# 运行题目要求的 DTrace probe 列表检查，并返回脱敏后的诊断文本。
def check_dtrace_probe(pid: int, timeout: float = 8.0) -> tuple[bool, str]:
    command = ["sudo", "dtrace", "-l", "-n", PROBE_SPEC, "-p", str(int(pid))]
    try:
        completed = subprocess.run(command, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
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


# 终止 DTrace 子进程并等待其释放资源。
def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        process_group = os.getpgid(process.pid)
        if process_group != os.getpgrp():
            os.killpg(process_group, signal.SIGINT)
        else:
            process.send_signal(signal.SIGINT)
        process.wait(timeout=3)
    except (AttributeError, TypeError, OSError, subprocess.TimeoutExpired):
        try:
            process.terminate()
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            try:
                process.kill()
            except OSError:
                pass


# 按当前操作系统采集密钥：macOS 用 DTrace，Windows 扫描进程内存。
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
    if sys.platform == "win32":
        return _capture_keys_windows(
            pid,
            validator,
            duration=duration,
            key_path=key_path,
            on_tick=on_tick,
            on_candidate=on_candidate,
            on_status=on_status,
            stop_event=stop_event,
        )
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


# 把采集到的候选密钥交给验证器，验证成功后写入本地密钥文件。
def _validate_and_store_candidate(
    candidate: str,
    validator: Callable[[str], Iterable[str]],
    key_path: Path | str,
    on_candidate: Callable[[str], object] | None,
    on_status: Callable[[str], object] | None,
    seen: set[str],
    candidates: list[str],
    validated_records: list[KeyRecord],
) -> None:
    if candidate in seen:
        return
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
        return
    record = save_validated_key(candidate, database_names, key_path)
    validated_records.append(record)
    _notify(on_status, f"候选密钥 {masked} 已验证并保存")


# 若验证器绑定了 WeChatReader，则用内存里发现的数据目录补全扫描根。
def _attach_discovered_data_roots(validator: Callable[..., object], data_dirs: Iterable[Path]) -> None:
    reader = getattr(validator, "__self__", None)
    if reader is None or not data_dirs:
        return
    current = getattr(reader, "data_root", None)
    if current is not None:
        return
    from read_wechat_conversation import discover_message_databases

    for root in data_dirs:
        try:
            if discover_message_databases(root):
                reader.data_root = root
                return
        except Exception:
            continue
    reader.data_root = next(iter(data_dirs))


# 把探针报告写到密钥目录，便于复制反馈。
def _write_probe_report(key_path: Path | str, report: str) -> Path | None:
    try:
        path = Path(key_path).expanduser()
        ensure_private_parent(path)
        log_path = path.parent / "last_capture_probe.txt"
        log_path.write_text(report + "\n", encoding="utf-8")
        return log_path
    except OSError:
        return None


# 只读扫描 Windows 微信进程内存，并输出可观察的探针报告。
def _capture_keys_windows(
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
    from windows_memory_probe import (
        WindowsProbeError,
        format_memory_scan_report,
        list_windows_wechat_processes,
        python_pointer_bits,
        scan_wechat_process_memory,
    )

    started = time.monotonic()
    candidates: list[str] = []
    seen: set[str] = set()
    validated_records: list[KeyRecord] = []
    error: str | None = None
    report = ""
    extra_lines: list[str] = []
    _notify(on_tick, max(0, int(duration)))
    try:
        from read_wechat_conversation import (
            discover_message_databases,
            find_sqlcipher_driver,
            find_sqlcipher_executable,
            read_sqlcipher_salt,
        )

        bits = python_pointer_bits()
        extra_lines.append(f"SQLCipher 驱动：{'有' if find_sqlcipher_driver() else '无'}")
        extra_lines.append(f"SQLCipher CLI：{'有' if find_sqlcipher_executable() else '无'}")
        if bits < 64:
            error = f"当前 Python 是 {bits} 位，无法读取 64 位微信进程。请改用 64 位 Python。"
            report = error
            raise WindowsProbeError(error)
        processes = list_windows_wechat_processes()
        extra_lines.append("微信进程：")
        if not processes:
            extra_lines.append("  （未枚举到 Weixin.exe / WeChat.exe）")
        for item in processes:
            extra_lines.append(
                f"  PID {item.pid} {item.name} 版本 {item.version or '未知'} 工作集 {item.working_set}"
            )
        reader = getattr(validator, "__self__", None)
        data_root = getattr(reader, "data_root", None) if reader is not None else None
        message_paths = discover_message_databases(data_root)
        extra_lines.append(f"message_N.db：{len(message_paths)} 个")
        salts: dict[str, bytes] = {}
        plaintext = 0
        for path in message_paths:
            salt = read_sqlcipher_salt(path)
            if salt is None:
                plaintext += 1
            else:
                salts[salt.hex()] = salt
        extra_lines.append(f"加密库 salt：{len(salts)} 个，明文/无法读头：{plaintext} 个")
        if salts:
            extra_lines.append("salt 样例：" + "、".join(list(salts)[:3]))
        _notify(on_status, f"探针：已发现 {len(message_paths)} 个数据库，开始读进程内存")
        targets = [int(pid)]
        for item in processes:
            if item.pid not in targets:
                targets.append(item.pid)
        last_stats = None
        for target in targets:
            if getattr(stop_event, "is_set", lambda: False)():
                break
            memory_keys, data_dirs, last_stats = scan_wechat_process_memory(
                target,
                salts=salts,
                on_status=on_status,
                stop_event=stop_event,
            )
            process = next((item for item in processes if item.pid == target), None)
            if process is not None and last_stats is not None:
                last_stats.process_name = process.name
                last_stats.version = process.version
                last_stats.working_set = process.working_set
            _attach_discovered_data_roots(validator, data_dirs)
            if data_dirs:
                extra_lines.append("内存中的数据目录：" + "；".join(str(item) for item in data_dirs[:3]))
            ordered = [item.key_hex for item in memory_keys if item.salt_hex] + [
                item.key_hex for item in memory_keys if not item.salt_hex
            ]
            extra_lines.append(f"PID {target} 完整密钥串：{len(memory_keys)} 个")
            for candidate in ordered:
                _validate_and_store_candidate(
                    candidate,
                    validator,
                    key_path,
                    on_candidate,
                    on_status,
                    seen,
                    candidates,
                    validated_records,
                )
            if validated_records:
                break
        extra_lines.append(f"验证通过：{len(validated_records)} 个，候选：{len(candidates)} 个")
        if last_stats is not None:
            report = format_memory_scan_report(last_stats, extra_lines)
        else:
            report = "\n".join(["=== Windows 密钥采集探针 ===", *extra_lines])
        log_path = _write_probe_report(key_path, report)
        if log_path is not None:
            extra_lines.append(f"完整日志：{log_path}")
            if last_stats is not None:
                report = format_memory_scan_report(last_stats, extra_lines)
            else:
                report = "\n".join(["=== Windows 密钥采集探针 ===", *extra_lines])
        if not validated_records:
            if not find_sqlcipher_driver() and not find_sqlcipher_executable():
                error = "未找到 SQLCipher，请先执行 python -m pip install -r requirements.txt"
            elif not message_paths and not candidates:
                error = "未找到 message_N.db，也未在内存中找到密钥串。请选择微信数据目录后重试。"
            elif not candidates:
                error = "内存中未出现 WCDB 密钥文本。请把界面里的探针报告发回来。"
            elif not message_paths:
                error = "已找到候选密钥，但未找到 message_N.db。请在第一步选择微信数据目录。"
            else:
                error = f"已扫描到 {len(candidates)} 个候选，但无法打开数据库。请把探针报告发回来。"
    except WindowsProbeError as exc:
        error = redact_output(str(exc))
        report = report or error
    except (OSError, KeyStoreError) as exc:
        error = redact_output(str(exc))
        report = report or error
    except Exception as exc:
        error = "密钥采集过程中发生未预期错误：" + redact_output(type(exc).__name__)
        report = report or error
    finally:
        _notify(on_tick, 0)
    elapsed = time.monotonic() - started
    return CaptureResult(tuple(candidates), tuple(validated_records), elapsed, None, error, report)


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
    try:
        command = ["sudo", "dtrace", "-q", "-n", build_dtrace_program(), "-p", str(int(pid))]
        _notify(on_status, "正在启动 DTrace 密钥采集")
        process = subprocess.Popen(
            command,
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
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
                error = "; ".join(stderr_details[-3:]) or "DTrace 密钥采集进程异常退出"
        _notify(on_tick, 0)
    elapsed = time.monotonic() - started
    return CaptureResult(tuple(candidates), tuple(validated_records), elapsed, returncode, error)


# 返回采集前需要满足的环境条件，供界面展示。
def get_capture_prerequisite() -> tuple[bool | None, str, str]:
    if sys.platform == "win32":
        from windows_memory_probe import is_current_user_admin, list_windows_wechat_processes

        processes = list_windows_wechat_processes()
        admin = is_current_user_admin()
        if processes:
            ok, detail = check_capture_probe(processes[0].pid)
            if ok:
                return True, "读取微信进程内存", "可进行内存密钥采集"
            return False, "读取微信进程内存", detail
        if admin is True:
            return True, "管理员权限", "启动微信后可采集密钥"
        if admin is False:
            return False, "管理员权限", "若采集失败，请以管理员身份运行"
        return None, "读取微信进程内存", "请启动并登录微信 4.x 后再采集"
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
    if sys.platform == "win32":
        from windows_memory_probe import find_windows_wechat_pid

        return find_windows_wechat_pid()
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
    if sys.platform == "win32":
        from windows_memory_probe import find_windows_wechat_version

        return find_windows_wechat_version()
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
    if sys.platform == "win32":
        from windows_memory_probe import list_windows_wechat_processes

        processes = list_windows_wechat_processes()
        if not processes:
            return WeChatStatus(False, None, None, "Weixin.exe", "未检测到微信主进程")
        current = processes[0]
        return WeChatStatus(True, current.pid, current.version, current.executable, "已检测到微信主进程")
    target = Path(executable or WECHAT_EXECUTABLE)
    pid = find_wechat_pid(target)
    version = read_wechat_version(info_plist or WECHAT_INFO_PLIST)
    if pid is None:
        return WeChatStatus(False, None, version, str(target), "未检测到微信主进程")
    return WeChatStatus(True, pid, version, str(target), "已检测到微信主进程")


# 请求启动本机微信客户端。
def launch_wechat() -> tuple[bool, str]:
    if sys.platform == "win32":
        from windows_memory_probe import launch_windows_wechat

        return launch_windows_wechat()
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
