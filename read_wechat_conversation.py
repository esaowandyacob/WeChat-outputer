"""微信 4.x 聊天数据库的只读扫描、解析和导出实现。

这里刻意不把解密后的数据另存为“中间 SQLite”：数据库只在临时目录中
复制后由 SQLCipher 后端查询，消息在 Python 内存中规范化，只有用户明确
选择 SQLite 导出时才会生成导出数据库。

微信 4.x 的 WCDB 表结构会随版本和账号变化，因此本模块采用“表名 + 列名
探测”的策略。已知的 4.x ``Msg_<md5>``、``SessionTable``、``contact``、
``VoiceInfo`` 结构会优先处理，同时保留通用列名兜底。
"""

from __future__ import annotations

import base64
import contextlib
import datetime as _dt
import hashlib
import hmac
import html
import importlib
import json
import mimetypes
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unicodedata
from concurrent.futures import ThreadPoolExecutor
import wave
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Protocol, Sequence
from xml.etree import ElementTree

from cccryptor_probe import DEFAULT_KEY_PATH, KeyRecord, load_key_records, normalize_key_hex


MESSAGE_FILE_RE = re.compile(r"^message_(\d+)\.db$", re.IGNORECASE)
SYSTEM_CONVERSATION_IDS = {
    "filehelper",
    "fmessage",
    "newsapp",
    "notification_messages",
    "notification_center",
    "floatbottle",
    "lbsapp",
    "qqmail",
    "mphelper",
    "brandsession",
    "weixin",
}
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
SILK_MAGIC = b"#!SILK_V3"
WECHAT_SILK_MAGIC = b"\x02#!SILK_V3"
PLAYABLE_AUDIO_MIMES = frozenset({"audio/wav", "audio/x-wav", "audio/mpeg", "audio/ogg", "audio/mp4", "audio/webm"})
SQLCIPHER_PAGE_SIZE = 4096
SQLCIPHER_HMAC_SIZE = 64
SQLCIPHER_SALT_SIZE = 16


class ReaderError(RuntimeError):
    """读取或解析微信数据时的可展示错误。"""


class DatabaseQueryError(ReaderError):
    """SQLCipher/SQLite 查询失败。"""


@dataclass(frozen=True)
class Conversation:
    """会话列表中的一行。"""

    conversation_id: str
    title: str
    recent_time: str
    recent_message: str
    conversation_type: str = "single"
    peer_id: str = ""
    peer_name: str = ""
    table_name: str = ""
    database_path: str = ""
    sort_timestamp: float = 0.0


@dataclass
class MediaRecord:
    """与某条消息关联的媒体字节。"""

    message_id: int
    media_type: str
    mime_type: str
    filename: str
    data: bytes | None = None
    source_path: str | None = None
    playable: bool = False


@dataclass
class MessageRecord:
    """解析后的单条消息；sender 使用稳定 wxid 而不是数据库内部整数。"""

    local_id: int
    server_id: str
    sent_at: str
    sender_wxid: str
    sender_name: str
    message_type: int
    content: str
    quote_sender_wxid: str | None = None
    quote_sender_name: str | None = None
    quote_content: str | None = None
    link_url: str | None = None
    link_title: str | None = None
    link_description: str | None = None
    link_source: str | None = None
    media: list[MediaRecord] = field(default_factory=list)
    raw_timestamp: float = 0.0


@dataclass(frozen=True)
class DatabaseCatalog:
    """从一个账号目录发现的数据库集合。"""

    message_paths: tuple[Path, ...]
    media_paths: tuple[Path, ...]
    contact_paths: tuple[Path, ...]
    session_paths: tuple[Path, ...]
    account_root: Path | None = None
    resource_paths: tuple[Path, ...] = ()
    emoticon_paths: tuple[Path, ...] = ()


class DatabaseBackend(Protocol):
    """SQLCipher 和测试用 SQLite 后端的最小协议。"""

    # 执行只读查询并返回字典行。
    def query(self, sql: str) -> list[dict[str, Any]]: ...

    # 验证 key 是否能读取 sqlite_master 和聊天相关表。
    def validate(self) -> bool: ...

    # 关闭底层连接或释放子进程资源。
    def close(self) -> None: ...


# 将值转成安全的 SQL 字符串字面量，供 CLI 后端构造只读查询。
def sql_literal(value: object) -> str:
    if value is None:
        return "NULL"
    text = str(value).replace("'", "''").replace("\x00", "")
    return f"'{text}'"


# 将数据库表/列名用双引号包裹，避免名称中的引号影响查询。
def sql_identifier(value: str) -> str:
    return '"' + str(value).replace('"', '""') + '"'


# 将命令输出中的敏感样式和过长细节压缩为可展示文本。
def _safe_process_detail(value: bytes | str) -> str:
    text = value.decode(errors="replace") if isinstance(value, bytes) else str(value)
    text = re.sub(r"[0-9a-fA-F]{64}", "***", text)
    return text.strip()[-2000:]


# 从 SQLCipher CLI 混杂输出中提取最后一个 JSON 数组或对象。
def parse_cli_json(raw: bytes | str) -> list[dict[str, Any]]:
    text = raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)
    decoder = json.JSONDecoder()
    candidates: list[tuple[int, Any]] = []
    for index, char in enumerate(text):
        if char not in "[{":
            continue
        try:
            value, end = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, (list, dict)):
            candidates.append((index + end, value))
    if not candidates:
        return []
    value = max(candidates, key=lambda item: item[0])[1]
    if isinstance(value, dict):
        return [dict(value)]
    return [dict(item) for item in value if isinstance(item, dict)]


# 用标准 sqlite3 读取未加密测试库或用户明确提供的明文库。
class SQLiteBackend:
    """只读的标准 SQLite 后端，主要用于明文数据库和自动化测试。"""

    # 初始化一个只读 SQLite 连接。
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        try:
            uri = f"file:{self.path.resolve()}?mode=ro"
            self.connection = sqlite3.connect(uri, uri=True)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA query_only = ON")
        except sqlite3.Error as exc:
            raise DatabaseQueryError("无法打开 SQLite 数据库副本") from exc

    # 执行查询并把 sqlite3.Row 转换为普通字典。
    def query(self, sql: str) -> list[dict[str, Any]]:
        try:
            cursor = self.connection.execute(sql)
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as exc:
            raise DatabaseQueryError("SQLite 查询失败") from exc

    # 检查明文库可以读取 sqlite_master。
    def validate(self) -> bool:
        try:
            rows = self.query("SELECT count(*) AS count FROM sqlite_master")
            return bool(rows)
        except DatabaseQueryError:
            return False

    # 关闭连接。
    def close(self) -> None:
        with contextlib.suppress(sqlite3.Error):
            self.connection.close()


# 生成 SQLCipher 4 解锁语句，优先 raw key，必要时再试 passphrase。
def sqlcipher_key_recipes(key_hex: str, *, mode: str | None = None) -> list[tuple[str, ...]]:
    normalized = normalize_key_hex(key_hex)
    raw = (
        "PRAGMA cipher_compatibility = 4",
        f'PRAGMA key = "x\'{normalized}\'"',
        "PRAGMA query_only = ON",
    )
    raw_legacy = (
        f'PRAGMA key = "x\'{normalized}\'"',
        "PRAGMA cipher_compatibility = 4",
        "PRAGMA query_only = ON",
    )
    passphrase = (
        "PRAGMA cipher_compatibility = 4",
        f"PRAGMA key = '{normalized}'",
        "PRAGMA query_only = ON",
    )
    if mode == "passphrase":
        return [passphrase, raw, raw_legacy]
    if mode == "raw":
        return [raw, raw_legacy]
    return [raw, raw_legacy, passphrase]


# 读取加密库第一页的 16 字节 salt；明文库返回 None。
def read_sqlcipher_salt(path: Path | str) -> bytes | None:
    db_path = Path(path)
    try:
        with db_path.open("rb") as handle:
            header = handle.read(SQLCIPHER_SALT_SIZE)
    except OSError:
        return None
    if len(header) < SQLCIPHER_SALT_SIZE or header.startswith(b"SQLite format 3"):
        return None
    return header


# 用 SQLCipher 4 的 page-1 HMAC 判断 32 字节 raw key 是否匹配。
def sqlcipher4_raw_key_matches(page: bytes, enc_key: bytes) -> bool:
    if len(page) < SQLCIPHER_PAGE_SIZE or len(enc_key) != 32:
        return False
    salt = page[:SQLCIPHER_SALT_SIZE]
    mac_salt = bytes(byte ^ 0x3A for byte in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=32)
    stored = page[-SQLCIPHER_HMAC_SIZE:]
    payload = page[SQLCIPHER_SALT_SIZE : SQLCIPHER_PAGE_SIZE - SQLCIPHER_HMAC_SIZE] + (1).to_bytes(4, "little")
    computed = hmac.new(mac_key, payload, hashlib.sha512).digest()
    return hmac.compare_digest(stored, computed)


# 判断候选是 raw key、passphrase，还是与该数据库不匹配。
def detect_sqlcipher_key_mode(path: Path | str, key_hex: str, *, try_passphrase: bool = False) -> str | None:
    db_path = Path(path)
    try:
        page = db_path.read_bytes()[:SQLCIPHER_PAGE_SIZE]
    except OSError:
        return None
    if len(page) < SQLCIPHER_SALT_SIZE:
        return None
    if page.startswith(b"SQLite format 3"):
        return "plaintext"
    if len(page) < SQLCIPHER_PAGE_SIZE:
        return None
    try:
        normalized = normalize_key_hex(key_hex)
        raw_key = bytes.fromhex(normalized)
    except Exception:
        return None
    if sqlcipher4_raw_key_matches(page, raw_key):
        return "raw"
    if not try_passphrase:
        return None
    derived = hashlib.pbkdf2_hmac("sha512", raw_key, page[:SQLCIPHER_SALT_SIZE], 256000, dklen=32)
    if sqlcipher4_raw_key_matches(page, derived):
        return "passphrase"
    derived_text = hashlib.pbkdf2_hmac("sha512", normalized.encode("ascii"), page[:SQLCIPHER_SALT_SIZE], 256000, dklen=32)
    if sqlcipher4_raw_key_matches(page, derived_text):
        return "passphrase"
    return None


# 在 SQLCipher Python 驱动可用时执行查询，避免每条消息启动 CLI。
class PythonSQLCipherBackend:
    """兼容 sqlcipher3 与 pysqlcipher3 的 Python 后端。"""

    # 打开 SQLCipher 连接并设置 4.x cipher 参数。
    def __init__(self, path: Path | str, key_hex: str, driver: Any) -> None:
        self.path = Path(path)
        self.key_hex = normalize_key_hex(key_hex)
        mode = detect_sqlcipher_key_mode(self.path, self.key_hex)
        last_error: Exception | None = None
        for statements in sqlcipher_key_recipes(self.key_hex, mode=mode):
            connection = None
            try:
                # Windows 上 file:C:\... URI 会打开错误路径，导致所有候选都验证失败。
                connection = driver.connect(str(self.path))
                for statement in statements:
                    connection.execute(statement)
                probe = connection.execute("SELECT count(*) FROM sqlite_master").fetchall()
                tables = connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
                if probe and tables:
                    self.connection = connection
                    return
            except Exception as exc:
                last_error = exc
            if connection is not None:
                with contextlib.suppress(Exception):
                    connection.close()
        raise DatabaseQueryError("SQLCipher 无法打开数据库副本") from last_error

    # 执行查询并把行转换为字典，不把 key 放入异常文本。
    def query(self, sql: str) -> list[dict[str, Any]]:
        try:
            cursor = self.connection.execute(sql)
            names = [item[0] for item in (cursor.description or [])]
            return [dict(zip(names, row)) for row in cursor.fetchall()]
        except Exception:
            raise DatabaseQueryError("SQLCipher 查询失败") from None

    # 验证 sqlite_master 与消息表是否可读。
    def validate(self) -> bool:
        try:
            rows = self.query("SELECT count(*) AS count FROM sqlite_master")
            if not rows:
                return False
            table_rows = self.query(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
            return bool(table_rows)
        except DatabaseQueryError:
            return False

    # 关闭 SQLCipher 连接。
    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.connection.close()


# 使用 sqlcipher 命令行执行单次查询；标准输出按 bytes 接收后再容错解码。
class SQLCipherCLIBackend:
    """不依赖 Python 扩展的 SQLCipher 4 CLI 后端。"""

    # 保存数据库路径、密钥和可执行文件路径。
    def __init__(self, path: Path | str, key_hex: str, executable: Path | str = "sqlcipher") -> None:
        self.path = Path(path)
        self.key_hex = normalize_key_hex(key_hex)
        self.executable = str(executable)

    # 通过 stdin 注入 key 和查询脚本，避免 key 出现在进程参数中。
    def query(self, sql: str) -> list[dict[str, Any]]:
        query = sql.strip().rstrip(";")
        if not query:
            return []
        mode = detect_sqlcipher_key_mode(self.path, self.key_hex)
        pragmas = "\n".join(f"{item};" for item in sqlcipher_key_recipes(self.key_hex, mode=mode)[0])
        script = (
            ".bail on\n"
            ".mode json\n"
            ".headers on\n"
            # PRAGMA key 会输出 [{"ok":"ok"}]。查询结果为空时它会被当成结果行，所以丢掉 pragma 的输出。
            ".output /dev/null\n"
            f"{pragmas}\n"
            ".output stdout\n"
            f"{query};\n"
            ".quit\n"
        ).encode("utf-8")
        try:
            completed = subprocess.run(
                [self.executable, str(self.path)],
                input=script,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise DatabaseQueryError("无法启动 SQLCipher，请安装 sqlcipher 命令行工具") from None
        if completed.returncode != 0:
            detail = _safe_process_detail(completed.stderr)
            raise DatabaseQueryError("SQLCipher 查询失败" + (f"：{detail}" if detail else ""))
        return parse_cli_json(completed.stdout)

    # 读取 sqlite_master 并确认数据库不是错误 key 导致的伪成功。
    def validate(self) -> bool:
        try:
            rows = self.query("SELECT count(*) AS count FROM sqlite_master")
            if not rows:
                return False
            tables = self.query(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
            return bool(tables)
        except DatabaseQueryError:
            return False

    # CLI 后端没有长连接需要关闭。
    def close(self) -> None:
        return None


# 查找本机可用的 SQLCipher CLI，优先环境变量和 PATH。
def find_sqlcipher_executable() -> str | None:
    configured = os.environ.get("SQLCIPHER_BIN", "").strip()
    candidates = []
    if configured:
        candidates.extend([configured, shutil.which(configured) or ""])
    candidates.extend(
        [
            shutil.which("sqlcipher") or "",
            shutil.which("sqlcipher.exe") or "",
            "/opt/homebrew/bin/sqlcipher",
            "/usr/local/bin/sqlcipher",
            "/opt/local/bin/sqlcipher",
            str(Path(sys.prefix) / "Library" / "bin" / "sqlcipher.exe"),
            str(Path(sys.prefix) / "bin" / "sqlcipher.exe"),
            str(Path(sys.prefix) / "Scripts" / "sqlcipher.exe"),
        ]
    )
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


# 尝试导入 SQLCipher Python 驱动；导入失败时返回 None 而不泄露环境细节。
def find_sqlcipher_driver() -> Any | None:
    for module_name in ("sqlcipher3.dbapi2", "pysqlcipher3.dbapi2"):
        try:
            return importlib.import_module(module_name)
        except Exception:
            continue
    return None


# 根据文件头和可用后端打开数据库副本。
def open_database_backend(
    path: Path | str,
    key_hex: str,
    *,
    executable: Path | str | None = None,
) -> DatabaseBackend:
    db_path = Path(path)
    try:
        with db_path.open("rb") as handle:
            header = handle.read(16)
    except OSError as exc:
        raise DatabaseQueryError("无法读取数据库副本") from exc
    if header.startswith(b"SQLite format 3\x00"):
        return SQLiteBackend(db_path)
    driver = find_sqlcipher_driver()
    if driver is not None:
        try:
            return PythonSQLCipherBackend(db_path, key_hex, driver)
        except DatabaseQueryError:
            # 某些环境能导入普通 sqlite 兼容模块但未编译 SQLCipher，继续尝试 CLI。
            pass
    binary = str(executable) if executable is not None else find_sqlcipher_executable()
    if binary is None:
        raise DatabaseQueryError("未找到 SQLCipher 后端；请安装 sqlcipher 或 sqlcipher3")
    return SQLCipherCLIBackend(db_path, key_hex, binary)


# 复制一个数据库及其 WAL/SHM 伴随文件到临时目录，绝不修改原文件。
def copy_database_snapshot(source: Path | str, destination_dir: Path | str) -> Path:
    source_path = Path(source).expanduser()
    destination = Path(destination_dir).expanduser()
    if source_path.is_symlink():
        source_path = source_path.resolve()
    if not source_path.is_file():
        raise ReaderError("数据库文件不存在或不可读")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = destination / source_path.name
    last_error: Exception | None = None
    for _attempt in range(2):
        try:
            before = source_path.stat()
            shutil.copy2(source_path, target)
            after = source_path.stat()
            if before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns:
                break
        except OSError as exc:
            last_error = exc
    else:
        if last_error is not None:
            raise ReaderError("无法复制数据库副本") from last_error
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    for suffix in ("-wal", "-shm"):
        companion = Path(str(source_path) + suffix)
        if not companion.is_file():
            continue
        companion_target = Path(str(target) + suffix)
        try:
            shutil.copy2(companion, companion_target)
            try:
                os.chmod(companion_target, 0o600)
            except OSError:
                pass
        except OSError:
            # WAL 在 checkpoint 时可能瞬间消失；主库副本仍可继续尝试读取。
            continue
    return target


# 在临时目录中复制一组数据库，并在离开上下文时清理所有副本。
# 提供自动清理临时数据库快照的上下文管理器。
@contextlib.contextmanager
# 复制一组数据库并在退出时清理临时目录。
def database_snapshot(paths: Iterable[Path | str]) -> Iterator[dict[Path, Path]]:
    unique_paths: list[Path] = []
    seen: set[Path] = set()
    for raw_path in paths:
        path = Path(raw_path).expanduser()
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique_paths.append(path)
    with tempfile.TemporaryDirectory(prefix="wechat-export-") as temporary:
        destination = Path(temporary)
        mapping: dict[Path, Path] = {}
        for index, source in enumerate(unique_paths):
            # 每个源文件使用独立子目录，避免多个账号存在同名 message_0.db 时互相覆盖。
            source_destination = destination / f"db_{index:03d}"
            mapping[source] = copy_database_snapshot(source, source_destination)
        yield mapping


# 返回当前平台常见的微信 4.x 数据根目录。
def default_wechat_data_roots(home: Path | None = None) -> list[Path]:
    home_path = home if home is not None else Path.home()
    env_root = os.environ.get("WECHAT_DATA_ROOT", "").strip()
    roots: list[Path] = []
    if env_root:
        roots.append(Path(env_root).expanduser())
    roots.extend(
        [
            home_path / "Library" / "Containers" / "com.tencent.xinWeChat" / "Data" / "Documents" / "xwechat_files",
            home_path
            / "Library"
            / "Containers"
            / "com.tencent.xinWeChat"
            / "Data"
            / "Library"
            / "Application Support"
            / "com.tencent.xinWeChat",
            home_path / "Library" / "Application Support" / "com.tencent.xinWeChat",
        ]
    )
    return roots


# 在一组根目录中扫描严格命名为 message_N.db 的消息分片。
def _scan_message_databases(roots: Iterable[Path]) -> list[Path]:
    discovered: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        try:
            root_resolved = root.resolve()
        except OSError:
            root_resolved = root
        if root.is_file():
            candidates = [root]
        elif root.is_dir():
            try:
                candidates = list(root.rglob("message_*.db"))
            except OSError:
                candidates = []
        else:
            continue
        for candidate in candidates:
            if not MESSAGE_FILE_RE.fullmatch(candidate.name):
                continue
            try:
                resolved = candidate.resolve()
                if root.is_dir():
                    resolved.relative_to(root_resolved)
                if not resolved.is_file() or resolved in seen:
                    continue
            except (OSError, ValueError):
                continue
            seen.add(resolved)
            discovered.append(resolved)
    return discovered


# 从给定根目录扫描严格命名为 message_N.db 的消息分片。
def discover_message_databases(data_root: Path | str | None = None, home: Path | None = None) -> list[Path]:
    if data_root is not None:
        roots = [Path(data_root).expanduser()]
    else:
        roots = default_wechat_data_roots(home)
    discovered = _scan_message_databases(roots)
    return sorted(
        discovered,
        key=lambda item: (str(item.parent), int(MESSAGE_FILE_RE.fullmatch(item.name).group(1) or 0)),
    )


# 从消息库路径推导 4.x 账号根目录和相邻数据库路径。
def _account_root_for_message(path: Path) -> Path:
    for parent in path.parents:
        if parent.name == "db_storage":
            return parent.parent
    return path.parent


# 按常见 4.x 布局发现 contact、session、media 数据库。
def build_database_catalog(message_paths: Iterable[Path | str]) -> DatabaseCatalog:
    messages = tuple(sorted({Path(item).resolve() for item in message_paths}))
    if not messages:
        return DatabaseCatalog((), (), (), (), None)
    account_root = _account_root_for_message(messages[0])
    db_storage = next((parent for parent in messages[0].parents if parent.name == "db_storage"), messages[0].parent)
    search_roots = [db_storage, messages[0].parent, account_root]
    media: set[Path] = set()
    contacts: set[Path] = set()
    sessions: set[Path] = set()
    resources: set[Path] = set()
    emoticons: set[Path] = set()
    for root in search_roots:
        for relative in (Path("message") / "media_0.db", Path("message") / "media_1.db", Path("media_0.db")):
            candidate = root / relative
            if candidate.is_file():
                media.add(candidate.resolve())
        for relative in (Path("contact") / "contact.db", Path("contact.db")):
            candidate = root / relative
            if candidate.is_file():
                contacts.add(candidate.resolve())
        for relative in (Path("session") / "session.db", Path("session.db")):
            candidate = root / relative
            if candidate.is_file():
                sessions.add(candidate.resolve())
        for relative in (
            Path("message") / "message_resource.db",
            Path("message_resource.db"),
            Path("message") / "hardlink.db",
        ):
            candidate = root / relative
            if candidate.is_file():
                resources.add(candidate.resolve())
        candidate = root / "emoticon" / "emoticon.db"
        if candidate.is_file():
            emoticons.add(candidate.resolve())
    # 兼容多个 media_N.db，仍只接受明确的 media_N 命名。
    for candidate in db_storage.rglob("media_*.db") if db_storage.is_dir() else []:
        if re.fullmatch(r"media_\d+\.db", candidate.name, re.IGNORECASE):
            media.add(candidate.resolve())
    return DatabaseCatalog(
        messages,
        tuple(sorted(media)),
        tuple(sorted(contacts)),
        tuple(sorted(sessions)),
        account_root,
        tuple(sorted(resources)),
        tuple(sorted(emoticons)),
    )


# 将列名统一为不含下划线的大小写形式，兼容 camelCase 与 snake_case schema。
def normalized_field_name(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).casefold())


# 不区分大小写读取字典行中的列值，并兼容 sqlite3.Row。
def row_value(row: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    try:
        items = row.items()
    except AttributeError:
        keys = getattr(row, "keys", lambda: ())()
        items = ((key, row[key]) for key in keys)
    lowered = {normalized_field_name(key): value for key, value in items}
    for name in names:
        normalized_name = normalized_field_name(name)
        if normalized_name in lowered and lowered[normalized_name] is not None:
            return lowered[normalized_name]
    return default


# 将字典行、sqlite3.Row 或兼容对象统一转换为普通字典。
def row_dict(row: Any) -> dict[str, Any]:
    try:
        return {str(key): value for key, value in row.items()}
    except AttributeError:
        keys = getattr(row, "keys", lambda: ())()
        return {str(key): row[key] for key in keys}


# 将数据库中的文本或 BLOB 值转换为可比较的 Unicode 文本。
def text_value(value: object, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace").replace("\x00", "").strip() or default
    text = str(value).replace("\x00", "").strip()
    return text or default


# 返回表的列名，供运行时构造兼容查询。
def table_columns(database: DatabaseBackend, table: str) -> list[str]:
    rows = database.query(f"PRAGMA table_info({sql_identifier(table)})")
    result: list[str] = []
    for row in rows:
        value = row_value(row, "name")
        if value is not None:
            result.append(text_value(value))
    return result


# 读取用户可查询的表名，排除 SQLite 内部表。
def table_names(database: DatabaseBackend) -> list[str]:
    rows = database.query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    return [text_value(row_value(row, "name")) for row in rows if text_value(row_value(row, "name"))]


# 在列名列表中选择第一个匹配候选。
def choose_column(columns: Sequence[str], candidates: Sequence[str]) -> str | None:
    mapping = {normalized_field_name(column): column for column in columns}
    for candidate in candidates:
        normalized_candidate = normalized_field_name(candidate)
        if normalized_candidate in mapping:
            return mapping[normalized_candidate]
    return None


# 识别微信 4.x 的 Msg_<md5> 表以及具备消息列的通用表。
def find_message_tables(database: DatabaseBackend) -> list[str]:
    result: list[tuple[int, str]] = []
    for table in table_names(database):
        lowered = table.casefold()
        if lowered.startswith("msg_"):
            result.append((100, table))
            continue
        try:
            columns = {normalized_field_name(column) for column in table_columns(database, table)}
        except DatabaseQueryError:
            continue
        score = 0
        if {normalized_field_name(item) for item in ("local_id", "meslocalid", "msg_local_id", "id")} & columns:
            score += 3
        if {normalized_field_name(item) for item in ("create_time", "createtime", "timestamp")} & columns:
            score += 2
        if {normalized_field_name(item) for item in ("message_content", "message", "content", "text")} & columns:
            score += 2
        if {normalized_field_name(item) for item in ("local_type", "type", "message_type")} & columns:
            score += 1
        if score >= 5:
            result.append((score, table))
    return [table for _score, table in sorted(result, key=lambda item: (-item[0], item[1].casefold()))]


# 把微信常见的秒、毫秒、微秒时间戳转换成排序用浮点秒。
def timestamp_seconds(value: object) -> float:
    if value is None or value == "":
        return 0.0
    if isinstance(value, _dt.datetime):
        parsed = value if value.tzinfo is not None else value.replace(tzinfo=_dt.datetime.now().astimezone().tzinfo)
        return parsed.timestamp()
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            value = bytes(value).decode("utf-8", errors="ignore")
        except Exception:
            return 0.0
    try:
        number = float(value)
    except (TypeError, ValueError):
        text = str(value).strip()
        try:
            parsed = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return 0.0
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.datetime.now().astimezone().tzinfo)
        return parsed.timestamp()
    magnitude = abs(number)
    if magnitude > 10**17:
        return number / 1_000_000_000
    if magnitude > 10**14:
        return number / 1_000_000
    if magnitude > 10**11:
        return number / 1_000
    return number


# 将时间戳格式化为用户本地时间，未知时间返回空字符串。
def format_timestamp(value: object) -> str:
    seconds = timestamp_seconds(value)
    if seconds <= 0:
        return ""
    try:
        return _dt.datetime.fromtimestamp(seconds).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


# 从字符串或二进制中解码 UTF-8，必要时尝试 zstandard/zlib 压缩。
def decode_message_content(value: object, compression_type: object = None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.replace("\x00", "").strip()
    if isinstance(value, memoryview):
        raw = value.tobytes()
    elif isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        return str(value).replace("\x00", "").strip()
    attempts: list[bytes] = [raw]
    should_decompress = (
        bool(compression_type not in (None, "", 0, "0", False))
        or raw.startswith(ZSTD_MAGIC)
        or raw[:2] in {b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"}
    )
    if should_decompress:
        try:
            import zstandard

            attempts.insert(0, zstandard.ZstdDecompressor().decompress(raw, max_output_size=32 * 1024 * 1024))
        except Exception:
            pass
        try:
            attempts.insert(0, zlib.decompress(raw))
        except zlib.error:
            pass
    for candidate in attempts:
        try:
            text = candidate.decode("utf-8")
        except UnicodeDecodeError:
            continue
        cleaned = text.replace("\x00", "").strip()
        readable_count = sum(char.isprintable() or char in "\r\n\t" for char in cleaned)
        if cleaned and readable_count / max(1, len(cleaned)) >= 0.85:
            return cleaned
    # 二进制中偶尔仍包含可读 XML/正文，只抽取连续可打印 UTF-8 片段。
    printable = re.findall(rb"[\x20-\x7e\x80-\xff]{3,}", raw)
    if printable:
        candidate = max((part.decode("utf-8", errors="ignore") for part in printable), key=len).strip()
        readable_count = sum(char.isprintable() or char in "\r\n\t" for char in candidate)
        if candidate and readable_count / max(1, len(candidate)) >= 0.85:
            return candidate
    return ""


# 解析 XML 文本并返回指定标签的首个非空文本。
def xml_text(root: ElementTree.Element | None, *paths: str) -> str:
    if root is None:
        return ""
    for path in paths:
        node = root.find(path)
        if node is not None and node.text:
            value = node.text.strip()
            if value:
                return value
    return ""


# 从 XML 根节点及其子节点属性中读取第一个非空值。
def xml_attribute(root: ElementTree.Element | None, *names: str) -> str:
    if root is None:
        return ""
    wanted = {name.casefold() for name in names}
    for node in root.iter():
        for key, value in node.attrib.items():
            if key.casefold() in wanted and str(value).strip():
                return str(value).strip()
    return ""


# 从 appmsg/location/card XML 中提取标题、描述、链接和来源。
def parse_message_xml(content: str) -> dict[str, str]:
    if isinstance(content, (bytes, bytearray, memoryview)):
        content = decode_message_content(content)
    else:
        content = str(content or "")
    if not content:
        return {}
    if "&lt;" in content.casefold() or "&gt;" in content.casefold():
        content = html.unescape(content)
    if "<" not in content or ">" not in content:
        return {}
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError:
        # 微信有时把 XML 包在前缀文本后面，尝试截取根元素。
        match = re.search(r"(<appmsg\b.*</appmsg>|<location\b.*?/?>|<msg\b.*</msg>)", content, re.I | re.S)
        if not match:
            return {}
        try:
            root = ElementTree.fromstring(match.group(1))
        except ElementTree.ParseError:
            return {}
    values = {
        "title": xml_text(root, "./title", ".//title", ".//appattach/title"),
        "description": xml_text(root, "./des", "./description", ".//des", ".//description"),
        "url": xml_text(root, "./url", ".//url"),
        "source": xml_text(root, "./appname", "./source", ".//appname", ".//source"),
        "appmsg_type": xml_text(root, "./type", ".//type"),
        "nickname": xml_text(root, "./nickname", ".//nickname") or xml_attribute(root, "nickname"),
        "location": xml_text(root, "./label", ".//label", "./poiname", ".//poiname") or xml_attribute(root, "label", "poiname", "address"),
        "duration": xml_text(root, "./duration", ".//duration", "./voipmsg/duration") or xml_attribute(root, "duration", "voipduration"),
        "file": xml_text(root, "./appattach/title", ".//appattach/title", "./title"),
        "refer_sender": xml_text(root, "./refermsg/displayname", ".//refermsg/displayname"),
        "refer_user": xml_text(root, "./refermsg/chatusr", ".//refermsg/chatusr"),
        "refer_content": xml_text(root, "./refermsg/content", ".//refermsg/content"),
        "system": xml_text(root, "./template", ".//template", ".//text"),
    }
    return {key: value for key, value in values.items() if value}


# 去掉标签和 CDATA 包装，只留下可读文字。
def _strip_markup(text: str) -> str:
    text = re.sub(r"<!\[CDATA\[(.*?)\]\]>", r"\1", text, flags=re.S)
    text = re.sub(r"<[^>]*>", "", text)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


# 系统消息转成纯文字：展开 sysmsgtemplate 的 $name$ 占位符，去掉 <_wc_custom_link_> 等标签。
def system_message_text(content: str) -> str:
    text = str(content or "")
    if "&lt;" in text and "<" not in text:
        text = html.unescape(text)
    # 群里的系统消息正文前面带 “xxx@chatroom:\n”。
    prefixed = re.match(r"^[A-Za-z0-9_.@-]{2,128}:\s*\n(?=\s*<)", text)
    if prefixed:
        text = text[prefixed.end():]
    start = text.find("<sysmsg")
    if start >= 0:
        end = text.rfind("</sysmsg>")
        xml = text[start:end + len("</sysmsg>")] if end > start else text[start:]
        try:
            root = ElementTree.fromstring(xml)
        except ElementTree.ParseError:
            root = None
        if root is not None:
            template = root.find(".//content_template")
            if template is not None:
                body = template.findtext("template") or template.findtext("plain") or ""
                for link in template.iter("link"):
                    name = link.get("name") or ""
                    nicknames = [
                        (member.findtext("nickname") or member.findtext("username") or "").strip()
                        for member in link.iter("member")
                    ]
                    value = "、".join(item for item in nicknames if item) or (link.findtext(".//plain") or "").strip()
                    body = body.replace(f"${name}$", value)
                return _strip_markup(body)
            for path in (".//revokemsg/replacemsg", ".//revokemsg", ".//template", ".//text", ".//content"):
                found = root.find(path)
                if found is not None:
                    value = _strip_markup("".join(found.itertext()))
                    if value:
                        return value
            return _strip_markup("".join(root.itertext()))
    return _strip_markup(text)


# 从正文前缀中提取稳定 wxid，并移除“wxid:\n”包装。
def extract_sender_prefix(content: str) -> tuple[str | None, str]:
    content = str(content or "")
    match = re.match(r"^([A-Za-z0-9_.@-]{2,128}):\s*\n(.*)$", content, re.S)
    if not match:
        return None, content
    candidate = match.group(1)
    if candidate.startswith(("http", "https")):
        return None, content
    return candidate, match.group(2)


# 读取联系人字段里的第一段非空文本。
def _contact_text(row: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = row_value(row, key, default="")
        if isinstance(value, (bytes, bytearray, memoryview)):
            value = bytes(value).decode("utf-8", errors="replace")
        text = str(value).replace("\x00", "").strip()
        if text:
            return text
    return ""


# 账号目录名 wxid_xxx_a9d3 和库里的 wxid_xxx 是同一个人。
def owner_aliases(self_wxid: str) -> set[str]:
    owner = str(self_wxid or "")
    aliases: set[str] = set()
    if not owner or owner == "self":
        if owner == "self":
            aliases.add("self")
        return aliases
    aliases.add(owner)
    short, separator, tail = owner.rpartition("_")
    if separator and short.startswith("wxid_") and re.fullmatch(r"[0-9a-fA-F]{4}", tail):
        aliases.add(short)
    return aliases


# 判断一个 wxid 是不是当前导出账号自己。
def is_account_owner(wxid: str, self_wxid: str = "") -> bool:
    value = str(wxid or "")
    if not value:
        return False
    if value == "self" and (not self_wxid or self_wxid == "self"):
        return True
    return value in owner_aliases(self_wxid)


# 在原名后面附上备注。没有备注或备注与原名相同时保持原名。
def _with_remark(base: str, contact: Mapping[str, Any], group: Mapping[str, Any]) -> str:
    remark = _contact_text(contact, "remark") or _contact_text(group, "remark")
    if remark and remark != base:
        return f"{base}（{remark}）"
    return base


# 生成会话和发送者的显示名：群名或昵称在前，备注放在括号里。
def preferred_display_name(
    wxid: str,
    contact: Mapping[str, Any] | None = None,
    group: Mapping[str, Any] | None = None,
) -> str:
    wxid = str(wxid or "")
    contact = contact or {}
    group = group or {}
    if wxid.casefold().endswith("@chatroom"):
        for key in (
            "group_name",
            "room_name",
            "chat_name",
            "display_name",
            "displayname",
            "nick_name",
            "alias",
            "nickname",
            "name",
        ):
            base = _contact_text(group, key) or _contact_text(contact, key)
            if base:
                return _with_remark(base, contact, group)
    for key in ("nick_name", "alias", "nickname", "display_name", "displayname"):
        base = _contact_text(contact, key)
        if base:
            return _with_remark(base, contact, group)
    return _with_remark(wxid or "未知用户", contact, group)


# 过滤明显的公众号、服务通知和系统会话，保留普通单聊与群聊。
def is_system_conversation(conversation_id: str, title: str = "") -> bool:
    value = str(conversation_id or "").strip().casefold()
    title_value = str(title or "").strip().casefold()
    if value.endswith("@chatroom"):
        return False
    if value in SYSTEM_CONVERSATION_IDS:
        return True
    if value.startswith(("gh_", "weixin_notify", "notification_", "service_")):
        return True
    if "公众号" in title_value or "服务通知" in title_value or "系统通知" in title_value:
        return True
    if value.endswith("@app") or value.endswith("@openim"):
        return True
    return False


# 将任意对象转换成稳定的非负整数消息 ID。
def integer_id(value: object, fallback: int = 0) -> int:
    if isinstance(value, (bytes, bytearray, memoryview)):
        value = bytes(value).decode("utf-8", errors="ignore")
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


# 根据消息类型、XML 和正文生成规范化占位符及链接字段。
def classify_message(
    message_type: int,
    content: str,
    xml_values: Mapping[str, str],
) -> tuple[str, str | None, str | None, str | None, str | None]:
    lowered = content.casefold()
    if "<emoji" in lowered or message_type in {47, 8_000_000} or "[表情]" in content:
        return "[表情]", None, None, None, None
    link_url = xml_values.get("url") or None
    link_title = xml_values.get("title") or None
    link_description = xml_values.get("description") or None
    link_source = xml_values.get("source") or None
    if message_type in {3, 1048625} or "[图片]" in content:
        return "[图片]", None, None, None, None
    if message_type in {34, 53} or "voipmsg" in lowered or "语音通话" in content:
        duration = xml_values.get("duration", "")
        suffix = f"：{duration}秒" if duration and re.fullmatch(r"\d+(?:\.\d+)?", duration) else ""
        return f"[语音通话{suffix}]", None, None, None, None
    if message_type in {43, 62, 44} or "[视频]" in content:
        return "[视频]", None, None, None, None
    if message_type in {47, 8_000_000} or "[表情]" in content:
        return "[表情]", None, None, None, None
    if message_type in {48} or "<location" in lowered:
        location = xml_values.get("location") or link_title or ""
        return f"[位置：{location}]" if location else "[位置]", None, None, None, None
    if message_type in {42} or "<br type=\"6\"" in lowered:
        nickname = xml_values.get("nickname") or xml_values.get("title") or ""
        return f"[名片：{nickname}]" if nickname else "[名片]", None, None, None, None
    if message_type in {49} or "<appmsg" in lowered:
        file_name = xml_values.get("file", "")
        if file_name and "appattach" in lowered and not link_url:
            return f"[文件：{file_name}]", None, None, None, None
        if "miniprogram" in lowered or xml_values.get("appmsg_type") in {"33", "34"}:
            return f"[小程序：{link_title}]" if link_title else "[小程序]", link_url, link_title, link_description, link_source
        if link_url or link_title or link_description:
            return link_title or "[链接]", link_url, link_title, link_description, link_source
        return "[应用消息]", link_url, link_title, link_description, link_source
    if message_type in {10000, 10002, 51} or "撤回" in content or "<sysmsg" in lowered or "revokemsg" in lowered:
        system_content = system_message_text(content)
        return f"[系统消息] {system_content}" if system_content else "[系统消息]", None, None, None, None
    if content:
        return content, link_url, link_title, link_description, link_source
    return "[未知消息]", link_url, link_title, link_description, link_source


# 规范化语音字节并识别浏览器可播放格式。
def normalize_audio_bytes(data: bytes) -> tuple[bytes, str, str, bool]:
    if data.startswith(WECHAT_SILK_MAGIC) or (len(data) > len(SILK_MAGIC) and data[1:].startswith(SILK_MAGIC)):
        return data[1:], "audio/silk", ".silk", False
    if data.startswith(SILK_MAGIC):
        return data, "audio/silk", ".silk", False
    if data.startswith(b"RIFF") and b"WAVE" in data[:16]:
        return data, "audio/wav", ".wav", True
    if data.startswith(b"ID3") or data[0:2] in {b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"}:
        return data, "audio/mpeg", ".mp3", True
    if data.startswith(b"OggS"):
        return data, "audio/ogg", ".ogg", True
    return data, "application/octet-stream", ".bin", False


# 使用可选 pysilk 或 ffmpeg 将 SILK 转换为浏览器可播放 WAV。
def decode_silk_to_wav(data: bytes) -> bytes | None:
    silk_data, _mime, _extension, _playable = normalize_audio_bytes(data)
    if not silk_data.startswith(SILK_MAGIC):
        return data if _playable else None
    try:
        pysilk = importlib.import_module("pysilk")
        decoder = getattr(pysilk, "decode", None)
        if callable(decoder):
            pcm = decoder(silk_data)
            if isinstance(pcm, tuple):
                pcm = pcm[0]
            if isinstance(pcm, (bytes, bytearray)):
                output = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
                output_path = Path(output.name)
                output.close()
                try:
                    with wave.open(str(output_path), "wb") as wav_file:
                        wav_file.setnchannels(1)
                        wav_file.setsampwidth(2)
                        wav_file.setframerate(24000)
                        wav_file.writeframes(bytes(pcm))
                    return output_path.read_bytes()
                finally:
                    output_path.unlink(missing_ok=True)
    except Exception:
        pass
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        return None
    with tempfile.TemporaryDirectory(prefix="wechat-silk-") as temporary:
        root = Path(temporary)
        source = root / "voice.silk"
        target = root / "voice.wav"
        source.write_bytes(silk_data)
        try:
            completed = subprocess.run(
                [ffmpeg, "-v", "error", "-y", "-f", "silk", "-i", str(source), str(target)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if completed.returncode == 0 and target.is_file():
            try:
                return target.read_bytes()
            except OSError:
                return None
    return None


# 根据相对/绝对文件名生成不会越出导出目录的安全文件名。
def safe_filename(value: str, fallback: str = "file") -> str:
    normalized = unicodedata.normalize("NFKC", str(value or "")).strip()
    normalized = normalized.replace("/", "_").replace("\\", "_")
    normalized = re.sub(r"[^\w.()\-\u4e00-\u9fff ]+", "_", normalized, flags=re.UNICODE)
    normalized = re.sub(r"\s+", "_", normalized).strip("._")
    return (normalized[:120] or fallback)


# 读取媒体数据库中的 VoiceInfo/Name2Id 记录并返回语音二进制。
def find_voice_data(
    database: DatabaseBackend,
    conversation_id: str,
    local_id: int,
    server_id: str,
    create_time: object,
) -> bytes | None:
    names = table_names(database)
    voice_table = next((name for name in names if normalized_field_name(name) == "voiceinfo"), None)
    if voice_table is None:
        voice_table = next(
            (name for name in names if "voice" in name.casefold() and choose_column(table_columns(database, name), ("voice_data", "data"))),
            None,
        )
    if voice_table is None:
        return None
    columns = table_columns(database, voice_table)
    data_column = choose_column(columns, ("voice_data", "data", "voice", "content"))
    local_column = choose_column(columns, ("local_id", "msg_local_id", "meslocalid", "message_id"))
    server_column = choose_column(columns, ("svr_id", "server_id", "messvrid"))
    time_column = choose_column(columns, ("create_time", "createtime", "timestamp"))
    chat_column = choose_column(columns, ("chat_name_id", "chat_id", "name_id"))
    if not data_column:
        return None
    wanted_time = timestamp_seconds(create_time)
    wanted_server = str(server_id or "")
    wanted_chat_ids: set[str] = set()
    name_table = next((name for name in names if normalized_field_name(name) == "name2id"), None)
    if name_table:
        name_columns = table_columns(database, name_table)
        user_column = choose_column(name_columns, ("user_name", "username", "chat_name", "name"))
        name_id_column = choose_column(name_columns, ("id", "name_id", "chat_name_id", "local_id"))
        if user_column:
            try:
                id_expression = sql_identifier(name_id_column) if name_id_column else "rowid"
                name_rows = database.query(
                    f"SELECT {id_expression} AS __name_id, {sql_identifier(user_column)} AS __user_name FROM {sql_identifier(name_table)} LIMIT 100000"
                )
            except DatabaseQueryError:
                try:
                    name_rows = database.query(
                        f"SELECT {sql_identifier(user_column)} AS __user_name FROM {sql_identifier(name_table)} LIMIT 100000"
                    )
                except DatabaseQueryError:
                    name_rows = []
            for row in name_rows:
                user_name = decode_message_content(row_value(row, "__user_name", default=""))
                if user_name == conversation_id:
                    identifier = decode_message_content(row_value(row, "__name_id", default=""))
                    if identifier:
                        wanted_chat_ids.add(identifier)
    # 不能把 local_id、server_id、会话 id 用 OR 拼在一起，否则别的消息的语音会贴到这条上。
    conditions: list[str] = []
    if server_column and wanted_server not in {"", "0", "None"}:
        conditions.append(f"{sql_identifier(server_column)} = {sql_literal(wanted_server)}")
    elif local_column and local_id:
        local_match = f"{sql_identifier(local_column)} = {sql_literal(local_id)}"
        if chat_column and wanted_chat_ids:
            chat_match = "(" + " OR ".join(
                f"{sql_identifier(chat_column)} = {sql_literal(item)}" for item in wanted_chat_ids
            ) + ")"
            conditions.append(f"{local_match} AND {chat_match}")
        else:
            conditions.append(local_match)
    if not conditions:
        return None
    select_parts = [f"hex({sql_identifier(data_column)}) AS __voice_hex"]
    for alias, column in (("local", local_column), ("server", server_column), ("time", time_column), ("chat", chat_column)):
        select_parts.append(f"{sql_identifier(column)} AS __{alias}" if column else f"NULL AS __{alias}")
    where_clause = " OR ".join(conditions)
    rows = database.query(
        f"SELECT {', '.join(select_parts)} FROM {sql_identifier(voice_table)} WHERE {where_clause} LIMIT 10000"
    )
    best: tuple[int, bytes] | None = None
    for row in rows:
        encoded = str(row_value(row, "__voice_hex", default="") or "")
        if not encoded or len(encoded) % 2:
            continue
        try:
            data = bytes.fromhex(encoded)
        except ValueError:
            continue
        # 某些导出器把 VoiceInfo 的 BLOB 先存成 ASCII hex，再由 hex() 返回一次。
        if len(data) % 2 == 0 and re.fullmatch(rb"[0-9a-fA-F]+", data):
            with contextlib.suppress(ValueError):
                data = bytes.fromhex(data.decode("ascii"))
        score = 0
        row_local = row_value(row, "__local")
        row_server = decode_message_content(row_value(row, "__server", default="") or "")
        row_time = timestamp_seconds(row_value(row, "__time"))
        row_chat = decode_message_content(row_value(row, "__chat", default="") or "")
        if local_column and integer_id(row_local) == local_id:
            score += 5
        if server_column and wanted_server and row_server == wanted_server:
            score += 5
        if time_column and wanted_time and row_time and abs(row_time - wanted_time) <= 2:
            score += 2
        if chat_column and wanted_chat_ids and row_chat in wanted_chat_ids:
            score += 3
        if score >= 5 and (best is None or score > best[0]):
            best = (score, data)
    return best[1] if best else None


# 从一组数据库后端读取联系人行，返回 wxid 到原始字段的映射。
def load_contact_records(backends: Iterable[DatabaseBackend]) -> dict[str, dict[str, Any]]:
    contacts: dict[str, dict[str, Any]] = {}
    for database in backends:
        try:
            names = table_names(database)
        except DatabaseQueryError:
            continue
        for table in names:
            try:
                columns = table_columns(database, table)
            except DatabaseQueryError:
                continue
            username_column = choose_column(columns, ("username", "user_name", "wxid", "usrname", "chat_name"))
            name_column = choose_column(
                columns,
                ("nick_name", "nickname", "display_name", "displayname", "alias", "remark", "name", "room_name"),
            )
            if not username_column or not name_column:
                continue
            # contact 表规模通常可控；限制行数避免误把缓存表读入内存。
            try:
                rows = database.query(f"SELECT * FROM {sql_identifier(table)} LIMIT 50000")
            except DatabaseQueryError:
                continue
            for row in rows:
                username = text_value(row_value(row, username_column, default=""))
                if not username:
                    continue
                normalized_row = row_dict(row)
                if username not in contacts:
                    contacts[username] = normalized_row
                else:
                    merged = dict(contacts[username])
                    for key, value in normalized_row.items():
                        if (not merged.get(key)) and value:
                            merged[key] = value
                    contacts[username] = merged
    return contacts


# 从联系人数据库中提取群名称字段，供群聊标题优先使用。
def load_group_records(backends: Iterable[DatabaseBackend]) -> dict[str, dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for database in backends:
        try:
            names = table_names(database)
        except DatabaseQueryError:
            continue
        for table in names:
            if not any(token in table.casefold() for token in ("group", "chatroom", "contact")):
                continue
            try:
                columns = table_columns(database, table)
            except DatabaseQueryError:
                continue
            username_column = choose_column(columns, ("username", "user_name", "room_id", "chat_name"))
            group_column = choose_column(
                columns,
                ("group_name", "room_name", "chat_name", "display_name", "displayname", "nickname", "nick_name", "name"),
            )
            if not username_column or not group_column:
                continue
            try:
                rows = database.query(f"SELECT * FROM {sql_identifier(table)} LIMIT 50000")
            except DatabaseQueryError:
                continue
            for row in rows:
                username = text_value(row_value(row, username_column, default=""))
                if not username.endswith("@chatroom"):
                    continue
                normalized_row = row_dict(row)
                if username not in groups:
                    groups[username] = normalized_row
                else:
                    merged = dict(groups[username])
                    for key, value in normalized_row.items():
                        if (not merged.get(key)) and value:
                            merged[key] = value
                    groups[username] = merged
    return groups


# 从 SessionTable 等表中读取会话行，兼容 sort_timestamp/last_msg_time 等列名。
def load_session_records(backends: Iterable[DatabaseBackend]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for database in backends:
        try:
            names = table_names(database)
        except DatabaseQueryError:
            continue
        for table in names:
            try:
                columns = table_columns(database, table)
            except DatabaseQueryError:
                continue
            username_column = choose_column(columns, ("username", "user_name", "conversation_id", "chat_name", "usrname"))
            if not username_column:
                continue
            session_hint = any(
                normalized_field_name(token) in {normalized_field_name(column) for column in columns}
                for token in (
                    "summary",
                    "sort_timestamp",
                    "sort_time",
                    "last_msg_time",
                    "last_timestamp",
                    "unread_count",
                )
            ) or normalized_field_name(table) in {"sessiontable", "session", "sessionnew"}
            if not session_hint:
                continue
            try:
                rows = database.query(f"SELECT * FROM {sql_identifier(table)} LIMIT 50000")
            except DatabaseQueryError:
                continue
            for row in rows:
                conversation_id = text_value(row_value(row, username_column, default=""))
                if not conversation_id or conversation_id in seen:
                    continue
                seen.add(conversation_id)
                result.append(row_dict(row))
    return result


# 从消息库 Name2Id 建立 md5(用户名) 到 wxid 的映射，用来给 Msg_<md5> 表恢复会话身份。
def load_name2id_usernames(backends: Iterable[DatabaseBackend]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for database in backends:
        try:
            names = table_names(database)
        except DatabaseQueryError:
            continue
        for table in names:
            if normalized_field_name(table) != "name2id":
                continue
            try:
                columns = table_columns(database, table)
            except DatabaseQueryError:
                continue
            username_column = choose_column(columns, ("user_name", "username", "usrname", "name"))
            if not username_column:
                continue
            try:
                rows = database.query(
                    f"SELECT {sql_identifier(username_column)} AS __user_name FROM {sql_identifier(table)}"
                )
            except DatabaseQueryError:
                continue
            for row in rows:
                username = text_value(row_value(row, "__user_name", default=""))
                if not username:
                    continue
                digest = hashlib.md5(username.encode("utf-8")).hexdigest().casefold()
                mapping.setdefault(digest, username)
    return mapping


# 读取单个消息库里的 Name2Id：rowid 只在这个库内表示发送者。
def load_name2id_by_rowid(database: DatabaseBackend) -> dict[int, str]:
    mapping: dict[int, str] = {}
    try:
        names = table_names(database)
    except DatabaseQueryError:
        return mapping
    for table in names:
        if normalized_field_name(table) != "name2id":
            continue
        try:
            columns = table_columns(database, table)
            username_column = choose_column(columns, ("user_name", "username", "usrname", "name"))
            if not username_column:
                continue
            rows = database.query(
                f"SELECT rowid AS __rowid, {sql_identifier(username_column)} AS __user_name FROM {sql_identifier(table)}"
            )
        except DatabaseQueryError:
            continue
        for row in rows:
            try:
                number = int(row.get("__rowid"))
            except (TypeError, ValueError):
                continue
            # 空名字也要记下：这个编号属于本库，不能再拿别的库同号的人顶上。
            mapping[number] = text_value(row.get("__user_name"))
    return mapping


# 从消息资源库的 SenderName2Id 表构建内部 sender id 到 wxid 的映射。
def load_sender_resource_map(backends: Iterable[DatabaseBackend]) -> dict[int, str]:
    mapping: dict[int, str] = {}
    for database in backends:
        try:
            names = table_names(database)
        except DatabaseQueryError:
            continue
        for table in names:
            if "sendername2id" not in normalized_field_name(table):
                continue
            try:
                columns = table_columns(database, table)
                rows = database.query(f"SELECT rowid AS __rowid, * FROM {sql_identifier(table)} LIMIT 100000")
            except DatabaseQueryError:
                continue
            id_column = choose_column(columns, ("sender_id", "id", "local_id", "member_id"))
            name_column = choose_column(columns, ("sender_name", "username", "user_name", "wxid", "name"))
            for row in rows:
                raw_id = row_value(row, id_column or "__rowid")
                raw_name = row_value(row, name_column or "") if name_column else None
                try:
                    number = int(raw_id)
                except (TypeError, ValueError):
                    continue
                name = text_value(raw_name)
                if name:
                    mapping[number] = name
    return mapping


# 将 key 参数统一成完整十六进制字符串，并去除 KeyRecord 的包装。
def normalize_reader_keys(keys: Iterable[str | KeyRecord] | None, key_path: Path | str = DEFAULT_KEY_PATH) -> list[str]:
    if keys is None:
        try:
            records = load_key_records(key_path)
        except Exception:
            records = []
        values: Iterable[str | KeyRecord] = records
    else:
        values = keys
    normalized: list[str] = []
    seen: set[str] = set()
    for item in values:
        raw = item.hex if isinstance(item, KeyRecord) else str(item)
        try:
            value = normalize_key_hex(raw)
        except Exception:
            continue
        if value not in seen:
            normalized.append(value)
            seen.add(value)
    return normalized


# 校验最近天数输入；空值表示不限制，正整数表示从当前时间向前过滤。
def parse_recent_days(value: object) -> int | None:
    if value is None or str(value).strip() == "":
        return None
    try:
        days = int(str(value).strip())
    except (TypeError, ValueError):
        raise ReaderError("最近天数必须是正整数或留空") from None
    if days <= 0:
        raise ReaderError("最近天数必须是正整数或留空")
    return days


# 在一组候选 key 中打开并验证一个数据库，失败时关闭当前后端。
def open_with_candidate_keys(
    path: Path,
    keys: Sequence[str],
    factory: Callable[[Path, str], DatabaseBackend],
) -> tuple[DatabaseBackend, str]:
    candidate_keys = list(keys) or ["0" * 64]
    for key in candidate_keys:
        database: DatabaseBackend | None = None
        validated = False
        try:
            database = factory(path, key)
            validated = database.validate()
            if validated:
                return database, key
        except Exception:
            pass
        finally:
            if database is not None and not validated:
                with contextlib.suppress(Exception):
                    database.close()
    raise ReaderError("没有可打开该数据库的已验证密钥")


# 解析单条原始消息行，提取发送者、正文、引用和链接字段。
def parse_message_row(
    row: Mapping[str, Any],
    conversation_id: str,
    *,
    contacts: Mapping[str, Mapping[str, Any]] | None = None,
    sender_resource: Mapping[int, str] | None = None,
    self_wxid: str = "self",
) -> MessageRecord:
    contacts = contacts or {}
    sender_resource = sender_resource or {}
    local_value = row_value(
        row,
        "local_id",
        "MesLocalID",
        "msg_local_id",
        "message_id",
        "id",
        "rowid",
        "__rowid",
        default=0,
    )
    local_id = integer_id(local_value, 0)
    server_value = row_value(row, "server_id", "MesSvrID", "svr_id", "msg_svr_id", default="")
    server_id = "" if server_value is None else decode_message_content(server_value)
    raw_time = row_value(
        row,
        "create_time",
        "CreateTime",
        "sort_time",
        "timestamp",
        "time",
        "sort_seq",
        default=0,
    )
    raw_type = row_value(row, "local_type", "type", "msg_type", "message_type", "Type", default=0)
    message_type = integer_id(raw_type, 0)
    if message_type > 0xFFFF:
        message_type &= 0xFFFF
    raw_content = row_value(
        row,
        "message_content",
        "Message",
        "content",
        "text",
        "compress_content",
        "body",
        default="",
    )
    # CLI JSON 对 BLOB 的表示依赖版本；优先使用额外的 hex 列保留原始字节。
    raw_hex_content = str(row_value(row, "__hex_message_content", default="") or "")
    if raw_hex_content and len(raw_hex_content) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", raw_hex_content):
        try:
            raw_content = bytes.fromhex(raw_hex_content)
        except ValueError:
            pass
    compression = row_value(row, "WCDB_CT_message_content", "content_compressed", "compression", "compress", default=None)
    decoded = decode_message_content(raw_content, compression)
    if not decoded:
        fallback_content = row_value(row, "compress_content", "compressed_content", "content_blob", default="")
        decoded = decode_message_content(fallback_content, compression)
    prefix_wxid, stripped_content = extract_sender_prefix(decoded)
    raw_sender = row_value(
        row,
        "sender_wxid",
        "sender_username",
        "from_user",
        "sender",
        "talker",
        "username",
        "from_wxid",
        "chatusr",
        default="",
    )
    sender_wxid = decode_message_content(raw_sender).strip()
    internal_sender = integer_id(row_value(row, "real_sender_id", "sender_id", "from_id", default=0), 0)
    # 每个 message_N.db 的 Name2Id 行号互不通用，必须以当前库为准。
    # 正文开头的“xxx:”经常只是聊天文字，不能盖过这个映射。
    mapped_sender = sender_resource.get(internal_sender) if internal_sender else None
    # Name2Id 里有的行名字是空的。视频、表情等 XML 带 fromusername，可以补上发送人。
    xml_sender = re.search(r"\bfromusername\s*=\s*[\"']([^\"']+)[\"']|<fromusername>(?:<!\[CDATA\[)?([^<\]]+)", decoded)
    from_wxid = (xml_sender.group(1) or xml_sender.group(2)).strip() if xml_sender else ""
    if from_wxid.casefold().endswith("@chatroom"):
        from_wxid = ""
    if mapped_sender:
        sender_wxid = mapped_sender
    elif not sender_wxid or sender_wxid.isdigit():
        if prefix_wxid:
            sender_wxid = prefix_wxid
        elif from_wxid:
            sender_wxid = from_wxid
        elif internal_sender == 2 and self_wxid and self_wxid != "self":
            sender_wxid = self_wxid
        elif conversation_id.casefold().endswith("@chatroom"):
            sender_wxid = f"unknown_sender_{internal_sender}" if internal_sender else "unknown_sender"
        else:
            sender_wxid = conversation_id
    clean_content = stripped_content if prefix_wxid and prefix_wxid == sender_wxid else decoded
    xml_values = parse_message_xml(clean_content)
    if not clean_content:
        clean_content = decoded
    content, link_url, link_title, link_description, link_source = classify_message(message_type, clean_content, xml_values)
    if content.startswith("[系统消息]"):
        # 拍一拍用 ${wxid}、领红包用 $wxid$ 指代成员。
        def member_name(match: re.Match[str]) -> str:
            wxid = match.group(1) or match.group(2)
            return preferred_display_name(wxid, contacts.get(wxid))

        content = re.sub(r"\$\{([^}]+)\}|\$(wxid_[A-Za-z0-9_-]+|[A-Za-z0-9_.-]+@chatroom)\$", member_name, content)
    # 只有纯文本消息才从正文里找链接。表情、图片等 XML 里的 cdnurl 不是用户发的链接。
    if link_url is None and content == clean_content:
        direct_url = re.search(r"https?://[^\s<>]+", clean_content, re.I)
        if direct_url:
            link_url = direct_url.group(0).rstrip("。，,；;）)>")
            link_title = link_title or clean_content
    quote_wxid = xml_values.get("refer_user") or None
    quote_name = xml_values.get("refer_sender") or None
    quote_content = xml_values.get("refer_content") or None
    if (quote_wxid or quote_name or "refermsg" in clean_content.casefold()) and not quote_content:
        quote_content = "[原消息内容不可用]"
    if quote_wxid and not quote_name:
        quote_name = preferred_display_name(quote_wxid, contacts.get(quote_wxid))
    if quote_content:
        quote_content = decode_message_content(quote_content)
    sender_name = preferred_display_name(sender_wxid, contacts.get(sender_wxid))
    if content.startswith("[系统消息]") and (
        sender_wxid.startswith("unknown_sender") or sender_wxid.casefold().endswith("@chatroom")
    ):
        sender_name = "系统"
    if is_account_owner(sender_wxid, self_wxid):
        sender_name = "我"
    if quote_wxid and is_account_owner(quote_wxid, self_wxid):
        quote_name = "我"
    return MessageRecord(
        local_id=local_id,
        server_id=server_id,
        sent_at=format_timestamp(raw_time),
        sender_wxid=sender_wxid,
        sender_name=sender_name,
        message_type=message_type,
        content=content,
        quote_sender_wxid=quote_wxid,
        quote_sender_name=quote_name,
        quote_content=quote_content,
        link_url=link_url,
        link_title=link_title,
        link_description=link_description,
        link_source=link_source,
        raw_timestamp=timestamp_seconds(raw_time),
    )


# 浏览器播不了 HEVC。这种视频在页面里只会出声音，转成 H.264 后画面才看得到。
def _browser_video_bytes(path: Path) -> bytes:
    original = path.read_bytes()
    if path.suffix.casefold() != ".mp4":
        return original
    ffmpeg = shutil.which("ffmpeg")
    ffprobe = shutil.which("ffprobe")
    if not ffmpeg or not ffprobe:
        return original
    from wxwatch.imagedat import _write_atomic

    # 转码结果按源文件路径、大小和修改时间缓存。再次导出同一会话时不用重新转码。
    cache_dir = _active_media_cache_dir()
    try:
        stat = path.stat()
        cache_key = hashlib.sha256(f"{path.resolve()}:{stat.st_size}:{stat.st_mtime_ns}".encode()).hexdigest()
    except OSError:
        return original
    converted = cache_dir / f"video_{cache_key}.mp4"
    unchanged = cache_dir / f"video_{cache_key}.h264"
    if unchanged.exists():
        return original
    with contextlib.suppress(OSError):
        return converted.read_bytes()
    probe = subprocess.run(
        [ffprobe, "-v", "error", "-select_streams", "v:0", "-show_entries", "stream=codec_name", "-of", "csv=p=0", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    codec = probe.stdout.strip().lower()
    if codec in {"", "h264"}:
        if codec:
            _write_atomic(unchanged, b"")
        return original
    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as handle:
        target = Path(handle.name)
    try:
        # veryfast 比默认的 medium 快好几倍，聊天视频的画质差别看不出来。
        result = subprocess.run(
            [ffmpeg, "-y", "-i", str(path), "-c:v", "libx264", "-preset", "veryfast", "-pix_fmt", "yuv420p",
             "-c:a", "aac", "-movflags", "+faststart", str(target)],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0 or not target.is_file():
            return original
        data = target.read_bytes()
    finally:
        target.unlink(missing_ok=True)
    _write_atomic(converted, data)
    return data


# 转码缓存放在应用数据目录，只有当前用户可读。
def _media_cache_dir() -> Path:
    from cccryptor_probe import default_app_support_dir

    return default_app_support_dir() / "media_cache"


# 当前导出使用的缓存目录。进程池的子进程从上下文取，和主进程保持一致。
def _active_media_cache_dir() -> Path:
    cache_dir = _MEDIA_CONTEXT.get("cache_dir")
    return Path(cache_dir) if cache_dir else _media_cache_dir()


# 媒体处理基本都在等 ffmpeg 子进程或网络，用线程并行。
MEDIA_WORKERS = max(2, min(8, os.cpu_count() or 4))
_IMAGE_KEY_LOCK = threading.Lock()


_IMAGE_KEY_DERIVED: set[str] = set()


# 媒体文件所在的微信账号目录，即包含 db_storage 的那一层。
def _account_root_of(path: Path) -> Path | None:
    for parent in path.parents:
        if (parent / "db_storage").is_dir():
            return parent
    return None


# 尝试把微信 .dat 解成图片。没有 V2 密钥时返回 None，调用方仍导出原始文件。
def _decode_wechat_dat(path: Path) -> bytes | None:
    try:
        from wxwatch.imagedat import decode_dat, load_image_keys
    except Exception:
        return None
    config_path = Path(__file__).resolve().parent / "config.json"
    image_key, xor_key = load_image_keys(config_path)
    try:
        decoded = decode_dat(path, image_key, xor_key)
    except Exception:
        decoded = None
    if decoded is not None or sys.platform != "darwin":
        return decoded
    # macOS 的图片密钥可以从本机微信配置推导。密钥缺失或换了账号时推导一次并写回 config.json。
    account_root = _account_root_of(path)
    if account_root is None:
        return None
    # 并行导出时只让一个线程推导并写 config.json，其余线程等它写完再读。
    with _IMAGE_KEY_LOCK:
        if str(account_root) not in _IMAGE_KEY_DERIVED:
            _IMAGE_KEY_DERIVED.add(str(account_root))
            try:
                from wxwatch.imagekey import ensure_image_key_macos

                ensure_image_key_macos(account_root)
            except Exception:
                return None
    retry_key, retry_xor = load_image_keys(config_path)
    if retry_key is None or (retry_key, retry_xor) == (image_key, xor_key):
        return None
    try:
        return decode_dat(path, retry_key, retry_xor)
    except Exception:
        return None


# macOS 单个路径分量最长 255 字节，整条路径最长 1024 字节。超限时 stat 会抛 Errno 63。
def _filesystem_path_ok(path: Path) -> bool:
    try:
        if len(os.fsencode(path)) >= 1024:
            return False
        return all(len(os.fsencode(part)) <= 255 for part in path.parts)
    except UnicodeEncodeError:
        return False


# 解出消息行的正文。CLI 后端把 BLOB 正文放在 __hex_message_content 里。
def _row_content(row: Mapping[str, Any]) -> str:
    raw_content = row_value(row, "message_content", "Message", "content", "text", default="")
    raw_hex = str(row_value(row, "__hex_message_content", default="") or "")
    if raw_hex and len(raw_hex) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", raw_hex):
        with contextlib.suppress(ValueError):
            raw_content = bytes.fromhex(raw_hex)
    return decode_message_content(raw_content, row_value(row, "WCDB_CT_message_content", "compress_type", default=None))


# 从原始消息行中查找可能存在的本地媒体路径，并限制在账号目录内。
def local_media_path(row: Mapping[str, Any], account_root: Path | None) -> Path | None:
    if account_root is None:
        return None
    raw = row_value(row, "media_path", "path", "file_path", "attach_path", "image_path", "video_path", default="")
    raw = text_value(raw)
    if not raw:
        content = _row_content(row)
        # 某些版本只在 appmsg/image XML 属性中留下本地附件相对路径。
        # cdnthumburl 是 CDN 标识，不是本地文件名，拼到账号目录上会超过系统路径长度。
        match = re.search(r"(?:filepath|attachurl|path|src)=[\"']([^\"']+)[\"']", content, re.IGNORECASE)
        if match:
            raw = match.group(1)
        else:
            tag_match = re.search(
                r"<(?:filepath|attachurl|path|src)>([^<]+)</(?:filepath|attachurl|path|src)>",
                content,
                re.IGNORECASE,
            )
            if tag_match:
                raw = tag_match.group(1)
        raw = text_value(raw)
    if not raw or raw.startswith(("http://", "https://")):
        return None
    candidate = Path(str(raw)).expanduser()
    if not candidate.is_absolute():
        candidate = account_root / candidate
    if not _filesystem_path_ok(candidate):
        return None
    try:
        resolved = candidate.resolve()
        resolved.relative_to(account_root.resolve())
        if not resolved.is_file():
            return None
    except (OSError, ValueError):
        return None
    return resolved


_CACHED_MEDIA_BY_ROOT: dict[str, dict[str, Path]] = {}


# 只有真实图片、视频，或可解密的 .dat 才挂到消息上。
def _displayable_media_file(path: Path) -> bool:
    try:
        head = path.read_bytes()[:16]
    except OSError:
        return False
    if head.startswith((b"\xff\xd8\xff", b"\x89PNG", b"GIF8", b"RIFF")):
        return True
    if head[:6] in {b"\x07\x08V1\x08\x07", b"\x07\x08V2\x08\x07"}:
        return True
    return path.suffix.casefold() in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp4", ".mov"}


# 按文件名主干索引 cache 里的表情和已解码图片，避免每条消息都扫一遍目录。
def _cached_media_by_stem(account_root: Path) -> dict[str, Path]:
    key = str(account_root)
    cached = _CACHED_MEDIA_BY_ROOT.get(key)
    if cached is not None:
        return cached
    index: dict[str, Path] = {}
    rank = {".jpg": 0, ".jpeg": 0, ".png": 0, ".gif": 0, ".webp": 0, "": 1, ".dat": 2}
    cache = account_root / "cache"
    if cache.is_dir():
        for path in cache.rglob("*"):
            if not path.is_file():
                continue
            stem = path.stem.lower()
            current = index.get(stem)
            path_rank = rank.get(path.suffix.lower(), 9)
            current_rank = rank.get(current.suffix.lower(), 9) if current is not None else 99
            if current is None or path_rank < current_rank:
                index[stem] = path
    _CACHED_MEDIA_BY_ROOT[key] = index
    return index


# 读取 emoticon.db 的收藏表情表：md5 -> 下载地址。商店表情只有本地加密包，没有地址。
def load_emoticon_index(backends: Iterable[DatabaseBackend]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for database in backends:
        if "kNonStoreEmoticonTable" not in table_names(database):
            continue
        try:
            rows = database.query("SELECT md5, cdn_url, encrypt_url, aes_key FROM kNonStoreEmoticonTable")
        except DatabaseQueryError:
            continue
        for row in rows:
            md5_hex = text_value(row_value(row, "md5")).casefold()
            if not re.fullmatch(r"[0-9a-f]{32}", md5_hex):
                continue
            index[md5_hex] = {
                "cdnurl": text_value(row_value(row, "cdn_url")),
                "encrypturl": text_value(row_value(row, "encrypt_url")),
                "aeskey": text_value(row_value(row, "aes_key")),
            }
    return index


# 只从微信自己的 CDN 下载表情。消息 XML 来自聊天对方，不能按里面的任意地址发请求。
_EMOJI_HOST_SUFFIXES = (".qq.com", ".qpic.cn", ".wechat.com")
_EMOJI_MAGICS = (b"GIF8", b"\x89PNG", b"\xff\xd8\xff", b"RIFF", b"wxgf")


def _emoji_url_allowed(url: str) -> bool:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = (parsed.hostname or "").casefold()
    return parsed.scheme in {"http", "https"} and any(host == item[1:] or host.endswith(item) for item in _EMOJI_HOST_SUFFIXES)


def _emoji_cache_dir() -> Path:
    from cccryptor_probe import default_app_support_dir

    return default_app_support_dir() / "emoji_cache"


# 本地表情缓存是另一把未公开的密钥加密的。用消息 XML 里的 cdnurl / encrypturl 取原图，按 md5 缓存到本机。
# XML 里没有地址时，用 emoticon.db 里同 md5 的记录补上（fallback 的键与 XML 属性同名）。
def fetch_emoji(content: str, md5_hex: str, fallback: Mapping[str, str] | None = None) -> Path | None:
    if os.environ.get("WECHAT_EXPORT_OFFLINE") or not re.fullmatch(r"[0-9a-f]{32}", md5_hex):
        return None
    cache_dir = _emoji_cache_dir()
    missed = False
    for cached in cache_dir.glob(f"{md5_hex}.*"):
        if cached.suffix != ".miss":
            return cached
        missed = True
    # 之前失败过、这次也没有新的地址来源时不再请求。
    if missed and not fallback:
        return None
    start = content.find("<emoji")
    attrs = {
        key.casefold(): html.unescape(value)
        for key, value in re.findall(r"(\w+)\s*=\s*\"([^\"]*)\"", content[start:start + 8000])
    } if start >= 0 else {}
    for key, value in (fallback or {}).items():
        if value and not attrs.get(key):
            attrs[key] = value
    import urllib.request

    data: bytes | None = None
    aes_key = attrs.get("aeskey", "")
    sources = [(attrs.get("cdnurl", ""), None)]
    if re.fullmatch(r"[0-9a-fA-F]{32}", aes_key):
        sources.append((attrs.get("encrypturl", ""), bytes.fromhex(aes_key)))
    for url, key in sources:
        if not url or not _emoji_url_allowed(url):
            continue
        try:
            with urllib.request.urlopen(url, timeout=15) as response:
                payload = response.read(20 * 1024 * 1024)
        except Exception:
            continue
        if key is not None:
            try:
                from Crypto.Cipher import AES
                from Crypto.Util import Padding

                payload = Padding.unpad(AES.new(key, AES.MODE_CBC, key).decrypt(payload), 16)
            except Exception:
                continue
        if payload.startswith(b"wxgf"):
            from wxwatch.imagedat import wxgf_to_jpeg

            payload = wxgf_to_jpeg(payload) or b""
        if payload.startswith(_EMOJI_MAGICS):
            data = payload
            break
    cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if data is None:
        # 记下失败，重复导出时不再请求同一个表情。
        (cache_dir / f"{md5_hex}.miss").touch()
        return None
    (cache_dir / f"{md5_hex}.miss").unlink(missing_ok=True)
    extension = ".gif" if data.startswith(b"GIF8") else ".png" if data.startswith(b"\x89PNG") else ".webp" if data.startswith(b"RIFF") else ".jpg"
    target = cache_dir / f"{md5_hex}{extension}"
    from wxwatch.imagedat import _write_atomic

    _write_atomic(target, data)
    return target


# 从 packed_info 或消息 XML 中取出 32 位媒体 md5。
def _packed_media_md5(row: Mapping[str, Any]) -> str:
    packed = row_value(row, "packed_info_data", default=b"")
    if isinstance(packed, memoryview):
        packed = packed.tobytes()
    if isinstance(packed, str):
        packed = packed.encode("utf-8", errors="ignore")
    if isinstance(packed, (bytes, bytearray)):
        match = re.search(rb"[0-9a-f]{32}", bytes(packed))
        if match:
            return match.group(0).decode("ascii")
    content = _row_content(row)
    xml_match = re.search(r"\bmd5=[\"']([0-9a-fA-F]{32})[\"']", content)
    return xml_match.group(1).lower() if xml_match else ""


# 按微信 4.x 的目录规则定位已经落盘的图片、视频和文件。
def local_media_files(
    row: Mapping[str, Any],
    account_root: Path | None,
    conversation_id: str,
    emoji_index: Mapping[str, Mapping[str, str]] | None = None,
) -> list[Path]:
    found: list[Path] = []
    if account_root is None:
        return found
    md5_hex = _packed_media_md5(row)
    created = timestamp_seconds(row_value(row, "create_time", "CreateTime", "timestamp", default=0))
    base_type = integer_id(row_value(row, "local_type", "type", "message_type", default=0), 0) & 0xFFFFFFFF
    if md5_hex and created > 0 and conversation_id:
        month = _dt.datetime.fromtimestamp(created).strftime("%Y-%m")
        talker_dir = hashlib.md5(conversation_id.encode("utf-8")).hexdigest()
        candidates: list[Path] = []
        if base_type == 3:
            image_dir = account_root / "msg" / "attach" / talker_dir / month / "Img"
            full_image = image_dir / f"{md5_hex}.dat"
            thumb = image_dir / f"{md5_hex}_t.dat"
            candidates = [full_image, thumb]
        elif base_type == 43:
            video_dir = account_root / "msg" / "video" / month
            movie = video_dir / f"{md5_hex}.mp4"
            cover = video_dir / f"{md5_hex}_thumb.jpg"
            # 有视频文件时只导出视频。封面只在视频文件不存在时单独显示。
            try:
                has_movie = movie.is_file()
            except OSError:
                has_movie = False
            candidates = [movie if has_movie else cover]
        elif base_type == 47:
            hit = _cached_media_by_stem(account_root).get(md5_hex)
            # 解不开的表情缓存文件名就是 md5，挂上去只会在正文下面显示一串代码。
            if hit is not None and _displayable_media_file(hit):
                candidates = [hit]
            else:
                content = _row_content(row)
                xml_md5 = re.search(r"<emoji\b[^>]*?\bmd5=[\"']([0-9a-fA-F]{32})[\"']", content)
                emoji_md5 = xml_md5.group(1).lower() if xml_md5 else md5_hex
                downloaded = fetch_emoji(content, emoji_md5, (emoji_index or {}).get(emoji_md5))
                if downloaded is not None:
                    return [downloaded]
        elif base_type == 34:
            voice_dir = account_root / "msg" / "voice" / month
            candidates = [voice_dir / f"{md5_hex}.aud", voice_dir / f"{md5_hex}.silk"]
        for candidate in candidates:
            if not _filesystem_path_ok(candidate):
                continue
            try:
                if candidate.is_file():
                    found.append(candidate.resolve())
                    if base_type == 3:
                        break
            except OSError:
                continue
    direct = local_media_path(row, account_root)
    if direct is not None and direct not in found and (not md5_hex or md5_hex in direct.name.casefold()):
        found.append(direct)
    return found


# 把账号目录内的已有媒体文件转换成消息媒体记录。进程池要求它是模块级函数。
def media_records_from_path(message_id: int, path: Path) -> list[MediaRecord]:
    try:
        data = _browser_video_bytes(path)
    except OSError:
        return []
    if path.suffix.casefold() == ".dat" or data[:6] in {b"\x07\x08V1\x08\x07", b"\x07\x08V2\x08\x07"}:
        decoded = _decode_wechat_dat(path)
        if decoded:
            extension = ".jpg"
            mime = "image/jpeg"
            if decoded.startswith(b"\x89PNG"):
                extension, mime = ".png", "image/png"
            elif decoded.startswith(b"GIF8"):
                extension, mime = ".gif", "image/gif"
            elif decoded.startswith(b"RIFF"):
                extension, mime = ".webp", "image/webp"
            return [
                MediaRecord(
                    message_id,
                    "image",
                    mime,
                    f"image_{message_id}{extension}",
                    decoded,
                    str(path),
                    True,
                )
            ]
        # V2 图片没有密钥时仍保存原始 dat，避免这条消息的文件丢失。
        return [
            MediaRecord(
                message_id,
                "file",
                "application/octet-stream",
                f"image_{message_id}.dat",
                data,
                str(path),
                False,
            )
        ]
    if data.startswith(b"\xff\xd8\xff"):
        mime, media_type, filename = "image/jpeg", "image", f"image_{message_id}.jpg"
    elif data.startswith(b"\x89PNG"):
        mime, media_type, filename = "image/png", "image", f"image_{message_id}.png"
    elif data.startswith(b"GIF8"):
        mime, media_type, filename = "image/gif", "image", f"image_{message_id}.gif"
    elif data.startswith(b"RIFF"):
        mime, media_type, filename = "image/webp", "image", f"image_{message_id}.webp"
    else:
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        media_type = "image" if mime.startswith("image/") else "video" if mime.startswith("video/") else "file"
        filename = safe_filename(path.name, f"media_{message_id}")
    playable = media_type in {"image", "video"} or mime.casefold() in PLAYABLE_AUDIO_MIMES
    return [MediaRecord(message_id, media_type, mime, filename, data, str(path), playable)]


# 导出时处理媒体的方式。thread 适合大多数情况；process 绕开 GIL，但每个进程要单独建索引、回传大块字节。
MEDIA_MODES = ("thread", "process", "serial")
# 上限防止一次拉起太多 ffmpeg 把内存和 CPU 占满。进程比线程重，上限更低。
MAX_THREAD_WORKERS = 16
MAX_PROCESS_WORKERS = max(1, min(8, os.cpu_count() or 4))


# 按模式把并发数限制在安全范围内。
def clamp_media_workers(mode: str, workers: int | None) -> int:
    if mode == "serial":
        return 1
    limit = MAX_PROCESS_WORKERS if mode == "process" else MAX_THREAD_WORKERS
    if workers is None or workers <= 0:
        workers = MEDIA_WORKERS
    return max(1, min(int(workers), limit))


# 进程池里每个工作进程共用的只读上下文，由 initializer 设置一次。
_MEDIA_CONTEXT: dict[str, Any] = {}


def _init_media_worker(context: dict[str, Any]) -> None:
    from wxwatch import imagedat

    _MEDIA_CONTEXT.clear()
    _MEDIA_CONTEXT.update(context)
    imagedat.CONVERT_CACHE_DIR = context["cache_dir"]
    account_root = context["account_root"]
    if account_root is not None:
        _CACHED_MEDIA_BY_ROOT[str(account_root)] = context["cached_media"]


# 读取一条消息的全部本地媒体。线程和进程都调用这个函数。
def load_message_media(job: tuple[int, Mapping[str, Any]]) -> list[MediaRecord]:
    message_id, row = job
    found: list[MediaRecord] = []
    for candidate_path in local_media_files(
        row,
        _MEDIA_CONTEXT["account_root"],
        _MEDIA_CONTEXT["conversation_id"],
        _MEDIA_CONTEXT["emoji_index"],
    ):
        found.extend(media_records_from_path(message_id, candidate_path))
    return found


# 按选定方式并行读取媒体，结果顺序与 jobs 一致。进程池起不来时退回线程。
def run_media_jobs(
    jobs: Sequence[tuple[int, Mapping[str, Any]]],
    context: dict[str, Any],
    mode: str = "thread",
    workers: int | None = None,
) -> list[list[MediaRecord]]:
    if mode not in MEDIA_MODES:
        mode = "thread"
    count = clamp_media_workers(mode, workers)
    _init_media_worker(context)
    if mode == "serial" or count == 1 or len(jobs) < 2:
        return [load_message_media(job) for job in jobs]
    if mode == "process":
        import multiprocessing
        from concurrent.futures import ProcessPoolExecutor
        from concurrent.futures.process import BrokenProcessPool

        try:
            # fork 会复制界面线程和 sqlcipher 连接，macOS 上不安全，统一用 spawn。
            with ProcessPoolExecutor(
                max_workers=count,
                mp_context=multiprocessing.get_context("spawn"),
                initializer=_init_media_worker,
                initargs=(context,),
            ) as pool:
                return list(pool.map(load_message_media, jobs, chunksize=max(1, len(jobs) // (count * 8))))
        except (BrokenProcessPool, OSError, RuntimeError, TypeError, AttributeError):
            pass
    with ThreadPoolExecutor(max_workers=count, thread_name_prefix="wechat-media") as pool:
        return list(pool.map(load_message_media, jobs))


# 将消息去重并按原始时间、local_id 稳定排序。
def deduplicate_messages(messages: Iterable[MessageRecord]) -> list[MessageRecord]:
    selected: dict[tuple[Any, ...], MessageRecord] = {}
    for message in messages:
        if message.server_id and message.server_id not in {"0", "None"}:
            key = ("server", message.server_id)
        elif message.local_id:
            key = ("local", message.local_id)
        else:
            key = ("local", message.local_id, message.raw_timestamp, message.sender_wxid, message.content)
        previous = selected.get(key)
        if previous is None:
            selected[key] = message
            continue
        winner = message if len(message.content) > len(previous.content) else previous
        # 同一消息在不同分片可能各自带有附件；保留两边的媒体而不重复写出。
        known_media = {
            (item.media_type, item.filename, hashlib.sha256(item.data or b"").hexdigest())
            for item in winner.media
        }
        for attached in (previous.media if winner is message else message.media):
            signature = (attached.media_type, attached.filename, hashlib.sha256(attached.data or b"").hexdigest())
            if signature not in known_media:
                winner.media.append(attached)
                known_media.add(signature)
        selected[key] = winner
    return sorted(selected.values(), key=lambda item: (item.raw_timestamp, item.local_id, item.server_id))


# 查询消息表并为 message_content 附加 hex 表达，兼容 SQLCipher CLI 的 BLOB 输出。
def fetch_message_rows(database: DatabaseBackend, table: str) -> list[dict[str, Any]]:
    columns = table_columns(database, table)
    if not columns:
        return []
    parts = ["rowid AS __rowid"] + [sql_identifier(column) for column in columns]
    content_column = choose_column(columns, ("message_content", "Message", "content", "text", "body"))
    if content_column:
        parts.append(f"hex({sql_identifier(content_column)}) AS __hex_message_content")
    try:
        return database.query(f"SELECT {', '.join(parts)} FROM {sql_identifier(table)} LIMIT 500000")
    except DatabaseQueryError:
        # 某些虚拟表不提供 rowid，退回不带辅助列的查询。
        return database.query(f"SELECT {', '.join(parts[1:])} FROM {sql_identifier(table)} LIMIT 500000")


class WeChatReader:
    """微信聊天数据库只读门面。"""

    # 初始化数据根目录、数据库后端工厂和 key 文件位置。
    def __init__(
        self,
        data_root: Path | str | None = None,
        *,
        db_root: Path | str | None = None,
        message_paths: Iterable[Path | str] | None = None,
        database_factory: Callable[[Path, str], DatabaseBackend] | None = None,
        key_path: Path | str = DEFAULT_KEY_PATH,
    ) -> None:
        selected_root = data_root if data_root is not None else db_root
        self.data_root = Path(selected_root).expanduser() if selected_root is not None else None
        self._message_paths = tuple(Path(item).expanduser().resolve() for item in (message_paths or ()))
        self.database_factory = database_factory or (
            lambda path, key: open_database_backend(path, key)
        )
        self.key_path = Path(key_path).expanduser()
        self.names_resolved = False

    # 发现当前账号的消息、联系人、会话和媒体数据库。
    def catalog(self) -> DatabaseCatalog:
        paths = list(self._message_paths)
        if not paths:
            paths = discover_message_databases(self.data_root)
        return build_database_catalog(paths)

    # 对候选 key 逐个复制并验证，放宽为只要能正确读取任意一个微信数据库即可保留
    def validate_key(self, key_hex: str, paths: Iterable[Path | str] | None = None) -> tuple[str, ...]:
        normalized = normalize_key_hex(key_hex)
        catalog = self.catalog()

        # 消息、联系人、会话各自有独立密钥。先用页首 HMAC 筛出真正匹配的库，避免把无关的大库整份复制一遍。
        if paths is None:
            candidates = [
                *catalog.message_paths,
                *catalog.contact_paths,
                *catalog.session_paths,
                *catalog.resource_paths,
                *catalog.emoticon_paths,
            ]
        else:
            candidates = [Path(item) for item in paths]
        if not candidates:
            # 尚未探测到具体库时，保留合法的 64 位十六进制候选，避免在扫描阶段被误删
            return ("candidate_key",)
        test_paths: list[Path] = []
        seen_paths: set[Path] = set()
        for source in candidates:
            try:
                resolved = source.expanduser().resolve()
            except OSError:
                resolved = source.expanduser()
            if resolved in seen_paths or not resolved.is_file():
                continue
            mode = detect_sqlcipher_key_mode(resolved, normalized)
            # 明文库只在调用方明确指定路径时接受，避免任意候选密钥因为旁边有明文文件而被保存。
            if mode in {"raw", "passphrase"} or (mode == "plaintext" and paths is not None):
                seen_paths.add(resolved)
                test_paths.append(resolved)
        if not test_paths:
            return ()

        valid: list[str] = []
        with database_snapshot(test_paths) as snapshots:
            for source in test_paths:
                copy_path = snapshots[source]
                database: DatabaseBackend | None = None
                try:
                    database = self.database_factory(copy_path, normalized)
                    # 关键修改：只要能够正常通过 SQLCipher 解密并读取 sqlite_master 即判定密钥有效
                    if database.validate():
                        valid.append(source.name)
                except Exception:
                    pass
                finally:
                    if database is not None:
                        with contextlib.suppress(Exception):
                            database.close()
        return tuple(sorted(set(valid)))

    # 读取当前数据库中的可导出会话列表，并过滤系统会话。
    def list_conversations(self, keys: Iterable[str | KeyRecord] | None = None) -> list[Conversation]:
        normalized_keys = normalize_reader_keys(keys, self.key_path)
        catalog = self.catalog()
        if not catalog.message_paths:
            raise ReaderError("未找到 message_N.db；请确认微信 4.x 已登录并授予文件访问权限")
        all_paths = list(catalog.message_paths) + list(catalog.contact_paths) + list(catalog.session_paths) + list(catalog.resource_paths)
        with database_snapshot(all_paths) as snapshots:
            message_backends: list[tuple[Path, DatabaseBackend]] = []
            contact_backends: list[DatabaseBackend] = []
            session_backends: list[DatabaseBackend] = []
            try:
                for source in catalog.message_paths:
                    try:
                        database, _key = open_with_candidate_keys(snapshots[source], normalized_keys, self.database_factory)
                    except ReaderError:
                        continue
                    message_backends.append((source, database))
                if not message_backends:
                    raise ReaderError("没有可读取的消息数据库，请检查密钥或 SQLCipher 配置")
                for source in catalog.contact_paths:
                    try:
                        database, _key = open_with_candidate_keys(snapshots[source], normalized_keys, self.database_factory)
                        contact_backends.append(database)
                    except ReaderError:
                        continue
                for source in catalog.session_paths:
                    try:
                        database, _key = open_with_candidate_keys(snapshots[source], normalized_keys, self.database_factory)
                        session_backends.append(database)
                    except ReaderError:
                        continue
                contacts = load_contact_records(contact_backends)
                groups = load_group_records(contact_backends)
                # 某些微信版本把 SessionTable 放在 message_N.db，而不是独立 session.db。
                sessions = load_session_records([*session_backends, *(database for _source, database in message_backends)])
                if not contacts:
                    contacts = load_contact_records(database for _source, database in message_backends)
                if not groups:
                    groups = load_group_records(database for _source, database in message_backends)
                self.names_resolved = bool(contacts)
                table_index = self._build_message_table_index(message_backends)
                usernames = load_name2id_usernames(database for _source, database in message_backends)
                result = self._assemble_conversations(sessions, contacts, groups, table_index)
                if not result:
                    result = self._fallback_conversations(contacts, table_index, usernames)
                return result
            finally:
                for _source, database in message_backends:
                    with contextlib.suppress(Exception):
                        database.close()
                for database in contact_backends + session_backends:
                    with contextlib.suppress(Exception):
                        database.close()

    # 为每个消息分片建立 md5 会话名到表的索引。
    def _build_message_table_index(
        self,
        backends: Iterable[tuple[Path, DatabaseBackend]],
    ) -> dict[str, tuple[Path, str, DatabaseBackend]]:
        index: dict[str, tuple[Path, str, DatabaseBackend]] = {}
        for source, database in backends:
            try:
                tables = find_message_tables(database)
            except DatabaseQueryError:
                continue
            for table in tables:
                if table.casefold().startswith("msg_"):
                    digest = table.split("_", 1)[1].casefold()
                    index.setdefault(digest, (source, table, database))
                else:
                    try:
                        columns = table_columns(database, table)
                        conversation_column = choose_column(
                            columns, ("conversation_id", "username", "talker", "chat_name", "user_name")
                        )
                        if not conversation_column:
                            continue
                        rows = database.query(
                            f"SELECT DISTINCT {sql_identifier(conversation_column)} AS __conversation_id FROM {sql_identifier(table)} LIMIT 50000"
                        )
                    except DatabaseQueryError:
                        continue
                    for row in rows:
                        conversation_id = text_value(row_value(row, "__conversation_id", default=""))
                        if conversation_id:
                            digest = hashlib.md5(conversation_id.encode("utf-8")).hexdigest().casefold()
                            index.setdefault(digest, (source, table, database))
        return index

    # 使用会话行、联系人和 md5 表索引组装三列会话列表。
    def _assemble_conversations(
        self,
        sessions: Iterable[Mapping[str, Any]],
        contacts: Mapping[str, Mapping[str, Any]],
        groups: Mapping[str, Mapping[str, Any]],
        table_index: Mapping[str, tuple[Path, str, DatabaseBackend]],
    ) -> list[Conversation]:
        result: list[Conversation] = []
        for row in sessions:
            conversation_id = text_value(
                row_value(row, "username", "user_name", "conversation_id", "chat_name", "usrname", default="")
            )
            if not conversation_id:
                continue
            contact = contacts.get(conversation_id, {})
            group = groups.get(conversation_id, {})
            title = preferred_display_name(conversation_id, contact, group)
            if title == conversation_id:
                session_hint = {
                    "group_name": row_value(row, "group_name", "room_name", default=""),
                    "nick_name": row_value(row, "nick_name", "nickname", default=""),
                    "alias": row_value(row, "alias", default=""),
                }
                title = preferred_display_name(conversation_id, session_hint, session_hint)
            if is_system_conversation(conversation_id, title):
                continue
            digest = hashlib.md5(conversation_id.encode("utf-8")).hexdigest().casefold()
            match = table_index.get(digest)
            recent_raw = row_value(
                row,
                "sort_timestamp",
                "sort_time",
                "last_msg_time",
                "last_timestamp",
                "update_time",
                "timestamp",
                default=0,
            )
            recent_time = format_timestamp(recent_raw)
            summary = decode_message_content(
                row_value(row, "summary", "last_message", "digest", "latest_message", "content", default="")
            )
            recent_message = summary or ""
            if not recent_message and match:
                recent_message, recent_time, recent_raw = self._latest_message_preview(
                    match[1], match[2], conversation_id
                )
            result.append(
                Conversation(
                    conversation_id=conversation_id,
                    title=title,
                    recent_time=recent_time,
                    recent_message=recent_message,
                    conversation_type="group" if conversation_id.casefold().endswith("@chatroom") else "single",
                    peer_id=conversation_id,
                    peer_name=title,
                    table_name=match[1] if match else "",
                    database_path=str(match[0]) if match else "",
                    sort_timestamp=timestamp_seconds(recent_raw),
                )
            )
        result.sort(key=lambda item: (-item.sort_timestamp, item.title.casefold(), item.conversation_id))
        return result

    # 当 SessionTable 不可用时，用 Name2Id 把 Msg_<md5> 还原成 wxid，并读取最新一条消息。
    def _fallback_conversations(
        self,
        contacts: Mapping[str, Mapping[str, Any]],
        table_index: Mapping[str, tuple[Path, str, DatabaseBackend]],
        usernames: Mapping[str, str] | None = None,
    ) -> list[Conversation]:
        by_digest = {
            hashlib.md5(wxid.encode("utf-8")).hexdigest().casefold(): wxid for wxid in contacts
        }
        by_digest.update(usernames or {})
        result: list[Conversation] = []
        for digest, (path, table, database) in table_index.items():
            conversation_id = by_digest.get(digest, table)
            title = preferred_display_name(conversation_id, contacts.get(conversation_id))
            if is_system_conversation(conversation_id, title):
                continue
            recent_message, recent_time, recent_raw = self._latest_message_preview(
                table, database, conversation_id
            )
            result.append(
                Conversation(
                    conversation_id,
                    title,
                    recent_time,
                    recent_message,
                    "group" if conversation_id.casefold().endswith("@chatroom") else "single",
                    conversation_id,
                    title,
                    table,
                    str(path),
                    timestamp_seconds(recent_raw),
                )
            )
        return sorted(result, key=lambda item: (-item.sort_timestamp, item.title.casefold(), item.conversation_id))

    # 只读取排序最后的一行，避免为了会话摘要把整个消息表载入内存。
    def _latest_message_preview(
        self,
        table: str,
        database: DatabaseBackend,
        conversation_id: str | None = None,
    ) -> tuple[str, str, object]:
        try:
            columns = table_columns(database, table)
        except DatabaseQueryError:
            return "", "", 0
        if not columns:
            return "", "", 0
        order_column = choose_column(columns, ("sort_seq", "create_time", "CreateTime", "timestamp"))
        parts = ["rowid AS __rowid", *[sql_identifier(column) for column in columns]]
        content_column = choose_column(columns, ("message_content", "Message", "content", "text", "body"))
        if content_column:
            parts.append(f"hex({sql_identifier(content_column)}) AS __hex_message_content")
        where_sql = ""
        if conversation_id and not table.casefold().startswith("msg_"):
            conversation_column = choose_column(
                columns, ("conversation_id", "username", "talker", "chat_name", "user_name")
            )
            if conversation_column:
                where_sql = f" WHERE {sql_identifier(conversation_column)} = {sql_literal(conversation_id)}"
        order_sql = f" ORDER BY {sql_identifier(order_column)} DESC" if order_column else ""
        try:
            rows = database.query(
                f"SELECT {', '.join(parts)} FROM {sql_identifier(table)}{where_sql}{order_sql} LIMIT 1"
            )
        except DatabaseQueryError:
            return "", "", 0
        if not rows:
            return "", "", 0
        parsed = parse_message_row(rows[0], conversation_id or "", self_wxid="self")
        summary = " ".join(parsed.content.split())
        if len(summary) > 80:
            summary = summary[:80] + "…"
        raw_time = row_value(rows[0], "create_time", "CreateTime", "timestamp", "time", "sort_seq", default=0)
        return summary, parsed.sent_at, raw_time

    # 读取一个选中会话的全部分片消息，去重后构建内存规范化模型。
    def read_conversation(
        self,
        conversation_id: str,
        keys: Iterable[str | KeyRecord] | None = None,
        *,
        recent_days: int | str | None = None,
        media_mode: str = "thread",
        media_workers: int | None = None,
    ) -> dict[str, Any]:
        normalized_keys = normalize_reader_keys(keys, self.key_path)
        days = parse_recent_days(recent_days)
        catalog = self.catalog()
        if not catalog.message_paths:
            raise ReaderError("未找到 message_N.db")
        all_paths = (
            list(catalog.message_paths)
            + list(catalog.media_paths)
            + list(catalog.contact_paths)
            + list(catalog.resource_paths)
            + list(catalog.emoticon_paths)
        )
        with database_snapshot(all_paths) as snapshots:
            message_backends: list[tuple[Path, DatabaseBackend]] = []
            auxiliary_backends: list[DatabaseBackend] = []
            try:
                for source in catalog.message_paths:
                    try:
                        database, _key = open_with_candidate_keys(snapshots[source], normalized_keys, self.database_factory)
                    except ReaderError:
                        continue
                    message_backends.append((source, database))
                if not message_backends:
                    raise ReaderError("没有可读取的消息数据库，请检查密钥或 SQLCipher 配置")
                for source in (
                    list(catalog.contact_paths)
                    + list(catalog.media_paths)
                    + list(catalog.resource_paths)
                    + list(catalog.emoticon_paths)
                ):
                    try:
                        database, _key = open_with_candidate_keys(snapshots[source], normalized_keys, self.database_factory)
                        auxiliary_backends.append(database)
                    except ReaderError:
                        continue
                # 辅助数据库已经按可读性筛选；直接探测其中的联系人/群组表。
                contacts = load_contact_records(auxiliary_backends)
                groups = load_group_records(auxiliary_backends)
                sender_resource = load_sender_resource_map(auxiliary_backends)
                emoji_index = load_emoticon_index(auxiliary_backends)
                if not contacts:
                    contacts = load_contact_records(database for _source, database in message_backends)
                if not groups:
                    groups = load_group_records(database for _source, database in message_backends)
                self_wxid = self._guess_self_wxid(catalog.account_root, contacts)
                digest = hashlib.md5(str(conversation_id).encode("utf-8")).hexdigest().casefold()
                selected_tables: list[tuple[Path, str, DatabaseBackend]] = []
                for source, database in message_backends:
                    matched_in_source = False
                    try:
                        tables = find_message_tables(database)
                    except DatabaseQueryError:
                        continue
                    for table in tables:
                        if table.casefold() == str(conversation_id).casefold() or (
                            table.casefold().startswith("msg_") and table.split("_", 1)[1].casefold() == digest
                        ):
                            selected_tables.append((source, table, database))
                            matched_in_source = True
                    # 兼容把 conversation_id 直接存成列的测试/新 schema。
                    if not matched_in_source:
                        for table in tables:
                            try:
                                columns = table_columns(database, table)
                            except DatabaseQueryError:
                                continue
                            conversation_column = choose_column(
                                columns, ("conversation_id", "username", "talker", "chat_name", "user_name")
                            )
                            if not conversation_column:
                                continue
                            try:
                                probe_rows = database.query(
                                    f"SELECT 1 AS __found FROM {sql_identifier(table)} WHERE {sql_identifier(conversation_column)} = {sql_literal(conversation_id)} LIMIT 1"
                                )
                            except DatabaseQueryError:
                                continue
                            if probe_rows:
                                selected_tables.append((source, table, database))
                if not selected_tables:
                    raise ReaderError("未找到所选会话对应的消息表")
                messages: list[MessageRecord] = []
                media_jobs: list[tuple[MessageRecord, Mapping[str, Any]]] = []
                cutoff = _dt.datetime.now().timestamp() - days * 86400 if days is not None else None
                for _source, table, database in selected_tables:
                    try:
                        rows = fetch_message_rows(database, table)
                    except DatabaseQueryError:
                        continue
                    # 通用消息表可能混放多个会话，选中会话时必须再次按列过滤。
                    try:
                        conversation_column = choose_column(
                            table_columns(database, table),
                            ("conversation_id", "username", "talker", "chat_name", "user_name"),
                        )
                    except DatabaseQueryError:
                        conversation_column = None
                    if conversation_column and not table.casefold().startswith("msg_"):
                        rows = [
                            row
                            for row in rows
                            if text_value(row_value(row, conversation_column, default=""))
                            == str(conversation_id)
                        ]
                    # Name2Id 和 message_resource.db 的 SenderName2Id 是两套编号，不能合并，否则同号会认错人。
                    local_senders = load_name2id_by_rowid(database)
                    sender_map = local_senders if local_senders else dict(sender_resource)
                    for row in rows:
                        message = parse_message_row(
                            row,
                            str(conversation_id),
                            contacts=contacts,
                            sender_resource=sender_map,
                            self_wxid=self_wxid,
                        )
                        if cutoff is not None and message.raw_timestamp and message.raw_timestamp < cutoff:
                            continue
                        media_jobs.append((message, row))
                        messages.append(message)
                # source 字段是压缩数据，不能当成路径。按媒体 md5 读取真实文件。
                # 解密、转码、下载表情都在等子进程或网络，按消息并行处理。
                context = {
                    "account_root": catalog.account_root,
                    "conversation_id": str(conversation_id),
                    "emoji_index": emoji_index,
                    "cache_dir": _media_cache_dir(),
                    "cached_media": _cached_media_by_stem(catalog.account_root) if catalog.account_root else {},
                }
                results = run_media_jobs(
                    [(message.local_id, row) for message, row in media_jobs],
                    context,
                    media_mode,
                    media_workers,
                )
                for (message, _row), media in zip(media_jobs, results):
                    message.media.extend(media)
                messages = deduplicate_messages(messages)
                media_backends = [
                    backend
                    for backend in auxiliary_backends
                    if self._backend_has_voice_table(backend)
                ]
                if media_backends:
                    self._attach_voice_media(messages, str(conversation_id), media_backends)
                # local_id 只在单个消息库内唯一。用它给 HTML 归媒体，会把别的分片里同号消息的视频贴过来。
                for index, message in enumerate(messages, start=1):
                    message.local_id = index
                    for item in message.media:
                        item.message_id = index
                contact = contacts.get(str(conversation_id), {})
                group = groups.get(str(conversation_id), {})
                title = preferred_display_name(str(conversation_id), contact, group)
                conversation_type = "group" if str(conversation_id).casefold().endswith("@chatroom") else "single"
                conversation = Conversation(
                    conversation_id=str(conversation_id),
                    title=title,
                    recent_time=messages[-1].sent_at if messages else "",
                    recent_message=messages[-1].content if messages else "",
                    conversation_type=conversation_type,
                    peer_id=str(conversation_id),
                    peer_name=title,
                )
                return build_memory_model(conversation, messages)
            finally:
                for _source, database in message_backends:
                    with contextlib.suppress(Exception):
                        database.close()
                for database in auxiliary_backends:
                    with contextlib.suppress(Exception):
                        database.close()

    # 依据账号目录名或联系人记录推断“我”的稳定 wxid。
    def _guess_self_wxid(
        self,
        account_root: Path | None,
        contacts: Mapping[str, Mapping[str, Any]],
    ) -> str:
        if account_root is not None:
            name = account_root.name
            short = name.rsplit("_", 1)[0]
            for candidate in (name, short):
                if candidate.startswith("wxid_") and candidate in contacts:
                    return name if name in contacts else short
            if name.startswith("wxid_"):
                return name
            if short.startswith("wxid_"):
                return short
        for wxid, row in contacts.items():
            if row_value(row, "is_self", "self_flag", "is_me", default=False) in (1, True, "1"):
                return wxid
        return "self"

    # 判断一个后端是否包含 VoiceInfo 或可识别 voice_data 列。
    def _backend_has_voice_table(self, database: DatabaseBackend) -> bool:
        try:
            names = table_names(database)
        except DatabaseQueryError:
            return False
        for table in names:
            if normalized_field_name(table) == "voiceinfo":
                return True
            try:
                if normalized_field_name("voice_data") in {
                    normalized_field_name(column) for column in table_columns(database, table)
                }:
                    return True
            except DatabaseQueryError:
                continue
        return False

    # 从媒体数据库为语音消息附加可播放或原始二进制。
    def _attach_voice_media(
        self,
        messages: Iterable[MessageRecord],
        conversation_id: str,
        databases: Iterable[DatabaseBackend],
    ) -> None:
        for message in messages:
            if message.message_type not in {34, 53}:
                continue
            raw_data: bytes | None = None
            for database in databases:
                try:
                    raw_data = find_voice_data(
                        database,
                        conversation_id,
                        message.local_id,
                        message.server_id,
                        message.raw_timestamp,
                    )
                except DatabaseQueryError:
                    raw_data = None
                if raw_data:
                    break
            if not raw_data:
                continue
            normalized, mime, extension, playable = normalize_audio_bytes(raw_data)
            if not playable and normalized.startswith(SILK_MAGIC):
                wav_data = decode_silk_to_wav(normalized)
                if wav_data:
                    normalized, mime, extension, playable = wav_data, "audio/wav", ".wav", True
            message.media.append(
                MediaRecord(
                    message_id=message.local_id,
                    media_type="voice",
                    mime_type=mime,
                    filename=f"voice_{message.local_id}{extension}",
                    data=normalized,
                    playable=playable,
                )
            )

    # 把账号目录内的已有媒体文件转换成消息媒体记录。
    def _media_from_local_path(self, message_id: int, path: Path) -> list[MediaRecord]:
        return media_records_from_path(message_id, path)

    # 使用 key 文件验证当前可见的所有消息分片，供 DTrace 回调调用。
    def validate_candidate_key(self, key_hex: str) -> tuple[str, ...]:
        return self.validate_key(key_hex)


# 把 Conversation/MessageRecord/普通字典统一为题目约定的内存数据模型。
def build_memory_model(
    conversation: Conversation | Mapping[str, Any],
    messages: Iterable[MessageRecord | Mapping[str, Any]],
    media: Iterable[MediaRecord | Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    if isinstance(conversation, Conversation):
        conversation_id = str(conversation.conversation_id or "")
        title = str(conversation.title or conversation_id)
        raw_conversation_type = str(conversation.conversation_type).casefold()
        conversation_type = "group" if raw_conversation_type in {"group", "chatroom"} or conversation_id.casefold().endswith("@chatroom") else "single"
        peer_id = conversation.peer_id or conversation_id
        peer_name = conversation.peer_name or title
    else:
        conversation_id = text_value(conversation.get("conversation_id", conversation.get("id", "")))
        title = text_value(conversation.get("title") or conversation.get("conversation_title"), conversation_id)
        raw_conversation_type = str(
            conversation.get("conversation_type", "group" if conversation_id.endswith("@chatroom") else "single")
        ).casefold()
        conversation_type = "group" if raw_conversation_type in {"group", "chatroom"} or conversation_id.casefold().endswith("@chatroom") else "single"
        peer_id = text_value(conversation.get("peer_id"), conversation_id)
        peer_name = text_value(conversation.get("peer_name"), title)
    records = list(messages)
    all_media: list[MediaRecord | Mapping[str, Any]] = list(media or [])
    users_by_wxid: dict[str, dict[str, Any]] = {}
    if isinstance(conversation, Mapping):
        for existing in conversation.get("users", []) or []:
            if not isinstance(existing, Mapping):
                continue
            stable = str(existing.get("wxid", "")).strip()
            identifier = integer_id(existing.get("id"), 0)
            if stable and identifier > 0:
                users_by_wxid[stable] = {
                    "id": identifier,
                    "wxid": stable,
                    "name": text_value(existing.get("name"), stable),
                }
    existing_wxid_by_id = {
        int(item["id"]): wxid for wxid, item in users_by_wxid.items()
    }

    # 为稳定 wxid 分配连续的规范化 user.id。
    def ensure_user(wxid: str, name: str = "") -> int:
        stable = str(wxid or "unknown_sender")
        if stable not in users_by_wxid:
            users_by_wxid[stable] = {
                "id": max((int(item["id"]) for item in users_by_wxid.values()), default=0) + 1,
                "wxid": stable,
                "name": text_value(name, stable),
            }
        elif name and users_by_wxid[stable]["name"] in {stable, "未知用户"}:
            users_by_wxid[stable]["name"] = text_value(name, stable)
        return int(users_by_wxid[stable]["id"])

    normalized_messages: list[dict[str, Any]] = []
    for item in records:
        if isinstance(item, MessageRecord):
            sender_wxid = item.sender_wxid
            sender_name = item.sender_name
            sender_id = ensure_user(sender_wxid, sender_name)
            quote_wxid = item.quote_sender_wxid
            if not quote_wxid and item.quote_sender_name:
                # 只有昵称没有 wxid 的旧引用记录也分配稳定的本地占位标识。
                quote_wxid = "quote_" + hashlib.sha256(item.quote_sender_name.encode("utf-8")).hexdigest()[:16]
            quote_sender = ensure_user(quote_wxid, item.quote_sender_name or quote_wxid) if quote_wxid else None
            msg = {
                "local_id": int(item.local_id),
                "server_id": text_value(item.server_id) or None,
                "sent_at": text_value(item.sent_at),
                "sender": sender_id,
                "message_type": int(item.message_type),
                "content": text_value(item.content),
                "quote_sender": quote_sender,
                "quote_content": text_value(item.quote_content) or None,
                "link_url": text_value(item.link_url) or None,
            }
            for key in ("link_title", "link_description", "link_source"):
                value = text_value(getattr(item, key))
                if value:
                    msg[key] = value
            for attached in item.media:
                all_media.append(attached)
        else:
            sender_raw = item.get("sender_wxid", item.get("wxid", item.get("sender", "unknown_sender")))
            sender_is_id = isinstance(sender_raw, int) or (
                isinstance(sender_raw, str) and sender_raw.strip().isdigit()
            )
            if sender_is_id:
                sender_number = integer_id(sender_raw, 0)
                sender_wxid = text_value(
                    item.get("sender_id_wxid", existing_wxid_by_id.get(sender_number, f"unknown_sender_{sender_number}")),
                    f"unknown_sender_{sender_number}",
                )
                sender_id = ensure_user(sender_wxid, text_value(item.get("sender_name"), sender_wxid))
            else:
                sender_wxid = text_value(sender_raw, "unknown_sender")
                sender_id = ensure_user(sender_wxid, text_value(item.get("sender_name"), sender_wxid))
            quote_raw = item.get("quote_sender_wxid", item.get("quote_wxid", item.get("quote_sender")))
            quote_name = text_value(item.get("quote_sender_name"))
            if not quote_raw and quote_name:
                quote_raw = "quote_" + hashlib.sha256(quote_name.encode("utf-8")).hexdigest()[:16]
            if isinstance(quote_raw, int) or (isinstance(quote_raw, str) and quote_raw.strip().isdigit()):
                quote_number = integer_id(quote_raw, 0)
                quote_raw = existing_wxid_by_id.get(quote_number, f"unknown_sender_{quote_number}")
            quote_sender = ensure_user(str(quote_raw), quote_name or str(quote_raw)) if quote_raw else None
            msg = {
                "local_id": integer_id(item.get("local_id", item.get("id", 0))),
                "server_id": text_value(item.get("server_id")) or None,
                "sent_at": text_value(item.get("sent_at")),
                "sender": sender_id,
                "message_type": integer_id(item.get("message_type", item.get("type", 0))),
                "content": text_value(item.get("content")),
                "quote_sender": quote_sender,
                "quote_content": text_value(item.get("quote_content")) or None,
                "link_url": text_value(item.get("link_url")) or None,
            }
            for key in ("link_title", "link_description", "link_source"):
                value = text_value(item.get(key))
                if value:
                    msg[key] = value
            raw_media = item.get("media", [])
            if isinstance(raw_media, (list, tuple)):
                all_media.extend(raw_media)
        normalized_messages.append(msg)
    # 允许调用方单独传入媒体，同时确保 media.message_id 都指向现有消息。
    message_ids = {int(item["local_id"]) for item in normalized_messages}
    normalized_media: list[dict[str, Any]] = []
    seen_media: set[tuple[int, str, str]] = set()
    next_media_id = 1
    for item in all_media:
        if isinstance(item, MediaRecord):
            message_id = int(item.message_id)
            media_item = {
                "id": next_media_id,
                "message_id": message_id,
                "media_type": item.media_type,
                "mime_type": item.mime_type,
                "filename": item.filename,
                "byte_size": len(item.data or b""),
                "sha256": hashlib.sha256(item.data or b"").hexdigest(),
                "data": item.data or b"",
                "playable": bool(item.playable) or str(item.mime_type or "").casefold() in PLAYABLE_AUDIO_MIMES,
            }
        else:
            message_id = integer_id(item.get("message_id", item.get("local_id", 0)))
            raw_data = media_bytes(item)
            media_item = {
                "id": next_media_id,
                "message_id": message_id,
                "media_type": str(item.get("media_type", "file")),
                "mime_type": str(item.get("mime_type", "application/octet-stream")),
                "filename": safe_filename(str(item.get("filename", f"media_{message_id}"))),
                "byte_size": len(raw_data),
                "sha256": hashlib.sha256(raw_data).hexdigest(),
                "data": raw_data,
                "playable": bool(item.get("playable", False))
                or str(item.get("mime_type", "")).casefold() in PLAYABLE_AUDIO_MIMES,
            }
        media_signature = (message_id, str(media_item["media_type"]), media_item["sha256"])
        if message_id in message_ids and media_item["data"] and media_signature not in seen_media:
            normalized_media.append(media_item)
            seen_media.add(media_signature)
            next_media_id += 1
    normalized_messages.sort(key=lambda item: (item["sent_at"], item["local_id"]))
    exported_at = _dt.datetime.now().astimezone().isoformat(timespec="seconds")
    return {
        "meta": {
            "schema_version": 1,
            "conversation_id": conversation_id,
            "conversation_title": title,
            "conversation_type": conversation_type,
            "peer_id": peer_id,
            "peer_name": peer_name,
            "exported_at": exported_at,
            "message_count": len(normalized_messages),
        },
        "users": sorted(users_by_wxid.values(), key=lambda item: int(item["id"])),
        "messages": normalized_messages,
        "media": normalized_media,
    }


# 从模型中建立 user.id 到显示名称的快速索引。
def model_user_names(model: Mapping[str, Any]) -> dict[int, str]:
    result: dict[int, str] = {}
    for item in model.get("users", []) or []:
        if not isinstance(item, Mapping):
            continue
        identifier = integer_id(item.get("id"), 0)
        if identifier:
            result[identifier] = text_value(item.get("name") or item.get("wxid"), "未知用户")
    return result


# 把模型中的媒体对象转换成列表，并按 message_id 建立分组。
def model_media_by_message(model: Mapping[str, Any]) -> dict[int, list[dict[str, Any]]]:
    grouped: dict[int, list[dict[str, Any]]] = {}
    for item in model.get("media", []) or []:
        if not isinstance(item, Mapping):
            continue
        message_id = integer_id(item.get("message_id"), 0)
        if message_id:
            grouped.setdefault(message_id, []).append(dict(item))
    return grouped


# 将模型媒体 data 字段安全转换成 bytes；文件不存在时返回空字节。
def media_bytes(item: Mapping[str, Any]) -> bytes:
    raw = item.get("data", b"")
    if isinstance(raw, memoryview):
        return raw.tobytes()
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    if isinstance(raw, str):
        try:
            return base64.b64decode(raw, validate=True)
        except Exception:
            return raw.encode("utf-8")
    source = item.get("source_path") or item.get("path")
    if source:
        try:
            return Path(str(source)).read_bytes()
        except OSError:
            return b""
    return b""


# 判断链接是否允许在 HTML 导出中作为可点击 URL。
def safe_link_url(value: object) -> str | None:
    text = html.unescape(str(value or "").strip())
    if not text:
        return None
    lowered = text.casefold()
    if lowered.startswith(("https://", "http://")):
        return text
    return None


# 为导出媒体生成唯一文件名并写入 HTML 同目录的 media 子目录。
def write_export_media(
    media_items: Iterable[Mapping[str, Any]],
    output_dir: Path,
) -> tuple[dict[int, list[dict[str, Any]]], list[dict[str, Any]]]:
    media_dir = output_dir / "media"
    if media_dir.is_symlink():
        raise ReaderError("导出媒体目录不能是符号链接")
    media_dir.mkdir(parents=True, exist_ok=True)
    by_message: dict[int, list[dict[str, Any]]] = {}
    manifest_items: list[dict[str, Any]] = []
    used_names: set[str] = set()
    for raw_item in media_items:
        item = dict(raw_item)
        message_id = integer_id(item.get("message_id"), 0)
        data = media_bytes(item)
        if not message_id:
            continue
        base_name = safe_filename(str(item.get("filename", f"media_{message_id}")), f"media_{message_id}")
        if not data:
            # 没有本地字节时仍保留媒体元数据，让 HTML/TXT 显示明确占位符。
            item["filename"] = base_name
            item["relative_path"] = ""
            item["byte_size"] = 0
            item["sha256"] = hashlib.sha256(b"").hexdigest()
            by_message.setdefault(message_id, []).append(item)
            manifest_items.append(
                {
                    "message_id": message_id,
                    "media_type": str(item.get("media_type", "file")),
                    "mime_type": str(item.get("mime_type", "application/octet-stream")),
                    "filename": base_name,
                    "relative_path": None,
                    "byte_size": 0,
                    "sha256": item["sha256"],
                    "available": False,
                }
            )
            continue
        name = base_name
        suffix = 2
        while name in used_names:
            stem = Path(base_name).stem
            extension = Path(base_name).suffix
            name = f"{stem}_{suffix}{extension}"
            suffix += 1
        used_names.add(name)
        target = media_dir / name
        if target.is_symlink():
            raise ReaderError("拒绝覆盖符号链接形式的导出媒体文件")
        try:
            target.write_bytes(data)
        except OSError as exc:
            raise ReaderError("无法写入导出媒体文件") from exc
        item["filename"] = name
        item["byte_size"] = len(data)
        item["sha256"] = hashlib.sha256(data).hexdigest()
        item["relative_path"] = f"media/{name}"
        by_message.setdefault(message_id, []).append(item)
        manifest_items.append(
            {
                "message_id": message_id,
                "media_type": str(item.get("media_type", "file")),
                "mime_type": str(item.get("mime_type", "application/octet-stream")),
                "filename": name,
                "relative_path": item["relative_path"],
                "byte_size": len(data),
                "sha256": item["sha256"],
                "available": True,
            }
        )
    return by_message, manifest_items


# 生成单条消息的安全 HTML 片段，正文和属性全部进行转义。
def render_message_html(
    message: Mapping[str, Any],
    user_names: Mapping[int, str],
    media_by_message: Mapping[int, list[Mapping[str, Any]]],
) -> str:
    local_id = integer_id(message.get("local_id"), 0)
    sender_id = integer_id(message.get("sender"), 0)
    sender_name = html.escape(str(user_names.get(sender_id, "未知用户")))
    sent_at = html.escape(str(message.get("sent_at", "")))
    content = str(message.get("content", ""))
    content_html = html.escape(content).replace("\n", "<br>\n")
    body: list[str] = []
    quote_content = message.get("quote_content")
    if quote_content or message.get("quote_sender") is not None:
        quote_sender_id = integer_id(message.get("quote_sender"), 0)
        quote_sender = html.escape(str(user_names.get(quote_sender_id, "未知用户")))
        quote_display = str(quote_content or "[原消息内容不可用]")
        body.append(
            '<blockquote><div class="quote-sender">引用 '
            + quote_sender
            + '</div><div class="quote-content">'
            + html.escape(quote_display).replace("\n", "<br>\n")
            + "</div></blockquote>"
        )
    link_url = safe_link_url(message.get("link_url"))
    showed_link = False
    if link_url:
        link_title = html.escape(str(message.get("link_title") or content or "链接"))
        link_description = html.escape(str(message.get("link_description") or ""))
        link_source = html.escape(str(message.get("link_source") or ""))
        body.append(
            '<a class="link-card" href="'
            + html.escape(link_url, quote=True)
            + '" target="_blank" rel="noopener noreferrer">'
            + f'<strong>{link_title}</strong>'
            + (f'<span class="link-description">{link_description}</span>' if link_description else "")
            + (f'<small class="link-source">{link_source}</small>' if link_source else "")
            + "</a>"
        )
        showed_link = True
    media_items = list(media_by_message.get(local_id, []))
    if any(str(item.get("media_type", "")).casefold() == "video" for item in media_items):
        media_items = [item for item in media_items if str(item.get("media_type", "")).casefold() != "image"]
    if content_html and not showed_link and not (media_items and content in {"[图片]", "[视频]", "[表情]"}):
        body.append(f'<div class="message-content">{content_html}</div>')
    for item in media_items:
        relative = html.escape(str(item.get("relative_path", "")), quote=True)
        media_type = str(item.get("media_type", "file")).casefold()
        playable = bool(item.get("playable", False)) or str(item.get("mime_type", "")).casefold() in PLAYABLE_AUDIO_MIMES
        is_voice = media_type in {"voice", "audio"}
        if is_voice and playable and relative:
            body.append(f'<audio controls src="{relative}"></audio>')
        elif media_type == "image" and relative:
            body.append(f'<img class="message-image" loading="lazy" src="{relative}" alt="图片">')
        elif media_type == "video" and relative:
            body.append(f'<video class="message-video" controls preload="metadata" src="{relative}"></video>')
        elif is_voice:
            body.append('<span class="media-placeholder">[语音不可播放]</span>')
        elif media_type == "image":
            body.append('<span class="media-placeholder">[图片不可用]</span>')
        elif media_type == "video":
            body.append('<span class="media-placeholder">[视频不可用]</span>')
        elif relative:
            filename = html.escape(str(item.get("filename", "文件")), quote=True)
            body.append(f'<a class="media-file" href="{relative}" download>{filename}</a>')
        else:
            filename = html.escape(str(item.get("filename", "文件")))
            body.append(f'<span class="media-placeholder">[文件：{filename}]</span>')
    if not body:
        body.append('<div class="message-content">[未知消息]</div>')
    return (
        f'<article class="message" data-message-id="{html.escape(str(local_id), quote=True)}">'
        f'<span class="message-id" aria-hidden="true">{html.escape(str(local_id))}</span>'
        f'<header><strong>{sender_name}</strong><time>{sent_at}</time></header>'
        + "".join(body)
        + "</article>"
    )


# 删掉上一次导出写在这个目录里的文件，便于直接覆盖。不删除目录中的其他文件。
def clear_previous_export(destination: Path, names: Iterable[str]) -> None:
    for name in names:
        path = destination / name
        try:
            if path.is_symlink() or path.is_file():
                path.unlink()
            elif path.is_dir():
                shutil.rmtree(path)
        except OSError as exc:
            raise ReaderError("无法覆盖已有导出文件") from exc


# 导出微信会话为带微信绿主题的 index.html 和 manifest.json。
def export_html(model: Mapping[str, Any], output_dir: Path | str) -> Path:
    destination = Path(output_dir).expanduser()
    destination.mkdir(parents=True, exist_ok=True)
    clear_previous_export(destination, ("index.html", "manifest.json", "media"))
    user_names = model_user_names(model)
    media_by_message, manifest_media = write_export_media(model.get("media", []) or [], destination)
    messages = [item for item in (model.get("messages", []) or []) if isinstance(item, Mapping)]
    messages.sort(key=lambda item: (str(item.get("sent_at", "")), integer_id(item.get("local_id"), 0)))
    meta = model.get("meta", {}) if isinstance(model.get("meta", {}), Mapping) else {}
    title = str(meta.get("conversation_title", meta.get("conversation_id", "微信会话")))
    rendered = "\n".join(render_message_html(item, user_names, media_by_message) for item in messages)
    document = f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root {{ color-scheme: light; font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "PingFang SC", "Microsoft YaHei UI", "Microsoft YaHei", sans-serif; }}
body {{ margin: 0; background: #f5f6f7; color: #1f2329; }}
.page {{ max-width: 920px; margin: 0 auto; padding: 28px 18px 48px; }}
h1 {{ color: #07c160; font-size: 25px; margin: 0 0 6px; }}
.meta {{ color: #7a7f85; font-size: 13px; margin-bottom: 22px; }}
.message {{ position: relative; background: #fff; border-radius: 12px; box-shadow: 0 1px 3px #0000000d; padding: 14px 16px; margin: 10px 0; }}
.message header {{ display: flex; gap: 12px; align-items: baseline; margin-bottom: 7px; }}
.message header strong {{ color: #078a4a; }}
.message time {{ color: #9aa0a6; font-size: 12px; }}
.message-content {{ white-space: normal; line-height: 1.65; overflow-wrap: anywhere; }}
.message-id {{ position: absolute; right: 12px; top: 10px; color: #c4c8cc; font: 11px ui-monospace, monospace; }}
blockquote {{ border-left: 3px solid #b7e8ce; margin: 8px 0 10px; padding: 6px 11px; color: #697078; background: #f7fbf8; }}
.quote-sender {{ font-size: 12px; color: #078a4a; margin-bottom: 3px; }}
.link-card {{ display: flex; flex-direction: column; gap: 5px; border: 1px solid #d7efe1; border-radius: 9px; padding: 11px 13px; color: #1f2329; text-decoration: none; background: #fbfffc; }}
.link-card:hover {{ border-color: #07c160; background: #f2fff7; }}
.link-description {{ color: #687078; font-size: 13px; }}
.link-source {{ color: #9aa0a6; font-size: 12px; }}
audio, video {{ max-width: 100%; margin-top: 8px; }}
.message-image {{ max-width: min(520px, 100%); max-height: 520px; border-radius: 8px; margin-top: 8px; }}
.media-file {{ display: inline-block; color: #078a4a; margin-top: 8px; text-decoration: underline; }}
.media-placeholder {{ display: inline-block; color: #89919a; background: #f1f3f5; border-radius: 6px; padding: 5px 9px; margin-top: 7px; }}
</style>
</head>
<body><main class="page">
<h1>{html.escape(title)}</h1>
<div class="meta">消息数：{len(messages)} · 导出时间：{html.escape(str(meta.get("exported_at", "")))}</div>
{rendered}
</main></body></html>
"""
    index_path = destination / "index.html"
    if index_path.is_symlink() or (destination / "manifest.json").is_symlink():
        raise ReaderError("拒绝覆盖符号链接形式的导出文件")
    index_path.write_text(document, encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "conversation": dict(meta),
        "message_count": len(messages),
        "media": manifest_media,
        "files": ["index.html", "manifest.json"]
        + [item["relative_path"] for item in manifest_media if item.get("relative_path")],
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return index_path


# 导出微信会话为按时间排序的 UTF-8 纯文本 chat.txt。
def export_text(model: Mapping[str, Any], output_dir: Path | str) -> Path:
    destination = Path(output_dir).expanduser()
    destination.mkdir(parents=True, exist_ok=True)
    clear_previous_export(destination, ("chat.txt",))
    user_names = model_user_names(model)
    media_by_message = model_media_by_message(model)
    lines: list[str] = []
    messages = [item for item in model.get("messages", []) or [] if isinstance(item, Mapping)]
    messages.sort(key=lambda item: (str(item.get("sent_at", "")), integer_id(item.get("local_id"), 0)))
    for item in messages:
        sender = user_names.get(integer_id(item.get("sender"), 0), "未知用户")
        sent_at = str(item.get("sent_at", "")) or "未知时间"
        content = str(item.get("content", ""))
        if not content:
            placeholders: list[str] = []
            for media in media_by_message.get(integer_id(item.get("local_id"), 0), []):
                media_type = str(media.get("media_type", "媒体")).casefold()
                if media_type in {"voice", "audio"}:
                    placeholders.append("[语音通话]")
                elif media_type == "image":
                    placeholders.append("[图片]")
                elif media_type == "video":
                    placeholders.append("[视频]")
                else:
                    filename = safe_filename(str(media.get("filename", "")), "文件")
                    placeholders.append(f"[文件：{filename}]")
            content = " ".join(placeholders) or "[未知消息]"
        lines.extend([f"[{sent_at}] {sender}", content])
        link_url = safe_link_url(item.get("link_url"))
        if link_url:
            lines.append(f"链接：{link_url}")
        if item.get("quote_content") or item.get("quote_sender") is not None:
            quote_sender = user_names.get(integer_id(item.get("quote_sender"), 0), "未知用户")
            quote_text = str(item.get("quote_content") or "[原消息内容不可用]").replace("\n", "\n  ")
            lines.extend(
                ["", f"  引用 {quote_sender}：", f"  {quote_text}"]
            )
        lines.append("")
    text_path = destination / "chat.txt"
    if text_path.is_symlink():
        raise ReaderError("拒绝覆盖符号链接形式的文本导出文件")
    text_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return text_path


# 将规范化模型写入用户明确选择的 chat.sqlite，并执行外键完整性检查。
def export_sqlite(model: Mapping[str, Any], output_dir: Path | str) -> Path:
    destination = Path(output_dir).expanduser()
    destination.mkdir(parents=True, exist_ok=True)
    clear_previous_export(destination, ("chat.sqlite", ".chat.sqlite.tmp"))
    target = destination / "chat.sqlite"
    temporary = destination / ".chat.sqlite.tmp"
    temporary.unlink(missing_ok=True)
    meta = model.get("meta", {}) if isinstance(model.get("meta", {}), Mapping) else {}
    try:
        connection = sqlite3.connect(str(temporary))
        with contextlib.suppress(OSError):
            os.chmod(temporary, 0o600)
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.executescript(
                """
                CREATE TABLE meta (
                  key TEXT PRIMARY KEY,
                  value TEXT NOT NULL
                );
                CREATE TABLE "user" (
                  id INTEGER PRIMARY KEY,
                  wxid TEXT NOT NULL UNIQUE,
                  name TEXT NOT NULL
                );
                CREATE TABLE message (
                  local_id INTEGER PRIMARY KEY,
                  server_id TEXT,
                  sent_at TEXT NOT NULL,
                  sender INTEGER NOT NULL REFERENCES "user"(id),
                  message_type INTEGER NOT NULL,
                  content TEXT,
                  quote_sender INTEGER REFERENCES "user"(id),
                  quote_content TEXT,
                  link_url TEXT
                );
                CREATE TABLE media (
                  id INTEGER PRIMARY KEY,
                  message_id INTEGER NOT NULL REFERENCES message(local_id),
                  media_type TEXT NOT NULL,
                  mime_type TEXT NOT NULL,
                  filename TEXT NOT NULL,
                  byte_size INTEGER NOT NULL,
                  sha256 TEXT NOT NULL,
                  data BLOB NOT NULL
                );
                """
            )
            meta_values = {
                "conversation_id": meta.get("conversation_id", ""),
                "conversation_title": meta.get("conversation_title", ""),
                "conversation_type": meta.get("conversation_type", "single"),
                "peer_id": meta.get("peer_id", ""),
                "peer_name": meta.get("peer_name", ""),
                "exported_at": meta.get("exported_at", ""),
                "message_count": meta.get("message_count", len(model.get("messages", []) or [])),
                "schema_version": meta.get("schema_version", 1),
            }
            connection.executemany(
                "INSERT INTO meta(key, value) VALUES (?, ?)",
                [(str(key), str(value if value is not None else "")) for key, value in meta_values.items()],
            )
            users = [item for item in model.get("users", []) or [] if isinstance(item, Mapping)]
            connection.executemany(
                'INSERT INTO "user"(id, wxid, name) VALUES (?, ?, ?)',
                [
                    (
                        integer_id(item.get("id"), 0),
                        str(item.get("wxid", "unknown_sender")),
                        str(item.get("name", item.get("wxid", "未知用户"))),
                    )
                    for item in users
                    if integer_id(item.get("id"), 0) > 0
                ],
            )
            messages = [item for item in model.get("messages", []) or [] if isinstance(item, Mapping)]
            messages.sort(key=lambda item: (str(item.get("sent_at", "")), integer_id(item.get("local_id"), 0)))
            valid_user_ids = {integer_id(item.get("id"), 0) for item in users}
            inserted_message_ids: set[int] = set()
            message_rows: list[tuple[Any, ...]] = []
            for item in messages:
                local_id = integer_id(item.get("local_id"), 0)
                sender_id = integer_id(item.get("sender"), 0)
                if local_id <= 0 or sender_id not in valid_user_ids or local_id in inserted_message_ids:
                    continue
                inserted_message_ids.add(local_id)
                quote_id = integer_id(item.get("quote_sender"), 0)
                message_rows.append(
                    (
                        local_id,
                        str(item.get("server_id")) if item.get("server_id") is not None else None,
                        str(item.get("sent_at", "")),
                        sender_id,
                        integer_id(item.get("message_type"), 0),
                        item.get("content"),
                        quote_id if quote_id in valid_user_ids else None,
                        item.get("quote_content"),
                        item.get("link_url"),
                    )
                )
            connection.executemany(
                "INSERT INTO message(local_id, server_id, sent_at, sender, message_type, content, quote_sender, quote_content, link_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                message_rows,
            )
            media_items = [item for item in model.get("media", []) or [] if isinstance(item, Mapping)]
            media_rows: list[tuple[Any, ...]] = []
            for index, item in enumerate(media_items, 1):
                message_id = integer_id(item.get("message_id"), 0)
                data = media_bytes(item)
                if message_id <= 0 or message_id not in inserted_message_ids or not data:
                    continue
                media_rows.append(
                    (
                        index,
                        message_id,
                        str(item.get("media_type", "file")),
                        str(item.get("mime_type", "application/octet-stream")),
                        safe_filename(str(item.get("filename", f"media_{message_id}"))),
                        len(data),
                        hashlib.sha256(data).hexdigest(),
                        sqlite3.Binary(data),
                    )
                )
            connection.executemany(
                "INSERT INTO media(id, message_id, media_type, mime_type, filename, byte_size, sha256, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                media_rows,
            )
            connection.commit()
            foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
            if foreign_key_errors:
                raise ReaderError("SQLite 导出外键检查失败")
        finally:
            connection.close()
        os.replace(temporary, target)
        with contextlib.suppress(OSError):
            os.chmod(target, 0o600)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return target


# 按格式分派导出器，供 GUI 和命令行测试共用。
def export_model(model: Mapping[str, Any], fmt: str, output_dir: Path | str) -> Path:
    normalized = str(fmt).strip().casefold()
    if normalized in {"html", ".html"}:
        return export_html(model, output_dir)
    if normalized in {"txt", "text", ".txt"}:
        return export_text(model, output_dir)
    if normalized in {"sqlite", "sql", ".sqlite"}:
        return export_sqlite(model, output_dir)
    raise ReaderError("不支持的导出格式")


# 兼容常见调用名称：将模型导出为 HTML。
def export_to_html(model: Mapping[str, Any], output_dir: Path | str) -> Path:
    return export_html(model, output_dir)


# 兼容常见调用名称：将模型导出为纯文本。
def export_to_text(model: Mapping[str, Any], output_dir: Path | str) -> Path:
    return export_text(model, output_dir)


# 兼容常见调用名称：将模型导出为 SQLite。
def export_to_sqlite(model: Mapping[str, Any], output_dir: Path | str) -> Path:
    return export_sqlite(model, output_dir)


# 兼容调用方常用命名：扫描微信消息分片。
def scan_message_databases(data_root: Path | str | None = None, home: Path | None = None) -> list[Path]:
    return discover_message_databases(data_root, home)


# 兼容调用方常用命名：验证一个 key 是否能打开聊天分片。
def validate_sqlcipher_key(
    key_hex: str,
    message_paths: Iterable[Path | str],
    database_factory: Callable[[Path, str], DatabaseBackend] | None = None,
) -> tuple[str, ...]:
    reader = WeChatReader(message_paths=message_paths, database_factory=database_factory)
    return reader.validate_key(key_hex)


__all__ = [
    "Conversation",
    "DatabaseBackend",
    "DatabaseCatalog",
    "DatabaseQueryError",
    "MediaRecord",
    "MessageRecord",
    "PLAYABLE_AUDIO_MIMES",
    "PythonSQLCipherBackend",
    "ReaderError",
    "SQLCipherCLIBackend",
    "SQLiteBackend",
    "WeChatReader",
    "build_database_catalog",
    "build_memory_model",
    "classify_message",
    "copy_database_snapshot",
    "choose_column",
    "database_snapshot",
    "decode_message_content",
    "default_wechat_data_roots",
    "detect_sqlcipher_key_mode",
    "decode_silk_to_wav",
    "deduplicate_messages",
    "discover_message_databases",
    "export_html",
    "export_model",
    "export_sqlite",
    "export_text",
    "export_to_html",
    "export_to_sqlite",
    "export_to_text",
    "find_message_tables",
    "fetch_message_rows",
    "find_sqlcipher_driver",
    "find_sqlcipher_executable",
    "find_voice_data",
    "format_timestamp",
    "is_system_conversation",
    "local_media_path",
    "media_bytes",
    "model_media_by_message",
    "model_user_names",
    "normalize_audio_bytes",
    "normalized_field_name",
    "normalize_reader_keys",
    "open_database_backend",
    "open_with_candidate_keys",
    "parse_cli_json",
    "parse_message_row",
    "parse_message_xml",
    "parse_recent_days",
    "preferred_display_name",
    "render_message_html",
    "row_dict",
    "row_value",
    "safe_filename",
    "safe_link_url",
    "scan_message_databases",
    "sql_identifier",
    "sqlcipher4_raw_key_matches",
    "sqlcipher_key_recipes",
    "sql_literal",
    "table_columns",
    "table_names",
    "text_value",
    "timestamp_seconds",
    "validate_sqlcipher_key",
    "write_export_media",
    "xml_attribute",
]
