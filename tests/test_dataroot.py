"""Mac 容器目录和 Windows 配置目录都能定位到当前账号的 db_storage。"""

from __future__ import annotations

import os
from pathlib import Path

from read_wechat_conversation import current_wechat_account_key, default_wechat_data_roots, discover_message_databases
from wxwatch.dataroot import locate_db_storage


_INI_NAME = "51a1fffea11325a1e4104c6b3de47af7.ini"


def _touch_message(account: Path, name: str = "message_0.db", stamp: int = 1_700_000_000) -> Path:
    message = account / "db_storage" / "message"
    message.mkdir(parents=True, exist_ok=True)
    db = message / name
    db.write_bytes(b"x")
    os.utime(db, (stamp, stamp))
    return db


def test_windows_ini_path_beats_documents(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WECHAT_DATA_ROOT", raising=False)
    custom = tmp_path / "custom-save"
    account = custom / "xwechat_files" / "wxid_cfg_ab12"
    _touch_message(account)
    decoy = tmp_path / "Documents" / "xwechat_files" / "wxid_decoy_cd34"
    _touch_message(decoy, stamp=1_800_000_000)
    ini = tmp_path / "AppData" / "Roaming" / "Tencent" / "xwechat" / "config" / _INI_NAME
    ini.parent.mkdir(parents=True)
    ini.write_bytes(str(custom).encode("utf-8"))

    found = locate_db_storage(tmp_path)
    assert found == account / "db_storage"
    roots = default_wechat_data_roots(tmp_path)
    assert custom / "xwechat_files" in roots
    discovered = discover_message_databases(home=tmp_path)
    assert discovered == [account / "db_storage" / "message" / "message_0.db"]


def test_windows_mydocument_token_uses_documents(tmp_path: Path) -> None:
    account = tmp_path / "Documents" / "xwechat_files" / "wxid_doc_aa11"
    _touch_message(account)
    ini = tmp_path / "AppData" / "Roaming" / "Tencent" / "xwechat" / "config" / _INI_NAME
    ini.parent.mkdir(parents=True)
    ini.write_text("MyDocument:", encoding="utf-8")
    assert locate_db_storage(tmp_path) == account / "db_storage"


def test_macos_container_db_storage(tmp_path: Path) -> None:
    account = (
        tmp_path
        / "Library"
        / "Containers"
        / "com.tencent.xinWeChat"
        / "Data"
        / "Documents"
        / "xwechat_files"
        / "wxid_mac_bb22"
    )
    _touch_message(account)
    assert locate_db_storage(tmp_path) == account / "db_storage"


def test_login_marker_selects_corresponding_account(tmp_path: Path) -> None:
    busy = tmp_path / "xwechat_files" / "wxid_busy_1111"
    quiet = tmp_path / "xwechat_files" / "wxid_quiet_2222"
    _touch_message(busy, stamp=1_700_000_000)
    _touch_message(quiet, stamp=1_900_000_000)
    login = tmp_path / "xwechat_files" / "all_users" / "login"
    busy_login = login / "wxid_busy"
    quiet_login = login / "wxid_quiet"
    busy_login.mkdir(parents=True)
    quiet_login.mkdir(parents=True)
    key = busy_login / "key_info.db"
    key.write_bytes(b"k")
    os.utime(key, (1_950_000_000, 1_950_000_000))
    os.utime(busy_login, (1_600_000_000, 1_600_000_000))
    os.utime(quiet_login, (1_800_000_000, 1_800_000_000))
    assert current_wechat_account_key(tmp_path) == "wxid_busy"
    assert locate_db_storage(tmp_path) == busy / "db_storage"


def test_without_login_marker_uses_newest_message_db(tmp_path: Path) -> None:
    older = tmp_path / "Documents" / "xwechat_files" / "wxid_aaa_abcd"
    newer = tmp_path / "Documents" / "xwechat_files" / "wxid_zzz_abcd"
    _touch_message(older, stamp=1_700_000_000)
    _touch_message(newer, stamp=1_800_000_000)
    assert locate_db_storage(tmp_path) == newer / "db_storage"
