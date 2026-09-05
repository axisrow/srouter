"""PR-1 #339: единый примитивный слой бэкапов (backup_lib) + канон atomic-write.

Контракт v2 (issue #339): naming-константы (BACKUP_INFIX / SIDECAR_SUFFIX) — единый
источник, потребители (install_config, claude_proxy, vscode_proxy) делегируют, а не
дублируют; create_backup атомарен (tmp + os.replace) — сбой посреди копии не оставляет
частично-записанный файл под ВАЛИДНЫМ backup-именем, который discover засчитает как
поколение (дыра прежнего shutil.copy2(path, backup) в install_config._backup);
discover — disk-доказательство (fullmatch-парс stamp), семантика перенесена из
install_config.discover_backups без изменений.
"""
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

import backup_lib
import claude_proxy
import install_config
import vscode_proxy
from test_install_flow import _env


# ============================ naming: единый источник ============================
def test_naming_constants_single_source():
    """BACKUP_INFIX/SIDECAR_SUFFIX определены в backup_lib; install-слой берёт оттуда же."""
    assert backup_lib.BACKUP_INFIX == ".srouter-backup-"
    assert backup_lib.SIDECAR_SUFFIX == ".srouter-proxy-backup.json"
    assert install_config._BACKUP_INFIX == backup_lib.BACKUP_INFIX


def test_sidecar_path_single_source():
    """claude/vscode sidecar-lease живёт по backup_lib.sidecar_path (суффикс не дублируется)."""
    assert claude_proxy._backup_path() == backup_lib.sidecar_path(claude_proxy.SETTINGS)
    sample = Path("/Editors/App/settings.json")
    assert vscode_proxy._backup_path(sample) == backup_lib.sidecar_path(sample)
    assert backup_lib.sidecar_path(sample).name.endswith(
        "settings.json.srouter-proxy-backup.json")


def test_user_backups_dir_canonical():
    """Каталог бэкапов СОБСТВЕННЫХ артефактов srouter, user-уровень (контракт v2)."""
    assert backup_lib.USER_BACKUPS_DIR == (
        Path.home() / "Library" / "Application Support" / "srouter" / "backups")


# ============================ stamp: формат имени ============================
def test_backup_stamp_sanitizes_and_roundtrips():
    """stamp = env.now без ':' ('/' → '-'); parse — обратная операция, не «почти-regex»."""
    stamp = backup_lib.backup_stamp("2026-09-05T10:11:12Z")
    assert stamp == "2026-09-05T101112Z"
    parsed = backup_lib.parse_stamp(stamp)
    assert parsed == datetime(2026, 9, 5, 10, 11, 12, tzinfo=timezone.utc)
    assert backup_lib.parse_stamp("not-a-stamp") is None
    assert backup_lib.parse_stamp("2026-09-05T10:11:12Z") is None  # необрезанный ISO — не формат имени


def test_parse_iso_utc_for_state_fields():
    """created_at хранится в НЕобрезанном ISO (с ':') — отдельный парсер, fail-open-граница."""
    assert backup_lib.parse_iso_utc("2026-09-05T10:11:12Z") == (
        datetime(2026, 9, 5, 10, 11, 12, tzinfo=timezone.utc))
    assert backup_lib.parse_iso_utc(None) is None
    assert backup_lib.parse_iso_utc(123) is None
    assert backup_lib.parse_iso_utc("garbage") is None


def test_backup_path_uses_infix():
    target = Path("/opt/etc/xray/config.json")
    assert backup_lib.backup_path(target, "2026-09-05T10:11:12Z") == Path(
        "/opt/etc/xray/config.json.srouter-backup-2026-09-05T101112Z")


# ============================ create_backup: атомарность ============================
def _partial_copy2_then_enospc(src, dst, *, follow_symlinks=True):
    """Обрыв ПОСЕРЕДИНЕ копии: в dst успели попасть байты, затем диск отказал."""
    Path(dst).write_text("partia", encoding="utf-8")
    raise OSError("ENOSPC")


def test_install_config_backup_crash_mid_copy_leaves_no_valid_name_file(tmp_path, monkeypatch):
    """Дыра PR-1: shutil.copy2(path, <финальное имя>) при обрыве оставляла частичный файл
    под ВАЛИДНЫМ backup-именем — discover_backups засчитала бы его как поколение, и
    uninstall могла бы «восстановить» пользователю обрезанный конфиг. Канон atomic-save:
    копия во tmp (tmp-хвост отсекается fullmatch-парсером), затем os.replace."""
    target = tmp_path / "config"
    target.write_text("foreign config, весь целиком\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "copy2", _partial_copy2_then_enospc)

    out = install_config._backup(target, _env(tmp_path))

    assert out == ""
    leftovers = list(tmp_path.glob("config.srouter-backup-*"))
    assert leftovers == [], f"частичная копия под валидным именем: {leftovers}"
    assert target.read_text(encoding="utf-8") == "foreign config, весь целиком\n"


def test_create_backup_crash_mid_copy_leaves_no_valid_name_file(tmp_path, monkeypatch):
    target = tmp_path / "config"
    target.write_text("foreign config\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "copy2", _partial_copy2_then_enospc)

    out = backup_lib.create_backup(target, _env(tmp_path))

    assert out == ""
    assert list(tmp_path.glob("config.srouter-backup-*")) == []


def test_create_backup_preserves_content_mode_and_makes_discoverable(tmp_path):
    target = tmp_path / "config"
    target.write_text("foreign config\n", encoding="utf-8")
    os.chmod(target, 0o640)

    out = backup_lib.create_backup(target, _env(tmp_path))

    backup = Path(out)
    assert backup.name == "config.srouter-backup-2026-06-29T000000Z"
    assert backup.read_text(encoding="utf-8") == "foreign config\n"
    assert (backup.stat().st_mode & 0o777) == 0o640, "режим оригинала сохранён (copy2-семантика)"
    assert backup_lib.discover(target) == [backup]
    assert install_config.discover_backups(target) == [backup], "делегирование семантики"


def test_create_backup_missing_target_returns_empty(tmp_path):
    assert backup_lib.create_backup(tmp_path / "absent", _env(tmp_path)) == ""


def test_install_config_backup_delegates_to_backup_lib(tmp_path, monkeypatch):
    """install-слой — фасад поверх примитива (канон #229: экстракция, не редизайн)."""
    calls = []

    def spy(path, env):
        calls.append((path, env))
        return str(path) + ".spied"

    monkeypatch.setattr(backup_lib, "create_backup", spy)
    target = tmp_path / "config"
    target.write_text("x", encoding="utf-8")
    env = _env(tmp_path)
    assert install_config._backup(target, env) == str(target) + ".spied"
    assert calls == [(target, env)]


# ============================ discover: disk-доказательство ============================
def test_discover_orders_old_to_new_and_rejects_impostors(tmp_path):
    """Семантика discover_backups (issue #124) перенесена без изменений: fullmatch-парс
    stamp, old→new, только regular file (симлинк/директория — вектор подмены), хвостовые
    .tmp от атомарной записи и вложенные двойные суффиксы отсекаются."""
    target = tmp_path / "config"
    target.write_text("current\n", encoding="utf-8")

    old = tmp_path / "config.srouter-backup-2026-01-01T000000Z"
    old.write_text("old\n", encoding="utf-8")
    new = tmp_path / "config.srouter-backup-2026-06-29T000000Z"
    new.write_text("new\n", encoding="utf-8")

    bad_stamp = tmp_path / "config.srouter-backup-x"
    bad_stamp.write_text("x", encoding="utf-8")
    tmp_tail = tmp_path / "config.srouter-backup-2026-06-29T000000Z.tmp"
    tmp_tail.write_text("partial", encoding="utf-8")
    nested = tmp_path / "config.srouter-backup-2026-06-29T000000Z.srouter-backup-2026-06-29T000000Z"
    nested.write_text("nested", encoding="utf-8")
    directory = tmp_path / "config.srouter-backup-2026-05-05T000000Z"
    directory.mkdir()
    linked = tmp_path / "config.srouter-backup-2026-04-04T000000Z"
    linked.symlink_to(old)

    assert backup_lib.discover(target) == [old, new]
    assert backup_lib.discover(tmp_path / "absent") == []
