#!/usr/bin/python3
"""Защищённый system-режим Privoxy для macOS.

Root-часть намеренно использует только stdlib, фиксированные абсолютные пути и закрытый набор
операций. Произвольные команды, shell=True и пользовательские target-path здесь запрещены.

АРХИТЕКТУРНЫЙ ИНВАРИАНТ (issue #287, tree-copy redesign — заменяет прежний single-file
инвариант issue #158): этот файл — entrypoint root-owned helper-ДЕРЕВА. Install копирует ЕГО
и соседние helper_tree-модули (см. HELPER_TREE_MODULES ниже) ВМЕСТЕ в
/Library/PrivilegedHelperTools/<entrypoint>(.modules/) — каждый файл дерева пиновым digest'ом
(см. _read_helper_tree_pinned/_install_helper в privoxy_control.py), и исполняется ИЗОЛИРОВАННО
через sudo — рядом с деревом нет других модулей srouter (только stdlib в каждом файле дерева,
каноны root-helper-stdlib-only-no-shared-imports, helper-stdlib-only-no-dashboard-common
ОБНОВЛЕНЫ #287: helper-модули МЕЖДУ СОБОЙ импортировать друг друга МОГУТ — это и есть дерево —
но по-прежнему НЕ dashboard_common/srouter_config/local_state и т.п.). Модуль делает
`sys.path.insert(0, <helper_modules_dir>)` В САМОМ НАЧАЛЕ (до import privoxy_helper_*) — под
sudo working directory непредсказуем, соседей нужно резолвить от каталога, произведённого от
пути entrypoint (helper_path.parent / f"{helper_path.name}.modules"), а не от CWD.

Helper payload теперь распределён по нескольким файлам-соседям (каждый — ТОЖЕ root-owned,
ТОЖЕ stdlib-only, ТОЖЕ копируется деревом, но НЕ дробится дальше без причины):
  - privoxy_helper_fs.py       — fd-pinning atomic-write/copy-tree/backup примитивы
  - privoxy_helper_launchd.py  — runner/launchd-обвязка, Privoxy runtime relink+codesign
  - privoxy_helper_config.py   — protected-config/plist/manifest/policy
Этот файл (privoxy_system.py) — entrypoint: helper_main, protect_as_root/unprotect_as_root/
control_as_root (транзакционная оркестрация верхнего уровня), tree digest-pinning install-примитивы.
Top-level `import privoxy_helper_fs` и т.п. здесь БЕЗОПАСЕН (в отличие от privoxy_control) —
tree-copy install гарантирует, что эти файлы физически рядом с entrypoint в production;
regression-гвард test_privoxy_system_helper_runs_isolated_without_dashboard_common адаптирован
под дерево (копирует ВСЕ файлы дерева, не один файл — см. docstring теста).

Пользовательская оркестрация (protect/unprotect/control/status, установка helper-дерева,
read-modify-write local_state) вынесена в privoxy_control.py — тот модуль выполняется в основном
процессе srouter и НЕ копируется под sudo, поэтому безопасно импортирует local_state/sys_probe.
Этот файл реэкспортирует его публичные имена в конце (facade re-export), полный контракт см. в
docstring privoxy_control.py.
"""

from __future__ import annotations

# srouter-protected-helper-v1

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import sys
import tempfile

# sys.path prepend ДО импорта соседей (issue #287): под sudo рабочая директория
# непредсказуема (production запускает helper из /Library/PrivilegedHelperTools через
# `sudo <helper_path> ...`, CWD процесса-родителя может быть где угодно). Соседние
# helper-модули копируются tree-copy install'ом НЕ рядом с entrypoint напрямую, а в
# поддиректорию `<entrypoint-name>.modules/` (см. ProtectedLayout.helper_modules_dir) —
# module-имя производится от __file__ тем же правилом, поэтому entrypoint резолвит её
# самостоятельно, не читая ProtectedLayout (тот определён ниже в этом же файле, но
# sys.path должен быть готов ДО import privoxy_helper_*, т.е. раньше в исполнении модуля).
# os.path, не Path.resolve(), — на случай что __file__ уже абсолютен (typical: install
# кладёт entrypoint по абсолютному helper_path).
_entry_dir = os.path.dirname(os.path.abspath(__file__))
_entry_name = os.path.basename(os.path.abspath(__file__))
_modules_dir = os.path.join(_entry_dir, f"{_entry_name}.modules")
# Fallback на _entry_dir, если modules-директория ещё не существует (dev/test-запуск
# из репозитория, где helper_helper_*.py лежат рядом с privoxy_system.py напрямую, не в
# поддиректории *.modules — см. regression-тест test_privoxy_system_helper_runs_isolated_*).
sys.path.insert(0, _modules_dir if os.path.isdir(_modules_dir) else _entry_dir)

import privoxy_helper_config
import privoxy_helper_fs
import privoxy_helper_launchd


PROTECTION_VERSION = 1
# Маркеры/label — единственный источник в privoxy_helper_config (там их читает
# _managed_file/protection_present внутри helper-дерева). Здесь ТОЛЬКО алиас, не копия
# литерала: расхождение маркеров = foreign-helper guard перестаёт узнавать свой же
# managed-файл (fail-closed → protect/unprotect ломаются) — см. parity-тест в
# tests/test_proxy_constants.py.
PROTECTED_MARKER = privoxy_helper_config.PROTECTED_MARKER
HELPER_MARKER = "srouter-protected-helper-v1"
SUDOERS_MARKER = privoxy_helper_config.SUDOERS_MARKER
SYSTEM_LABEL = privoxy_helper_config.SYSTEM_LABEL
USER_LABEL = "homebrew.mxcl.privoxy"
SYSTEM_DOMAIN = "system"
SUDO = "/usr/bin/sudo"
INSTALL = "/usr/bin/install"
MKDIR = "/bin/mkdir"
LAUNCHCTL = "/bin/launchctl"
PLUTIL = "/usr/bin/plutil"
VISUDO = "/usr/sbin/visudo"
PS = "/bin/ps"
OTOOL = "/usr/bin/otool"
INSTALL_NAME_TOOL = "/usr/bin/install_name_tool"
CODESIGN = "/usr/bin/codesign"

# Helper-дерево (issue #287): entrypoint (этот файл) + перечисленные соседи. ЯВНЫЙ whitelist
# имён, НЕ directory-scan — directory-scan впустил бы в root-owned tree-copy любой файл, который
# атакующий подложит рядом с __file__ до/во время install (тот же класс риска, что star-import
# без явного контракта). Порядок не важен — используется только для перечисления/digest.
HELPER_TREE_MODULES = (
    "privoxy_helper_fs.py",
    "privoxy_helper_launchd.py",
    "privoxy_helper_config.py",
)

# Прокси-порты (8118/10808) — переехали в privoxy_helper_config (единственный потребитель
# protected_config_text). Оставлены здесь как facade-алиасы для обратной совместимости атрибутов
# (privoxy_system._PRIVOXY_PORT читается тестами и status()).
_PRIVOXY_PORT = privoxy_helper_config._PRIVOXY_PORT
_XRAY_SOCKS_PORT = privoxy_helper_config._XRAY_SOCKS_PORT

# #152: разрешённые privoxy-уровни логирования (см. privoxy_helper_config.py docstring —
# man-раздел 7.3 Debugging, битовые значения, канон probe-semantics-from-primary-source).
PRIVOXY_DEBUG_LEVELS = privoxy_helper_config.PRIVOXY_DEBUG_LEVELS
PRIVOXY_DEBUG_ENV = "SROUTER_PRIVOXY_DEBUG"


@dataclass(frozen=True)
class ProtectedLayout:
    """Только системные fixed paths; CLI не позволяет переопределять их."""

    helper_path: Path = Path("/Library/PrivilegedHelperTools/com.srouter.privoxyctl")
    launchdaemon_path: Path = Path("/Library/LaunchDaemons/com.srouter.privoxy.plist")
    config_dir: Path = Path("/Library/Application Support/srouter/privoxy")
    config_path: Path = Path("/Library/Application Support/srouter/privoxy/config")
    templates_dir: Path = Path("/Library/Application Support/srouter/privoxy/templates")
    manifest_path: Path = Path("/Library/Application Support/srouter/privoxy/manifest.json")
    backup_root: Path = Path("/Library/Application Support/srouter/backups/privoxy")
    log_dir: Path = Path("/Library/Logs/srouter/privoxy")
    stdout_path: Path = Path("/Library/Logs/srouter/privoxy/stdout.log")
    stderr_path: Path = Path("/Library/Logs/srouter/privoxy/stderr.log")
    sudoers_path: Path = Path("/private/etc/sudoers.d/srouter-privoxy-no-cache")

    @property
    def runtime_dir(self):
        return self.config_dir / "runtime"

    @property
    def binary_path(self):
        return self.runtime_dir / "bin" / "privoxy"

    @property
    def lib_dir(self):
        return self.runtime_dir / "lib"

    @property
    def helper_modules_dir(self):
        """Директория соседних helper-модулей (issue #287, tree-copy).

        Производится от helper_path, а не отдельное поле — entrypoint на import-time
        (module-level, до любых вызовов) делает sys.path.insert(0, <__file__>.modules)
        и импортирует соседей по имени. Имя директории жёстко привязано к имени
        entrypoint'а (`<entrypoint>.modules`), поэтому оба обязаны жить в одном
        родителе, иначе entrypoint не найдёт соседей после install в
        /Library/PrivilegedHelperTools.
        """
        return self.helper_path.parent / f"{self.helper_path.name}.modules"


DEFAULT_LAYOUT = ProtectedLayout()


def _now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _result(ok, *, error="", **extra):
    return {"ok": bool(ok), "error": error, **extra}


# ---- facade re-export: runner/launchd-обвязка (issue #287 → privoxy_helper_launchd.py) ----
# Top-level import (см. заголовок модуля) — helper_tree-модули физически едут вместе с
# entrypoint при tree-copy install, top-level импорт между НИМИ безопасен. Presence-имена
# сохранены как атрибуты privoxy_system для обратной совместимости вызовов/тестов/patch-точек.
_run = privoxy_helper_launchd._run
_run_as_nobody = privoxy_helper_launchd._run_as_nobody
_launchd_target = privoxy_helper_launchd._launchd_target
_launchd_loaded = privoxy_helper_launchd._launchd_loaded
_launchd_pid = privoxy_helper_launchd._launchd_pid
_launchd_field = privoxy_helper_launchd._launchd_field
_bootout = privoxy_helper_launchd._bootout
_bootstrap = privoxy_helper_launchd._bootstrap
_otool_dependencies = privoxy_helper_launchd._otool_dependencies


def _port_open(port=_PRIVOXY_PORT):
    return privoxy_helper_launchd._port_open(port)


def _wait_port(expected, *, checker=_port_open, timeout=8.0, interval=0.1):
    return privoxy_helper_launchd._wait_port(expected, checker=checker, timeout=timeout, interval=interval)


def _install_runtime(source_binary, prefix, layout, *, runner=_run, chown=os.chown):
    return privoxy_helper_launchd._install_runtime(source_binary, prefix, layout, runner=runner, chown=chown)


# ---- facade re-export: protected-config/plist/manifest/policy (issue #287 → privoxy_helper_config.py) ----
def protected_config_text(layout=DEFAULT_LAYOUT, debug=0):
    """Минимальная конфигурация bridge-only без user-writable action/filter files.

    debug — уровень privoxy-логирования (issue #152): 0=выкл (ДЕФОЛТ, privacy), 1=URLs (чувствительно),
    2=connections (приватно, ловит флап). Уровень вне whitelist PRIVOXY_DEBUG_LEVELS молча опускается
    до 0 — env-ускорение НЕ способно включить header-parsing (8, чувствительно) или raw-запросы (32768).
    """
    return privoxy_helper_config.protected_config_text(layout, debug=debug)


def _config_directives(text):
    return privoxy_helper_config._config_directives(text)


def validate_protected_config(text, layout=DEFAULT_LAYOUT, debug=0):
    """Fail-closed: exact minimal contract, loopback-only and fixed upstream.

    debug — ожидаемый уровень логирования (#152); expected-конфиг генерируется с тем же уровнем,
    чтобы staged_config с `debug 2` прошёл точный exact-match. Контракт остаётся строгим
    (got != expected); параметризуется только уровень debug.
    """
    result = privoxy_helper_config.validate_protected_config(text, layout, debug=debug)
    return _result(result["ok"], error=result.get("error", ""),
                   **{k: v for k, v in result.items() if k not in ("ok", "error")})


def launchdaemon_bytes(prefix="/opt/homebrew", layout=DEFAULT_LAYOUT):
    # prefix не используется телом (наследие исходной сигнатуры) — см. privoxy_helper_config.
    return privoxy_helper_config.launchdaemon_bytes(prefix, layout)


def _managed_file(path, marker):
    return privoxy_helper_config._managed_file(path, marker)


def protection_present(layout=DEFAULT_LAYOUT):
    return privoxy_helper_config.protection_present(layout)


# ---- facade re-export: fd-pinning примитивы (issue #287 → privoxy_helper_fs.py) ----
_fchown_if_privileged = privoxy_helper_fs._fchown_if_privileged
_atomic_write = privoxy_helper_fs._atomic_write
_read_regular_nofollow = privoxy_helper_fs._read_regular_nofollow
_copy_file_nofollow = privoxy_helper_fs._copy_file_nofollow
_read_fd_regular = privoxy_helper_fs._read_fd_regular
_read_all_fd = privoxy_helper_fs._read_all_fd
_copy_tree_fd = privoxy_helper_fs._copy_tree_fd
_copy_tree_nofollow = privoxy_helper_fs._copy_tree_nofollow
_reject_symlinks_in_tree = privoxy_helper_fs._reject_symlinks_in_tree
_restore_file = privoxy_helper_fs._restore_file
_backup_existing = privoxy_helper_fs._backup_existing


def _safe_staged_config(path, uid, layout=DEFAULT_LAYOUT, debug=0):
    result = privoxy_helper_config._safe_staged_config(path, uid, layout, debug=debug)
    return _result(result["ok"], error=result.get("error", ""),
                   **{k: v for k, v in result.items() if k not in ("ok", "error")})


def _copy_templates(source, target, *, chown=os.chown):
    return privoxy_helper_config._copy_templates(source, target, chown=chown)


# ---- facade re-export: sudoers/identity/prefix/manifest policy (issue #287 → privoxy_helper_config.py) ----
def _sudoers_text(username):
    return privoxy_helper_config._sudoers_text(username)


def _valid_identity(username, uid):
    return privoxy_helper_config._valid_identity(username, uid)


def _allowed_prefix(prefix):
    return privoxy_helper_config._allowed_prefix(prefix)


def _load_manifest(layout=DEFAULT_LAYOUT):
    return privoxy_helper_config._load_manifest(layout)


def _verify_managed_assets(layout=DEFAULT_LAYOUT):
    result = privoxy_helper_config._verify_managed_assets(layout)
    return _result(result["ok"], error=result.get("error", ""))


def _privoxy_debug_from_env():
    """Уровень privoxy-логирования из SROUTER_PRIVOXY_DEBUG (issue #152, канон InstallEnv.from_env).

    Возвращает int из whitelist PRIVOXY_DEBUG_LEVELS; при отсутствии/нечисле/вне whitelist → 0
    (privacy-дефолт: логирование выкл). env-ускорение НЕ способно включить header-parsing (8,
    чувствительно: auth/cookie заголовки на диск) или raw-запросы (32768) — только осознанные
    диагностические уровни {1, 2} (URLs осознанно, connections приватно).
    """
    raw = os.environ.get(PRIVOXY_DEBUG_ENV, "").strip()
    if not raw:
        return 0
    try:
        level = int(raw)
    except ValueError:
        return 0
    return level if level in PRIVOXY_DEBUG_LEVELS else 0


def _rollback_live(snapshot, *, layout, runner, checker, chown):
    _bootout(SYSTEM_DOMAIN, SYSTEM_LABEL, runner)
    _wait_port(False, checker=checker, timeout=5)

    config_dir_backup = snapshot.get("config_dir_backup")
    if config_dir_backup and Path(config_dir_backup).is_dir():
        if layout.config_dir.exists():
            shutil.rmtree(layout.config_dir)
        shutil.copytree(config_dir_backup, layout.config_dir)
    elif not snapshot.get("config_dir_existed") and layout.config_dir.exists():
        shutil.rmtree(layout.config_dir)

    system_plist_backup = snapshot.get("system_plist_backup")
    if system_plist_backup:
        _restore_file(system_plist_backup, layout.launchdaemon_path,
                      uid=0, gid=0, mode=0o644, chown=chown)
    elif _managed_file(layout.launchdaemon_path, PROTECTED_MARKER):
        layout.launchdaemon_path.unlink(missing_ok=True)

    sudoers_backup = snapshot.get("sudoers_backup")
    if sudoers_backup:
        _restore_file(sudoers_backup, layout.sudoers_path,
                      uid=0, gid=0, mode=0o440, chown=chown)
    elif _managed_file(layout.sudoers_path, SUDOERS_MARKER):
        layout.sudoers_path.unlink(missing_ok=True)

    user_plist_backup = snapshot.get("user_plist_backup")
    if user_plist_backup:
        _restore_file(user_plist_backup, snapshot["user_plist"],
                      uid=snapshot["uid"], gid=snapshot["gid"], mode=0o644, chown=chown)

    if snapshot.get("system_loaded") and layout.launchdaemon_path.is_file():
        _bootstrap(SYSTEM_DOMAIN, layout.launchdaemon_path, runner)
        _wait_port(True, checker=checker, timeout=8)
    elif user_plist_backup and snapshot.get("user_loaded"):
        _bootstrap(f"gui/{snapshot['uid']}", snapshot["user_plist"], runner)
        _wait_port(True, checker=checker, timeout=8)


def protect_as_root(*, username, uid, prefix, staged_config, layout=DEFAULT_LAYOUT,
                    runner=_run, checker=_port_open, chown=os.chown, enforce_root=True,
                    user_home=None, config_test_runner=_run_as_nobody, debug=0):
    """Одна root-транзакция: backup → bootout user job → install → bootstrap system → verify.

    debug — ожидаемый уровень логирования (#152); staged_config валидируется exact-match с тем же
    уровнем, что и был при user-side генерации (пробрасывается через privileged-helper как --debug).
    """
    if enforce_root and os.geteuid() != 0:
        return _result(False, error="root_required")
    identity = _valid_identity(username, int(uid))
    if identity is None:
        return _result(False, error="identity_mismatch")
    prefix = _allowed_prefix(prefix)
    if not prefix:
        return _result(False, error="unsupported_homebrew_prefix")

    checked = _safe_staged_config(staged_config, int(uid), layout, debug=debug)
    if not checked["ok"]:
        return checked
    binary = Path(prefix) / "opt" / "privoxy" / "sbin" / "privoxy"
    template_source = Path(prefix) / "etc" / "privoxy" / "templates"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        return _result(False, error="privoxy_binary_missing")
    if not template_source.is_dir():
        return _result(False, error="privoxy_templates_missing")

    for path, marker in (
        (layout.launchdaemon_path, PROTECTED_MARKER),
        (layout.config_path, PROTECTED_MARKER),
        (layout.sudoers_path, SUDOERS_MARKER),
    ):
        if path.exists() and not _managed_file(path, marker):
            return _result(False, error=f"foreign_protected_asset:{path}")
    existing_protection = protection_present(layout)
    previous_manifest = _load_manifest(layout) if existing_protection else None
    if existing_protection and previous_manifest is None:
        return _result(False, error="existing_protection_manifest_missing")

    home = Path(user_home or identity.pw_dir)
    user_plist = home / "Library" / "LaunchAgents" / f"{USER_LABEL}.plist"
    user_domain = f"gui/{uid}"
    user_loaded = _launchd_loaded(user_domain, USER_LABEL, runner)
    system_loaded = _launchd_loaded(SYSTEM_DOMAIN, SYSTEM_LABEL, runner)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for parent in {layout.config_dir.parent, layout.log_dir.parent, layout.backup_root.parent}:
        parent.mkdir(parents=True, exist_ok=True)
        os.chmod(parent, 0o755)
        chown(parent, 0, 0)
    layout.backup_root.mkdir(parents=True, exist_ok=True)
    os.chmod(layout.backup_root, 0o700)
    chown(layout.backup_root, 0, 0)
    backup_dir = Path(tempfile.mkdtemp(prefix=f"{stamp}-", dir=str(layout.backup_root)))
    os.chmod(backup_dir, 0o700)
    chown(backup_dir, 0, 0)
    try:
        snapshot = {
            "version": PROTECTION_VERSION,
            "created_at": _now(),
            "username": username,
            "uid": int(uid),
            "gid": identity.pw_gid,
            "prefix": prefix,
            "user_plist": str(user_plist),
            "user_loaded": user_loaded,
            "system_loaded": system_loaded,
            "user_plist_backup": _backup_existing(
                user_plist, backup_dir, "user-launchagent.plist", chown=chown
            ),
            "system_plist_backup": _backup_existing(
                layout.launchdaemon_path, backup_dir, "system-launchdaemon.plist", chown=chown
            ),
            "sudoers_backup": _backup_existing(layout.sudoers_path, backup_dir, "sudoers", chown=chown),
            "config_dir_existed": layout.config_dir.exists(),
            "config_dir_backup": _backup_existing(
                layout.config_dir, backup_dir, "protected-config-dir", chown=chown
            ),
            "backup_dir": str(backup_dir),
        }
    except (OSError, RuntimeError) as exc:
        return _result(False, error=f"backup_failed:{exc}", backup_dir=str(backup_dir))
    if user_loaded and not snapshot["user_plist_backup"]:
        return _result(False, error="loaded_user_job_without_plist", backup_dir=str(backup_dir))

    try:
        layout.config_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(layout.config_dir, 0o755)
        chown(layout.config_dir, 0, 0)
        layout.log_dir.mkdir(parents=True, exist_ok=True)
        nobody = pwd.getpwnam("nobody")
        os.chmod(layout.log_dir, 0o2750)
        chown(layout.log_dir, nobody.pw_uid, identity.pw_gid)
        if not _copy_templates(template_source, layout.templates_dir, chown=chown):
            raise RuntimeError("templates_install_failed")
        runtime = _install_runtime(binary, prefix, layout, runner=runner, chown=chown)
        if not runtime["ok"]:
            raise RuntimeError(runtime["error"])
        if not _atomic_write(layout.config_path, checked["text"].encode(), mode=0o644,
                             uid=0, gid=0, chown=chown):
            raise RuntimeError("config_install_failed")
        if not _atomic_write(layout.launchdaemon_path, launchdaemon_bytes(prefix, layout), mode=0o644,
                             uid=0, gid=0, chown=chown):
            raise RuntimeError("plist_install_failed")

        plist_check = runner([PLUTIL, "-lint", str(layout.launchdaemon_path)], 10)
        if plist_check.get("rc") != 0:
            raise RuntimeError("plist_invalid")
        config_check = config_test_runner(
            [str(layout.binary_path), "--config-test", str(layout.config_path)], 15
        )
        if config_check.get("rc") != 0:
            detail = (config_check.get("err") or config_check.get("out") or "")[:240]
            raise RuntimeError(f"config_test_failed:{detail}")

        sudoers_data = _sudoers_text(username).encode()
        sudoers_temp = backup_dir / "sudoers.candidate"
        if not _atomic_write(sudoers_temp, sudoers_data, mode=0o440,
                             uid=0, gid=0, chown=chown):
            raise RuntimeError("sudoers_stage_failed")
        sudoers_check = runner([VISUDO, "-cf", str(sudoers_temp)], 10)
        if sudoers_check.get("rc") != 0:
            raise RuntimeError("sudoers_invalid")
        if not _atomic_write(layout.sudoers_path, sudoers_data, mode=0o440,
                             uid=0, gid=0, chown=chown):
            raise RuntimeError("sudoers_install_failed")

        if user_loaded:
            _bootout(user_domain, USER_LABEL, runner)
            if _launchd_loaded(user_domain, USER_LABEL, runner):
                raise RuntimeError("user_privoxy_job_still_loaded")
        if user_plist.exists():
            user_plist.unlink()
        if _launchd_loaded(SYSTEM_DOMAIN, SYSTEM_LABEL, runner):
            _bootout(SYSTEM_DOMAIN, SYSTEM_LABEL, runner)
        if not _wait_port(False, checker=checker, timeout=8):
            raise RuntimeError("port_8118_still_busy")

        boot = _bootstrap(SYSTEM_DOMAIN, layout.launchdaemon_path, runner)
        if boot.get("rc") != 0 and not _launchd_loaded(SYSTEM_DOMAIN, SYSTEM_LABEL, runner):
            raise RuntimeError(f"system_bootstrap_failed:{(boot.get('err') or '')[:160]}")
        if not _wait_port(True, checker=checker, timeout=10):
            raise RuntimeError("protected_privoxy_port_not_up")
        if _launchd_loaded(user_domain, USER_LABEL, runner):
            raise RuntimeError("user_privoxy_job_still_loaded")
        pid = _launchd_pid(SYSTEM_DOMAIN, SYSTEM_LABEL, runner)
        if not pid:
            raise RuntimeError("protected_privoxy_pid_missing")
        owner_result = runner([PS, "-o", "user=", "-p", str(pid)], 5)
        if (owner_result.get("out") or "").strip() != "nobody":
            raise RuntimeError("protected_privoxy_wrong_user")
        expected_owner = 0 if enforce_root else os.getuid()
        for protected_path in (
            layout.config_dir.parent,
            layout.config_dir,
            layout.config_path,
            layout.runtime_dir,
            layout.binary_path,
            layout.lib_dir / "libpcre2-8.0.dylib",
            layout.lib_dir / "libpcre2-posix.3.dylib",
            layout.launchdaemon_path,
            layout.sudoers_path,
        ):
            protected_stat = protected_path.stat()
            if protected_stat.st_uid != expected_owner or protected_stat.st_mode & 0o022:
                raise RuntimeError(f"protected_runtime_permissions_invalid:{protected_path.name}")

        manifest = dict(snapshot)
        if previous_manifest:
            for key in ("username", "uid", "gid", "user_plist", "user_loaded",
                        "user_plist_backup"):
                if key in previous_manifest:
                    manifest[key] = previous_manifest[key]
            manifest["previous_protection_backup_dir"] = previous_manifest.get("backup_dir", "")
        manifest.update({
            "label": SYSTEM_LABEL,
            "config_path": str(layout.config_path),
            "launchdaemon_path": str(layout.launchdaemon_path),
        })
        if not _atomic_write(layout.manifest_path,
                             (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode(),
                             mode=0o644, uid=0, gid=0, chown=chown):
            raise RuntimeError("manifest_write_failed")
        return _result(True, label=SYSTEM_LABEL, backup_dir=str(backup_dir), user_loaded=user_loaded)
    except (OSError, RuntimeError) as exc:
        error = str(exc)
        try:
            _rollback_live(snapshot, layout=layout, runner=runner, checker=checker, chown=chown)
        except OSError as rollback_error:
            error += f"; rollback_failed:{rollback_error}"
        return _result(False, error=error, backup_dir=str(backup_dir))


def unprotect_as_root(*, restore=True, layout=DEFAULT_LAYOUT, runner=_run,
                      checker=_port_open, chown=os.chown, enforce_root=True):
    if enforce_root and os.geteuid() != 0:
        return _result(False, error="root_required")
    safe = _verify_managed_assets(layout)
    if not safe["ok"]:
        return safe
    manifest = _load_manifest(layout)
    if not manifest:
        return _result(False, error="manifest_missing")

    try:
        uid = int(manifest["uid"])
        gid = int(manifest["gid"])
    except (KeyError, TypeError, ValueError):
        return _result(False, error="manifest_identity_invalid")
    user_backup = manifest.get("user_plist_backup")
    user_plist = Path(manifest.get("user_plist") or "")
    if not user_plist.is_absolute():
        return _result(False, error="manifest_user_plist_invalid")
    user_domain = f"gui/{uid}"
    user_loaded = _launchd_loaded(user_domain, USER_LABEL, runner)
    user_drift = user_loaded or user_plist.exists()
    if user_drift and not (restore and user_backup):
        # За время protection агент мог создать новый homebrew.mxcl.privoxy. Не принимаем его за
        # исходную службу и не удаляем молча: защищённый system-job остаётся нетронутым.
        return _result(False, error="user_privoxy_shadow_drift")
    if user_loaded:
        _bootout(user_domain, USER_LABEL, runner)
        if _launchd_loaded(user_domain, USER_LABEL, runner):
            return _result(False, error="user_privoxy_shadow_still_loaded")

    _bootout(SYSTEM_DOMAIN, SYSTEM_LABEL, runner)
    if not _wait_port(False, checker=checker, timeout=8):
        return _result(False, error="protected_privoxy_did_not_stop")

    restored = False
    if restore and user_backup:
        user_plist.parent.mkdir(parents=True, exist_ok=True)
        restored = _restore_file(user_backup, user_plist,
                                 uid=uid, gid=gid,
                                 mode=0o644, chown=chown)
        if not restored:
            _bootstrap(SYSTEM_DOMAIN, layout.launchdaemon_path, runner)
            return _result(False, error="user_plist_restore_failed")
        if manifest.get("user_loaded"):
            boot = _bootstrap(user_domain, user_plist, runner)
            if boot.get("rc") != 0 and not _launchd_loaded(user_domain, USER_LABEL, runner):
                _bootstrap(SYSTEM_DOMAIN, layout.launchdaemon_path, runner)
                return _result(False, error="user_service_restore_failed")

    try:
        layout.launchdaemon_path.unlink(missing_ok=True)
        if _managed_file(layout.sudoers_path, SUDOERS_MARKER):
            layout.sudoers_path.unlink(missing_ok=True)
        if layout.config_dir.exists() and _managed_file(layout.config_path, PROTECTED_MARKER):
            shutil.rmtree(layout.config_dir)
        if layout.helper_path.exists() and _managed_file(layout.helper_path, HELPER_MARKER):
            layout.helper_path.unlink()
            # #287 tree-copy: helper_modules_dir — соседи entrypoint (privoxy_helper_*.py),
            # не несут собственного marker'а (см. _helper_tree_has_marker_fd — marker
            # проверяется только в entrypoint). Удаляем её ВМЕСТЕ с entrypoint, guard'ится
            # тем же marker-check на entrypoint выше — чужую/неуправляемую директорию не тронем.
            if layout.helper_modules_dir.is_dir():
                shutil.rmtree(layout.helper_modules_dir, ignore_errors=True)
    except OSError as exc:
        return _result(False, error=f"protected_assets_remove_failed:{exc}")
    return _result(True, restored=restored, backup_dir=manifest.get("backup_dir", ""))


def control_as_root(action, *, layout=DEFAULT_LAYOUT, runner=_run,
                    checker=_port_open, enforce_root=True):
    if enforce_root and os.geteuid() != 0:
        return _result(False, error="root_required")
    if action not in {"start", "stop", "restart", "status"}:
        return _result(False, error="action_not_allowed")
    if action == "status":
        return _result(True, loaded=_launchd_loaded(SYSTEM_DOMAIN, SYSTEM_LABEL, runner),
                       port_up=bool(checker()))
    safe = _verify_managed_assets(layout)
    if not safe["ok"]:
        return safe
    if not _managed_file(layout.launchdaemon_path, PROTECTED_MARKER):
        return _result(False, error="protected_service_not_installed")

    loaded = _launchd_loaded(SYSTEM_DOMAIN, SYSTEM_LABEL, runner)
    if action == "stop":
        if loaded:
            _bootout(SYSTEM_DOMAIN, SYSTEM_LABEL, runner)
        ok = _wait_port(False, checker=checker, timeout=8)
        return _result(ok, error="port_8118_still_up" if not ok else "")
    if action == "start" and loaded and checker():
        pid = _launchd_pid(SYSTEM_DOMAIN, SYSTEM_LABEL, runner)
        owner = runner([PS, "-o", "user=", "-p", str(pid)], 5) if pid else {}
        if not pid or (owner.get("out") or "").strip() != "nobody":
            return _result(False, error="protected_privoxy_wrong_user")
        return _result(True, changed=False)
    if action == "start" and not loaded and checker():
        return _result(False, error="port_8118_busy_without_protected_job")
    if loaded:
        _bootout(SYSTEM_DOMAIN, SYSTEM_LABEL, runner)
        if not _wait_port(False, checker=checker, timeout=8):
            return _result(False, error="port_8118_still_busy")
    boot = _bootstrap(SYSTEM_DOMAIN, layout.launchdaemon_path, runner)
    if boot.get("rc") != 0 and not _launchd_loaded(SYSTEM_DOMAIN, SYSTEM_LABEL, runner):
        return _result(False, error=f"system_bootstrap_failed:{(boot.get('err') or '')[:160]}")
    ok = _wait_port(True, checker=checker, timeout=10)
    if not ok:
        return _result(False, error="protected_privoxy_port_not_up", changed=True)
    pid = _launchd_pid(SYSTEM_DOMAIN, SYSTEM_LABEL, runner)
    owner = runner([PS, "-o", "user=", "-p", str(pid)], 5) if pid else {}
    if not pid or (owner.get("out") or "").strip() != "nobody":
        return _result(False, error="protected_privoxy_wrong_user", changed=True)
    return _result(True, changed=True)


def _digest_fd_nofollow(path):
    """sha256 по fd (O_NOFOLLOW). None если файл не открывается / не regular."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError:
        return None
    try:
        try:
            data = _read_fd_regular(fd, max_size=4 * 1024 * 1024)
        except RuntimeError:
            return None
    finally:
        os.close(fd)
    return hashlib.sha256(data).hexdigest()


def _read_file_pinned(path, *, max_size=4 * 1024 * 1024):
    """Открыть path через O_NOFOLLOW, прочитать bytes + digest одним fd (TOCTOU-свободно).

    Общий примитив для tree digest-pinning (issue #287): и entrypoint, и каждый
    HELPER_TREE_MODULES-файл читаются через один и тот же паттерн — открытие с
    O_NOFOLLOW делает symlink-check и чтение содержимого одной операцией, digest
    считается на bytes ТОГО ЖЕ fd, что и прочитаны — окна между проверкой и
    использованием нет (тот же инвариант, что был у прежнего однофайлового
    _read_helper_bytes_pinned, #148). Возвращает (bytes, digest) или (None, None).

    Почему НЕ _reject_symlinks_in_tree (#287 просил переиспользовать примитивы): тот —
    lstat-препроход для shutil.copytree, который разыменовывает symlink'и, по дереву
    НЕИЗВЕСТНОЙ формы (user-writable Homebrew templates), и он оставляет окно между
    lstat и копированием. Здесь дерево — фиксированный whitelist HELPER_TREE_MODULES,
    а не обход, и O_NOFOLLOW делает symlink-отказ и чтение ОДНОЙ операцией: окна нет
    вовсе. Препроход здесь был бы строго слабее (то самое ослабление, которое #287
    запрещает), поэтому переиспользован _copy_tree_nofollow-инвариант (O_NOFOLLOW),
    а не его lstat-обёртка для copytree.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError:
        return None, None
    try:
        try:
            data = _read_fd_regular(fd, max_size=max_size)
        except RuntimeError:
            return None, None
    finally:
        os.close(fd)
    return data, hashlib.sha256(data).hexdigest()


def _read_helper_tree_pinned():
    """Прочитать entrypoint (__file__) + все HELPER_TREE_MODULES из его директории, пиновым digest.

    tree-copy redesign (issue #287) заменяет прежний однофайловый _read_helper_bytes_pinned:
    helper — уже не один файл, а entrypoint + N соседних модулей (privoxy_helper_fs.py и т.п.),
    которые install обязан скопировать ВМЕСТЕ с тем же TOCTOU-инвариантом на КАЖДЫЙ файл.

    Marker (HELPER_MARKER) проверяется ТОЛЬКО в entrypoint — соседние модули не несут
    самостоятельного marker'а (они не исполняются напрямую через sudo <path>, только
    импортом из entrypoint после sys.path-prepend), но их digest пиннится наравне с
    entrypoint: любая подмена соседа между "честным чтением здесь" и "install под sudo"
    обязана быть поймана post-install digest-check по каждому файлу дерева, не только по
    entrypoint (иначе tree-copy деградировал бы до single-file security).

    Возвращает dict {relative_name: (bytes, digest)} для entrypoint (ключ — basename __file__)
    и каждого модуля, или None целиком при любой ошибке (отсутствующий файл, symlink,
    non-regular, missing marker) — fail-closed: неполное дерево не считается валидным.
    """
    root = Path(__file__).resolve().parent
    entry_name = Path(__file__).name
    entry_data, entry_digest = _read_file_pinned(root / entry_name)
    if entry_data is None or HELPER_MARKER.encode() not in entry_data[:16384]:
        return None
    tree = {entry_name: (entry_data, entry_digest)}
    for module_name in HELPER_TREE_MODULES:
        data, digest = _read_file_pinned(root / module_name)
        if data is None:
            return None  # неполное дерево — fail-closed, а не partial install.
        tree[module_name] = (data, digest)
    return tree


def _helper_tree_has_marker_fd(path):
    """Проверка marker на fd-чтении entrypoint-path (не path-based read_text — TOCTOU-свободно)."""
    data, _ = _read_file_pinned(path)
    if data is None:
        return False
    return HELPER_MARKER.encode() in data[:16384]


def _stage_helper_tree(tree):
    """Записать helper-дерево в staged root в /private/tmp (fd-pinning per-file write).

    `tree` — dict {relname: (bytes, digest)} от _read_helper_tree_pinned. Layout staged root:
      <staged_root>/<entrypoint-name>          — entrypoint bytes (0755, как раньше)
      <staged_root>/modules/<module-name>      — каждый HELPER_TREE_MODULES-файл (0644: НЕ
                                                  исполняется напрямую, только импортируется)

    ВАЖНО (#148 variant 3, унаследовано): _stage_helper_tree вызывается в user-процессе
    `protect()` (НЕ под sudo) — mkstemp/mkdtemp создают USER-owned объекты, staged
    user-owned/writable в окне [staging .. sudo install]. Это НЕ небезопасно: post-install
    digest-check в _install_helper (privoxy_control.py) ловит расхождение КАЖДОГО файла
    дерева staged↔честно-прочитанные bytes — та же защита, что раньше покрывала один файл,
    теперь покрывает все N. Возвращает Path staged_root или None при ошибке.
    """
    staged_root = Path(tempfile.mkdtemp(prefix="srouter-helper-tree-", dir="/private/tmp"))
    try:
        os.chmod(staged_root, 0o755)
        modules_dir = staged_root / "modules"
        modules_dir.mkdir()
        os.chmod(modules_dir, 0o755)
        for relname, (data, _digest) in tree.items():
            is_entry = "/" not in relname and relname not in HELPER_TREE_MODULES
            target = staged_root / relname if is_entry else modules_dir / relname
            mode = 0o755 if is_entry else 0o644
            fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb", closefd=False) as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.fchmod(fd, mode)
                _fchown_if_privileged(fd, 0, 0)
            finally:
                try:
                    os.close(fd)
                except OSError:
                    pass
        return staged_root
    except OSError:
        try:
            shutil.rmtree(staged_root, ignore_errors=True)
        except OSError:
            pass
        return None


# ============================ user-side фасад (lazy facade re-export) ============================
# privoxy_control.py — оркестрация protect/unprotect/control/status, выполняется в ОСНОВНОМ
# процессе srouter (НЕ копируется под sudo, см. docstring модуля выше и docstring
# privoxy_control.py).
#
# КРИТИЧНО: импорт privoxy_control НЕ может быть top-level здесь. Regression-тест
# test_privoxy_system_helper_runs_isolated_without_dashboard_common копирует ТОЛЬКО этот файл
# в изолированную директорию и запускает `python3 -S com.srouter.privoxyctl status` — ровно то,
# что делает production sudo-запуск (helper копируется ОДНИМ файлом, privoxy_control.py рядом
# физически отсутствует). Top-level `import privoxy_control` уронил бы helper_main
# ModuleNotFoundError на самой первой строке — та же регрессия, что cycle-review PR #177 поймал
# на `from dashboard_common import`.
#
# Решение — module-level __getattr__ (PEP 562): `privoxy_system.status`/`.protect`/... резолвятся
# ЛЕНИВО, импорт privoxy_control происходит только при фактическом обращении к атрибуту (вызов из
# srouter_cli.py/health.py/install_config.py и т.п. — основной процесс, где privoxy_control.py
# физически рядом). helper_main обращается только к helper-side именам (protect_as_root и т.д.,
# уже в globals этого модуля) — __getattr__ для них не вызывается, privoxy_control не
# импортируется, изоляция сохраняется.
_USER_SIDE_NAMES = frozenset({
    "status", "state_protected", "_write_pending", "_write_unprotect_pending", "_mark_failed",
    "_promote_state", "_restore_state_after_unprotect", "_parse_helper_output", "_sudo_reset",
    "_install_helper", "_remove_via_runner", "_rollback_protection", "protect", "control",
    "unprotect",
})


def __getattr__(name):
    if name in _USER_SIDE_NAMES:
        import privoxy_control
        return getattr(privoxy_control, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    # PEP 562: без этого dir(privoxy_system)/hasattr-интроспекция не видит lazy user-side имена
    # (только то, что реально в globals() на момент вызова). Явный __dir__ держит полный
    # re-export surface видимым — тот же паттерн, что local_state.py (см. его __dir__).
    return sorted(set(globals()) | set(_USER_SIDE_NAMES))


def helper_main(argv=None):
    parser = argparse.ArgumentParser(prog="com.srouter.privoxyctl")
    sub = parser.add_subparsers(dest="command", required=True)
    protect_parser = sub.add_parser("protect")
    protect_parser.add_argument("--username", required=True)
    protect_parser.add_argument("--uid", required=True, type=int)
    protect_parser.add_argument("--prefix", required=True)
    protect_parser.add_argument("--config", required=True)
    protect_parser.add_argument("--debug", type=int, default=0)
    unprotect_parser = sub.add_parser("unprotect")
    unprotect_parser.add_argument("--restore", action="store_true")
    for name in ("start", "stop", "restart", "status"):
        sub.add_parser(name)
    args = parser.parse_args(argv)

    if args.command == "protect":
        outcome = protect_as_root(username=args.username, uid=args.uid, prefix=args.prefix,
                                  staged_config=args.config, debug=args.debug)
    elif args.command == "unprotect":
        outcome = unprotect_as_root(restore=args.restore)
    else:
        outcome = control_as_root(args.command)
    print(json.dumps(outcome, ensure_ascii=False, separators=(",", ":")))
    return 0 if outcome.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(helper_main())
