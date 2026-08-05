"""Конфиг/manifest/policy root-helper'а (issue #287, tree-copy redesign).

АРХИТЕКТУРНЫЙ ИНВАРИАНТ: часть root-owned helper-дерева (см. docstring privoxy_helper_fs.py) —
tree-copy install копирует этот файл рядом с privoxy_system.py (entrypoint) в
/Library/PrivilegedHelperTools, исполняется изолированно под sudo. Только stdlib.

Protected-config generation/validation, launchd-plist generation, managed-marker проверки,
Homebrew templates-копирование (`_copy_templates`, использует `_copy_tree_nofollow` из
privoxy_helper_fs), sudoers-текст, identity/prefix whitelisting, manifest load/verify —
перенесены без изменений логики из privoxy_system.py (issue #287).

Прокси-порты (8118/10808) — локальные литералы, НЕ dashboard_common (тот же canonical-fallback-port
инвариант, что и раньше в privoxy_system.py; parity-гвард
tests/test_proxy_constants.py::test_privoxy_protected_config_follows_canonical_ports не переехал —
он импортирует privoxy_system.protected_config_text, которая ре-экспортирует эту функцию).
"""

from __future__ import annotations

import json
from pathlib import Path
import plistlib
import re

import privoxy_helper_fs

_PRIVOXY_PORT = 8118  # canonical-fallback-port (helper-изоляция: stdlib-only, без dashboard_common)
_XRAY_SOCKS_PORT = 10808  # canonical-fallback-port (helper-изоляция: stdlib-only, без dashboard_common)

PROTECTED_MARKER = "srouter-protected-privoxy-v1"
SUDOERS_MARKER = "srouter-privoxy-no-sudo-cache-v1"
SYSTEM_LABEL = "com.srouter.privoxy"

# #152: разрешённые privoxy-уровни логирования (см. исходный docstring privoxy_system.py —
# man-раздел 7.3 Debugging, битовые значения). Не переносится дословно в комментарии второй раз;
# см. privoxy_system.py PRIVOXY_DEBUG_LEVELS/PRIVOXY_DEBUG_ENV — module facade экспортирует
# именно оттуда, эти два имени сохранены только там как единственный источник константы.
PRIVOXY_DEBUG_LEVELS = frozenset({0, 1, 2})


def protected_config_text(layout, debug=0):
    """Минимальная конфигурация bridge-only без user-writable action/filter files.

    debug — уровень privoxy-логирования (issue #152): 0=выкл (ДЕФОЛТ, privacy), 1=URLs (чувствительно),
    2=connections (приватно, ловит флап). Уровень вне whitelist PRIVOXY_DEBUG_LEVELS молча опускается
    до 0 — env-ускорение НЕ способно включить header-parsing (8, чувствительно) или raw-запросы (32768).
    """
    debug = debug if debug in PRIVOXY_DEBUG_LEVELS else 0
    debug_line = f"debug {debug}\n" if debug else ""
    return (
        f"# {PROTECTED_MARKER}\n"
        "# Управляется только: srouter privoxy ...\n"
        f"confdir {layout.config_dir}\n"
        f"templdir {layout.templates_dir}\n"
        f"logdir {layout.log_dir}\n"
        "logfile logfile\n"
        f"{debug_line}"
        f"listen-address 127.0.0.1:{_PRIVOXY_PORT}\n"
        "toggle 1\n"
        "enable-remote-toggle 0\n"
        "enable-edit-actions 0\n"
        "enforce-blocks 0\n"
        "buffer-limit 4096\n"
        f"forward-socks5t / 127.0.0.1:{_XRAY_SOCKS_PORT} .\n"
    )


def _config_directives(text):
    directives = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or parts[0] in directives:
            raise ValueError(f"bad or duplicate directive: {line[:80]}")
        directives[parts[0]] = parts[1].strip()
    return directives


def validate_protected_config(text, layout, debug=0):
    """Fail-closed: exact minimal contract, loopback-only and fixed upstream.

    debug — ожидаемый уровень логирования (#152); expected-конфиг генерируется с тем же уровнем,
    чтобы staged_config с `debug 2` прошёл точный exact-match. Контракт остаётся строгим
    (got != expected); параметризуется только уровень debug.
    """
    if not isinstance(text, str) or len(text.encode("utf-8")) > 64 * 1024:
        return {"ok": False, "error": "config_size_invalid"}
    if PROTECTED_MARKER not in text:
        return {"ok": False, "error": "config_marker_missing"}
    try:
        got = _config_directives(text)
        expected = _config_directives(protected_config_text(layout, debug=debug))
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    if got != expected:
        unexpected = sorted(set(got) - set(expected))
        missing = sorted(set(expected) - set(got))
        changed = sorted(k for k in set(got) & set(expected) if got[k] != expected[k])
        return {"ok": False, "error": "config_contract_mismatch",
                "unexpected": unexpected, "missing": missing, "changed": changed}
    return {"ok": True, "error": ""}


def launchdaemon_bytes(prefix, layout):
    payload = {
        "Label": SYSTEM_LABEL,
        "ProgramArguments": [str(layout.binary_path), "--no-daemon", str(layout.config_path)],
        "UserName": "nobody",
        "GroupName": "nobody",
        "RunAtLoad": True,
        "KeepAlive": True,
        "ProcessType": "Background",
        "ThrottleInterval": 5,
        "WorkingDirectory": str(layout.config_dir),
        "StandardOutPath": str(layout.stdout_path),
        "StandardErrorPath": str(layout.stderr_path),
    }
    raw = plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=False)
    marker = f"<!-- {PROTECTED_MARKER} -->\n".encode()
    return raw.replace(b"?>\n", b"?>\n" + marker, 1)


def _managed_file(path, marker):
    try:
        return marker in Path(path).read_text(encoding="utf-8", errors="ignore")[:16384]
    except OSError:
        return False


def protection_present(layout):
    return (_managed_file(layout.launchdaemon_path, PROTECTED_MARKER)
            and _managed_file(layout.config_path, PROTECTED_MARKER))


def _safe_staged_config(path, uid, layout, debug=0):
    import stat
    path = Path(path)
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            return {"ok": False, "error": "staged_config_not_regular"}
        if info.st_uid != uid:
            return {"ok": False, "error": "staged_config_wrong_owner"}
        if info.st_mode & 0o022:
            return {"ok": False, "error": "staged_config_writable_by_others"}
        if info.st_size > 64 * 1024:
            return {"ok": False, "error": "staged_config_too_large"}
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return {"ok": False, "error": f"staged_config_unreadable: {exc}"}
    checked = validate_protected_config(text, layout, debug=debug)
    if not checked["ok"]:
        return checked
    checked = dict(checked)
    checked["text"] = text
    return checked


def _copy_templates(source, target, *, chown=None):
    """Копирует Homebrew templates-каталог в root-owned target (race-free одним проходом).

    `source` — user-writable Homebrew prefix (#122). Копирование идёт через _copy_tree_nofollow:
    каждый файл читается через open(O_NOFOLLOW)+fstat (symlink отвергается до чтения содержимого),
    копируется атомарно. Никакого отдельного pre-scan-прохода перед copytree — TOCTOU-окна
    между проверкой и копированием нет, проверка и копирование элемента — одна fd-операция.
    """
    import os
    import shutil
    import tempfile

    if chown is None:
        chown = os.chown
    source, target = Path(source), Path(target)
    if not source.is_dir():
        return False
    temp = Path(tempfile.mkdtemp(dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp"))
    try:
        staged = temp / target.name
        if not privoxy_helper_fs._copy_tree_nofollow(source, staged, chown=chown):
            raise RuntimeError("templates_copy_rejected_symlink")
        if target.exists():
            shutil.rmtree(target)
        os.replace(staged, target)
        return True
    except (OSError, RuntimeError):
        try:
            if temp.exists():
                shutil.rmtree(temp)
        except OSError:
            pass
        return False
    finally:
        try:
            if temp.exists():
                shutil.rmtree(temp)
        except OSError:
            pass


def _sudoers_text(username):
    return (
        f"# {SUDOERS_MARKER}\n"
        "# Явное подтверждение требуется для каждого sudo: агенты не используют timestamp cache.\n"
        f"Defaults:{username} timestamp_timeout=0\n"
    )


def _valid_identity(username, uid):
    import pwd
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", username or ""):
        return None
    try:
        record = pwd.getpwnam(username)
    except KeyError:
        return None
    return record if record.pw_uid == uid else None


def _allowed_prefix(prefix):
    resolved = str(Path(prefix))
    return resolved if resolved in {"/opt/homebrew", "/usr/local"} else ""


def _load_manifest(layout):
    try:
        value = json.loads(layout.manifest_path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None


def _verify_managed_assets(layout):
    for path, marker in (
        (layout.launchdaemon_path, PROTECTED_MARKER),
        (layout.config_path, PROTECTED_MARKER),
        (layout.sudoers_path, SUDOERS_MARKER),
    ):
        if path.exists() and not _managed_file(path, marker):
            return {"ok": False, "error": f"protected_asset_drift:{path}"}
    return {"ok": True, "error": ""}
