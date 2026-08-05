#!/usr/bin/python3
"""Защищённый system-режим Privoxy для macOS.

Root-часть намеренно использует только stdlib, фиксированные абсолютные пути и закрытый набор
операций. Произвольные команды, shell=True и пользовательские target-path здесь запрещены.

АРХИТЕКТУРНЫЙ ИНВАРИАНТ (issue #158, декомпозиция крупных файлов — этот модуль НЕ дробится
дальше на root-side): этот файл — root-owned helper, копируется РОВНО ОДНИМ файлом в
/Library/PrivilegedHelperTools (_read_helper_bytes_pinned читает __file__ целиком, digest
считается от этих байт) и исполняется ИЗОЛИРОВАННО через sudo — рядом с ним нет других модулей
srouter (только stdlib, каноны root-helper-stdlib-only-no-shared-imports,
helper-stdlib-only-no-dashboard-common). Весь код, транзитивно достижимый из
helper_main→protect_as_root/unprotect_as_root/control_as_root (примитивы atomic-write,
fd-pinning copy, backup/restore, launchd-обвязка), ФИЗИЧЕСКИ обязан оставаться в этом файле —
разбить его на модули с `import` означало бы ModuleNotFoundError под sudo в production
(cycle-review PR #177 уже ловил эту регрессию на попытке `from dashboard_common import`).
Полный tree-copy редизайн install-механизма (который разрешил бы дальнейшее дробление) —
отдельная security-критичная задача вне scope этого issue, см. issue tree-copy redesign.

Пользовательская оркестрация (protect/unprotect/control/status, установка helper'а,
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
import plistlib
import pwd
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import time


PROTECTION_VERSION = 1
PROTECTED_MARKER = "srouter-protected-privoxy-v1"
HELPER_MARKER = "srouter-protected-helper-v1"
SUDOERS_MARKER = "srouter-privoxy-no-sudo-cache-v1"
SYSTEM_LABEL = "com.srouter.privoxy"
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

# Прокси-порты (8118/10808). Этот модуль — root-only helper (см. docstring модуля: «намеренно
# использует только stdlib»). Он копируется ОДНИМ файлом в /Library/PrivilegedHelperTools и
# исполняется изолированно через sudo — рядом НЕТ dashboard_common.py (и srouter_config.py).
# Поэтому НЕ импортируем dashboard_common (ModuleNotFoundError убил бы helper в production —
# regression, пойманная cycle-review PR #177). Порты держим локальными литералами; anti-drift
# гарантирует parity-гвард tests/test_proxy_constants.py::test_privoxy_protected_config_follows_canonical_ports
# — он эмпирически сверяет listen-address/forward-socks5t из protected_config_text с каноническим
# источником dashboard_common (та же стратегия, что для shell/config: mutation-доказуемо ловит drift).
# Если канонический порт меняется — parity-гвард падает и указывает сюда.
# canonical-fallback-port: гвард PR #162 (test_single_source_defines_proxy_port_constants)
# разрешает эти локальные литералы как осознанный fallback для helper-изоляции (НЕ свежий дубли).
_PRIVOXY_PORT = 8118  # canonical-fallback-port (helper-изоляция: stdlib-only, без dashboard_common)
_XRAY_SOCKS_PORT = 10808  # canonical-fallback-port (helper-изоляция: stdlib-only, без dashboard_common)

# #152: разрешённые privoxy-уровни логирования. Канон probe-semantics-from-primary-source —
# уровень по privoxy user-manual (раздел 7.3 Debugging, битовые значения), НЕ по аналогии/имени.
#   0 — выкл (ДЕФОЛТ, privacy: на диск не идёт даже производное контента);
#   1 — show each GET/POST/CONNECT request = URLs / Common Log Format (ЧУВСТВИТЕЛЬНО: URL могут
#       содержать токены/query — dictionary-атака, см. privacy-no-content-hash-on-disk); осознанно;
#   2 — show each connection status (open/close/timeout) — приватно (без URL/body), ловит
#       флап/таймауты к github через 8118; рекомендуемый уровень диагностики.
# Намеренно НЕ включает:
#   8 — show header parsing: пишет ЗНАЧЕНИЯ заголовков (auth/cookie) на диск → чувствительно,
#       как 1 и 32768 (канон privacy-no-content-hash-on-disk); env-ускорение его не включает;
#   32768 — raw-запросы с заголовками/телом — ручная правка конфига, не env-переключатель.
PRIVOXY_DEBUG_LEVELS = frozenset({0, 1, 2})
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


DEFAULT_LAYOUT = ProtectedLayout()


def _now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _run(cmd, timeout=30):
    """Root-helper runner: argv only, deterministic result, never raises."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "rc": proc.returncode,
            "out": proc.stdout.strip(),
            "err": proc.stderr.strip(),
            "timeout": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "rc": None,
            "out": (exc.stdout or "").strip() if isinstance(exc.stdout, str) else "",
            "err": "timeout",
            "timeout": True,
        }
    except OSError as exc:
        return {"rc": None, "out": "", "err": f"{type(exc).__name__}: {exc}", "timeout": False}


def _run_as_nobody(cmd, timeout=30):
    """Выполняет cmd под euid/egid `nobody`, а не root.

    Privoxy runtime копируется из user-writable Homebrew prefix (#122); подмена бинаря до
    легитимного `protect --strict` иначе выполнилась бы с правами root внутри самого helper'а,
    хотя итоговый LaunchDaemon и так запускает privoxy от `nobody`. config-test не требует root —
    drop privileges здесь закрывает разницу между "скопировано под root" и "доверено выполнять как root".
    """
    nobody = pwd.getpwnam("nobody")

    def _drop_privileges():
        os.setgroups([])
        os.setgid(nobody.pw_gid)
        os.setuid(nobody.pw_uid)

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            preexec_fn=_drop_privileges if os.geteuid() == 0 else None,
        )
        return {
            "rc": proc.returncode,
            "out": proc.stdout.strip(),
            "err": proc.stderr.strip(),
            "timeout": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "rc": None,
            "out": (exc.stdout or "").strip() if isinstance(exc.stdout, str) else "",
            "err": "timeout",
            "timeout": True,
        }
    except OSError as exc:
        return {"rc": None, "out": "", "err": f"{type(exc).__name__}: {exc}", "timeout": False}


def _result(ok, *, error="", **extra):
    return {"ok": bool(ok), "error": error, **extra}


def protected_config_text(layout=DEFAULT_LAYOUT, debug=0):
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


def validate_protected_config(text, layout=DEFAULT_LAYOUT, debug=0):
    """Fail-closed: exact minimal contract, loopback-only and fixed upstream.

    debug — ожидаемый уровень логирования (#152); expected-конфиг генерируется с тем же уровнем,
    чтобы staged_config с `debug 2` прошёл точный exact-match. Контракт остаётся строгим
    (got != expected); параметризуется только уровень debug.
    """
    if not isinstance(text, str) or len(text.encode("utf-8")) > 64 * 1024:
        return _result(False, error="config_size_invalid")
    if PROTECTED_MARKER not in text:
        return _result(False, error="config_marker_missing")
    try:
        got = _config_directives(text)
        expected = _config_directives(protected_config_text(layout, debug=debug))
    except ValueError as exc:
        return _result(False, error=str(exc))
    if got != expected:
        unexpected = sorted(set(got) - set(expected))
        missing = sorted(set(expected) - set(got))
        changed = sorted(k for k in set(got) & set(expected) if got[k] != expected[k])
        return _result(False, error="config_contract_mismatch",
                       unexpected=unexpected, missing=missing, changed=changed)
    return _result(True)


def launchdaemon_bytes(prefix="/opt/homebrew", layout=DEFAULT_LAYOUT):
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


def protection_present(layout=DEFAULT_LAYOUT):
    return (_managed_file(layout.launchdaemon_path, PROTECTED_MARKER)
            and _managed_file(layout.config_path, PROTECTED_MARKER))


def _launchd_target(domain, label):
    return f"{domain}/{label}"


def _launchd_loaded(domain, label, runner=_run):
    result = runner([LAUNCHCTL, "print", _launchd_target(domain, label)], 5)
    return result.get("rc") == 0 and bool((result.get("out") or "").strip())


def _launchd_pid(domain, label, runner=_run):
    result = runner([LAUNCHCTL, "print", _launchd_target(domain, label)], 5)
    if result.get("rc") != 0:
        return None
    raw = _launchd_field(result.get("out") or "", "pid")
    try:
        return int(raw) if raw is not None else None
    except ValueError:
        return None


def _port_open(port=_PRIVOXY_PORT):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.25):
            return True
    except OSError:
        return False


def _wait_port(expected, *, checker=_port_open, timeout=8.0, interval=0.1):
    deadline = time.monotonic() + timeout
    state = bool(checker())
    while state != expected and time.monotonic() < deadline:
        time.sleep(interval)
        state = bool(checker())
    return state == expected


def _fchown_if_privileged(fd, uid, gid):
    """fchown по fd ТОЛЬКО под root. fd-pinning (#148): метаданные выставляются по fd,
    а не по пути — закрывает TOCTOU arbitrary-chown (path-based chown следует symlink).

    Под non-root (тесты без sudo) fchown(0,0) дал бы EPERM и пропускается: реальный
    chown невозможен без привилегий, security-инвариант не нарушается (production
    helper всегда работает под root через sudo — там fchown обязателен и выполнится).
    """
    if os.geteuid() != 0:
        return
    os.fchown(fd, uid, gid)


def _atomic_write(path, data, *, mode, uid=0, gid=0, chown=os.chown):
    """Race-free atomic write: непредсказуемое temp-имя + O_EXCL + fchmod/fchown по fd.

    Прежний temp `.name.tmp-PID` был предсказуем и жил в user-writable директории (при restore
    user_plist это ~/Library/LaunchAgents) — атакующий подкладывал symlink с этим именем на
    произвольный root-path, и open(temp, "wb") + chmod + chown, следуя symlink, писали/меняли
    владельца цели (arbitrary root file write). tempfile.mkstemp даёт криптографически
    случайное имя и создаёт файл атомарно с O_EXCL. КРИТИЧНО (#148): fchmod/fchown работают
    по fd, а НЕ по пути. Прежний код закрывал fd через fdopen и затем звал os.chmod(temp)/
    chown(temp) по пути — между fd-close и chmod/chown владелец parent-каталога мог
    переименовать temp и поставить symlink с тем же именем на произвольную цель, и
    os.chmod/chown (по умолчанию следующие symlink) меняли владельца цели (arbitrary chown).
    Теперь fd держится открытым до конца и метаданные выставляются по fd (TOCTOU-окна нет).
    os.replace(temp, path) безопасен по имени: temp-имя непредсказуемо, атакующий не может
    его подменить; path — финальная цель, переименование атомарно и не даёт arbitrary chown.

    Параметр `chown` сохранён в сигнатуре для обратной совместимости вызовов; fd-pinning
    делает его избыточным (используется os.fchown). Под non-root (тесты без sudo) fchown(0,0)
    дал бы EPERM и пропускается — под root (production) chown обязателен.
    """
    del chown  # fd-pinning: chown делается через os.fchown(fd), path-based хук более не нужен.
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    temp = Path(tmp_name)
    try:
        # НЕ передаём closefd=True — fd должен жить для fchmod/fchown после flush.
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        # Метаданные — по fd, а не по пути. fchmod/fchown не следуют symlink и не
        # делают path-resolution: даже если temp-путь подменён symlink'ом на чужую
        # цель, fd всё ещё указывает на оригинальный regular-файл mkstemp (#148).
        os.fchmod(fd, mode)
        _fchown_if_privileged(fd, uid, gid)
        # Переименование по имени безопасно: temp-имя непредсказуемо (атакующий не
        # знает его), path — финальная цель; rename атомарен и не открывает
        # TOCTOU-окно для arbitrary chown.
        os.replace(temp, path)
        temp = None  # успех — не удалять в finally.
        return True
    except OSError:
        if temp is not None:
            try:
                os.unlink(temp)
            except OSError:
                pass
        return False
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _safe_staged_config(path, uid, layout=DEFAULT_LAYOUT, debug=0):
    path = Path(path)
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            return _result(False, error="staged_config_not_regular")
        if info.st_uid != uid:
            return _result(False, error="staged_config_wrong_owner")
        if info.st_mode & 0o022:
            return _result(False, error="staged_config_writable_by_others")
        if info.st_size > 64 * 1024:
            return _result(False, error="staged_config_too_large")
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return _result(False, error=f"staged_config_unreadable: {exc}")
    checked = validate_protected_config(text, layout, debug=debug)
    if not checked["ok"]:
        return checked
    return _result(True, text=text)


def _copy_templates(source, target, *, chown=os.chown):
    """Копирует Homebrew templates-каталог в root-owned target (race-free одним проходом).

    `source` — user-writable Homebrew prefix (#122). Копирование идёт через _copy_tree_nofollow:
    каждый файл читается через open(O_NOFOLLOW)+fstat (symlink отвергается до чтения содержимого),
    копируется атомарно. Никакого отдельного pre-scan-прохода перед copytree — TOCTOU-окна
    между проверкой и копированием нет, проверка и копирование элемента — одна fd-операция.
    """
    source, target = Path(source), Path(target)
    if not source.is_dir():
        return False
    temp = Path(tempfile.mkdtemp(dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp"))
    try:
        staged = temp / target.name
        if not _copy_tree_nofollow(source, staged, chown=chown):
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


def _otool_dependencies(path, runner=_run):
    result = runner([OTOOL, "-L", str(path)], 10)
    if result.get("rc") != 0:
        return _result(False, error=f"otool_failed:{(result.get('err') or '')[:160]}")
    dependencies = []
    for line in (result.get("out") or "").splitlines()[1:]:
        value = line.strip().split(" (", 1)[0]
        if value:
            dependencies.append(value)
    return _result(True, dependencies=dependencies)


def _install_runtime(source_binary, prefix, layout, *, runner=_run, chown=os.chown):
    """Copy and relink Privoxy so the protected service never executes user-owned Homebrew files.

    Sources (Homebrew binary/dylib) — user-writable prefix (#122). Копирование через
    _copy_file_nofollow: source открывается с O_NOFOLLOW (symlink отвергается до чтения
    содержимого), копируется атомарно. Прежний copy2(follow_symlinks=True) разыменовывал
    symlink и копировал содержимое root-only цели как root-owned executable (0755) —
    arbitrary-root-readable-file-disclosure + потенциально attacker-controlled Mach-O.
    """
    pcre_dir = Path(prefix) / "opt" / "pcre2" / "lib"
    sources = {
        "privoxy": Path(source_binary),
        "libpcre2-8.0.dylib": pcre_dir / "libpcre2-8.0.dylib",
        "libpcre2-posix.3.dylib": pcre_dir / "libpcre2-posix.3.dylib",
    }
    # lstat-проверка (НЕ stat/is_file, которые следуют symlink) только для раннего missing-отчёта;
    # реальная защита — в _copy_file_nofollow ниже.
    missing = sorted(name for name, path in sources.items() if not path.exists())
    if missing:
        return _result(False, error=f"protected_runtime_source_missing:{','.join(missing)}")

    temp = layout.runtime_dir.with_name(f".{layout.runtime_dir.name}.tmp-{os.getpid()}")
    try:
        if temp.exists():
            shutil.rmtree(temp)
        temp_bin = temp / "bin"
        temp_lib = temp / "lib"
        temp_bin.mkdir(parents=True)
        temp_lib.mkdir()
        targets = {
            "privoxy": temp_bin / "privoxy",
            "libpcre2-8.0.dylib": temp_lib / "libpcre2-8.0.dylib",
            "libpcre2-posix.3.dylib": temp_lib / "libpcre2-posix.3.dylib",
        }
        for name, source in sources.items():
            if not _copy_file_nofollow(source, targets[name], mode=0o755, chown=chown):
                return _result(False, error=f"runtime_source_not_regular:{name}")
        for directory in (temp, temp_bin, temp_lib):
            os.chmod(directory, 0o755)
            chown(directory, 0, 0)

        final_libraries = {
            name: str(layout.lib_dir / name)
            for name in ("libpcre2-8.0.dylib", "libpcre2-posix.3.dylib")
        }
        for name, target in targets.items():
            dependencies = _otool_dependencies(target, runner)
            if not dependencies["ok"]:
                return dependencies
            for dependency in dependencies["dependencies"]:
                replacement = final_libraries.get(Path(dependency).name)
                if replacement and dependency != replacement:
                    changed = runner(
                        [INSTALL_NAME_TOOL, "-change", dependency, replacement, str(target)],
                        10,
                    )
                    if changed.get("rc") != 0:
                        return _result(False, error=f"runtime_relink_failed:{name}")
            if name != "privoxy":
                changed_id = runner(
                    [INSTALL_NAME_TOOL, "-id", final_libraries[name], str(target)],
                    10,
                )
                if changed_id.get("rc") != 0:
                    return _result(False, error=f"runtime_id_relink_failed:{name}")

        for name, target in targets.items():
            signed = runner([CODESIGN, "--force", "--sign", "-", str(target)], 15)
            if signed.get("rc") != 0:
                return _result(False, error=f"runtime_codesign_failed:{name}")
            verified = runner([CODESIGN, "--verify", "--strict", str(target)], 10)
            if verified.get("rc") != 0:
                return _result(False, error=f"runtime_signature_invalid:{name}")

        for name, target in targets.items():
            dependencies = _otool_dependencies(target, runner)
            if not dependencies["ok"]:
                return dependencies
            unsafe = [item for item in dependencies["dependencies"]
                      if item.startswith(("/opt/homebrew/", "/usr/local/"))]
            if unsafe:
                return _result(False, error=f"runtime_user_owned_dependency:{name}")

        if layout.runtime_dir.exists():
            shutil.rmtree(layout.runtime_dir)
        os.replace(temp, layout.runtime_dir)
        return _result(True)
    except OSError as exc:
        return _result(False, error=f"runtime_install_failed:{exc}")
    finally:
        if temp.exists():
            shutil.rmtree(temp, ignore_errors=True)


def _read_regular_nofollow(path, *, max_size=8 * 1024 * 1024):
    """Race-free чтение: O_NOFOLLOW делает check (не symlink) и use (чтение) одним syscall.

    lstat()-затем-copy2() (прежний подход) оставляет TOCTOU-окно: атакующий меняет
    regular-file на symlink к root-only секрету МЕЖДУ проверкой и копированием. open(O_NOFOLLOW)
    атомарно проваливается с ELOOP, если путь уже symlink — окна для подмены не существует,
    т.к. это единственный syscall, который и проверяет, и открывает.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        raise RuntimeError(f"backup_source_open_failed:{path}:{exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"backup_source_not_regular:{path}")
        if info.st_size > max_size:
            raise RuntimeError(f"backup_source_too_large:{path}")
        with os.fdopen(fd, "rb", closefd=True) as handle:
            fd = -1  # fdopen приняла владение fd; не закрывать повторно в finally.
            return handle.read()
    finally:
        if fd >= 0:
            os.close(fd)


def _copy_file_nofollow(src, dst, *, mode, chown=os.chown, max_size=64 * 1024 * 1024):
    """Race-free копирование regular-файла без разыменования symlink.

    Единый примитив для копирования user-controlled файлов в защищаемую root-зону (templates,
    Privoxy binary/dylib). Чтение source — через _read_regular_nofollow (open(O_NOFOLLOW)+fstat:
    symlink отвергается атомарно, содержимое root-only цели не читается), запись dst — через
    _atomic_write (непредсказуемое temp-имя, O_EXCL). Прежний copy2(follow_symlinks=True) /
    copytree(symlinks=False) разыменовывали symlink и копировали содержимое цели — arbitrary
    root-readable-file-disclosure (templates → 0644; binary/dylib → 0755 executable).
    Возвращает True при успехе, False при отказе (symlink/non-regular/нет файла).
    """
    src = Path(src)
    dst = Path(dst)
    try:
        data = _read_regular_nofollow(src, max_size=max_size)
    except RuntimeError:
        return False
    return _atomic_write(dst, data, mode=mode, uid=0, gid=0, chown=chown)


def _read_fd_regular(fd, *, max_size=8 * 1024 * 1024):
    """Прочитать regular-файл по fd (TOCTOU-свободно: fd уже открыт).

    fstat по fd не делает path-resolution. Размер/тип проверяются по fstat того же fd,
    что и читается — окна для подмены нет (используется в fd-tree-traversal, #148).
    """
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"fd_not_regular:mode={oct(info.st_mode)}")
    if info.st_size > max_size:
        raise RuntimeError(f"fd_too_large:{info.st_size}")
    return _read_all_fd(fd, info.st_size)


def _read_all_fd(fd, expected_size):
    """Прочитать всё содержимое fd чанками (fd уже past-stat, контент мог измениться —
    читаем до EOF, но отсекаем runaway-рост после fstat)."""
    chunks = []
    total = 0
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > expected_size + (1 << 20):
            # Файл вырос после fstat (гонка записи) — не копировать растущий объект.
            raise RuntimeError(f"fd_grew_after_stat:{total}>{expected_size}")
    return b"".join(chunks)


def _copy_tree_fd(src_fd, dst, *, dir_mode, file_mode):
    """fd-relative рекурсивное копирование дерева (TOCTOU-свободно, #148).

    src_fd — уже открытый O_NOFOLLOW|O_DIRECTORY дескриптор корня. Каждый элемент
    открывается через openat (os.open с dir_fd=src_fd) с O_NOFOLLOW: путь `name`
    разрешается относительно зафиксированного src_fd, а НЕ повторным разрешением
    полного src/name. Даже если атакующий атомарно подменит src-каталог на symlink
    между lstat-root и перечислением — openat берёт name из уже открытого src_fd,
    повторного path-resolution нет. symlink/non-regular child отвергается O_NOFOLLOW.

    dst (root-owned protected зона) НЕ user-controlled: path-based mkdir/chmod/chown
    на dst безопасны и не открывают TOCTOU (атакующий не контролирует dst-путь).
    """
    dst.mkdir(parents=True, exist_ok=True)
    os.chmod(dst, dir_mode)
    if os.geteuid() == 0:
        os.chown(dst, 0, 0)
    for name in sorted(os.listdir(src_fd)):
        child_fd = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=src_fd,
        )
        try:
            info = os.fstat(child_fd)
            dst_child = dst / name
            if stat.S_ISDIR(info.st_mode):
                if not _copy_tree_fd(child_fd, dst_child, dir_mode=dir_mode,
                                     file_mode=file_mode):
                    return False
            elif stat.S_ISREG(info.st_mode):
                try:
                    data = _read_fd_regular(child_fd)
                except RuntimeError:
                    return False
                if not _atomic_write(dst_child, data, mode=file_mode):
                    return False
            else:
                return False  # non-regular (symlink уже отсечён O_NOFOLLOW; fifo/socket/device) — отказ.
        finally:
            os.close(child_fd)
    return True


def _copy_tree_nofollow(src, dst, *, dir_mode=0o755, file_mode=0o644, chown=os.chown):
    """Race-free копирование дерева без разыменования symlink (полный fd-pinning, #148).

    Прежний _copy_templates звал _reject_symlinks_in_tree (отдельный lstat-проход) и затем
    copytree — между ними TOCTOU-окно. Дальнейшая fd-relative версия делала src.lstat()
    корня и затем os.listdir(src)/src_entry.lstat() ПО ПУТИ — между lstat(root) и listdir
    атакующий атомарно подменял src на symlink к root-only дереву, и listdir по пути шёл
    по symlink, читая чужое содержимое как 0644 world-readable.

    Теперь: root открывается ОДНИМ syscall os.open(O_NOFOLLOW|O_DIRECTORY) (отказ, если
    root сам symlink), перечисление — os.listdir(dir_fd), каждый child — через openat
    (os.open с dir_fd=root_fd, O_NOFOLLOW). Повторного path-resolution полного src-пути
    нет нигде — TOCTOU-окно между проверкой и travers'ом закрыто.
    """
    del chown  # fd-pinning: владельца dst выставляет _copy_tree_fd (inline os.chown под root), path-based хук не нужен.
    src = Path(src)
    dst = Path(dst)
    try:
        root_fd = os.open(
            str(src),
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError:
        return False  # root — symlink/не-каталог/нет файла (O_NOFOLLOW|O_DIRECTORY отвергает одним syscall).
    try:
        return _copy_tree_fd(root_fd, dst, dir_mode=dir_mode, file_mode=file_mode)
    finally:
        os.close(root_fd)


def _backup_existing(path, backup_dir, name, *, chown=os.chown):
    """Backup только regular-файла/директории, НЕ symlink (race-free через fd).

    `path` (например user_plist в ~/Library/LaunchAgents) до sudo-подтверждения полностью
    под контролем непривилегированного пользователя. root-процесс не должен читать/копировать
    содержимое ПО symlink — иначе backup (и позже restore) превращается в arbitrary-root-file-read
    примитив: подмени plist на symlink к root-only секрету → protect скопирует его в backup_dir →
    unprotect --restore запишет его содержимое обратно пользователю с 0644 (#122 privileged boundary).
    """
    path = Path(path)
    try:
        info = path.lstat()
    except OSError:
        return ""
    if stat.S_ISDIR(info.st_mode):
        _reject_symlinks_in_tree(path)
        target = Path(backup_dir) / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(path, target, symlinks=False)
        return str(target)
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"backup_source_not_regular:{path}")
    data = _read_regular_nofollow(path)
    target = Path(backup_dir) / name
    target.parent.mkdir(parents=True, exist_ok=True)
    if not _atomic_write(target, data, mode=0o600, uid=0, gid=0, chown=chown):
        raise RuntimeError(f"backup_write_failed:{path}")
    return str(target)


def _reject_symlinks_in_tree(root):
    """lstat каждого элемента дерева ДО копирования — ни один symlink не должен быть скопирован.

    `copytree(symlinks=False)` разыменовывает symlink внутри дерева и материализует содержимое
    его цели как обычный файл (задокументированное поведение shutil, не баг) — для user-writable
    дерева (Homebrew templates) это arbitrary-root-readable-file-disclosure: подложи symlink на
    root-only секрет внутри templates/ → root-хелпер скопирует его содержимое как root-owned
    world-readable файл. Валидация всего дерева ДО copytree закрывает это до чтения содержимого.
    """
    root = Path(root)
    top_info = root.lstat()
    if stat.S_ISLNK(top_info.st_mode):
        raise RuntimeError(f"tree_root_is_symlink:{root}")
    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in dirs:
            info = (current_path / name).lstat()
            if stat.S_ISLNK(info.st_mode):
                raise RuntimeError(f"tree_contains_symlink_dir:{current_path / name}")
        for name in files:
            info = (current_path / name).lstat()
            if stat.S_ISLNK(info.st_mode):
                raise RuntimeError(f"tree_contains_symlink_file:{current_path / name}")
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError(f"tree_contains_non_regular_file:{current_path / name}")


def _restore_file(backup, target, *, uid, gid, mode, chown=os.chown):
    if not backup:
        return False
    try:
        data = _read_regular_nofollow(backup)
    except RuntimeError:
        return False
    return _atomic_write(target, data, mode=mode, uid=uid, gid=gid, chown=chown)


def _bootout(domain, label, runner=_run):
    return runner([LAUNCHCTL, "bootout", _launchd_target(domain, label)], 15)


def _bootstrap(domain, plist_path, runner=_run):
    return runner([LAUNCHCTL, "bootstrap", domain, str(plist_path)], 20)


def _sudoers_text(username):
    return (
        f"# {SUDOERS_MARKER}\n"
        "# Явное подтверждение требуется для каждого sudo: агенты не используют timestamp cache.\n"
        f"Defaults:{username} timestamp_timeout=0\n"
    )


def _valid_identity(username, uid):
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


def _load_manifest(layout=DEFAULT_LAYOUT):
    try:
        value = json.loads(layout.manifest_path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None


def _verify_managed_assets(layout=DEFAULT_LAYOUT):
    for path, marker in (
        (layout.launchdaemon_path, PROTECTED_MARKER),
        (layout.config_path, PROTECTED_MARKER),
        (layout.sudoers_path, SUDOERS_MARKER),
    ):
        if path.exists() and not _managed_file(path, marker):
            return _result(False, error=f"protected_asset_drift:{path}")
    return _result(True)


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


def _launchd_field(output, key):
    match = re.search(rf"^\s*{re.escape(key)}\s*=\s*(.*?)\s*;?\s*$", output or "", re.MULTILINE)
    return match.group(1) if match else None


def _read_helper_bytes_pinned():
    """Открыть __file__ через O_NOFOLLOW, прочитать bytes, проверить marker и вычислить digest.

    marker-check и digest делаются на bytes одного и того же fd — TOCTOU-окна между
    проверкой и использованием нет. Возвращает (bytes, digest) или (None, None) если
    файл не regular / нет marker'а.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(__file__, flags)
    except OSError:
        return None, None
    try:
        try:
            data = _read_fd_regular(fd, max_size=4 * 1024 * 1024)
        except RuntimeError:
            return None, None
    finally:
        os.close(fd)
    if HELPER_MARKER.encode() not in data[:16384]:
        return None, None
    return data, hashlib.sha256(data).hexdigest()


def _helper_has_marker_fd(path):
    """Проверка marker на fd-чтении path (не path-based read_text — TOCTOU-свободно)."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError:
        return False
    try:
        try:
            data = _read_fd_regular(fd, max_size=4 * 1024 * 1024)
        except RuntimeError:
            return False
    finally:
        os.close(fd)
    return HELPER_MARKER.encode() in data[:16384]


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


def _stage_helper_bytes(data):
    """Записать helper bytes в staged temp в /private/tmp (fd-pinning: fchmod/fchown по fd).

    temp живёт в /private/tmp (sticky), имя непредсказуемо (mkstemp O_EXCL). ВАЖНО
    (#148): _stage_helper_bytes вызывается в user-процессе `protect()`, НЕ под sudo —
    поэтому mkstemp создаёт USER-owned файл (fchown no-op'ит под non-root). staged
    user-owned/writable в окне [mkstemp .. sudo install]. Эта подмена НЕ небезопасна:
    post-install digest-check в _install_helper ловит любое расхождение staged↔__file__
    (install копирует staged байт-в-байт, digest dst сравнивается с честным __file__).
    Возвращает Path temp или None при ошибке.
    """
    fd, tmp_name = tempfile.mkstemp(prefix="srouter-helper-", suffix=".py", dir="/private/tmp")
    temp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.fchmod(fd, 0o755)
        _fchown_if_privileged(fd, 0, 0)
        return temp
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temp)
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
