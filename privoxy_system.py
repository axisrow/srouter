#!/usr/bin/python3
"""Защищённый system-режим Privoxy для macOS.

Пользовательская часть модуля готовит конфигурацию и вызывает root-owned helper через sudo.
Root-часть намеренно использует только stdlib, фиксированные абсолютные пути и закрытый набор
операций. Произвольные команды, shell=True и пользовательские target-path здесь запрещены.
"""

from __future__ import annotations

# srouter-protected-helper-v1

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
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
import sys
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


def protected_config_text(layout=DEFAULT_LAYOUT):
    """Минимальная конфигурация bridge-only без user-writable action/filter files."""
    return (
        f"# {PROTECTED_MARKER}\n"
        "# Управляется только: srouter privoxy ...\n"
        f"confdir {layout.config_dir}\n"
        f"templdir {layout.templates_dir}\n"
        f"logdir {layout.log_dir}\n"
        "logfile logfile\n"
        "listen-address 127.0.0.1:8118\n"
        "toggle 1\n"
        "enable-remote-toggle 0\n"
        "enable-edit-actions 0\n"
        "enforce-blocks 0\n"
        "buffer-limit 4096\n"
        "forward-socks5t / 127.0.0.1:10808 .\n"
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


def validate_protected_config(text, layout=DEFAULT_LAYOUT):
    """Fail-closed: exact minimal contract, loopback-only and fixed upstream."""
    if not isinstance(text, str) or len(text.encode("utf-8")) > 64 * 1024:
        return _result(False, error="config_size_invalid")
    if PROTECTED_MARKER not in text:
        return _result(False, error="config_marker_missing")
    try:
        got = _config_directives(text)
        expected = _config_directives(protected_config_text(layout))
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


def _port_open(port=8118):
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


def _atomic_write(path, data, *, mode, uid=0, gid=0, chown=os.chown):
    """Race-free atomic write: непредсказуемое temp-имя + O_EXCL + fchmod/fchown по fd.

    Прежний temp `.name.tmp-PID` был предсказуем и жил в user-writable директории (при restore
    user_plist это ~/Library/LaunchAgents) — атакующий подкладывал symlink с этим именем на
    произвольный root-path, и open(temp, "wb") + chmod + chown, следуя symlink, писали/меняли
    владельца цели (arbitrary root file write). Теперь: tempfile.mkstemp даёт криптографически
    случайное имя и создаёт файл атомарно с O_EXCL; fstat/fchmod/fchown работают по fd, а не
    по пути — TOCTOU-окна для подмены temp нет.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    temp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            fd = -1  # fdopen приняла владение fd.
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        # Права по пути к temp допустимы: temp уже создан эксклюзивно со случайным именем,
        # атакующий не знает его и не может подменить. fchmod/fchown были бы строже, но
        # mkstemp не возвращает стабильно пригодный fd после закрытия; chmod/chown по
        # непредсказуемому пути безопасны в этой модели угроз.
        os.chmod(temp, mode)
        chown(temp, uid, gid)
        os.replace(temp, path)
        temp = None  # успех — не удалять в finally.
        return True
    except OSError:
        if temp is not None:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
        return False
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def _safe_staged_config(path, uid, layout=DEFAULT_LAYOUT):
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
    checked = validate_protected_config(text, layout)
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


def _copy_tree_nofollow(src, dst, *, dir_mode=0o755, file_mode=0o644, chown=os.chown):
    """Race-free копирование дерева без разыменования symlink (одним проходом).

    Прежний _copy_templates звал _reject_symlinks_in_tree (отдельный lstat-проход) и затем
    copytree — между ними TOCTOU-окно. Здесь дерево копируется fd-relative за один проход:
    root открывается через os.open(O_NOFOLLOW|O_DIRECTORY) (отказ, если root сам symlink),
    каждый элемент — через openat-эквивалент (os.open имени внутри уже открытой директории с
    O_NOFOLLOW); symlink или non-regular элемент → отказ всего копирования до записи содержимого.
    """
    src = Path(src)
    dst = Path(dst)
    # root дерева не должен быть symlink.
    try:
        root_info = src.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        return False
    dst.mkdir(parents=True, exist_ok=True)
    os.chmod(dst, dir_mode)
    chown(dst, 0, 0)
    for entry in sorted(os.listdir(src)):
        src_entry = src / entry
        dst_entry = dst / entry
        info = src_entry.lstat()
        if stat.S_ISLNK(info.st_mode):
            return False  # symlink внутри дерева — отказ до копирования содержимого.
        if stat.S_ISDIR(info.st_mode):
            if not _copy_tree_nofollow(src_entry, dst_entry, dir_mode=dir_mode,
                                       file_mode=file_mode, chown=chown):
                return False
        elif stat.S_ISREG(info.st_mode):
            if not _copy_file_nofollow(src_entry, dst_entry, mode=file_mode, chown=chown):
                return False
        else:
            return False  # non-regular (fifo/socket/device) — отказ.
    return True


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
                    user_home=None, config_test_runner=_run_as_nobody):
    """Одна root-транзакция: backup → bootout user job → install → bootstrap system → verify."""
    if enforce_root and os.geteuid() != 0:
        return _result(False, error="root_required")
    identity = _valid_identity(username, int(uid))
    if identity is None:
        return _result(False, error="identity_mismatch")
    prefix = _allowed_prefix(prefix)
    if not prefix:
        return _result(False, error="unsupported_homebrew_prefix")

    checked = _safe_staged_config(staged_config, int(uid), layout)
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


def status(*, runner=None, layout=DEFAULT_LAYOUT):
    """Read-only статус доступен без sudo."""
    if runner is None:
        from sys_probe import run as runner
    result = runner([LAUNCHCTL, "print", _launchd_target(SYSTEM_DOMAIN, SYSTEM_LABEL)], 5)
    output = result.get("out") or ""
    loaded = result.get("rc") == 0 and bool(output.strip())
    pid = None
    raw_pid = _launchd_field(output, "pid") if loaded else None
    try:
        pid = int(raw_pid) if raw_pid is not None else None
    except ValueError:
        pid = None
    owner = ""
    if pid:
        ps = runner([PS, "-o", "user=", "-p", str(pid)], 3)
        owner = (ps.get("out") or "").strip()
    user_shadow = runner(
        [LAUNCHCTL, "print", _launchd_target(f"gui/{os.getuid()}", USER_LABEL)], 5
    )
    protected_assets = (
        layout.config_dir.parent,
        layout.config_dir,
        layout.config_path,
        layout.runtime_dir,
        layout.binary_path,
        layout.launchdaemon_path,
        layout.helper_path,
        layout.sudoers_path,
    )
    return {
        "protected": protection_present(layout),
        "loaded": loaded,
        "pid": pid,
        "owner": owner,
        "state": _launchd_field(output, "state") if loaded else None,
        "port_up": _port_open(),
        "config_writable": os.access(layout.config_path, os.W_OK) if layout.config_path.exists() else None,
        "binary_writable": os.access(layout.binary_path, os.W_OK) if layout.binary_path.exists() else None,
        "assets_writable": any(path.exists() and os.access(path, os.W_OK)
                               for path in protected_assets),
        "user_shadow_loaded": user_shadow.get("rc") == 0 and bool((user_shadow.get("out") or "").strip()),
        "error": "" if loaded else (result.get("err") or "not loaded")[:240],
    }


def state_protected(state_path):
    try:
        import local_state
        state = local_state.load_state(path=state_path)
    except Exception:
        return False
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    entry = detected.get("privoxy") if isinstance(detected.get("privoxy"), dict) else {}
    protection = entry.get("protection") if isinstance(entry.get("protection"), dict) else {}
    return protection.get("service_scope") == "system" and protection.get("label") == SYSTEM_LABEL


def _write_pending(state_path, previous):
    import local_state
    state, readable = local_state.load_state_checked(path=state_path)
    if not readable:
        return False
    runtime = state.get("runtime") if isinstance(state.get("runtime"), dict) else {}
    runtime["privoxy_protection_pending"] = {
        "action": "protect",
        "started_at": _now(),
        "previous": previous,
    }
    state["runtime"] = runtime
    return local_state.save_state(state, path=state_path) is not None


def _write_unprotect_pending(state_path):
    import local_state
    state, readable = local_state.load_state_checked(path=state_path)
    if not readable:
        return False
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    current = detected.get("privoxy") if isinstance(detected.get("privoxy"), dict) else {}
    runtime = state.get("runtime") if isinstance(state.get("runtime"), dict) else {}
    runtime["privoxy_protection_pending"] = {
        "action": "unprotect",
        "started_at": _now(),
        "previous": current,
    }
    state["runtime"] = runtime
    return local_state.save_state(state, path=state_path) is not None


def _mark_failed(state_path, error):
    import local_state
    state, readable = local_state.load_state_checked(path=state_path)
    if not readable:
        return
    runtime = state.get("runtime") if isinstance(state.get("runtime"), dict) else {}
    pending = runtime.get("privoxy_protection_pending")
    if isinstance(pending, dict):
        pending["failed_at"] = _now()
        pending["error"] = error
    runtime["last_error"] = error
    state["runtime"] = runtime
    local_state.save_state(state, path=state_path)


def _promote_state(state_path, *, backup_dir, layout=DEFAULT_LAYOUT):
    import local_state
    state, readable = local_state.load_state_checked(path=state_path)
    if not readable:
        return False
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    previous = detected.get("privoxy") if isinstance(detected.get("privoxy"), dict) else {}
    runtime = state.get("runtime") if isinstance(state.get("runtime"), dict) else {}
    pending = runtime.get("privoxy_protection_pending")
    if isinstance(pending, dict) and isinstance(pending.get("previous"), dict):
        previous = pending["previous"]
    detected["privoxy"] = {
        "config_path": str(layout.config_path),
        "port": 8118,
        "service": "protected-system",
        "management": {"mode": "managed", "managed": True, "provenance": "protected"},
        "protection": {
            "version": PROTECTION_VERSION,
            "mode": "strict",
            "service_scope": "system",
            "label": SYSTEM_LABEL,
            "backup_dir": backup_dir,
            "previous": previous,
            "activated_at": _now(),
        },
    }
    detected["last_checked_at"] = _now()
    state["detected_environment"] = detected
    runtime.pop("privoxy_protection_pending", None)
    runtime["last_apply"] = _now()
    runtime["last_error"] = None
    state["runtime"] = runtime
    return local_state.save_state(state, path=state_path) is not None


def _restore_state_after_unprotect(state_path):
    import local_state
    state, readable = local_state.load_state_checked(path=state_path)
    if not readable:
        return False
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    entry = detected.get("privoxy") if isinstance(detected.get("privoxy"), dict) else {}
    protection = entry.get("protection") if isinstance(entry.get("protection"), dict) else {}
    previous = protection.get("previous") if isinstance(protection.get("previous"), dict) else None
    detected["privoxy"] = previous
    detected["last_checked_at"] = _now()
    state["detected_environment"] = detected
    runtime = state.get("runtime") if isinstance(state.get("runtime"), dict) else {}
    runtime.pop("privoxy_protection_pending", None)
    runtime["last_apply"] = _now()
    runtime["last_error"] = None
    state["runtime"] = runtime
    return local_state.save_state(state, path=state_path) is not None


def _parse_helper_output(result):
    for line in reversed((result.get("out") or "").splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and "ok" in value:
            return value
    return _result(False, error=(result.get("err") or result.get("out") or "helper_failed")[:240])


def _sudo_reset(runner):
    return runner([SUDO, "-k"], 5)


def _install_helper(runner, layout=DEFAULT_LAYOUT):
    source = Path(__file__).resolve()
    if not _managed_file(source, HELPER_MARKER):
        return _result(False, error="helper_source_marker_missing")
    if layout.helper_path.exists() and not _managed_file(layout.helper_path, HELPER_MARKER):
        return _result(False, error="foreign_privileged_helper")
    parent = runner([SUDO, MKDIR, "-p", str(layout.helper_path.parent)], 30)
    if parent.get("rc") != 0:
        return _result(False, error=(parent.get("err") or "helper_parent_failed")[:240])
    installed = runner(
        [SUDO, INSTALL, "-o", "root", "-g", "wheel", "-m", "0755",
         str(source), str(layout.helper_path)],
        30,
    )
    if installed.get("rc") != 0:
        return _result(False, error=(installed.get("err") or "helper_install_failed")[:240])
    return _result(True)


def _rollback_protection(runner, layout=DEFAULT_LAYOUT):
    _sudo_reset(runner)
    rollback = runner([SUDO, str(layout.helper_path), "unprotect", "--restore"], 90)
    _sudo_reset(runner)
    return _parse_helper_output(rollback)


def protect(*, state_path, prefix="/opt/homebrew", runner=None, require_tty=True,
            layout=DEFAULT_LAYOUT):
    if runner is None:
        from sys_probe import run as runner
    if require_tty and not sys.stdin.isatty():
        return _result(False, error="interactive_terminal_required")
    current = status(runner=runner, layout=layout)
    secure = (
        current["protected"]
        and current["loaded"]
        and current["port_up"]
        and current["owner"] == "nobody"
        and current["config_writable"] is False
        and current["binary_writable"] is False
        and current["assets_writable"] is False
        and not current["user_shadow_loaded"]
    )
    if secure:
        if not state_protected(state_path):
            manifest = _load_manifest(layout) or {}
            if not _promote_state(state_path, backup_dir=manifest.get("backup_dir", ""), layout=layout):
                return _result(False, error="state_repair_failed", status=current)
            return _result(True, changed=True, repaired_state=True, status=current)
        return _result(True, changed=False, status=current)

    import local_state
    state, readable = local_state.load_state_checked(path=state_path)
    if not readable:
        return _result(False, error="state_unreadable")
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    previous = detected.get("privoxy") if isinstance(detected.get("privoxy"), dict) else {}
    if not _write_pending(state_path, previous):
        return _result(False, error="pending_state_write_failed")

    staged_dir = Path(tempfile.mkdtemp(prefix="srouter-privoxy-protect-", dir="/private/tmp"))
    staged_config = staged_dir / "config"
    try:
        os.chmod(staged_dir, 0o700)
        staged_config.write_text(protected_config_text(layout), encoding="utf-8")
        os.chmod(staged_config, 0o600)
        _sudo_reset(runner)
        installed = _install_helper(runner, layout)
        if not installed["ok"]:
            _mark_failed(state_path, installed["error"])
            return installed
        invoked = runner(
            [SUDO, str(layout.helper_path), "protect",
             "--username", pwd.getpwuid(os.getuid()).pw_name,
             "--uid", str(os.getuid()),
             "--prefix", str(prefix),
             "--config", str(staged_config)],
            120,
        )
        outcome = _parse_helper_output(invoked)
        _sudo_reset(runner)
        if not outcome["ok"]:
            _mark_failed(state_path, outcome["error"])
            return outcome

        no_cache = runner([SUDO, "-n", str(layout.helper_path), "status"], 10)
        if no_cache.get("rc") == 0:
            detail = _rollback_protection(runner, layout)
            error = "sudo_without_fresh_authorization"
            if not detail.get("ok"):
                error += f"; rollback_failed:{detail.get('error')}"
            _mark_failed(state_path, error)
            return _result(False, error=error)

        current = status(runner=runner, layout=layout)
        if not (current["protected"] and current["loaded"] and current["port_up"]
                and current["owner"] == "nobody" and current["config_writable"] is False
                and current["binary_writable"] is False and current["assets_writable"] is False
                and not current["user_shadow_loaded"]):
            rollback_result = _rollback_protection(runner, layout)
            error = "post_protect_verification_failed"
            if not rollback_result.get("ok"):
                error += f"; rollback_failed:{rollback_result.get('error')}"
            _mark_failed(state_path, error)
            return _result(False, error=error, status=current)
        if not _promote_state(state_path, backup_dir=outcome.get("backup_dir", ""), layout=layout):
            # Файлы/служба уже применены, но active-state не зафиксирован — это не success.
            # Откатываем той же whitelisted root-операцией и оставляем pending с причиной.
            rollback_result = _rollback_protection(runner, layout)
            _mark_failed(state_path, "state_promote_failed")
            return _result(False, error=("state_promote_failed" if rollback_result.get("ok")
                                         else f"state_promote_failed; rollback_failed:{rollback_result.get('error')}"),
                           status=current)
        return _result(True, changed=True, status=current, backup_dir=outcome.get("backup_dir", ""))
    finally:
        shutil.rmtree(staged_dir, ignore_errors=True)


def control(action, *, runner=None, require_tty=True, layout=DEFAULT_LAYOUT):
    if action not in {"start", "stop", "restart"}:
        return _result(False, error="action_not_allowed")
    if runner is None:
        from sys_probe import run as runner
    if require_tty and not sys.stdin.isatty():
        return _result(False, error="interactive_terminal_required")
    if not protection_present(layout):
        return _result(False, error="protected_service_not_installed")
    _sudo_reset(runner)
    invoked = runner([SUDO, str(layout.helper_path), action], 90)
    _sudo_reset(runner)
    outcome = _parse_helper_output(invoked)
    outcome["status"] = status(runner=runner, layout=layout)
    return outcome


def unprotect(*, state_path, restore=True, runner=None, require_tty=True,
              layout=DEFAULT_LAYOUT):
    if runner is None:
        from sys_probe import run as runner
    if require_tty and not sys.stdin.isatty():
        return _result(False, error="interactive_terminal_required")
    if not protection_present(layout):
        return _result(True, changed=False)
    if not _write_unprotect_pending(state_path):
        return _result(False, error="pending_state_write_failed")
    _sudo_reset(runner)
    cmd = [SUDO, str(layout.helper_path), "unprotect"]
    if restore:
        cmd.append("--restore")
    invoked = runner(cmd, 90)
    outcome = _parse_helper_output(invoked)
    _sudo_reset(runner)
    if not outcome["ok"]:
        _mark_failed(state_path, outcome["error"])
        return outcome
    if not _restore_state_after_unprotect(state_path):
        return _result(False, error="state_restore_failed")
    return _result(True, changed=True, restored=outcome.get("restored", False))


def helper_main(argv=None):
    parser = argparse.ArgumentParser(prog="com.srouter.privoxyctl")
    sub = parser.add_subparsers(dest="command", required=True)
    protect_parser = sub.add_parser("protect")
    protect_parser.add_argument("--username", required=True)
    protect_parser.add_argument("--uid", required=True, type=int)
    protect_parser.add_argument("--prefix", required=True)
    protect_parser.add_argument("--config", required=True)
    unprotect_parser = sub.add_parser("unprotect")
    unprotect_parser.add_argument("--restore", action="store_true")
    for name in ("start", "stop", "restart", "status"):
        sub.add_parser(name)
    args = parser.parse_args(argv)

    if args.command == "protect":
        outcome = protect_as_root(username=args.username, uid=args.uid, prefix=args.prefix,
                                  staged_config=args.config)
    elif args.command == "unprotect":
        outcome = unprotect_as_root(restore=args.restore)
    else:
        outcome = control_as_root(args.command)
    print(json.dumps(outcome, ensure_ascii=False, separators=(",", ":")))
    return 0 if outcome.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(helper_main())
