"""launchd/процесс-обвязка root-helper'а (issue #287, tree-copy redesign).

АРХИТЕКТУРНЫЙ ИНВАРИАНТ: часть root-owned helper-дерева (см. docstring privoxy_helper_fs.py) —
tree-copy install копирует этот файл рядом с privoxy_system.py (entrypoint) в
/Library/PrivilegedHelperTools, исполняется изолированно под sudo. Только stdlib.

Runner-примитивы (`_run`/`_run_as_nobody`), опрос launchd (`_launchd_loaded`/`_launchd_pid`/
`_launchd_field`), TCP-порт-чекеры (`_port_open`/`_wait_port`) и relink/codesign Privoxy-рантайма
(`_install_runtime`, `_otool_dependencies`) — перенесены без изменений логики из
privoxy_system.py (issue #287). `_install_runtime` использует `_copy_file_nofollow` из
privoxy_helper_fs (fd-pinning copy) — единственная межмодульная helper-зависимость этого файла.
"""

from __future__ import annotations

import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import time

import privoxy_helper_fs

OTOOL = "/usr/bin/otool"
INSTALL_NAME_TOOL = "/usr/bin/install_name_tool"
CODESIGN = "/usr/bin/codesign"
LAUNCHCTL = "/bin/launchctl"


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


def _launchd_target(domain, label):
    return f"{domain}/{label}"


def _launchd_loaded(domain, label, runner=_run):
    result = runner([LAUNCHCTL, "print", _launchd_target(domain, label)], 5)
    return result.get("rc") == 0 and bool((result.get("out") or "").strip())


def _launchd_field(output, key):
    import re
    match = re.search(rf"^\s*{re.escape(key)}\s*=\s*(.*?)\s*;?\s*$", output or "", re.MULTILINE)
    return match.group(1) if match else None


def _launchd_pid(domain, label, runner=_run):
    result = runner([LAUNCHCTL, "print", _launchd_target(domain, label)], 5)
    if result.get("rc") != 0:
        return None
    raw = _launchd_field(result.get("out") or "", "pid")
    try:
        return int(raw) if raw is not None else None
    except ValueError:
        return None


def _port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.25):
            return True
    except OSError:
        return False


def _wait_port(expected, *, checker, timeout=8.0, interval=0.1):
    deadline = time.monotonic() + timeout
    state = bool(checker())
    while state != expected and time.monotonic() < deadline:
        time.sleep(interval)
        state = bool(checker())
    return state == expected


def _bootout(domain, label, runner=_run):
    return runner([LAUNCHCTL, "bootout", _launchd_target(domain, label)], 15)


def _bootstrap(domain, plist_path, runner=_run):
    return runner([LAUNCHCTL, "bootstrap", domain, str(plist_path)], 20)


def _otool_dependencies(path, runner=_run):
    result = runner([OTOOL, "-L", str(path)], 10)
    if result.get("rc") != 0:
        return {"ok": False, "error": f"otool_failed:{(result.get('err') or '')[:160]}"}
    dependencies = []
    for line in (result.get("out") or "").splitlines()[1:]:
        value = line.strip().split(" (", 1)[0]
        if value:
            dependencies.append(value)
    return {"ok": True, "error": "", "dependencies": dependencies}


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
        return {"ok": False, "error": f"protected_runtime_source_missing:{','.join(missing)}"}

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
            if not privoxy_helper_fs._copy_file_nofollow(source, targets[name], mode=0o755, chown=chown):
                return {"ok": False, "error": f"runtime_source_not_regular:{name}"}
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
                        return {"ok": False, "error": f"runtime_relink_failed:{name}"}
            if name != "privoxy":
                changed_id = runner(
                    [INSTALL_NAME_TOOL, "-id", final_libraries[name], str(target)],
                    10,
                )
                if changed_id.get("rc") != 0:
                    return {"ok": False, "error": f"runtime_id_relink_failed:{name}"}

        for name, target in targets.items():
            signed = runner([CODESIGN, "--force", "--sign", "-", str(target)], 15)
            if signed.get("rc") != 0:
                return {"ok": False, "error": f"runtime_codesign_failed:{name}"}
            verified = runner([CODESIGN, "--verify", "--strict", str(target)], 10)
            if verified.get("rc") != 0:
                return {"ok": False, "error": f"runtime_signature_invalid:{name}"}

        for name, target in targets.items():
            dependencies = _otool_dependencies(target, runner)
            if not dependencies["ok"]:
                return dependencies
            unsafe = [item for item in dependencies["dependencies"]
                      if item.startswith(("/opt/homebrew/", "/usr/local/"))]
            if unsafe:
                return {"ok": False, "error": f"runtime_user_owned_dependency:{name}"}

        if layout.runtime_dir.exists():
            shutil.rmtree(layout.runtime_dir)
        os.replace(temp, layout.runtime_dir)
        return {"ok": True, "error": ""}
    except OSError as exc:
        return {"ok": False, "error": f"runtime_install_failed:{exc}"}
    finally:
        if temp.exists():
            shutil.rmtree(temp, ignore_errors=True)
