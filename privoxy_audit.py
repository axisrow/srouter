#!/usr/bin/python3
"""Пассивный root-owned аудит команд, меняющих lifecycle Privoxy на macOS."""

from __future__ import annotations

# srouter-privoxy-audit-helper-v1

import argparse
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import signal
import stat
import subprocess
import sys
import threading


AUDIT_VERSION = 1
AUDIT_MARKER = "srouter-privoxy-command-audit-v1"
HELPER_MARKER = "srouter-privoxy-audit-helper-v1"
AUDIT_LABEL = "com.srouter.privoxy.audit"
LAUNCHCTL = "/bin/launchctl"
SUDO = "/usr/bin/sudo"
INSTALL = "/usr/bin/install"
MKDIR = "/bin/mkdir"
ESLOGGER = "/usr/bin/eslogger"

_SECRET_KEY = re.compile(
    r"(?i)(password|passwd|token|secret|api[_-]?key|authorization|credential)"
)
_SECRET_INLINE = re.compile(
    r"(?i)\b(password|passwd|token|secret|api[_-]?key|authorization|credential)"
    r"(?:\s*[:=]\s*|\s+)([^\s;]+)"
)
_SHELLS = {"sh", "bash", "zsh", "fish", "env", "osascript"}
_LIFECYCLE_WORDS = {
    "start", "stop", "restart", "install", "uninstall", "bootout", "bootstrap", "kickstart",
    "load", "unload", "remove", "enable", "disable", "kill", "cleanup", "protect", "unprotect",
}


@dataclass(frozen=True)
class AuditLayout:
    """Фиксированные system paths; публичный CLI не принимает их от пользователя."""

    helper_path: Path = Path("/Library/PrivilegedHelperTools/com.srouter.privoxyaudit")
    launchdaemon_path: Path = Path("/Library/LaunchDaemons/com.srouter.privoxy.audit.plist")
    data_dir: Path = Path("/Library/Application Support/srouter/privoxy/audit")
    status_path: Path = Path("/Library/Application Support/srouter/privoxy/audit/status.json")
    log_dir: Path = Path("/Library/Logs/srouter/privoxy-audit")
    event_log_path: Path = Path("/Library/Logs/srouter/privoxy-audit/command-audit.jsonl")
    stdout_path: Path = Path("/Library/Logs/srouter/privoxy-audit/stdout.log")
    stderr_path: Path = Path("/Library/Logs/srouter/privoxy-audit/stderr.log")
    eslogger_path: Path = Path(ESLOGGER)


DEFAULT_LAYOUT = AuditLayout()


def _now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _result(ok, *, error="", **extra):
    return {"ok": bool(ok), "error": error, **extra}


def _run(cmd, timeout=30):
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


def _managed_file(path, marker):
    try:
        return marker in Path(path).read_text(encoding="utf-8", errors="ignore")[:16384]
    except OSError:
        return False


def _secure_managed_file(path, marker, *, expected_uid=0, executable=False):
    path = Path(path)
    try:
        info = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == expected_uid
        and not info.st_mode & 0o022
        and (not executable or bool(info.st_mode & 0o111))
        and _managed_file(path, marker)
    )


def _atomic_write(path, data, *, mode, uid=0, gid=0, chown=os.chown):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with open(temp, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, mode)
        chown(temp, uid, gid)
        os.replace(temp, path)
        return True
    except OSError:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        return False


def _write_status(layout, payload, *, chown=os.chown):
    value = {
        "marker": AUDIT_MARKER,
        "audit_version": AUDIT_VERSION,
        "updated_at": _now(),
        **payload,
    }
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    return _atomic_write(layout.status_path, raw, mode=0o644, uid=0, gid=0, chown=chown)


def audit_launchdaemon_bytes(layout=DEFAULT_LAYOUT):
    payload = {
        "Label": AUDIT_LABEL,
        "ProgramArguments": [str(layout.helper_path), "daemon"],
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ProcessType": "Background",
        "ThrottleInterval": 60,
        "StandardOutPath": str(layout.stdout_path),
        "StandardErrorPath": str(layout.stderr_path),
    }
    raw = plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=False)
    marker = f"<!-- {AUDIT_MARKER} -->\n".encode()
    return raw.replace(b"?>\n", b"?>\n" + marker, 1)


def _string(value, limit=512):
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, (int, float, bool)):
        return str(value)[:limit]
    if isinstance(value, dict):
        for key in ("string", "value", "path"):
            if isinstance(value.get(key), str):
                return value[key][:limit]
    return ""


def _event_args(event):
    raw = (((event.get("event") or {}).get("exec") or {}).get("args") or [])
    if not isinstance(raw, list):
        return []
    return [_string(item) for item in raw[:64] if _string(item)]


def _executable_path(process):
    if not isinstance(process, dict):
        return ""
    executable = process.get("executable")
    if isinstance(executable, dict):
        return _string(executable.get("path"), 1024)
    return _string(executable, 1024)


def _target_process(event):
    return (((event.get("event") or {}).get("exec") or {}).get("target") or {})


def _contains_lifecycle(text):
    lowered = text.lower()
    return any(word in lowered for word in _LIFECYCLE_WORDS)


def is_privoxy_event(event):
    """Оставить только exec-события, способные менять lifecycle Privoxy."""
    if not isinstance(event, dict):
        return False
    target = _target_process(event)
    target_path = _executable_path(target)
    basename = Path(target_path).name.lower()
    args = _event_args(event)
    joined = " ".join(args).lower()
    if "privoxyaudit" in joined or ("privoxy" in args and "audit" in args):
        return False
    runs_srouter = basename in {"srouter", "srouter.py"} or any(
        Path(value).name.lower() in {"srouter", "srouter.py"} for value in args[:4]
    )
    if runs_srouter and any(action in args for action in ("install", "uninstall")):
        return True
    mentions_privoxy = (
        "privoxy" in joined
        or "homebrew.mxcl.privoxy" in joined
        or "com.srouter.privoxy" in joined
    )
    if not mentions_privoxy:
        return False
    if basename == "brew":
        return "services" in args and _contains_lifecycle(joined)
    if basename == "launchctl":
        return _contains_lifecycle(joined)
    if basename in {"srouter", "srouter.py"}:
        return _contains_lifecycle(joined)
    if basename.startswith("python") and runs_srouter:
        return _contains_lifecycle(joined)
    if basename == "sudo":
        return _contains_lifecycle(joined)
    if basename in {"pkill", "killall"}:
        return True
    if basename in _SHELLS:
        return _contains_lifecycle(joined)
    return (
        target_path == "/Library/PrivilegedHelperTools/com.srouter.privoxyctl"
        and _contains_lifecycle(joined)
    )


def _redacted_args(args):
    result = []
    redact_next = False
    for raw in args[:64]:
        value = _string(raw)
        if redact_next:
            result.append("<redacted>")
            redact_next = False
            continue
        if value.startswith("--") and "=" in value:
            key, _ = value.split("=", 1)
            if _SECRET_KEY.search(key):
                result.append(f"{key}=<redacted>")
                continue
        if value.startswith("-") and _SECRET_KEY.search(value):
            result.append(value[:128])
            redact_next = True
            continue
        if "=" in value:
            key, _ = value.split("=", 1)
            if _SECRET_KEY.search(key):
                result.append(f"{key[:128]}=<redacted>")
                continue
        inline = _SECRET_INLINE.search(value)
        if inline:
            value = f"{value[:inline.start()]}{inline.group(1)}=<redacted>"
        result.append(value[:512])
    return result


def _pid(process):
    if not isinstance(process, dict):
        return None
    token = process.get("audit_token")
    raw = token.get("pid") if isinstance(token, dict) else process.get("pid")
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _identity(process):
    if not isinstance(process, dict):
        return {}
    return {
        "pid": _pid(process),
        "executable": _executable_path(process),
        "signing_id": _string(process.get("signing_id"), 256),
        "team_id": _string(process.get("team_id"), 256),
    }


def normalize_event(event):
    if not is_privoxy_event(event):
        return None
    process = event.get("process") if isinstance(event.get("process"), dict) else {}
    target = _target_process(event)
    exec_event = ((event.get("event") or {}).get("exec") or {})
    responsible = exec_event.get("responsible_process")
    if not isinstance(responsible, dict):
        responsible = event.get("responsible_process")
    record = {
        "audit_version": AUDIT_VERSION,
        "captured_at": _now(),
        "event_time": _string(event.get("time") or event.get("timestamp"), 128),
        "eslogger_schema_version": event.get("schema_version"),
        "actor": _identity(process),
        "target": {
            **_identity(target),
            "args": _redacted_args(_event_args(event)),
        },
    }
    if isinstance(responsible, dict):
        record["responsible"] = _identity(responsible)
    return record


def _append_event(layout, record, *, gid, chown=os.chown):
    path = layout.event_log_path
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    fd = os.open(path, flags, 0o640)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return False
        os.fchmod(fd, 0o640)
        chown(path, 0, gid)
        raw = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        remaining = memoryview(raw)
        while remaining:
            written = os.write(fd, remaining)
            if written <= 0:
                return False
            remaining = remaining[written:]
        os.fsync(fd)
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


def _valid_identity(username, uid, gid):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", username or ""):
        return None
    try:
        record = pwd.getpwnam(username)
    except KeyError:
        return None
    return record if record.pw_uid == uid and record.pw_gid == gid else None


def _launchd_loaded(runner=_run):
    result = runner([LAUNCHCTL, "print", f"system/{AUDIT_LABEL}"], 5)
    return result.get("rc") == 0 and bool((result.get("out") or "").strip())


def _prepare_directories(layout, gid, *, chown=os.chown, expected_uid=0):
    try:
        # Каталог аудитора не разделяется с Privoxy: процесс nobody не может менять доказательства.
        # Ни один существующий symlink или доступный для записи каталог не принимается.
        for path, mode, manage, allowed_uids in (
            (layout.data_dir, 0o755, True, {expected_uid}),
            (layout.log_dir, 0o755, True, {expected_uid}),
            (layout.helper_path.parent, 0o755, False, {expected_uid, 0}),
            (layout.launchdaemon_path.parent, 0o755, False, {expected_uid, 0}),
        ):
            if path.exists() or path.is_symlink():
                info = path.lstat()
                if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                        or info.st_uid not in allowed_uids or info.st_mode & 0o022):
                    return _result(False, error=f"audit_directory_drift:{path}")
            else:
                path.mkdir(parents=True)
                manage = True
            if manage:
                os.chmod(path, mode)
                chown(path, 0, 0)
        if layout.event_log_path.exists():
            info = layout.event_log_path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                return _result(False, error="audit_log_not_regular")
            if info.st_uid != expected_uid or info.st_mode & 0o027:
                return _result(False, error="audit_log_ownership_or_mode_drift")
            os.chmod(layout.event_log_path, 0o640)
            chown(layout.event_log_path, 0, gid)
        else:
            fd = os.open(layout.event_log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
            os.close(fd)
            chown(layout.event_log_path, 0, gid)
        return _result(True)
    except OSError as exc:
        return _result(False, error=f"audit_directory_prepare_failed:{exc}")


def install_as_root(*, username, uid, gid, layout=DEFAULT_LAYOUT, runner=_run,
                    chown=os.chown, enforce_root=True):
    if enforce_root and os.geteuid() != 0:
        return _result(False, error="root_required")
    if enforce_root and layout != DEFAULT_LAYOUT:
        return _result(False, error="fixed_layout_required")
    if not _valid_identity(username, uid, gid):
        return _result(False, error="identity_invalid")
    expected_uid = 0 if enforce_root else os.getuid()
    if not _secure_managed_file(
            layout.helper_path, HELPER_MARKER, expected_uid=expected_uid, executable=True):
        return _result(False, error="audit_helper_insecure")
    if not layout.eslogger_path.is_file() or not os.access(layout.eslogger_path, os.X_OK):
        return _result(False, error="eslogger_missing")
    if layout.launchdaemon_path.exists() and not _secure_managed_file(
            layout.launchdaemon_path, AUDIT_MARKER, expected_uid=expected_uid):
        return _result(False, error="foreign_audit_launchdaemon")
    prepared = _prepare_directories(layout, gid, chown=chown, expected_uid=expected_uid)
    if not prepared["ok"]:
        return prepared

    old_plist = layout.launchdaemon_path.read_bytes() if layout.launchdaemon_path.exists() else None
    was_loaded = _launchd_loaded(runner)
    raw = audit_launchdaemon_bytes(layout)
    try:
        plistlib.loads(raw)
    except Exception as exc:
        return _result(False, error=f"audit_plist_invalid:{exc}")
    if not _atomic_write(layout.launchdaemon_path, raw, mode=0o644, uid=0, gid=0, chown=chown):
        return _result(False, error="audit_plist_write_failed")
    previous_status = _read_status_file(layout)
    _write_status(layout, {
        "state": "installing",
        "installed_at": _now(),
        "username": username,
        "uid": uid,
        "gid": gid,
        "events_written": int(previous_status.get("events_written") or 0),
        "parse_errors": int(previous_status.get("parse_errors") or 0),
        "schema_versions": list(previous_status.get("schema_versions") or [])[:16],
        "last_error": "",
    }, chown=chown)

    if was_loaded:
        stopped = runner([LAUNCHCTL, "bootout", f"system/{AUDIT_LABEL}"], 15)
        if stopped.get("rc") != 0 or _launchd_loaded(runner):
            if old_plist is not None:
                _atomic_write(layout.launchdaemon_path, old_plist, mode=0o644,
                              uid=0, gid=0, chown=chown)
            error = f"audit_bootout_failed:{(stopped.get('err') or '')[:160]}"
            _write_status(layout, {"state": "error", "gid": gid, "last_error": error}, chown=chown)
            return _result(False, error=error)
    boot = runner([LAUNCHCTL, "bootstrap", "system", str(layout.launchdaemon_path)], 20)
    if not _launchd_loaded(runner):
        if old_plist is None:
            layout.launchdaemon_path.unlink(missing_ok=True)
        else:
            _atomic_write(layout.launchdaemon_path, old_plist, mode=0o644, uid=0, gid=0, chown=chown)
            if was_loaded:
                runner([LAUNCHCTL, "bootstrap", "system", str(layout.launchdaemon_path)], 20)
        error = f"audit_bootstrap_failed:{(boot.get('err') or '')[:160]}"
        _write_status(layout, {"state": "error", "gid": gid, "last_error": error}, chown=chown)
        return _result(False, error=error)
    return _result(True, changed=True)


def uninstall_as_root(*, purge_log=False, layout=DEFAULT_LAYOUT, runner=_run,
                      chown=os.chown, enforce_root=True):
    if enforce_root and os.geteuid() != 0:
        return _result(False, error="root_required")
    if enforce_root and layout != DEFAULT_LAYOUT:
        return _result(False, error="fixed_layout_required")
    expected_uid = 0 if enforce_root else os.getuid()
    if layout.launchdaemon_path.exists() and not _secure_managed_file(
            layout.launchdaemon_path, AUDIT_MARKER, expected_uid=expected_uid):
        return _result(False, error="foreign_audit_launchdaemon")
    if layout.helper_path.exists() and not _secure_managed_file(
            layout.helper_path, HELPER_MARKER, expected_uid=expected_uid, executable=True):
        return _result(False, error="foreign_audit_helper")
    if _launchd_loaded(runner):
        runner([LAUNCHCTL, "bootout", f"system/{AUDIT_LABEL}"], 15)
        if _launchd_loaded(runner):
            return _result(False, error="audit_daemon_still_loaded")
    _write_status(layout, {"state": "uninstalled", "uninstalled_at": _now(), "last_error": ""}, chown=chown)
    try:
        layout.launchdaemon_path.unlink(missing_ok=True)
        if purge_log:
            layout.event_log_path.unlink(missing_ok=True)
        if layout.helper_path.exists():
            layout.helper_path.unlink()
    except OSError as exc:
        return _result(False, error=f"audit_assets_remove_failed:{exc}")
    return _result(True, changed=True, log_preserved=not purge_log)


def _read_status_file(layout):
    try:
        value = json.loads(layout.status_path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) and value.get("marker") == AUDIT_MARKER else {}
    except (OSError, ValueError):
        return {}


def status(*, layout=DEFAULT_LAYOUT, runner=None, expected_uid=0):
    if runner is None:
        from sys_probe import run as runner
    loaded = _launchd_loaded(runner)
    saved = _read_status_file(layout)
    last_error = _string(saved.get("last_error"), 512)
    lowered = last_error.lower()
    fda_required = any(word in lowered for word in (
        "full disk access", "operation not permitted", "not permitted", "tcc",
    ))
    return {
        "installed": _secure_managed_file(
            layout.launchdaemon_path, AUDIT_MARKER, expected_uid=expected_uid,
        ) and _secure_managed_file(
            layout.helper_path, HELPER_MARKER, expected_uid=expected_uid, executable=True,
        ),
        "loaded": loaded,
        "state": saved.get("state") or ("running" if loaded else "not_installed"),
        "events_written": saved.get("events_written", 0),
        "parse_errors": saved.get("parse_errors", 0),
        "schema_versions": saved.get("schema_versions", []),
        "last_event_at": saved.get("last_event_at"),
        "last_error": last_error,
        "fda_required": fda_required,
        "event_log": str(layout.event_log_path),
    }


def report(*, limit=50, layout=DEFAULT_LAYOUT):
    limit = max(1, min(int(limit), 1000))
    records = deque(maxlen=limit)
    parse_errors = 0
    try:
        with open(layout.event_log_path, encoding="utf-8") as handle:
            for line in handle:
                try:
                    value = json.loads(line)
                except ValueError:
                    parse_errors += 1
                    continue
                if isinstance(value, dict):
                    records.append(value)
    except FileNotFoundError:
        return _result(True, records=[], parse_errors=0, path=str(layout.event_log_path))
    except OSError as exc:
        return _result(False, error=f"audit_log_unreadable:{exc}", records=[])
    return _result(True, records=list(records), parse_errors=parse_errors,
                   path=str(layout.event_log_path))


def _event_shape_valid(event):
    if not isinstance(event, dict) or "schema_version" not in event:
        return False
    process = event.get("process")
    exec_event = ((event.get("event") or {}).get("exec") or {})
    target = exec_event.get("target")
    return (
        isinstance(process, dict)
        and isinstance(exec_event, dict)
        and isinstance(target, dict)
        and isinstance(exec_event.get("args"), list)
        and bool(_executable_path(target))
    )


def daemon(*, layout=DEFAULT_LAYOUT, popen=subprocess.Popen, chown=os.chown):
    if os.geteuid() != 0:
        _write_status(layout, {"state": "error", "last_error": "root_required"}, chown=chown)
        return 2
    saved = _read_status_file(layout)
    try:
        gid = int(saved["gid"])
    except (KeyError, TypeError, ValueError):
        _write_status(layout, {"state": "error", "last_error": "audit_gid_missing"}, chown=chown)
        return 2
    counters = {
        "gid": gid,
        "events_written": int(saved.get("events_written") or 0),
        "parse_errors": int(saved.get("parse_errors") or 0),
        "schema_versions": list(saved.get("schema_versions") or [])[:16],
    }
    stopped = False
    child = None
    stderr_lines = deque(maxlen=20)

    def request_stop(signum, frame):
        nonlocal stopped
        stopped = True
        if child is not None and child.poll() is None:
            child.terminate()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        child = popen(
            [str(layout.eslogger_path), "--format", "json", "exec"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        _write_status(layout, {**counters, "state": "error", "last_error": f"eslogger_start_failed:{exc}"}, chown=chown)
        return 2
    assert child.stderr is not None

    def drain_stderr():
        for stderr_line in child.stderr:
            stderr_lines.append(stderr_line.rstrip()[:400])

    stderr_thread = threading.Thread(target=drain_stderr, name="privoxy-audit-stderr", daemon=True)
    stderr_thread.start()
    _write_status(layout, {
        **counters,
        "state": "running",
        "started_at": _now(),
        "pid": os.getpid(),
        "eslogger_pid": child.pid,
        "last_error": "",
    }, chown=chown)

    assert child.stdout is not None
    for line in child.stdout:
        if stopped:
            break
        try:
            event = json.loads(line)
        except ValueError:
            counters["parse_errors"] += 1
            if counters["parse_errors"] == 1 or counters["parse_errors"] % 100 == 0:
                _write_status(layout, {**counters, "state": "degraded", "last_error": "eslogger_json_parse_error"}, chown=chown)
            continue
        if not _event_shape_valid(event):
            counters["parse_errors"] += 1
            if counters["parse_errors"] == 1 or counters["parse_errors"] % 100 == 0:
                _write_status(layout, {
                    **counters,
                    "state": "degraded",
                    "last_error": "eslogger_schema_changed",
                }, chown=chown)
            continue
        schema_version = event.get("schema_version")
        if schema_version not in counters["schema_versions"]:
            counters["schema_versions"].append(schema_version)
            counters["schema_versions"] = counters["schema_versions"][-16:]
        record = normalize_event(event)
        if record is None:
            continue
        if not _append_event(layout, record, gid=gid, chown=chown):
            _write_status(layout, {**counters, "state": "error", "last_error": "audit_log_write_failed"}, chown=chown)
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
            return 2
        counters["events_written"] += 1
        _write_status(layout, {
            **counters,
            "state": "running",
            "last_event_at": record["captured_at"],
            "last_error": "",
        }, chown=chown)

    rc = child.wait()
    stderr_thread.join(timeout=1)
    if stopped:
        _write_status(layout, {**counters, "state": "stopped", "stopped_at": _now(), "last_error": ""}, chown=chown)
        return 0
    stderr = " | ".join(stderr_lines)[-1200:]
    error = f"eslogger_exited:{rc}:{stderr}"
    _write_status(layout, {**counters, "state": "error", "last_error": error}, chown=chown)
    return 2


def _sudo_reset(runner):
    return runner([SUDO, "-k"], 5)


def _parse_helper_output(result):
    for line in reversed((result.get("out") or "").splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and "ok" in value:
            return value
    return _result(False, error=(result.get("err") or result.get("out") or "helper_failed")[:240])


def _install_helper(runner, layout=DEFAULT_LAYOUT):
    source = Path(__file__).resolve()
    if not _managed_file(source, HELPER_MARKER):
        return _result(False, error="audit_helper_source_marker_missing")
    if layout.helper_path.exists() and not _secure_managed_file(
            layout.helper_path, HELPER_MARKER, expected_uid=0, executable=True):
        return _result(False, error="foreign_audit_helper")
    if layout.launchdaemon_path.exists() and not _secure_managed_file(
            layout.launchdaemon_path, AUDIT_MARKER, expected_uid=0):
        return _result(False, error="foreign_audit_launchdaemon")
    parent = runner([SUDO, MKDIR, "-p", str(layout.helper_path.parent)], 30)
    if parent.get("rc") != 0:
        return _result(False, error=(parent.get("err") or "audit_helper_parent_failed")[:240])
    installed = runner([
        SUDO, INSTALL, "-o", "root", "-g", "wheel", "-m", "0755",
        str(source), str(layout.helper_path),
    ], 30)
    if installed.get("rc") != 0:
        return _result(False, error=(installed.get("err") or "audit_helper_install_failed")[:240])
    return _result(True)


def install(*, runner=None, require_tty=True, layout=DEFAULT_LAYOUT):
    if runner is None:
        from sys_probe import run as runner
    if require_tty and not sys.stdin.isatty():
        return _result(False, error="interactive_terminal_required")
    identity = pwd.getpwuid(os.getuid())
    _sudo_reset(runner)
    installed = _install_helper(runner, layout)
    if not installed["ok"]:
        _sudo_reset(runner)
        return installed
    # Не оставляем окно с действующим sudo timestamp между копированием helper и его запуском.
    _sudo_reset(runner)
    invoked = runner([
        SUDO, str(layout.helper_path), "install",
        "--username", identity.pw_name,
        "--uid", str(identity.pw_uid),
        "--gid", str(identity.pw_gid),
    ], 60)
    _sudo_reset(runner)
    outcome = _parse_helper_output(invoked)
    outcome["status"] = status(runner=runner, layout=layout)
    return outcome


def uninstall(*, purge_log=False, runner=None, require_tty=True, layout=DEFAULT_LAYOUT):
    if runner is None:
        from sys_probe import run as runner
    if require_tty and not sys.stdin.isatty():
        return _result(False, error="interactive_terminal_required")
    if not _managed_file(layout.helper_path, HELPER_MARKER):
        if layout.helper_path.exists():
            return _result(False, error="foreign_audit_helper")
        return _result(True, changed=False, log_preserved=layout.event_log_path.exists())
    _sudo_reset(runner)
    cmd = [SUDO, str(layout.helper_path), "uninstall"]
    if purge_log:
        cmd.append("--purge-log")
    invoked = runner(cmd, 60)
    _sudo_reset(runner)
    return _parse_helper_output(invoked)


def helper_main(argv=None):
    parser = argparse.ArgumentParser(prog="com.srouter.privoxyaudit")
    sub = parser.add_subparsers(dest="command", required=True)
    install_parser = sub.add_parser("install")
    install_parser.add_argument("--username", required=True)
    install_parser.add_argument("--uid", required=True, type=int)
    install_parser.add_argument("--gid", required=True, type=int)
    uninstall_parser = sub.add_parser("uninstall")
    uninstall_parser.add_argument("--purge-log", action="store_true")
    sub.add_parser("daemon")
    args = parser.parse_args(argv)

    if args.command == "install":
        outcome = install_as_root(username=args.username, uid=args.uid, gid=args.gid)
        print(json.dumps(outcome, ensure_ascii=False, separators=(",", ":")))
        return 0 if outcome.get("ok") else 2
    if args.command == "uninstall":
        outcome = uninstall_as_root(purge_log=args.purge_log)
        print(json.dumps(outcome, ensure_ascii=False, separators=(",", ":")))
        return 0 if outcome.get("ok") else 2
    return daemon()


if __name__ == "__main__":
    raise SystemExit(helper_main())
