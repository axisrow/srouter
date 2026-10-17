"""Исходные пользовательские файлы: история в srouter.local.json, без отдельного state."""
import base64
import ctypes
import hashlib
import json
import os
import stat
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

import local_state


def _darwin_xattrs(path, wanted=None):
    """Darwin не предоставляет os.*xattr; NOFOLLOW сохраняет саму ссылку."""
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    lib.listxattr.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    lib.listxattr.restype = ctypes.c_ssize_t
    lib.getxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t,
                             ctypes.c_uint32, ctypes.c_int]
    lib.getxattr.restype = ctypes.c_ssize_t
    lib.setxattr.argtypes = lib.getxattr.argtypes
    lib.removexattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    encoded = os.fsencode(path)

    def checked(result):
        if result < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), str(path))
        return result

    size = checked(lib.listxattr(encoded, None, 0, 1))
    buffer = ctypes.create_string_buffer(size or 1)
    count = checked(lib.listxattr(encoded, buffer, size, 1))
    names = [os.fsdecode(name) for name in buffer.raw[:count].split(b"\0") if name]
    if wanted is None:
        attributes = {}
        for name in names:
            size = checked(lib.getxattr(encoded, os.fsencode(name), None, 0, 0, 1))
            buffer = ctypes.create_string_buffer(size or 1)
            count = checked(lib.getxattr(encoded, os.fsencode(name), buffer, size, 0, 1))
            attributes[name] = base64.b64encode(buffer.raw[:count]).decode("ascii")
        return attributes
    if not isinstance(wanted, dict):
        raise OSError("file_xattrs_invalid")
    for name in names:
        if name not in wanted:
            checked(lib.removexattr(encoded, os.fsencode(name), 1))
    for name, value in wanted.items():
        data = base64.b64decode(value, validate=True)
        checked(lib.setxattr(encoded, os.fsencode(name), data, len(data), 0, 1))


def _darwin_acl(path, text=None):
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    lib.acl_get_link_np.argtypes = [ctypes.c_char_p, ctypes.c_int]
    lib.acl_get_link_np.restype = ctypes.c_void_p
    lib.acl_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
    lib.acl_to_text.restype = ctypes.c_void_p
    lib.acl_from_text.argtypes = [ctypes.c_char_p]
    lib.acl_from_text.restype = ctypes.c_void_p
    lib.acl_init.argtypes = [ctypes.c_int]
    lib.acl_init.restype = ctypes.c_void_p
    lib.acl_set_link_np.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
    lib.acl_free.argtypes = [ctypes.c_void_p]
    acl = (lib.acl_get_link_np(os.fsencode(path), 0x100) if text is None else
           lib.acl_from_text(text.encode("utf-8")) if text else lib.acl_init(0))
    if not acl:
        error = ctypes.get_errno()
        # Darwin сообщает ENOENT и для существующего файла без расширенного ACL.
        if text is None and error == 2 and path.exists():
            return ""
        raise OSError(error, os.strerror(error), str(path))
    try:
        if text is not None:
            if lib.acl_set_link_np(os.fsencode(path), 0x100, acl) != 0:
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error), str(path))
            return
        size = ctypes.c_ssize_t()
        value = lib.acl_to_text(acl, ctypes.byref(size))
        if not value:
            raise OSError("acl_read_failed")
        try:
            return ctypes.string_at(value, size.value).decode("utf-8")
        finally:
            lib.acl_free(value)
    finally:
        lib.acl_free(acl)


def file_metadata(path):
    info = path.lstat()
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
        raise OSError(f"необычный тип файла: {path}")
    result = {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}
    if path.is_symlink():
        result["link"] = os.readlink(path)
    if sys.platform == "darwin":
        result["xattrs"] = _darwin_xattrs(path)
    elif hasattr(os, "listxattr"):
        result["xattrs"] = {name: base64.b64encode(os.getxattr(path, name, follow_symlinks=False)).decode("ascii")
                            for name in sorted(os.listxattr(path, follow_symlinks=False))}
    if sys.platform == "darwin" and not path.is_symlink():
        result["acl"] = _darwin_acl(path)
    return result


def _snapshot(path):
    try:
        result = file_metadata(path)
    except FileNotFoundError:
        if path.exists() or path.is_symlink():
            raise OSError(f"метаданные файла не прочитаны: {path}")
        return None
    if "link" not in result:
        if path.stat().st_size > 2 * 1024 * 1024:
            raise OSError(f"слишком большой файл для истории установки: {path}")
        result["data"] = base64.b64encode(path.read_bytes()).decode("ascii")
    return result


def _digest(snapshot):
    return hashlib.sha256(json.dumps(snapshot, sort_keys=True).encode()).hexdigest()


def _history(env):
    state, readable = local_state.load_state_checked(path=env.state_path)
    if not readable:
        raise OSError("state_unreadable")
    detected = state.setdefault("detected_environment", {})
    if not isinstance(detected, dict):
        raise OSError("detected_environment_invalid")
    history = detected.setdefault("install_files", {})
    if not isinstance(history, dict):
        raise OSError("install_files_invalid")
    return state, history


def _save(env, state):
    if local_state.save_state(state, path=env.state_path) is None:
        raise OSError("state_write_failed")


def capture_install_files(env, paths):
    state, history = _history(env)
    for path in map(Path, paths):
        key = str(path.absolute())
        if key not in history:
            history[key] = {"previous": _snapshot(path)}
    _save(env, state)


def record_install_files(env, paths):
    state, history = _history(env)
    for path in map(Path, paths):
        history[str(path.absolute())]["applied"] = _digest(_snapshot(path))
    _save(env, state)


def _restore_ppp(previous, runner):
    from privileged_ops import build_osascript
    target = "/etc/ppp/ip-up"
    stage = f"/etc/ppp/.srouter-ip-up-restore-{os.getpid()}"
    with tempfile.TemporaryDirectory(prefix="srouter-ppp-restore-") as directory:
        if previous is None:
            command = f"/bin/rm -f {target}"
        else:
            source = Path(directory) / "original"
            if "link" in previous:
                source.symlink_to(previous["link"])
            else:
                source.write_bytes(base64.b64decode(previous["data"], validate=True))
            _restore_metadata(source, previous)
            command = (f"/bin/cp -Pp {shlex.quote(str(source))} {stage} && "
                       f"/usr/sbin/chown -h {previous['uid']}:{previous['gid']} {stage} && "
                       + (f"/bin/chmod {previous['mode']:o} {stage} && " if "link" not in previous else "")
                       + f"/bin/mv -fh {stage} {target}")
        result = runner(build_osascript(["/bin/sh", "-c", command]), 60)
        if result.get("timeout") or result.get("rc") != 0:
            raise OSError("ppp_restore_failed")


def _restore_metadata(path, previous):
    if not path.is_symlink():
        path.chmod(previous["mode"])
    if sys.platform == "darwin":
        _darwin_xattrs(path, previous.get("xattrs", {}))
    elif hasattr(os, "listxattr"):
        wanted = previous.get("xattrs", {})
        for name in os.listxattr(path, follow_symlinks=False):
            if name not in wanted:
                os.removexattr(path, name, follow_symlinks=False)
        for name, value in wanted.items():
            os.setxattr(path, name, base64.b64decode(value, validate=True), follow_symlinks=False)
    if sys.platform == "darwin" and not path.is_symlink():
        acl = previous.get("acl")
        if not isinstance(acl, str):
            raise OSError("file_acl_invalid")
        _darwin_acl(path, acl)


def _restore(path, previous, runner=None):
    if previous is not None:
        if not isinstance(previous, dict) or not all(type(previous.get(k)) is int for k in ("mode", "uid", "gid")):
            raise OSError("file_backup_invalid")
        if not 0 <= previous["mode"] <= 0o7777 or min(previous["uid"], previous["gid"]) < 0:
            raise OSError("file_backup_invalid")
    if str(path) == "/etc/ppp/ip-up":
        if runner is None:
            raise OSError("ppp_privileged_runner_required")
        _restore_ppp(previous, runner)
        return
    if previous is None:
        path.unlink(missing_ok=True)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    # Private staging directory keeps both regular files and restored symlinks atomic.
    with tempfile.TemporaryDirectory(prefix=".srouter-restore-", dir=path.parent) as staging:
        target = Path(staging) / "original"
        if "link" in previous:
            os.symlink(previous["link"], target)
        else:
            target.write_bytes(base64.b64decode(previous["data"], validate=True))
        info = target.lstat()
        if (info.st_uid, info.st_gid) != (previous["uid"], previous["gid"]):
            os.chown(target, previous["uid"], previous["gid"], follow_symlinks=False)
        _restore_metadata(target, previous)
        target.replace(path)


def restore_install_files(env, paths, *, mixed=(), runner=None):
    """Only caller-supplied paths are writable; paths from JSON never expand the scope."""
    state, history = _history(env)
    mixed = {str(Path(p).absolute()) for p in mixed}
    handled, fallback, blocked, errors = [], [], [], []
    for path in map(Path, paths):
        key = str(path.absolute())
        if key not in history:
            continue
        try:
            entry = history[key]
            if not isinstance(entry, dict) or "previous" not in entry:
                raise OSError("file_backup_invalid")
            current = _digest(_snapshot(path))
            original = _digest(entry["previous"])
            if current in (original, entry.get("applied")):
                if current != original:
                    _restore(path, entry["previous"], runner)
                if _digest(_snapshot(path)) != original:
                    raise OSError("file_restore_unverified")
                handled.append(key)
            elif key in mixed and entry.get("applied"):
                # Mixed files have existing field/block-aware cleaners; keep later foreign edits.
                fallback.append(key)
            else:
                raise OSError("файл изменён после установки; оставлен для ручного разбора")
        except (OSError, ValueError, TypeError, KeyError) as exc:
            blocked.append(key)
            errors.append(f"{path}: {exc}")
    return {"ok": not errors, "handled": handled, "fallback": fallback, "blocked": blocked, "errors": errors}


def finish_file_restore(env, paths):
    if not paths:
        return
    state, history = _history(env)
    for path in paths:
        history.pop(str(Path(path).absolute()), None)
    _save(env, state)
