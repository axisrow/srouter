import json
import os
from pathlib import Path
import plistlib
import pwd
import subprocess

import pytest
import dashboard
import health
import install_lib
import local_state
import privoxy_system
import srouter


def _layout(tmp_path):
    system = tmp_path / "system"
    return privoxy_system.ProtectedLayout(
        helper_path=system / "helpers" / "com.srouter.privoxyctl",
        launchdaemon_path=system / "LaunchDaemons" / "com.srouter.privoxy.plist",
        config_dir=system / "config",
        config_path=system / "config" / "config",
        templates_dir=system / "config" / "templates",
        manifest_path=system / "config" / "manifest.json",
        backup_root=system / "backups",
        log_dir=system / "logs",
        stdout_path=system / "logs" / "stdout.log",
        stderr_path=system / "logs" / "stderr.log",
        sudoers_path=system / "sudoers.d" / "srouter-privoxy-no-cache",
    )


def _write_state(path, privoxy=None):
    data = {
        "schema_version": 1,
        "nodes": [],
        "active_node": {"name": None, "pending": None},
        "probes": {},
        "network": {},
        "traffic_guard": {"mode": "off", "domains": {}},
        "detected_environment": {"privoxy": privoxy},
        "runtime": {"last_apply": None, "last_error": None},
    }
    path.write_text(json.dumps(data), encoding="utf-8")


def _fake_prefix(tmp_path):
    prefix = tmp_path / "homebrew"
    binary = prefix / "opt" / "privoxy" / "sbin" / "privoxy"
    binary.parent.mkdir(parents=True)
    binary.write_text("fake", encoding="utf-8")
    binary.chmod(0o755)
    templates = prefix / "etc" / "privoxy" / "templates"
    templates.mkdir(parents=True)
    (templates / "default").write_text("template", encoding="utf-8")
    libraries = prefix / "opt" / "pcre2" / "lib"
    libraries.mkdir(parents=True)
    (libraries / "libpcre2-8.0.dylib").write_text("fake", encoding="utf-8")
    (libraries / "libpcre2-posix.3.dylib").write_text("fake", encoding="utf-8")
    return prefix


def test_protected_config_and_plist_are_strict_and_loopback_only(tmp_path):
    layout = _layout(tmp_path)
    config = privoxy_system.protected_config_text(layout)

    assert privoxy_system.validate_protected_config(config, layout)["ok"] is True
    assert "listen-address 127.0.0.1:8118" in config
    assert "forward-socks5t / 127.0.0.1:10808 ." in config
    assert "enable-edit-actions 0" in config

    plist = plistlib.loads(privoxy_system.launchdaemon_bytes("/opt/homebrew", layout))
    assert plist["Label"] == privoxy_system.SYSTEM_LABEL
    assert plist["UserName"] == "nobody"
    assert plist["GroupName"] == "nobody"
    assert plist["KeepAlive"] is True
    assert plist["ProgramArguments"] == [
        str(layout.binary_path),
        "--no-daemon",
        str(layout.config_path),
    ]


def test_config_validation_rejects_extra_or_changed_directive(tmp_path):
    layout = _layout(tmp_path)
    config = privoxy_system.protected_config_text(layout)

    extra = privoxy_system.validate_protected_config(config + "debug 1\n", layout)
    changed = privoxy_system.validate_protected_config(
        config.replace("listen-address 127.0.0.1:8118", "listen-address 0.0.0.0:8118"),
        layout,
    )

    assert extra["ok"] is False
    assert extra["unexpected"] == ["debug"]
    assert changed["ok"] is False
    assert changed["changed"] == ["listen-address"]


def test_installed_privoxy_accepts_protected_config(tmp_path):
    binary = Path("/opt/homebrew/opt/privoxy/sbin/privoxy")
    if not binary.is_file():
        pytest.skip("Homebrew privoxy is not installed")
    layout = _layout(tmp_path)
    layout.config_dir.mkdir(parents=True)
    layout.templates_dir.mkdir()
    layout.log_dir.mkdir(parents=True)
    layout.config_path.write_text(privoxy_system.protected_config_text(layout), encoding="utf-8")

    result = subprocess.run(
        [str(binary), "--config-test", str(layout.config_path)],
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr or result.stdout


def test_protected_runtime_is_independent_from_user_owned_homebrew_files(tmp_path):
    prefix = Path("/opt/homebrew")
    binary = prefix / "opt" / "privoxy" / "sbin" / "privoxy"
    required_tools = [
        Path(privoxy_system.OTOOL),
        Path(privoxy_system.INSTALL_NAME_TOOL),
        Path(privoxy_system.CODESIGN),
    ]
    if not binary.is_file() or any(not path.is_file() for path in required_tools):
        pytest.skip("Homebrew Privoxy or macOS binary tools are not available")

    layout = _layout(tmp_path)
    layout.config_dir.mkdir(parents=True)
    layout.templates_dir.mkdir()
    layout.log_dir.mkdir(parents=True)
    layout.config_path.write_text(privoxy_system.protected_config_text(layout), encoding="utf-8")

    installed = privoxy_system._install_runtime(
        binary,
        str(prefix),
        layout,
        runner=privoxy_system._run,
        chown=lambda path, uid, gid: None,
    )

    assert installed["ok"] is True, installed["error"]
    for path in (
        layout.binary_path,
        layout.lib_dir / "libpcre2-8.0.dylib",
        layout.lib_dir / "libpcre2-posix.3.dylib",
    ):
        dependencies = privoxy_system._otool_dependencies(path)
        assert dependencies["ok"] is True
        assert not any(
            item.startswith(("/opt/homebrew/", "/usr/local/"))
            for item in dependencies["dependencies"]
        )

    checked = subprocess.run(
        [str(layout.binary_path), "--config-test", str(layout.config_path)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert checked.returncode == 0, checked.stderr or checked.stdout


def test_macos_visudo_accepts_strict_no_cache_rule(tmp_path):
    visudo = Path(privoxy_system.VISUDO)
    if not visudo.is_file():
        pytest.skip("visudo is not available")
    candidate = tmp_path / "sudoers"
    candidate.write_text(
        privoxy_system._sudoers_text(pwd.getpwuid(os.getuid()).pw_name),
        encoding="utf-8",
    )
    candidate.chmod(0o440)

    result = subprocess.run(
        [str(visudo), "-cf", str(candidate)],
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr or result.stdout


def test_staged_config_rejects_symlink_and_group_writable_file(tmp_path):
    layout = _layout(tmp_path)
    real = tmp_path / "config"
    real.write_text(privoxy_system.protected_config_text(layout), encoding="utf-8")
    real.chmod(0o620)
    link = tmp_path / "link"
    link.symlink_to(real)

    assert privoxy_system._safe_staged_config(real, os.getuid(), layout)["error"] == \
        "staged_config_writable_by_others"
    assert privoxy_system._safe_staged_config(link, os.getuid(), layout)["error"] == \
        "staged_config_not_regular"


def test_backup_existing_refuses_to_follow_symlink(tmp_path):
    """Finding #2 (Codex, critical): symlink TOCTOU через user_plist backup.

    user_plist (~/Library/LaunchAgents/homebrew.mxcl.privoxy.plist) полностью под контролем
    непривилегированного пользователя до sudo-подтверждения. Если это symlink на произвольный
    root-only секрет, root-процесс не должен читать его содержимое — иначе последующий
    `unprotect --restore` запишет секрет пользователю обратно с 0644 (arbitrary file disclosure).
    """
    secret = tmp_path / "root-only-secret"
    secret.write_text("top-secret-root-content", encoding="utf-8")
    link = tmp_path / "homebrew.mxcl.privoxy.plist"
    link.symlink_to(secret)
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()

    with pytest.raises(RuntimeError, match="backup_source_not_regular"):
        privoxy_system._backup_existing(link, backup_dir, "user-launchagent.plist")

    assert list(backup_dir.iterdir()) == []


def test_read_regular_nofollow_race_free_against_toctou_swap(tmp_path):
    """Cycle-2 Finding B (Codex, critical): lstat-затем-copy2 оставляла TOCTOU-окно.

    Между проверкой (lstat) и использованием (copy2) атакующий мог подменить regular-file
    на symlink к root-only секрету — copy2(follow_symlinks=False) скопировал бы сам symlink,
    а _restore_file (Path.is_file()/read_bytes(), СЛЕДУЮЩИЕ symlink) прочитали бы секрет при
    restore. _read_regular_nofollow обязана открывать путь с O_NOFOLLOW — единственный способ
    закрыть race: open() и есть та же операция, что и проверка "не symlink".
    """
    secret = tmp_path / "root-only-secret"
    secret.write_text("top-secret-root-content", encoding="utf-8")
    # Симулируем состояние ПОСЛЕ TOCTOU-подмены: путь, ожидаемый как regular file,
    # на самом деле уже symlink на секрет к моменту чтения.
    swapped = tmp_path / "user_plist_after_swap"
    swapped.symlink_to(secret)

    # O_NOFOLLOW провалит сам open() (ELOOP) — check и use это один и тот же syscall,
    # окна для подмены между ними не существует.
    with pytest.raises(RuntimeError, match="backup_source_open_failed"):
        privoxy_system._read_regular_nofollow(swapped)


def test_restore_file_refuses_symlink_backup(tmp_path):
    """_restore_file больше не использует Path.is_file()/read_bytes() (следуют symlink).

    Если backup-путь сам оказался symlink (например из-за race при создании backup),
    restore обязан отказаться, а не прочитать содержимое цели symlink через root-путь.
    """
    secret = tmp_path / "root-only-secret"
    secret.write_text("top-secret-root-content", encoding="utf-8")
    fake_backup = tmp_path / "backup-that-is-actually-a-symlink"
    fake_backup.symlink_to(secret)
    target = tmp_path / "restored-user-plist"

    result = privoxy_system._restore_file(
        str(fake_backup), target, uid=os.getuid(), gid=os.getgid(), mode=0o644,
        chown=lambda path, uid, gid: None,
    )

    assert result is False
    assert not target.exists()


def test_copy_templates_refuses_symlink_inside_source_tree(tmp_path, monkeypatch):
    """Cycle-2 Finding A (Codex, critical): copytree(symlinks=False) разыменовывает

    symlink ВНУТРИ дерева и материализует содержимое его цели как обычный файл. templates_dir
    берётся из user-writable Homebrew prefix — symlink на root-only секрет внутри templates/
    привёл бы к раскрытию его содержимого как root-owned world-readable (0644) файла.
    """
    source = tmp_path / "templates"
    source.mkdir()
    (source / "default").write_text("normal template", encoding="utf-8")
    secret = tmp_path / "root-only-secret"
    secret.write_text("top-secret-root-content", encoding="utf-8")
    (source / "sneaky-symlink").symlink_to(secret)

    target = tmp_path / "protected-templates"

    ok = privoxy_system._copy_templates(source, target, chown=lambda path, uid, gid: None)

    assert ok is False
    assert not target.exists()


def test_reject_symlinks_in_tree_accepts_clean_tree(tmp_path):
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "default").write_text("template", encoding="utf-8")
    (clean / "subdir").mkdir()
    (clean / "subdir" / "nested").write_text("nested", encoding="utf-8")

    privoxy_system._reject_symlinks_in_tree(clean)  # не должно бросить


def test_root_transaction_refuses_protect_when_user_plist_is_symlink_to_secret(tmp_path, monkeypatch):
    """End-to-end: protect_as_root не должен раскрыть содержимое чужого root-only файла,

    если пользователь заранее подменил свой LaunchAgent-plist на symlink к секрету.
    """
    layout = _layout(tmp_path)
    prefix = _fake_prefix(tmp_path)
    identity = pwd.getpwuid(os.getuid())
    home = tmp_path / "home"
    home.mkdir()
    secret = tmp_path / "etc-master-passwd-stand-in"
    secret.write_text("root:only:secret:content", encoding="utf-8")
    user_plist = home / "Library" / "LaunchAgents" / f"{privoxy_system.USER_LABEL}.plist"
    user_plist.parent.mkdir(parents=True)
    user_plist.symlink_to(secret)
    staged = tmp_path / "staged"
    staged.write_text(privoxy_system.protected_config_text(layout), encoding="utf-8")
    staged.chmod(0o600)
    monkeypatch.setattr(privoxy_system, "_allowed_prefix", lambda value: str(value))

    def runner(cmd, timeout):
        if cmd[:2] == [privoxy_system.LAUNCHCTL, "print"]:
            return {"rc": 0, "out": "loaded", "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    result = privoxy_system.protect_as_root(
        username=identity.pw_name,
        uid=identity.pw_uid,
        prefix=str(prefix),
        staged_config=staged,
        layout=layout,
        runner=runner,
        checker=lambda: True,
        chown=lambda path, uid, gid: None,
        enforce_root=False,
        user_home=home,
    )

    assert result["ok"] is False
    assert "backup_source_not_regular" in result["error"]
    # Секрет НЕ должен был попасть ни в один файл под backup_root.
    for backed_up in layout.backup_root.rglob("*"):
        if backed_up.is_file():
            assert "root:only:secret:content" not in backed_up.read_text(encoding="utf-8")


def test_root_transaction_migrates_and_restores_user_service(tmp_path, monkeypatch):
    layout = _layout(tmp_path)
    prefix = _fake_prefix(tmp_path)
    identity = pwd.getpwuid(os.getuid())
    home = tmp_path / "home"
    user_plist = home / "Library" / "LaunchAgents" / f"{privoxy_system.USER_LABEL}.plist"
    user_plist.parent.mkdir(parents=True)
    original_plist = b"<plist><dict><key>Label</key><string>homebrew.mxcl.privoxy</string></dict></plist>"
    user_plist.write_bytes(original_plist)
    staged = tmp_path / "staged-config"
    staged.write_text(privoxy_system.protected_config_text(layout), encoding="utf-8")
    staged.chmod(0o600)
    monkeypatch.setattr(privoxy_system, "_allowed_prefix", lambda value: str(value))

    lifecycle = {"user": True, "system": False, "port": True}
    calls = []

    def runner(cmd, timeout):
        calls.append(cmd)
        if cmd[:2] == [privoxy_system.LAUNCHCTL, "print"]:
            target = cmd[2]
            loaded = lifecycle["system"] if target.startswith("system/") else lifecycle["user"]
            return {"rc": 0 if loaded else 113,
                    "out": f"{target} = {{\n state = running\n pid = 4242\n}}" if loaded else "",
                    "err": "" if loaded else "not found", "timeout": False}
        if cmd[:2] == [privoxy_system.LAUNCHCTL, "bootout"]:
            target = cmd[2]
            if target.startswith("system/"):
                lifecycle["system"] = False
            else:
                lifecycle["user"] = False
            lifecycle["port"] = False
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        if cmd[:2] == [privoxy_system.LAUNCHCTL, "bootstrap"]:
            if cmd[2] == "system":
                lifecycle["system"] = True
            else:
                lifecycle["user"] = True
            lifecycle["port"] = True
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        if cmd[0] == privoxy_system.PS:
            return {"rc": 0, "out": "nobody", "err": "", "timeout": False}
        return {"rc": 0, "out": "ok", "err": "", "timeout": False}

    def no_chown(path, uid, gid):
        return None

    def config_test_runner(cmd, timeout):
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    result = privoxy_system.protect_as_root(
        username=identity.pw_name,
        uid=identity.pw_uid,
        prefix=str(prefix),
        staged_config=staged,
        layout=layout,
        runner=runner,
        checker=lambda: lifecycle["port"],
        chown=no_chown,
        enforce_root=False,
        user_home=home,
        config_test_runner=config_test_runner,
    )

    assert result["ok"] is True
    assert lifecycle == {"user": False, "system": True, "port": True}
    assert not user_plist.exists()
    assert privoxy_system.protection_present(layout) is True
    assert json.loads(layout.manifest_path.read_text())["user_loaded"] is True
    assert [privoxy_system.LAUNCHCTL, "bootstrap", "system", str(layout.launchdaemon_path)] in calls

    # Пока protection был активен, агент мог создать новую user-службу с тем же label. Откат обязан
    # выгрузить её и восстановить точную plist из backup, а не принять shadow за прежний сервис.
    user_plist.write_text("shadow", encoding="utf-8")
    lifecycle["user"] = True
    restored = privoxy_system.unprotect_as_root(
        restore=True,
        layout=layout,
        runner=runner,
        checker=lambda: lifecycle["port"],
        chown=no_chown,
        enforce_root=False,
    )

    assert restored["ok"] is True
    assert restored["restored"] is True
    assert lifecycle == {"user": True, "system": False, "port": True}
    assert user_plist.read_bytes() == original_plist
    assert not layout.launchdaemon_path.exists()
    assert not layout.sudoers_path.exists()
    assert [privoxy_system.LAUNCHCTL, "bootout", f"gui/{identity.pw_uid}/{privoxy_system.USER_LABEL}"] in calls


def test_unprotect_refuses_new_user_shadow_without_original_backup(tmp_path):
    layout = _layout(tmp_path)
    identity = pwd.getpwuid(os.getuid())
    home = tmp_path / "home"
    user_plist = home / "Library" / "LaunchAgents" / f"{privoxy_system.USER_LABEL}.plist"
    user_plist.parent.mkdir(parents=True)
    user_plist.write_text("shadow", encoding="utf-8")

    layout.config_path.parent.mkdir(parents=True)
    layout.config_path.write_text(privoxy_system.protected_config_text(layout), encoding="utf-8")
    layout.launchdaemon_path.parent.mkdir(parents=True)
    layout.launchdaemon_path.write_bytes(privoxy_system.launchdaemon_bytes(layout=layout))
    layout.sudoers_path.parent.mkdir(parents=True)
    layout.sudoers_path.write_text(privoxy_system._sudoers_text(identity.pw_name), encoding="utf-8")
    layout.manifest_path.write_text(json.dumps({
        "uid": identity.pw_uid,
        "gid": identity.pw_gid,
        "user_plist": str(user_plist),
        "user_plist_backup": "",
    }), encoding="utf-8")
    calls = []

    def runner(cmd, timeout):
        calls.append(cmd)
        if cmd[:2] == [privoxy_system.LAUNCHCTL, "print"]:
            return {"rc": 0, "out": "state = running\npid = 44", "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    result = privoxy_system.unprotect_as_root(
        restore=True,
        layout=layout,
        runner=runner,
        checker=lambda: True,
        chown=lambda path, uid, gid: None,
        enforce_root=False,
    )

    assert result == {"ok": False, "error": "user_privoxy_shadow_drift"}
    assert not any(cmd[:2] == [privoxy_system.LAUNCHCTL, "bootout"] for cmd in calls)
    assert user_plist.read_text(encoding="utf-8") == "shadow"
    assert layout.launchdaemon_path.exists()



def test_root_transaction_rolls_back_before_touching_user_job_on_bad_config_test(tmp_path, monkeypatch):
    layout = _layout(tmp_path)
    prefix = _fake_prefix(tmp_path)
    identity = pwd.getpwuid(os.getuid())
    home = tmp_path / "home"
    user_plist = home / "Library" / "LaunchAgents" / f"{privoxy_system.USER_LABEL}.plist"
    user_plist.parent.mkdir(parents=True)
    user_plist.write_text("<plist/>", encoding="utf-8")
    staged = tmp_path / "staged"
    staged.write_text(privoxy_system.protected_config_text(layout), encoding="utf-8")
    staged.chmod(0o600)
    monkeypatch.setattr(privoxy_system, "_allowed_prefix", lambda value: str(value))

    def runner(cmd, timeout):
        if cmd[:2] == [privoxy_system.LAUNCHCTL, "print"]:
            return {"rc": 0, "out": "loaded", "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    def config_test_runner(cmd, timeout):
        assert cmd[0] == str(layout.binary_path) and cmd[1] == "--config-test"
        return {"rc": 1, "out": "", "err": "invalid", "timeout": False}

    result = privoxy_system.protect_as_root(
        username=identity.pw_name,
        uid=identity.pw_uid,
        prefix=str(prefix),
        staged_config=staged,
        layout=layout,
        runner=runner,
        checker=lambda: True,
        chown=lambda path, uid, gid: None,
        enforce_root=False,
        user_home=home,
        config_test_runner=config_test_runner,
    )

    assert result["ok"] is False
    assert result["error"].startswith("config_test_failed")
    assert user_plist.exists()
    assert not layout.launchdaemon_path.exists()


def test_protect_as_root_runs_config_test_as_nobody_not_root(tmp_path, monkeypatch):
    """Finding #1 (Codex, critical): config-test не должен исполнять скопированный из

    user-writable Homebrew бинарь с правами root — иначе подмена бинаря до легитимного
    `protect --strict` даёт непривилегированному пользователю выполнение кода от root.
    protect_as_root обязан прогонять config-test через изолированный config_test_runner
    (drop privileges к `nobody`), а не через общий root `runner`.
    """
    layout = _layout(tmp_path)
    prefix = _fake_prefix(tmp_path)
    identity = pwd.getpwuid(os.getuid())
    home = tmp_path / "home"
    user_plist = home / "Library" / "LaunchAgents" / f"{privoxy_system.USER_LABEL}.plist"
    user_plist.parent.mkdir(parents=True)
    user_plist.write_bytes(b"<plist/>")
    staged = tmp_path / "staged"
    staged.write_text(privoxy_system.protected_config_text(layout), encoding="utf-8")
    staged.chmod(0o600)
    monkeypatch.setattr(privoxy_system, "_allowed_prefix", lambda value: str(value))

    lifecycle = {"user": True, "system": False, "port": True}

    def root_runner(cmd, timeout):
        # config-test НИКОГДА не должен попадать в привилегированный runner.
        assert not (len(cmd) > 1 and cmd[0] == str(layout.binary_path)
                    and cmd[1] == "--config-test"), \
            "config-test must not run through the root-privileged runner"
        if cmd[:2] == [privoxy_system.LAUNCHCTL, "print"]:
            target = cmd[2]
            loaded = lifecycle["system"] if target.startswith("system/") else lifecycle["user"]
            return {"rc": 0 if loaded else 113,
                    "out": f"{target} = state = running\npid = 4242" if loaded else "",
                    "err": "" if loaded else "not found", "timeout": False}
        if cmd[:2] == [privoxy_system.LAUNCHCTL, "bootout"]:
            target = cmd[2]
            if target.startswith("system/"):
                lifecycle["system"] = False
            else:
                lifecycle["user"] = False
            lifecycle["port"] = False
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        if cmd[:2] == [privoxy_system.LAUNCHCTL, "bootstrap"]:
            if cmd[2] == "system":
                lifecycle["system"] = True
            else:
                lifecycle["user"] = True
            lifecycle["port"] = True
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        if cmd[0] == privoxy_system.PS:
            return {"rc": 0, "out": "nobody", "err": "", "timeout": False}
        return {"rc": 0, "out": "ok", "err": "", "timeout": False}

    calls = []

    def isolated_config_test_runner(cmd, timeout):
        calls.append(cmd)
        assert cmd[0] == str(layout.binary_path) and cmd[1] == "--config-test"
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    result = privoxy_system.protect_as_root(
        username=identity.pw_name,
        uid=identity.pw_uid,
        prefix=str(prefix),
        staged_config=staged,
        layout=layout,
        runner=root_runner,
        checker=lambda: lifecycle["port"],
        chown=lambda path, uid, gid: None,
        enforce_root=False,
        user_home=home,
        config_test_runner=isolated_config_test_runner,
    )

    assert result["ok"] is True
    assert len(calls) == 1


def test_run_as_nobody_drops_privileges_before_exec(monkeypatch):
    """_run_as_nobody обязана дропать euid/egid ДО exec, когда процесс — root."""
    calls = []
    monkeypatch.setattr(privoxy_system.os, "geteuid", lambda: 0)
    monkeypatch.setattr(privoxy_system.os, "setgroups", lambda groups: calls.append(("setgroups", groups)))
    monkeypatch.setattr(privoxy_system.os, "setgid", lambda gid: calls.append(("setgid", gid)))
    monkeypatch.setattr(privoxy_system.os, "setuid", lambda uid: calls.append(("setuid", uid)))

    captured = {}

    def fake_run(cmd, capture_output, text, timeout, preexec_fn):
        captured["preexec_fn"] = preexec_fn
        if preexec_fn is not None:
            preexec_fn()
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr(privoxy_system.subprocess, "run", fake_run)

    result = privoxy_system._run_as_nobody(["/bin/true"], timeout=5)

    assert result["rc"] == 0
    assert captured["preexec_fn"] is not None
    nobody = pwd.getpwnam("nobody")
    assert ("setgid", nobody.pw_gid) in calls
    assert ("setuid", nobody.pw_uid) in calls
    assert calls.index(("setgid", nobody.pw_gid)) < calls.index(("setuid", nobody.pw_uid))


def test_reapply_failure_restores_previous_protected_runtime_and_service(tmp_path, monkeypatch):
    layout = _layout(tmp_path)
    prefix = _fake_prefix(tmp_path)
    identity = pwd.getpwuid(os.getuid())
    home = tmp_path / "home"
    home.mkdir()
    staged = tmp_path / "staged"
    staged.write_text(privoxy_system.protected_config_text(layout), encoding="utf-8")
    staged.chmod(0o600)
    monkeypatch.setattr(privoxy_system, "_allowed_prefix", lambda value: str(value))

    layout.config_dir.mkdir(parents=True)
    old_config = privoxy_system.protected_config_text(layout).replace(
        f"# {privoxy_system.PROTECTED_MARKER}\n",
        f"# {privoxy_system.PROTECTED_MARKER}\n# previous protected config\n",
    )
    layout.config_path.write_text(old_config, encoding="utf-8")
    layout.templates_dir.mkdir()
    (layout.templates_dir / "old-template").write_text("old", encoding="utf-8")
    layout.runtime_dir.mkdir()
    (layout.runtime_dir / "old-runtime").write_text("old", encoding="utf-8")
    old_manifest = b'{"previous":true}\n'
    layout.manifest_path.write_bytes(old_manifest)
    layout.launchdaemon_path.parent.mkdir(parents=True)
    old_plist = privoxy_system.launchdaemon_bytes(layout=layout)
    layout.launchdaemon_path.write_bytes(old_plist)
    layout.sudoers_path.parent.mkdir(parents=True)
    old_sudoers = privoxy_system._sudoers_text(identity.pw_name).encode()
    layout.sudoers_path.write_bytes(old_sudoers)

    lifecycle = {"system": True, "port": True}
    calls = []

    def runner(cmd, timeout):
        calls.append(cmd)
        if cmd[:2] == [privoxy_system.LAUNCHCTL, "print"]:
            if cmd[2].startswith("system/") and lifecycle["system"]:
                return {"rc": 0, "out": "state = running\npid = 9191", "err": "", "timeout": False}
            return {"rc": 113, "out": "", "err": "not found", "timeout": False}
        if cmd[:2] == [privoxy_system.LAUNCHCTL, "bootout"]:
            lifecycle.update(system=False, port=False)
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        if cmd[:2] == [privoxy_system.LAUNCHCTL, "bootstrap"]:
            lifecycle.update(system=True, port=True)
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        return {"rc": 0, "out": "ok", "err": "", "timeout": False}

    def config_test_runner(cmd, timeout):
        return {"rc": 1, "out": "", "err": "new runtime rejected", "timeout": False}

    result = privoxy_system.protect_as_root(
        username=identity.pw_name,
        uid=identity.pw_uid,
        prefix=str(prefix),
        staged_config=staged,
        layout=layout,
        runner=runner,
        checker=lambda: lifecycle["port"],
        chown=lambda path, uid, gid: None,
        enforce_root=False,
        user_home=home,
        config_test_runner=config_test_runner,
    )

    assert result["ok"] is False
    assert result["error"].startswith("config_test_failed")
    assert lifecycle == {"system": True, "port": True}
    assert layout.config_path.read_text(encoding="utf-8") == old_config
    assert (layout.templates_dir / "old-template").read_text(encoding="utf-8") == "old"
    assert (layout.runtime_dir / "old-runtime").read_text(encoding="utf-8") == "old"
    assert layout.manifest_path.read_bytes() == old_manifest
    assert layout.launchdaemon_path.read_bytes() == old_plist
    assert layout.sudoers_path.read_bytes() == old_sudoers
    assert [privoxy_system.LAUNCHCTL, "bootstrap", "system", str(layout.launchdaemon_path)] in calls


def test_status_reads_system_domain_and_reports_nobody_owner(tmp_path):
    layout = _layout(tmp_path)
    layout.launchdaemon_path.parent.mkdir(parents=True)
    layout.launchdaemon_path.write_bytes(privoxy_system.launchdaemon_bytes(layout=layout))
    layout.config_path.parent.mkdir(parents=True)
    layout.config_path.write_text(privoxy_system.protected_config_text(layout), encoding="utf-8")
    calls = []

    def runner(cmd, timeout):
        calls.append(cmd)
        if cmd[:2] == [privoxy_system.LAUNCHCTL, "print"] and cmd[2].startswith("system/"):
            return {"rc": 0, "out": "state = running\npid = 123", "err": "", "timeout": False}
        if cmd[0] == privoxy_system.PS:
            return {"rc": 0, "out": "nobody", "err": "", "timeout": False}
        return {"rc": 113, "out": "", "err": "not found", "timeout": False}

    result = privoxy_system.status(runner=runner, layout=layout)

    assert result["protected"] is True
    assert result["loaded"] is True
    assert result["pid"] == 123
    assert result["owner"] == "nobody"
    assert [privoxy_system.LAUNCHCTL, "print", f"system/{privoxy_system.SYSTEM_LABEL}"] in calls


def test_state_promotion_and_restore_preserve_previous_entry(tmp_path, monkeypatch):
    state_path = tmp_path / "state.json"
    previous = {
        "config_path": "/opt/homebrew/etc/privoxy/config",
        "management": {"mode": "adopted", "managed": False},
    }
    _write_state(state_path, previous)
    assert privoxy_system._write_pending(state_path, previous) is True

    monkeypatch.setattr(privoxy_system, "DEFAULT_LAYOUT", _layout(tmp_path))
    assert privoxy_system._promote_state(state_path, backup_dir="/backup") is True
    protected = local_state.load_state(path=state_path)["detected_environment"]["privoxy"]
    assert protected["protection"]["service_scope"] == "system"
    assert protected["protection"]["previous"] == previous

    assert privoxy_system._write_unprotect_pending(state_path) is True
    pending = local_state.load_state(path=state_path)["runtime"]["privoxy_protection_pending"]
    assert pending["action"] == "unprotect"

    assert privoxy_system._restore_state_after_unprotect(state_path) is True
    restored = local_state.load_state(path=state_path)["detected_environment"]["privoxy"]
    assert restored == previous


def test_post_protect_verification_failure_calls_root_rollback(tmp_path, monkeypatch):
    layout = _layout(tmp_path)
    state_path = tmp_path / "state.json"
    _write_state(state_path, {"service": "homebrew-user"})
    statuses = iter([
        {
            "protected": False,
            "loaded": False,
            "port_up": True,
            "owner": "",
            "config_writable": None,
            "binary_writable": None,
            "assets_writable": False,
        },
        {
            "protected": True,
            "loaded": True,
            "port_up": True,
            "owner": "axisrow",
            "config_writable": False,
            "binary_writable": False,
            "assets_writable": False,
            "user_shadow_loaded": False,
        },
    ])
    monkeypatch.setattr(privoxy_system, "status", lambda **kwargs: next(statuses))
    monkeypatch.setattr(
        privoxy_system,
        "_install_helper",
        lambda runner, selected_layout: {"ok": True, "error": ""},
    )
    calls = []

    def runner(cmd, timeout):
        calls.append(cmd)
        if "protect" in cmd:
            return {"rc": 0, "out": '{"ok":true,"error":"","backup_dir":"/backup"}',
                    "err": "", "timeout": False}
        if "unprotect" in cmd:
            return {"rc": 0, "out": '{"ok":true,"error":"","restored":true}',
                    "err": "", "timeout": False}
        if "-n" in cmd:
            return {"rc": 1, "out": "", "err": "password required", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    result = privoxy_system.protect(
        state_path=state_path,
        runner=runner,
        require_tty=False,
        layout=layout,
    )

    assert result["ok"] is False
    assert result["error"] == "post_protect_verification_failed"
    assert [privoxy_system.SUDO, str(layout.helper_path), "unprotect", "--restore"] in calls
    state = local_state.load_state(path=state_path)
    assert state["runtime"]["privoxy_protection_pending"]["error"] == \
        "post_protect_verification_failed"


def test_protect_rolls_back_when_sudo_cache_survives_timestamp_timeout(tmp_path, monkeypatch):
    """timestamp_timeout=0 — критичный инвариант: `sudo -n` обязан требовать пароль.

    Если кэш всё же сработал (rc=0), protect() должен считать это компрометацией
    strict-режима и откатить protection тем же root-helper'ом, а не оставить систему
    в состоянии, где sudo-cache-bypass остаётся незамеченным.
    """
    layout = _layout(tmp_path)
    state_path = tmp_path / "state.json"
    _write_state(state_path, {"service": "homebrew-user"})
    monkeypatch.setattr(
        privoxy_system, "status", lambda **kwargs: {
            "protected": False, "loaded": False, "port_up": True, "owner": "",
            "config_writable": None, "binary_writable": None, "assets_writable": False,
        }
    )
    monkeypatch.setattr(
        privoxy_system,
        "_install_helper",
        lambda runner, selected_layout: {"ok": True, "error": ""},
    )
    calls = []

    def runner(cmd, timeout):
        calls.append(cmd)
        if "protect" in cmd:
            return {"rc": 0, "out": '{"ok":true,"error":"","backup_dir":"/backup"}',
                    "err": "", "timeout": False}
        if "unprotect" in cmd:
            return {"rc": 0, "out": '{"ok":true,"error":"","restored":true}',
                    "err": "", "timeout": False}
        if "-n" in cmd:
            # Симулируем утечку sudo-кэша вопреки timestamp_timeout=0.
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    result = privoxy_system.protect(
        state_path=state_path,
        runner=runner,
        require_tty=False,
        layout=layout,
    )

    assert result["ok"] is False
    assert result["error"] == "sudo_without_fresh_authorization"
    assert [privoxy_system.SUDO, str(layout.helper_path), "unprotect", "--restore"] in calls
    state = local_state.load_state(path=state_path)
    assert state["runtime"]["privoxy_protection_pending"]["error"] == \
        "sudo_without_fresh_authorization"


def test_build_plan_marks_protected_privoxy_and_never_schedules_brew_restart(tmp_path, monkeypatch):
    state_path = tmp_path / "state.json"
    _write_state(state_path, {
        "protection": {"service_scope": "system", "label": privoxy_system.SYSTEM_LABEL},
    })
    env = install_lib.InstallEnv.from_env(state_path=state_path, prefix=tmp_path / "brew")

    def runner(cmd, timeout):
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    plan = install_lib.build_plan(env=env, runner=runner, port_checker=lambda *a, **kw: False)
    item = plan["components"]["privoxy"]
    assert item["protected"] is True
    assert item["service"] == "protected-system"
    assert item["conflict"] is False


def test_apply_install_preserves_protected_privoxy_without_brew_call(tmp_path):
    state_path = tmp_path / "state.json"
    protected_entry = {
        "config_path": str(privoxy_system.DEFAULT_LAYOUT.config_path),
        "management": {"mode": "managed", "managed": True, "provenance": "protected"},
        "protection": {"service_scope": "system", "label": privoxy_system.SYSTEM_LABEL},
    }
    _write_state(state_path, protected_entry)
    env = install_lib.InstallEnv.from_env(state_path=state_path, prefix=tmp_path / "brew")
    calls = []

    def runner(cmd, timeout):
        calls.append(cmd)
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    result = install_lib.apply_install(
        env=env,
        confirm=True,
        choices={"xray": "skip", "dnsmasq": "skip"},
        runner=runner,
        port_checker=lambda *args, **kwargs: False,
        install_launchagent=False,
    )

    assert result["ok"] is True
    assert {a["component"]: a["mode"] for a in result["actions"]}["privoxy"] == "protected"
    assert not any("privoxy" in cmd and "services" in cmd for cmd in calls)
    after = local_state.load_state(path=state_path)["detected_environment"]["privoxy"]
    assert after["protection"] == protected_entry["protection"]


def test_dashboard_refuses_unprivileged_protected_privoxy_action(monkeypatch):
    monkeypatch.setattr(privoxy_system, "protection_present", lambda: True)
    calls = []
    monkeypatch.setattr(dashboard.sys_probe, "run", lambda cmd, timeout: calls.append(cmd))

    response = dashboard.app.test_client().post("/api/service/privoxy/restart")

    assert response.status_code == 409
    assert response.get_json()["err"].startswith("privoxy_protected")
    assert calls == []


def test_health_lifecycle_switches_privoxy_to_system_domain(monkeypatch):
    calls = []
    monkeypatch.setattr(privoxy_system, "protection_present", lambda: True)
    monkeypatch.setattr(
        health,
        "_launchd_job_snapshot",
        lambda label, **kwargs: calls.append((label, kwargs)) or {"label": label},
    )

    health._collect_launchd_lifecycle()

    assert calls[0][0] == privoxy_system.SYSTEM_LABEL
    assert calls[0][1]["domain"] == "system"
    assert calls[1][0] == "homebrew.mxcl.xray"


def test_health_checks_protected_privoxy_with_loopback_connect_not_lsof(monkeypatch):
    monkeypatch.setattr(privoxy_system, "protection_present", lambda: True)
    calls = []
    monkeypatch.setattr(
        health.sys_probe,
        "port_open",
        lambda host, port, timeout: calls.append((host, port, timeout)) or True,
    )
    monkeypatch.setattr(
        health.sys_probe,
        "run",
        lambda *args, **kwargs: pytest.fail("protected Privoxy must not depend on lsof visibility"),
    )

    assert health._port_up(health.PRIVOXY_PORT) is True
    assert calls == [("127.0.0.1", health.PRIVOXY_PORT, 0.5)]


def test_privoxy_cli_requires_explicit_strict_flag(monkeypatch, capsys):
    called = []
    monkeypatch.setattr(privoxy_system, "protect", lambda **kwargs: called.append(kwargs))

    rc = srouter.main(["privoxy", "protect"])

    assert rc == 2
    assert called == []
    assert "--strict" in capsys.readouterr().err


# ============================ cycle-3 hardening: единый race-free примитив ============================
# 3 вектора одного класса: root копирует/пишет user-controlled пути без race-free примитива.
# Тесты фиксируют ИНВАРИАНТ privileged-boundary-fail-closed (держится после внедрения примитива).


def test_atomic_write_never_writes_through_symlink_in_user_writable_dir(tmp_path):
    """C1: restore user_plist пишет temp-файл в user-writable ~/Library/LaunchAgents.

    Если temp-имя предсказуемо (.name.tmp-PID), атакующий заранее подкладывает symlink с этим
    именем на произвольный root-path → arbitrary root file write. Инвариант: _atomic_write
    создаёт temp эксклюзивно (O_EXCL|O_NOFOLLOW) и/или с непредсказуемым именем (mkstemp) —
    запись НИКОГДА не идёт по чужому symlink. Здесь подкладываем symlink под КАЖДЫЙ возможный
    temp-паттерн и проверяем, что victim не перезаписан.
    """
    target = tmp_path / "user-plist.plist"
    victim = tmp_path / "victim-root-file"
    victim.write_text("original-victim-content", encoding="utf-8")

    # Засеваем директорию symlink'ами под всеми правдоподобными temp-паттернами.
    for planted_name in (
        ".user-plist.plist.tmp",                      # generic prefix
        f".user-plist.plist.tmp-{os.getpid()}",       # PID-based (текущий процесс теста ~= helper)
        ".user-plist.plist.tmp-helper",               # любая явная форма
    ):
        planted = tmp_path / planted_name
        if not planted.exists() and not planted.is_symlink():
            planted.symlink_to(victim)

    privoxy_system._atomic_write(
        target, b"attacker-bytes", mode=0o644, uid=os.getuid(), gid=os.getgid(),
        chown=lambda path, uid, gid: None,
    )

    assert victim.read_text(encoding="utf-8") == "original-victim-content"


def test_atomic_write_replaces_symlink_at_target_without_writing_through_it(tmp_path):
    """C1 (доп): сам target — symlink в user-writable dir.

    write в temp и последующий os.replace(temp, target) должны атомарно ЗАМЕНИТЬ symlink
    regular-файлом, НЕ записав attacker-bytes в symlink-цель (victim).
    """
    victim = tmp_path / "victim-root-file"
    victim.write_text("original-victim-content", encoding="utf-8")
    target = tmp_path / "user-plist.plist"
    target.symlink_to(victim)

    privoxy_system._atomic_write(
        target, b"attacker-bytes", mode=0o644, uid=os.getuid(), gid=os.getgid(),
        chown=lambda path, uid, gid: None,
    )

    assert victim.read_text(encoding="utf-8") == "original-victim-content"


def test_copy_templates_does_not_leak_secret_via_symlink_in_tree(tmp_path):
    """C2: templates-копирование не должно вынести root-only секрет, даже если symlink

    внутри дерева (статичный — для race-варианта отдельный класс-инвариант тот же).
    Содержимое секрета не должно оказаться в защищённой зоне ни при каком исходе.
    """
    secret = tmp_path / "root-only-secret"
    secret.write_text("top-secret-root-content", encoding="utf-8")
    source = tmp_path / "templates"
    source.mkdir()
    (source / "default").write_text("normal template", encoding="utf-8")
    (source / "sneaky").symlink_to(secret)
    target = tmp_path / "protected-templates"

    privoxy_system._copy_templates(source, target, chown=lambda path, uid, gid: None)

    if target.exists():
        for copied in target.rglob("*"):
            if copied.is_file():
                assert copied.read_text(encoding="utf-8") != "top-secret-root-content"


def test_install_runtime_does_not_leak_secret_via_symlink_binary(tmp_path, monkeypatch):
    """C3: _install_runtime копирует Homebrew binary/dylib от root.

    Source-binary как symlink на root-only секрет (без race) → copy2(follow_symlinks=True)
    разыменует и скопирует содержимое как root-owned executable (0755). Инвариант: секрет
    не должен оказаться в runtime_dir ни в каком виде.
    """
    layout = _layout(tmp_path)
    prefix = tmp_path / "homebrew"
    binary_dir = prefix / "opt" / "privoxy" / "sbin"
    binary_dir.mkdir(parents=True)
    secret = tmp_path / "root-only-secret"
    secret.write_text("top-secret-root-content", encoding="utf-8")
    binary_link = binary_dir / "privoxy"
    binary_link.symlink_to(secret)
    binary_link.chmod(0o755)
    templates = prefix / "etc" / "privoxy" / "templates"
    templates.mkdir(parents=True)
    (templates / "default").write_text("template", encoding="utf-8")
    libraries = prefix / "opt" / "pcre2" / "lib"
    libraries.mkdir(parents=True)
    for lib in ("libpcre2-8.0.dylib", "libpcre2-posix.3.dylib"):
        (libraries / lib).write_text("fake-dylib", encoding="utf-8")

    monkeypatch.setattr(privoxy_system, "_allowed_prefix", lambda value: str(value))

    privoxy_system._install_runtime(
        binary_link, str(prefix), layout,
        runner=lambda cmd, timeout: {"rc": 0, "out": "", "err": "", "timeout": False},
        chown=lambda path, uid, gid: None,
    )

    if layout.runtime_dir.exists():
        for copied in layout.runtime_dir.rglob("*"):
            if copied.is_file():
                assert copied.read_text(encoding="utf-8") != "top-secret-root-content"


# ============================ #152: privoxy observability — debug-логирование ============================
# Молчаливый privoxy (config без директивы debug → logfile пуст) — observability-дыра: не поймать
# флап к github через 8118. Канон: more-options-better (env SROUTER_PRIVOXY_DEBUG, не хардкод),
# privacy-no-content-hash-on-disk (дефолт ВЫКЛ), probe-semantics-from-primary-source (уровни debug —
# privoxy user-manual 7.3: 1=URLs чувствительно, 2=connections приватно, 8=non-blocking log).


def test_protected_config_has_no_debug_by_default(tmp_path):
    """Дефолт = молчаливый (privacy): без SROUTER_PRIVOXY_DEBUG директивы debug в конфиге НЕТ.

    На диск не должно идти даже производное контента (privacy-no-content-hash-on-disk).
    """
    layout = _layout(tmp_path)
    config = privoxy_system.protected_config_text(layout)
    assert "debug" not in config
    assert privoxy_system.validate_protected_config(config, layout)["ok"] is True


def test_protected_config_debug_2_writes_connections_level(tmp_path):
    """debug 2 = connections (open/close/timeout) — приватно, без URL/body; ловит флап/таймауты."""
    layout = _layout(tmp_path)
    config = privoxy_system.protected_config_text(layout, debug=2)
    assert "debug 2\n" in config
    assert privoxy_system.validate_protected_config(config, layout, debug=2)["ok"] is True


def test_protected_config_debug_1_only_when_explicit(tmp_path):
    """debug 1 = URLs (чувствительно, токены в query) — только при явном запросе, не дефолт."""
    layout = _layout(tmp_path)
    assert "debug 1\n" not in privoxy_system.protected_config_text(layout)
    assert "debug 1\n" in privoxy_system.protected_config_text(layout, debug=1)


def test_protected_config_debug_8_header_parsing_rejected_for_privacy(tmp_path):
    """debug 8 = show HEADER PARSING (privoxy manual) — ЧУВствительно (auth/cookie заголовки).

    Канон probe-semantics-from-primary-source: privoxy user-manual определяет debug 8 как
    «show header parsing», НЕ «non-blocking log» (это 8192). Header parsing пишет значения
    заголовков на диск → dictionary-атака (privacy-no-content-hash-on-disk). env-whitelist обязан
    отвергать 8 так же, как 32768 (raw-запросы).
    """
    layout = _layout(tmp_path)
    config = privoxy_system.protected_config_text(layout, debug=8)
    directives = privoxy_system._config_directives(config)
    assert "debug" not in directives, "level 8 (header parsing) не должен стать директивой debug"
    assert privoxy_system.validate_protected_config(config, layout)["ok"] is True


def test_validate_protected_config_rejects_debug_level_mismatch(tmp_path):
    """ROOT-side дыра: staged_config с debug=2 должен валидироваться ТОЛЬКО с тем же debug.

    _safe_staged_config валидирует staged_config от root; если он зовёт validate БЕЗ debug,
    а пользователь сгенерировал с debug=2 — корректный конфиг будет отвергнут (unexpected=debug).
    Уровень обязан пройти через privileged-helper (как --prefix).
    """
    layout = _layout(tmp_path)
    staged = privoxy_system.protected_config_text(layout, debug=2)
    # Без указания debug валидатор ждёт конфиг без debug → debug в staged = unexpected.
    assert privoxy_system.validate_protected_config(staged, layout, debug=0)["ok"] is False
    assert privoxy_system.validate_protected_config(staged, layout, debug=2)["ok"] is True


def test_safe_staged_config_threads_debug_level_to_validation(tmp_path):
    """_safe_staged_config (root-сторона) обязан пробросить debug в validate_protected_config."""
    layout = _layout(tmp_path)
    staged = tmp_path / "config"
    staged.write_text(privoxy_system.protected_config_text(layout, debug=2), encoding="utf-8")
    staged.chmod(0o600)

    rejected = privoxy_system._safe_staged_config(staged, os.getuid(), layout, debug=0)
    accepted = privoxy_system._safe_staged_config(staged, os.getuid(), layout, debug=2)

    assert rejected["ok"] is False
    assert accepted["ok"] is True


def test_privoxy_debug_from_env_whitelist_and_default(monkeypatch):
    """SROUTER_PRIVOXY_DEBUG → int из whitelist {1,2}; остальное/пусто/отсутствие/8 → 0 (privacy)."""
    monkeypatch.delenv("SROUTER_PRIVOXY_DEBUG", raising=False)
    assert privoxy_system._privoxy_debug_from_env() == 0

    for raw, expected in [("2", 2), ("1", 1), ("", 0), ("abc", 0), ("-1", 0), ("8", 0)]:
        monkeypatch.setenv("SROUTER_PRIVOXY_DEBUG", raw)
        assert privoxy_system._privoxy_debug_from_env() == expected, raw


def test_privoxy_debug_from_env_rejects_header_parsing_level_8_for_privacy(monkeypatch):
    """debug 8 = header parsing (auth/cookie VALUES на диск) — env НЕ ускоряет его, как 32768.

    Канон probe-semantics-from-primary-source: уровень — по privoxy manual, не по аналогии/имени.
    8 выглядит «невинно» (младший бит), но парсит заголовки → чувствительно. env-переключатель
    обязан ограничиться приватными уровнями {1, 2}.
    """
    monkeypatch.setenv("SROUTER_PRIVOXY_DEBUG", "8")
    assert privoxy_system._privoxy_debug_from_env() == 0


def test_privoxy_debug_from_env_rejects_raw_requests_level_for_privacy(monkeypatch):
    """debug 32768 = raw-запросы с заголовками/телом — приватность НИКОГДА через env-ускорение.

    Даже если пользователь поставил SROUTER_PRIVOXY_DEBUG=32768, env-парсер обязан вернуть 0:
    raw-уровни — только осознанная ручная правка конфига, не env-переключатель «по требованию».
    (Канон privacy-no-content-hash-on-disk: на диск не идёт даже производное контента.)
    """
    monkeypatch.setenv("SROUTER_PRIVOXY_DEBUG", "32768")
    assert privoxy_system._privoxy_debug_from_env() == 0


def test_protected_config_clamps_unknown_debug_level(tmp_path):
    """protected_config_text с уровнем вне whitelist → ничего не пишет (не падает, не гадает)."""
    layout = _layout(tmp_path)
    config = privoxy_system.protected_config_text(layout, debug=32768)
    assert "debug" not in config
    # Конфиг остаётся валидным без-debug контрактом.
    assert privoxy_system.validate_protected_config(config, layout)["ok"] is True


def test_protect_passes_debug_to_generated_config_and_helper(tmp_path, monkeypatch):
    """protect() читает SROUTER_PRIVOXY_DEBUG, пишет debug в staged_config И передаёт --debug в helper."""
    layout = _layout(tmp_path)
    state_path = tmp_path / "state.json"
    _write_state(state_path, {"service": "homebrew-user"})
    monkeypatch.setattr(
        privoxy_system, "_install_helper",
        lambda runner, selected_layout: {"ok": True, "error": ""},
    )
    monkeypatch.setenv("SROUTER_PRIVOXY_DEBUG", "2")
    captured = {}

    def runner(cmd, timeout):
        # staged_config пишется protect() в /private/tmp; ловим helper-argv.
        if "protect" in cmd:
            staged_arg = cmd[cmd.index("--config") + 1]
            captured["staged_debug"] = "debug 2" in Path(staged_arg).read_text(encoding="utf-8")
            captured["helper_debug"] = "--debug" in cmd and cmd[cmd.index("--debug") + 1] == "2"
            return {"rc": 0, "out": '{"ok":true,"error":"","backup_dir":"/backup"}',
                    "err": "", "timeout": False}
        if "unprotect" in cmd:
            return {"rc": 0, "out": '{"ok":true,"error":"","restored":true}',
                    "err": "", "timeout": False}
        if "-n" in cmd:
            return {"rc": 1, "out": "", "err": "password required", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    # status: при входе в protect — не защищён (ветка установки пишет staged_config),
    # после применения — secure (постпроверка проходит, protect возвращает ok).
    statuses = iter([
        {"protected": False, "loaded": False, "port_up": True, "owner": "",
         "config_writable": None, "binary_writable": None, "assets_writable": False},
        {"protected": True, "loaded": True, "port_up": True, "owner": "nobody",
         "config_writable": False, "binary_writable": False, "assets_writable": False,
         "user_shadow_loaded": False},
    ])
    monkeypatch.setattr(privoxy_system, "status", lambda **kwargs: next(statuses))

    privoxy_system.protect(
        state_path=state_path, runner=runner, require_tty=False, layout=layout,
    )

    assert captured["staged_debug"] is True
    assert captured["helper_debug"] is True

