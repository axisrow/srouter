import io
import json
import os
import plistlib
import pwd

import privoxy_audit
import srouter


def _layout(tmp_path):
    system = tmp_path / "system"
    eslogger = system / "usr" / "bin" / "eslogger"
    eslogger.parent.mkdir(parents=True)
    eslogger.write_text("fake", encoding="utf-8")
    eslogger.chmod(0o755)
    return privoxy_audit.AuditLayout(
        helper_path=system / "helpers" / "com.srouter.privoxyaudit",
        launchdaemon_path=system / "LaunchDaemons" / "com.srouter.privoxy.audit.plist",
        data_dir=system / "data",
        status_path=system / "data" / "status.json",
        log_dir=system / "logs",
        event_log_path=system / "logs" / "command-audit.jsonl",
        stdout_path=system / "logs" / "stdout.log",
        stderr_path=system / "logs" / "stderr.log",
        eslogger_path=eslogger,
    )


def _write_helper(layout):
    layout.helper_path.parent.mkdir(parents=True, exist_ok=True)
    layout.helper_path.write_text(f"#!/bin/sh\n# {privoxy_audit.HELPER_MARKER}\n", encoding="utf-8")
    layout.helper_path.chmod(0o755)


def _event(path, args, *, actor="/Applications/Codex.app/Contents/MacOS/Codex", pid=123):
    return {
        "schema_version": 4,
        "time": "2026-07-21T18:01:00+08:00",
        "process": {
            "audit_token": {"pid": pid},
            "executable": {"path": actor},
            "signing_id": "com.openai.codex",
            "team_id": "2DC432GLL2",
        },
        "event": {
            "exec": {
                "target": {
                    "audit_token": {"pid": pid + 1},
                    "executable": {"path": path},
                },
                "args": args,
            }
        },
    }


def test_launchdaemon_runs_fixed_root_helper_with_throttle(tmp_path):
    layout = _layout(tmp_path)
    raw = privoxy_audit.audit_launchdaemon_bytes(layout)
    plist = plistlib.loads(raw)

    assert privoxy_audit.AUDIT_MARKER.encode() in raw
    assert plist["Label"] == privoxy_audit.AUDIT_LABEL
    assert plist["ProgramArguments"] == [str(layout.helper_path), "daemon"]
    assert plist["RunAtLoad"] is True
    assert plist["KeepAlive"] == {"SuccessfulExit": False}
    assert plist["ThrottleInterval"] == 60


def test_filter_keeps_privoxy_lifecycle_commands_and_srouter_uninstall():
    matching = [
        _event("/opt/homebrew/bin/brew", ["brew", "services", "restart", "privoxy"]),
        _event("/bin/launchctl", ["launchctl", "bootout", "gui/501/homebrew.mxcl.privoxy"]),
        _event("/opt/homebrew/bin/srouter", ["srouter", "uninstall"]),
        _event("/opt/homebrew/bin/python3", ["python3", "/repo/srouter.py", "install"]),
        _event("/bin/zsh", ["zsh", "-lc", "brew services stop privoxy"]),
        _event(
            "/Library/PrivilegedHelperTools/com.srouter.privoxyctl",
            ["/Library/PrivilegedHelperTools/com.srouter.privoxyctl", "restart"],
        ),
    ]
    ignored = [
        _event("/opt/homebrew/bin/brew", ["brew", "services", "restart", "xray"]),
        _event("/usr/bin/curl", ["curl", "http://127.0.0.1:8118"]),
        _event("/opt/homebrew/bin/srouter", ["srouter", "privoxy", "status"]),
        _event(
            "/Library/PrivilegedHelperTools/com.srouter.privoxyctl",
            ["/Library/PrivilegedHelperTools/com.srouter.privoxyctl", "status"],
        ),
        _event("/opt/homebrew/bin/srouter", ["srouter", "privoxy", "audit", "install"]),
        _event(
            "/Library/PrivilegedHelperTools/com.srouter.privoxyaudit",
            ["/Library/PrivilegedHelperTools/com.srouter.privoxyaudit", "daemon"],
        ),
    ]

    assert all(privoxy_audit.is_privoxy_event(value) for value in matching)
    assert not any(privoxy_audit.is_privoxy_event(value) for value in ignored)


def test_normalize_event_keeps_attribution_and_redacts_secrets():
    event = _event(
        "/bin/zsh",
        [
            "zsh", "-lc", "brew services stop privoxy",
            "brew services stop privoxy; TOKEN=inline-secret",
            "--api-key=super-secret", "PASSWORD=hunter2", "--token", "abc",
        ],
    )

    record = privoxy_audit.normalize_event(event)

    assert record["eslogger_schema_version"] == 4
    assert record["actor"]["pid"] == 123
    assert record["actor"]["executable"].endswith("/Codex")
    assert record["target"]["pid"] == 124
    assert record["target"]["args"][-4:] == [
        "--api-key=<redacted>", "PASSWORD=<redacted>", "--token", "<redacted>",
    ]
    assert "super-secret" not in json.dumps(record)
    assert "hunter2" not in json.dumps(record)
    assert "inline-secret" not in json.dumps(record)


def test_install_transaction_creates_root_contract_and_bootstraps(tmp_path):
    layout = _layout(tmp_path)
    _write_helper(layout)
    identity = pwd.getpwuid(os.getuid())
    loaded = {"value": False}
    calls = []

    def runner(cmd, timeout):
        calls.append(cmd)
        if cmd[:2] == [privoxy_audit.LAUNCHCTL, "print"]:
            return {"rc": 0 if loaded["value"] else 113,
                    "out": "state = running" if loaded["value"] else "", "err": ""}
        if cmd[:2] == [privoxy_audit.LAUNCHCTL, "bootstrap"]:
            loaded["value"] = True
        if cmd[:2] == [privoxy_audit.LAUNCHCTL, "bootout"]:
            loaded["value"] = False
        return {"rc": 0, "out": "", "err": ""}

    result = privoxy_audit.install_as_root(
        username=identity.pw_name,
        uid=identity.pw_uid,
        gid=identity.pw_gid,
        layout=layout,
        runner=runner,
        chown=lambda path, uid, gid: None,
        enforce_root=False,
        readiness_poll=lambda layout_: None,
    )

    assert result["ok"] is True
    assert privoxy_audit.AUDIT_MARKER in layout.launchdaemon_path.read_text()
    assert layout.event_log_path.exists()
    # event log — root-only (0o600), НЕ group-readable. Redaction эвристический, поэтому captured
    # command args не должны быть читаемы shared primary group (staff) — cross-user disclosure (B2).
    assert (layout.event_log_path.stat().st_mode & 0o777) == 0o600
    assert [privoxy_audit.LAUNCHCTL, "bootstrap", "system", str(layout.launchdaemon_path)] in calls


def _install_runner_factory(loaded_ref):
    """runner для install_as_root: bootstrap переключает loaded; bootout сбрасывает."""
    calls = []

    def runner(cmd, timeout):
        calls.append(cmd)
        if cmd[:2] == [privoxy_audit.LAUNCHCTL, "print"]:
            return {"rc": 0 if loaded_ref["value"] else 113,
                    "out": "state = running" if loaded_ref["value"] else "", "err": ""}
        if cmd[:2] == [privoxy_audit.LAUNCHCTL, "bootstrap"]:
            loaded_ref["value"] = True
        if cmd[:2] == [privoxy_audit.LAUNCHCTL, "bootout"]:
            loaded_ref["value"] = False
        return {"rc": 0, "out": "", "err": ""}
    return runner, calls


def test_install_fails_when_daemon_reports_fda_denial_during_readiness(tmp_path):
    """B1: install обязан дождаться readiness daemon'а и вернуть failure, если eslogger падает

    от Full Disk Access denial. Иначе CLI рапортует установленное security-control, хотя audit
    нефункционален (false-success). install_as_root опрашивает status после bootstrap; если daemon
    пишет state=error (FDA/eslogger_exited), install возвращает ok=False с error=fda_denial.
    """
    layout = _layout(tmp_path)
    _write_helper(layout)
    identity = pwd.getpwuid(os.getuid())
    runner, _ = _install_runner_factory({"value": False})

    # Симулируем FDA-denial: readiness-poll видит state=error (daemon "успел" упасть).
    def readiness_poll(layout_):
        return "eslogger_exited:1:Operation not permitted (TCC)"

    result = privoxy_audit.install_as_root(
        username=identity.pw_name, uid=identity.pw_uid, gid=identity.pw_gid,
        layout=layout, runner=runner, chown=lambda path, uid, gid: None, enforce_root=False,
        readiness_poll=readiness_poll,
    )

    assert result["ok"] is False
    assert "fda" in result["error"]


def test_install_succeeds_when_daemon_reaches_running_readiness(tmp_path):
    """B1 (happy path): daemon подтвердил readiness (state=running) в окне — install success."""
    layout = _layout(tmp_path)
    _write_helper(layout)
    identity = pwd.getpwuid(os.getuid())
    runner, _ = _install_runner_factory({"value": False})

    def readiness_poll(layout_):
        return None  # readiness подтверждена

    result = privoxy_audit.install_as_root(
        username=identity.pw_name, uid=identity.pw_uid, gid=identity.pw_gid,
        layout=layout, runner=runner, chown=lambda path, uid, gid: None, enforce_root=False,
        readiness_poll=readiness_poll,
    )

    assert result["ok"] is True


def test_install_fails_when_daemon_never_confirms_readiness(tmp_path):
    """B1 (timeout): daemon не переписал status из 'installing' за bounded-окно — install failure.

    Скорее всего FDA-denial, eslogger ещё не упал. CLI не должен рапортовать success вслепую.
    """
    layout = _layout(tmp_path)
    _write_helper(layout)
    identity = pwd.getpwuid(os.getuid())
    runner, _ = _install_runner_factory({"value": False})

    def readiness_poll(layout_):
        return "readiness_timeout"

    result = privoxy_audit.install_as_root(
        username=identity.pw_name, uid=identity.pw_uid, gid=identity.pw_gid,
        layout=layout, runner=runner, chown=lambda path, uid, gid: None, enforce_root=False,
        readiness_poll=readiness_poll,
    )

    assert result["ok"] is False
    assert "fda" in result["error"]


def test_install_refuses_foreign_launchdaemon_before_lifecycle_change(tmp_path):
    layout = _layout(tmp_path)
    _write_helper(layout)
    identity = pwd.getpwuid(os.getuid())
    layout.launchdaemon_path.parent.mkdir(parents=True)
    layout.launchdaemon_path.write_text("foreign", encoding="utf-8")
    calls = []

    result = privoxy_audit.install_as_root(
        username=identity.pw_name,
        uid=identity.pw_uid,
        gid=identity.pw_gid,
        layout=layout,
        runner=lambda cmd, timeout: calls.append(cmd) or {"rc": 0, "out": "", "err": ""},
        chown=lambda path, uid, gid: None,
        enforce_root=False,
    )

    assert result["ok"] is False
    assert result["error"] == "foreign_audit_launchdaemon"
    assert calls == []


def test_install_aborts_if_existing_daemon_cannot_be_booted_out(tmp_path):
    layout = _layout(tmp_path)
    _write_helper(layout)
    identity = pwd.getpwuid(os.getuid())
    layout.launchdaemon_path.parent.mkdir(parents=True)
    original = privoxy_audit.audit_launchdaemon_bytes(layout)
    layout.launchdaemon_path.write_bytes(original)
    calls = []

    def runner(cmd, timeout):
        calls.append(cmd)
        if cmd[:2] == [privoxy_audit.LAUNCHCTL, "print"]:
            return {"rc": 0, "out": "state = running", "err": ""}
        if cmd[:2] == [privoxy_audit.LAUNCHCTL, "bootout"]:
            return {"rc": 5, "out": "", "err": "not permitted"}
        return {"rc": 0, "out": "", "err": ""}

    result = privoxy_audit.install_as_root(
        username=identity.pw_name,
        uid=identity.pw_uid,
        gid=identity.pw_gid,
        layout=layout,
        runner=runner,
        chown=lambda path, uid, gid: None,
        enforce_root=False,
    )

    assert result["ok"] is False
    assert result["error"].startswith("audit_bootout_failed")
    assert not any(cmd[:2] == [privoxy_audit.LAUNCHCTL, "bootstrap"] for cmd in calls)
    assert layout.launchdaemon_path.read_bytes() == original


def test_status_surfaces_full_disk_access_denial(tmp_path):
    layout = _layout(tmp_path)
    _write_helper(layout)
    layout.launchdaemon_path.parent.mkdir(parents=True)
    layout.launchdaemon_path.write_bytes(privoxy_audit.audit_launchdaemon_bytes(layout))
    layout.status_path.parent.mkdir(parents=True)
    layout.status_path.write_text(json.dumps({
        "marker": privoxy_audit.AUDIT_MARKER,
        "state": "error",
        "last_error": "eslogger_exited:1:Operation not permitted (TCC)",
    }), encoding="utf-8")

    current = privoxy_audit.status(
        layout=layout,
        runner=lambda cmd, timeout: {"rc": 0, "out": "state = running", "err": ""},
        expected_uid=os.getuid(),
    )

    assert current["installed"] is True
    assert current["loaded"] is True
    assert current["state"] == "error"
    assert current["fda_required"] is True


def test_user_install_clears_sudo_timestamp_between_privileged_steps(tmp_path):
    layout = _layout(tmp_path)
    calls = []

    def runner(cmd, timeout):
        calls.append(cmd)
        if cmd[:3] == [privoxy_audit.SUDO, str(layout.helper_path), "install"]:
            return {"rc": 0, "out": '{"ok":true,"changed":true}', "err": ""}
        if cmd[:2] == [privoxy_audit.LAUNCHCTL, "print"]:
            return {"rc": 113, "out": "", "err": "not found"}
        return {"rc": 0, "out": "", "err": ""}

    result = privoxy_audit.install(runner=runner, require_tty=False, layout=layout)

    assert result["ok"] is True
    invoke_index = next(
        index for index, cmd in enumerate(calls)
        if cmd[:3] == [privoxy_audit.SUDO, str(layout.helper_path), "install"]
    )
    assert calls[invoke_index - 1] == [privoxy_audit.SUDO, "-k"]
    assert calls[invoke_index + 1] == [privoxy_audit.SUDO, "-k"]


def test_report_returns_tail_and_counts_bad_lines(tmp_path):
    layout = _layout(tmp_path)
    layout.event_log_path.parent.mkdir(parents=True)
    layout.event_log_path.write_text(
        '{"captured_at":"one"}\nnot-json\n{"captured_at":"two"}\n',
        encoding="utf-8",
    )

    result = privoxy_audit.report(limit=1, layout=layout)

    assert result["ok"] is True
    assert result["records"] == [{"captured_at": "two"}]
    assert result["parse_errors"] == 1


def test_daemon_persists_only_matching_exec_events(tmp_path, monkeypatch):
    layout = _layout(tmp_path)
    identity = pwd.getpwuid(os.getuid())
    layout.status_path.parent.mkdir(parents=True)
    layout.status_path.write_text(json.dumps({
        "marker": privoxy_audit.AUDIT_MARKER,
        "gid": identity.pw_gid,
        "events_written": 0,
        "parse_errors": 0,
    }), encoding="utf-8")
    events = [
        _event("/usr/bin/curl", ["curl", "https://example.com"]),
        {"schema_version": 999, "event": {"exec": {}}},
        _event("/opt/homebrew/bin/brew", ["brew", "services", "stop", "privoxy"]),
    ]

    class Child:
        pid = 9001
        stdout = io.StringIO("".join(json.dumps(value) + "\n" for value in events))
        stderr = io.StringIO("")
        _exited = False

        def poll(self):
            # Живой eslogger с открытым stdout: None, пока не вычитан полностью.
            return None if not self._exited else 0

        def wait(self, timeout=None):
            self._exited = True
            return 1

        def terminate(self):
            return None

    monkeypatch.setattr(privoxy_audit.os, "geteuid", lambda: 0)
    monkeypatch.setattr(privoxy_audit.signal, "signal", lambda signum, handler: None)

    rc = privoxy_audit.daemon(
        layout=layout,
        popen=lambda *args, **kwargs: Child(),
        chown=lambda path, uid, gid: None,
        grace=0,  # grace-handshake вылючен для unit-теста (мок-Child жив, реальный grace не нужен).
    )
    result = privoxy_audit.report(limit=10, layout=layout)

    assert rc == 2
    assert result["ok"] is True
    assert len(result["records"]) == 1
    assert result["records"][0]["target"]["args"][-3:] == ["services", "stop", "privoxy"]
    saved = json.loads(layout.status_path.read_text(encoding="utf-8"))
    assert saved["gid"] == identity.pw_gid
    assert saved["parse_errors"] == 1


def test_daemon_reports_fda_failure_when_eslogger_dies_during_grace(tmp_path, monkeypatch):
    """B1-v2 (Codex cycle-2): eslogger стартует (Popen успешен), но падает от FDA/TCC-denial

    ВНУТРИ startup-grace — ДО того, как readiness мог бы быть опубликован. daemon обязан поймать
    это (child.poll() != None за grace) и написать state=error, а НЕ ранний running. Иначе
    install's readiness-poll принял бы running за success (false-success race из cycle 1).
    """
    layout = _layout(tmp_path)
    identity = pwd.getpwuid(os.getuid())
    layout.status_path.parent.mkdir(parents=True)
    layout.status_path.write_text(json.dumps({
        "marker": privoxy_audit.AUDIT_MARKER, "gid": identity.pw_gid,
    }), encoding="utf-8")

    class FailingChild:
        pid = 9002
        # stdout пустой — eslogger падает до первого event.
        stdout = io.StringIO("")
        stderr = io.StringIO("Operation not permitted (TCC)")

        def poll(self):
            return 1  # упал немедленно (FDA-denial).

        def wait(self, timeout=None):
            return 1

        def terminate(self):
            return None

    monkeypatch.setattr(privoxy_audit.os, "geteuid", lambda: 0)
    monkeypatch.setattr(privoxy_audit.signal, "signal", lambda signum, handler: None)

    rc = privoxy_audit.daemon(
        layout=layout,
        popen=lambda *args, **kwargs: FailingChild(),
        chown=lambda path, uid, gid: None,
        grace=0.2,  # короткий grace для теста; FailingChild.poll()=1 → падение поймано сразу.
    )

    assert rc == 2
    saved = json.loads(layout.status_path.read_text(encoding="utf-8"))
    assert saved["state"] == "error"
    assert "startup" in saved["last_error"]


def test_cli_parser_exposes_nested_audit_commands():
    parser = srouter.build_parser()

    install = parser.parse_args(["privoxy", "audit", "install"])
    report = parser.parse_args(["privoxy", "audit", "report", "--limit", "12", "--json"])
    uninstall = parser.parse_args(["privoxy", "audit", "uninstall", "--purge-log"])

    assert install.privoxy_audit_action == "install"
    assert report.limit == 12 and report.json is True
    assert uninstall.purge_log is True
