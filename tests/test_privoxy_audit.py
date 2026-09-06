import io
import json
import os
import plistlib
import pwd
from datetime import datetime, timezone

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


def test_wait_daemon_readiness_returns_timeout_when_status_never_advances(tmp_path, monkeypatch):
    """B1-v3 (Codex cycle-3): если daemon застрял в starting/installing или не публикует status,

    _wait_daemon_readiness обязан вернуть readiness_timeout (НЕ fall-through к None). Иначе
    install трактует None как success → false-success (security-control рапортован установленным,
    audit нефункционален). Баг: return readiness_timeout стоял в недостижимом месте.
    """
    layout = _layout(tmp_path)
    monkeypatch.setattr(privoxy_audit, "_read_status_file", lambda layout_: {"state": "starting"})

    result = privoxy_audit._wait_daemon_readiness(
        layout, timeout=0.2, interval=0.05,
        clock=privoxy_audit.time.monotonic, sleep=privoxy_audit.time.sleep,
    )

    assert result == "readiness_timeout"


def test_install_fails_when_readiness_poll_times_out_via_real_poller(tmp_path, monkeypatch):
    """B1-v3: real-poller path — daemon застрял в starting → install возвращает ok=False (не None-success)."""
    layout = _layout(tmp_path)
    _write_helper(layout)
    identity = pwd.getpwuid(os.getuid())
    runner, _ = _install_runner_factory({"value": False})
    monkeypatch.setattr(privoxy_audit, "_read_status_file", lambda layout_: {"state": "starting"})

    class FakeClock:
        now = 0.0

        def __call__(self):
            return self.now

        def sleep(self, seconds):
            self.now += seconds

    clock = FakeClock()
    real_poller = privoxy_audit._wait_daemon_readiness
    monkeypatch.setattr(
        privoxy_audit,
        "_wait_daemon_readiness",
        lambda layout_: real_poller(layout_, clock=clock, sleep=clock.sleep),
    )

    # Без readiness_poll — install вызывает настоящий polling loop, но его время детерминированно.
    result = privoxy_audit.install_as_root(
        username=identity.pw_name, uid=identity.pw_uid, gid=identity.pw_gid,
        layout=layout, runner=runner, chown=lambda path, uid, gid: None, enforce_root=False,
    )

    assert result["ok"] is False
    assert "fda" in result["error"]
    assert clock.now >= 5.0


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


# ===========================================================================
# PR-4 #339, остаток (D3): ротация command-audit.jsonl. Writer сам ротирует свой
# журнал: daemon — единственный append-процесс, ротация происходит МЕЖДУ событиями,
# fd под append открывается заново на каждое событие (_append_event) — os.replace
# не осиротивает записи. Opt-in SROUTER_AUDIT_LOG_ROTATE=1 — та же граница согласия,
# что и D2 (#354): удаление содержимого логов — только явное решение оператора
# (для launchd-даемона — `sudo launchctl setenv`). Дефолты 30d/16MB (контракт §3).
# Битые строки СОХРАНЯЮТСЯ — audit-журнал не теряет улики (осознанное отличие от
# metrics-канона «битая строка вырезается»). stdout/stderr.log НЕ ротируются: их
# держит launchd (StandardOutPath/StandardErrorPath), rename осиротил бы вывод.
# ===========================================================================

def test_rotate_event_log_drops_stale_keeps_malformed(tmp_path):
    layout = _layout(tmp_path)
    layout.event_log_path.parent.mkdir(parents=True)
    stale = json.dumps({"captured_at": "2026-08-01T00:00:00+00:00"})
    fresh = json.dumps({"captured_at": "2026-09-06T00:00:00+00:00"})
    layout.event_log_path.write_text(
        stale + "\ngarbage-not-json\n" + fresh + "\n", encoding="utf-8")

    ok = privoxy_audit.rotate_event_log(
        layout, retention_days=30, max_bytes=16 * 1024 * 1024,
        now=datetime(2026, 9, 6, 12, tzinfo=timezone.utc).timestamp(),
        chown=lambda path, uid, gid: None)

    assert ok is True
    kept = layout.event_log_path.read_text(encoding="utf-8").splitlines()
    assert kept == ["garbage-not-json", fresh], "протухшее вырезано, битая улика сохранена"


def test_rotate_event_log_early_exit_fresh_head(tmp_path):
    layout = _layout(tmp_path)
    layout.event_log_path.parent.mkdir(parents=True)
    content = json.dumps({"captured_at": "2026-09-06T00:00:00+00:00"}) + "\n"
    layout.event_log_path.write_text(content, encoding="utf-8")
    before = layout.event_log_path.stat().st_mtime_ns

    ok = privoxy_audit.rotate_event_log(
        layout, retention_days=30, max_bytes=16 * 1024 * 1024,
        now=datetime(2026, 9, 6, 12, tzinfo=timezone.utc).timestamp(),
        chown=lambda path, uid, gid: None)

    assert ok is True
    assert layout.event_log_path.read_text(encoding="utf-8") == content
    assert layout.event_log_path.stat().st_mtime_ns == before, "fresh-голова — rewrite не нужен"


def test_rotate_event_log_trims_oldest_fresh_lines_on_size_cap(tmp_path):
    """Перевес по max_bytes при полностью свежих строках: хвост обязан влезть в бюджет —
    срезаются СТАРЕЙШИЕ строки (журнал append-only, монотонен), не «ничего не делать».
    Канон размера из метрик (rewrite обязан уменьшить файл), без line-count костыля."""
    layout = _layout(tmp_path)
    layout.event_log_path.parent.mkdir(parents=True)
    lines = [json.dumps({"captured_at": f"2026-09-0{1 + i // 10}T0{i % 10}:00:00+00:00",
                         "seq": i}) for i in range(60)]
    layout.event_log_path.write_text("".join(l + "\n" for l in lines), encoding="utf-8")

    ok = privoxy_audit.rotate_event_log(
        layout, retention_days=30, max_bytes=1400,
        now=datetime(2026, 9, 6, 12, tzinfo=timezone.utc).timestamp(),
        chown=lambda path, uid, gid: None)

    assert ok is True
    kept = layout.event_log_path.read_text(encoding="utf-8").splitlines()
    assert len(kept) < 60, "перевес по размеру обязан ужаться"
    assert len("".join(l + "\n" for l in kept).encode("utf-8")) <= 1400
    kept_seqs = [json.loads(l)["seq"] for l in kept]
    assert kept_seqs == list(range(60 - len(kept), 60)), "срезан СТАРЫЙ хвост, новый цел"


def test_rotate_event_log_failure_keeps_file_intact(tmp_path, monkeypatch):
    layout = _layout(tmp_path)
    layout.event_log_path.parent.mkdir(parents=True)
    stale = json.dumps({"captured_at": "2026-08-01T00:00:00+00:00"})
    fresh = json.dumps({"captured_at": "2026-09-06T00:00:00+00:00"})
    content = stale + "\n" + fresh + "\n"
    layout.event_log_path.write_text(content, encoding="utf-8")

    def failing_replace(src, dst, **kwargs):
        raise OSError("replace failed")

    monkeypatch.setattr(privoxy_audit.os, "replace", failing_replace)

    ok = privoxy_audit.rotate_event_log(
        layout, retention_days=30, max_bytes=16 * 1024 * 1024,
        now=datetime(2026, 9, 6, 12, tzinfo=timezone.utc).timestamp(),
        chown=lambda path, uid, gid: None)

    assert ok is False
    assert layout.event_log_path.read_text(encoding="utf-8") == content, "сбой — файл нетронут"


def test_event_log_rotation_config_defaults_off_and_env_overrides(monkeypatch):
    for name in ("SROUTER_AUDIT_LOG_ROTATE", "SROUTER_AUDIT_LOG_RETENTION_DAYS",
                 "SROUTER_AUDIT_LOG_MAX_BYTES"):
        monkeypatch.delenv(name, raising=False)
    assert privoxy_audit.event_log_rotation_config() == {
        "enabled": False, "retention_days": 30, "max_bytes": 16 * 1024 * 1024}

    monkeypatch.setenv("SROUTER_AUDIT_LOG_ROTATE", "1")
    monkeypatch.setenv("SROUTER_AUDIT_LOG_RETENTION_DAYS", "7")
    monkeypatch.setenv("SROUTER_AUDIT_LOG_MAX_BYTES", "1024")
    assert privoxy_audit.event_log_rotation_config() == {
        "enabled": True, "retention_days": 7, "max_bytes": 1024}

    # more-options-better: мусор → дефолт (кривое значение не опаснее отсутствия ручки)
    monkeypatch.setenv("SROUTER_AUDIT_LOG_RETENTION_DAYS", "banana")
    monkeypatch.setenv("SROUTER_AUDIT_LOG_MAX_BYTES", "-5")
    assert privoxy_audit.event_log_rotation_config() == {
        "enabled": True, "retention_days": 30, "max_bytes": 16 * 1024 * 1024}


def test_daemon_rotates_event_log_between_events(tmp_path, monkeypatch):
    """Интеграция: enabled + stale-хвост → daemon ротирует МЕЖДУ событиями, и новое
    событие при этом не теряется (fail-closed: ротация не съедает append)."""
    layout = _layout(tmp_path)
    identity = pwd.getpwuid(os.getuid())
    layout.status_path.parent.mkdir(parents=True)
    layout.status_path.write_text(json.dumps({
        "marker": privoxy_audit.AUDIT_MARKER, "gid": identity.pw_gid,
        "events_written": 0, "parse_errors": 0,
    }), encoding="utf-8")
    layout.event_log_path.parent.mkdir(parents=True)
    layout.event_log_path.write_text(
        json.dumps({"captured_at": "2026-08-01T00:00:00+00:00"}) + "\n", encoding="utf-8")

    class Child:
        pid = 9101
        stdout = io.StringIO(json.dumps(_event(
            "/opt/homebrew/bin/brew", ["brew", "services", "stop", "privoxy"])) + "\n")
        stderr = io.StringIO("")
        _exited = False

        def poll(self):
            return None if not self._exited else 0

        def wait(self, timeout=None):
            self._exited = True
            return 1

        def terminate(self):
            return None

    monkeypatch.setattr(privoxy_audit.os, "geteuid", lambda: 0)
    monkeypatch.setattr(privoxy_audit.signal, "signal", lambda signum, handler: None)
    monkeypatch.setenv("SROUTER_AUDIT_LOG_ROTATE", "1")

    rc = privoxy_audit.daemon(layout=layout, popen=lambda *args, **kwargs: Child(),
                              chown=lambda path, uid, gid: None, grace=0)

    kept = layout.event_log_path.read_text(encoding="utf-8").splitlines()
    assert rc == 2
    assert len(kept) == 1, "stale-строка вырезана, событие daemon'а записано"
    record = json.loads(kept[0])
    assert record["target"]["args"][-2:] == ["stop", "privoxy"]


def test_daemon_rotation_failure_does_not_stop_writer(tmp_path, monkeypatch):
    """Сбой ротации — best-effort: writer продолжает писать события; сбой гигиены не
    превращается в сбой аудита (последний error в статусе — от harness-child, не ротации)."""
    layout = _layout(tmp_path)
    identity = pwd.getpwuid(os.getuid())
    layout.status_path.parent.mkdir(parents=True)
    layout.status_path.write_text(json.dumps({
        "marker": privoxy_audit.AUDIT_MARKER, "gid": identity.pw_gid,
        "events_written": 0, "parse_errors": 0,
    }), encoding="utf-8")

    class Child:
        pid = 9102
        stdout = io.StringIO(json.dumps(_event(
            "/opt/homebrew/bin/brew", ["brew", "services", "stop", "privoxy"])) + "\n")
        stderr = io.StringIO("")
        _exited = False

        def poll(self):
            return None if not self._exited else 0

        def wait(self, timeout=None):
            self._exited = True
            return 1

        def terminate(self):
            return None

    monkeypatch.setattr(privoxy_audit.os, "geteuid", lambda: 0)
    monkeypatch.setattr(privoxy_audit.signal, "signal", lambda signum, handler: None)
    monkeypatch.setenv("SROUTER_AUDIT_LOG_ROTATE", "1")
    monkeypatch.setattr(privoxy_audit, "rotate_event_log", lambda *args, **kwargs: False)

    rc = privoxy_audit.daemon(layout=layout, popen=lambda *args, **kwargs: Child(),
                              chown=lambda path, uid, gid: None, grace=0)

    result = privoxy_audit.report(limit=10, layout=layout)
    assert rc == 2
    assert result["ok"] is True and len(result["records"]) == 1
    saved = json.loads(layout.status_path.read_text(encoding="utf-8"))
    assert saved["events_written"] == 1
    assert "eslogger_exited" in saved["last_error"], saved


def test_daemon_rotation_throttled_to_hourly_gate(tmp_path, monkeypatch):
    """eslogger стримит ВСЕ exec-события машины — проверка ротации обязана висеть на
    throttle'е (canon hourly-гейт метрик), а не гонять stat/read на каждой строке."""
    layout = _layout(tmp_path)
    identity = pwd.getpwuid(os.getuid())
    layout.status_path.parent.mkdir(parents=True)
    layout.status_path.write_text(json.dumps({
        "marker": privoxy_audit.AUDIT_MARKER, "gid": identity.pw_gid,
        "events_written": 0, "parse_errors": 0,
    }), encoding="utf-8")

    calls = []
    real_rotate = privoxy_audit.rotate_event_log

    def counting_rotate(*args, **kwargs):
        calls.append(1)
        return real_rotate(*args, **kwargs)

    monkeypatch.setattr(privoxy_audit, "rotate_event_log", counting_rotate)
    monkeypatch.setattr(privoxy_audit.os, "geteuid", lambda: 0)
    monkeypatch.setattr(privoxy_audit.signal, "signal", lambda signum, handler: None)
    monkeypatch.setenv("SROUTER_AUDIT_LOG_ROTATE", "1")

    events = [_event("/usr/bin/curl", ["curl", f"https://x{i}.example.com"]) for i in range(40)]

    class Child:
        pid = 9103
        stdout = io.StringIO("".join(json.dumps(value) + "\n" for value in events))
        stderr = io.StringIO("")
        _exited = False

        def poll(self):
            return None if not self._exited else 0

        def wait(self, timeout=None):
            self._exited = True
            return 1

        def terminate(self):
            return None

    privoxy_audit.daemon(layout=layout, popen=lambda *args, **kwargs: Child(),
                         chown=lambda path, uid, gid: None, grace=0)

    assert len(calls) == 1, "throttle: одна проверка за прогон, не по одной на строку"
