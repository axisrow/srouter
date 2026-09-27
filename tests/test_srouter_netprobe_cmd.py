"""srouter netprobe apply|stop|report — LaunchAgent диагностической кампании (деградация туннеля 2026-09).

Канон: apply = _install_generic_launchagent (как watchdog/codenv: marker-gate + atomic write +
_launchd_reload); stop = семантика _remove_launchctl_env (чужой plist не трогаем, unlink только
после подтверждённой выгрузки); report = прогон коррелятора diag_netprobe.py. Fake runner — как в
test_srouter_codex_launchctl_env: print → rc 113 (не загружен), остальное rc 0.
"""
import argparse
from pathlib import Path

import srouter_cli


def _env(monkeypatch, tmp_path):
    """Tmp LaunchAgents/Logs через SROUTER_* (канон InstallEnv.from_env); root — реальный репо."""
    agents = tmp_path / "LaunchAgents"
    agents.mkdir(parents=True)
    logs = tmp_path / "Logs"
    logs.mkdir()
    monkeypatch.setenv("SROUTER_LAUNCHAGENTS_DIR", str(agents))
    monkeypatch.setenv("SROUTER_LOG_DIR", str(logs))
    monkeypatch.setenv("SROUTER_NOW", "2026-09-27T00:00:00Z")
    return agents


def _fake_runner():
    calls = []

    def runner(cmd, timeout):
        calls.append(list(cmd))
        if len(cmd) > 1 and cmd[1] == "print":
            return {"rc": 113, "out": "", "err": "Could not find service", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    runner.calls = calls
    return runner


def _cmd(action):
    return argparse.Namespace(netprobe_action=action)


def test_netprobe_apply_renders_plist_and_bootstraps(monkeypatch, tmp_path):
    agents = _env(monkeypatch, tmp_path)
    runner = _fake_runner()
    monkeypatch.setattr(srouter_cli, "run", runner)

    rc = srouter_cli.cmd_netprobe(_cmd("apply"))

    assert rc == 0
    plist = agents / f"{srouter_cli.NETPROBE_LABEL}.plist"
    assert plist.exists(), "plist создан в launchagent_dir"
    text = plist.read_text(encoding="utf-8")
    assert srouter_cli.NETPROBE_MARKER in text, "plist содержит маркер"
    assert srouter_cli.NETPROBE_LABEL in text
    assert "diag_netprobe.py" in text, "рендер подставил путь скрипта"
    assert "srouter-netprobe.out.log" in text, "свои логи, не dashboard"
    assert "__SROUTER_" not in text, "плейсхолдеры заменены все"
    assert any(len(c) > 1 and c[1] == "bootstrap" for c in runner.calls), "bootstrap вызван"


def test_netprobe_apply_is_idempotent(monkeypatch, tmp_path):
    agents = _env(monkeypatch, tmp_path)
    runner = _fake_runner()
    monkeypatch.setattr(srouter_cli, "run", runner)

    assert srouter_cli.cmd_netprobe(_cmd("apply")) == 0
    first = (agents / f"{srouter_cli.NETPROBE_LABEL}.plist").read_text(encoding="utf-8")
    assert srouter_cli.cmd_netprobe(_cmd("apply")) == 0
    assert (agents / f"{srouter_cli.NETPROBE_LABEL}.plist").read_text(encoding="utf-8") == first


def test_netprobe_apply_refuses_foreign(monkeypatch, tmp_path):
    agents = _env(monkeypatch, tmp_path)
    runner = _fake_runner()
    monkeypatch.setattr(srouter_cli, "run", runner)
    plist = agents / f"{srouter_cli.NETPROBE_LABEL}.plist"
    foreign = ("<?xml version='1.0'?><plist version='1.0'><dict>"
               "<key>Label</key><string>other</string></dict></plist>")
    plist.write_text(foreign, encoding="utf-8")

    rc = srouter_cli.cmd_netprobe(_cmd("apply"))

    assert rc == 2
    assert plist.read_text(encoding="utf-8") == foreign, "чужой plist не перезаписан"
    assert not any(len(c) > 1 and c[1] == "bootstrap" for c in runner.calls)


def test_netprobe_stop_unloads_and_unlinks(monkeypatch, tmp_path):
    agents = _env(monkeypatch, tmp_path)
    runner = _fake_runner()
    monkeypatch.setattr(srouter_cli, "run", runner)
    assert srouter_cli.cmd_netprobe(_cmd("apply")) == 0
    plist = agents / f"{srouter_cli.NETPROBE_LABEL}.plist"
    assert plist.exists()

    rc = srouter_cli.cmd_netprobe(_cmd("stop"))

    assert rc == 0
    assert not plist.exists(), "свой plist удалён после подтверждённой выгрузки"
    assert any(len(c) > 1 and c[1] == "bootout" for c in runner.calls)


def test_netprobe_stop_keeps_foreign(monkeypatch, tmp_path):
    agents = _env(monkeypatch, tmp_path)
    runner = _fake_runner()
    monkeypatch.setattr(srouter_cli, "run", runner)
    plist = agents / f"{srouter_cli.NETPROBE_LABEL}.plist"
    foreign = ("<?xml version='1.0'?><plist version='1.0'><dict>"
               "<key>Label</key><string>other</string></dict></plist>")
    plist.write_text(foreign, encoding="utf-8")

    rc = srouter_cli.cmd_netprobe(_cmd("stop"))

    assert rc == 2
    assert plist.read_text(encoding="utf-8") == foreign
    assert not any(len(c) > 1 and c[1] == "bootout" for c in runner.calls)


def test_netprobe_stop_when_not_installed(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    monkeypatch.setattr(srouter_cli, "run", _fake_runner())

    assert srouter_cli.cmd_netprobe(_cmd("stop")) == 2


def test_netprobe_report_runs_correlator(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    calls = []

    def runner(cmd, timeout):
        calls.append(list(cmd))
        return {"rc": 0, "out": "отчёт-строка\n", "err": "", "timeout": False}

    monkeypatch.setattr(srouter_cli, "run", runner, raising=False)

    rc = srouter_cli.cmd_netprobe(_cmd("report"))

    assert rc == 0
    assert len(calls) == 1
    assert Path(calls[0][-2]).name == "diag_netprobe.py"
    assert calls[0][-1] == "report"


def test_netprobe_report_rc_propagates(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    monkeypatch.setattr(
        srouter_cli, "run",
        lambda cmd, timeout: {"rc": 1, "out": "", "err": "fail", "timeout": False},
        raising=False)

    assert srouter_cli.cmd_netprobe(_cmd("report")) == 2


def test_netprobe_template_in_repo_has_marker_and_placeholders():
    """Шаблон в репо темизирован: маркер-плейсхолдер + плейсхолдеры generic-рендера на месте."""
    template = (Path(srouter_cli.__file__).resolve().parent
                / "launchagents" / srouter_cli.NETPROBE_TEMPLATE).read_text(encoding="utf-8")
    assert "__SROUTER_NETPROBE_MARKER__" in template
    assert "__SROUTER_NETPROBE_PATH__" in template
    assert "__SROUTER_PYTHON_BIN__" in template
    assert "StartInterval" in template
