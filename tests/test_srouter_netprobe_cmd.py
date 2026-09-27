"""srouter netprobe apply|stop|report — LaunchAgent диагностической кампании (деградация туннеля 2026-09).

Канон: apply = _install_generic_launchagent (как watchdog/codenv: marker-gate + atomic write +
_launchd_reload); stop = семантика _remove_launchctl_env (чужой plist не трогаем, unlink только
после подтверждённой выгрузки); report = прогон коррелятора diag_netprobe.py. Fake runner — как в
test_srouter_codex_launchctl_env: print → rc 113 (не загружен), остальное rc 0.
"""
import argparse
import json
import time
from pathlib import Path

import diag_netprobe
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


# ============================ ssid — ручная аннотация сети ============================
def test_default_route_parses_gateway_and_iface(monkeypatch):
    def fake_run(cmd, timeout):
        return {"rc": 0, "out": "   gateway: 192.168.3.1\n   interface: en0\n",
                "err": "", "timeout": False}

    monkeypatch.setattr(diag_netprobe, "run", fake_run)
    assert diag_netprobe._default_route() == ("192.168.3.1", "en0")


def test_default_route_vpn_iface_without_gateway(monkeypatch):
    """ipsec0 (VPN) не имеет gateway: — iface фиксируется, нога gateway пропускается."""
    def fake_run(cmd, timeout):
        return {"rc": 0, "out": "   interface: ipsec0\n", "err": "", "timeout": False}

    monkeypatch.setattr(diag_netprobe, "run", fake_run)
    assert diag_netprobe._default_route() == (None, "ipsec0")


def test_netprobe_ssid_runs_script(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    calls = []

    def runner(cmd, timeout):
        calls.append(list(cmd))
        return {"rc": 0, "out": "SSID: X\n", "err": "", "timeout": False}

    monkeypatch.setattr(srouter_cli, "run", runner, raising=False)

    rc = srouter_cli.cmd_netprobe(_cmd("ssid"))

    assert rc == 0
    assert Path(calls[0][-2]).name == "diag_netprobe.py"
    assert calls[0][-1] == "ssid"


def test_read_ssid_parses_ipconfig(monkeypatch):
    def fake_run(cmd, timeout):
        if cmd[1] == "getsummary":
            return {"rc": 0, "out": "  SSID : HomeWifi\n  BSSID : <redacted>\n",
                    "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(diag_netprobe, "run", fake_run)
    assert diag_netprobe.read_ssid() == "HomeWifi"


def test_read_ssid_falls_back_to_networksetup(monkeypatch):
    def fake_run(cmd, timeout):
        if cmd[1] == "getsummary":
            return {"rc": 0, "out": "  SSID : <redacted>\n", "err": "", "timeout": False}
        return {"rc": 0, "out": "Current Wi-Fi Network: OfficeNet\n", "err": "", "timeout": False}

    monkeypatch.setattr(diag_netprobe, "run", fake_run)
    assert diag_netprobe.read_ssid() == "OfficeNet"


def test_read_ssid_none_when_redacted_everywhere(monkeypatch):
    def fake_run(cmd, timeout):
        if cmd[1] == "getsummary":
            return {"rc": 0, "out": "  SSID : <redacted>\n", "err": "", "timeout": False}
        return {"rc": 1, "out": "You are not associated with an AirPort network.\n",
                "err": "", "timeout": False}

    monkeypatch.setattr(diag_netprobe, "run", fake_run)
    assert diag_netprobe.read_ssid() is None


def test_read_ssid_none_when_networksetup_reports_error(monkeypatch):
    """Wi-Fi выключен: networksetup печатает '** Error **' — мусор не должен пройти как SSID."""
    def fake_run(cmd, timeout):
        if cmd[1] == "getsummary":
            return {"rc": 0, "out": "  SSID : <redacted>\n", "err": "", "timeout": False}
        return {"rc": 0, "out": "Current Wi-Fi Network: ** Error **\n", "err": "", "timeout": False}

    monkeypatch.setattr(diag_netprobe, "run", fake_run)
    assert diag_netprobe.read_ssid() is None


def test_report_ignores_ssid_rows(monkeypatch, tmp_path, capsys):
    """Строки-метки leg="ssid" (без sent/recv) не считаются раундами и не ломают отчёт."""
    now = time.time()
    tunnel = tmp_path / "metrics.jsonl"
    statuses = ["ok"] * 6 + ["connection-failed"] * 3 + ["ok"] * 6
    tunnel.write_text(
        "\n".join(json.dumps({"ts": now - 1000 + i * 10, "status": s})
                  for i, s in enumerate(statuses)) + "\n", encoding="utf-8")
    netlog = tmp_path / "netprobe.jsonl"
    rows = []
    for i in range(27):  # 27 раундов шагом 30с от t0; окно фейлов [300, 320] → inside [180, 440]
        ts = now - 1000 + i * 30
        rows.append(json.dumps({"ts": ts, "leg": "gateway", "target": "192.168.3.1",
                                "sent": 3, "recv": 3, "avg_ms": 3.0}))
        rows.append(json.dumps({"ts": ts, "leg": "vps", "target": "85.136.181.198",
                                "sent": 3, "recv": 3, "avg_ms": 230.0}))
    rows.append(json.dumps({"ts": now - 1000 + 310, "leg": "ssid",
                            "target": "192.168.3.1", "ssid": "HomeWifi"}))
    netlog.write_text("\n".join(rows) + "\n", encoding="utf-8")
    monkeypatch.setattr(diag_netprobe, "NETPROBE_LOG", netlog)
    monkeypatch.setattr(diag_netprobe.metrics_store, "METRICS_LOG", tunnel)

    diag_netprobe.report()

    out = capsys.readouterr().out
    assert "блэкаут-окон туннеля за это время: 1" in out
    vps_line = next(line for line in out.splitlines() if line.startswith("vps"))
    # фейлы туннеля на смещениях 60–80с, окно ±120с → inside = i*30 ∈ [0,200] → 7 раундов
    assert "7 раундов, потери 0/21" in vps_line, "ssid-строка не посчитана раундом"
    assert "20 раундов, потери 0/60" in vps_line, "7+20=27 vps-строк; ssid-строка исключена"
