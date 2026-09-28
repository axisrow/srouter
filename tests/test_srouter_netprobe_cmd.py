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


# ============================ netname — автоопределение сети по отпечатку ============================
def test_dns_servers_parses_resolv(tmp_path):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text(
        "# комментарий\nnameserver 211.136.192.6\nnameserver fe80::52f7:edff:fe36:9923%en0\n"
        "search lan\n", encoding="utf-8")
    assert diag_netprobe._dns_servers(resolv) == ("211.136.192.6", "fe80::52f7:edff:fe36:9923%en0")


def test_dns_servers_missing_file(tmp_path):
    assert diag_netprobe._dns_servers(tmp_path / "absent.conf") == ()


def test_net_name_matches_by_dns_intersection(monkeypatch, tmp_path):
    nets = tmp_path / "nets.json"
    nets.write_text(json.dumps({
        "103": {"dns": ["192.168.3.1", "fe80::52f7:edff:fe36:9923%en0"]},
        "888-5G": {"dns": ["211.136.192.6", "120.196.165.24"]},
    }), encoding="utf-8")
    monkeypatch.setattr(diag_netprobe, "NETS_MAP", nets)
    assert diag_netprobe._net_name(("120.196.165.24",)) == "888-5G"
    assert diag_netprobe._net_name(("192.168.3.1",)) == "103"


def test_net_name_none_without_match_or_map(monkeypatch, tmp_path):
    monkeypatch.setattr(diag_netprobe, "NETS_MAP", tmp_path / "absent.json")
    assert diag_netprobe._net_name(("8.8.8.8",)) is None
    assert diag_netprobe._net_name(()) is None


def test_learn_net_writes_and_replaces(monkeypatch, tmp_path):
    nets = tmp_path / "nets.json"
    monkeypatch.setattr(diag_netprobe, "NETS_MAP", nets)
    monkeypatch.setattr(diag_netprobe, "_default_route", lambda: (None, "ipsec0"))
    monkeypatch.setattr(diag_netprobe, "_dns_servers",
                        lambda path=None: ("211.136.192.6",))
    monkeypatch.setattr(diag_netprobe, "run",
                        lambda cmd, timeout, **kw: {"rc": 0, "err": "", "timeout": False,
                                                    "out": "   router 10.9.9.1\n"})
    monkeypatch.setattr(diag_netprobe, "_gateway_mac", lambda ip: "b6:00:11:22:33:44")

    diag_netprobe.learn_net("888-5G")
    first = json.loads(nets.read_text(encoding="utf-8"))
    assert first["888-5G"]["dns"] == ["211.136.192.6"]
    assert first["888-5G"]["iface"] == "en0", "туннельный default → физический en0"
    assert first["888-5G"]["gateway"] == "10.9.9.1"

    monkeypatch.setattr(diag_netprobe, "_dns_servers", lambda path=None: ("192.168.3.1",))
    monkeypatch.setattr(diag_netprobe, "_default_route", lambda: ("192.168.3.1", "en0"))
    monkeypatch.setattr(diag_netprobe, "_gateway_mac", lambda ip: "a4:2b:8c:11:22:33")
    diag_netprobe.learn_net("888-5G")
    replaced = json.loads(nets.read_text(encoding="utf-8"))
    assert replaced["888-5G"]["dns"] == ["192.168.3.1"], "повторный learn перезаписывает"
    assert replaced["888-5G"]["gateway_mac"] == "a4:2b:8c:11:22:33", \
        "learn запоминает MAC шлюза — дискриминатор hotspot vs роутер"


# ---------- MAC шлюза из ARP — дискриминатор «мобилка ≠ домашний Wi-Fi» ----------

def _mock_arp(monkeypatch, out, rc=0):
    monkeypatch.setattr(diag_netprobe, "run",
                        lambda cmd, timeout, **kw: {"rc": rc, "out": out, "err": "",
                                                    "timeout": False})


def test_gateway_mac_parses_arp_output(monkeypatch):
    _mock_arp(monkeypatch, "172.20.10.1 (172.20.10.1) at ae:df:a1:f0:2d:64 on en0 ifscope [ethernet]\n")
    assert diag_netprobe._gateway_mac("172.20.10.1") == "ae:df:a1:f0:2d:64"


def test_gateway_mac_soft_fails(monkeypatch):
    _mock_arp(monkeypatch, "172.20.10.1 (172.20.10.1) -- no entry\n")
    assert diag_netprobe._gateway_mac("172.20.10.1") is None, "нет ARP-записи — None"
    _mock_arp(monkeypatch, "arp: foo", rc=1)
    assert diag_netprobe._gateway_mac("foo") is None, "rc≠0 — None, не бросает"
    monkeypatch.setattr(diag_netprobe, "run",
                        lambda cmd, timeout, **kw: {"rc": None, "out": "", "err": "",
                                                    "timeout": True})
    assert diag_netprobe._gateway_mac("x") is None, "timeout — None"
    assert diag_netprobe._gateway_mac(None) is None, "без gateway arp не зовётся"


def test_net_name_matches_by_gateway_mac_even_without_dns(monkeypatch, tmp_path):
    nets = tmp_path / "nets.json"
    nets.write_text(json.dumps({
        "mobile-hotspot": {"dns": [], "gateway": "172.20.10.1",
                           "gateway_mac": "ae:df:a1:f0:2d:64"},
    }), encoding="utf-8")
    monkeypatch.setattr(diag_netprobe, "NETS_MAP", nets)
    assert diag_netprobe._net_name(("8.8.8.8",), gateway="172.20.10.1",
                                   gateway_mac="ae:df:a1:f0:2d:64") == "mobile-hotspot", \
        "MAC-совпадение матчит сеть даже при пустом DNS-пересечении"


def test_net_name_mac_conflict_blocks_dns(monkeypatch, tmp_path):
    """Кейс 2026-09-28: hotspot мобилки отдаёт DNS домашнего оператора — раньше склеивался
    с 888-5G. Теперь MAC в записи другой → запись блокируется, DNS не спасает."""
    nets = tmp_path / "nets.json"
    nets.write_text(json.dumps({
        "888-5G": {"dns": ["211.136.192.6", "120.196.165.24"],
                   "gateway": "192.168.1.1", "gateway_mac": "a4:2b:8c:11:22:33"},
    }), encoding="utf-8")
    monkeypatch.setattr(diag_netprobe, "NETS_MAP", nets)
    assert diag_netprobe._net_name(("211.136.192.6",), gateway="172.20.10.1",
                                   gateway_mac="ae:df:a1:f0:2d:64") is None, \
        "MAC другой — сеть не 888-5G, хотя DNS оператора совпал"


def test_net_name_gateway_conflict_blocks_dns(monkeypatch, tmp_path):
    """Запись старого формата (без MAC), но шлюз другой подсети — тоже блок."""
    nets = tmp_path / "nets.json"
    nets.write_text(json.dumps({
        "103": {"dns": ["192.168.3.1"], "gateway": "192.168.3.1"},
    }), encoding="utf-8")
    monkeypatch.setattr(diag_netprobe, "NETS_MAP", nets)
    assert diag_netprobe._net_name(("192.168.3.1",), gateway="172.20.10.1") is None


def test_net_name_gateway_match_for_legacy_record_without_mac(monkeypatch, tmp_path):
    nets = tmp_path / "nets.json"
    nets.write_text(json.dumps({
        "103": {"dns": ["192.168.3.1"], "gateway": "192.168.3.1"},
    }), encoding="utf-8")
    monkeypatch.setattr(diag_netprobe, "NETS_MAP", nets)
    assert diag_netprobe._net_name(("192.168.3.1",), gateway="192.168.3.1") == "103", \
        "старая запись без MAC матчится по шлюзу"


def test_learn_net_records_gateway_mac(monkeypatch, tmp_path):
    nets = tmp_path / "nets.json"
    monkeypatch.setattr(diag_netprobe, "NETS_MAP", nets)
    monkeypatch.setattr(diag_netprobe, "_default_route", lambda: ("172.20.10.1", "en0"))
    monkeypatch.setattr(diag_netprobe, "_dns_servers", lambda path=None: ())
    monkeypatch.setattr(diag_netprobe, "_gateway_mac",
                        lambda ip: "ae:df:a1:f0:2d:64" if ip == "172.20.10.1" else None)
    diag_netprobe.learn_net("mobile-hotspot")
    rec = json.loads(nets.read_text(encoding="utf-8"))["mobile-hotspot"]
    assert rec["gateway_mac"] == "ae:df:a1:f0:2d:64"
    assert rec["gateway"] == "172.20.10.1"


def test_learn_net_vpn_iface_uses_physical_dhcp_router(monkeypatch, tmp_path):
    """VPN перехватил default (iface=ipsec0) — learn обязан обучить физический Wi-Fi
    (DHCP-router en0), а не туннель: иначе запись мусорная (gateway=None, кейс
    2026-09-28)."""
    nets = tmp_path / "nets.json"
    monkeypatch.setattr(diag_netprobe, "NETS_MAP", nets)
    monkeypatch.setattr(diag_netprobe, "_default_route", lambda: (None, "ipsec0"))
    monkeypatch.setattr(diag_netprobe, "_dns_servers", lambda path=None: ())
    monkeypatch.setattr(diag_netprobe, "_gateway_mac", lambda ip: "ae:df:a1:f0:2d:64")
    monkeypatch.setattr(diag_netprobe, "run",
                        lambda cmd, timeout, **kw: {"rc": 0, "err": "", "timeout": False,
                                                    "out": "   router 172.20.10.1\n"})
    diag_netprobe.learn_net("mobile-hotspot")
    rec = json.loads(nets.read_text(encoding="utf-8"))["mobile-hotspot"]
    assert rec["gateway"] == "172.20.10.1" and rec["iface"] == "en0"
    assert rec["gateway_mac"] == "ae:df:a1:f0:2d:64"


def test_physical_gateway_passthrough_and_vpn_fallback(monkeypatch):
    monkeypatch.setattr(diag_netprobe, "_default_route", lambda: ("192.168.3.1", "en0"))
    assert diag_netprobe._physical_gateway() == ("192.168.3.1", "en0"), \
        "физический default — без запросов DHCP"
    monkeypatch.setattr(diag_netprobe, "_default_route", lambda: (None, "ipsec0"))
    monkeypatch.setattr(diag_netprobe, "run",
                        lambda cmd, timeout, **kw: {"rc": 0, "err": "", "timeout": False,
                                                    "out": "   router 172.20.10.1\n"})
    assert diag_netprobe._physical_gateway() == ("172.20.10.1", "en0"), \
        "туннельный default → DHCP-router en0 (MAC шлюза становится доступен)"
    monkeypatch.setattr(diag_netprobe, "run",
                        lambda cmd, timeout, **kw: {"rc": 0, "err": "", "timeout": False,
                                                    "out": ""})
    assert diag_netprobe._physical_gateway() == (None, "ipsec0"), \
        "DHCP-router не читается → честный None, не выдумка"


def test_netprobe_netname_passes_name(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    calls = []

    def runner(cmd, timeout):
        calls.append(list(cmd))
        return {"rc": 0, "out": "ok\n", "err": "", "timeout": False}

    monkeypatch.setattr(srouter_cli, "run", runner, raising=False)

    rc = srouter_cli.cmd_netprobe(argparse.Namespace(netprobe_action="netname", name="103"))

    assert rc == 0
    assert calls[0][-2:] == ["netname", "103"]


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
