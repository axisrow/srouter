import importlib
import sys
import types


def _fresh_dashboard(monkeypatch):
    monkeypatch.delitem(sys.modules, "dashboard", raising=False)
    cfg = types.ModuleType("srouter_config")
    cfg.GATEWAY = "192.0.2.1"
    cfg.VPN_SERVER = "198.51.100.20"
    cfg.VPN_EXIT_IP = "198.51.100.20"
    monkeypatch.setitem(sys.modules, "srouter_config", cfg)
    dashboard = importlib.import_module("dashboard")
    dashboard._cache.update(ts=0.0, data=None)
    dashboard._nodes_cache.update(ts=0.0, data=None)
    return dashboard


NETWORKSETUP_WIFI = """Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 00:11:22:33:44:55

Hardware Port: iPhone USB
Device: en5
Ethernet Address: aa:bb:cc:dd:ee:ff
"""


IFCONFIG_WIFI = """en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
    inet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255
    status: active
en5: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
    inet 172.20.10.2 netmask 0xfffffff0 broadcast 172.20.10.15
    status: active
"""


def test_probe_connectivity_classifies_wifi_and_real_reachability(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)

    def fake_run(cmd, timeout):
        if cmd == [dashboard.ROUTE, "-n", "get", "default"]:
            return {"rc": 0, "out": "interface: en0", "err": "", "timeout": False}
        if cmd == [dashboard.IFCONFIG]:
            return {"rc": 0, "out": IFCONFIG_WIFI, "err": "", "timeout": False}
        if cmd == [dashboard.NETWORKSETUP, "-listallhardwareports"]:
            return {"rc": 0, "out": NETWORKSETUP_WIFI, "err": "", "timeout": False}
        if cmd[0] == dashboard.CURL:
            return {"rc": 0, "out": "204 0.125000", "err": "", "timeout": False}
        raise AssertionError(cmd)

    monkeypatch.setattr(dashboard, "run", fake_run)

    out = dashboard.probe_connectivity()

    assert out["active_iface"] == "en0"
    assert out["channel"] == "wifi"
    assert out["hardware_port"] == "Wi-Fi"
    assert out["reachable"] is True
    assert out["reachability"]["code"] == "204"
    assert out["reachability"]["ms"] == 125
    assert out["metered"] is None
    assert out["status"] == "ok"


def test_probe_connectivity_classifies_iphone_usb_as_metered(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)

    def fake_run(cmd, timeout):
        if cmd == [dashboard.ROUTE, "-n", "get", "default"]:
            return {"rc": 0, "out": "interface: en5", "err": "", "timeout": False}
        if cmd == [dashboard.IFCONFIG]:
            return {"rc": 0, "out": IFCONFIG_WIFI, "err": "", "timeout": False}
        if cmd == [dashboard.NETWORKSETUP, "-listallhardwareports"]:
            return {"rc": 0, "out": NETWORKSETUP_WIFI, "err": "", "timeout": False}
        if cmd[0] == dashboard.CURL:
            return {"rc": 0, "out": "200 0.250000", "err": "", "timeout": False}
        raise AssertionError(cmd)

    monkeypatch.setattr(dashboard, "run", fake_run)

    out = dashboard.probe_connectivity()

    assert out["active_iface"] == "en5"
    assert out["channel"] == "usb_tether"
    assert out["hardware_port"] == "iPhone USB"
    assert out["metered"] is True
    assert out["metered_reason"] == "usb_tether"
    assert out["reachable"] is True
    assert out["status"] == "ok"


def test_probe_connectivity_classifies_other_and_down_reachability(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    networksetup = """Hardware Port: Thunderbolt Ethernet
Device: en7
Ethernet Address: 12:34:56:78:90:ab
"""
    ifconfig = """en7: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
    inet 10.0.0.12 netmask 0xffffff00 broadcast 10.0.0.255
    status: active
"""

    def fake_run(cmd, timeout):
        if cmd == [dashboard.ROUTE, "-n", "get", "default"]:
            return {"rc": 0, "out": "interface: en7", "err": "", "timeout": False}
        if cmd == [dashboard.IFCONFIG]:
            return {"rc": 0, "out": ifconfig, "err": "", "timeout": False}
        if cmd == [dashboard.NETWORKSETUP, "-listallhardwareports"]:
            return {"rc": 0, "out": networksetup, "err": "", "timeout": False}
        if cmd[0] == dashboard.CURL:
            return {"rc": 28, "out": "000 0.000000", "err": "", "timeout": False}
        raise AssertionError(cmd)

    monkeypatch.setattr(dashboard, "run", fake_run)

    out = dashboard.probe_connectivity()

    assert out["active_iface"] == "en7"
    assert out["channel"] == "other"
    assert out["reachable"] is False
    assert out["status"] == "down"


def test_probe_direct_reachability_empty_output_is_unknown(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)

    def fake_run(cmd, timeout):
        if cmd[0] == dashboard.CURL:
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        raise AssertionError(cmd)

    monkeypatch.setattr(dashboard, "run", fake_run)

    out = dashboard._probe_direct_reachability()

    assert out["reachable"] is None
    assert out["status"] == "unknown"


def test_probe_direct_reachability_curl_000_is_down(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)

    def fake_run(cmd, timeout):
        if cmd[0] == dashboard.CURL:
            return {"rc": 28, "out": "000 0.000000", "err": "", "timeout": False}
        raise AssertionError(cmd)

    monkeypatch.setattr(dashboard, "run", fake_run)

    out = dashboard._probe_direct_reachability()

    assert out["reachable"] is False
    assert out["status"] == "down"


def test_probe_connectivity_unknown_channel_with_reachability_is_not_ok(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)

    def fake_run(cmd, timeout):
        if cmd == [dashboard.ROUTE, "-n", "get", "default"]:
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        if cmd == [dashboard.IFCONFIG]:
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        if cmd == [dashboard.NETWORKSETUP, "-listallhardwareports"]:
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        if cmd[0] == dashboard.CURL:
            return {"rc": 0, "out": "200 0.100000", "err": "", "timeout": False}
        raise AssertionError(cmd)

    monkeypatch.setattr(dashboard, "run", fake_run)

    out = dashboard.probe_connectivity()

    assert out["channel"] == "unknown"
    assert out["reachable"] is True
    assert out["status"] == "unknown"


def test_probe_connectivity_defensive_on_empty_ifconfig_and_curl_timeout(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)

    def fake_run(cmd, timeout):
        if cmd == [dashboard.ROUTE, "-n", "get", "default"]:
            return {"rc": 0, "out": "interface: en0", "err": "", "timeout": False}
        if cmd == [dashboard.IFCONFIG]:
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        if cmd == [dashboard.NETWORKSETUP, "-listallhardwareports"]:
            return {"rc": 1, "out": "", "err": "missing", "timeout": False}
        if cmd[0] == dashboard.CURL:
            return {"rc": None, "out": "", "err": "timeout", "timeout": True}
        raise AssertionError(cmd)

    monkeypatch.setattr(dashboard, "run", fake_run)

    out = dashboard.probe_connectivity()

    assert out["active_iface"] == "en0"
    assert out["channel"] == "unknown"
    assert out["reachable"] is None
    assert out["reachability"]["status"] == "unknown"
    assert out["status"] == "unknown"


def test_gather_status_registers_connectivity_probe(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    seen = {}

    def fake_run_probe_set(probes, budget_sec):
        seen.update(probes)
        return {name: {"status": "ok"} for name in probes}

    monkeypatch.setattr(dashboard, "_run_status_probe_set", fake_run_probe_set)
    monkeypatch.setattr(dashboard, "probe_nodes_snapshot", lambda: [])

    out = dashboard.gather_status()

    assert "connectivity" in seen
    assert out["connectivity"] == {"status": "ok"}
