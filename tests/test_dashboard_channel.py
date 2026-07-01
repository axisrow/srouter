import importlib
import sys
import types

import pytest
import sys_probe


NETWORK_SERVICES = """An asterisk (*) denotes that a network service is disabled.
Wi-Fi
iPhone USB
Thunderbolt Bridge
"""

HARDWARE_PORTS = """Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 00:11:22:33:44:55

Hardware Port: iPhone USB
Device: en5
Ethernet Address: aa:bb:cc:dd:ee:ff
"""


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


def _ok(out=""):
    return {"rc": 0, "out": out, "err": "", "timeout": False}


def _state(wifi="Wi-Fi", usb="iPhone USB"):
    return {
        "network": {
            "channels": {
                "wifi_service": wifi,
                "usb_tether_service": usb,
            }
        }
    }


def _install_channel_runner(monkeypatch, dashboard, osascript_result=None, services=NETWORK_SERVICES, ports=HARDWARE_PORTS):
    calls = []

    def fake_run(cmd, timeout):
        calls.append((list(cmd), timeout))
        if cmd == [dashboard.NETWORKSETUP, "-listallnetworkservices"]:
            return _ok(services)
        if cmd == [dashboard.NETWORKSETUP, "-listallhardwareports"]:
            return _ok(ports)
        if cmd[0] == dashboard.OSASCRIPT:
            return osascript_result or _ok()
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(sys_probe, "run", fake_run)
    return calls


def _osascript_calls(calls, dashboard):
    return [cmd for cmd, _timeout in calls if cmd and cmd[0] == dashboard.OSASCRIPT]


def test_parse_network_services_strips_disabled_marker(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    text = """An asterisk (*) denotes that a network service is disabled.
*Wi-Fi
 iPhone USB

Thunderbolt Bridge
"""

    assert dashboard._parse_network_services(text) == ["Wi-Fi", "iPhone USB", "Thunderbolt Bridge"]


def test_known_service_name_matches_case_insensitively(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    services = ["Wi-Fi", "iPhone USB"]

    assert dashboard._known_service_name("wi-fi", services) == "Wi-Fi"
    assert dashboard._known_service_name(" IPHONE USB ", services) == "iPhone USB"
    assert dashboard._known_service_name("Bluetooth", services) == ""


def test_switch_channel_wifi_uses_osascript_with_validated_service(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard.local_state, "load_state", lambda path=None: _state())
    calls = _install_channel_runner(monkeypatch, dashboard)

    out = dashboard.switch_channel("wifi")

    assert out["ok"] is True
    assert out["target"] == "wifi"
    assert out["service"] == "Wi-Fi"
    osascript = _osascript_calls(calls, dashboard)
    assert len(osascript) == 1
    assert osascript[0][0:2] == [dashboard.OSASCRIPT, "-e"]
    assert all(isinstance(cmd, list) for cmd, _timeout in calls)
    script = osascript[0][2]
    assert "do shell script" in script
    assert f"{dashboard.NETWORKSETUP} -setnetworkserviceenabled Wi-Fi on" in script
    assert "-ordernetworkservices Wi-Fi 'iPhone USB' 'Thunderbolt Bridge'" in script


def test_switch_channel_usb_uses_osascript_with_validated_service(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard.local_state, "load_state", lambda path=None: _state())
    calls = _install_channel_runner(monkeypatch, dashboard)

    out = dashboard.switch_channel("usb")

    assert out["ok"] is True
    assert out["target"] == "usb"
    assert out["service"] == "iPhone USB"
    osascript = _osascript_calls(calls, dashboard)
    assert len(osascript) == 1
    assert osascript[0][0:2] == [dashboard.OSASCRIPT, "-e"]
    assert all(isinstance(cmd, list) for cmd, _timeout in calls)
    script = osascript[0][2]
    assert f"{dashboard.NETWORKSETUP} -setnetworkserviceenabled 'iPhone USB' on" in script
    assert "-ordernetworkservices 'iPhone USB' Wi-Fi 'Thunderbolt Bridge'" in script


@pytest.mark.parametrize("target", ["bluetooth", "auto", "", "wifi; rm -rf /"])
def test_switch_channel_rejects_non_whitelisted_targets_before_mutation(monkeypatch, target):
    dashboard = _fresh_dashboard(monkeypatch)
    calls = []

    def fail_run(cmd, timeout):
        calls.append(cmd)
        raise AssertionError("invalid channel target must not call runner")

    monkeypatch.setattr(sys_probe, "run", fail_run)

    out = dashboard.switch_channel(target)

    assert out == {
        "ok": False,
        "rc": None,
        "out": "",
        "err": "bad channel target",
        "cancelled": False,
        "timeout": False,
        "target": target,
        "service": "",
    }
    assert calls == []


def test_switch_channel_user_cancel_is_structured(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard.local_state, "load_state", lambda path=None: _state())
    calls = _install_channel_runner(
        monkeypatch,
        dashboard,
        osascript_result={"rc": -128, "out": "", "err": "User canceled.", "timeout": False},
    )

    out = dashboard.switch_channel("wifi")

    assert out["ok"] is False
    assert out["cancelled"] is True
    assert out["rc"] == -128
    assert len(_osascript_calls(calls, dashboard)) == 1


def test_switch_channel_osascript_failure_is_structured(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard.local_state, "load_state", lambda path=None: _state())
    _install_channel_runner(
        monkeypatch,
        dashboard,
        osascript_result={"rc": 7, "out": "", "err": "networksetup failed", "timeout": False},
    )

    out = dashboard.switch_channel("usb")

    assert out["ok"] is False
    assert out["cancelled"] is False
    assert out["rc"] == 7
    assert out["err"] == "networksetup failed"
    assert out["timeout"] is False


def test_switch_channel_osascript_timeout_is_structured(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard.local_state, "load_state", lambda path=None: _state())
    _install_channel_runner(
        monkeypatch,
        dashboard,
        osascript_result={"rc": None, "out": "", "err": "timeout", "timeout": True},
    )

    out = dashboard.switch_channel("wifi")

    assert out["ok"] is False
    assert out["cancelled"] is False
    assert out["timeout"] is True
    assert out["err"] == "timeout"


def test_switch_channel_missing_service_does_not_call_osascript(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard.local_state, "load_state", lambda path=None: _state(wifi="", usb=""))
    calls = _install_channel_runner(
        monkeypatch,
        dashboard,
        services="Thunderbolt Bridge\n",
        ports=HARDWARE_PORTS,
    )

    out = dashboard.switch_channel("wifi")

    assert out["ok"] is False
    assert "not found" in out["err"]
    assert out["target"] == "wifi"
    assert out["service"] == ""
    assert _osascript_calls(calls, dashboard) == []


def test_switch_channel_usb_without_config_or_hardware_match_fails_closed(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard.local_state, "load_state", lambda path=None: _state(wifi="", usb=""))
    calls = _install_channel_runner(
        monkeypatch,
        dashboard,
        services=NETWORK_SERVICES,
        ports="",
    )

    out = dashboard.switch_channel("usb")

    assert out["ok"] is False
    assert "not found" in out["err"]
    assert out["service"] == ""
    assert _osascript_calls(calls, dashboard) == []


def test_switch_channel_usb_configured_service_survives_missing_hardware_probe(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard.local_state, "load_state", lambda path=None: _state(wifi="", usb="iPhone USB"))
    calls = _install_channel_runner(
        monkeypatch,
        dashboard,
        services=NETWORK_SERVICES,
        ports="",
    )

    out = dashboard.switch_channel("usb")

    assert out["ok"] is True
    assert out["service"] == "iPhone USB"
    assert len(_osascript_calls(calls, dashboard)) == 1


def test_api_channel_wifi_success_and_bad_targets(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    calls = []

    def fake_switch(target):
        calls.append(target)
        return {
            "ok": True,
            "rc": 0,
            "out": "",
            "err": "",
            "cancelled": False,
            "timeout": False,
            "target": target,
            "service": "Wi-Fi",
        }

    monkeypatch.setattr(dashboard, "switch_channel", fake_switch)
    client = dashboard.app.test_client()

    ok = client.post("/api/channel/wifi")
    bad = client.post("/api/channel/bluetooth")
    empty = client.post("/api/channel")
    empty_slash = client.post("/api/channel/")

    assert ok.status_code == 200
    assert ok.get_json()["ok"] is True
    assert bad.status_code == 400
    assert bad.get_json() == {"ok": False, "err": "bad channel target"}
    assert empty.status_code == 400
    assert empty.get_json() == {"ok": False, "err": "bad channel target"}
    assert empty_slash.status_code == 400
    assert calls == ["wifi"]


def test_api_channel_incidental_minus_128_is_failure_not_cancel(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard.local_state, "load_state", lambda path=None: _state())
    _install_channel_runner(
        monkeypatch,
        dashboard,
        osascript_result={"rc": 7, "out": "", "err": "networksetup detail -128 but not osascript cancel", "timeout": False},
    )

    response = dashboard.app.test_client().post("/api/channel/wifi")

    assert response.status_code == 500
    body = response.get_json()
    assert body["ok"] is False
    assert body["cancelled"] is False
    assert body["rc"] == 7


def test_switch_channel_canonical_osascript_cancel_marker_is_cancelled(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard.local_state, "load_state", lambda path=None: _state())
    _install_channel_runner(
        monkeypatch,
        dashboard,
        osascript_result={"rc": 1, "out": "", "err": "User canceled. (-128)", "timeout": False},
    )

    out = dashboard.switch_channel("wifi")

    assert out["ok"] is False
    assert out["cancelled"] is True


def test_security_rejects_injected_target_without_runner_call(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    calls = []

    def fail_run(cmd, timeout):
        calls.append(cmd)
        raise AssertionError("injected target must not reach runner")

    monkeypatch.setattr(sys_probe, "run", fail_run)

    out = dashboard.switch_channel("wifi; rm -rf /")

    assert out["ok"] is False
    assert out["err"] == "bad channel target"
    assert calls == []


def test_security_shell_command_uses_validated_service_not_configured_injection(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard.local_state, "load_state", lambda path=None: _state(wifi="Wi-Fi; rm -rf /"))
    calls = _install_channel_runner(monkeypatch, dashboard)

    out = dashboard.switch_channel("wifi")

    assert out["ok"] is True
    assert out["service"] == "Wi-Fi"
    script = _osascript_calls(calls, dashboard)[0][2]
    assert "rm -rf" not in script
    assert "Wi-Fi; rm -rf /" not in script
    assert f"{dashboard.NETWORKSETUP} -setnetworkserviceenabled Wi-Fi on" in script
