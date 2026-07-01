import importlib
import sys
import types

import pytest
import sys_probe


ACTIVE_NODE = {
    "name": "sg-1",
    "endpoint_host": "node.example.test",
    "enabled": True,
}


def _fresh_dashboard(monkeypatch):
    monkeypatch.delitem(sys.modules, "dashboard", raising=False)
    cfg = types.ModuleType("srouter_config")
    cfg.GATEWAY = "192.0.2.1"
    cfg.VPN_SERVER = "198.51.100.20"
    cfg.VPN_EXIT_IP = "198.51.100.20"
    monkeypatch.setitem(sys.modules, "srouter_config", cfg)
    dashboard = importlib.import_module("dashboard")
    dashboard._cache.update(ts=0.0, data=None, active_route_ip="", active_route_key=None)
    dashboard._nodes_cache.update(ts=0.0, data=None)
    return dashboard


def _ok(out=""):
    return {"rc": 0, "out": out, "err": "", "timeout": False}


def _install_active_route(monkeypatch, dashboard, route_ip="203.0.113.44"):
    seen = {}
    active = dict(ACTIVE_NODE)

    def active_node():
        seen["active_called"] = True
        return active

    def resolve_route_ip(node, path=None):
        seen["resolved_node"] = node
        seen["path"] = path
        return route_ip

    monkeypatch.setattr(dashboard.local_state, "active_node", active_node)
    monkeypatch.setattr(dashboard.local_state, "resolve_route_ip", resolve_route_ip)
    return seen


def _install_runner(monkeypatch, result=None):
    calls = []

    def fake_run(cmd, timeout):
        calls.append((list(cmd), timeout))
        return result or _ok()

    monkeypatch.setattr(sys_probe, "run", fake_run)
    return calls


def test_api_route_host_add_uses_resolved_route_ip_and_osascript_argv(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    seen = _install_active_route(monkeypatch, dashboard, route_ip="203.0.113.44")
    calls = _install_runner(monkeypatch)

    response = dashboard.app.test_client().post("/api/route/host", json={"action": "add"})

    assert response.status_code == 200
    body = response.get_json()
    assert body["ok"] is True
    assert body["action"] == "add"
    assert body["route_ip"] == "203.0.113.44"
    assert seen["resolved_node"] == ACTIVE_NODE
    assert seen["path"] is None
    assert len(calls) == 1
    cmd, timeout = calls[0]
    assert isinstance(cmd, list)
    assert timeout == 60
    assert cmd[:2] == [dashboard.OSASCRIPT, "-e"]
    script = cmd[2]
    assert f"{dashboard.ROUTE} -n add -host 203.0.113.44 {dashboard.GATEWAY}" in script
    assert ACTIVE_NODE["endpoint_host"] not in script


@pytest.mark.parametrize(
    ("payload_action", "expected_action", "expected_route_fragment"),
    [
        ("remove", "remove", "/sbin/route -n delete -host 203.0.113.45"),
        ("del", "remove", "/sbin/route -n delete -host 203.0.113.45"),
    ],
)
def test_api_route_host_remove_and_del_alias(monkeypatch, payload_action, expected_action, expected_route_fragment):
    dashboard = _fresh_dashboard(monkeypatch)
    _install_active_route(monkeypatch, dashboard, route_ip="203.0.113.45")
    calls = _install_runner(monkeypatch)

    response = dashboard.app.test_client().post("/api/route/host", json={"action": payload_action})

    assert response.status_code == 200
    body = response.get_json()
    assert body["ok"] is True
    assert body["action"] == expected_action
    assert body["route_ip"] == "203.0.113.45"
    assert len(calls) == 1
    assert expected_route_fragment in calls[0][0][2]


@pytest.mark.parametrize(
    "request_kwargs",
    [
        {},
        {"json": {}},
        {"json": {"action": ""}},
        {"json": {"action": "foo"}},
        {"json": {"action": "delete"}},
    ],
)
def test_api_route_host_rejects_bad_action_before_mutation(monkeypatch, request_kwargs):
    dashboard = _fresh_dashboard(monkeypatch)
    state_calls = []
    run_calls = []

    def fail_active_node():
        state_calls.append("active_node")
        raise AssertionError("bad action must not resolve route_ip")

    def fail_run(cmd, timeout):
        run_calls.append((cmd, timeout))
        raise AssertionError("bad action must not call runner")

    monkeypatch.setattr(dashboard.local_state, "active_node", fail_active_node)
    monkeypatch.setattr(sys_probe, "run", fail_run)

    response = dashboard.app.test_client().post("/api/route/host", **request_kwargs)

    assert response.status_code == 400
    assert response.get_json() == {"ok": False, "err": "bad action"}
    assert state_calls == []
    assert run_calls == []


@pytest.mark.parametrize("route_ip", ["", "node.example.test", "203.0.113.44; rm -rf /"])
def test_api_route_host_rejects_missing_or_non_literal_route_ip_fail_closed(monkeypatch, route_ip):
    dashboard = _fresh_dashboard(monkeypatch)
    _install_active_route(monkeypatch, dashboard, route_ip=route_ip)
    calls = _install_runner(monkeypatch)

    assert dashboard._active_host_route_ip() == ""

    response = dashboard.app.test_client().post("/api/route/host", json={"action": "add"})

    assert response.status_code == 200
    body = response.get_json()
    assert body["ok"] is False
    assert body["route_ip"] == ""
    assert "active route_ip" in body["err"]
    assert calls == []


def test_api_route_host_osascript_cancel_is_structured(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    _install_active_route(monkeypatch, dashboard)
    _install_runner(monkeypatch, {"rc": -128, "out": "", "err": "User canceled.", "timeout": False})

    response = dashboard.app.test_client().post("/api/route/host", json={"action": "add"})

    assert response.status_code == 200
    body = response.get_json()
    assert body["ok"] is False
    assert body["cancelled"] is True
    assert body["rc"] == -128


def test_api_route_host_nonzero_rc_is_failure(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    _install_active_route(monkeypatch, dashboard)
    _install_runner(monkeypatch, {"rc": 7, "out": "", "err": "route failed", "timeout": False})

    response = dashboard.app.test_client().post("/api/route/host", json={"action": "add"})

    assert response.status_code == 200
    body = response.get_json()
    assert body["ok"] is False
    assert body["cancelled"] is False
    assert body["rc"] == 7
    assert body["err"] == "route failed"


@pytest.mark.parametrize(
    "request_kwargs",
    [
        {"json": {"action": "add"}},
        {"data": {"action": "remove"}},
        {"query_string": {"action": "del"}},
    ],
)
def test_api_route_host_reads_action_from_json_form_or_query(monkeypatch, request_kwargs):
    dashboard = _fresh_dashboard(monkeypatch)
    _install_active_route(monkeypatch, dashboard)
    calls = _install_runner(monkeypatch)

    response = dashboard.app.test_client().post("/api/route/host", **request_kwargs)

    assert response.status_code == 200
    assert response.get_json()["ok"] is True
    assert len(calls) == 1


def test_api_route_existing_contract_survives_route_result_refactor(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)

    def fake_sudo_route(action):
        assert action == "add"
        return {"rc": 1, "out": "stdout", "err": "User canceled. (-128)", "timeout": False}

    monkeypatch.setattr(dashboard, "sudo_route", fake_sudo_route)

    response = dashboard.app.test_client().post("/api/route/add")

    assert response.status_code == 200
    assert response.get_json() == {
        "ok": False,
        "cancelled": True,
        "rc": 1,
        "out": "stdout",
        "err": "User canceled. (-128)",
        "timeout": False,
    }
