import importlib
import json
import sys
import threading
import time
import types

import sys_probe


PROBE_NAMES = (
    "probe_services",
    "probe_tunnel",
    "probe_exit_ip",
    "probe_vpn",
    "probe_route_to_vps",
    "probe_direct",
    "probe_traffic_guard",
    "probe_hot_routes",
    "probe_connectivity",
    "probe_ips",
    "probe_ping",
    "probe_dns",
    "probe_ifaces",
    "probe_exit_ips_per_iface",
    "probe_geo_distance",
)


def _state(active_name="sg-1", *, nodes=None):
    return {
        "nodes": nodes
        if nodes is not None
        else [
            {
                "name": "sg-1",
                "endpoint_host": "203.0.113.10",
                "route_ip": "203.0.113.10",
                "enabled": True,
            },
            {
                "name": "hk-1",
                "endpoint_host": "203.0.113.20",
                "route_ip": "203.0.113.20",
                "enabled": True,
            },
        ],
        "active_node": {"name": active_name, "pending": None},
    }


def _write_state(path, state):
    path.write_text(json.dumps(state), encoding="utf-8")


def _fresh_dashboard(monkeypatch, state_path):
    import local_state

    monkeypatch.setattr(local_state, "_DEFAULT_PATH", state_path)
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


def test_active_route_ip_reads_changed_active_node_without_restart(monkeypatch, tmp_path):
    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, _state("sg-1"))
    dashboard = _fresh_dashboard(monkeypatch, state_path)

    assert dashboard._active_route_ip() == "203.0.113.10"

    _write_state(state_path, _state("hk-1"))

    assert dashboard._active_route_ip() == "203.0.113.20"


def test_gather_status_cache_invalidates_when_active_route_ip_changes(monkeypatch, tmp_path):
    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, _state("sg-1"))
    dashboard = _fresh_dashboard(monkeypatch, state_path)
    monkeypatch.setattr(dashboard, "STATUS_CACHE_TTL_SEC", 999)

    run_count = 0
    lock = threading.Lock()

    def fake_probe(name):
        def inner(*args, **kwargs):
            nonlocal run_count
            with lock:
                run_count += 1
                call_no = run_count
            return {"status": "ok", "probe": name, "call_no": call_no}

        return inner

    for name in PROBE_NAMES:
        monkeypatch.setattr(dashboard, name, fake_probe(name))
    monkeypatch.setattr(
        dashboard,
        "probe_nodes_snapshot",
        lambda: [{"status": "unknown"}],
    )

    first = dashboard.gather_status()
    assert run_count == len(PROBE_NAMES)
    assert dashboard._cache["active_route_ip"] == "203.0.113.10"
    assert dashboard._cache["active_route_key"] == ("sg-1", "203.0.113.10", "203.0.113.10")

    cached = dashboard.gather_status()
    assert cached is first
    assert run_count == len(PROBE_NAMES)

    _write_state(state_path, _state("hk-1"))
    second = dashboard.gather_status()

    assert second is not first
    assert run_count == len(PROBE_NAMES) * 2
    assert dashboard._cache["active_route_ip"] == "203.0.113.20"
    assert dashboard._cache["active_route_key"] == ("hk-1", "203.0.113.20", "203.0.113.20")
    assert second["nodes"] == [{"status": "unknown"}]


def test_gather_status_hostname_without_route_ip_does_not_block_on_dns(monkeypatch, tmp_path):
    import local_state

    state_path = tmp_path / "srouter.local.json"
    _write_state(
        state_path,
        _state(
            "sg-1",
            nodes=[
                {
                    "name": "sg-1",
                    "endpoint_host": "node.example.test",
                    "enabled": True,
                }
            ],
        ),
    )
    dns_calls = []

    def slow_dns(host):
        dns_calls.append(host)
        time.sleep(1.0)
        return "203.0.113.99"

    monkeypatch.setattr(local_state.socket, "gethostbyname", slow_dns)
    dashboard = _fresh_dashboard(monkeypatch, state_path)
    monkeypatch.setattr(dashboard, "STATUS_CACHE_TTL_SEC", 999)

    run_count = 0
    kwargs_seen = []

    def fake_probe(name):
        def inner(*args, **kwargs):
            nonlocal run_count
            run_count += 1
            kwargs_seen.append(kwargs)
            return {"status": "ok", "probe": name}

        return inner

    for name in PROBE_NAMES:
        monkeypatch.setattr(dashboard, name, fake_probe(name))
    monkeypatch.setattr(dashboard, "probe_nodes_snapshot", lambda: [])

    started = time.monotonic()
    first = dashboard.gather_status()
    cached = dashboard.gather_status()
    elapsed = time.monotonic() - started

    assert cached is first
    assert run_count == len(PROBE_NAMES)
    assert dashboard._cache["active_route_ip"] == ""
    assert dashboard._cache["active_route_key"] == ("sg-1", "", "node.example.test")
    assert dns_calls == []
    assert elapsed < 0.5
    assert {kwargs["route_ip"] for kwargs in kwargs_seen if "route_ip" in kwargs} == {""}


def test_empty_active_route_degrades_without_route_commands(monkeypatch, tmp_path):
    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, _state("missing", nodes=[]))
    dashboard = _fresh_dashboard(monkeypatch, state_path)
    calls = []

    def fake_run(cmd, timeout):
        calls.append(cmd)
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(sys_probe, "run", fake_run)

    assert dashboard._active_route_ip() == ""
    assert dashboard.probe_route_to_vps() == {"interface": "", "gateway": "", "split_active": False, "status": "down"}
    assert dashboard.sudo_route("add")["rc"] is None
    assert dashboard.probe_exit_ip()["status"] == "down"
    assert dashboard.probe_ips()["vps"]["ip"] == ""
    assert calls
    assert all(cmd[0] == dashboard.CURL for cmd in calls)


def test_broken_state_degrades_without_route_commands(monkeypatch, tmp_path):
    state_path = tmp_path / "srouter.local.json"
    state_path.write_text("{not-json", encoding="utf-8")
    dashboard = _fresh_dashboard(monkeypatch, state_path)

    def fail_route_run(cmd, timeout):
        raise AssertionError("route command must not run without active route_ip")

    monkeypatch.setattr(sys_probe, "run", fail_route_run)

    assert dashboard._active_route_ip() == ""
    assert dashboard.probe_route_to_vps() == {"interface": "", "gateway": "", "split_active": False, "status": "down"}
    assert dashboard.sudo_route("remove")["rc"] is None
