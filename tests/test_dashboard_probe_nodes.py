import importlib
import json
import sys
import time
import types

import sys_probe


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


def _write_state(path, state):
    path.write_text(json.dumps(state), encoding="utf-8")


def test_parse_ping_stats_direct(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    out = (
        "3 packets transmitted, 3 packets received, 0.0% packet loss\n"
        "round-trip min/avg/max/stddev = 10.123/20.456/30.789/1.000 ms"
    )

    ping_ms, loss = dashboard._parse_ping_stats(out)

    assert ping_ms == 20
    assert loss == 0.0


def test_parse_throughput_output_direct(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)

    assert dashboard._parse_throughput_output("200 0.500000 2048", expected_bytes=2048) == 33
    assert dashboard._parse_throughput_output("000 0.500000 2048", expected_bytes=2048) is None
    assert dashboard._parse_throughput_output("200 0 2048", expected_bytes=2048) is None


def test_probe_nodes_reads_enabled_nodes_and_state_targets_read_only(monkeypatch, tmp_path):
    dashboard = _fresh_dashboard(monkeypatch)
    dashboard_geo = importlib.import_module("dashboard_geo")
    state_path = tmp_path / "srouter.local.json"
    state = {
        "nodes": [
            {
                "name": "sg-1",
                "endpoint_host": "203.0.113.10",
                "route_ip": "203.0.113.10",
                "enabled": True,
                "probe": {"socks_port": 11080},
            },
            {
                "name": "hk-1",
                "endpoint_host": "203.0.113.20",
                "route_ip": "203.0.113.20",
                "enabled": True,
                "probe": {"socks_port": 11081},
            },
            {
                "name": "off",
                "endpoint_host": "203.0.113.30",
                "route_ip": "203.0.113.30",
                "enabled": False,
                "probe": {"socks_port": 11082},
            },
        ],
        "probes": {
            "reachability_targets": ["https://reach.local/ping"],
            "throughput_targets": [{"url": "https://speed.local/down?bytes=2048", "bytes": 2048}],
            "connect_timeout_sec": 2,
            "max_time_sec": 5,
        },
    }
    _write_state(state_path, state)
    before = state_path.read_text(encoding="utf-8")
    calls = []

    def fake_run(cmd, timeout):
        calls.append((cmd, timeout))
        if cmd[0] == dashboard.PING:
            return {
                "rc": 0,
                "out": (
                    "3 packets transmitted, 3 packets received, 0.0% packet loss\n"
                    "round-trip min/avg/max/stddev = 10.0/20.0/30.0/1.0 ms"
                ),
                "err": "",
                "timeout": False,
            }
        url = cmd[-1]
        if url == "https://reach.local/ping":
            return {"rc": 0, "out": "204", "err": "", "timeout": False}
        if url == "https://speed.local/down?bytes=2048":
            return {"rc": 0, "out": "200 0.500000 2048", "err": "", "timeout": False}
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(sys_probe, "run", fake_run)
    monkeypatch.setattr(sys_probe, "port_open", lambda host, port, timeout=0.5: True)
    monkeypatch.setattr(dashboard_geo, "_geo_lookup", lambda ip: {"country_code": "SG", "flag": "SG"})
    monkeypatch.setattr(
        dashboard.local_state,
        "save_state",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("probe_nodes must be read-only")),
    )

    out = dashboard.probe_nodes(state_path=state_path)

    assert [item["name"] for item in out] == ["sg-1", "hk-1"]
    assert all(
        set(item) == {"name", "endpoint_host", "route_ip", "ping_ms", "loss", "throughput_kbps", "geo", "status"}
        for item in out
    )
    assert all(item["ping_ms"] == 20 for item in out)
    assert all(item["loss"] == 0.0 for item in out)
    assert all(item["throughput_kbps"] == 33 for item in out)
    assert all(item["geo"]["country_code"] == "SG" for item in out)
    assert all(item["status"] == "ok" for item in out)
    assert state_path.read_text(encoding="utf-8") == before

    curl_calls = [cmd for cmd, _timeout in calls if cmd[0] == dashboard.CURL]
    assert {cmd[-1] for cmd in curl_calls} == {"https://reach.local/ping", "https://speed.local/down?bytes=2048"}
    assert any("socks5h://127.0.0.1:11080" in cmd for cmd in curl_calls)
    assert any("socks5h://127.0.0.1:11081" in cmd for cmd in curl_calls)
    assert all("--connect-timeout" in cmd and "2" in cmd for cmd in curl_calls)
    assert all("--max-time" in cmd and "5" in cmd for cmd in curl_calls)


def test_probe_nodes_missing_or_invalid_socks_degrades_without_curl(monkeypatch, tmp_path):
    dashboard = _fresh_dashboard(monkeypatch)
    dashboard_geo = importlib.import_module("dashboard_geo")
    state_path = tmp_path / "srouter.local.json"
    _write_state(
        state_path,
        {
            "nodes": [
                {"name": "no-probe", "endpoint_host": "203.0.113.10", "route_ip": "203.0.113.10", "enabled": True},
                {
                    "name": "bad-probe",
                    "endpoint_host": "203.0.113.20",
                    "route_ip": "203.0.113.20",
                    "enabled": True,
                    "probe": {"socks_port": "bad"},
                },
            ]
        },
    )
    calls = []

    def fake_run(cmd, timeout):
        calls.append(cmd)
        if cmd[0] == dashboard.PING:
            return {"rc": 1, "out": "3 packets transmitted, 0 packets received, 100.0% packet loss", "err": "", "timeout": False}
        raise AssertionError("curl must not run without valid per-node socks_port")

    monkeypatch.setattr(sys_probe, "run", fake_run)
    monkeypatch.setattr(dashboard_geo, "_geo_lookup", lambda ip: {})

    out = dashboard.probe_nodes(state_path=state_path)

    assert [item["name"] for item in out] == ["no-probe", "bad-probe"]
    assert all(item["throughput_kbps"] is None for item in out)
    assert all(item["status"] in ("down", "unknown") for item in out)
    assert all(call[0] == dashboard.PING for call in calls)


def test_gather_status_returns_node_snapshot_without_running_heavy_probe(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    dashboard._cache.update(ts=0.0, data=None)
    called = False

    for name in (
        "probe_services",
        "probe_tunnel",
        "probe_exit_ip",
        "probe_vpn",
        "probe_route_to_vps",
        "probe_direct",
        "probe_connectivity",
        "probe_ips",
        "probe_ping",
        "probe_dns",
        "probe_ifaces",
        "probe_geo_distance",
    ):
        monkeypatch.setattr(dashboard, name, lambda *args, name=name, **kwargs: {"status": "ok", "probe": name})

    def slow_probe_nodes():
        nonlocal called
        called = True
        time.sleep(0.2)
        return [{"name": "sg-1", "status": "ok"}]

    monkeypatch.setattr(dashboard, "probe_nodes", slow_probe_nodes)
    monkeypatch.setattr(
        dashboard.local_state,
        "enabled_nodes",
        lambda path=None: [{"name": "sg-1", "endpoint_host": "203.0.113.10", "route_ip": "203.0.113.10", "enabled": True}],
    )

    started = time.monotonic()
    out = dashboard.gather_status()
    elapsed = time.monotonic() - started

    assert elapsed < 0.1
    assert called is False
    assert out["nodes"] == [
        {
            "name": "sg-1",
            "endpoint_host": "203.0.113.10",
            "route_ip": "203.0.113.10",
            "ping_ms": None,
            "loss": None,
            "throughput_kbps": None,
            "geo": {},
            "status": "unknown",
        }
    ]


def test_gather_status_timeout_does_not_wait_for_executor_shutdown(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    dashboard._cache.update(ts=0.0, data=None)
    monkeypatch.setattr(dashboard, "STATUS_PROBE_BUDGET_SEC", 0.01)

    def slow_probe():
        time.sleep(0.2)
        return {"status": "ok"}

    for name in (
        "probe_services",
        "probe_tunnel",
        "probe_exit_ip",
        "probe_vpn",
        "probe_route_to_vps",
        "probe_direct",
        "probe_connectivity",
        "probe_ips",
        "probe_ping",
        "probe_dns",
        "probe_ifaces",
        "probe_geo_distance",
    ):
        monkeypatch.setattr(
            dashboard,
            name,
            slow_probe if name == "probe_services" else lambda *args, **kwargs: {"status": "ok"},
        )
    monkeypatch.setattr(dashboard, "probe_nodes_snapshot", lambda: [])

    started = time.monotonic()
    out = dashboard.gather_status()
    elapsed = time.monotonic() - started

    assert elapsed < 0.1
    assert out["services"]["status"] == "unknown"
    assert out["tunnel"]["status"] == "ok"
    assert out["nodes"] == []


def test_api_probe_nodes_is_explicit_heavy_probe_endpoint(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard, "probe_nodes", lambda: [{"name": "sg-1", "status": "ok"}])

    response = dashboard.app.test_client().get("/api/probe/nodes")

    assert response.status_code == 200
    assert response.get_json() == [{"name": "sg-1", "status": "ok"}]
