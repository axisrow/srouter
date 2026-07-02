import importlib
import json
import sys
import threading
import time
import types

import dashboard_hotroutes


def _write_state(path, hot_routes_config):
    path.write_text(json.dumps({"hot_routes": hot_routes_config}), encoding="utf-8")


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
    return dashboard


def test_probe_hot_routes_disabled_does_not_touch_logs(monkeypatch, tmp_path):
    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, {"enabled": False})

    def boom(*args, **kwargs):
        raise AssertionError("hot_routes must not be touched while disabled")

    monkeypatch.setattr(dashboard_hotroutes.hot_routes, "parse_access_log", boom)
    monkeypatch.setattr(dashboard_hotroutes.hot_routes, "parse_new_access_log", boom)
    monkeypatch.setattr(dashboard_hotroutes.hot_routes, "update_cache", boom)
    monkeypatch.setattr(dashboard_hotroutes.hot_routes, "hot_domains", boom)

    out = dashboard_hotroutes.probe_hot_routes(state_path=state_path)

    assert out["enabled"] is False
    assert out["status"] == "disabled"
    assert out["domains"] == []


def test_probe_hot_routes_enabled_returns_ranked_domains_with_counts(monkeypatch, tmp_path):
    state_path = tmp_path / "srouter.local.json"
    cache_path = tmp_path / "srouter.hot_routes.json"
    log_path = tmp_path / "privoxy.log"
    _write_state(state_path, {"enabled": True, "top_n": 2})

    calls = []

    def fake_parse_new_access_log(path=None, offset=None, inode=None, dev=None):
        calls.append(("parse", path, offset, inode, dev))
        return {"b.example": 1, "a.example": 3}, {
            "log_offset": 12,
            "log_inode": 34,
            "log_dev": 56,
            "log_size": 12,
        }

    def fake_update_cache(
        counts,
        path=None,
        ttl=None,
        top_n=None,
        now=None,
        *,
        bucket_size=None,
        cursor=None,
    ):
        calls.append(("update", counts, path, top_n, now, bucket_size, cursor))
        return {
            "a.example": {"domain": "a.example", "count": 3, "last_seen": 1000.0},
            "b.example": {"domain": "b.example", "count": 1, "last_seen": 1000.0},
        }

    def fake_hot_domains(path=None, top_n=None, ttl=None, now=None):
        calls.append(("hot_domains", path, top_n, now))
        return ["a.example", "b.example"]

    monkeypatch.setattr(
        dashboard_hotroutes.hot_routes,
        "parse_new_access_log",
        fake_parse_new_access_log,
    )
    monkeypatch.setattr(dashboard_hotroutes.hot_routes, "update_cache", fake_update_cache)
    monkeypatch.setattr(dashboard_hotroutes.hot_routes, "hot_domains", fake_hot_domains)

    out = dashboard_hotroutes.probe_hot_routes(
        state_path=state_path,
        cache_path=cache_path,
        log_path=log_path,
        now=1000.0,
    )

    assert out["enabled"] is True
    assert out["status"] == "ok"
    assert out["updated"] is True
    assert out["domains"] == [
        {"domain": "a.example", "count": 3},
        {"domain": "b.example", "count": 1},
    ]
    assert all(set(entry) == {"domain", "count"} for entry in out["domains"])
    assert ("parse", log_path, None, None, None) in calls
    assert any(call[0] == "update" and call[3] == 2 for call in calls)
    assert any(
        call[0] == "update"
        and call[5] == dashboard_hotroutes.hot_routes.DEFAULT_BUCKET_SECONDS
        for call in calls
    )
    assert any(call[0] == "update" and call[6]["log_offset"] == 12 for call in calls)
    assert any(call[0] == "hot_domains" for call in calls)


def test_probe_hot_routes_missing_log_and_cache_is_empty_not_error(tmp_path):
    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, {"enabled": True})

    out = dashboard_hotroutes.probe_hot_routes(
        state_path=state_path,
        cache_path=tmp_path / "missing-cache.json",
        log_path=tmp_path / "missing-privoxy.log",
        now=1000.0,
    )

    assert out["enabled"] is True
    assert out["status"] == "ok"
    assert out["domains"] == []


def test_api_status_contains_hot_routes_section(monkeypatch, tmp_path):
    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, {"enabled": False})
    dashboard = _fresh_dashboard(monkeypatch, state_path)
    seen = {}

    def fake_run_probe_set(probes, budget_sec):
        seen.update(probes)
        return {name: {"status": "ok"} for name in probes}

    monkeypatch.setattr(dashboard, "_run_status_probe_set", fake_run_probe_set)
    monkeypatch.setattr(dashboard, "probe_nodes_snapshot", lambda: [])

    response = dashboard.app.test_client().get("/api/status")

    assert response.status_code == 200
    assert "hot_routes" in seen
    assert response.get_json()["hot_routes"] == {"status": "ok"}


def test_api_status_hot_routes_public_domains_exclude_timing_metadata(monkeypatch, tmp_path):
    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, {"enabled": True})
    dashboard = _fresh_dashboard(monkeypatch, state_path)

    monkeypatch.setattr(
        dashboard_hotroutes.hot_routes,
        "parse_new_access_log",
        lambda path=None, offset=None, inode=None, dev=None: (
            {"a.example": 3},
            {"log_offset": 1, "log_inode": 2, "log_dev": 3, "log_size": 1},
        ),
    )
    monkeypatch.setattr(
        dashboard_hotroutes.hot_routes,
        "update_cache",
        lambda counts,
        path=None,
        ttl=None,
        top_n=None,
        now=None,
        bucket_size=None,
        cursor=None: {
            "a.example": {
                "domain": "a.example",
                "count": 3,
                "last_seen": 1000.0,
            }
        },
    )
    monkeypatch.setattr(
        dashboard_hotroutes.hot_routes,
        "hot_domains",
        lambda path=None, top_n=None, ttl=None, now=None: ["a.example"],
    )

    def fake_run_probe_set(probes, budget_sec):
        return {
            name: fn() if name == "hot_routes" else {"status": "ok"}
            for name, fn in probes.items()
        }

    monkeypatch.setattr(dashboard, "_run_status_probe_set", fake_run_probe_set)
    monkeypatch.setattr(dashboard, "probe_nodes_snapshot", lambda: [])

    response = dashboard.app.test_client().get("/api/status")

    assert response.status_code == 200
    domains = response.get_json()["hot_routes"]["domains"]
    assert domains == [{"domain": "a.example", "count": 3}]
    assert all(set(entry) == {"domain", "count"} for entry in domains)


def test_probe_hot_routes_bucket_seconds_configurable():
    opts = dashboard_hotroutes._options(
        {"hot_routes": {"enabled": True, "bucket_seconds": 30}}
    )
    assert opts["bucket_size"] == 30

    opts = dashboard_hotroutes._options(
        {"hot_routes": {"enabled": True, "bucket_seconds": 0}}
    )
    assert opts["bucket_size"] == dashboard_hotroutes.hot_routes.DEFAULT_BUCKET_SECONDS


def test_probe_hot_routes_uses_file_cursor_after_restart(tmp_path):
    state_path = tmp_path / "srouter.local.json"
    cache_path = tmp_path / "srouter.hot_routes.json"
    log_path = tmp_path / "privoxy.log"
    _write_state(state_path, {"enabled": True, "update_interval_sec": 0})
    log_path.write_text(
        '127.0.0.1 - - [Jul 02 14:00:00.000] "CONNECT a.example:443 HTTP/1.1" 200 0\n',
        encoding="utf-8",
    )

    first = dashboard_hotroutes.probe_hot_routes(
        state_path=state_path,
        cache_path=cache_path,
        log_path=log_path,
        now=1000.0,
    )
    assert first["domains"] == [{"domain": "a.example", "count": 1}]

    with dashboard_hotroutes._lock:
        dashboard_hotroutes._probe_cache.update(
            key=None, updated_at=0.0, entries={}, error=""
        )

    second = dashboard_hotroutes.probe_hot_routes(
        state_path=state_path,
        cache_path=cache_path,
        log_path=log_path,
        now=1001.0,
    )

    assert second["domains"] == [{"domain": "a.example", "count": 1}]


def test_probe_hot_routes_concurrent_poll_reserves_update_slot(monkeypatch, tmp_path):
    state_path = tmp_path / "srouter.local.json"
    cache_path = tmp_path / "srouter.hot_routes.json"
    log_path = tmp_path / "privoxy.log"
    _write_state(state_path, {"enabled": True, "update_interval_sec": 60})

    with dashboard_hotroutes._lock:
        dashboard_hotroutes._probe_cache.update(
            key=None, updated_at=0.0, entries={}, error=""
        )

    real_update_cache = dashboard_hotroutes.hot_routes.update_cache
    parse_entered = threading.Event()
    release_parse = threading.Event()
    start = threading.Barrier(3)
    calls = {"parse": 0, "update": 0}
    calls_lock = threading.Lock()
    results = []
    errors = []

    def fake_parse_new_access_log(path=None, offset=None, inode=None, dev=None):
        with calls_lock:
            calls["parse"] += 1
        parse_entered.set()
        assert release_parse.wait(timeout=2.0)
        return {"race.example": 1}, {
            "log_offset": 1,
            "log_inode": 2,
            "log_dev": 3,
            "log_size": 1,
        }

    def counting_update_cache(*args, **kwargs):
        with calls_lock:
            calls["update"] += 1
        return real_update_cache(*args, **kwargs)

    monkeypatch.setattr(
        dashboard_hotroutes.hot_routes,
        "parse_new_access_log",
        fake_parse_new_access_log,
    )
    monkeypatch.setattr(
        dashboard_hotroutes.hot_routes,
        "update_cache",
        counting_update_cache,
    )

    def run_probe():
        try:
            start.wait(timeout=2.0)
            results.append(
                dashboard_hotroutes.probe_hot_routes(
                    state_path=state_path,
                    cache_path=cache_path,
                    log_path=log_path,
                    now=1000.0,
                )
            )
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=run_probe) for _ in range(2)]
    for thread in threads:
        thread.start()
    start.wait(timeout=2.0)
    assert parse_entered.wait(timeout=2.0)
    time.sleep(0.05)
    release_parse.set()
    for thread in threads:
        thread.join(timeout=2.0)

    assert errors == []
    assert len(results) == 2
    assert calls == {"parse": 1, "update": 1}

    data = json.loads(cache_path.read_text(encoding="utf-8"))
    assert data["domains"] == [
        {"domain": "race.example", "count": 1, "last_seen": 1000.0}
    ]
