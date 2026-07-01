import copy
import importlib
import json
import sys
import types

import pytest

import gen_xray_config
import local_state
import sys_probe


def _write_state(path, state):
    path.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")


def _node(name, host, *, enabled=True, route_ip=None, uuid_suffix="0", socks_port=11080):
    return {
        "name": name,
        "endpoint_host": host,
        "route_ip": route_ip or host,
        "port": 443,
        "enabled": enabled,
        "uuid": f"00000000-0000-4000-8000-00000000000{uuid_suffix}",
        "reality": {
            "public_key": "PLACEHOLDER",
            "short_id": "0123456789abcdef",
            "sni": "www.163.com",
            "dest": "www.163.com:443",
            "flow": "xtls-rprx-vision",
        },
        "probe": {"socks_port": socks_port},
    }


def _state(active="sg-1", pending=None, *, hk_enabled=True):
    return {
        "schema_version": 1,
        "nodes": [
            _node("sg-1", "203.0.113.10", uuid_suffix="0", socks_port=11080),
            _node("hk-1", "203.0.113.20", enabled=hk_enabled, uuid_suffix="1", socks_port=11081),
        ],
        "active_node": {"name": active, "pending": pending},
    }


def _active_state(path):
    return json.loads(path.read_text(encoding="utf-8"))["active_node"]


def _metrics():
    return [
        {"name": "sg-1", "ping_ms": 20, "loss": 0.0, "throughput_kbps": 1000, "status": "ok"},
        {"name": "hk-1", "ping_ms": 60, "loss": 10.0, "throughput_kbps": 3000, "status": "ok"},
        {"name": "de-1", "ping_ms": 100, "loss": 0.0, "throughput_kbps": 500, "status": "warn"},
    ]


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


def test_rank_nodes_combines_normalized_latency_throughput_and_loss():
    import node_selector

    ranked = node_selector.rank_nodes(_metrics())

    assert [item["name"] for item in ranked] == ["hk-1", "sg-1", "de-1"]
    assert [item["rank"] for item in ranked] == [1, 2, 3]
    assert ranked[0]["score"] == pytest.approx(0.805)
    assert ranked[1]["score"] == pytest.approx(0.64)
    assert ranked[2]["score"] == pytest.approx(0.20)


def test_rank_nodes_weight_sum_and_single_node_degenerate_score():
    import node_selector

    assert node_selector.W_TPUT + node_selector.W_LAT + node_selector.W_LOSS == pytest.approx(1.0)

    metrics = {"name": "sg-1", "ping_ms": 20, "loss": 0.0, "throughput_kbps": 1000, "status": "ok"}
    ranked = node_selector.rank_nodes([metrics])

    assert ranked[0]["score"] == pytest.approx(1.0)
    assert ranked[0]["rank"] == 1
    assert node_selector.score_node(metrics) == ranked[0]["score"]


def test_rank_nodes_puts_unusable_measurements_last_by_name():
    import node_selector

    ranked = node_selector.rank_nodes(
        [
            {"name": "ok", "ping_ms": 30, "loss": 0.0, "throughput_kbps": 1000, "status": "ok"},
            {"name": "z-down", "ping_ms": 1, "loss": 0.0, "throughput_kbps": 9000, "status": "down"},
            {"name": "a-unknown", "ping_ms": 1, "loss": 0.0, "throughput_kbps": 9000, "status": "unknown"},
            {"name": "no-ping", "ping_ms": None, "loss": 0.0, "throughput_kbps": 9000, "status": "ok"},
        ]
    )

    assert [item["name"] for item in ranked] == ["ok", "a-unknown", "no-ping", "z-down"]
    assert ranked[0]["score"] == pytest.approx(1.0)
    assert all(item["score"] is None for item in ranked[1:])
    assert [item["rank"] for item in ranked] == [1, None, None, None]


def test_recommendation_is_pure_and_reports_hold_switch_or_no_data():
    import node_selector

    metrics = _metrics()
    before = copy.deepcopy(metrics)

    assert node_selector.recommendation(metrics, "hk-1")["recommendation"] == "hold"
    switch = node_selector.recommendation(metrics, "sg-1")
    assert switch["active"] == "sg-1"
    assert switch["best"] == "hk-1"
    assert switch["recommendation"] == "switch:hk-1"
    assert switch["score_window"][0] == {"name": "hk-1", "score": pytest.approx(0.805), "status": "ok"}
    assert node_selector.recommendation([], "sg-1") == {
        "active": "sg-1",
        "best": None,
        "score_window": [],
        "recommendation": "no-data",
    }
    assert metrics == before


def test_select_node_rejects_disabled_before_mutation_or_runner(tmp_path):
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, _state())
    before = state_path.read_bytes()
    runner_calls = []

    out = node_selector.select_node(
        "hk-1",
        enabled_names={"sg-1"},
        runner=lambda cmd, timeout: runner_calls.append((cmd, timeout)),
        state_path=state_path,
        config_path=tmp_path / "config.json",
    )

    assert out["ok"] is False
    assert out["step"] == "whitelist"
    assert out["active"] == "sg-1"
    assert runner_calls == []
    assert state_path.read_bytes() == before


def test_select_node_begin_rejection_preserves_previous_and_skips_apply(tmp_path, monkeypatch):
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, _state(hk_enabled=False))
    writes = []
    runner_calls = []
    monkeypatch.setattr(gen_xray_config, "write_config", lambda *args, **kwargs: writes.append((args, kwargs)) or True)

    out = node_selector.select_node(
        "hk-1",
        enabled_names={"hk-1"},
        runner=lambda cmd, timeout: runner_calls.append((cmd, timeout)),
        state_path=state_path,
        config_path=tmp_path / "config.json",
    )

    assert out["ok"] is False
    assert out["step"] == "begin"
    assert out["active"] == "sg-1"
    assert _active_state(state_path) == {"name": "sg-1", "pending": None}
    assert writes == []
    assert runner_calls == []


def test_select_node_blocks_invalid_traffic_guard_before_pending_write(tmp_path):
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    state = _state()
    state["traffic_guard"] = {"mode": "auto", "domains": {"video.example.com": "block"}}
    _write_state(state_path, state)
    runner_calls = []

    out = node_selector.select_node(
        "hk-1",
        enabled_names={"sg-1", "hk-1"},
        runner=lambda cmd, timeout: runner_calls.append((cmd, timeout)),
        state_path=state_path,
        config_path=tmp_path / "config.json",
    )

    assert out["ok"] is False
    assert out["step"] == "validate"
    assert "traffic_guard" in out["error"]
    assert _active_state(state_path) == {"name": "sg-1", "pending": None}
    assert runner_calls == []
    assert not (tmp_path / "config.json").exists()


def test_select_node_success_promotes_only_after_whitelisted_restart_and_renders_pending(tmp_path, monkeypatch):
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    config_path = tmp_path / "config.json"
    _write_state(state_path, _state())
    writes = []
    rendered_nodes = []

    def fake_write(path, state_path=None, **kwargs):
        writes.append((path, state_path, kwargs))
        hook = kwargs.get("outbound_hook")
        assert hook is not None
        old = gen_xray_config._vless_outbound(local_state.get_node("sg-1", path=state_path), "active", state_path=state_path)
        patched = hook(old, node=local_state.get_node("sg-1", path=state_path), role="active")
        rendered_nodes.append(patched["srouter"]["node"])
        assert hook(old, node=local_state.get_node("sg-1", path=state_path), role="probe") == old
        return True

    runner_calls = []
    monkeypatch.setattr(gen_xray_config, "write_config", fake_write)

    out = node_selector.select_node(
        "hk-1",
        enabled_names={"sg-1", "hk-1"},
        runner=lambda cmd, timeout: runner_calls.append((cmd, timeout)) or {"rc": 0, "out": "", "err": "", "timeout": False},
        state_path=state_path,
        config_path=config_path,
    )

    assert out["ok"] is True
    assert out["step"] == "done"
    assert out["active"] == "hk-1"
    assert _active_state(state_path) == {"name": "hk-1", "pending": None}
    assert writes[0][0] == config_path
    assert writes[0][2]["outbound_hook"] is not None
    assert rendered_nodes == ["hk-1"]
    assert runner_calls == [(node_selector.XRAY_RESTART_CMD, 40)]
    assert isinstance(runner_calls[0][0], list)


def test_select_node_generate_failure_rolls_back_to_previous_config(tmp_path, monkeypatch):
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, _state())
    write_kwargs = []
    runner_calls = []

    def fake_write(path, state_path=None, **kwargs):
        write_kwargs.append(kwargs)
        return len(write_kwargs) != 1

    monkeypatch.setattr(gen_xray_config, "write_config", fake_write)

    out = node_selector.select_node(
        "hk-1",
        enabled_names={"sg-1", "hk-1"},
        runner=lambda cmd, timeout: runner_calls.append((cmd, timeout)) or {"rc": 0, "out": "", "err": "", "timeout": False},
        state_path=state_path,
        config_path=tmp_path / "config.json",
    )

    assert out["ok"] is False
    assert out["step"] == "generate"
    assert out["active"] == "sg-1"
    assert _active_state(state_path) == {"name": "sg-1", "pending": None}
    assert "outbound_hook" in write_kwargs[0]
    assert "outbound_hook" not in write_kwargs[1]
    assert runner_calls == [(node_selector.XRAY_RESTART_CMD, 40)]


def test_select_node_restart_failure_rolls_back_active_and_config(tmp_path, monkeypatch):
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, _state())
    write_kwargs = []
    runner_calls = []

    monkeypatch.setattr(
        gen_xray_config,
        "write_config",
        lambda path, state_path=None, **kwargs: write_kwargs.append(kwargs) or True,
    )

    def fake_runner(cmd, timeout):
        runner_calls.append((cmd, timeout))
        return {"rc": 1 if len(runner_calls) == 1 else 0, "out": "", "err": "boom", "timeout": False}

    out = node_selector.select_node(
        "hk-1",
        enabled_names={"sg-1", "hk-1"},
        runner=fake_runner,
        state_path=state_path,
        config_path=tmp_path / "config.json",
    )

    assert out["ok"] is False
    assert out["step"] == "restart"
    assert out["active"] == "sg-1"
    assert _active_state(state_path) == {"name": "sg-1", "pending": None}
    assert "outbound_hook" in write_kwargs[0]
    assert "outbound_hook" not in write_kwargs[1]
    assert runner_calls == [(node_selector.XRAY_RESTART_CMD, 40), (node_selector.XRAY_RESTART_CMD, 40)]


def test_select_node_restart_failure_reports_rollback_failed_when_restore_write_fails(tmp_path, monkeypatch):
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, _state())
    write_kwargs = []
    runner_calls = []

    def fake_write(path, state_path=None, **kwargs):
        write_kwargs.append(kwargs)
        return len(write_kwargs) == 1

    monkeypatch.setattr(gen_xray_config, "write_config", fake_write)

    out = node_selector.select_node(
        "hk-1",
        enabled_names={"sg-1", "hk-1"},
        runner=lambda cmd, timeout: runner_calls.append((cmd, timeout)) or {"rc": 1, "out": "", "err": "boom", "timeout": False},
        state_path=state_path,
        config_path=tmp_path / "config.json",
    )

    assert out["ok"] is False
    assert out["step"] == "rollback_failed"
    assert out["failed_step"] == "restart"
    assert out["active"] == "sg-1"
    assert out["rollback"]["restore_ok"] is False
    assert "rollback config restore failed" in out["error"]
    assert _active_state(state_path) == {"name": "sg-1", "pending": None}
    assert "outbound_hook" in write_kwargs[0]
    assert "outbound_hook" not in write_kwargs[1]
    assert runner_calls == [(node_selector.XRAY_RESTART_CMD, 40)]


def test_select_node_restart_timeout_rolls_back_without_promoting(tmp_path, monkeypatch):
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, _state())
    monkeypatch.setattr(gen_xray_config, "write_config", lambda *args, **kwargs: True)

    out = node_selector.select_node(
        "hk-1",
        enabled_names={"sg-1", "hk-1"},
        runner=lambda cmd, timeout: {"rc": None, "out": "", "err": "timeout", "timeout": True},
        state_path=state_path,
        config_path=tmp_path / "config.json",
    )

    assert out["ok"] is False
    assert out["step"] == "restart"
    assert out["active"] == "sg-1"
    assert _active_state(state_path) == {"name": "sg-1", "pending": None}


def test_select_node_commit_failure_rolls_back_after_successful_restart(tmp_path, monkeypatch):
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, _state())
    write_kwargs = []
    runner_calls = []
    monkeypatch.setattr(
        gen_xray_config,
        "write_config",
        lambda path, state_path=None, **kwargs: write_kwargs.append(kwargs) or True,
    )
    monkeypatch.setattr(local_state, "commit_active_node_change", lambda name, path=None: None)

    out = node_selector.select_node(
        "hk-1",
        enabled_names={"sg-1", "hk-1"},
        runner=lambda cmd, timeout: runner_calls.append((cmd, timeout)) or {"rc": 0, "out": "", "err": "", "timeout": False},
        state_path=state_path,
        config_path=tmp_path / "config.json",
    )

    assert out["ok"] is False
    assert out["step"] == "commit"
    assert out["active"] == "sg-1"
    assert _active_state(state_path) == {"name": "sg-1", "pending": None}
    assert "outbound_hook" in write_kwargs[0]
    assert "outbound_hook" not in write_kwargs[1]
    assert runner_calls == [(node_selector.XRAY_RESTART_CMD, 40), (node_selector.XRAY_RESTART_CMD, 40)]


def test_api_node_select_rejects_disabled_before_mutation(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard.local_state, "enabled_nodes", lambda path=None: [{"name": "sg-1"}])
    monkeypatch.setattr(
        dashboard.node_selector,
        "select_node",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("selector must not run")),
    )

    response = dashboard.app.test_client().post("/api/node/select/hk-1")

    assert response.status_code == 400
    assert response.get_json() == {"ok": False, "err": "node not enabled or unknown"}


def test_api_node_select_success_uses_sys_probe_runner(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard.local_state, "enabled_nodes", lambda path=None: [{"name": "hk-1"}])

    def fake_select(name, *, enabled_names, runner, state_path):
        assert name == "hk-1"
        assert enabled_names == {"hk-1"}
        assert runner is sys_probe.run
        assert state_path is None
        return {"ok": True, "active": "hk-1", "step": "done"}

    monkeypatch.setattr(dashboard.node_selector, "select_node", fake_select)

    response = dashboard.app.test_client().post("/api/node/select/hk-1")

    assert response.status_code == 200
    assert response.get_json() == {"ok": True, "active": "hk-1", "step": "done"}


def test_api_node_select_apply_failure_returns_500(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard.local_state, "enabled_nodes", lambda path=None: [{"name": "hk-1"}])
    monkeypatch.setattr(
        dashboard.node_selector,
        "select_node",
        lambda name, *, enabled_names, runner, state_path: {"ok": False, "active": "sg-1", "step": "restart"},
    )

    response = dashboard.app.test_client().post("/api/node/select/hk-1")

    assert response.status_code == 500
    assert response.get_json() == {"ok": False, "active": "sg-1", "step": "restart"}


def test_api_nodes_ranking_returns_recommendation_from_snapshot(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard, "probe_nodes_snapshot", lambda: _metrics())
    monkeypatch.setattr(dashboard.local_state, "active_node", lambda path=None: {"name": "sg-1"})

    response = dashboard.app.test_client().get("/api/nodes/ranking")

    assert response.status_code == 200
    body = response.get_json()
    assert body["active"] == "sg-1"
    assert body["best"] == "hk-1"
    assert body["recommendation"] == "switch:hk-1"
    assert [item["name"] for item in body["score_window"]] == ["hk-1", "sg-1", "de-1"]
