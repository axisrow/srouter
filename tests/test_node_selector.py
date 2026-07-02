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


# ============================ split-route auto-sync (issue #21) ============================
# Реальный route/osascript НЕ зовётся: sys_probe.run замокан, argv проверяется на константы.


def _install_gateway(monkeypatch, gateway="192.0.2.1"):
    """Фейковый srouter_config для ленивого import в node_selector._gateway_literal."""
    cfg = types.ModuleType("srouter_config")
    cfg.GATEWAY = gateway
    monkeypatch.setitem(sys.modules, "srouter_config", cfg)
    return cfg


def _install_route_runner(monkeypatch, result=None):
    """Замокать sys_probe.run; вернуть список вызванных (argv, timeout)."""
    calls = []

    def fake_run(cmd, timeout):
        calls.append((list(cmd), timeout))
        return result if result is not None else {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(sys_probe, "run", fake_run)
    return calls


def _apply_switch(monkeypatch, state_path, tmp_path, *, name="hk-1"):
    """Прогнать успешный two-phase switch (write_config/restart замоканы на success)."""
    monkeypatch.setattr(gen_xray_config, "write_config", lambda *args, **kwargs: True)
    import node_selector

    return node_selector.select_node(
        name,
        enabled_names={"sg-1", "hk-1"},
        runner=lambda cmd, timeout: {"rc": 0, "out": "", "err": "", "timeout": False},
        state_path=state_path,
        config_path=tmp_path / "config.json",
    )


def _route_argv_fragments(calls):
    """Собрать shell-фрагменты (третий элемент osascript-argv) всех route-вызовов."""
    return [cmd[2] for cmd, _timeout in calls]


def test_route_sync_flag_absent_makes_zero_privileged_calls(tmp_path, monkeypatch):
    """Флаг отсутствует -> route-sync не зван вообще; поведение как раньше."""
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, _state())  # без auto_route_sync
    _install_gateway(monkeypatch)
    calls = _install_route_runner(monkeypatch)

    out = _apply_switch(monkeypatch, state_path, tmp_path)

    assert out["ok"] is True
    assert out["step"] == "done"
    assert out["active"] == "hk-1"
    assert "route_sync" not in out
    assert calls == []


@pytest.mark.parametrize("flag", [False, "true", 1, None, "yes"])
def test_route_sync_only_explicit_true_enables(tmp_path, monkeypatch, flag):
    """Только строгий boolean True включает sync; truthy-суррогаты не считаются."""
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    state = _state()
    state["auto_route_sync"] = flag
    _write_state(state_path, state)
    _install_gateway(monkeypatch)
    calls = _install_route_runner(monkeypatch)

    out = _apply_switch(monkeypatch, state_path, tmp_path)

    assert out["ok"] is True
    assert "route_sync" not in out
    assert calls == []


def test_route_sync_enabled_adds_new_first_then_deletes_old_from_constants(tmp_path, monkeypatch):
    """Флаг включён: commit узла -> add нового ПЕРВЫМ, затем delete старого, argv из констант+IP."""
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    state = _state(active="sg-1")
    state["auto_route_sync"] = True
    _write_state(state_path, state)
    _install_gateway(monkeypatch, gateway="192.0.2.1")
    calls = _install_route_runner(monkeypatch)

    out = _apply_switch(monkeypatch, state_path, tmp_path, name="hk-1")

    assert out["ok"] is True
    assert out["active"] == "hk-1"
    sync = out["route_sync"]
    assert sync["enabled"] is True
    assert sync["added"]["ok"] is True
    assert sync["removed"]["ok"] is True

    # add нового (hk-1: 203.0.113.20) ПЕРВЫМ, delete прежнего (sg-1: 203.0.113.10) — после.
    assert len(calls) == 2
    add_cmd, add_timeout = calls[0]
    delete_cmd, delete_timeout = calls[1]
    assert add_timeout == 60 and delete_timeout == 60
    assert add_cmd[:2] == [node_selector.OSASCRIPT, "-e"]
    assert delete_cmd[:2] == [node_selector.OSASCRIPT, "-e"]
    assert f"{node_selector.ROUTE} -n add -host 203.0.113.20 192.0.2.1" in add_cmd[2]
    assert f"{node_selector.ROUTE} -n delete -host 203.0.113.10" in delete_cmd[2]
    # do shell script + admin privileges — точный канон моста.
    for cmd, _timeout in calls:
        assert cmd[2].startswith('do shell script "')
        assert "with administrator privileges" in cmd[2]


def test_route_sync_reports_but_never_makes_switch_fail_on_invalid_new_ip(tmp_path, monkeypatch):
    """Невалидный/пустой route_ip нового узла -> add reject, node-switch всё равно успешен."""
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    state = _state(active="sg-1")
    state["auto_route_sync"] = True
    _write_state(state_path, state)
    _install_gateway(monkeypatch)
    calls = _install_route_runner(monkeypatch)

    # hk-1 не даёт валидного IP (детерминированно, без реального DNS): resolve -> hostname.
    real_resolve = local_state.resolve_route_ip

    def fake_resolve(node, path=None):
        if isinstance(node, dict) and node.get("name") == "hk-1":
            return "node.example.test"  # не IP -> _ip_literal reject
        return real_resolve(node, path=path)

    monkeypatch.setattr(local_state, "resolve_route_ip", fake_resolve)

    out = _apply_switch(monkeypatch, state_path, tmp_path, name="hk-1")

    assert out["ok"] is True  # node-switch успешен несмотря на route-sync reject
    assert out["active"] == "hk-1"
    sync = out["route_sync"]
    assert sync["added"] is None
    assert sync["removed"] is None  # валидация до мутации: ни add, ни delete
    assert "route_ip" in sync["error"]
    # валидация провалилась до мутации — ни одной privileged-команды.
    assert calls == []


def test_route_sync_cancelled_add_leaves_old_route_intact_and_switch_succeeds(tmp_path, monkeypatch):
    """Отмена (-128) add нового -> старый route НЕ трогается (removed is None),
    node-switch успешен, route_sync.added = cancelled."""
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    state = _state(active="sg-1")
    state["auto_route_sync"] = True
    _write_state(state_path, state)
    _install_gateway(monkeypatch)
    calls = _install_route_runner(monkeypatch, {"rc": -128, "out": "", "err": "User canceled.", "timeout": False})

    out = _apply_switch(monkeypatch, state_path, tmp_path, name="hk-1")

    assert out["ok"] is True
    assert out["active"] == "hk-1"
    sync = out["route_sync"]
    assert sync["added"]["cancelled"] is True
    assert sync["added"]["ok"] is False
    assert sync["removed"] is None  # транзакционность: add провален -> delete не зван
    # только одна попытка — add; delete прежнего не выполнялся.
    assert len(calls) == 1
    assert "-n add -host" in calls[0][0][2]


def test_route_sync_same_old_and_new_ip_skips_delete(tmp_path, monkeypatch):
    """old_ip == new_ip -> без delete дубликата; только add нового route."""
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    state = _state(active="sg-1")
    state["auto_route_sync"] = True
    # hk-1 делим route_ip с sg-1 (оба 203.0.113.10) — delete прежнего сносил бы новый маршрут.
    state["nodes"][1]["route_ip"] = "203.0.113.10"
    _write_state(state_path, state)
    _install_gateway(monkeypatch)
    calls = _install_route_runner(monkeypatch)

    out = _apply_switch(monkeypatch, state_path, tmp_path, name="hk-1")

    assert out["ok"] is True
    sync = out["route_sync"]
    assert sync["removed"] is None  # delete пропущен: old == new
    assert sync["added"]["ok"] is True
    assert len(calls) == 1
    assert f"{node_selector.ROUTE} -n add -host 203.0.113.10 192.0.2.1" in calls[0][0][2]


def test_route_sync_add_failure_does_not_delete_old_route(tmp_path, monkeypatch):
    """Сбой add (ненулевой rc, не File-exists) -> delete старого НЕ зовётся (транзакционность)."""
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    state = _state(active="sg-1")
    state["auto_route_sync"] = True
    _write_state(state_path, state)
    _install_gateway(monkeypatch)

    def runner(cmd, timeout):
        # add возвращает ошибку; delete вообще не должен быть вызван — поэтому не готовим его ветку.
        if "-n add" in cmd[2]:
            return {"rc": 7, "out": "", "err": "route add boom", "timeout": False}
        raise AssertionError("delete must not run after add failure: " + cmd[2])

    monkeypatch.setattr(sys_probe, "run", runner)

    out = _apply_switch(monkeypatch, state_path, tmp_path, name="hk-1")

    assert out["ok"] is True
    sync = out["route_sync"]
    assert sync["added"]["ok"] is False
    assert sync["removed"] is None  # старый route не тронут — провал midway не ухудшает состояние


def test_route_sync_file_exists_with_matching_readback_gateway_deletes_old_route(tmp_path, monkeypatch):
    """«File exists» на add — успех только если route get подтвердил тот же gateway."""
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    state = _state(active="sg-1")
    state["auto_route_sync"] = True
    _write_state(state_path, state)
    _install_gateway(monkeypatch)

    run_calls = []

    def tracked(cmd, timeout):
        run_calls.append((list(cmd), timeout))
        if cmd == [node_selector.ROUTE, "-n", "get", "-host", "203.0.113.20"]:
            return {"rc": 0, "out": "route to: 203.0.113.20\n    gateway: 192.0.2.1\n", "err": "", "timeout": False}
        if "-n add" in cmd[2]:
            # macOS: повторный add того же host-route -> ненулевой rc + 'File exists'.
            return {"rc": 17, "out": "add host: gateway 192.0.2.1 File exists", "err": "", "timeout": False}
        if "-n delete" in cmd[2]:
            return {"rc": 0, "out": "delete", "err": "", "timeout": False}
        raise AssertionError(f"unexpected route command: {cmd!r}")

    monkeypatch.setattr(sys_probe, "run", tracked)

    out = _apply_switch(monkeypatch, state_path, tmp_path, name="hk-1")

    assert out["ok"] is True
    sync = out["route_sync"]
    # add «провалился» по rc, но File-exists + read-back gateway совпал -> delete зовётся.
    assert sync["added"]["rc"] == 17  # исходный rc сохранён для диагностики
    assert sync["removed"]["ok"] is True
    assert "-n add -host" in run_calls[0][0][2]
    assert run_calls[1] == ([node_selector.ROUTE, "-n", "get", "-host", "203.0.113.20"], 60)
    assert "-n delete -host" in run_calls[2][0][2]


def test_route_sync_file_exists_with_wrong_readback_gateway_keeps_old_route(tmp_path, monkeypatch):
    """Stale route через чужой gateway -> File exists НЕ успех; старый рабочий route не трогаем."""
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    state = _state(active="sg-1")
    state["auto_route_sync"] = True
    _write_state(state_path, state)
    _install_gateway(monkeypatch, gateway="192.0.2.1")

    run_calls = []

    def tracked(cmd, timeout):
        run_calls.append((list(cmd), timeout))
        if cmd == [node_selector.ROUTE, "-n", "get", "-host", "203.0.113.20"]:
            return {"rc": 0, "out": "route to: 203.0.113.20\n    gateway: 192.0.2.254\n", "err": "", "timeout": False}
        if "-n add" in cmd[2]:
            return {"rc": 17, "out": "", "err": "route: writing to routing socket: File exists", "timeout": False}
        if "-n delete" in cmd[2]:
            raise AssertionError("delete must not run when read-back gateway differs")
        raise AssertionError(f"unexpected route command: {cmd!r}")

    monkeypatch.setattr(sys_probe, "run", tracked)

    out = _apply_switch(monkeypatch, state_path, tmp_path, name="hk-1")

    assert out["ok"] is True
    sync = out["route_sync"]
    assert sync["added"]["rc"] == 17
    assert sync["removed"] is None
    assert "gateway" in sync["error"]
    assert len(run_calls) == 2
    assert "-n add -host" in run_calls[0][0][2]
    assert run_calls[1] == ([node_selector.ROUTE, "-n", "get", "-host", "203.0.113.20"], 60)


@pytest.mark.parametrize(
    "readback",
    [
        {"rc": 1, "out": "", "err": "route get boom", "timeout": False},
        {"rc": 0, "out": "", "err": "", "timeout": False},
    ],
)
def test_route_sync_file_exists_with_failed_readback_keeps_old_route(tmp_path, monkeypatch, readback):
    """Read-back упал или не вернул gateway -> fail-closed, delete старого route не зовётся."""
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    state = _state(active="sg-1")
    state["auto_route_sync"] = True
    _write_state(state_path, state)
    _install_gateway(monkeypatch, gateway="192.0.2.1")

    run_calls = []

    def tracked(cmd, timeout):
        run_calls.append((list(cmd), timeout))
        if cmd == [node_selector.ROUTE, "-n", "get", "-host", "203.0.113.20"]:
            return readback
        if "-n add" in cmd[2]:
            return {"rc": 17, "out": "add host: gateway 192.0.2.1 File exists", "err": "", "timeout": False}
        if "-n delete" in cmd[2]:
            raise AssertionError("delete must not run when read-back fails")
        raise AssertionError(f"unexpected route command: {cmd!r}")

    monkeypatch.setattr(sys_probe, "run", tracked)

    out = _apply_switch(monkeypatch, state_path, tmp_path, name="hk-1")

    assert out["ok"] is True
    sync = out["route_sync"]
    assert sync["added"]["rc"] == 17
    assert sync["removed"] is None
    assert "read-back" in sync["error"]
    assert len(run_calls) == 2


def test_sudo_route_ip_rejects_invalid_ip_inside_bridge_without_shell(tmp_path, monkeypatch):
    """In-bridge валидация (канон dashboard.py:118): невалидный route_ip -> reject без osascript."""
    import node_selector

    _install_gateway(monkeypatch)
    run_calls = []

    def boom(cmd, timeout):
        run_calls.append(cmd)
        raise AssertionError("bridge must reject before calling sys_probe.run")

    monkeypatch.setattr(sys_probe, "run", boom)

    # Невалидный scoped IPv6 и hostname не должны попасть в shell text.
    for bad in ("fe80::1%en0", "node.example.test", ""):
        r = node_selector._sudo_route_ip("add", bad, "192.0.2.1")
        assert r["rc"] is None
        assert r["timeout"] is False
        assert run_calls == []


def test_sudo_route_ip_rejects_invalid_gateway_on_add_without_shell(tmp_path, monkeypatch):
    """В add gateway интерполируется в shell -> невалидный gateway reject на границе моста."""
    import node_selector

    monkeypatch.setattr(sys_probe, "run", lambda cmd, timeout: (_ for _ in ()).throw(
        AssertionError("invalid gateway must not reach shell")
    ))

    r = node_selector._sudo_route_ip("add", "203.0.113.20", "not-a-gateway")
    assert r["rc"] is None
    assert "GATEWAY" in r["err"]


def test_sudo_route_ip_remove_does_not_require_gateway(monkeypatch):
    """remove не интерполирует gateway -> валидный IP + невалидный gateway проходит на remove."""
    import node_selector

    seen = []
    monkeypatch.setattr(sys_probe, "run", lambda cmd, timeout: seen.append(cmd) or {"rc": 0, "out": "", "err": "", "timeout": False})

    r = node_selector._sudo_route_ip("remove", "203.0.113.10", "not-a-gateway")
    assert r["rc"] == 0
    assert len(seen) == 1
    assert "-n delete -host 203.0.113.10" in seen[0][2]
    assert "not-a-gateway" not in seen[0][2]  # gateway не попал в shell-команду remove


def test_route_sync_defensive_when_runner_raises(tmp_path, monkeypatch):
    """sys_probe.run бросает -> route-sync ловит, node-switch остаётся успешным."""
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    state = _state(active="sg-1")
    state["auto_route_sync"] = True
    _write_state(state_path, state)
    _install_gateway(monkeypatch)

    def boom(cmd, timeout):
        raise RuntimeError("osascript exploded")

    monkeypatch.setattr(sys_probe, "run", boom)

    out = _apply_switch(monkeypatch, state_path, tmp_path, name="hk-1")

    assert out["ok"] is True
    assert out["active"] == "hk-1"
    assert out["route_sync"]["error"] == "osascript exploded"


def test_route_sync_missing_gateway_rejects_add_switch_succeeds(tmp_path, monkeypatch):
    """srouter_config недоступен/битый GATEWAY -> add reject, node-switch успешен."""
    import node_selector

    state_path = tmp_path / "srouter.local.json"
    state = _state(active="sg-1")
    state["auto_route_sync"] = True
    _write_state(state_path, state)
    monkeypatch.delitem(sys.modules, "srouter_config", raising=False)
    _install_gateway(monkeypatch, gateway="not-an-ip")  # невалидный -> _gateway_literal вернёт ""
    calls = _install_route_runner(monkeypatch)

    out = _apply_switch(monkeypatch, state_path, tmp_path, name="hk-1")

    assert out["ok"] is True
    sync = out["route_sync"]
    assert sync["added"] is None
    assert "GATEWAY" in sync["error"]
    assert all("-n add -host" not in frag for frag in _route_argv_fragments(calls))


def test_route_sync_ip_literal_rejects_scoped_and_noncanonical():
    """_ip_literal (канон dashboard_common) режет scoped-zone и non-canonical формы."""
    import node_selector

    assert node_selector._ip_literal("203.0.113.44") is True
    assert node_selector._ip_literal("2001:db8::1") is True
    assert node_selector._ip_literal("fe80::1%en0") is False
    assert node_selector._ip_literal("fe80::1%en0;touch x") is False
    assert node_selector._ip_literal("2001:DB8::1") is False
    assert node_selector._ip_literal("2001:db8:0:0:0:0:0:1") is False
    assert node_selector._ip_literal("") is False
    assert node_selector._ip_literal(None) is False


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
