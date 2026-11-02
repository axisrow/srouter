"""Транзакция `ssh_route` (#438): port 22 → всегда туннель, никогда direct.

Прецедент — github_direct (marker-правило, flock, byte-exact rollback, recovery-restart).
Правило НИКОГДА не должно оказаться ПОСЛЕ правила, способного увести порт 22 в direct
(catch-all direct, github-direct on). Фикстуры — tmp-конфиги, рестарт — мок runner.
"""
import json

import local_state_routing
from local_state_routing import SSH_ROUTE_MARKER


def _write_cfg(p, domains, outbound="reality-out", managed=True):
    """Production-подобный конфиг: managed-правило доменов + catch-all direct (как на живой машине)."""
    rule = {"type": "field", "outboundTag": outbound, "domain": list(domains)}
    if managed:
        rule["_srouter_managed"] = True
    p.write_text(json.dumps({
        "outbounds": [{"tag": outbound, "protocol": "vless"}],
        "routing": {"rules": [rule, {"type": "field", "outboundTag": "direct"}]},
    }), encoding="utf-8")


def _write_state(p):
    """state c routing.outbound (adopt-режим) — источник тега туннеля."""
    p.write_text(json.dumps({"schema_version": 1,
                             "routing": {"outbound": "reality-out"}}), encoding="utf-8")


def _ok_runner(calls):
    def run(cmd, timeout):
        calls.append(list(cmd))
        return {"rc": 0, "out": "", "err": "", "timeout": False}
    return run


def _port_checker_settle_then_up():
    calls = {"n": 0}

    def checker(host, port, timeout):
        calls["n"] += 1
        return calls["n"] % 2 == 0
    return checker


def _apply(action, tmp_path, domains, runner, calls=None):
    cfg_p = tmp_path / "config.json"
    state_p = tmp_path / "srouter.local.json"
    _write_cfg(cfg_p, domains)
    _write_state(state_p)
    return local_state_routing.ssh_route(
        action, config_path=cfg_p, state_path=state_p,
        runner=runner, port_checker=_port_checker_settle_then_up()), cfg_p


# ============================ on: правило вставлено и первым ============================


def test_on_inserts_port_rule_before_direct_catchall(tmp_path):
    calls = []
    out, cfg_p = _apply("on", tmp_path, ["domain:example.com"], _ok_runner(calls))

    assert out["ok"] is True and out["changed"] is True, out
    rules = json.loads(cfg_p.read_text(encoding="utf-8"))["routing"]["rules"]
    ssh_rules = [r for r in rules if r.get(SSH_ROUTE_MARKER) is True]
    assert len(ssh_rules) == 1
    assert ssh_rules[0]["port"] == "22"
    assert ssh_rules[0]["outboundTag"] == "reality-out"
    # правило раньше catch-all direct: порт 22 не уходит в direct ни при каком раскладе
    idx_ssh = rules.index(ssh_rules[0])
    idx_direct = [i for i, r in enumerate(rules)
                  if r.get("outboundTag") == "direct" and not r.get(SSH_ROUTE_MARKER)]
    assert idx_direct and idx_ssh < min(idx_direct)
    assert any("xray" in " ".join(c) for c in calls), "рестарт зван"


def test_on_survives_github_direct_on_flip(tmp_path):
    """github-direct on переворачивает github-правило в direct — ssh-правило должно остаться
    РАНЬШЕ него, иначе ssh до github.com:22 уйдёт напрямую (нарушение контракта #438)."""
    domains = ["domain:github.com", "domain:example.com"]
    cfg_p = tmp_path / "config.json"
    state_p = tmp_path / "srouter.local.json"
    _write_cfg(cfg_p, domains)
    _write_state(state_p)
    runner, checker = _ok_runner([]), _port_checker_settle_then_up()

    gd = local_state_routing.github_direct(
        "on", config_path=cfg_p, state_path=state_p, runner=runner, port_checker=checker)
    assert gd["ok"] is True, gd
    out = local_state_routing.ssh_route(
        "on", config_path=cfg_p, state_path=state_p, runner=runner, port_checker=checker)

    assert out["ok"] is True, out
    rules = json.loads(cfg_p.read_text(encoding="utf-8"))["routing"]["rules"]
    gh = [r for r in rules if r.get("_srouter_github")][0]
    ssh_rules = [r for r in rules if r.get(SSH_ROUTE_MARKER) is True]
    assert gh["outboundTag"] == "direct", "github перевёрнут в direct (условие сценария)"
    assert rules.index(ssh_rules[0]) < rules.index(gh), "ssh-правило раньше github-правила"


# ============================ off / idempotency ============================


def test_off_removes_rule(tmp_path):
    runner, checker = _ok_runner([]), _port_checker_settle_then_up()
    _, cfg_p = _apply("on", tmp_path, ["domain:example.com"], runner)

    state_p = tmp_path / "srouter.local.json"
    out = local_state_routing.ssh_route(
        "off", config_path=cfg_p, state_path=state_p, runner=runner, port_checker=checker)

    assert out["ok"] is True and out["changed"] is True, out
    rules = json.loads(cfg_p.read_text(encoding="utf-8"))["routing"]["rules"]
    assert not [r for r in rules if r.get(SSH_ROUTE_MARKER) is True]


def test_on_twice_is_noop_without_restart(tmp_path):
    runner, checker = _ok_runner([]), _port_checker_settle_then_up()
    _, cfg_p = _apply("on", tmp_path, ["domain:example.com"], runner)
    before = cfg_p.read_bytes()
    calls = []

    out = local_state_routing.ssh_route(
        "on", config_path=cfg_p, state_path=tmp_path / "srouter.local.json",
        runner=_ok_runner(calls), port_checker=checker)

    assert out["ok"] is True and out["changed"] is False, out
    assert cfg_p.read_bytes() == before
    assert calls == [], "no-op — рестарт не зван"


def test_off_when_absent_is_noop(tmp_path):
    calls = []
    out, cfg_p = _apply("off", tmp_path, ["domain:example.com"], _ok_runner(calls))

    assert out["ok"] is True and out["changed"] is False, out
    assert calls == []


def test_bad_action_refuses(tmp_path):
    calls = []
    out, cfg_p = _apply("restart", tmp_path, ["domain:example.com"], _ok_runner(calls))

    assert out["ok"] is False and out["err"] == "bad_action"
    assert calls == []


# ============================ rollback / adopt-guard ============================


def test_rollback_on_restart_failure(tmp_path, monkeypatch):
    import install_lib

    cfg_p = tmp_path / "config.json"
    state_p = tmp_path / "srouter.local.json"
    _write_cfg(cfg_p, ["domain:example.com"])
    _write_state(state_p)
    before_cfg = cfg_p.read_bytes()
    restart_calls = []

    def fake_restart(name, runner, *, port_checker=None):
        restart_calls.append(name)
        if len(restart_calls) == 1:
            return {"rc": 1, "out": "", "err": "xray_port_not_up", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(install_lib, "_restart_component", fake_restart)

    out = local_state_routing.ssh_route(
        "on", config_path=cfg_p, state_path=state_p,
        runner=_ok_runner([]), port_checker=None)

    assert out["ok"] is False
    assert out["step"] == "restart"
    assert out["err"].startswith("restart_failed:"), out
    assert cfg_p.read_bytes() == before_cfg, "конфиг откачен byte-exact"
    assert len(restart_calls) == 2, "recovery-рестарт старым конфигом зван"


def test_refuses_without_managed_rule(tmp_path):
    cfg_p = tmp_path / "config.json"
    _write_cfg(cfg_p, ["domain:example.com"], managed=False)
    before = cfg_p.read_bytes()
    calls = []

    out = local_state_routing.ssh_route(
        "on", config_path=cfg_p, state_path=tmp_path / "srouter.local.json",
        runner=_ok_runner(calls), port_checker=None)

    assert out["ok"] is False
    assert out["err"] == "adopt_needed", out
    assert cfg_p.read_bytes() == before
    assert calls == []


# ============================ status / coexistence ============================


def test_status_readonly(tmp_path):
    cfg_p = tmp_path / "config.json"
    _write_cfg(cfg_p, ["domain:example.com"])
    before = cfg_p.read_bytes()

    pre = local_state_routing.ssh_route_status(config_path=cfg_p)
    assert pre == {"ok": True, "on": False}

    runner, checker = _ok_runner([]), _port_checker_settle_then_up()
    state_p = tmp_path / "srouter.local.json"
    _write_state(state_p)
    local_state_routing.ssh_route(
        "on", config_path=cfg_p, state_path=state_p, runner=runner, port_checker=checker)
    on = local_state_routing.ssh_route_status(config_path=cfg_p)

    assert on == {"ok": True, "on": True}
    status_again = local_state_routing.ssh_route_status(config_path=cfg_p)
    assert status_again == on, "status — read-only"


def test_status_unreadable_config(tmp_path):
    out = local_state_routing.ssh_route_status(config_path=tmp_path / "absent.json")
    assert out == {"ok": False, "err": "config_unreadable"}


def test_routing_apply_after_ssh_route_has_no_drift(tmp_path):
    """ssh-правило не трогает managed-состав → routing_apply не умирает по hash_drift."""
    domains = ["domain:example.com"]
    cfg_p = tmp_path / "config.json"
    state_p = tmp_path / "srouter.local.json"
    _write_cfg(cfg_p, domains)
    state_p.write_text(json.dumps({
        "schema_version": 1,
        "routing": {"outbound": "reality-out", "active": list(domains), "active_ips": [],
                    "last_applied_hash":
                        local_state_routing._routing_domains_hash(domains, [])}}),
        encoding="utf-8")
    runner, checker = _ok_runner([]), _port_checker_settle_then_up()
    out = local_state_routing.ssh_route(
        "on", config_path=cfg_p, state_path=state_p, runner=runner, port_checker=checker)
    assert out["ok"] is True, out
    calls = []

    res = local_state_routing.routing_apply(
        ["domain:new.example"], action="add", adopt=False, outbound="reality-out",
        config_path=cfg_p, state_path=state_p, runner=_ok_runner(calls),
        port_checker=checker)

    assert res["ok"] is True, res
    rules = json.loads(cfg_p.read_text(encoding="utf-8"))["routing"]["rules"]
    managed = [r for r in rules if r.get("_srouter_managed")][0]
    assert "domain:new.example" in managed["domain"]
