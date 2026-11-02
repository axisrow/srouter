"""ТДД-тесты health._ssh_tunnel_check (#438): SSH-маршрут — port 22 правило в xray + клиентский
ssh-config через туннель. info-only ВСЕГДА (как _github_direct_check): пользовательский
ssh-клиент не часть srouter-стека — отсутствие правила/дефолтов = подсказка, не сбой стека.
"""
import local_state_routing
import ssh_client_config
import health

_REAL_SSH_TUNNEL_CHECK = health._ssh_tunnel_check


# ============================ предикаты по двум слоям ============================


def test_ok_when_rule_on_and_client_ok(monkeypatch):
    monkeypatch.setattr(local_state_routing, "ssh_route_status",
                        lambda **k: {"ok": True, "on": True})
    monkeypatch.setattr(ssh_client_config, "audit",
                        lambda **k: {"status": "ok", "detail": "SSH через туннель"})
    res = health._ssh_tunnel_check()
    assert res["status"] == "ok"


def test_warn_when_rule_missing(monkeypatch):
    monkeypatch.setattr(local_state_routing, "ssh_route_status",
                        lambda **k: {"ok": True, "on": False})
    monkeypatch.setattr(ssh_client_config, "audit",
                        lambda **k: {"status": "ok", "detail": "SSH через туннель"})
    res = health._ssh_tunnel_check()
    assert res["status"] == "warn"
    assert "ssh route on" in res["detail"], "подсказка включения правила"


def test_down_when_client_bypasses_tunnel(monkeypatch):
    monkeypatch.setattr(local_state_routing, "ssh_route_status",
                        lambda **k: {"ok": True, "on": True})
    monkeypatch.setattr(ssh_client_config, "audit",
                        lambda **k: {"status": "down", "detail": "work: ProxyCommand none"})
    res = health._ssh_tunnel_check()
    assert res["status"] == "down"


def test_warn_when_route_status_errors(monkeypatch):
    monkeypatch.setattr(local_state_routing, "ssh_route_status",
                        lambda **k: {"ok": False, "err": "config_unreadable"})
    monkeypatch.setattr(ssh_client_config, "audit",
                        lambda **k: {"status": "ok", "detail": "SSH через туннель"})
    res = health._ssh_tunnel_check()
    assert res["status"] == "warn"
    assert "config_unreadable" in res["detail"]


def test_never_raises(monkeypatch):
    """Любой мусор от слоёв → status-строка, не бросает (probe-канон)."""
    monkeypatch.setattr(local_state_routing, "ssh_route_status",
                        lambda **k: {"weird": True})
    monkeypatch.setattr(ssh_client_config, "audit",
                        lambda **k: {"status": "мусор", "detail": None})
    res = health._ssh_tunnel_check()
    assert res["status"] in ("ok", "warn", "down", "unknown")


# ============================ check_all: info-only интеграция (не driver) ============================


def test_check_all_has_ssh_check(monkeypatch):
    from test_health import _all_up_monkey  # rootdir-insertion pytest: tests/ в sys.path
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_ssh_tunnel_check", _REAL_SSH_TUNNEL_CHECK)
    monkeypatch.setattr(local_state_routing, "ssh_route_status",
                        lambda **k: {"ok": True, "on": True})
    monkeypatch.setattr(ssh_client_config, "audit",
                        lambda **k: {"status": "ok", "detail": "SSH через туннель"})
    result = health.check_all()
    names = [c["name"] for c in result["checks"]]
    assert any("ssh" in n.lower() for n in names), names


def test_check_all_ssh_is_info_only(monkeypatch):
    from test_health import _all_up_monkey
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_ssh_tunnel_check", _REAL_SSH_TUNNEL_CHECK)
    monkeypatch.setattr(local_state_routing, "ssh_route_status",
                        lambda **k: {"ok": True, "on": False})
    monkeypatch.setattr(ssh_client_config, "audit",
                        lambda **k: {"status": "down", "detail": "нет конфига"})
    result = health.check_all()
    assert result["status"] == "ok", "info-only чек не роняет вердикт"
    ssh_checks = [c for c in result["checks"] if "ssh" in c["name"].lower()]
    assert ssh_checks
    assert all(c.get("info") for c in ssh_checks), "ssh-чек ВСЕГДА info-only"
