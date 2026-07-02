import importlib
import sys
from pathlib import Path

import sys_probe


def _fresh_dashboard_without_legacy_vps(monkeypatch):
    monkeypatch.delitem(sys.modules, "dashboard", raising=False)
    dashboard = importlib.import_module("dashboard")
    # Пустое состояние: нет активного узла -> route_ip == "". Раньше helper подменял
    # sys.modules["srouter_config"], но активный узел всё равно шёл из srouter.local.json
    # (там активный sg-1 с route_ip). Изолируем источник — каноничный паттерн из
    # test_dashboard_mutation_lock (dashboard.local_state.active_node).
    monkeypatch.setattr(dashboard.local_state, "active_node", lambda: {})
    return dashboard


def test_dashboard_source_has_no_legacy_vps_config_lookup():
    source = (Path(__file__).resolve().parent.parent / "dashboard.py").read_text(encoding="utf-8")
    assert "_cfg.VPS_IP" not in source
    assert "VPS_IP = _cfg" not in source


def test_dashboard_import_uses_local_state_without_legacy_vps(monkeypatch):
    dashboard = _fresh_dashboard_without_legacy_vps(monkeypatch)
    assert dashboard.VPS_IP == ""
    assert dashboard.ACTIVE_ENDPOINT == ""


def test_dashboard_empty_state_treats_empty_exit_as_down(monkeypatch):
    dashboard = _fresh_dashboard_without_legacy_vps(monkeypatch)
    monkeypatch.setattr(sys_probe, "run", lambda cmd, timeout: {"rc": 0, "out": "", "err": "", "timeout": False})
    assert dashboard.probe_exit_ip()["status"] == "down"


def test_dashboard_empty_state_does_not_probe_route_without_route_ip(monkeypatch):
    dashboard = _fresh_dashboard_without_legacy_vps(monkeypatch)
    calls = []

    def fake_run(cmd, timeout):
        calls.append(cmd)
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(sys_probe, "run", fake_run)
    assert dashboard.probe_route_to_vps() == {"interface": "", "gateway": "", "split_active": False, "status": "down"}
    assert calls == []


def test_dashboard_sudo_route_rejects_empty_active_route(monkeypatch):
    dashboard = _fresh_dashboard_without_legacy_vps(monkeypatch)

    def fail_run(cmd, timeout):
        raise AssertionError("sudo route must not run without active route_ip")

    monkeypatch.setattr(sys_probe, "run", fail_run)
    out = dashboard.sudo_route("add")
    assert out["rc"] is None
    assert "active route_ip" in out["err"]
