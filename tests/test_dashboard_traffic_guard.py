import importlib
import json
import sys
import types


def _fresh_dashboard(monkeypatch):
    monkeypatch.delitem(sys.modules, "dashboard", raising=False)
    # issue #227: app/роуты живут в dashboard_app.py/dashboard_routes.py — при свежем
    # импорте dashboard их тоже надо сбросить, иначе Flask ругнётся на повторную
    # регистрацию роутов на СТАРОМ app (dashboard_app не пересоздаётся сам по себе).
    monkeypatch.delitem(sys.modules, "dashboard_app", raising=False)
    monkeypatch.delitem(sys.modules, "dashboard_routes", raising=False)
    cfg = types.ModuleType("srouter_config")
    cfg.GATEWAY = "192.0.2.1"
    cfg.VPN_SERVER = "198.51.100.20"
    cfg.VPN_EXIT_IP = "198.51.100.20"
    monkeypatch.setitem(sys.modules, "srouter_config", cfg)
    dashboard = importlib.import_module("dashboard")
    dashboard._cache.update(ts=0.0, data=None)
    return dashboard


def test_probe_traffic_guard_reports_counts_and_config_status(monkeypatch, tmp_path):
    dashboard = _fresh_dashboard(monkeypatch)
    state_path = tmp_path / "srouter.local.json"
    state_path.write_text(
        json.dumps(
            {
                "traffic_guard": {
                    "mode": "on",
                    "domains": {
                        "blocked.example.com": "block",
                        "allowed.example.com": "allow",
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    out = dashboard.probe_traffic_guard(state_path=state_path)

    assert out["status"] == "ok"
    assert out["config_status"] == "on"
    assert out["configured_domains"] == 2
    assert out["blocked_domains"] == 1
    assert out["allowed_domains"] == 1
    assert out["rule_count"] == 1


def test_gather_status_registers_traffic_guard_probe(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    # issue #227: gather_status/_run_status_probe_set/probe_nodes_snapshot физически
    # живут в dashboard_app.py — dashboard.py лишь реэкспортирует их.
    dashboard_app = importlib.import_module("dashboard_app")
    seen = {}

    def fake_run_probe_set(probes, budget_sec):
        seen.update(probes)
        return {name: {"status": "ok"} for name in probes}

    monkeypatch.setattr(dashboard_app, "_run_status_probe_set", fake_run_probe_set)
    monkeypatch.setattr(dashboard_app, "probe_nodes_snapshot", lambda: [])

    out = dashboard.gather_status()

    assert "traffic_guard" in seen
    assert "connectivity" in seen
    assert out["traffic_guard"] == {"status": "ok"}
