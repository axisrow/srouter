"""Тесты probe_speedtest (дашборд): чтение журнала speedtest, fail-soft контракт,
регистрация в gather_status (канон «новая телеметрия = новая probe» — образец
test_dashboard_connectivity.test_gather_status_registers_connectivity_probe).
"""
import importlib
import sys
import types

import speedtest_store
from dashboard_network import probe_speedtest


def _record(ts, net="home-5G", dl=0.66):
    return {"ts": ts, "timestamp": "t", "net": net, "net_known": True, "vpn": True,
            "iface": "ipsec0", "isp": "M247 Europe", "download_mbps": dl,
            "upload_mbps": 39.22, "ping_ms": 231.9}


def test_probe_returns_last_and_recent(tmp_path, monkeypatch):
    log = tmp_path / "speedtest.jsonl"
    speedtest_store.append_result(_record(1.0, "office"), log_path=log)
    speedtest_store.append_result(_record(2.0, "home-5G"), log_path=log)
    monkeypatch.setattr(speedtest_store, "SPEEDTEST_LOG", log)
    out = probe_speedtest()
    assert out["status"] == "ok"
    assert out["last"]["net"] == "home-5G"  # newest-first
    assert [r["net"] for r in out["recent"]] == ["home-5G", "office"]


def test_probe_missing_journal_is_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(speedtest_store, "SPEEDTEST_LOG", tmp_path / "nope.jsonl")
    out = probe_speedtest()
    assert out["status"] == "unknown"
    assert out["last"] is None and out["recent"] == []


def test_probe_garbage_journal_never_raises(tmp_path, monkeypatch):
    log = tmp_path / "speedtest.jsonl"
    log.write_text("мусор\n{}\n", encoding="utf-8")
    monkeypatch.setattr(speedtest_store, "SPEEDTEST_LOG", log)
    out = probe_speedtest()  # битые строки/пустой dict — probe не роняем
    assert out["status"] in ("ok", "unknown")


def test_gather_status_registers_speedtest_probe(monkeypatch):
    monkeypatch.delitem(sys.modules, "dashboard", raising=False)
    monkeypatch.delitem(sys.modules, "dashboard_app", raising=False)
    monkeypatch.delitem(sys.modules, "dashboard_routes", raising=False)
    cfg = types.ModuleType("srouter_config")
    cfg.GATEWAY = "192.0.2.1"
    cfg.VPN_SERVER = "198.51.100.20"
    cfg.VPN_EXIT_IP = "198.51.100.20"
    monkeypatch.setitem(sys.modules, "srouter_config", cfg)
    dashboard = importlib.import_module("dashboard")
    dashboard._cache.update(ts=0.0, data=None)
    dashboard._nodes_cache.update(ts=0.0, data=None)
    dashboard_app = importlib.import_module("dashboard_app")
    seen = {}

    def fake_run_probe_set(probes, budget_sec):
        seen.update(probes)
        return {name: {"status": "ok"} for name in probes}

    monkeypatch.setattr(dashboard_app, "_run_status_probe_set", fake_run_probe_set)
    monkeypatch.setattr(dashboard_app, "probe_nodes_snapshot", lambda: [])

    out = dashboard.gather_status()

    assert "speedtest" in seen
    assert out["speedtest"]["status"] == "ok"
