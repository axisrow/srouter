"""Тесты классов проб #396: direct (без прокси), bulk (объёмная передача), via_proxy-режим
_tunnel_target_up. Мок формата -w — живой захват #396 (curl к speed.cloudflare.com/__down,
7 токенов: code connect appconnect starttransfer total size_download speed_download).
"""
import pytest

import health
import metrics_store
from health_constants import _PROXY


# ============================ _tunnel_target_up(via_proxy=...) ============================

def _capture_run(monkeypatch, out="200 0.000453 0.410941 0.649536 1.286087", rc=0):
    """Мок sys_probe.run: захват cmd и env; -w печатает заданный вывод."""
    captured = {}

    def fake_run(cmd, timeout, env=None):
        captured["cmd"] = cmd
        captured["env"] = env
        return {"rc": rc, "out": out, "err": "", "timeout": False}

    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    return captured


def test_tunnel_target_up_proxy_mode_keeps_proxy_flag(monkeypatch):
    """Дефолт via_proxy=True — как раньше: -x _PROXY в команде, env не трогается."""
    captured = _capture_run(monkeypatch)
    health._tunnel_target_up("https://github.com/")
    assert "-x" in captured["cmd"] and _PROXY in captured["cmd"]


def test_tunnel_target_up_direct_mode_drops_proxy_flag(monkeypatch):
    """via_proxy=False — curl БЕЗ -x и с env без proxy-переменных (прямой ход #396)."""
    captured = _capture_run(monkeypatch)
    ok, detail, kind, timing = health._tunnel_target_up(
        "https://www.baidu.com/", via_proxy=False)
    assert ok is True and kind == "ok"
    assert "-x" not in captured["cmd"]
    env = captured["env"] or {}
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        assert key not in env, f"{key} должен быть вырезан из env прямого хода"


def test_no_proxy_env_strips_all_proxy_vars(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8118")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:8118")
    monkeypatch.setenv("NO_PROXY", "z.ai")
    env = health._no_proxy_env()
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        assert key not in env


# ============================ _bulk_status: чистый маппинг исходов ============================

def test_bulk_status_full_download_is_ok():
    assert health._bulk_status(0, 200, 262144, 262144) == "ok"


def test_bulk_status_short_download_is_not_ok():
    """<90% объёма при rc 0 — недокачано, не ok (обрыв без явного rc)."""
    assert health._bulk_status(0, 200, 100000, 262144) != "ok"


def test_bulk_status_5xx_is_upstream_error():
    """Вендор/CDN ответил 5xx — канал жив, категория не bulk-фейл."""
    assert health._bulk_status(0, 503, 0, 262144) == "upstream-error"


@pytest.mark.parametrize("rc", [56, 35, 52, 18])
def test_bulk_status_reset_class_rcs(rc):
    """56=recv-reset посреди передачи (класс Forge), 18=partial file, 35/52=TLS/повтор."""
    assert health._bulk_status(rc, "200", 1000, 262144) == "reset"


def test_bulk_status_stall_vs_timeout():
    assert health._bulk_status(28, "200", 50000, 262144) == "stalled"
    assert health._bulk_status(28, "000", 0, 262144) == "timeout"


def test_bulk_status_other_rc_is_connection_failed():
    assert health._bulk_status(7, "000", 0, 262144) == "connection-failed"


# ============================ _bulk_probe ============================

_BULK_OUT = "200 0.000453 0.410941 0.649536 1.286087 262144 203830"


def test_bulk_probe_parses_size_and_speed(monkeypatch):
    """7-токенный -w (живой захват #396) → kind=bulk, bytes_dl, kibs=speed/1024."""
    captured = _capture_run(monkeypatch, out=_BULK_OUT)
    timing = health._bulk_probe()
    assert timing["kind"] == "bulk"
    assert timing["status"] == "ok"
    assert timing["bytes_dl"] == 262144
    assert timing["kibs"] == pytest.approx(203830 / 1024, abs=0.1)
    assert timing["target"] == "speed.cloudflare.com"
    assert "-x" in captured["cmd"], "bulk через туннель (зарубежный эндпоинт)"
    assert "--speed-limit" in captured["cmd"] and "--speed-time" in captured["cmd"], \
        "ловушка stall: --speed-limit/--speed-time (байты перестали течь → rc 28)"


def test_bulk_probe_legacy_five_token_output_bulk_fields_none(monkeypatch):
    """curl не выдал size/speed (частичный -w) → bulk-поля None, timing жив."""
    _capture_run(monkeypatch, out="200 0.000453 0.410941 0.649536 1.286087")
    timing = health._bulk_probe()
    assert timing["bytes_dl"] is None
    assert timing["kibs"] is None
    assert timing["status"] == "ok"


def test_bulk_probe_reset_rc_56_maps_to_reset_status(monkeypatch):
    captured = _capture_run(monkeypatch, out="", rc=56)
    timing = health._bulk_probe()
    assert timing["status"] == "reset"
    assert timing["rc"] == 56


# ============================ _direct_up ============================

def test_direct_up_or_semantics_any_target_ok(monkeypatch):
    """baidu не ответил (000), github 200 → класс direct жив (OR-семантика канареек)."""
    def fake_run(cmd, timeout, env=None):
        url = cmd[-1] if cmd else ""
        if "baidu" in url:
            return {"rc": 7, "out": "000", "err": "connection refused", "timeout": False}
        return {"rc": 0, "out": "200 0.001 0.05 0.06 0.07", "err": "", "timeout": False}

    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    ok, detail, timings = health._direct_up()
    assert ok is True
    assert len(timings) == 2
    assert all(t["kind"] == "direct" for t in timings)


def test_direct_up_all_down(monkeypatch):
    def fake_run(cmd, timeout, env=None):
        return {"rc": 28, "out": "000", "err": "", "timeout": False}

    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    ok, detail, timings = health._direct_up()
    assert ok is False
    assert len(timings) == len(health.DIRECT_PROBE_URLS)


def test_direct_up_default_targets_domestic_plus_github(monkeypatch):
    """Прямые цели #396: baidu (domestica-эталон) + github (A/B с tunnel-рядом)."""
    hosts = {health._url_host(u) for u in health.DIRECT_PROBE_URLS}
    assert "www.baidu.com" in hosts
    assert "github.com" in hosts


def test_direct_up_extra_targets_replaces_defaults(monkeypatch):
    """extra_targets вместо дефолта (замер по конфигу probes.metrics_direct_targets)."""
    def fake_run(cmd, timeout, env=None):
        return {"rc": 0, "out": "204 0.001 0.05 0.06 0.07", "err": "", "timeout": False}

    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    ok, _, timings = health._direct_up(extra_targets=["https://www.gstatic.com/generate_204"])
    assert ok is True
    assert [t["target"] for t in timings] == ["www.gstatic.com"]


# ============================ wiring: запись классов + флап-гейт ============================

def test_tunnel_window_stats_ignores_non_tunnel_kinds(tmp_path, monkeypatch):
    """РЕГРЕСС #396: bulk-reset/direct-фейл НЕ раздувает failure_rate флап-гейта, даже
    если их target совпал с канарейкой — класс решает event_kind, не хост."""
    now = 1_000_000.0
    log = tmp_path / "m.jsonl"
    canary = "api.anthropic.com"
    for st, kind, code in (("ok", "tunnel", "200"), ("ok", "tunnel", "200"),
                           ("ok", "tunnel", "200"), ("reset", "bulk", "200"),
                           ("timeout", "direct", "000")):
        e = metrics_store.build_event(
            {"status": st, "kind": kind, "target": canary, "code": code}, now=now - 60)
        metrics_store.append_timing_event(e, log_path=log)
    stats = health._tunnel_window_stats(now=now, log_path=log)
    assert stats == {"fails": 0, "samples": 3, "rate": 0.0}


def test_record_watchdog_metrics_writes_all_three_classes(tmp_path, monkeypatch):
    """Write-тик пишет tunnel+direct+bulk события с ОДНОЙ net-меткой и вердикт в sidecar."""
    import metrics_store as ms

    log = tmp_path / "m.jsonl"
    state_path = tmp_path / "watchdog-state.json"
    monkeypatch.setattr(ms, "METRICS_LOG", log)
    monkeypatch.setattr(health, "WATCHDOG_METRICS_STATE", state_path)
    monkeypatch.setattr(health.diag_netprobe, "current_net", lambda: "Atour")
    monkeypatch.setattr(health, "_metrics_probe_options", lambda: {
        "enabled": True, "interval_sec": 60, "retention_days": 7,
        "metrics_targets": ["https://github.com/"],
        "metrics_direct_targets": ["https://www.baidu.com/"],
        "metrics_bulk_target": "https://speed.cloudflare.com/__down?bytes=262144"})
    monkeypatch.setattr(health, "_direct_up", lambda extra_targets=None: (
        True, "HTTP 200", [{"target": "www.baidu.com", "status": "ok", "kind": "direct",
                            "total_ms": 50}]))
    monkeypatch.setattr(health, "_bulk_probe", lambda url=None: {
        "target": "speed.cloudflare.com", "status": "ok", "kind": "bulk",
        "total_ms": 1200, "bytes_dl": 262144, "kibs": 200.0})
    result = {"status": "ok", "checks": [{"id": "tunnel", "name": "туннель", "ok": True,
                                          "timings": [{"target": "api.anthropic.com",
                                                       "status": "ok", "total_ms": 300}] * 4}]}
    health._record_watchdog_metrics(result)
    events = metrics_store.read_timing_events(hours=1, log_path=log, now=None)
    kinds = sorted({e["kind"] for e in events})
    assert kinds == ["bulk", "direct", "tunnel"], kinds
    assert {e["net"] for e in events} == {"Atour"}
    cached = health.cached_attribution(state_path=state_path)
    assert isinstance(cached, dict) and cached["verdict"] == "ok"
