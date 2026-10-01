"""Тесты атрибуции «что тормозит» (#396): чистый _attribution_from_events по классам
direct/tunnel/bulk + снапшот/кэш для Flask. Пороги — ATTRIB_* из health.
"""
import pytest

import health
import metrics_store


NOW = 1_000_000.0


def _ev(kind, status, age_sec, target="api.anthropic.com", **extra):
    e = metrics_store.build_event(
        {"status": status, "kind": kind, "target": target, "total_ms": 200},
        now=NOW - age_sec)
    e["ts"] = NOW - age_sec
    e.update(extra)
    return e


def _events(tunnel=(10, 0), direct=(10, 0), bulk=(0, 0), ages=None):
    """(ok, fail) по классам → список событий в 10-минутном окне."""
    out = []
    for cls, (ok_n, fail_n), status in (
            ("tunnel", tunnel, "timeout"), ("direct", direct, "timeout"),
            ("bulk", bulk, "reset")):
        for i in range(ok_n):
            out.append(_ev(cls, "ok", 60 + i * 10))
        for i in range(fail_n):
            out.append(_ev(cls, status, 65 + i * 10, target="netflix.com"
                           if cls == "tunnel" else "www.baidu.com"))
    return out


# ============================ правила вердикта ============================

def test_attribution_all_ok_says_ok():
    attr = health._attribution_from_events(_events(), now=NOW)
    assert attr["verdict"] == "ok"
    assert attr["chain_wedge"] is False


def test_attribution_direct_down_says_provider():
    attr = health._attribution_from_events(
        _events(direct=(2, 8)), now=NOW)
    assert attr["verdict"] == "provider"
    assert "провайдер" in attr["culprit"]


def test_attribution_tunnel_timeouts_with_direct_ok_says_wedge():
    """direct жив, туннель молчит (timeout/no-response) — сигнатура застрявшего стека."""
    out = _events(tunnel=(2, 8), direct=(10, 0))
    for e in out:
        if e["kind"] == "tunnel" and e["status"] != "ok":
            e["status"] = "timeout"
            e["rc"] = 28
    attr = health._attribution_from_events(out, now=NOW)
    assert attr["verdict"] == "chain-wedge"
    assert attr["chain_wedge"] is True
    assert "privoxy" in attr["detail"] or "рестарт" in attr["detail"]


def test_attribution_tunnel_resets_with_direct_ok_says_tunnel():
    """direct жив, туннель рвётся соединениями (000/connection-failed) — VPS/DPI."""
    out = _events(tunnel=(2, 8), direct=(10, 0))
    for e in out:
        if e["kind"] == "tunnel" and e["status"] != "ok":
            e["status"] = "connection-failed"
            e["code"] = "000"
    attr = health._attribution_from_events(out, now=NOW)
    assert attr["verdict"] == "tunnel"
    assert attr["chain_wedge"] is False


def test_attribution_site_when_classes_alive_but_one_target_dead():
    """Классы живы, конкретная цель стабильно мертва 1ч — вердикт site, culprit=цель."""
    out = _events()
    for i in range(8):  # netflix: 1 ok из 8 за час (в окне тоже фейлы)
        out.append(_ev("tunnel", "ok" if i == 0 else "upstream-error",
                       300 + i * 300, target="netflix.com"))
    attr = health._attribution_from_events(out, now=NOW)
    assert attr["verdict"] == "site"
    assert attr["culprit"] == "netflix.com"


def test_attribution_channel_when_bulk_resets_with_healthy_handshakes():
    out = _events(bulk=(0, 2))
    attr = health._attribution_from_events(out, now=NOW)
    assert attr["verdict"] == "channel"
    assert "передачи" in attr["culprit"]


def test_attribution_single_failure_does_not_flip_verdict():
    """Шум: 1 фейл туннеля в окне при живом остальном — вердикт ok (rate не двигается)."""
    attr = health._attribution_from_events(
        _events(tunnel=(9, 1)), now=NOW)
    assert attr["verdict"] == "ok"


def test_attribution_insufficient_samples_is_unknown():
    """Fail-open: <4 событий в окне — verdict unknown, UI молчит, не гадает."""
    attr = health._attribution_from_events(
        _events(tunnel=(1, 0), direct=(1, 0)), now=NOW)
    assert attr["verdict"] == "unknown"


def test_attribution_no_direct_data_yet_tunnel_bad_labels_tunnel_transitional():
    """Прямой класс ещё не мерился (деплой свежий), туннель плох — tunnel с честной
    оговоркой в detail (провайдер не исключён), не неизвестность."""
    out = _events(tunnel=(2, 8), direct=(0, 0))
    for e in out:
        if e["kind"] == "tunnel" and e["status"] != "ok":
            e["status"] = "connection-failed"
    attr = health._attribution_from_events(out, now=NOW)
    assert attr["verdict"] == "tunnel"
    assert "прямая" in attr["detail"]


# ============================ снапшот/кэш ============================

def test_snapshot_writes_state_and_cached_reads_back(tmp_path):
    log = tmp_path / "m.jsonl"
    state_path = tmp_path / "state.json"
    for e in _events():
        metrics_store.append_timing_event(e, log_path=log)
    attr = health._attribution_snapshot(now=NOW, log_path=log, state_path=state_path)
    assert attr["verdict"] == "ok"
    cached = health.cached_attribution(state_path=state_path, now=NOW + 60)
    assert cached["verdict"] == "ok"


def test_cached_attribution_stale_returns_none(tmp_path):
    state_path = tmp_path / "state.json"
    health._attribution_snapshot(now=NOW, log_path=tmp_path / "m.jsonl",
                                 state_path=state_path)
    assert health.cached_attribution(state_path=state_path, now=NOW + 400,
                                     max_age_sec=300) is None


def test_cached_attribution_missing_state_returns_none(tmp_path):
    assert health.cached_attribution(state_path=tmp_path / "absent.json") is None
