"""Тесты metrics_store: append/read JSONL, retention-ротация, summarize-детектор тренда.

Observe-only контракт (automation ladder): хранилище только пишет/читает/считает,
никаких решений. Все файловые пути — через tmp_path (module-level METRICS_LOG мокается).
"""
import json

import metrics_store
import pytest


def _write_events(path, events):
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")


def _event(ts, total_ms=200, status="ok", connect_ms=1, tls_ms=50, ttfb_ms=100):
    from datetime import datetime
    return {"timestamp": datetime.fromtimestamp(ts).isoformat(), "ts": ts,
            "target": "api.anthropic.com", "code": "200" if status == "ok" else None,
            "status": status, "connect_ms": connect_ms, "tls_ms": tls_ms,
            "ttfb_ms": ttfb_ms, "total_ms": total_ms}


# ============================ build_event ============================

def test_build_event_normalizes_timing_dict():
    ev = metrics_store.build_event(
        {"target": "api.anthropic.com", "code": "200", "status": "ok",
         "connect_ms": 1, "tls_ms": 44, "ttfb_ms": 75, "total_ms": 260},
        now=1700000000.0,
    )
    assert ev["ts"] == 1700000000.0
    assert ev["target"] == "api.anthropic.com"
    assert ev["code"] == "200"
    assert ev["status"] == "ok"
    assert ev["total_ms"] == 260
    assert "timestamp" in ev


def test_build_event_none_timing_becomes_down_event():
    ev = metrics_store.build_event({"status": "down"}, now=1700000000.0)
    assert ev["status"] == "down"
    assert ev["total_ms"] is None
    assert ev["target"] is None


def test_build_event_negative_ms_clamped_to_zero():
    ev = metrics_store.build_event({"status": "ok", "total_ms": -5, "tls_ms": -1}, now=1.0)
    assert ev["total_ms"] == 0
    assert ev["tls_ms"] == 0


def test_build_event_garbage_status_becomes_down():
    ev = metrics_store.build_event({"status": "weird-thing", "code": 200}, now=1.0)
    assert ev["status"] == "down"


def test_build_event_includes_rc_and_err():
    """#315 п.5: rc/err пробы в событии — сигнатуры отказов #301 (exit 56/35/28) видны
    в JSONL ретроспективно, без повторения инцидента."""
    ev = metrics_store.build_event(
        {"status": "connection-failed", "code": "000", "rc": 28,
         "err": "curl: (28) Connection timed out after 4001 milliseconds"},
        now=1700000000.0,
    )
    assert ev["rc"] == 28
    assert ev["err"] == "curl: (28) Connection timed out after 4001 milliseconds"


def test_build_event_rc_err_sanitized():
    """rc-мусор → None (bool — не rc); err bounded: одна строка, ≤ 200 символов."""
    ev = metrics_store.build_event(
        {"status": "ok", "rc": True, "err": "x" * 500 + "\nsecond line"},
        now=1700000000.0,
    )
    assert ev["rc"] is None
    assert "\n" not in (ev["err"] or "")
    assert len(ev["err"]) <= 200


def test_build_event_rc_err_absent_stays_none():
    ev = metrics_store.build_event({"status": "ok", "code": "200"}, now=1.0)
    assert ev["rc"] is None
    assert ev["err"] is None


# ============================ append/read ============================

def test_append_and_read_roundtrip(tmp_path):
    log = tmp_path / "metrics.jsonl"
    assert metrics_store.append_timing_event(metrics_store.build_event({"status": "ok", "total_ms": 100}, now=1000.0), log_path=log)
    assert metrics_store.append_timing_event(metrics_store.build_event({"status": "down"}, now=2000.0), log_path=log)
    events = metrics_store.read_timing_events(hours=1, log_path=log, now=2000.0)
    assert [e["status"] for e in events] == ["ok", "down"]
    assert events[0]["total_ms"] == 100


def test_append_non_dict_returns_false(tmp_path):
    assert metrics_store.append_timing_event("not-a-dict", log_path=tmp_path / "m.jsonl") is False


def test_read_missing_file_returns_empty(tmp_path):
    assert metrics_store.read_timing_events(log_path=tmp_path / "nope.jsonl") == []


def test_read_skips_broken_lines_and_stale_events(tmp_path):
    log = tmp_path / "metrics.jsonl"
    log.write_text(
        "{not json}\n"
        + json.dumps({"ts": 100.0, "status": "ok", "total_ms": 1}) + "\n"
        + json.dumps({"ts": 5000.0, "status": "ok", "total_ms": 2}) + "\n"
        + json.dumps({"no_ts": True}) + "\n",
        encoding="utf-8",
    )
    events = metrics_store.read_timing_events(hours=1, log_path=log, now=5000.0)
    assert len(events) == 1
    assert events[0]["total_ms"] == 2


# ============================ retention ============================

def test_rotate_drops_events_older_than_retention(tmp_path):
    log = tmp_path / "metrics.jsonl"
    _write_events(log, [_event(1000.0), _event(2000.0), _event(9999999.0)])
    assert metrics_store.rotate_metrics_log(log_path=log, retention_days=1, now=10000000.0)
    events = metrics_store.read_timing_events(log_path=log, now=10000000.0)
    assert [e["ts"] for e in events] == [9999999.0]


def test_rotate_keeps_file_when_nothing_to_drop(tmp_path):
    log = tmp_path / "metrics.jsonl"
    fresh = _event(5000.0)
    _write_events(log, [fresh])
    before = log.read_text()
    assert metrics_store.rotate_metrics_log(log_path=log, retention_days=7, now=5000.0)
    assert log.read_text() == before


def test_rotate_drops_broken_lines(tmp_path):
    log = tmp_path / "metrics.jsonl"
    log.write_text("{garbage}\n" + json.dumps({"ts": 5000.0, "status": "ok"}) + "\n", encoding="utf-8")
    assert metrics_store.rotate_metrics_log(log_path=log, retention_days=7, now=5000.0)
    assert "garbage" not in log.read_text()


# ============================ thin_series ============================

def test_thin_series_keeps_endpoints_and_limit():
    pts = metrics_store.thin_series([_event(float(i)) for i in range(100)], max_points=10)
    assert len(pts) == 10
    assert pts[0]["ts"] == 0.0
    assert pts[-1]["ts"] == 99.0


def test_thin_series_short_input_untouched():
    pts = metrics_store.thin_series([_event(1.0), _event(2.0)], max_points=60)
    assert len(pts) == 2


# ============================ summarize ============================

def test_summarize_empty_is_insufficient():
    out = metrics_store.summarize([], now=1000000.0)
    assert out["trend"] == "insufficient"
    assert out["latest"] is None
    assert out["baseline"]["source"] == "none"


def test_summarize_stable_with_trailing_baseline():
    now = 1_000_000.0
    events = [_event(now - 3600.0 * 10, total_ms=200) for _ in range(40)]  # baseline 10ч назад
    events += [_event(now - 60.0 * i, total_ms=200) for i in range(1, 11)]  # окно, всё 200мс
    out = metrics_store.summarize(events, now=now)
    assert out["trend"] == "stable"
    assert out["baseline"]["source"] == "trailing"
    assert out["ratio"] == 1.0
    assert out["latest"]["total_ms"] == 200.0
    assert out["latest"]["failure_rate"] == 0.0


def test_summarize_degraded_when_window_slower_than_baseline():
    now = 1_000_000.0
    events = [_event(now - 3600.0 * 10, total_ms=200) for _ in range(40)]
    events += [_event(now - 60.0 * i, total_ms=500) for i in range(1, 11)]  # ×2.5 медленнее
    out = metrics_store.summarize(events, now=now)
    assert out["trend"] == "degraded"
    assert out["ratio"] == 2.5


def test_summarize_degraded_by_flapping_even_if_survivors_fast():
    """Флап ≥50% окна — деградация, даже если медиана выживших не выросла."""
    now = 1_000_000.0
    events = [_event(now - 3600.0 * 10, total_ms=200) for _ in range(40)]
    events += [_event(now - 60.0 * i, total_ms=200) for i in range(1, 6)]   # 5 ок
    events += [_event(now - 60.0 * i, status="timeout", total_ms=None) for i in range(1, 6)]  # 5 упали
    out = metrics_store.summarize(events, now=now)
    assert out["trend"] == "degraded"
    assert out["latest"]["failure_rate"] == 0.5


def test_summarize_too_few_window_samples_is_insufficient():
    now = 1_000_000.0
    events = [_event(now - 3600.0 * 10, total_ms=200) for _ in range(40)]
    events += [_event(now - 60.0, total_ms=10000)]  # один медленный замер — не тренд
    out = metrics_store.summarize(events, now=now)
    assert out["trend"] == "insufficient"


def test_summarize_prefers_same_hour_baseline_over_trailing():
    now = 1_700_000_000.0
    # 30 ok-замеров 25ч назад (тот же час суток ±30мин не гарантирован, но рядом),
    # и 40 замеров ровно 24ч назад — тот же час.
    same_hour = [_event(now - 24 * 3600.0, total_ms=300) for _ in range(40)]
    trailing = [_event(now - 10 * 3600.0, total_ms=150) for _ in range(40)]
    window = [_event(now - 60.0 * i, total_ms=300) for i in range(1, 11)]
    out = metrics_store.summarize(same_hour + trailing + window, now=now)
    assert out["baseline"]["source"] == "same-hour"
    assert out["baseline"]["total_ms"] == 300.0
    assert out["trend"] == "stable"  # 300 vs 300 same-hour, а не ×2 против 150


def test_summarize_ignores_far_hours_in_same_hour_baseline():
    """Замеры в ДРУГОЙ час суток (2–24ч назад) — trailing, не same-hour."""
    now = 1_700_000_000.0
    other_hour = [_event(now - 3 * 3600.0, total_ms=900) for _ in range(40)]
    window = [_event(now - 60.0 * i, total_ms=200) for i in range(1, 11)]
    out = metrics_store.summarize(other_hour + window, now=now)
    assert out["baseline"]["source"] == "trailing"


def test_summarize_no_baseline_means_insufficient_trend():
    now = 1_000_000.0
    window = [_event(now - 60.0 * i, total_ms=500) for i in range(1, 11)]
    out = metrics_store.summarize(window, now=now)
    assert out["trend"] == "insufficient"
    assert out["latest"]["total_ms"] == 500.0
