"""Тесты diag_netprobe: leg_snapshots (окно vs база по ногам) и diagnose_degradation.

Атрибуция деградации отвечает «почему тормозит»: Wi-Fi/роутер → провайдер → транзит
до VPS → сам VPS → DPI. Все файлы — tmp_path, время — параметр now (чистые функции).
"""
import json

import diag_netprobe
import metrics_store


def _leg_row(ts, leg, sent=3, recv=3, avg_ms=None):
    return {"ts": ts, "timestamp": "2026-09-28T10:00:00+08:00", "leg": leg,
            "target": "1.2.3.4", "net": None, "iface": "en0",
            "sent": sent, "recv": recv, "avg_ms": avg_ms}


def _write_log(path, rows, extra_lines=()):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
        for line in extra_lines:
            f.write(line + "\n")
    return path


# ============================ leg_snapshots ============================

def test_leg_snapshots_window_median_and_loss(tmp_path):
    now = 1_000_000.0
    log = _write_log(tmp_path / "n.jsonl",
                     [_leg_row(now - 3600.0 * 10, "vps", recv=3, avg_ms=50) for _ in range(40)]
                     + [_leg_row(now - 60, "vps", recv=2, avg_ms=100),
                        _leg_row(now - 120, "vps", recv=2, avg_ms=200),
                        _leg_row(now - 180, "vps", recv=3, avg_ms=300)])
    vps = diag_netprobe.leg_snapshots(now=now, log_path=log)["vps"]
    assert vps["avg_ms"] == 200.0                 # медиана окна
    assert vps["samples"] == 3
    assert abs(vps["loss"] - 0.222) < 1e-9        # 1 - 7/9, round до 3 знаков
    assert vps["loss_base"] == 0.016              # база = окно + 40 чистых старых раундов


def test_leg_snapshots_baseline_differs_from_window(tmp_path):
    now = 1_000_000.0
    log = _write_log(tmp_path / "n.jsonl",
                     [_leg_row(now - 3600.0 * 30, "vps", avg_ms=50) for _ in range(40)]
                     + [_leg_row(now - 60 * i, "vps", avg_ms=500) for i in range(1, 4)])
    vps = diag_netprobe.leg_snapshots(now=now, log_path=log)["vps"]
    assert vps["avg_ms"] == 500.0
    assert vps["avg_ms_base"] == 50.0


def test_leg_snapshots_missing_leg_none_fields(tmp_path):
    now = 1_000_000.0
    log = _write_log(tmp_path / "n.jsonl", [_leg_row(now - 60, "vps", avg_ms=100)])
    out = diag_netprobe.leg_snapshots(now=now, log_path=log)
    for leg in ("gateway", "domestic"):
        assert out[leg]["avg_ms"] is None
        assert out[leg]["avg_ms_base"] is None
        assert out[leg]["loss"] is None
        assert out[leg]["samples"] == 0


def test_leg_snapshots_skips_ssid_and_broken_lines(tmp_path):
    now = 1_000_000.0
    log = _write_log(tmp_path / "n.jsonl", [_leg_row(now - 60, "vps", avg_ms=100)],
                     extra_lines=[json.dumps({"ts": now - 60, "leg": "ssid", "ssid": "home"}),
                                  "{not json}"])
    out = diag_netprobe.leg_snapshots(now=now, log_path=log)
    assert out["vps"]["samples"] == 1
    assert "ssid" not in out


def test_leg_snapshots_missing_log_fail_open(tmp_path):
    out = diag_netprobe.leg_snapshots(log_path=tmp_path / "nope.jsonl")
    for leg in diag_netprobe.LEGS:
        assert out[leg]["avg_ms"] is None
        assert out[leg]["loss"] is None


# ============================ diagnose_degradation ============================

def _snap(avg=None, base=None, loss=None, loss_base=None, samples=3):
    return {"avg_ms": avg, "avg_ms_base": base, "loss": loss,
            "loss_base": loss_base, "samples": samples}


def _legs(**kw):
    d = {leg: _snap(avg=50, base=50, loss=0.0, loss_base=0.0)
         for leg in ("gateway", "domestic", "vps")}
    d.update(kw)
    return d


def _summary(connect=None, tls=None, ttfb=None, total=None,
             cur_ttfb=None, base_ttfb=None, cur_tls=None, base_tls=None):
    return {"latest": {"ttfb_ms": cur_ttfb, "tls_ms": cur_tls},
            "baseline": {"phases": {"ttfb_ms": base_ttfb, "tls_ms": base_tls}},
            "ratios": {"connect": connect, "tls": tls, "ttfb": ttfb, "total": total}}


def test_diagnose_gateway_ratio_suspects_wifi():
    legs = _legs(gateway=_snap(avg=28, base=12, loss=0.0, loss_base=0.0))
    out = diag_netprobe.diagnose_degradation(_summary(tls=1.0, connect=1.0), legs)
    assert out is not None
    assert out["suspect"] == "Wi-Fi/роутер"
    assert "×2.3" in out["evidence"]


def test_diagnose_domestic_ratio_suspects_provider():
    legs = _legs(domestic=_snap(avg=84, base=40, loss=0.0, loss_base=0.0))
    out = diag_netprobe.diagnose_degradation(_summary(tls=1.0, connect=1.0), legs)
    assert out is not None
    assert out["suspect"] == "провайдер (дом→интернет)"


def test_diagnose_vps_loss_and_tls_suspects_transit():
    legs = _legs(vps=_snap(avg=265, base=85, loss=0.14, loss_base=0.0))
    out = diag_netprobe.diagnose_degradation(
        _summary(connect=1.0, tls=2.5, cur_tls=290, base_tls=116), legs)
    assert out is not None
    assert out["suspect"] == "транзит до VPS"
    assert "потери 14%" in out["evidence"]


def test_diagnose_vps_clean_ttfb_up_suspects_vps():
    """ICMP до VPS чист, но TTFB вырос — тормозит сам сервер (нагрузка/выход)."""
    out = diag_netprobe.diagnose_degradation(
        _summary(connect=1.0, tls=1.1, ttfb=2.1, cur_ttfb=630, base_ttfb=300), _legs())
    assert out is not None
    assert out["suspect"] == "сам VPS"
    assert "TTFB ×2.1" in out["evidence"]


def test_diagnose_tls_up_connect_flat_suspects_dpi():
    """TLS-фаза растёт при чистом connect и без данных vps-ноги — DPI/потери на пути."""
    legs = _legs(vps=_snap())
    out = diag_netprobe.diagnose_degradation(
        _summary(connect=1.0, tls=2.4, cur_tls=290, base_tls=120), legs)
    assert out is not None
    assert out["suspect"].startswith("DPI")


def test_diagnose_all_normal_returns_none():
    assert diag_netprobe.diagnose_degradation(
        _summary(connect=1.0, tls=1.0, ttfb=1.0), _legs()) is None


def test_diagnose_insufficient_data_returns_none():
    assert diag_netprobe.diagnose_degradation(
        _summary(), _legs(gateway=_snap(), domestic=_snap(), vps=_snap())) is None
    assert diag_netprobe.diagnose_degradation(None, None) is None


# ============================ report ============================

def test_report_prints_segment_line(tmp_path, capsys, monkeypatch):
    now = 1_000_000.0
    tunnel = [{"ts": now - 60, "status": "ok", "connect_ms": 10, "tls_ms": 250,
               "ttfb_ms": 100, "total_ms": 400}] * 11
    legs = [_leg_row(now - 60, "vps", recv=2, avg_ms=265),
            _leg_row(now - 30 * 3600, "vps", recv=3, avg_ms=85)]

    def fake_read(hours=None, max_lines=None, log_path=None, now=None):
        return list(tunnel) if log_path == metrics_store.METRICS_LOG else list(legs)

    monkeypatch.setattr(metrics_store, "read_timing_events", fake_read)
    diag_netprobe.report()
    out = capsys.readouterr().out
    assert "Сегмент" in out
    assert "транзит" in out or "неопределим" in out


# ============================ мульти-таргет: корреляция по канарейке (2026-09-29) ============================
# Metrics-JSONL теперь мульти-таргетный: вендор-события (netflix/github) не должны
# участвовать ни в окнах блэкаутов туннеля, ни в diagnose_degradation — корреляция
# с netprobe-ногами остаётся на стабильной канареечной серии (api.anthropic.com).

def test_canary_tunnel_events_keeps_canary_and_legacy_only():
    events = [
        {"target": "api.anthropic.com", "status": "ok", "ts": 1.0},
        {"target": "www.netflix.com", "status": "ok", "ts": 2.0},
        {"target": None, "status": "down", "ts": 3.0},
        {"ts": 4.0, "status": "ok"},                 # без ключа target = legacy
        "мусор-строка",
        42,
    ]
    out = diag_netprobe._canary_tunnel_events(events)
    targets = [e.get("target") for e in out]
    assert targets == ["api.anthropic.com", None, None], \
        "вендор-цели вырезаны, канарейка и legacy-события остались"


def test_blackout_windows_ignore_foreign_targets(monkeypatch, tmp_path):
    """Окна блэкаутов строятся из канареечных фейлов: вечный лежащий netflix
    не рисует «блэкауты туннеля» и не портит вердикт (а)/(б)."""
    now = 1_000_000.0
    rows = [{"ts": now - 3600, "target": "www.netflix.com", "status": "connection-failed"},
            {"ts": now - 3500, "target": "www.netflix.com", "status": "connection-failed"},
            {"ts": now - 300, "target": "api.anthropic.com", "status": "ok"}]
    monkeypatch.setattr(metrics_store, "METRICS_LOG", tmp_path / "m.jsonl")
    _write_log(tmp_path / "m.jsonl", rows)
    tunnel = metrics_store.read_timing_events(log_path=tmp_path / "m.jsonl")
    windows = diag_netprobe._blackout_windows(diag_netprobe._canary_tunnel_events(tunnel))
    assert windows == [], "вендор-фейлы не создают окон туннеля"
