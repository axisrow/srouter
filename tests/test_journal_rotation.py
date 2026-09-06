"""PR-4 #339: ротация journals (D2) + count-only отчёт root-snapshots (A5).

Контракт §3: D2/D3 — к примитиву rotate_metrics_log с индивидуальными дефолтами;
A5 — «чистить каталоги без manifest-ссылки старше N», но v2 §5: первая итерация —
«только считаем», удаление — отдельное явное решение оператора.

ГРАНИЦА СОГЛАСИЯ (прямое указание автора, PR-4): НИЧЕГО не удалять без явного
согласия — ротация watchdog-журналов ВЫКЛЮЧЕНА по умолчанию (env
SROUTER_WATCHDOG_LOG_ROTATE=1 включает), root-snapshots — только подсчёт/доклад.
"""
import json
import os
from datetime import datetime, timedelta, timezone

import metrics_store


# ============================ примитив: rotate_journal (обобщение rotate_metrics_log) ============================
def _write_lines(path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(l + "\n" for l in lines), encoding="utf-8")


def test_rotate_journal_drops_stale_iso_timestamp_lines(tmp_path):
    """status/lifecycle-формат: JSONL с ISO 'timestamp' (не epoch 'ts' метрик) —
    обобщённый примитет обязан понимать оба через ts_of_line."""
    log = tmp_path / "status.jsonl"
    old = datetime(2026, 8, 1, tzinfo=timezone.utc)
    fresh = datetime(2026, 9, 6, tzinfo=timezone.utc)
    _write_lines(log, [
        json.dumps({"timestamp": old.isoformat(), "current": {"status": "down"}}),
        json.dumps({"timestamp": fresh.isoformat(), "current": {"status": "ok"}}),
    ])

    ok = metrics_store.rotate_journal(
        log, retention_days=14, max_bytes=1024 * 1024,
        now=datetime(2026, 9, 6, 12, tzinfo=timezone.utc),
        ts_of_line=metrics_store.iso_timestamp_ts)

    assert ok is True
    kept = [json.loads(l) for l in log.read_text(encoding="utf-8").splitlines()]
    assert [e["current"]["status"] for e in kept] == ["ok"], "протухшее событие вырезано"


def test_rotate_journal_text_iso_prefix(tmp_path):
    """notify.log-формат: plain-text строка с ISO-префиксом ('<iso> [Sound] msg')."""
    log = tmp_path / "notify.log"
    _write_lines(log, [
        "2026-08-01T00:00:00+07:00 [Basso] упал",
        "2026-09-06T00:00:00+07:00 [Glass] восстановлен",
    ])

    ok = metrics_store.rotate_journal(
        log, retention_days=14, max_bytes=1024 * 1024,
        now=datetime(2026, 9, 6, 12, tzinfo=timezone.utc),
        ts_of_line=metrics_store.iso_prefix_ts)

    assert ok is True
    lines = log.read_text(encoding="utf-8").splitlines()
    assert lines == ["2026-09-06T00:00:00+07:00 [Glass] восстановлен"]


def test_rotate_journal_keeps_fresh_file_untouched(tmp_path):
    """Fresh-голова + размер в лимите → early-exit, файл не переписывается (inode/контент)."""
    log = tmp_path / "status.jsonl"
    fresh = datetime(2026, 9, 6, tzinfo=timezone.utc)
    content = json.dumps({"timestamp": fresh.isoformat()}) + "\n"
    log.write_text(content, encoding="utf-8")
    before = log.stat().st_mtime_ns

    ok = metrics_store.rotate_journal(
        log, retention_days=14, max_bytes=1024 * 1024,
        now=datetime(2026, 9, 6, 12, tzinfo=timezone.utc),
        ts_of_line=metrics_store.iso_timestamp_ts)

    assert ok is True
    assert log.read_text(encoding="utf-8") == content
    assert log.stat().st_mtime_ns == before, "ничего не удалялось — rewrite не нужен"


def test_rotate_journal_broken_line_is_dropped_like_metrics(tmp_path):
    """Семантика rotate_metrics_log сохранена: битая строка (ts не читается) — вырезается."""
    log = tmp_path / "status.jsonl"
    _write_lines(log, ["garbage-not-json", '{"timestamp": "2026-09-06T00:00:00+00:00"}'])

    ok = metrics_store.rotate_journal(
        log, retention_days=14, max_bytes=1024 * 1024,
        now=datetime(2026, 9, 6, 12, tzinfo=timezone.utc),
        ts_of_line=metrics_store.iso_timestamp_ts)

    assert ok is True
    assert log.read_text(encoding="utf-8").splitlines() == ['{"timestamp": "2026-09-06T00:00:00+00:00"}']


def test_rotate_metrics_log_still_delegates_canon(tmp_path):
    """rotate_metrics_log — прежняя семантика (epoch 'ts'), реализована через обобщение."""
    log = tmp_path / "metrics.jsonl"
    _write_lines(log, [
        json.dumps({"ts": 1750000000.0, "status": "ok"}),   # ~58д старше now — вырезается
        json.dumps({"ts": 1755000000.0, "status": "ok"}),
    ])

    ok = metrics_store.rotate_metrics_log(
        log, retention_days=14, max_bytes=1024 * 1024, now=1755000600.0)

    assert ok is True
    kept = [json.loads(l) for l in log.read_text(encoding="utf-8").splitlines()]
    assert [e["ts"] for e in kept] == [1755000000.0]


# ============================ health: ротация watchdog-журналов — выключена по умолчанию ============================
def test_watchdog_journal_rotation_off_by_default(tmp_path, monkeypatch):
    """ГРАНИЦА СОГЛАСИЯ: без SROUTER_WATCHDOG_LOG_ROTATE=1 журналы НЕ трогаются —
    удаление содержимого логов только с явного согласия оператора."""
    import health

    log = tmp_path / "status.jsonl"
    _write_lines(log, ['{"timestamp": "2026-08-01T00:00:00+00:00"}'])
    monkeypatch.delenv("SROUTER_WATCHDOG_LOG_ROTATE", raising=False)
    monkeypatch.setattr(health, "WATCHDOG_STATUS_LOG", log)

    health._rotate_watchdog_journals()

    assert log.read_text(encoding="utf-8") == '{"timestamp": "2026-08-01T00:00:00+00:00"}\n'


def test_watchdog_journal_rotation_enabled_by_env(tmp_path, monkeypatch):
    """SROUTER_WATCHDOG_LOG_ROTATE=1 — осознанный opt-in: протухшие строки вырезаются."""
    import health

    status = tmp_path / "status.jsonl"
    lifecycle = tmp_path / "lifecycle.jsonl"
    notify = tmp_path / "notify.log"
    _write_lines(status, [
        '{"timestamp": "2026-08-01T00:00:00+00:00"}',
        '{"timestamp": "2026-09-06T00:00:00+00:00"}',
    ])
    _write_lines(lifecycle, ['{"timestamp": "2026-08-01T00:00:00+00:00"}'])
    _write_lines(notify, ["2026-09-06T00:00:00+07:00 [Glass] восстановлен"])
    monkeypatch.setenv("SROUTER_WATCHDOG_LOG_ROTATE", "1")
    monkeypatch.setattr(health, "WATCHDOG_STATUS_LOG", status)
    monkeypatch.setattr(health, "WATCHDOG_LIFECYCLE_LOG", lifecycle)
    monkeypatch.setattr(health, "WATCHDOG_NOTIFY_LOG", notify)

    health._rotate_watchdog_journals()

    assert status.read_text(encoding="utf-8").splitlines() == ['{"timestamp": "2026-09-06T00:00:00+00:00"}']
    assert lifecycle.read_text(encoding="utf-8") == "", "протухший lifecycle вырезан целиком"
    assert notify.read_text(encoding="utf-8").splitlines() == ["2026-09-06T00:00:00+07:00 [Glass] восстановлен"]


def test_metrics_hourly_gate_calls_journal_rotation(tmp_path, monkeypatch):
    """Интеграция: journal-ротация висит на том же hourly-гейте, что и metrics-ротация
    (не отдельный таймер; при выключенной ручке — дешёвый no-op)."""
    import health

    calls = []
    monkeypatch.setattr(health, "_rotate_watchdog_journals", lambda: calls.append(1))
    monkeypatch.delenv("SROUTER_WATCHDOG_LOG_ROTATE", raising=False)
    # честный прогон _record_watchdog_metrics с fresh-write и истёкшим last_rotate
    state_path = tmp_path / "metrics-state.json"
    monkeypatch.setattr(health, "WATCHDOG_METRICS_STATE", state_path)
    tun_check = {"id": "tunnel", "ok": True,
                 "timing": {"connect_ms": 1, "tls_ms": 2, "ttfb_ms": 3, "total_ms": 4}}
    metrics_log = tmp_path / "metrics.jsonl"
    monkeypatch.setattr(metrics_store, "METRICS_LOG", metrics_log)
    monkeypatch.setattr(health, "_metrics_probe_options",
                        lambda: {"enabled": True, "interval_sec": 60, "retention_days": 7})

    health._record_watchdog_metrics({"checks": [tun_check]})

    assert calls == [1], "hourly-гейт метрик дёрнул и journal-ротацию"


# ============================ A5: count-only отчёт root-snapshots ============================
def _layout(tmp_path, *, backup_root=None, manifest_path=None):
    import privoxy_system

    root = backup_root or tmp_path / "backups" / "privoxy"
    return privoxy_system.ProtectedLayout(
        manifest_path=manifest_path or tmp_path / "privoxy" / "manifest.json",
        backup_root=root,
    ), root


def _make_snapshot(backup_root, name, age_days):
    d = backup_root / name
    d.mkdir(parents=True)
    stamp = datetime.now(timezone.utc) - timedelta(days=age_days)
    os.utime(d, (stamp.timestamp(), stamp.timestamp()))
    return d


def test_snapshot_report_counts_unreferenced_old_dirs(tmp_path):
    """A5 (контракт §3/v2 §5): count-only — старые каталоги без manifest-ссылки
    перечисляются, но НЕ удаляются (удаление — отдельное явное решение оператора)."""
    import privoxy_system

    layout, backup_root = _layout(tmp_path)
    referenced = _make_snapshot(backup_root, "2026-08-01T000000Z-aaa", age_days=40)
    previous = _make_snapshot(backup_root, "2026-08-05T000000Z-bbb", age_days=35)
    stale = _make_snapshot(backup_root, "2026-08-10T000000Z-ccc", age_days=30)
    fresh_unref = _make_snapshot(backup_root, "2026-09-05T000000Z-ddd", age_days=1)
    layout.manifest_path.parent.mkdir(parents=True, exist_ok=True)
    layout.manifest_path.write_text(json.dumps({
        "backup_dir": str(referenced),
        "previous_protection_backup_dir": str(previous),
    }), encoding="utf-8")

    report = privoxy_system.snapshot_accumulation_report(layout=layout, older_than_days=28)

    assert report["old_unreferenced"] == [str(stale)], report
    assert set(report["referenced"]) == {str(referenced), str(previous)}
    # НИЧЕГО не удалено (count-only)
    assert stale.exists() and fresh_unref.exists() and referenced.exists() and previous.exists()


def test_snapshot_report_no_manifest_marks_all_old_as_candidates(tmp_path):
    """Manifest отсутствует → все старые каталоги кандидаты, но опять же БЕЗ удаления
    (fail-closed: manifest_missing мы не знаем, что уже не нужно)."""
    import privoxy_system

    layout, backup_root = _layout(tmp_path)
    old = _make_snapshot(backup_root, "2026-08-01T000000Z-aaa", age_days=40)

    report = privoxy_system.snapshot_accumulation_report(layout=layout, older_than_days=28)

    assert report["old_unreferenced"] == [str(old)]
    assert report["manifest_missing"] is True
    assert old.exists()


def test_snapshot_report_unreadable_root_is_fail_soft(tmp_path):
    """0700 root-каталог из user-процесса → error-поле, не исключение (doctor-грань)."""
    import privoxy_system

    layout, _ = _layout(tmp_path, backup_root=tmp_path / "nonexistent-root",
                        manifest_path=tmp_path / "nonexistent-root-manifest.json")

    report = privoxy_system.snapshot_accumulation_report(layout=layout)

    assert report["old_unreferenced"] == []
    assert report["error"], "сбой чтения отражён в report, не брошен"


def test_doctor_edge_warns_on_root_snapshot_accumulation(tmp_path, monkeypatch):
    """Doctor-грань (PR-3 health_backups) подхватывает A5-отчёт: старые каталоги без
    manifest-ссылки → warn «накопление root-snapshots» (count-only, без удаления)."""
    import health_backups
    import privoxy_system

    state = tmp_path / "srouter.local.json"
    state.write_text(json.dumps({"schema_version": 1, "detected_environment": {}}),
                     encoding="utf-8")
    monkeypatch.setattr(
        privoxy_system, "snapshot_accumulation_report",
        lambda *a, **kw: {"error": "", "older_than_days": 28,
                          "old_unreferenced": ["/Library/.../2026-08-01T000000Z-aaa"]})

    result = health_backups.check_backup_slots(state_path=state)

    assert any("root-snapshots" in f for f in result["findings"]), result["findings"]
