"""Роут инцидентов: GET /api/incidents — почасовой календарь деградаций watchdog.

Источник — status.jsonl (переходы previous→current); инцидент = начало не-ok
эпизода (previous.status == "ok", current in degraded/down). Обserve-only:
на календарь ничто не влияет, только показывается. GET → без _MUTATION_LOCK.
"""
import json
from datetime import datetime, timedelta

import pytest

import dashboard
import dashboard_routes


def _get(path):
    return dashboard.app.test_client().get(path)


def _local_iso(dt):
    """ISO-штамп с локальным offset — бакет агрегатора в локальной шкале, тест
    детерминирован на любой TZ-машине."""
    return dt.astimezone().isoformat()


def _lines(monkeypatch, lines):
    monkeypatch.setattr(dashboard_routes, "_read_status_events",
                        lambda max_lines=None, log_path=None: list(lines))


# ---------------- агрегатор: что считается инцидентом ----------------

def test_incident_counts_only_ok_to_not_ok_transitions():
    now = datetime(2026, 9, 28, 15, 0)
    lines = [
        json.dumps({"timestamp": _local_iso(now - timedelta(minutes=40)),
                    "previous": {"status": "ok", "failed": []},
                    "current": {"status": "down", "failed": ["upstream VPS"]}}, ensure_ascii=False),
        json.dumps({"timestamp": _local_iso(now - timedelta(minutes=30)),
                    "previous": {"status": "down", "failed": ["upstream VPS"]},
                    "current": {"status": "degraded", "failed": ["upstream VPS"]}}, ensure_ascii=False),
        json.dumps({"timestamp": _local_iso(now - timedelta(minutes=20)),
                    "previous": {"status": "degraded", "failed": ["upstream VPS"]},
                    "current": {"status": "ok", "failed": []}}, ensure_ascii=False),
        json.dumps({"timestamp": _local_iso(now - timedelta(minutes=10)),
                    "previous": {"status": "ok", "failed": []},
                    "current": {"status": "degraded", "failed": ["туннель"]}}, ensure_ascii=False),
    ]
    buckets = dashboard_routes._incident_counts(lines, days=30, now=now)
    day = now.date().isoformat()
    assert buckets[(day, 14)]["count"] == 2, "два начала не-ok эпизода: ok→down и ok→degraded"
    assert buckets[(day, 14)]["down"] == 1, "из них один с текущим status=down"
    assert sum(b["count"] for b in buckets.values()) == 2, \
        "down→degraded и degraded→ok — не инциденты (эпизод продолжается/закрылся)"


def test_incident_counts_skips_garbage_and_out_of_window():
    now = datetime(2026, 9, 28, 15, 0)
    lines = [
        "не-json мусор",
        json.dumps({"timestamp": _local_iso(now - timedelta(days=40)),
                    "previous": {"status": "ok", "failed": []},
                    "current": {"status": "down", "failed": ["x"]}}, ensure_ascii=False),
        json.dumps({"timestamp": "не-iso", "previous": {"status": "ok", "failed": []},
                    "current": {"status": "down", "failed": ["x"]}}, ensure_ascii=False),
        json.dumps({"timestamp": _local_iso(now - timedelta(minutes=5)),
                    "previous": "degraded", "current": "ok"}, ensure_ascii=False),  # legacy-строки
        json.dumps({"previous": {"status": "ok", "failed": []},
                    "current": {"status": "down", "failed": ["x"]}}, ensure_ascii=False),  # без ts
    ]
    assert dashboard_routes._incident_counts(lines, days=30, now=now) == {}


def test_incident_counts_buckets_by_local_hour_and_day():
    now = datetime(2026, 9, 28, 1, 0)
    lines = [
        json.dumps({"timestamp": _local_iso(now - timedelta(hours=2)),  # вчера, 23:xx
                    "previous": {"status": "ok", "failed": []},
                    "current": {"status": "down", "failed": ["x"]}}, ensure_ascii=False),
        json.dumps({"timestamp": _local_iso(now - timedelta(minutes=10)),  # сегодня, 00:xx
                    "previous": {"status": "ok", "failed": []},
                    "current": {"status": "down", "failed": ["x"]}}, ensure_ascii=False),
    ]
    buckets = dashboard_routes._incident_counts(lines, days=30, now=now)
    total = sum(b["count"] for b in buckets.values())
    assert total == 2
    today = now.date().isoformat()
    yesterday = (now - timedelta(days=1)).date().isoformat()
    assert buckets[(today, 0)]["count"] == 1 and buckets[(today, 0)]["down"] == 1
    assert buckets[(yesterday, 23)]["count"] == 1, "событие до полуночи — во вчерашний бакет"


# ---------------- payload: форма ответа ----------------

def test_incidents_payload_shape_days_grid_and_future_nulls(monkeypatch):
    now = datetime(2026, 9, 28, 15, 0)
    event = json.dumps({"timestamp": _local_iso(now - timedelta(minutes=30)),
                        "previous": {"status": "ok", "failed": []},
                        "current": {"status": "down", "failed": ["x"]}}, ensure_ascii=False)
    _lines(monkeypatch, [event])
    payload = dashboard_routes._incidents_payload(3, now=now)
    assert payload["status"] == "ok"
    assert payload["bucket_minutes"] == 60, "дефолтный бакет — час"
    assert [d["date"] for d in payload["days"]] == \
        [(now - timedelta(days=i)).date().isoformat() for i in (2, 1, 0)], "новые дни последними"
    today = payload["days"][-1]
    assert len(today["slots"]) == 24
    assert today["slots"][14] == {"count": 1, "down": 1}, "текущий час несёт бакет"
    assert today["slots"][16] is None and today["slots"][23] is None, "часы после now — null"
    assert all(s is not None for s in payload["days"][0]["slots"]), "прошлые дни — все 24 часа"


def test_incidents_payload_empty_log_still_full_grid(monkeypatch, tmp_path):
    _lines(monkeypatch, [])
    payload = dashboard_routes._incidents_payload(2,
                                                  now=datetime(2026, 9, 28, 15, 0))
    assert payload["status"] == "ok"
    assert len(payload["days"]) == 2
    assert payload["days"][-1]["slots"][0] == {"count": 0, "down": 0}
    assert payload["days"][-1]["slots"][15] == {"count": 0, "down": 0}


# ---------------- читатель: fail-soft хвост JSONL ----------------

def test_read_status_events_missing_file_empty(monkeypatch, tmp_path):
    monkeypatch.setattr(dashboard_routes, "_INCIDENTS_LOG", tmp_path / "absent.jsonl")
    assert dashboard_routes._read_status_events() == []


def test_read_status_events_reads_tail(monkeypatch, tmp_path):
    log = tmp_path / "status.jsonl"
    event = json.dumps({"timestamp": "2026-09-28T14:00:00+08:00",
                        "previous": {"status": "ok", "failed": []},
                        "current": {"status": "down", "failed": ["x"]}})
    log.write_text(event + "\nмусор\n", encoding="utf-8")
    monkeypatch.setattr(dashboard_routes, "_INCIDENTS_LOG", log)
    out = dashboard_routes._read_status_events()
    assert len(out) == 2, "битые строки не роняют чтение"


# ---------------- роут ----------------

@pytest.fixture(autouse=True)
def _no_real_incidents_log(monkeypatch, tmp_path):
    monkeypatch.setattr(dashboard_routes, "_INCIDENTS_LOG", tmp_path / "absent.jsonl")


def test_incidents_route_ok(monkeypatch):
    now = datetime.now()
    event = json.dumps({"timestamp": _local_iso(now - timedelta(minutes=30)),
                        "previous": {"status": "ok", "failed": []},
                        "current": {"status": "down", "failed": ["x"]}}, ensure_ascii=False)
    _lines(monkeypatch, [event])
    r = _get("/api/incidents")
    assert r.status_code == 200
    data = r.get_json()
    assert data["status"] == "ok"
    assert sum(s["count"] for s in data["days"][-1]["slots"] if s) == 1


def test_incidents_route_days_validated(monkeypatch):
    _lines(monkeypatch, [])
    assert _get("/api/incidents?days=abc").status_code == 400
    assert _get("/api/incidents?days=0").status_code == 400
    assert _get("/api/incidents?days=91").status_code == 400
    assert _get("/api/incidents?days=90").status_code == 200
    assert _get("/api/incidents").status_code == 200, "без параметра — дефолтные 30 дней"


def test_incidents_route_fail_soft_on_crash(monkeypatch):
    def boom(max_lines=None, log_path=None):
        raise OSError("log vanished")
    monkeypatch.setattr(dashboard_routes, "_read_status_events", boom)
    r = _get("/api/incidents")
    assert r.status_code == 200
    assert r.get_json()["status"] == "warn"


def test_incidents_route_is_get_only_no_mutation_lock(monkeypatch):
    _lines(monkeypatch, [])
    assert dashboard._MUTATION_LOCK.acquire(blocking=False)
    try:
        assert _get("/api/incidents").status_code == 200
    finally:
        dashboard._MUTATION_LOCK.release()


# ---------------- 10-минутные бакеты (переключатель календаря) ----------------

def test_incident_counts_bucket_10m_slot_boundaries():
    now = datetime(2026, 9, 28, 19, 15)

    def ev(ts):
        return json.dumps({"timestamp": _local_iso(ts),
                           "previous": {"status": "ok", "failed": []},
                           "current": {"status": "down", "failed": ["x"]}}, ensure_ascii=False)

    lines = [ev(now - timedelta(minutes=8)),   # 19:07
             ev(now - timedelta(minutes=5))]   # 19:10 — граница бакетов
    buckets = dashboard_routes._incident_counts(lines, days=30, now=now, bucket_minutes=10)
    day = now.date().isoformat()
    assert buckets[(day, 114)]["count"] == 1, "19:07 — в слот 19:00–19:10 (114)"
    assert buckets[(day, 115)]["count"] == 1, "19:10 — уже следующий слот (115)"
    assert buckets[(day, 115)]["down"] == 1


def test_incidents_payload_bucket_10m_grid(monkeypatch):
    now = datetime(2026, 9, 28, 15, 0)
    event = json.dumps({"timestamp": _local_iso(now - timedelta(minutes=30)),  # 14:30 → слот 87
                        "previous": {"status": "ok", "failed": []},
                        "current": {"status": "down", "failed": ["x"]}}, ensure_ascii=False)
    _lines(monkeypatch, [event])
    payload = dashboard_routes._incidents_payload(2, now=now, bucket_minutes=10)
    assert payload["bucket_minutes"] == 10
    today = payload["days"][-1]
    assert len(today["slots"]) == 144
    assert today["slots"][87] == {"count": 1, "down": 1}, "14:30 — в слот 87"
    assert today["slots"][91] is None and today["slots"][143] is None, "бакеты после now — null"
    assert all(s is not None for s in payload["days"][0]["slots"]), "прошлый день — все 144 слота"


def test_incidents_route_bucket_validated(monkeypatch):
    _lines(monkeypatch, [])
    assert _get("/api/incidents?bucket=abc").status_code == 400
    assert _get("/api/incidents?bucket=7").status_code == 400
    assert _get("/api/incidents?bucket=0").status_code == 400
    assert _get("/api/incidents?bucket=10").status_code == 200
    assert _get("/api/incidents?bucket=10").get_json()["bucket_minutes"] == 10
    assert _get("/api/incidents").get_json()["bucket_minutes"] == 60, "без параметра — дефолтный час"
