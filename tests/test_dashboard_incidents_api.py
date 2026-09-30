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
    buckets = dashboard_routes._incident_counts(lines, days=30, now=now)
    assert sum(b["count"] for b in buckets.values()) == 0, \
        "мусор/legacy/без-ts не считаются инцидентами; вневходовое событие могло перенести состояние"


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
    assert today["slots"][14] == {"count": 1, "down": 1, "bad_min": 30.0}, \
        "текущий час несёт бакет; эпизод с 14:30 не закрыт — полчаса плохого времени"
    assert today["slots"][16] is None and today["slots"][23] is None, "часы после now — null"
    assert all(s is not None for s in payload["days"][0]["slots"]), "прошлые дни — все 24 часа"


def test_incidents_payload_empty_log_still_full_grid(monkeypatch, tmp_path):
    _lines(monkeypatch, [])
    payload = dashboard_routes._incidents_payload(2,
                                                  now=datetime(2026, 9, 28, 15, 0))
    assert payload["status"] == "ok"
    assert len(payload["days"]) == 2
    assert payload["days"][-1]["slots"][0] == {"count": 0, "down": 0, "bad_min": 0.0}
    assert payload["days"][-1]["slots"][15] == {"count": 0, "down": 0, "bad_min": 0.0}


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
    assert today["slots"][87] == {"count": 1, "down": 1, "bad_min": 10.0}, "14:30 — в слот 87"
    assert today["slots"][89] == {"count": 0, "down": 0, "bad_min": 10.0}, \
        "слот 14:50–15:00 без единого перехода, но эпизод не закрыт — bad_min"
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


# ---------------- net-фильтр: инциденты конкретной сети ----------------

def _net_ev(net, ts, prev="ok", cur="down"):
    ev = {"timestamp": _local_iso(ts),
          "previous": {"status": prev, "failed": []},
          "current": {"status": cur, "failed": ["x"]}}
    if net is not None:
        ev["net"] = net
    return json.dumps(ev, ensure_ascii=False)


def test_incident_counts_net_filter():
    now = datetime(2026, 9, 28, 15, 0)
    lines = [_net_ev("103", now - timedelta(minutes=40)),
             _net_ev("888-5G", now - timedelta(minutes=20))]
    day = now.date().isoformat()
    b103 = dashboard_routes._incident_counts(lines, days=30, now=now, net="103")
    assert b103[(day, 14)]["count"] == 1, "фильтр 103 — только событие 103"
    ball = dashboard_routes._incident_counts(lines, days=30, now=now)
    assert ball[(day, 14)]["count"] == 2, "без net — обе сети в одном бакете"
    assert dashboard_routes._incident_counts(lines, days=30, now=now, net="no-such") == {}


def test_incident_counts_net_filter_excludes_rows_without_net():
    now = datetime(2026, 9, 28, 15, 0)
    lines = [_net_ev(None, now - timedelta(minutes=30))]  # legacy-строка до PR #385
    assert dashboard_routes._incident_counts(lines, days=30, now=now, net="103") == {}, \
        "строки без net не принадлежат ни одной конкретной сети"


# ---------------- bad_min: время в плохом состоянии, а не только переходы ----------------

def test_bad_min_sustained_down_paints_silent_slots():
    now = datetime(2026, 9, 28, 15, 0)
    lines = [_net_ev("103", now - timedelta(minutes=70))]  # 13:50 ok→down, дальше тишина
    buckets = dashboard_routes._incident_counts(lines, days=30, now=now, net="103")
    day = now.date().isoformat()
    assert buckets[(day, 13)]["bad_min"] == 10.0, "хвост плохого часа 13:xx (13:50→14:00)"
    assert buckets[(day, 14)]["count"] == 0 and buckets[(day, 14)]["bad_min"] == 60.0, \
        "КЛЮЧЕВОЙ кейс: час без единого перехода, но сеть была мертва весь слот — не зелёный"
    assert buckets[(day, 14)]["down"] == 0


def test_bad_min_closes_on_recovery_and_crosses_day():
    now = datetime(2026, 9, 28, 1, 0)
    lines = [_net_ev("103", now - timedelta(minutes=70), prev="ok", cur="down"),   # вчера 23:50
             _net_ev("103", now - timedelta(minutes=50), prev="down", cur="ok")]   # сегодня 00:10
    buckets = dashboard_routes._incident_counts(lines, days=30, now=now, net="103")
    yesterday = (now - timedelta(days=1)).date().isoformat()
    today = now.date().isoformat()
    assert buckets[(yesterday, 23)]["bad_min"] == 10.0
    assert buckets[(today, 0)]["bad_min"] == 10.0, "плохое состояние переносится через полночь"
    assert buckets[(today, 0)]["count"] == 0, "down→ok — закрытие эпизода, не инцидент"
    assert "bad_min" not in buckets.get((today, 1), {}) or buckets[(today, 1)]["bad_min"] == 0.0


def test_bad_min_tail_capped_at_now():
    now = datetime(2026, 9, 28, 15, 0)
    lines = [_net_ev("103", now - timedelta(minutes=5))]
    buckets = dashboard_routes._incident_counts(lines, days=30, now=now, net="103")
    day = now.date().isoformat()
    assert buckets[(day, 14)]["bad_min"] == 5.0, "хвост считается до now, не до конца слота"


def test_bad_min_events_before_window_set_initial_state():
    now = datetime(2026, 9, 28, 1, 0)
    lines = [_net_ev("103", datetime(2026, 9, 27, 23, 50))]  # ok→down до начала окна days=1
    buckets = dashboard_routes._incident_counts(lines, days=1, now=now, net="103")
    day = now.date().isoformat()
    assert buckets[(day, 0)]["bad_min"] == 60.0, "состояние до окна переносится в окно"
    assert buckets[(day, 0)]["count"] == 0, "сам переход вне окна инцидентом не считается"


def test_incidents_payload_nets_list_and_bad_min_shape(monkeypatch):
    now = datetime(2026, 9, 28, 15, 0)
    _lines(monkeypatch, [_net_ev("888-5G", now - timedelta(minutes=30)),
                         _net_ev("103", now - timedelta(minutes=20))])
    payload = dashboard_routes._incidents_payload(1, now=now, net="103")
    assert payload["nets"] == ["103", "888-5G"], "отсортированный список сетей из журнала"
    today = payload["days"][-1]
    assert today["slots"][14] == {"count": 1, "down": 1, "bad_min": 20.0}, \
        "слоты несут bad_min наряду с count/down (эпизод 14:40→now)"


def test_incidents_route_net_param_fail_soft(monkeypatch):
    now = datetime.now()
    _lines(monkeypatch, [_net_ev("103", now - timedelta(minutes=30))])
    r = _get("/api/incidents?net=103")
    assert r.status_code == 200
    data = r.get_json()
    assert data["status"] == "ok"
    assert sum((s or {}).get("count", 0) for s in data["days"][-1]["slots"]) == 1
    r_all = _get("/api/incidents")
    assert r_all.status_code == 200, "без net — backward compat (все сети)"
    r_junk = _get("/api/incidents?net=no-such-net")
    assert r_junk.status_code == 200, "неизвестная сеть — пустая сетка, не 400 (fail-soft)"
    assert sum((s or {}).get("count", 0) for s in r_junk.get_json()["days"][-1]["slots"]) == 0
