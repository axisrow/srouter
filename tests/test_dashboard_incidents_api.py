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
import metrics_store


def _get(path):
    return dashboard.app.test_client().get(path)


def _local_iso(dt):
    """ISO-штамп с локальным offset — бакет агрегатора в локальной шкале, тест
    детерминирован на любой TZ-машине."""
    return dt.astimezone().isoformat()


def _epoch(dt):
    """ts-epoch для метрик-строк (datetime.fromtimestamp возвращает naive local)."""
    return dt.astimezone().timestamp()


def _lines(monkeypatch, lines):
    monkeypatch.setattr(dashboard_routes, "_read_status_events",
                        lambda max_lines=None, log_path=None: list(lines))


def _metrics_lines(monkeypatch, tmp_path, rows):
    """Живой формат metrics.jsonl (health.py пишет ts+net в каждой строке, PR #385)."""
    log = tmp_path / "metrics.jsonl"
    log.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
                   encoding="utf-8")
    monkeypatch.setattr(metrics_store, "METRICS_LOG", log)


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
    buckets, _ = dashboard_routes._incident_counts(lines, days=30, now=now)
    day = now.date().isoformat()
    assert buckets[(day, 14)]["count"] == 2, "два начала не-ok эпизода: ok→down и ok→degraded"
    assert buckets[(day, 14)]["down"] == 1, "из них один с текущим status=down"
    assert sum(b["count"] for b in buckets.values()) == 2, \
        "down→degraded и degraded→ok — не инциденты (эпизод продолжается/закрылся)"


def test_incident_counts_tolerates_gated_keys():
    """Диагноз 2026-10-04: события с gated/gated_details (флап-гейт туннеля) агрегатор
    читает как прежде — только .status; служебные ключи не ломают календарь."""
    now = datetime(2026, 10, 4, 15, 0)
    lines = [
        json.dumps({"timestamp": _local_iso(now - timedelta(minutes=5)),
                    "previous": {"status": "ok", "failed": []},
                    "current": {"status": "degraded", "failed": [],
                                "gated": ["туннель"]},
                    "gated_details": {"туннель": "1/10 фейлов за 15м ниже порога"}},
                   ensure_ascii=False),
        json.dumps({"timestamp": _local_iso(now - timedelta(minutes=2)),
                    "previous": {"status": "degraded", "failed": [],
                                 "gated": ["туннель"]},
                    "current": {"status": "ok", "failed": []}}, ensure_ascii=False),
    ]
    buckets, _ = dashboard_routes._incident_counts(lines, days=30, now=now)
    day = now.date().isoformat()
    assert buckets[(day, 14)]["count"] == 1
    assert buckets[(day, 14)]["down"] == 0


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
    buckets, _ = dashboard_routes._incident_counts(lines, days=30, now=now)
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
    buckets, _ = dashboard_routes._incident_counts(lines, days=30, now=now)
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
    assert all(s is None for s in today["slots"][:14]), "до первого события данных нет — null (серый)"
    assert today["slots"][16] is None and today["slots"][23] is None, "часы после now — null"
    assert all(s is None for s in payload["days"][0]["slots"]) \
        and all(s is None for s in payload["days"][1]["slots"]), \
        "дни до первого события журнала — без данных, серые (не зелёные)"


def test_incidents_payload_empty_log_all_null(monkeypatch, tmp_path):
    _lines(monkeypatch, [])
    payload = dashboard_routes._incidents_payload(2,
                                                  now=datetime(2026, 9, 28, 15, 0))
    assert payload["status"] == "ok"
    assert len(payload["days"]) == 2
    assert all(s is None for day in payload["days"] for s in day["slots"]), \
        "пустой журнал — данных нет нигде: null (серый), а не зелёные нули"


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
def _no_real_logs(monkeypatch, tmp_path):
    monkeypatch.setattr(dashboard_routes, "_INCIDENTS_LOG", tmp_path / "absent.jsonl")
    monkeypatch.setattr(metrics_store, "METRICS_LOG", tmp_path / "absent-metrics.jsonl")


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
    buckets, _ = dashboard_routes._incident_counts(lines, days=30, now=now, bucket_minutes=10)
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
    assert all(s is None for s in today["slots"][:87]), "до 14:30 событий не было — null"
    assert today["slots"][89] == {"count": 0, "down": 0, "bad_min": 10.0}, \
        "слот 14:50–15:00 без единого перехода, но эпизод не закрыт — bad_min"
    assert today["slots"][91] is None and today["slots"][143] is None, "бакеты после now — null"
    assert all(s is None for s in payload["days"][0]["slots"]), "прошлый день до первого события — null"


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
    b103, _ = dashboard_routes._incident_counts(lines, days=30, now=now, net="103")
    assert b103[(day, 14)]["count"] == 1, "фильтр 103 — только событие 103"
    ball, _ = dashboard_routes._incident_counts(lines, days=30, now=now)
    assert ball[(day, 14)]["count"] == 2, "без net — обе сети в одном бакете"
    assert dashboard_routes._incident_counts(lines, days=30, now=now, net="no-such") == ({}, None)


def test_incident_counts_net_filter_excludes_rows_without_net():
    now = datetime(2026, 9, 28, 15, 0)
    lines = [_net_ev(None, now - timedelta(minutes=30))]  # legacy-строка до PR #385
    assert dashboard_routes._incident_counts(lines, days=30, now=now, net="103") == ({}, None), \
        "строки без net не принадлежат ни одной конкретной сети"


def test_incident_counts_returns_known_from():
    """known_from — момент, с которого состояние потока известно (серые слоты до него)."""
    now = datetime(2026, 9, 28, 15, 0)
    start = (now - timedelta(days=29)).replace(hour=0, minute=0, second=0, microsecond=0)
    assert dashboard_routes._incident_counts([], days=30, now=now)[1] is None, \
        "нет событий — данных нет нигде"
    _, known_from = dashboard_routes._incident_counts(
        [_net_ev("103", now - timedelta(minutes=30))], days=30, now=now, net="103")
    assert known_from == now - timedelta(minutes=30), "первое событие открывает известность"
    _, known_from = dashboard_routes._incident_counts(
        [_net_ev("103", start - timedelta(minutes=5))], days=30, now=now, net="103")
    assert known_from == start, "событие до окна: состояние известно с начала окна"
    _, known_from = dashboard_routes._incident_counts(
        [_net_ev("103", now + timedelta(days=2))], days=30, now=now, net="103")
    assert known_from == now, "событие «из будущего» (skew часов) не делает всю сетку серой"


# ---------------- bad_min: время в плохом состоянии, а не только переходы ----------------

def test_bad_min_sustained_down_paints_silent_slots():
    now = datetime(2026, 9, 28, 15, 0)
    lines = [_net_ev("103", now - timedelta(minutes=70))]  # 13:50 ok→down, дальше тишина
    buckets, _ = dashboard_routes._incident_counts(lines, days=30, now=now, net="103")
    day = now.date().isoformat()
    assert buckets[(day, 13)]["bad_min"] == 10.0, "хвост плохого часа 13:xx (13:50→14:00)"
    assert buckets[(day, 14)]["count"] == 0 and buckets[(day, 14)]["bad_min"] == 60.0, \
        "КЛЮЧЕВОЙ кейс: час без единого перехода, но сеть была мертва весь слот — не зелёный"
    assert buckets[(day, 14)]["down"] == 0


def test_bad_min_closes_on_recovery_and_crosses_day():
    now = datetime(2026, 9, 28, 1, 0)
    lines = [_net_ev("103", now - timedelta(minutes=70), prev="ok", cur="down"),   # вчера 23:50
             _net_ev("103", now - timedelta(minutes=50), prev="down", cur="ok")]   # сегодня 00:10
    buckets, _ = dashboard_routes._incident_counts(lines, days=30, now=now, net="103")
    yesterday = (now - timedelta(days=1)).date().isoformat()
    today = now.date().isoformat()
    assert buckets[(yesterday, 23)]["bad_min"] == 10.0
    assert buckets[(today, 0)]["bad_min"] == 10.0, "плохое состояние переносится через полночь"
    assert buckets[(today, 0)]["count"] == 0, "down→ok — закрытие эпизода, не инцидент"
    assert "bad_min" not in buckets.get((today, 1), {}) or buckets[(today, 1)]["bad_min"] == 0.0


def test_bad_min_tail_capped_at_now():
    now = datetime(2026, 9, 28, 15, 0)
    lines = [_net_ev("103", now - timedelta(minutes=5))]
    buckets, _ = dashboard_routes._incident_counts(lines, days=30, now=now, net="103")
    day = now.date().isoformat()
    assert buckets[(day, 14)]["bad_min"] == 5.0, "хвост считается до now, не до конца слота"


def test_bad_min_events_before_window_set_initial_state():
    now = datetime(2026, 9, 28, 1, 0)
    lines = [_net_ev("103", datetime(2026, 9, 27, 23, 50))]  # ok→down до начала окна days=1
    buckets, known_from = dashboard_routes._incident_counts(lines, days=1, now=now, net="103")
    assert known_from == now.replace(hour=0, minute=0, second=0, microsecond=0), \
        "событие до окна: сетка известна с начала окна, серых слотов нет"
    day = now.date().isoformat()
    assert buckets[(day, 0)]["bad_min"] == 60.0, "состояние до окна переносится в окно"
    assert buckets[(day, 0)]["count"] == 0, "сам переход вне окна инцидентом не считается"


def test_incidents_payload_nets_list_and_bad_min_shape(monkeypatch, tmp_path):
    now = datetime(2026, 9, 28, 15, 0)
    _lines(monkeypatch, [_net_ev("888-5G", now - timedelta(minutes=30)),
                         _net_ev("103", now - timedelta(minutes=20))])
    _metrics_lines(monkeypatch, tmp_path,
                   [{"ts": _epoch(now - timedelta(minutes=15)), "net": "103"}])
    payload = dashboard_routes._incidents_payload(1, now=now, net="103")
    assert payload["nets"] == ["103", "888-5G"], "отсортированный список сетей из журнала"
    today = payload["days"][-1]
    assert today["slots"][14] == {"count": 1, "down": 1, "bad_min": 20.0}, \
        "слоты несут bad_min наряду с count/down (эпизод 14:40→now)"


def test_incidents_route_net_param_fail_soft(monkeypatch, tmp_path):
    now = datetime.now()
    _lines(monkeypatch, [_net_ev("103", now - timedelta(minutes=30))])
    _metrics_lines(monkeypatch, tmp_path,
                   [{"ts": _epoch(now - timedelta(minutes=30)), "net": "103"},   # слот перехода
                    {"ts": _epoch(now - timedelta(minutes=10)), "net": "103"}])
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


# ---------------- слоты без данных: null (серый), не зелёные нули ----------------

def test_payload_slots_before_first_event_are_null(monkeypatch):
    """Тишина ДО первого события = данных нет (null → серый), а не «всё хорошо».
    Тишина ПОСЛЕ первого события — известное состояние (перенос), остаётся объектом."""
    now = datetime(2026, 9, 28, 15, 0)
    _lines(monkeypatch, [_net_ev("103", now - timedelta(minutes=30))])  # 14:30, первое и единственное
    payload = dashboard_routes._incidents_payload(1, now=now)
    today = payload["days"][-1]
    assert all(s is None for s in today["slots"][:14]), "утро без единого события — null (серый)"
    assert today["slots"][14] == {"count": 1, "down": 1, "bad_min": 30.0}, \
        "слот первого события — данные"
    assert today["slots"][15] == {"count": 0, "down": 0, "bad_min": 0.0}, \
        "после первого события тишина = известное состояние, не null"


def test_payload_net_filter_foreign_events_do_not_known_slots(monkeypatch):
    now = datetime(2026, 9, 28, 15, 0)
    _lines(monkeypatch, [_net_ev("888-5G", now - timedelta(minutes=30))])
    payload = dashboard_routes._incidents_payload(1, now=now, net="103")
    assert all(s is None for s in payload["days"][-1]["slots"]), \
        "нет heartbeats 103 и переходов 103 — сетка без данных (чужая сеть не считается)"


def test_payload_pre_window_event_known_from_window_start(monkeypatch, tmp_path):
    now = datetime(2026, 9, 28, 1, 0)
    _lines(monkeypatch, [_net_ev("103", datetime(2026, 9, 27, 23, 50))])
    _metrics_lines(monkeypatch, tmp_path,
                   [{"ts": _epoch(now - timedelta(minutes=30)), "net": "103"}])
    payload = dashboard_routes._incidents_payload(1, now=now, net="103")
    today = payload["days"][-1]
    assert today["slots"][0] is not None and today["slots"][0]["bad_min"] == 60.0, \
        "событие до окна + покрытие: состояние известно с начала окна — нулей-заглушек нет"


# ---------------- известность net-режима: покрытие heartbeats'ами метрик ----------------

def test_heartbeat_slots_net_filter_and_slot_mapping(monkeypatch, tmp_path):
    """metrics.jsonl — строка каждый цикл с net (PR #385): честный первоисточник
    «watchdog мерил ЭТУ сеть в момент T». Переходы молчат на стабильной сети и
    не различают «сеть ок» от «сеть не мерялась»."""
    now = datetime(2026, 9, 30, 15, 0)
    _metrics_lines(monkeypatch, tmp_path, [
        {"ts": _epoch(datetime(2026, 9, 30, 13, 10)), "net": "888-5G"},
        {"ts": _epoch(datetime(2026, 9, 30, 13, 50)), "net": "103"},
        {"ts": _epoch(datetime(2026, 9, 30, 2, 0)), "net": "103"},     # ночь — только 103
        {"ts": _epoch(datetime(2026, 9, 30, 9, 0))},                   # без net (до PR #385)
        {"timestamp": "мусор", "net": "888-5G"},                        # без ts
        "не-json",
        {"ts": "не-число", "net": "888-5G"},
    ])
    day = now.date().isoformat()
    covered = dashboard_routes._heartbeat_slots("888-5G", 1, now, 60)
    assert covered == {(day, 13)}, "888-5G покрыт только слотом 13:xx"
    covered_103 = dashboard_routes._heartbeat_slots("103", 1, now, 60)
    assert covered_103 == {(day, 2), (day, 13)}, "103: ночь и 13:xx; строка без net сеть не покрывает"


def test_heartbeat_slots_fail_soft_missing_log(monkeypatch, tmp_path):
    monkeypatch.setattr(metrics_store, "METRICS_LOG", tmp_path / "absent.jsonl")
    assert dashboard_routes._heartbeat_slots(
        "103", 1, datetime(2026, 9, 30, 15, 0), 60) == set()


def test_payload_net_mode_gates_on_heartbeat_coverage(monkeypatch, tmp_path):
    """КЛЮЧЕВОЙ кейс пользователя: ночь ноут стоял на 103 — слоты 888-5G серые,
    хотя переход 888 был (перенос состояния не рисуется там, где сеть не мерялась)."""
    now = datetime(2026, 9, 30, 15, 0)
    _lines(monkeypatch, [_net_ev("888-5G", datetime(2026, 9, 30, 0, 10))])  # ok→down в 00:10
    _metrics_lines(monkeypatch, tmp_path,
                   [{"ts": _epoch(datetime(2026, 9, 30, 13, 5)), "net": "888-5G"}])
    payload = dashboard_routes._incidents_payload(1, now=now, net="888-5G")
    slots = payload["days"][-1]["slots"]
    assert slots[0] is None, "00:xx: переход 888 есть, но watchdog мерял 103 — серый"
    assert slots[13] == {"count": 0, "down": 0, "bad_min": 60.0}, \
        "13:xx: покрытие есть; down от перехода 00:10 перенесён в покрытый слот"
    assert all(s is None for s in slots[14:]), "после конца покрытия — серые"
