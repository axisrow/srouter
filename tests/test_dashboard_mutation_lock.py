"""Server-side mutation-лок для POST mutation-роутов dashboard.py (issue #57).

app.run(threaded=True): каждый POST — отдельный Flask-поток. Клиентский MUTATION-лок
(#14) сериализует одну вкладку, но не multi-tab/прямые POST. Глобальный _MUTATION_LOCK
обязан пускать одно мутирующее действие за раз: занято → 409 структурированно,
освобождение гарантировано (и при исключении в handler), CSRF-403 лок не захватывает,
409-отказ чужой лок не отпускает, GET read-only не блокируется.
"""
import importlib
import sys
import threading
import types

import pytest
import sys_probe


BUSY_ERR = {"ok": False, "err": "another mutation is in progress"}


def _fresh_dashboard(monkeypatch):
    monkeypatch.delitem(sys.modules, "dashboard", raising=False)
    cfg = types.ModuleType("srouter_config")
    cfg.GATEWAY = "192.0.2.1"
    cfg.VPN_SERVER = "198.51.100.20"
    cfg.VPN_EXIT_IP = "198.51.100.20"
    monkeypatch.setitem(sys.modules, "srouter_config", cfg)
    dashboard = importlib.import_module("dashboard")
    dashboard._cache.update(ts=0.0, data=None, active_route_ip="", active_route_key=None)
    dashboard._nodes_cache.update(ts=0.0, data=None)
    return dashboard


def _trap_mutations(monkeypatch, dashboard):
    """Ловушки на привилегированные пути (канон test_dashboard_csrf_guard): если запрос
    при занятом локе дошёл до handler — AssertionError (→500), тест не пройдёт молча."""

    def boom(*a, **k):
        raise AssertionError("запрос дошёл до привилегированного пути при занятом локе")

    monkeypatch.setattr(sys_probe, "run", boom)
    monkeypatch.setattr(dashboard.node_selector, "select_node", boom)
    monkeypatch.setattr(dashboard, "switch_channel", boom)
    monkeypatch.setattr(dashboard.local_state, "save_state", boom)
    monkeypatch.setattr(dashboard.local_state, "enabled_nodes", lambda: [{"name": "sg-1"}])
    monkeypatch.setattr(dashboard.local_state, "active_node", lambda: {"name": "sg-1"})


# Все POST mutation-роуты, которые обязаны быть под общим локом.
MUTATION_POSTS = [
    "/api/node/select/sg-1",
    "/api/route/host",
    "/api/route/add",
    "/api/route/remove",
    "/api/channel/wifi",
    "/api/channel",
    "/api/channel/",
    "/api/service/xray/restart",
    "/api/guard",
]


# --- конкурентность: одно мутирующее действие за раз ---
def test_concurrent_posts_one_wins_second_409_then_lock_released(monkeypatch):
    """Два одновременных POST: один входит в handler, второй → 409 сразу (без ожидания);
    после завершения первого лок освобождён — третий POST проходит."""
    dashboard = _fresh_dashboard(monkeypatch)

    entered = threading.Event()
    release = threading.Event()

    def slow_service_control(name, action):
        entered.set()
        assert release.wait(timeout=5), "тест не отпустил handler"
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(dashboard, "service_control", slow_service_control)

    results = {}

    def first_post():
        results["first"] = dashboard.app.test_client().post("/api/service/xray/restart")

    t = threading.Thread(target=first_post)
    t.start()
    try:
        assert entered.wait(timeout=5), "первый POST не дошёл до handler"

        # Первый держит лок внутри handler → конкурент отбивается структурированным 409.
        second = dashboard.app.test_client().post("/api/service/xray/restart")
        assert second.status_code == 409
        assert second.get_json() == BUSY_ERR
    finally:
        release.set()
        t.join(timeout=5)
    assert not t.is_alive()
    assert results["first"].status_code == 200

    # Лок освобождён после ответа — третий POST доходит до handler.
    third = dashboard.app.test_client().post("/api/service/xray/restart")
    assert third.status_code == 200


@pytest.mark.parametrize("path", MUTATION_POSTS)
def test_busy_lock_rejects_every_mutation_route(monkeypatch, path):
    """При занятом локе КАЖДЫЙ mutation-роут отвечает 409 до handler."""
    dashboard = _fresh_dashboard(monkeypatch)
    _trap_mutations(monkeypatch, dashboard)

    assert dashboard._MUTATION_LOCK.acquire(blocking=False)
    try:
        response = dashboard.app.test_client().post(path)
        assert response.status_code == 409
        assert response.get_json() == BUSY_ERR
    finally:
        dashboard._MUTATION_LOCK.release()


def test_409_rejection_does_not_release_foreign_lock(monkeypatch):
    """409-отказ НЕ отпускает чужой лок: teardown освобождает только лок владельца."""
    dashboard = _fresh_dashboard(monkeypatch)
    _trap_mutations(monkeypatch, dashboard)

    assert dashboard._MUTATION_LOCK.acquire(blocking=False)
    try:
        first = dashboard.app.test_client().post("/api/service/xray/restart")
        assert first.status_code == 409
        # Лок всё ещё у "первого" владельца — повторный конкурент снова 409.
        assert dashboard._MUTATION_LOCK.locked()
        second = dashboard.app.test_client().post("/api/service/xray/restart")
        assert second.status_code == 409
        assert dashboard._MUTATION_LOCK.locked()
    finally:
        dashboard._MUTATION_LOCK.release()


def test_lock_released_after_handler_exception(monkeypatch):
    """Handler бросил → teardown обязан отпустить лок, следующий POST не получает вечный 409."""
    dashboard = _fresh_dashboard(monkeypatch)

    def boom(name, action):
        raise RuntimeError("boom")

    monkeypatch.setattr(dashboard, "service_control", boom)
    crashed = dashboard.app.test_client().post("/api/service/xray/restart")
    assert crashed.status_code == 500
    assert not dashboard._MUTATION_LOCK.locked()

    monkeypatch.setattr(
        dashboard, "service_control", lambda n, a: {"rc": 0, "out": "", "err": "", "timeout": False}
    )
    after = dashboard.app.test_client().post("/api/service/xray/restart")
    assert after.status_code == 200


def test_sequential_posts_do_not_conflict(monkeypatch):
    """Регрессия: лок per-request — последовательные POST проходят как раньше."""
    dashboard = _fresh_dashboard(monkeypatch)
    client = dashboard.app.test_client()
    for _ in range(3):
        # 400 (bad action) доказывает, что запрос ДОШЁЛ до handler-валидации, а не отбит 409.
        response = client.post("/api/route/host", json={"action": "bogus"})
        assert response.status_code == 400


# --- GET read-only не под локом ---
def test_get_status_not_blocked_while_mutation_holds_lock(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard, "gather_status", lambda: {"ok": True})

    assert dashboard._MUTATION_LOCK.acquire(blocking=False)
    try:
        response = dashboard.app.test_client().get("/api/status")
        assert response.status_code == 200
    finally:
        dashboard._MUTATION_LOCK.release()


# --- порядок с CSRF-guard (#58): reject не трогает лок ---
def test_csrf_reject_does_not_take_lock(monkeypatch):
    """Cross-origin POST → 403, лок НЕ взят: следующий легитимный POST проходит."""
    dashboard = _fresh_dashboard(monkeypatch)

    rejected = dashboard.app.test_client().post(
        "/api/route/host", headers={"Origin": "http://evil.com"}
    )
    assert rejected.status_code == 403
    assert not dashboard._MUTATION_LOCK.locked()

    follow_up = dashboard.app.test_client().post("/api/route/host", json={"action": "bogus"})
    assert follow_up.status_code == 400  # дошёл до handler, не 409


def test_csrf_reject_at_busy_lock_is_403_and_keeps_foreign_lock(monkeypatch):
    """CSRF-проверка бьёт РАНЬШЕ лока: при занятом локе cross-origin POST → 403 (не 409),
    и чужой лок остаётся на месте."""
    dashboard = _fresh_dashboard(monkeypatch)
    _trap_mutations(monkeypatch, dashboard)

    assert dashboard._MUTATION_LOCK.acquire(blocking=False)
    try:
        response = dashboard.app.test_client().post(
            "/api/route/host", headers={"Origin": "http://evil.com"}
        )
        assert response.status_code == 403
        assert dashboard._MUTATION_LOCK.locked()
    finally:
        dashboard._MUTATION_LOCK.release()


# --- TOCTOU /api/guard (комментарий в issue #57) ---
def test_guard_read_modify_write_serialized_toctou(monkeypatch):
    """Окно load_state_checked → проверка mode==auto → save_state целиком под локом:
    конкурирующий /api/guard отбивается 409 ДО load, затереть state он не может."""
    dashboard = _fresh_dashboard(monkeypatch)

    entered = threading.Event()
    release = threading.Event()
    saved = []

    monkeypatch.setattr(
        dashboard.local_state,
        "load_state_checked",
        lambda path=None: ({"schema_version": 1, "traffic_guard": {"mode": "off", "domains": {}}}, True),
    )

    def slow_save(state, path=None):
        entered.set()
        assert release.wait(timeout=5), "тест не отпустил save_state"
        saved.append(state)
        return state

    monkeypatch.setattr(dashboard.local_state, "save_state", slow_save)
    monkeypatch.setattr(dashboard, "probe_traffic_guard", lambda **kw: {"status": "ok"})

    results = {}

    def first_post():
        results["first"] = dashboard.app.test_client().post(
            "/api/guard", json={"mode": "on", "domains": {"ads.example.com": "block"}}
        )

    t = threading.Thread(target=first_post)
    t.start()
    try:
        assert entered.wait(timeout=5), "первый POST не дошёл до save_state"

        # Первый ВНУТРИ окна read-modify-write. Конкурент обязан получить 409 сразу.
        second = dashboard.app.test_client().post("/api/guard", json={"mode": "off", "domains": {}})
        assert second.status_code == 409
        assert second.get_json() == BUSY_ERR
    finally:
        release.set()
        t.join(timeout=5)
    assert not t.is_alive()
    assert results["first"].status_code == 200
    # Ровно одна запись state — конкурент ничего не затёр.
    assert len(saved) == 1
    assert saved[0]["traffic_guard"]["mode"] == "on"
