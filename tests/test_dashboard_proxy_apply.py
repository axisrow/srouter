"""POST /api/proxy/{enable,disable} — единый write-путь поверх реестра.

Ловушка, которую обязан обойти этот роут (разведано по коду): git_proxy берёт БЛОКИРУЮЩИЙ
cross-process flock (git_proxy.py, fcntl.LOCK_EX). Flask-хендлер уже держит неблокирующий
_MUTATION_LOCK; если flock занят CLI-процессом (`srouter install`), HTTP-запрос повиснет
без таймаута — lock_hierarchy этот путь не покрывает (там только threading.Lock).
"""
import time

import dashboard
import dashboard_routes
import proxy_registry


def _post(path, payload=None):
    return dashboard.app.test_client().post(
        path,
        json=payload if payload is not None else {},
        headers={"Origin": "http://127.0.0.1:8787"},
    )


def _post_raw(path, *, data, content_type="application/json"):
    """POST с сырым телом (не через json=) — единственный способ отправить malformed JSON
    или non-JSON content-type, который Flask.get_json(silent=True) не распарсит."""
    return dashboard.app.test_client().post(
        path,
        data=data,
        content_type=content_type,
        headers={"Origin": "http://127.0.0.1:8787"},
    )


def test_enable_delegates_to_registry(monkeypatch):
    seen = {}

    def fake_apply(ids=None, *, action, force=False):
        seen["ids"], seen["action"] = ids, action
        return {"ok": True, "results": [{"id": "git", "ok": True, "err": ""}]}

    monkeypatch.setattr(proxy_registry, "apply", fake_apply)
    r = _post("/api/proxy/enable", {"ids": ["git"]})
    assert r.status_code == 200
    assert seen == {"ids": ["git"], "action": "enable"}


def test_unknown_action_is_rejected_by_route_whitelist():
    """Вайтлист в роуте, а не только в реестре (канон: мутирующий роут валидирует сам)."""
    assert _post("/api/proxy/destroy", {"ids": ["git"]}).status_code == 404


def test_failure_returns_non_200(monkeypatch):
    """git/claude роуты исторически отдают 200 даже при ok=false; новый роут так не делает."""
    monkeypatch.setattr(proxy_registry, "apply",
                        lambda ids=None, *, action, force=False: {"ok": False, "results":
                                                     [{"id": "git", "ok": False, "err": "боль"}]})
    r = _post("/api/proxy/enable", {"ids": ["git"]})
    assert r.status_code != 200
    assert r.get_json()["ok"] is False


def test_non_list_ids_is_rejected():
    """ids приходит от клиента — форму проверяем до передачи в реестр."""
    r = _post("/api/proxy/enable", {"ids": "git"})
    assert r.status_code == 400


def test_malformed_json_body_is_rejected_not_treated_as_apply_all(monkeypatch):
    """ДЫРА (cycle-review PR #306, Codex confidence 0.98): `request.get_json(silent=True)
    or {}` не различает «валидное пустое тело {}» (осознанное apply-ко-всем) от «битое тело/
    ошибка транспорта» — оба схлопываются в {} -> ids=None -> все управляемые потребители.
    Сбой транспорта или неверный Content-Type не должен незаметно включить/выключить
    прокси у git/Claude/VSCode — должен быть честный 400, а не молчаливый apply-all."""
    called = []
    monkeypatch.setattr(proxy_registry, "apply",
                        lambda ids=None, *, action, force=False: called.append(ids) or {"ok": True, "results": []})
    r = _post_raw("/api/proxy/enable", data=b"{not valid json", content_type="application/json")
    assert r.status_code == 400, f"malformed JSON должен давать 400, получили {r.status_code}"
    assert called == [], "proxy_registry.apply не должен был вызываться с malformed телом"


def test_null_json_body_is_rejected_not_treated_as_apply_all(monkeypatch):
    """Тело `null` — валидный JSON, но не object; тоже не должно стать ids=None-apply-all."""
    called = []
    monkeypatch.setattr(proxy_registry, "apply",
                        lambda ids=None, *, action, force=False: called.append(ids) or {"ok": True, "results": []})
    r = _post_raw("/api/proxy/enable", data=b"null", content_type="application/json")
    assert r.status_code == 400
    assert called == []


def test_empty_object_body_still_means_apply_all(monkeypatch):
    """Контрольный случай: явный {} — валидный apply-all запрос, НЕ должен сломаться фиксом."""
    called = []
    monkeypatch.setattr(proxy_registry, "apply",
                        lambda ids=None, *, action, force=False: called.append(ids) or {"ok": True, "results": []})
    r = _post("/api/proxy/enable", {})
    assert r.status_code == 200
    assert called == [None]


def test_ids_omitted_means_all_manageable(monkeypatch):
    seen = {}
    monkeypatch.setattr(proxy_registry, "apply",
                        lambda ids=None, *, action, force=False: seen.update(ids=ids) or {"ok": True, "results": []})
    _post("/api/proxy/enable", {})
    assert seen["ids"] is None


def test_cross_origin_post_is_rejected():
    """CSRF-guard обязан покрывать новый мутирующий роут (канон privileged-boundary)."""
    r = dashboard.app.test_client().post(
        "/api/proxy/enable", json={}, headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


# ==================== issue #307: force + conflict 409 ====================

def test_force_flag_is_forwarded_to_registry(monkeypatch):
    """force — осознанное действие клиента: роут обязан донести его до реестра."""
    seen = {}

    def fake_apply(ids=None, *, action, force=False):
        seen["force"] = force
        return {"ok": True, "results": []}

    monkeypatch.setattr(proxy_registry, "apply", fake_apply)
    assert _post("/api/proxy/enable", {"ids": ["git"], "force": True}).status_code == 200
    assert seen["force"] is True


def test_force_defaults_to_false(monkeypatch):
    seen = {}

    def fake_apply(ids=None, *, action, force=False):
        seen["force"] = force
        return {"ok": True, "results": []}

    monkeypatch.setattr(proxy_registry, "apply", fake_apply)
    _post("/api/proxy/enable", {"ids": ["git"]})
    assert seen["force"] is False


def test_non_bool_force_is_rejected():
    """force — вайтлист типа: строка/число от клиента не может протащить «истину»."""
    r = _post("/api/proxy/enable", {"ids": ["git"], "force": "yes"})
    assert r.status_code == 400


def test_conflict_returns_409_not_500(monkeypatch):
    """Чужое значение — это КОНФЛИКТ состояния (клиент должен показать confirm), а не
    серверная ошибка. 409 различим для панели, 500 — нет."""
    def fake_apply(ids=None, *, action, force=False):
        return {"ok": False,
                "results": [{"id": "git", "ok": False, "conflict": True,
                             "state": "foreign", "err": "foreign value"}]}

    monkeypatch.setattr(proxy_registry, "apply", fake_apply)
    r = _post("/api/proxy/enable", {"ids": ["git"]})
    assert r.status_code == 409
    assert r.get_json()["results"][0]["conflict"] is True


def test_plain_failure_stays_non_200_non_409(monkeypatch):
    """Рядовая ошибка (не конфликт) — как раньше, не 409 (панель не покажет confirm)."""
    def fake_apply(ids=None, *, action, force=False):
        return {"ok": False, "results": [{"id": "git", "ok": False, "err": "flock unavailable"}]}

    monkeypatch.setattr(proxy_registry, "apply", fake_apply)
    r = _post("/api/proxy/enable", {"ids": ["git"]})
    assert r.status_code == 500


def test_blocking_flock_cannot_hang_the_request(monkeypatch):
    """Роут не должен зависать: если git_proxy ждёт межпроцессный flock, нужен предел.

    Проверяем контракт, а не время: реестр вызывается через обёртку с таймаутом, и её
    срабатывание даёт честный ok=false, а не бесконечное ожидание.
    """
    import threading
    started = threading.Event()

    def never_returns(ids=None, *, action, force=False):
        started.set()
        # Имитируем захваченный flock. Ждём немного дольше бюджета роута (1s):
        # длиннее не нужно — ThreadPoolExecutor на выходе ждёт поток, и лишние
        # секунды здесь напрямую тормозят весь набор.
        threading.Event().wait(3)
        return {"ok": True, "results": []}

    monkeypatch.setattr(proxy_registry, "apply", never_returns)
    monkeypatch.setattr(dashboard_routes, "_PROXY_APPLY_TIMEOUT_SEC", 1)
    r = _post("/api/proxy/enable", {"ids": ["git"]})
    assert started.is_set()
    assert r.status_code != 200
    assert "timeout" in str(r.get_json()).lower() or "таймаут" in str(r.get_json()).lower()


def test_timeout_response_is_actually_bounded_by_wall_clock(monkeypatch):
    """ДЫРА (cycle-review PR #300, Codex confidence 0.99): предыдущий тест проверял только
    статус-код/тело ответа, не реальное время. `with ThreadPoolExecutor(...) as pool:` на
    выходе из блока вызывает pool.__exit__ -> shutdown(wait=True) БЕЗУСЛОВНО, даже когда
    future.result() уже кинул TimeoutError раньше — return внутри with не освобождает HTTP-
    ответ немедленно, Python сначала дожидается shutdown(wait=True), который блокируется на
    зависшем потоке. Заявленный бюджет _PROXY_APPLY_TIMEOUT_SEC честен только на бумаге:
    реальная latency ответа равна max(timeout, время_зависшего_потока), не timeout.
    """
    import threading
    started = threading.Event()
    STUB_SLEEP = 2.0
    TIMEOUT = 0.3

    def never_returns(ids=None, *, action, force=False):
        started.set()
        threading.Event().wait(STUB_SLEEP)
        return {"ok": True, "results": []}

    monkeypatch.setattr(proxy_registry, "apply", never_returns)
    monkeypatch.setattr(dashboard_routes, "_PROXY_APPLY_TIMEOUT_SEC", TIMEOUT)
    t0 = time.monotonic()
    r = _post("/api/proxy/enable", {"ids": ["git"]})
    elapsed = time.monotonic() - t0
    assert started.is_set()
    assert r.status_code != 200
    # Реальный HTTP-ответ обязан вернуться в пределах заявленного бюджета (+запас на
    # накладные расходы), а не ждать, пока зависший поток отработает свои STUB_SLEEP секунд.
    assert elapsed < TIMEOUT + 1.0, (
        f"ответ занял {elapsed:.2f}s при заявленном таймауте {TIMEOUT}s — "
        f"ThreadPoolExecutor.__exit__ заблокировал возврат на зависшем потоке "
        f"({STUB_SLEEP}s stub sleep), заявленный бюджет не соблюдается"
    )
