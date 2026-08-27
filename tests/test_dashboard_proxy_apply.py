"""POST /api/proxy/{enable,disable} — единый write-путь поверх реестра.

Ловушка, которую обязан обойти этот роут (разведано по коду): git_proxy берёт БЛОКИРУЮЩИЙ
cross-process flock (git_proxy.py, fcntl.LOCK_EX). Flask-хендлер уже держит неблокирующий
_MUTATION_LOCK; если flock занят CLI-процессом (`srouter install`), HTTP-запрос повиснет
без таймаута — lock_hierarchy этот путь не покрывает (там только threading.Lock).
"""
import dashboard
import dashboard_routes
import proxy_registry


def _post(path, payload=None):
    return dashboard.app.test_client().post(
        path,
        json=payload if payload is not None else {},
        headers={"Origin": "http://127.0.0.1:8787"},
    )


def test_enable_delegates_to_registry(monkeypatch):
    seen = {}

    def fake_apply(ids=None, *, action):
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
                        lambda ids=None, *, action: {"ok": False, "results":
                                                     [{"id": "git", "ok": False, "err": "боль"}]})
    r = _post("/api/proxy/enable", {"ids": ["git"]})
    assert r.status_code != 200
    assert r.get_json()["ok"] is False


def test_non_list_ids_is_rejected():
    """ids приходит от клиента — форму проверяем до передачи в реестр."""
    r = _post("/api/proxy/enable", {"ids": "git"})
    assert r.status_code == 400


def test_ids_omitted_means_all_manageable(monkeypatch):
    seen = {}
    monkeypatch.setattr(proxy_registry, "apply",
                        lambda ids=None, *, action: seen.update(ids=ids) or {"ok": True, "results": []})
    _post("/api/proxy/enable", {})
    assert seen["ids"] is None


def test_cross_origin_post_is_rejected():
    """CSRF-guard обязан покрывать новый мутирующий роут (канон privileged-boundary)."""
    r = dashboard.app.test_client().post(
        "/api/proxy/enable", json={}, headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


def test_blocking_flock_cannot_hang_the_request(monkeypatch):
    """Роут не должен зависать: если git_proxy ждёт межпроцессный flock, нужен предел.

    Проверяем контракт, а не время: реестр вызывается через обёртку с таймаутом, и её
    срабатывание даёт честный ok=false, а не бесконечное ожидание.
    """
    import threading
    started = threading.Event()

    def never_returns(ids=None, *, action):
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
