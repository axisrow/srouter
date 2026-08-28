"""Роут единой картины прокси: GET /api/proxy/overview.

Почему отдельный роут, а не поле в /api/status или /health:
  - /health документирован как «мгновенный, лёгкий» (внешний мониторинг/балансеры);
  - gather_status имеет бюджет 12s и кэш 1.5s на телеметрию;
  - парный замер direct-vs-proxy стоит секунды и нужен по требованию, а не каждые 1.5s.

GET (не POST) -> не попадает под _MUTATION_LOCK: чтение картины не должно конкурировать
с мутациями и получать 409.
"""
import dashboard
import proxy_registry


def _get(path):
    return dashboard.app.test_client().get(path)


def test_overview_returns_consumers_and_stack(monkeypatch):
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    r = _get("/api/proxy/overview")
    assert r.status_code == 200
    data = r.get_json()
    assert data["consumers"] and isinstance(data["consumers"], list)
    assert set(("privoxy", "xray")) <= set(data["stack"])
    for c in data["consumers"]:
        assert set(("id", "title", "configured", "runtime")) <= set(c)


def test_light_by_default_no_expensive_probe(monkeypatch):
    """Открытие страницы не должно стоить секунд: замер только по ?probe=1."""
    called = []
    monkeypatch.setattr(proxy_registry, "_effective",
                        lambda: called.append(1) or {"status": "ok"})
    _get("/api/proxy/overview")
    assert called == []


def test_probe_param_triggers_measurement(monkeypatch):
    called = []
    monkeypatch.setattr(proxy_registry, "_effective",
                        lambda: called.append(1) or {"status": "ok", "verdict": "ok"})
    r = _get("/api/proxy/overview?probe=1")
    assert called == [1]
    assert r.get_json()["effective"]["verdict"] == "ok"


def test_probe_param_accepts_only_explicit_truthy(monkeypatch):
    """Вайтлист значения, а не bool(строки): ?probe=0 не должен запускать тяжёлый замер."""
    called = []
    monkeypatch.setattr(proxy_registry, "_effective",
                        lambda: called.append(1) or {"status": "ok"})
    _get("/api/proxy/overview?probe=0")
    assert called == []


def test_overview_is_get_only_no_mutation_lock(monkeypatch):
    """GET не берёт _MUTATION_LOCK — иначе чтение конкурировало бы с мутациями (409)."""
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    # Держим mutation-lock захваченным: GET обязан всё равно ответить 200.
    assert dashboard._MUTATION_LOCK.acquire(blocking=False)
    try:
        assert _get("/api/proxy/overview").status_code == 200
    finally:
        dashboard._MUTATION_LOCK.release()


def test_overview_survives_broken_consumer(monkeypatch):
    """Fail-soft доходит до HTTP: сломанный потребитель не даёт 500."""
    def boom():
        raise RuntimeError("git config сломался")
    monkeypatch.setattr(proxy_registry.git_proxy, "status", boom)
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    r = _get("/api/proxy/overview")
    assert r.status_code == 200
    git = next(c for c in r.get_json()["consumers"] if c["id"] == "git")
    assert git["configured"] is None
