"""Роут качества туннеля: GET /api/metrics/tunnel.

Почему отдельный роут (как /api/proxy/overview): для baseline-тренда читается
7-дневный хвост metrics-JSONL и инкрементально парсится privoxy-лог — это не для
5-секундного поллинга статуса. GET → без _MUTATION_LOCK: observe-only чтение
не ловит 409. Observe-only: тренд ни на что не влияет, только показывается.
"""
import pytest

import dashboard
import dashboard_routes
import metrics_store


@pytest.fixture(autouse=True)
def _reset_metrics_route_cache():
    """TTL-кэш роута общий на процесс — сбрасываем, иначе ответ предыдущего теста
    переживает смену моков (и порядок тестов начинает влиять на результат)."""
    dashboard_routes._metrics_cache.update({"key": None, "at": 0.0, "payload": None})
    yield
    dashboard_routes._metrics_cache.update({"key": None, "at": 0.0, "payload": None})


@pytest.fixture(autouse=True)
def _no_real_proxy_errors(monkeypatch, tmp_path):
    """Не трогать реальный privoxy-лог/кэш этой машины: error-rate всегда замокан
    (тесты, проверяющие его поля, ставят свой мок поверх — он выполняется позже)."""
    monkeypatch.setattr(
        dashboard_routes.proxy_errors, "probe_error_rate",
        lambda **kw: {"status": "disabled", "window_hours": kw.get("window_hours", 1),
                      "total": 0, "errors": 0, "error_rate": None, "by_code": {}})


def _get(path):
    return dashboard.app.test_client().get(path)


def _mock_events(monkeypatch, events):
    monkeypatch.setattr(metrics_store, "read_timing_events", lambda hours=None, **kw: list(events))
    monkeypatch.setattr(metrics_store, "rotate_metrics_log", lambda **kw: True)


def test_metrics_tunnel_returns_no_data_when_empty(monkeypatch):
    _mock_events(monkeypatch, [])
    monkeypatch.setattr(dashboard_routes.proxy_errors, "probe_error_rate",
                        lambda **kw: {"status": "disabled", "window_hours": 1,
                                      "total": 0, "errors": 0, "error_rate": None, "by_code": {}})
    r = _get("/api/metrics/tunnel")
    assert r.status_code == 200
    data = r.get_json()
    assert data["status"] == "no-data"
    assert data["trend"] == "insufficient"
    assert data["series"] == []
    assert data["proxy_errors"]["status"] == "disabled"


def test_metrics_tunnel_returns_trend_and_series(monkeypatch):
    import time
    events = [metrics_store.build_event({"status": "ok", "total_ms": 300}, now=time.time() - 60.0)]
    _mock_events(monkeypatch, events)
    monkeypatch.setattr(dashboard_routes.proxy_errors, "probe_error_rate",
                        lambda **kw: {"status": "ok", "window_hours": 1,
                                      "total": 10, "errors": 1, "error_rate": 0.1, "by_code": {"502": 1}})
    r = _get("/api/metrics/tunnel")
    data = r.get_json()
    assert data["status"] == "ok"
    assert data["latest"]["total_ms"] == 300.0
    assert data["trend"] in ("stable", "degraded", "insufficient")
    assert len(data["series"]) == 1
    assert data["proxy_errors"]["errors"] == 1


def test_metrics_tunnel_hours_whitelisted(monkeypatch):
    _mock_events(monkeypatch, [])
    assert _get("/api/metrics/tunnel?hours=abc").status_code == 400
    assert _get("/api/metrics/tunnel?hours=0").status_code == 400
    assert _get("/api/metrics/tunnel?hours=999").status_code == 400
    assert _get("/api/metrics/tunnel?hours=48").status_code == 200


def test_metrics_tunnel_is_get_only_no_mutation_lock(monkeypatch):
    """GET не берёт _MUTATION_LOCK — иначе чтение конкурировало бы с мутациями (409)."""
    _mock_events(monkeypatch, [])
    assert dashboard._MUTATION_LOCK.acquire(blocking=False)
    try:
        assert _get("/api/metrics/tunnel").status_code == 200
    finally:
        dashboard._MUTATION_LOCK.release()


def test_metrics_tunnel_fail_soft_on_reader_crash(monkeypatch):
    """Fail-soft: сбой чтения JSONL -> 200 со status=warn, не 500 (probe-канон)."""
    def boom(**kw):
        raise OSError("log vanished")
    monkeypatch.setattr(metrics_store, "read_timing_events", boom)
    r = _get("/api/metrics/tunnel")
    assert r.status_code == 200
    assert r.get_json()["status"] == "warn"
    assert "error" in r.get_json()


def test_metrics_tunnel_disabled_reads_nothing(monkeypatch):
    """probes.metrics_enabled=false гасит САМ сбор, а не только отрисовку в UI:
    ни JSONL, ни privoxy-лог (который пишет свой кэш на диск) не трогаются."""
    monkeypatch.setattr(dashboard_routes.health, "_metrics_probe_options",
                        lambda *a, **kw: {"enabled": False, "interval_sec": 60,
                                          "retention_days": 7})

    def forbidden(*a, **kw):
        raise AssertionError("при enabled=false чтение не должно происходить")

    monkeypatch.setattr(metrics_store, "read_timing_events", forbidden)
    monkeypatch.setattr(dashboard_routes.proxy_errors, "probe_error_rate", forbidden)
    r = _get("/api/metrics/tunnel")
    assert r.status_code == 200
    data = r.get_json()
    assert data["enabled"] is False
    assert data["status"] == "disabled"


def test_metrics_tunnel_cached_within_ttl(monkeypatch):
    """Повторный GET в пределах TTL не пересобирает 7-дневный хвост заново."""
    calls = []
    monkeypatch.setattr(metrics_store, "read_timing_events",
                        lambda hours=None, **kw: calls.append(1) or [])
    assert _get("/api/metrics/tunnel").status_code == 200
    assert _get("/api/metrics/tunnel").status_code == 200
    assert len(calls) == 1, "второй запрос обязан прийти из TTL-кэша"
