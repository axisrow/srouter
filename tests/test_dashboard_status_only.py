"""?only= — частичный gather_status для двухволнового lazy-UI дашборда.

Контракт:
- only=None — легаси: полный прогон probe, полный ответ, TTL short-circuit как раньше.
- only="a,b" — гоняются ТОЛЬКО запрошенные пробы (+nodes/ts всегда); unknown-ключи
  молча игнорируются (fail-soft, не 4xx); ответ фильтруется до запрошенных ключей
  (light-ответ не затирает fresh heavy-ключи при shallow-merge на клиенте);
  TTL short-circuit не действует — иначе light-опросы каждые 5с «заморозили» бы heavy.
- Кэш МЕРЖИТ волны; смена active_route_key сбрасывает базу — устаревшие ключи не протекают.
"""

import threading

from test_dashboard_active_route import (
    PROBE_NAMES,
    _fresh_dashboard,
    _fresh_dashboard_app,
    _state,
    _write_state,
)


def _stub_probes(monkeypatch, dashboard_app, calls):
    lock = threading.Lock()

    def fake_probe(name):
        def inner(*args, **kwargs):
            with lock:
                calls.append(name)
            return {"status": "ok", "probe": name}

        return inner

    for name in PROBE_NAMES:
        monkeypatch.setattr(dashboard_app, name, fake_probe(name))
    monkeypatch.setattr(
        dashboard_app,
        "probe_nodes_snapshot",
        lambda: [{"name": "sg-1", "status": "ok"}],
    )
    monkeypatch.setattr(dashboard_app, "STATUS_CACHE_TTL_SEC", 999)


# ключи полного ответа gather_status (= ключи probes-словаря dashboard_app)
RESPONSE_KEYS = {
    "services", "tunnel", "exit_ip", "vpn", "route", "direct", "traffic_guard",
    "hot_routes", "isolate", "connectivity", "ips", "ping", "dns", "ifaces",
    "exit_ips", "geo_distance",
}


def _setup(monkeypatch, tmp_path, active="sg-1"):
    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, _state(active))
    dashboard = _fresh_dashboard(monkeypatch, state_path)
    dashboard_app = _fresh_dashboard_app(monkeypatch)
    calls = []
    _stub_probes(monkeypatch, dashboard_app, calls)
    return dashboard, calls


def test_gather_status_only_runs_requested_probes(monkeypatch, tmp_path):
    dashboard, calls = _setup(monkeypatch, tmp_path)

    out = dashboard.gather_status("services,ping")

    assert sorted(calls) == ["probe_ping", "probe_services"]
    assert out["nodes"] == [{"name": "sg-1", "status": "ok"}]
    assert "ts" in out


def test_gather_status_only_ignores_unknown_keys(monkeypatch, tmp_path):
    dashboard, calls = _setup(monkeypatch, tmp_path)

    out = dashboard.gather_status("services,nope,such_probe_missing")

    assert sorted(calls) == ["probe_services"]
    assert out["services"]["probe"] == "probe_services"


def test_gather_status_only_filters_response_keys(monkeypatch, tmp_path):
    dashboard, calls = _setup(monkeypatch, tmp_path)

    out = dashboard.gather_status("services")

    assert "tunnel" not in out
    assert "exit_ip" not in out
    assert out["services"]["status"] == "ok"
    assert "nodes" in out
    assert "ts" in out


def test_gather_status_full_request_unchanged(monkeypatch, tmp_path):
    dashboard, calls = _setup(monkeypatch, tmp_path)

    out = dashboard.gather_status()

    assert sorted(calls) == sorted(PROBE_NAMES)
    assert out["services"]["probe"] == "probe_services"
    assert out["tunnel"]["probe"] == "probe_tunnel"
    assert "nodes" in out
    assert "ts" in out


def test_gather_status_waves_merge_in_cache(monkeypatch, tmp_path):
    dashboard, calls = _setup(monkeypatch, tmp_path)

    dashboard.gather_status("services")
    dashboard.gather_status("ping")

    # волны мержатся в общем кэше, а не затирают друг друга
    assert "services" in dashboard._cache["data"]
    assert "ping" in dashboard._cache["data"]

    # partial-волны не делают кэш «полным»: легаси-запрос перегоняет всё
    full = dashboard.gather_status()
    assert full is dashboard._cache["data"]
    assert RESPONSE_KEYS <= set(full)

    before = calls.count("probe_services")
    dashboard.gather_status("services")
    # only-запросы не садятся на TTL short-circuit — light-данные остаются свежими
    assert calls.count("probe_services") == before + 1


def test_gather_status_only_drops_stale_keys_on_route_change(monkeypatch, tmp_path):
    dashboard, calls = _setup(monkeypatch, tmp_path)

    dashboard.gather_status("ping")
    assert "ping" in dashboard._cache["data"]

    _write_state(tmp_path / "srouter.local.json", _state("hk-1"))
    out = dashboard.gather_status("services")

    # база кэша сброшена сменой маршрута: heavy-ключ старого VPS не протекает
    assert "ping" not in dashboard._cache["data"]
    assert "ping" not in out
    assert dashboard._cache["active_route_key"] == ("hk-1", "203.0.113.20", "203.0.113.20")
    assert sorted(calls) == ["probe_ping", "probe_services"]


def test_gather_status_full_request_does_not_serve_partial_wave_from_cache(monkeypatch, tmp_path):
    """Находка code-review #376: partial-волна пишет в общий кэш — полный запрос
    в пределах TTL не должен получить partial-данные как «полный» ответ."""
    dashboard, calls = _setup(monkeypatch, tmp_path)

    dashboard.gather_status("services")  # light-волна: в кэше только services
    full = dashboard.gather_status()  # легаси-запрос в пределах TTL

    assert len(calls) == len(PROBE_NAMES) + 1, (
        "полный запрос после partial-волны обязан перегнать все пробы"
    )
    assert sorted(set(calls)) == sorted(PROBE_NAMES)
    assert RESPONSE_KEYS <= set(full)
    assert full is dashboard._cache["data"]

    # обратное направление: полный прогон, затем partial, затем полный в TTL — кэш валиден
    before = sorted(calls)
    dashboard.gather_status("services")
    cached = dashboard.gather_status()
    assert cached is dashboard._cache["data"]
    assert len(calls) == len(before) + 1, "partial между полными не должен будить полный TTL-кэш"


def test_gather_status_partial_after_route_change_does_not_serve_stale_full_cache(monkeypatch, tmp_path):
    """Смена маршрута сбрасывает и полноту кэша: полный запрос не берёт union старого VPS."""
    dashboard, calls = _setup(monkeypatch, tmp_path)

    dashboard.gather_status()  # полный прогон, маршрут sg-1
    full_calls = len(calls)
    _write_state(tmp_path / "srouter.local.json", _state("hk-1"))
    dashboard.gather_status("services")  # волна нового маршрута
    full = dashboard.gather_status()

    assert "ping" in full and "tunnel" in full, (
        "полный запрос после смены маршрута обязан пересчитать все пробы заново"
    )
    assert len(calls) > full_calls + 1


def test_api_status_route_passes_only(monkeypatch, tmp_path):
    dashboard, _calls = _setup(monkeypatch, tmp_path)
    import dashboard_routes

    seen = []

    def spy(only=None):
        seen.append(only)
        return {"ok": True}

    monkeypatch.setattr(dashboard_routes, "gather_status", spy)
    client = dashboard_routes.app.test_client()

    rv = client.get("/api/status?only=services,ping")
    assert rv.status_code == 200
    assert seen == ["services,ping"]

    rv = client.get("/api/status?only=")
    assert rv.status_code == 200
    # пустой only → легаси ноль-арг вызов (тесты гардов монкипатчат лямбдой без аргументов)
    assert seen == ["services,ping", None]

    # чужой Host режется ДО gather_status (DNS-rebinding guard)
    rv = client.get("/api/status?only=services", headers={"Host": "evil.test:8787"})
    assert rv.status_code == 403
    assert len(seen) == 2
