"""DNS-rebinding guard: валидация заголовка Host для ВСЕХ роутов dashboard.py (issue #82, находка #2).

Сервис слушает loopback, но DNS-rebinding обходит SOP: атакующий резолвит evil.com → 127.0.0.1,
страница на его домене делает fetch('/api/status') как СВОЙ same-origin (Origin: http://evil.com,
Host: evil.com:8787), браузер не мешает. CSRF/Origin-guard тут не помогает — он режет только POST
и только по Origin; GET /api/status раньше отдавал jsonify(gather_status()) любому Host.

Единственная защита от rebinding — сервер знает свой Host: легитимно к нему обращаются лишь по
127.0.0.1/localhost. Чужой hostname в Host → 403 БЕЗУСЛОВНО (привилегированная граница, fail-closed),
неоднозначный/непарсимый Host → тоже 403. Порт в Host не сигнал (атакующий всё равно бьёт в :8787,
а легит-клиенты шлют голый hostname / другой порт) — валидируем hostname, не порт.
"""
import importlib
import sys
import types

import pytest


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


# --- RED: DNS-rebinding на GET /api/status ---
def test_rebinding_host_on_status_rejected(monkeypatch):
    """GET /api/status с чужим Host (evil.com:8787) → 403, до gather_status."""
    dashboard = _fresh_dashboard(monkeypatch)

    def boom():
        raise AssertionError("rebinding-запрос дошёл до gather_status")

    monkeypatch.setattr(dashboard, "gather_status", boom)

    response = dashboard.app.test_client().get(
        "/api/status", headers={"Host": "evil.com:8787"}
    )

    assert response.status_code == 403
    assert response.get_json() == {"ok": False, "err": "host not allowed"}


@pytest.mark.parametrize("host", ["127.0.0.1:8787", "localhost:8787", "127.0.0.1", "localhost"])
def test_loopback_host_on_status_passes(monkeypatch, host):
    """Легитимный Host (loopback hostname, с портом и без) проходит к gather_status."""
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard, "gather_status", lambda: {"ok": True})

    response = dashboard.app.test_client().get("/api/status", headers={"Host": host})

    assert response.status_code == 200
    assert response.get_json() == {"ok": True}


@pytest.mark.parametrize(
    "host",
    [
        "evil.com",              # чужой hostname без порта
        "evil.com:8787",         # чужой hostname, наш порт
        "attacker.example",      # чужой FQDN
        "127.0.0.1.evil.com",    # loopback как префикс чужого домена
        "localhost.evil.com",    # localhost как префикс чужого домена
        "0.0.0.0:8787",          # не loopback
        "[::1]evil",             # мусор после bracket-хоста
        "127.0.0.1@evil.com",    # userinfo-обход: urlsplit дал бы hostname=evil.com
        "evil.com@127.0.0.1",    # userinfo-обход в другую сторону
        "user@localhost:8787",   # userinfo перед легит-хостом — аномальный Host
        "localhost:8787/x",      # path в Host — аномалия
        "localhost:8787?x",      # query в Host — аномалия
        "127.0.0.1 ",            # trailing whitespace
        " localhost",            # leading whitespace
        "localhost:evil",        # непарсимый порт
    ],
)
def test_hostile_host_rejected(monkeypatch, host):
    """Любой не-loopback / неоднозначный Host → 403 (fail-closed)."""
    dashboard = _fresh_dashboard(monkeypatch)

    def boom():
        raise AssertionError(f"hostile Host {host!r} дошёл до gather_status")

    monkeypatch.setattr(dashboard, "gather_status", boom)

    response = dashboard.app.test_client().get("/api/status", headers={"Host": host})

    assert response.status_code == 403
    assert response.get_json() == {"ok": False, "err": "host not allowed"}


def test_missing_host_rejected(monkeypatch):
    """Пустой Host → 403 (нельзя доказать loopback → fail-closed)."""
    dashboard = _fresh_dashboard(monkeypatch)

    def boom():
        raise AssertionError("запрос без Host дошёл до gather_status")

    monkeypatch.setattr(dashboard, "gather_status", boom)

    # HTTP/1.0-style: снимаем Host целиком.
    response = dashboard.app.test_client().get(
        "/api/status", environ_overrides={"HTTP_HOST": "", "SERVER_NAME": ""}
    )

    assert response.status_code == 403


# --- guard общий: rebinding режется на ВСЕХ роутах, не только /api/status ---
GET_ROUTES = ["/", "/api/status", "/api/probe/nodes", "/api/nodes/ranking"]


@pytest.mark.parametrize("path", GET_ROUTES)
def test_rebinding_rejected_on_all_get_routes(monkeypatch, path):
    """Host allow-list — общий before_request, а не заплатка на одном роуте."""
    dashboard = _fresh_dashboard(monkeypatch)

    response = dashboard.app.test_client().get(path, headers={"Host": "evil.com:8787"})

    assert response.status_code == 403


def test_rebinding_rejected_on_post_route(monkeypatch):
    """POST-роуты тоже под Host-guard: rebinding + same-origin fetch мог бы триггерить мутацию."""
    dashboard = _fresh_dashboard(monkeypatch)

    def boom_run(cmd, timeout):
        raise AssertionError("rebinding POST дошёл до sys_probe.run")

    import sys_probe

    monkeypatch.setattr(sys_probe, "run", boom_run)

    response = dashboard.app.test_client().post(
        "/api/route/add", headers={"Host": "evil.com:8787"}
    )

    assert response.status_code == 403


# --- регресс: легит-путь UI не сломан ---
def test_default_test_client_host_passes(monkeypatch):
    """Дефолтный Host тестового клиента (localhost) остаётся легитимным —
    существующая тестовая база и легит-браузер по 127.0.0.1/localhost не ломаются."""
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard, "gather_status", lambda: {"ok": True})

    response = dashboard.app.test_client().get("/api/status")

    assert response.status_code == 200


# --- unit на первоисточник: валидатор проверяем напрямую, без werkzeug test-client ---
# (некоторые враждебные Host — напр. порт вне диапазона — реальный HTTP-сервер передаёт
#  как строку, а werkzeug test_client не может собрать для них environ и падает ДО guard.
#  Поэтому парсер валидируем на уровне функции.)
@pytest.mark.parametrize(
    "raw_host",
    ["127.0.0.1:8787", "localhost:8787", "127.0.0.1", "localhost", "[::1]:8787", "LOCALHOST"],
)
def test_is_allowed_host_accepts_loopback(monkeypatch, raw_host):
    dashboard = _fresh_dashboard(monkeypatch)
    assert dashboard._is_allowed_host(raw_host) is True


@pytest.mark.parametrize(
    "raw_host",
    [
        None,                    # заголовок отсутствует
        "",                      # пустой Host
        "evil.com",
        "evil.com:8787",
        "127.0.0.1.evil.com",
        "localhost.evil.com",
        "0.0.0.0:8787",
        "127.0.0.1@evil.com",    # userinfo-обход
        "user@localhost:8787",
        "localhost:8787/x",      # path в Host
        "localhost:8787?x",      # query в Host
        "localhost:evil",        # непарсимый порт
        "localhost:99999",       # порт вне диапазона 0-65535
        "127.0.0.1 ",            # trailing whitespace
        " localhost",            # leading whitespace
        "[::1]evil",             # мусор после bracket-хоста → Invalid IPv6 URL
        "local\thost",           # встроенный таб
    ],
)
def test_is_allowed_host_rejects_hostile(monkeypatch, raw_host):
    dashboard = _fresh_dashboard(monkeypatch)
    assert dashboard._is_allowed_host(raw_host) is False
