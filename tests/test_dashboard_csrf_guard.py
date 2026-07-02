"""CSRF/Origin-guard для mutation-роутов dashboard.py (issue #42).

Сервис биндится на loopback, но browser-origin CSRF всё ещё вектор: любой сайт
в браузере может form-POST/fetch на http://127.0.0.1:8787 и триггерить osascript
admin-prompt. Guard должен резать ЯВНО cross-origin браузерные POST до handler,
пропуская same-origin UI и curl/non-browser (без Origin/Sec-Fetch-Site).
"""
import importlib
import sys
import types

import pytest
import sys_probe


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


def _guard_all_mutations(monkeypatch, dashboard):
    """Ставим ловушки на все привилегированные пути: если guard пропустил
    cross-origin запрос — тест упадёт на этих AssertionError, а не тихо пройдёт."""

    def boom_run(cmd, timeout):
        raise AssertionError("cross-origin запрос дошёл до sys_probe.run")

    monkeypatch.setattr(sys_probe, "run", boom_run)

    def boom_select(*a, **k):
        raise AssertionError("cross-origin запрос дошёл до select_node")

    monkeypatch.setattr(dashboard.node_selector, "select_node", boom_select)

    def boom_switch(*a, **k):
        raise AssertionError("cross-origin запрос дошёл до switch_channel")

    monkeypatch.setattr(dashboard, "switch_channel", boom_switch)

    def enabled_nodes():
        return [{"name": "sg-1"}]

    monkeypatch.setattr(dashboard.local_state, "enabled_nodes", enabled_nodes)

    def active_node():
        return {"name": "sg-1", "endpoint_host": "node.example.test"}

    monkeypatch.setattr(dashboard.local_state, "active_node", active_node)


# Все POST mutation-роуты, которые обязаны быть под guard.
MUTATION_POSTS = [
    "/api/node/select/sg-1",
    "/api/route/host",
    "/api/route/add",
    "/api/route/remove",
    "/api/channel/wifi",
    "/api/channel",
    "/api/channel/",
    "/api/service/xray/restart",
]


@pytest.mark.parametrize("path", MUTATION_POSTS)
def test_cross_origin_post_rejected_before_handler(monkeypatch, path):
    dashboard = _fresh_dashboard(monkeypatch)
    _guard_all_mutations(monkeypatch, dashboard)

    response = dashboard.app.test_client().post(
        path, headers={"Origin": "http://evil.com"}
    )

    assert response.status_code == 403
    assert response.get_json() == {"ok": False, "err": "cross-origin request rejected"}


@pytest.mark.parametrize("path", MUTATION_POSTS)
def test_cross_site_fetch_metadata_rejected(monkeypatch, path):
    dashboard = _fresh_dashboard(monkeypatch)
    _guard_all_mutations(monkeypatch, dashboard)

    response = dashboard.app.test_client().post(
        path, headers={"Sec-Fetch-Site": "cross-site"}
    )

    assert response.status_code == 403
    assert response.get_json() == {"ok": False, "err": "cross-origin request rejected"}


# --- defense-in-depth: явно враждебный Origin бьёт РАНЬШЕ Fetch-Metadata ---
# Regression на Origin-bypass (cycle-review PR #58, Codex): атакующий не может
# обойти guard, выставив Sec-Fetch-Site: none/same-origin при чужом Origin.
# На привилегированной границе present-hostile-Origin -> 403 БЕЗУСЛОВНО.
@pytest.mark.parametrize("sec_fetch_site", ["none", "same-origin", "cross-site"])
@pytest.mark.parametrize("path", MUTATION_POSTS)
def test_hostile_origin_rejected_regardless_of_fetch_metadata(monkeypatch, path, sec_fetch_site):
    dashboard = _fresh_dashboard(monkeypatch)
    _guard_all_mutations(monkeypatch, dashboard)

    response = dashboard.app.test_client().post(
        path,
        headers={"Origin": "http://evil.com", "Sec-Fetch-Site": sec_fetch_site},
    )

    assert response.status_code == 403
    assert response.get_json() == {"ok": False, "err": "cross-origin request rejected"}


@pytest.mark.parametrize("sec_fetch_site", ["none", "same-origin", "cross-site"])
def test_allowed_origin_passes_regardless_of_fetch_metadata(monkeypatch, sec_fetch_site):
    """Легитимный Origin (127.0.0.1:8787) проходит при ЛЮБОМ Sec-Fetch-Site —
    не сломать легит из-за нового порядка проверок."""
    dashboard = _fresh_dashboard(monkeypatch)

    response = dashboard.app.test_client().post(
        "/api/route/host",
        headers={"Origin": "http://127.0.0.1:8787", "Sec-Fetch-Site": sec_fetch_site},
        json={"action": "bogus"},
    )

    assert response.status_code == 400  # дошёл до валидации handler (bad action), не отбит guard'ом


@pytest.mark.parametrize("sec_fetch_site", ["none", "same-origin"])
def test_missing_origin_with_benign_fetch_metadata_passes(monkeypatch, sec_fetch_site):
    """Origin отсутствует (curl/навигация) + Sec-Fetch-Site none/same-origin → pass."""
    dashboard = _fresh_dashboard(monkeypatch)

    response = dashboard.app.test_client().post(
        "/api/route/host",
        headers={"Sec-Fetch-Site": sec_fetch_site},
        json={"action": "bogus"},
    )

    assert response.status_code == 400


def test_missing_origin_with_cross_site_fetch_metadata_rejected(monkeypatch):
    """Origin отсутствует, но Sec-Fetch-Site: cross-site → 403 (браузер пометил чужим)."""
    dashboard = _fresh_dashboard(monkeypatch)
    _guard_all_mutations(monkeypatch, dashboard)

    response = dashboard.app.test_client().post(
        "/api/route/host", headers={"Sec-Fetch-Site": "cross-site"}
    )

    assert response.status_code == 403
    assert response.get_json() == {"ok": False, "err": "cross-origin request rejected"}


@pytest.mark.parametrize(
    "origin",
    ["http://127.0.0.1:8787", "http://localhost:8787"],
)
def test_same_origin_post_passes_guard(monkeypatch, origin):
    """Same-origin UI (Origin совпадает с host сервиса) проходит guard.
    Проверяем, что запрос дошёл до валидации handler (400 bad action),
    а не отбит guard'ом (403)."""
    dashboard = _fresh_dashboard(monkeypatch)

    response = dashboard.app.test_client().post(
        "/api/route/host", headers={"Origin": origin}, json={"action": "bogus"}
    )

    # == 400 (bad action) доказывает, что запрос ДОШЁЛ до валидации handler,
    # а не просто "не 403": != 403 было бы ложно-зелёным (500/краш тоже не 403).
    assert response.status_code == 400


def test_same_origin_fetch_metadata_passes_guard(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)

    response = dashboard.app.test_client().post(
        "/api/route/host",
        headers={"Sec-Fetch-Site": "same-origin"},
        json={"action": "bogus"},
    )

    assert response.status_code == 400


def test_fetch_metadata_none_passes_guard(monkeypatch):
    """Sec-Fetch-Site: none — прямой ввод адреса/закладка, не cross-origin."""
    dashboard = _fresh_dashboard(monkeypatch)

    response = dashboard.app.test_client().post(
        "/api/route/host",
        headers={"Sec-Fetch-Site": "none"},
        json={"action": "bogus"},
    )

    assert response.status_code == 400


def test_missing_origin_and_fetch_metadata_passes_guard(monkeypatch):
    """curl/non-browser без Origin и без Sec-Fetch-Site — legit, пропускаем.
    Это гарантия, что существующие тесты (POST без заголовков) остаются зелёными."""
    dashboard = _fresh_dashboard(monkeypatch)

    response = dashboard.app.test_client().post("/api/route/host", json={"action": "bogus"})

    assert response.status_code == 400


def test_get_routes_not_guarded(monkeypatch):
    """GET read-only роуты не трогаем даже с cross-origin Origin."""
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard, "gather_status", lambda: {"ok": True})

    response = dashboard.app.test_client().get(
        "/api/status", headers={"Origin": "http://evil.com"}
    )

    assert response.status_code == 200


def test_index_get_not_guarded(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)

    response = dashboard.app.test_client().get("/", headers={"Origin": "http://evil.com"})

    assert response.status_code == 200
