"""Тесты редактора Traffic Guard: POST /api/guard (issue #15).

Роут валидирует payload через local_state.validate_traffic_guard, пишет секцию
traffic_guard в unified state через local_state.save_state (atomic helper). Роут
defensive: невалидный/битый ввод → 400 + structured errors, state не перезаписан.
"""
import importlib
import sys
import types


def _fresh_dashboard(monkeypatch):
    """Свежий импорт dashboard с замоканным srouter_config (как в соседних тестах)."""
    monkeypatch.delitem(sys.modules, "dashboard", raising=False)
    cfg = types.ModuleType("srouter_config")
    cfg.GATEWAY = "192.0.2.1"
    cfg.VPN_SERVER = "198.51.100.20"
    cfg.VPN_EXIT_IP = "198.51.100.20"
    monkeypatch.setitem(sys.modules, "srouter_config", cfg)
    dashboard = importlib.import_module("dashboard")
    dashboard._cache.update(ts=0.0, data=None)
    return dashboard


def _install_state(monkeypatch, dashboard, state=None, readable=True):
    """Замокать load_state_checked/save_state; вернуть список записанных состояний."""
    base = state if state is not None else {"schema_version": 1, "traffic_guard": {"mode": "off", "domains": {}}}
    saved = []

    def fake_load_checked(path=None):
        # Копия, чтобы роут не мутировал наш эталон незаметно.
        import copy

        return copy.deepcopy(base), readable

    def fake_save(new_state, path=None):
        saved.append(new_state)
        return new_state

    monkeypatch.setattr(dashboard.local_state, "load_state_checked", fake_load_checked)
    monkeypatch.setattr(dashboard.local_state, "save_state", fake_save)
    return saved


def test_api_guard_valid_write_persists_and_returns_probe(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    saved = _install_state(monkeypatch, dashboard)
    # probe для рендера count'ов не должен зависеть от реального файла.
    monkeypatch.setattr(
        dashboard, "probe_traffic_guard", lambda **kw: {"status": "ok", "rule_count": 1, "blocked_domains": 1}
    )

    # Два независимых домена: block + allow без parent/child пересечения.
    payload = {"mode": "on", "domains": {"ads.example.com": "block", "cdn.example.net": "allow"}}
    response = dashboard.app.test_client().post("/api/guard", json=payload)

    assert response.status_code == 200
    body = response.get_json()
    assert body["ok"] is True
    assert body["errors"] == []
    # Секция записана в unified state ровно один раз.
    assert len(saved) == 1
    assert saved[0]["traffic_guard"]["mode"] == "on"
    assert saved[0]["traffic_guard"]["domains"]["ads.example.com"] == "block"
    assert saved[0]["traffic_guard"]["domains"]["cdn.example.net"] == "allow"
    # Остальные секции state сохранены (роут не затирает файл целиком).
    assert saved[0]["schema_version"] == 1
    # probe-поля прокидываются для UI count'ов.
    assert body["guard"]["rule_count"] == 1


def test_api_guard_rejects_conflicting_parent_child(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    saved = _install_state(monkeypatch, dashboard)

    payload = {"mode": "on", "domains": {"example.com": "block", "api.example.com": "allow"}}
    response = dashboard.app.test_client().post("/api/guard", json=payload)

    assert response.status_code == 400
    body = response.get_json()
    assert body["ok"] is False
    assert body["errors"], "conflict must yield structured errors"
    assert any("conflict" in e.lower() for e in body["errors"])
    # State НЕ перезаписан при отклонении.
    assert saved == []


def test_api_guard_rejects_auto_mode(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    saved = _install_state(monkeypatch, dashboard)

    response = dashboard.app.test_client().post("/api/guard", json={"mode": "auto", "domains": {}})

    assert response.status_code == 400
    body = response.get_json()
    assert body["ok"] is False
    assert body["errors"]
    assert saved == []


def test_api_guard_rejects_throttle_policy(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    saved = _install_state(monkeypatch, dashboard)

    response = dashboard.app.test_client().post(
        "/api/guard", json={"mode": "on", "domains": {"slow.example.com": "throttle"}}
    )

    assert response.status_code == 400
    body = response.get_json()
    assert body["ok"] is False
    assert body["errors"]
    assert saved == []


def test_api_guard_malformed_body_is_400_not_500(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    saved = _install_state(monkeypatch, dashboard)

    # Совсем не JSON-объект: строка вместо {mode, domains}.
    response = dashboard.app.test_client().post(
        "/api/guard", data="not-json", content_type="application/json"
    )

    assert response.status_code == 400
    body = response.get_json()
    assert body["ok"] is False
    assert body["errors"]
    assert saved == []


def test_api_guard_non_object_domains_rejected(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    saved = _install_state(monkeypatch, dashboard)

    response = dashboard.app.test_client().post(
        "/api/guard", json={"mode": "on", "domains": ["youtube.com"]}
    )

    assert response.status_code == 400
    assert response.get_json()["ok"] is False
    assert saved == []


def test_api_guard_off_mode_empty_domains_ok(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    saved = _install_state(monkeypatch, dashboard)
    monkeypatch.setattr(dashboard, "probe_traffic_guard", lambda **kw: {"status": "ok", "rule_count": 0})

    response = dashboard.app.test_client().post("/api/guard", json={"mode": "off", "domains": {}})

    assert response.status_code == 200
    assert response.get_json()["ok"] is True
    assert len(saved) == 1
    assert saved[0]["traffic_guard"] == {"mode": "off", "domains": {}}


def test_api_guard_unwritable_state_not_overwritten(monkeypatch):
    """readable=False (битый существующий файл) → роут не перезаписывает вслепую."""
    dashboard = _fresh_dashboard(monkeypatch)
    saved = _install_state(monkeypatch, dashboard, readable=False)

    response = dashboard.app.test_client().post("/api/guard", json={"mode": "off", "domains": {}})

    assert response.status_code == 409
    body = response.get_json()
    assert body["ok"] is False
    assert saved == []


def test_api_guard_save_failure_reports_error(monkeypatch):
    """save_state вернул None (запись не удалась) → 500, не молчаливый успех."""
    dashboard = _fresh_dashboard(monkeypatch)

    monkeypatch.setattr(
        dashboard.local_state, "load_state_checked", lambda path=None: ({"traffic_guard": {}}, True)
    )
    monkeypatch.setattr(dashboard.local_state, "save_state", lambda state, path=None: None)

    response = dashboard.app.test_client().post("/api/guard", json={"mode": "off", "domains": {}})

    assert response.status_code == 500
    assert response.get_json()["ok"] is False


def test_api_guard_get_returns_current_rules_for_editor(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(
        dashboard.local_state,
        "traffic_guard_config",
        lambda **kw: {"mode": "on", "domains": {"ads.example.com": "block"}, "valid": True, "errors": []},
    )
    monkeypatch.setattr(dashboard, "probe_traffic_guard", lambda **kw: {"status": "ok", "rule_count": 1})

    response = dashboard.app.test_client().get("/api/guard")

    assert response.status_code == 200
    body = response.get_json()
    assert body["mode"] == "on"
    assert body["domains"] == {"ads.example.com": "block"}
    assert body["guard"]["rule_count"] == 1


def test_api_guard_get_auto_mode_degrades_to_off_for_v1_editor(monkeypatch):
    """auto-режим (#23) в v1-редакторе не показываем: деградируем в off/пусто."""
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(
        dashboard.local_state,
        "traffic_guard_config",
        lambda **kw: {"mode": "auto", "domains": {}, "channels": {}, "valid": True, "errors": []},
    )
    monkeypatch.setattr(dashboard, "probe_traffic_guard", lambda **kw: {"status": "ok", "rule_count": 0})

    response = dashboard.app.test_client().get("/api/guard")

    assert response.status_code == 200
    body = response.get_json()
    assert body["mode"] == "off"
    assert body["domains"] == {}
