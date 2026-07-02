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


def test_api_guard_rejects_auto_mode_with_valid_channel_map(monkeypatch):
    """Регрессия: auto с ВАЛИДНОЙ channel-картой (#56 расширил validate_traffic_guard,
    чтобы её принимать) обязан резаться scope-границей роута v1-редактора → 400.

    Раньше validate_traffic_guard возвращал [] на такой payload, роут писал mode:auto
    в state (auto-bypass). Scope on/off теперь привязан к роуту, не к валидатору.
    """
    dashboard = _fresh_dashboard(monkeypatch)
    saved = _install_state(monkeypatch, dashboard)

    response = dashboard.app.test_client().post(
        "/api/guard", json={"mode": "auto", "domains": {"wifi": {"example.com": "block"}}}
    )

    assert response.status_code == 400
    body = response.get_json()
    assert body["ok"] is False
    assert body["errors"]
    assert any("on" in e and "off" in e for e in body["errors"])
    # State НЕ перезаписан — auto не должен просочиться в v1-редактор.
    assert saved == []


def test_api_guard_rejects_auto_mode_flat_domains(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    saved = _install_state(monkeypatch, dashboard)

    response = dashboard.app.test_client().post("/api/guard", json={"mode": "auto", "domains": {}})

    assert response.status_code == 400
    body = response.get_json()
    assert body["ok"] is False
    assert body["errors"]
    assert saved == []


def test_api_guard_rejects_throttle_mode(monkeypatch):
    """throttle как mode (#13, вне scope v1) режется scope-границей роута → 400."""
    dashboard = _fresh_dashboard(monkeypatch)
    saved = _install_state(monkeypatch, dashboard)

    response = dashboard.app.test_client().post("/api/guard", json={"mode": "throttle", "domains": {}})

    assert response.status_code == 400
    assert response.get_json()["ok"] is False
    assert saved == []


def test_api_guard_valid_on_with_block_domain_still_writes(monkeypatch):
    """Легит on+block не должен сломаться scope-проверкой mode."""
    dashboard = _fresh_dashboard(monkeypatch)
    saved = _install_state(monkeypatch, dashboard)
    monkeypatch.setattr(dashboard, "probe_traffic_guard", lambda **kw: {"status": "ok", "rule_count": 1})

    response = dashboard.app.test_client().post(
        "/api/guard", json={"mode": "on", "domains": {"ads.example.com": "block"}}
    )

    assert response.status_code == 200
    assert response.get_json()["ok"] is True
    assert len(saved) == 1
    assert saved[0]["traffic_guard"]["mode"] == "on"
    assert saved[0]["traffic_guard"]["domains"] == {"ads.example.com": "block"}


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
    assert body["editable"] is True
    assert body["domains"] == {"ads.example.com": "block"}
    assert body["guard"]["rule_count"] == 1


def test_api_guard_get_auto_mode_reports_honest_mode_not_editable(monkeypatch):
    """auto-режим (#23) в v1-редакторе не редактируется, но GET сообщает ЧЕСТНЫЙ mode.

    Раньше GET деградировал auto→off — это ложь о состоянии: пользователь жал save
    и легальный {mode:on/off} затирал channel-map (round-trip потеря). Теперь GET
    отдаёт mode:"auto" + editable:false + domains:{} (плоскую ложь не отдаём).
    """
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(
        dashboard.local_state,
        "traffic_guard_config",
        lambda **kw: {
            "mode": "auto",
            "domains": {"example.com": "block"},  # плоская проекция активного канала — НЕ отдаём в редактор
            "channels": {"wifi": {"example.com": "block"}},
            "valid": True,
            "errors": [],
        },
    )
    monkeypatch.setattr(dashboard, "probe_traffic_guard", lambda **kw: {"status": "ok", "rule_count": 1})

    response = dashboard.app.test_client().get("/api/guard")

    assert response.status_code == 200
    body = response.get_json()
    assert body["mode"] == "auto"
    assert body["editable"] is False
    # Плоскую проекцию канала не отдаём: редактор её не сохраняет обратно.
    assert body["domains"] == {}


def test_api_guard_post_blocked_when_existing_state_is_auto(monkeypatch):
    """Round-trip fail-closed: если ТЕКУЩИЙ state в auto — легальный on/off POST его
    не перезаписывает (409), channel-map остаётся цел."""
    dashboard = _fresh_dashboard(monkeypatch)
    auto_state = {
        "schema_version": 1,
        "traffic_guard": {
            "mode": "auto",
            "domains": {"wifi": {"example.com": "block"}, "metered": {"cdn.example.net": "allow"}},
            "channel": "wifi",
        },
    }
    saved = _install_state(monkeypatch, dashboard, state=auto_state)

    # Полностью легальный payload редактора — и mode-чек, и validate_traffic_guard он бы прошёл.
    response = dashboard.app.test_client().post(
        "/api/guard", json={"mode": "on", "domains": {"ads.example.com": "block"}}
    )

    assert response.status_code == 409
    body = response.get_json()
    assert body["ok"] is False
    assert body["errors"]
    assert any("auto" in e.lower() for e in body["errors"])
    # State НЕ тронут — channel-map цел.
    assert saved == []


def test_api_guard_post_allows_write_when_existing_state_is_off(monkeypatch):
    """Штатный round-trip: существующий state on/off → редактор пишет нормально."""
    dashboard = _fresh_dashboard(monkeypatch)
    off_state = {"schema_version": 1, "traffic_guard": {"mode": "off", "domains": {}}}
    saved = _install_state(monkeypatch, dashboard, state=off_state)
    monkeypatch.setattr(dashboard, "probe_traffic_guard", lambda **kw: {"status": "ok", "rule_count": 1})

    response = dashboard.app.test_client().post(
        "/api/guard", json={"mode": "on", "domains": {"ads.example.com": "block"}}
    )

    assert response.status_code == 200
    assert response.get_json()["ok"] is True
    assert len(saved) == 1
    assert saved[0]["traffic_guard"]["mode"] == "on"
