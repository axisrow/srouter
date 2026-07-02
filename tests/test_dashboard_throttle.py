"""Тесты роута Traffic Guard throttle: POST /api/guard/throttle (issue #13/#22).

Mocked — реальный pf/dnctl/root НЕ зовётся: traffic_shape.{apply,clear}_throttle
и throttle-lease в local_state замоканы. Проверяем: валидация ВХОДА в роуте
(fail-closed: невалидный domain/rate -> 400, движок НЕ зван), персист токена при
успешном apply (issue #61), 409 при активном throttle (одно-pipe движок),
cancelled -> структурированный ответ (не 500), clear с сохранённым токеном.
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


def _spy_engine(dashboard, monkeypatch, apply_result=None, clear_result=None):
    """Замокать traffic_shape.apply_throttle/clear_throttle; вернуть журнал вызовов."""
    calls = {"apply": [], "clear": []}

    def fake_apply(domain, rate):
        calls["apply"].append((domain, rate))
        return apply_result if apply_result is not None else {
            "ok": True, "cancelled": False, "rc": 0, "out": "", "err": "", "timeout": False, "token": "5"
        }

    def fake_clear(token=None):
        calls["clear"].append(token)
        return clear_result if clear_result is not None else {
            "ok": True, "cancelled": False, "rc": 0, "out": "", "err": "", "timeout": False
        }

    monkeypatch.setattr(dashboard.traffic_shape, "apply_throttle", fake_apply)
    monkeypatch.setattr(dashboard.traffic_shape, "clear_throttle", fake_clear)
    return calls


def _install_lease(dashboard, monkeypatch, active=None):
    """Замокать throttle-lease helpers; вернуть журнал записанных/очищенных lease."""
    log = {"saved": [], "cleared": 0, "active": active}

    def fake_load(path=None):
        return log["active"]

    def fake_save(entry, path=None):
        log["saved"].append(entry)
        log["active"] = entry
        return entry

    def fake_clear(path=None):
        log["cleared"] += 1
        log["active"] = None
        return True

    monkeypatch.setattr(dashboard.local_state, "load_active_throttle", fake_load)
    monkeypatch.setattr(dashboard.local_state, "save_active_throttle", fake_save)
    monkeypatch.setattr(dashboard.local_state, "clear_active_throttle", fake_clear)
    return log


# ============================ apply: успех + персист токена ============================
def test_apply_valid_calls_engine_and_persists_token(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    calls = _spy_engine(dashboard, monkeypatch)
    lease = _install_lease(dashboard, monkeypatch)

    resp = dashboard.app.test_client().post(
        "/api/guard/throttle", json={"action": "apply", "domain": "video.example.com", "rate": 512}
    )

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True
    # Движок зван с ВАЛИДИРОВАННЫМИ (нормализованными) аргументами.
    assert calls["apply"] == [("video.example.com", 512)]
    # Токен персистится (issue #61) — иначе clear не освободит enable-ref.
    assert len(lease["saved"]) == 1
    saved = lease["saved"][0]
    assert saved["domain"] == "video.example.com"
    assert saved["rate"] == 512
    assert saved["token"] == "5"
    assert "applied_at" in saved


def test_apply_normalizes_domain_before_engine(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    calls = _spy_engine(dashboard, monkeypatch)
    _install_lease(dashboard, monkeypatch)

    resp = dashboard.app.test_client().post(
        "/api/guard/throttle", json={"action": "apply", "domain": "Video.Example.COM.", "rate": "512"}
    )

    assert resp.status_code == 200
    # domain нормализован (lower, trailing dot снят), rate из строки -> int.
    assert calls["apply"] == [("video.example.com", 512)]


# ============================ apply: fail-closed валидация в роуте ============================
def test_apply_invalid_domain_is_400_engine_not_called(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    calls = _spy_engine(dashboard, monkeypatch)
    lease = _install_lease(dashboard, monkeypatch)

    resp = dashboard.app.test_client().post(
        "/api/guard/throttle", json={"action": "apply", "domain": "bad;touch.example.com", "rate": 512}
    )

    assert resp.status_code == 400
    assert resp.get_json()["ok"] is False
    # Движок НЕ зван, lease не тронут (fail-closed до privileged-вызова).
    assert calls["apply"] == []
    assert lease["saved"] == []


def test_apply_invalid_rate_is_400_engine_not_called(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    calls = _spy_engine(dashboard, monkeypatch)
    _install_lease(dashboard, monkeypatch)

    for bad in (0, -1, "abc", "10Kbit", 1.5):
        resp = dashboard.app.test_client().post(
            "/api/guard/throttle", json={"action": "apply", "domain": "x.example.com", "rate": bad}
        )
        assert resp.status_code == 400, bad
        assert resp.get_json()["ok"] is False

    assert calls["apply"] == []


def test_apply_missing_rate_is_400(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    calls = _spy_engine(dashboard, monkeypatch)
    _install_lease(dashboard, monkeypatch)

    resp = dashboard.app.test_client().post(
        "/api/guard/throttle", json={"action": "apply", "domain": "x.example.com"}
    )
    assert resp.status_code == 400
    assert calls["apply"] == []


# ============================ apply: одно-pipe (409 при активном) ============================
def test_apply_when_already_active_is_409_no_engine_call(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    calls = _spy_engine(dashboard, monkeypatch)
    lease = _install_lease(
        dashboard, monkeypatch, active={"domain": "old.example.com", "rate": 256, "token": "3"}
    )

    resp = dashboard.app.test_client().post(
        "/api/guard/throttle", json={"action": "apply", "domain": "new.example.com", "rate": 512}
    )

    assert resp.status_code == 409
    body = resp.get_json()
    assert body["ok"] is False
    assert "already active" in body["err"]
    assert body["active"]["domain"] == "old.example.com"
    # Движок НЕ зван, существующий lease НЕ тронут (одно-pipe: сначала явный clear).
    assert calls["apply"] == []
    assert lease["saved"] == []


# ============================ apply: cancelled / сбой движка ============================
def test_apply_cancelled_is_structured_not_500(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    cancelled = {"ok": False, "cancelled": True, "rc": -128, "out": "", "err": "cancel", "timeout": False, "token": None}
    _spy_engine(dashboard, monkeypatch, apply_result=cancelled)
    lease = _install_lease(dashboard, monkeypatch)

    resp = dashboard.app.test_client().post(
        "/api/guard/throttle", json={"action": "apply", "domain": "x.example.com", "rate": 512}
    )

    assert resp.status_code == 200  # НЕ 500
    body = resp.get_json()
    assert body["cancelled"] is True
    assert body["ok"] is False
    # Отмена -> throttle не включён -> lease не пишем.
    assert lease["saved"] == []


def test_apply_engine_failure_is_structured_no_lease(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    failure = {
        "ok": False, "cancelled": False, "rc": 71, "out": "", "token": None,
        "err": "dummynet pipe 1 уже существует", "timeout": False,
    }
    _spy_engine(dashboard, monkeypatch, apply_result=failure)
    lease = _install_lease(dashboard, monkeypatch)

    resp = dashboard.app.test_client().post(
        "/api/guard/throttle", json={"action": "apply", "domain": "x.example.com", "rate": 512}
    )

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is False
    assert "pipe" in body["err"]
    # Сбой движка -> lease НЕ пишем (нечего снимать позже).
    assert lease["saved"] == []


def test_apply_token_persist_failure_rolls_back(monkeypatch):
    """Токен получен, но персист упал -> роут откатывает throttle (иначе enable-ref течёт)."""
    dashboard = _fresh_dashboard(monkeypatch)
    calls = _spy_engine(dashboard, monkeypatch)  # apply ok token=5, clear ok
    _install_lease(dashboard, monkeypatch)
    # save_active_throttle возвращает None (запись не удалась).
    monkeypatch.setattr(dashboard.local_state, "save_active_throttle", lambda entry, path=None: None)

    resp = dashboard.app.test_client().post(
        "/api/guard/throttle", json={"action": "apply", "domain": "x.example.com", "rate": 512}
    )

    assert resp.status_code == 500
    body = resp.get_json()
    assert body["ok"] is False
    assert "persist" in body["err"]
    # Откат сохранённым токеном, чтобы enable-ref не тёк.
    assert calls["clear"] == ["5"]


# ============================ clear ============================
def test_clear_uses_persisted_token_and_resets_lease(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    calls = _spy_engine(dashboard, monkeypatch)
    lease = _install_lease(
        dashboard, monkeypatch, active={"domain": "x.example.com", "rate": 512, "token": "9"}
    )

    resp = dashboard.app.test_client().post("/api/guard/throttle", json={"action": "clear"})

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True
    # clear зван с СОХРАНЁННЫМ токеном (issue #61) -> enable-ref освобождён.
    assert calls["clear"] == ["9"]
    # lease сброшен после успешного снятия.
    assert lease["cleared"] == 1


def test_clear_without_active_lease_calls_engine_with_none(monkeypatch):
    """Нет активного lease -> clear идемпотентен (token=None: cleanup pipe/anchor)."""
    dashboard = _fresh_dashboard(monkeypatch)
    calls = _spy_engine(dashboard, monkeypatch)
    _install_lease(dashboard, monkeypatch, active=None)

    resp = dashboard.app.test_client().post("/api/guard/throttle", json={"action": "clear"})

    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True
    assert calls["clear"] == [None]


def test_clear_cancelled_keeps_lease(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    cancelled = {"ok": False, "cancelled": True, "rc": -128, "out": "", "err": "cancel", "timeout": False}
    _spy_engine(dashboard, monkeypatch, clear_result=cancelled)
    lease = _install_lease(
        dashboard, monkeypatch, active={"domain": "x.example.com", "rate": 512, "token": "9"}
    )

    resp = dashboard.app.test_client().post("/api/guard/throttle", json={"action": "clear"})

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["cancelled"] is True
    # Отмена -> throttle всё ещё активен -> lease НЕ сброшен.
    assert lease["cleared"] == 0


def test_clear_engine_failure_keeps_lease(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    failure = {"ok": False, "cancelled": False, "rc": 1, "out": "", "err": "boom", "timeout": False}
    _spy_engine(dashboard, monkeypatch, clear_result=failure)
    lease = _install_lease(
        dashboard, monkeypatch, active={"domain": "x.example.com", "rate": 512, "token": "9"}
    )

    resp = dashboard.app.test_client().post("/api/guard/throttle", json={"action": "clear"})

    assert resp.status_code == 200
    assert resp.get_json()["ok"] is False
    # Сбой clear -> lease оставляем (throttle мог остаться частично), пользователь повторит.
    assert lease["cleared"] == 0


# ============================ payload / action guard ============================
def test_bad_action_is_400(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    calls = _spy_engine(dashboard, monkeypatch)
    _install_lease(dashboard, monkeypatch)

    resp = dashboard.app.test_client().post(
        "/api/guard/throttle", json={"action": "explode", "domain": "x.example.com", "rate": 512}
    )

    assert resp.status_code == 400
    assert resp.get_json()["ok"] is False
    assert calls["apply"] == [] and calls["clear"] == []


def test_missing_action_is_400(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    _spy_engine(dashboard, monkeypatch)
    _install_lease(dashboard, monkeypatch)

    resp = dashboard.app.test_client().post(
        "/api/guard/throttle", json={"domain": "x.example.com", "rate": 512}
    )
    assert resp.status_code == 400
    assert resp.get_json()["ok"] is False


def test_malformed_body_is_400_not_500(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    _spy_engine(dashboard, monkeypatch)
    _install_lease(dashboard, monkeypatch)

    resp = dashboard.app.test_client().post(
        "/api/guard/throttle", data="not-json", content_type="application/json"
    )
    assert resp.status_code == 400
    assert resp.get_json()["ok"] is False


# ============================ GET /api/guard: throttle-проекция без токена ============================
def test_get_guard_exposes_active_throttle_without_token(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(
        dashboard.local_state, "traffic_guard_config",
        lambda **kw: {"mode": "off", "domains": {}, "valid": True, "errors": []},
    )
    monkeypatch.setattr(dashboard, "probe_traffic_guard", lambda **kw: {"status": "ok", "rule_count": 0})
    monkeypatch.setattr(
        dashboard.local_state, "load_active_throttle",
        lambda path=None: {"domain": "x.example.com", "rate": 512, "token": "9", "applied_at": 1000},
    )

    body = dashboard.app.test_client().get("/api/guard").get_json()

    assert body["throttle"] == {"domain": "x.example.com", "rate": 512, "applied_at": 1000}
    # Токен pf enable-ref наружу НЕ отдаётся.
    assert "token" not in body["throttle"]


def test_get_guard_throttle_none_when_inactive(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    monkeypatch.setattr(
        dashboard.local_state, "traffic_guard_config",
        lambda **kw: {"mode": "off", "domains": {}, "valid": True, "errors": []},
    )
    monkeypatch.setattr(dashboard, "probe_traffic_guard", lambda **kw: {"status": "ok", "rule_count": 0})
    monkeypatch.setattr(dashboard.local_state, "load_active_throttle", lambda path=None: None)

    assert dashboard.app.test_client().get("/api/guard").get_json()["throttle"] is None


def test_apply_success_returns_public_throttle_without_token(monkeypatch):
    dashboard = _fresh_dashboard(monkeypatch)
    _spy_engine(dashboard, monkeypatch)
    # После сохранения lease роут отдаёт публичную проекцию через load_active_throttle.
    _install_lease(dashboard, monkeypatch)

    body = dashboard.app.test_client().post(
        "/api/guard/throttle", json={"action": "apply", "domain": "x.example.com", "rate": 512}
    ).get_json()

    assert body["ok"] is True
    assert body["throttle"]["domain"] == "x.example.com"
    assert body["throttle"]["rate"] == 512
    assert "token" not in body["throttle"]
    # token движка наружу не течёт и в самом ответе apply.
    assert "token" not in body
