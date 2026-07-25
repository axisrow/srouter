"""ТДД-тесты srouter._install/_remove_codex_isolation: token lifecycle (issue #168, cycle-review cycle 1).

cycle-review cycle 1 (5 линз + adversarial verify) нашёл 2 подтверждённых бага token-lifecycle:
  1. (high, canon fail-closed-proxy-down) _remove_codex_isolation безусловно clear_active_codex_isolate
     ДАЖЕ при disable failure → leaked pfctl -E enable-ref + state не отражает реальность.
  2. (medium) _install_codex_isolation не передаёт существующий token из lease → на re-install плодит
     новые enable-ref'ы (CLI-путь isolate_firewall.py:534-535 делает правильно).

Инвариант: state (active_codex_isolate) должен отражать реальность PF (enable-ref захвачен/освобождён).
Не «clear всегда», а «clear только при подтверждённом disable» — иначе disable-failure оставляет
leaked enable-ref, который release'ится только pfctl -d (ядерный вариант). Канон config-contract:
state = генератор/контракт, отражающий реальность.
"""
import isolate_firewall
import local_state
import srouter

# Оригинальные функции (до любых monkeypatch) — srouter.local_state и local_state это один модуль,
# патч srouter.local_state.X виден и как local_state.X → рекурсия. Захватываем оригиналы заранее.
_LS_LOAD = local_state.load_active_codex_isolate
_LS_SAVE = local_state.save_active_codex_isolate
_LS_CLEAR = local_state.clear_active_codex_isolate


def test_install_codex_reuses_existing_lease_token(monkeypatch, tmp_path):
    """cycle-1 finding 2: re-install обязан переиспользовать token из существующего lease (НЕ плодить новые pfctl -E).

    Без этого re-install каждый раз зовёт pfctl -E → копит leaked enable-ref'ы.
    CLI-путь (isolate_firewall.py:534) читает lease и передаёт token; install-путь обязан так же.
    """
    state_path = str(tmp_path / "s.json")
    _LS_SAVE({"token": "42", "applied_at": 111}, path=state_path)  # существующий lease от прошлого install
    monkeypatch.setattr(srouter.local_state, "load_active_codex_isolate",
                        lambda path=None: _LS_LOAD(path=state_path))
    monkeypatch.setattr(srouter.local_state, "save_active_codex_isolate",
                        lambda entry, path=None: _LS_SAVE(entry, path=state_path))

    captured = {}
    def fake_enable(token=None):
        captured["token_arg"] = token
        return {"ok": True, "token": token or "new", "err": ""}
    monkeypatch.setattr(isolate_firewall, "enable_codex_isolation", fake_enable)

    srouter._install_codex_isolation(env=None, runner=None)
    assert captured["token_arg"] == "42", (
        "install обязан переиспользовать существующий token из lease (НЕ pfctl -E заново); "
        f"передано {captured.get('token_arg')!r}")


def test_remove_codex_keeps_state_on_disable_failure(monkeypatch, tmp_path):
    """cycle-1 finding 1 (high): при disable failure state НЕ очищается (fail-closed, no leaked enable-ref).

    Иначе: disable упал (pfctl -X не выполнен, enable-ref захвачен), но token стёрт из state →
    следующий install не сможет его release'ить → leaked enable-ref (только pfctl -d спасает).
    """
    state_path = str(tmp_path / "s.json")
    _LS_SAVE({"token": "99", "applied_at": 222}, path=state_path)
    monkeypatch.setattr(srouter.local_state, "load_active_codex_isolate",
                        lambda path=None: _LS_LOAD(path=state_path))
    cleared = {"called": False}
    def fake_clear(path=None):
        cleared["called"] = True
    monkeypatch.setattr(srouter.local_state, "clear_active_codex_isolate", fake_clear)

    # disable FAILS (pfctl/osascript cancel) → ok=False, enable-ref всё ещё захвачен
    monkeypatch.setattr(isolate_firewall, "disable_codex_isolation",
                        lambda token=None: {"ok": False, "err": "pfctl cancel", "rc": -128})

    note = srouter._remove_codex_isolation(env=None, runner=None)
    assert not cleared["called"], (
        "при disable failure state НЕ очищать (иначе leaked enable-ref без возможности release); "
        f"note={note!r}")
    assert "частично" in note or "не снята" in note, f"note сообщает partial: {note!r}"
    # lease уцелел — можно повторить disable
    assert _LS_LOAD(path=state_path) is not None


def test_remove_codex_clears_state_on_disable_success(monkeypatch, tmp_path):
    """Позитивный контр-кейс: при disable SUCCESS state очищается (нормальный uninstall)."""
    state_path = str(tmp_path / "s.json")
    _LS_SAVE({"token": "99", "applied_at": 222}, path=state_path)
    monkeypatch.setattr(srouter.local_state, "load_active_codex_isolate",
                        lambda path=None: _LS_LOAD(path=state_path))
    monkeypatch.setattr(srouter.local_state, "clear_active_codex_isolate",
                        lambda path=None: _LS_CLEAR(path=state_path))
    monkeypatch.setattr(isolate_firewall, "disable_codex_isolation",
                        lambda token=None: {"ok": True, "err": ""})

    note = srouter._remove_codex_isolation(env=None, runner=None)
    assert "снята" in note, note
    assert _LS_LOAD(path=state_path) is None


# ============================ #186 provisioning UID: install/uninstall порядок ============================
# issue #186: install обязан provision_codex_user() ДО enable (UID готов к моменту загрузки PF-rules).
# uninstall обязан deprovision_codex_user() ПОСЛЕ успешного disable+clear (симметрия state-lifecycle).
def test_install_codex_provisions_user_before_enable(monkeypatch, tmp_path):
    """provision_codex_user вызывается ДО enable_codex_isolation (UID готов → rules активны сразу)."""
    state_path = str(tmp_path / "s.json")
    monkeypatch.setattr(srouter.local_state, "load_active_codex_isolate",
                        lambda path=None: _LS_LOAD(path=state_path) or {})
    monkeypatch.setattr(srouter.local_state, "save_active_codex_isolate",
                        lambda entry, path=None: _LS_SAVE(entry, path=state_path))
    order = []

    def fake_provision():
        order.append("provision")
        return {"ok": True, "cancelled": False, "rc": 0, "err": "", "out": "", "timeout": False}

    def fake_enable(token=None):
        order.append("enable")
        return {"ok": True, "token": token or "7", "err": ""}
    monkeypatch.setattr(isolate_firewall, "provision_codex_user", fake_provision)
    monkeypatch.setattr(isolate_firewall, "enable_codex_isolation", fake_enable)

    srouter._install_codex_isolation(env=None, runner=None)
    assert order == ["provision", "enable"], (
        f"provision обязан идти ДО enable (UID готов к моменту загрузки правил); порядок={order}")


def test_install_codex_provision_failure_does_not_crash_install(monkeypatch, tmp_path):
    """provision best-effort: сбой НЕ валит install — enable всё ещё зовётся, note упоминает ошибку."""
    state_path = str(tmp_path / "s.json")
    monkeypatch.setattr(srouter.local_state, "load_active_codex_isolate",
                        lambda path=None: _LS_LOAD(path=state_path) or {})
    monkeypatch.setattr(srouter.local_state, "save_active_codex_isolate",
                        lambda entry, path=None: _LS_SAVE(entry, path=state_path))
    enable_called = {"v": False}

    def fake_provision():
        return {"ok": False, "cancelled": False, "rc": 1, "err": "uid занят", "out": "", "timeout": False}

    def fake_enable(token=None):
        enable_called["v"] = True
        return {"ok": True, "token": "7", "err": ""}
    monkeypatch.setattr(isolate_firewall, "provision_codex_user", fake_provision)
    monkeypatch.setattr(isolate_firewall, "enable_codex_isolation", fake_enable)

    note = srouter._install_codex_isolation(env=None, runner=None)
    assert enable_called["v"], "provision failure НЕ должен валить install (best-effort, как codex-шаги)"
    assert isinstance(note, str), "install возвращает строку-статус, не бросает"


def test_remove_codex_deprovisions_after_successful_disable(monkeypatch, tmp_path):
    """uninstall: deprovision_codex_user вызывается ПОСЛЕ успешного disable + clear."""
    state_path = str(tmp_path / "s.json")
    _LS_SAVE({"token": "9", "applied_at": 1}, path=state_path)
    monkeypatch.setattr(srouter.local_state, "load_active_codex_isolate",
                        lambda path=None: _LS_LOAD(path=state_path) or {})
    monkeypatch.setattr(srouter.local_state, "clear_active_codex_isolate",
                        lambda path=None: _LS_CLEAR(path=state_path))
    order = []
    monkeypatch.setattr(srouter.local_state, "clear_active_codex_isolate",
                        lambda path=None: order.append("clear") or _LS_CLEAR(path=state_path))
    monkeypatch.setattr(isolate_firewall, "disable_codex_isolation",
                        lambda token=None: order.append("disable") or {"ok": True, "err": ""})
    monkeypatch.setattr(isolate_firewall, "deprovision_codex_user",
                        lambda: order.append("deprovision") or {"ok": True, "err": ""})

    srouter._remove_codex_isolation(env=None, runner=None)
    assert order == ["disable", "clear", "deprovision"], (
        f"deprovision ПОСЛЕ disable+clear; порядок={order}")


def test_remove_codex_does_not_deprovision_on_disable_failure(monkeypatch, tmp_path):
    """disable failure → deprovision НЕ зовётся (симметрия state-keep: не трогаем пользователя
    при незавершённом disable)."""
    state_path = str(tmp_path / "s.json")
    _LS_SAVE({"token": "9", "applied_at": 1}, path=state_path)
    monkeypatch.setattr(srouter.local_state, "load_active_codex_isolate",
                        lambda path=None: _LS_LOAD(path=state_path) or {})
    monkeypatch.setattr(isolate_firewall, "disable_codex_isolation",
                        lambda token=None: {"ok": False, "err": "pfctl cancel", "rc": -128})
    deprovision_called = {"v": False}
    monkeypatch.setattr(isolate_firewall, "deprovision_codex_user",
                        lambda: deprovision_called.update(v=True) or {"ok": True, "err": ""})

    srouter._remove_codex_isolation(env=None, runner=None)
    assert not deprovision_called["v"], (
        "при disable failure deprovision НЕ зовётся (правила ещё живы → пользователь нужен)")


def test_remove_codex_deprovision_failure_kept_best_effort(monkeypatch, tmp_path):
    """deprovision best-effort: сбой НЕ роняет uninstall-результат (правила уже сняты, user остался)."""
    state_path = str(tmp_path / "s.json")
    _LS_SAVE({"token": "9", "applied_at": 1}, path=state_path)
    monkeypatch.setattr(srouter.local_state, "load_active_codex_isolate",
                        lambda path=None: _LS_LOAD(path=state_path) or {})
    monkeypatch.setattr(srouter.local_state, "clear_active_codex_isolate",
                        lambda path=None: _LS_CLEAR(path=state_path))
    monkeypatch.setattr(isolate_firewall, "disable_codex_isolation",
                        lambda token=None: {"ok": True, "err": ""})
    monkeypatch.setattr(isolate_firewall, "deprovision_codex_user",
                        lambda: {"ok": False, "err": "dscl cancel", "rc": -128})

    note = srouter._remove_codex_isolation(env=None, runner=None)
    assert isinstance(note, str), "deprovision failure best-effort, uninstall не бросает"
    assert _LS_LOAD(path=state_path) is None, "lease очищен при успешном disable (не завязан на deprovision)"
