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
