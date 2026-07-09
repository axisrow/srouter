"""Контракт единого примитива выгрузки launchd-агента: install_lib._launchd_unload.

`launchctl bootout` асинхронен — launchd освобождает gui/<uid>/<label> не сразу (окно до ~2с),
и _launchd_is_loaded ещё возвращает True сразу после bootout. Любой потребитель ОБЯЗАН дождаться
реальной выгрузки, прежде чем действовать на результат (unlink plist / unsetenv / re-bootstrap).
Раньше poll-wait переизобретался inline в трёх местах с разной корректностью (issue #84); теперь
единственный примитив выгрузки *и есть* bootout+poll+confirm — «забыть poll» структурно нельзя.

Контракт возврата — сырой tristate {"state": True/False/None} (тот же словарь, что _launchd_is_loaded):
  state is False -> подтверждённо выгружен  (можно unlink/unsetenv/продолжать)
  state is True  -> ещё загружен после settle (fail-safe: оставить plist)
  state is None  -> неизвестно, list timeout  (fail-safe: оставить plist)

Тайминг нейтрализуем monkeypatch'ем install_lib._BOOTOUT_* — НЕ патчим time. list-состояния гонит
runner последовательно по каждому вызову list (эмулирует «ещё выгружается» → «выгрузился»).
"""
import install_lib


def _unload_runner(*, bootout_rc=0, list_states=None, record=None):
    """Фейк runner для _launchd_unload: диспетчеризует bootout/list по cmd[1].

    list_states: список loaded-значений (True/False/None) ПОСЛЕДОВАТЕЛЬНО на каждый вызов list.
      True → out=label (загружен); False → out=чужая строка (не загружен); None → timeout.
      Если исчерпан — держим последнее значение.
    record: если задан (список) — каждый вызов launchctl добавляется туда (для подсчёта).
    """
    state = {"list_idx": 0}
    label = install_lib.LAUNCHAGENT_LABEL

    def runner(cmd, timeout):
        if record is not None:
            record.append(list(cmd))
        sub = cmd[1] if len(cmd) > 1 else ""
        if sub == "bootout":
            return {"rc": bootout_rc, "out": "", "err": "", "timeout": False}
        if sub == "list":
            if list_states:
                idx = min(state["list_idx"], len(list_states) - 1)
                state["list_idx"] += 1
                loaded = list_states[idx]
            else:
                loaded = False
            if loaded is None:  # timeout
                return {"rc": None, "out": "", "err": "timeout", "timeout": True}
            out = (label + "\n") if loaded else "999\t0\tcom.other\n"
            return {"rc": 0, "out": out, "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    return runner


def _lists(calls):
    return [c for c in calls if len(c) > 1 and c[1] == "list"]


def _bootouts(calls):
    return [c for c in calls if len(c) > 1 and c[1] == "bootout"]


def test_unload_confirmed_after_settle(monkeypatch):
    """Агент «висит» в list (True), затем выгружается (False) → state is False. 1 bootout, ≥2 list."""
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    calls = []
    runner = _unload_runner(list_states=[True, False], record=calls)

    res = install_lib._launchd_unload(install_lib._launchd_domain(),
                                      install_lib.LAUNCHAGENT_LABEL, runner=runner)

    assert res["state"] is False, "после settle агент выгружен — подтверждённо False"
    assert len(_bootouts(calls)) == 1, "bootout ровно один раз"
    assert len(_lists(calls)) >= 2, "poll должен увидеть и loaded=True, и последующий loaded=False"


def test_unload_still_loaded_returns_True(monkeypatch):
    """Агент так и не выгружается (list всегда True), settle-потолок ≈0 → state is True (fail-safe)."""
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_lib, "_BOOTOUT_SETTLE_MAX_WAIT", 0)
    runner = _unload_runner(list_states=[True] * 5)

    res = install_lib._launchd_unload(install_lib._launchd_domain(),
                                      install_lib.LAUNCHAGENT_LABEL, runner=runner)

    assert res["state"] is True, "не выгрузился после settle — True, потребитель обязан оставить plist"


def test_unload_list_timeout_returns_None(monkeypatch):
    """list timeout (None) — короткое замыкание: цикл `while state and …` выходит сразу.

    Гард регресса PR #83 на уровне примитива: None (неизвестно) НЕ схлопывается в True/False и НЕ
    крутит полные settle-2с. ≤2 list (первичный + возможный, но None falsy → цикл не входит).
    """
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    calls = []
    runner = _unload_runner(list_states=[None], record=calls)

    res = install_lib._launchd_unload(install_lib._launchd_domain(),
                                      install_lib.LAUNCHAGENT_LABEL, runner=runner)

    assert res["state"] is None, "list timeout → неизвестно (None), проходит насквозь"
    assert len(_lists(calls)) <= 2, "None falsy → цикл не крутится, list вызван минимально"


def test_unload_already_unloaded_first_check(monkeypatch):
    """Агент уже выгружен на первой проверке (list False) → state is False, ровно 1 list."""
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    calls = []
    runner = _unload_runner(list_states=[False], record=calls)

    res = install_lib._launchd_unload(install_lib._launchd_domain(),
                                      install_lib.LAUNCHAGENT_LABEL, runner=runner)

    assert res["state"] is False
    assert len(_lists(calls)) == 1, "уже выгружен — poll-цикл не нужен, ровно одна проверка"


def test_unload_bootout_rc_ignored(monkeypatch):
    """bootout rc≠0 (напр. «уже выгружен») игнорируется — статус определяет только list."""
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    runner = _unload_runner(bootout_rc=3, list_states=[False])

    res = install_lib._launchd_unload(install_lib._launchd_domain(),
                                      install_lib.LAUNCHAGENT_LABEL, runner=runner)

    assert res["state"] is False, "bootout rc игнорируем — «уже выгружен» не ошибка"
