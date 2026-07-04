"""Тесты srouter.cmd_restart/cmd_start: надёжная перезагрузка launchd-агента без гонки.

Гонка: `launchctl bootout` + `launchctl bootstrap` подряд падают с `Bootstrap failed: 5:
Input/output error`, если launchd не успел освободить слот домена gui/<uid>/<label>. Лечится
poll-wait'ом выгрузки после bootout + retry на bootstrap. Канон always-tdd: тесты ПЕРВЫМИ.

Мок `run` различает launchctl-подкоманды по cmd[1] (list / bootout / bootstrap) и считает вызовы
(через record=), чтобы проверять retry-логику без реального launchd и без долгих слипов
(интервалы зануляем monkeypatch'ем модуля install_lib — там живут константы).
"""
from types import SimpleNamespace

import install_lib
import srouter


def _make_runner(*, bootout_rc=0, bootstrap_sequence=None, list_states=None, record=None):
    """Фабрика фейка runner, различающего launchctl-подкоманды. Опционально пишет вызовы в record.

    bootstrap_sequence: список rc-кодов, выдаваемых ПОСЛЕДОВАТЕЛЬНО на каждый вызов bootstrap
      (напр. [5, 0] — первый занят, второй ок). Если исчерпан — последний код.
    list_states: список loaded-значений (True/False/None) последовательно на каждый вызов list.
      Эмулирует «демон ещё выгружается» (True) → «выгрузился» (False). None → timeout.
    record: если задан (список) — каждый вызок добавляется туда (для подсчёта bootstraps).
    """
    state = {"bootstrap_idx": 0, "list_idx": 0}

    def fake_run(cmd, timeout):
        if record is not None:
            record.append(list(cmd))
        sub = cmd[1] if len(cmd) > 1 else ""
        if sub == "list":
            if list_states is not None:
                idx = min(state["list_idx"], len(list_states) - 1)
                state["list_idx"] += 1
                loaded = list_states[idx]
            else:
                loaded = False
            if loaded is None:  # timeout
                return {"rc": None, "out": "", "err": "timeout", "timeout": True}
            out = (srouter.LAUNCHAGENT_LABEL + "\n") if loaded else "999\t0\tcom.other\n"
            return {"rc": 0, "out": out, "err": "", "timeout": False}
        if sub == "bootout":
            return {"rc": bootout_rc, "out": "", "err": "", "timeout": False}
        if sub == "bootstrap":
            if bootstrap_sequence:
                idx = min(state["bootstrap_idx"], len(bootstrap_sequence) - 1)
                rc = bootstrap_sequence[idx]
                state["bootstrap_idx"] += 1
            else:
                rc = 0
            return {"rc": rc, "out": "", "err": "Bootstrap failed: 5" if rc else "",
                    "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    return fake_run


def _args():
    """Минимальный args-объект для cmd_start/cmd_restart (как argparse отдаёт)."""
    return SimpleNamespace(state=None, prefix=None, launchagents_dir=None, python=None)


def _bootstraps(calls):
    return [c for c in calls if len(c) > 1 and c[1] == "bootstrap"]


def test_restart_success_on_first_try(monkeypatch):
    """Happy path: bootout ok, bootstrap rc=0 с первой попытки → rc=0, bootstrap ровно 1 раз."""
    monkeypatch.setattr(install_lib, "_BOOTSTRAP_RETRY_DELAY", 0)
    monkeypatch.setattr(srouter.Path, "exists", lambda self: True)
    calls = []
    monkeypatch.setattr(srouter, "run", _make_runner(bootstrap_sequence=[0], record=calls))

    rc = srouter.cmd_restart(_args())
    assert rc == 0
    assert len(_bootstraps(calls)) == 1, "happy path — bootstrap ровно один раз"


def test_restart_retries_bootstrap_when_domain_busy(monkeypatch):
    """ГОНКА: первый bootstrap → rc=5 (домен занят), второй → rc=0. restart должен выстоять (rc=0).

    На нелеченом коде этот тест ПАДАЕТ: один bootstrap с rc=5, _is_loaded() False → rc=2.
    """
    monkeypatch.setattr(install_lib, "_BOOTSTRAP_RETRY_DELAY", 0)
    monkeypatch.setattr(srouter.Path, "exists", lambda self: True)
    calls = []
    monkeypatch.setattr(srouter, "run", _make_runner(bootstrap_sequence=[5, 0], record=calls))

    rc = srouter.cmd_restart(_args())
    assert rc == 0, "retry должен привести к успеху, а не к rc=2"
    assert len(_bootstraps(calls)) >= 2, "первый bootstrap провалился (rc=5) → нужна вторая попытка"


def test_restart_fails_after_max_retries(monkeypatch):
    """Все попытки bootstrap дают rc=5, демон так и не загрузился → rc=2, ошибка в stderr."""
    monkeypatch.setattr(install_lib, "_BOOTSTRAP_RETRY_DELAY", 0)
    monkeypatch.setattr(srouter.Path, "exists", lambda self: True)
    monkeypatch.setattr(srouter, "run", _make_runner(bootstrap_sequence=[5, 5, 5]))

    rc = srouter.cmd_restart(_args())
    assert rc == 2


def test_restart_waits_for_unload_after_bootout(monkeypatch):
    """После bootout демон ещё «висит» в list (True), потом выгружается (False).

    bootstrap НЕ должен вызываться, пока _is_loaded() ещё True — ждём полной выгрузки.
    """
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_lib, "_BOOTSTRAP_RETRY_DELAY", 0)
    monkeypatch.setattr(srouter.Path, "exists", lambda self: True)
    calls = []
    # list: первый poll (после bootout) → True (ещё загружен), затем False (выгрузился). bootstrap → 0.
    monkeypatch.setattr(srouter, "run",
                        _make_runner(bootstrap_sequence=[0], list_states=[True, False], record=calls))

    rc = srouter.cmd_restart(_args())
    assert rc == 0
    bootstraps = _bootstraps(calls)
    assert len(bootstraps) == 1, "bootstrap вызывается ровно один раз после выгрузки"
    # bootstrap должен идти ПОСЛЕ list→False (полной выгрузки), а не до неё.
    subs = [c[1] for c in calls if len(c) > 1]
    first_bootstrap = subs.index("bootstrap")
    # Все list-вызовы до bootstrap: последний из них должен вернуть выгрузку (loaded-чередование в _make_runner).
    lists_before = [c for c in calls[:first_bootstrap] if len(c) > 1 and c[1] == "list"]
    assert len(lists_before) >= 2, "poll должен увидеть и loaded=True, и последующий loaded=False до bootstrap"


def test_start_idempotent_when_already_loaded(monkeypatch):
    """cmd_start: демон уже загружен → bootstrap не вызывается вообще (текущее поведение сохранить)."""
    calls = []
    monkeypatch.setattr(srouter, "run", _make_runner(list_states=[True], record=calls))
    monkeypatch.setattr(srouter.Path, "exists", lambda self: True)

    rc = srouter.cmd_start(_args())
    assert rc == 0
    assert _bootstraps(calls) == [], "уже загружен → bootstrap не нужен"


# ============================ _launchd_reload (install_lib) ============================
def _reload_runner(*, bootstrap_rcs, list_loaded=False):
    """Фейк runner для прямых тестов _launchd_reload: bootstrap отдаёт rc по списку, list — loaded."""
    state = {"i": 0}

    def runner(cmd, timeout):
        sub = cmd[1] if len(cmd) > 1 else ""
        if sub == "bootstrap":
            idx = min(state["i"], len(bootstrap_rcs) - 1)
            state["i"] += 1
            rc = bootstrap_rcs[idx]
            return {"rc": rc, "out": "", "err": "" if rc == 0 else "Bootstrap failed", "timeout": False}
        if sub == "list":
            out = (install_lib.LAUNCHAGENT_LABEL + "\n") if list_loaded else "999\t0\tcom.other\n"
            return {"rc": 0, "out": out, "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    return runner


def test_launchd_reload_retries_bootstrap_when_busy(monkeypatch):
    """_launchd_reload: первый bootstrap rc=5, второй rc=0 → ok, bootstrap ≥2 раз."""
    monkeypatch.setattr(install_lib, "_BOOTSTRAP_RETRY_DELAY", 0)
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)

    calls = []
    runner = _reload_runner(bootstrap_rcs=[5, 0], list_loaded=False)
    res = install_lib._launchd_reload("gui/501", "/tmp/x.plist", "com.srouter.dashboard",
                                      runner=lambda cmd, t: (calls.append(list(cmd)), runner(cmd, t))[1])
    bootstraps = _bootstraps(calls)
    assert res["ok"] is True
    assert len(bootstraps) >= 2


def test_launchd_reload_fails_after_max_retries(monkeypatch):
    """Все попытки bootstrap rc=5, агент не загружен → ok=False."""
    monkeypatch.setattr(install_lib, "_BOOTSTRAP_RETRY_DELAY", 0)
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)

    res = install_lib._launchd_reload("gui/501", "/tmp/x.plist", "com.srouter.dashboard",
                                      runner=_reload_runner(bootstrap_rcs=[5, 5, 5], list_loaded=False))
    assert res["ok"] is False


def test_launchd_reload_soft_success_when_loaded_after_busy(monkeypatch):
    """bootstrap вернул rc≠0, но list показывает агент загружен → ok=True (soft-success)."""
    monkeypatch.setattr(install_lib, "_BOOTSTRAP_RETRY_DELAY", 0)
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_lib, "_BOOTOUT_SETTLE_MAX_WAIT", 0)

    res = install_lib._launchd_reload("gui/501", "/tmp/x.plist", "com.srouter.dashboard",
                                      runner=_reload_runner(bootstrap_rcs=[5], list_loaded=True))
    assert res["ok"] is True
