"""Контракт единого примитива выгрузки launchd-агента: install_lib._launchd_unload.

`launchctl bootout` асинхронен — launchd освобождает gui/<uid>/<label> не сразу (окно до ~2с),
и _launchd_is_loaded ещё возвращает True сразу после bootout. Любой потребитель ОБЯЗАН дождаться
реальной выгрузки, прежде чем действовать на результат (unlink plist / unsetenv / re-bootstrap).
Раньше poll-wait переизобретался inline в трёх местах с разной корректностью (issue #84); теперь
единственный примитив выгрузки *и есть* bootout+poll+confirm — «забыть poll» структурно нельзя.

Контракт возврата — сырой tristate {"state": True/False/None} (тот же словарь, что _launchd_is_loaded):
  state is False -> подтверждённо выгружен  (можно unlink/unsetenv/продолжать)
  state is True  -> ещё загружен после settle (fail-safe: оставить plist)
  state is None  -> неизвестно (print сбой/timeout)  (fail-safe: оставить plist)

Проверка выгрузки — домен-осознанный `launchctl print <domain>/<label>` (cycle-review #93): loaded
кодируется rc print (0=загружен / 113=service-not-found=выгружен / прочее=unknown), НЕ текстом.
Тайминг нейтрализуем monkeypatch'ем install_lib._BOOTOUT_* — НЕ патчим time. print-состояния гонит
runner последовательно по каждому вызову print (эмулирует «ещё выгружается» → «выгрузился»).
"""
import install_lib


def _print_rc(loaded):
    """Транслирует абстрактное loaded-состояние в результат `launchctl print`.

    True → rc=0 (есть в домене); False → rc=113 (service-not-found = выгружен);
    None → timeout (unknown). Единый маппинг для всех print-моков.
    """
    if loaded is None:
        return {"rc": None, "out": "", "err": "timeout", "timeout": True}
    if loaded:
        return {"rc": 0, "out": f"{install_lib.LAUNCHAGENT_LABEL} = {{ state = running }}",
                "err": "", "timeout": False}
    return {"rc": 113, "out": "", "err": "Could not find service", "timeout": False}


def _unload_runner(*, bootout_rc=0, list_states=None, record=None):
    """Фейк runner для _launchd_unload: диспетчеризует bootout/print по cmd[1].

    list_states: список loaded-значений (True/False/None) ПОСЛЕДОВАТЕЛЬНО на каждый вызов print.
      True → rc=0 (загружен); False → rc=113 (выгружен); None → timeout (unknown).
      Если исчерпан — держим последнее значение.
    record: если задан (список) — каждый вызов launchctl добавляется туда (для подсчёта).
    """
    state = {"list_idx": 0}

    def runner(cmd, timeout):
        if record is not None:
            record.append(list(cmd))
        sub = cmd[1] if len(cmd) > 1 else ""
        if sub == "bootout":
            return {"rc": bootout_rc, "out": "", "err": "", "timeout": False}
        if sub == "print":
            if list_states:
                idx = min(state["list_idx"], len(list_states) - 1)
                state["list_idx"] += 1
                loaded = list_states[idx]
            else:
                loaded = False
            return _print_rc(loaded)
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    return runner


def _lists(calls):
    return [c for c in calls if len(c) > 1 and c[1] == "print"]


def _bootouts(calls):
    return [c for c in calls if len(c) > 1 and c[1] == "bootout"]


def test_unload_confirmed_after_settle(monkeypatch):
    """Агент «висит» в print (True), затем выгружается (False) → state is False. 1 bootout, ≥2 print."""
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    calls = []
    runner = _unload_runner(list_states=[True, False], record=calls)

    res = install_lib._launchd_unload(install_lib._launchd_domain(),
                                      install_lib.LAUNCHAGENT_LABEL, runner=runner)

    assert res["state"] is False, "после settle агент выгружен — подтверждённо False"
    assert len(_bootouts(calls)) == 1, "bootout ровно один раз"
    assert len(_lists(calls)) >= 2, "poll должен увидеть и loaded=True, и последующий loaded=False"


def test_unload_still_loaded_returns_True(monkeypatch):
    """Агент так и не выгружается (print всегда rc=0), settle-потолок ≈0 → state is True (fail-safe)."""
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_lib, "_BOOTOUT_SETTLE_MAX_WAIT", 0)
    runner = _unload_runner(list_states=[True] * 5)

    res = install_lib._launchd_unload(install_lib._launchd_domain(),
                                      install_lib.LAUNCHAGENT_LABEL, runner=runner)

    assert res["state"] is True, "не выгрузился после settle — True, потребитель обязан оставить plist"


def test_unload_print_timeout_returns_None(monkeypatch):
    """print timeout (None) — короткое замыкание: цикл `while state and …` выходит сразу.

    Гард регресса PR #83 на уровне примитива: None (неизвестно) НЕ схлопывается в True/False и НЕ
    крутит полные settle-2с. ≤2 print (первичный + возможный, но None falsy → цикл не входит).
    """
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    calls = []
    runner = _unload_runner(list_states=[None], record=calls)

    res = install_lib._launchd_unload(install_lib._launchd_domain(),
                                      install_lib.LAUNCHAGENT_LABEL, runner=runner)

    assert res["state"] is None, "print timeout → неизвестно (None), проходит насквозь"
    assert len(_lists(calls)) <= 2, "None falsy → цикл не крутится, print вызван минимально"


def test_unload_already_unloaded_first_check(monkeypatch):
    """Агент уже выгружен на первой проверке (print rc=113) → state is False, ровно 1 print."""
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    calls = []
    runner = _unload_runner(list_states=[False], record=calls)

    res = install_lib._launchd_unload(install_lib._launchd_domain(),
                                      install_lib.LAUNCHAGENT_LABEL, runner=runner)

    assert res["state"] is False
    assert len(_lists(calls)) == 1, "уже выгружен — poll-цикл не нужен, ровно одна проверка"


def test_unload_bootout_rc_ignored(monkeypatch):
    """bootout rc≠0 (напр. «уже выгружен») игнорируется — статус определяет только print."""
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    runner = _unload_runner(bootout_rc=3, list_states=[False])

    res = install_lib._launchd_unload(install_lib._launchd_domain(),
                                      install_lib.LAUNCHAGENT_LABEL, runner=runner)

    assert res["state"] is False, "bootout rc игнорируем — «уже выгружен» не ошибка"


# ============================ _launchd_is_loaded: домен-осознанный `print`, rc-семантика (cycle-review #93) ============================
def _print_result_runner(print_result):
    """runner, отдающий фиксированный dict на `print` (bootout/прочее → успех)."""
    def runner(cmd, timeout):
        if len(cmd) > 1 and cmd[1] == "print":
            return dict(print_result)
        return {"rc": 0, "out": "", "err": "", "timeout": False}
    return runner


def test_is_loaded_True_on_rc0():
    """print rc=0 → сервис есть в домене → True (загружен)."""
    runner = _print_result_runner({"rc": 0, "out": "com.srouter.dashboard = { state = running }",
                                   "err": "", "timeout": False})
    assert install_lib._launchd_is_loaded(install_lib.LAUNCHAGENT_LABEL, runner=runner) is True


def test_is_loaded_False_only_on_rc113():
    """print rc=113 (service-not-found) — ЕДИНСТВЕННЫЙ достоверный «выгружен» → False."""
    runner = _print_result_runner({"rc": 113, "out": "", "err": "Could not find service",
                                   "timeout": False})
    assert install_lib._launchd_is_loaded(install_lib.LAUNCHAGENT_LABEL, runner=runner) is False


def test_is_loaded_None_on_rc112_domain_not_found():
    """print rc=112 (домен не найден) → НЕИЗВЕСТНО (None), НЕ «выгружен».

    Из не-gui контекста (SSH/cron) домен gui/<uid> может быть недоступен — это не «агента нет»,
    а «не смогли спросить правильный домен». fail-safe: не трогать plist.
    """
    runner = _print_result_runner({"rc": 112, "out": "", "err": "Could not find domain",
                                   "timeout": False})
    assert install_lib._launchd_is_loaded(install_lib.LAUNCHAGENT_LABEL, runner=runner) is None


def test_is_loaded_None_on_nonzero_rc():
    """print дал прочий rc≠0/≠113 (сбой) → НЕИЗВЕСТНО (None), НЕ False (регресс-гард раунда 1, print)."""
    runner = _print_result_runner({"rc": 1, "out": "", "err": "boom", "timeout": False})
    assert install_lib._launchd_is_loaded(install_lib.LAUNCHAGENT_LABEL, runner=runner) is None


def test_is_loaded_None_on_rc_none_launch_failure():
    """sys_probe.run при OSError/FileNotFoundError/PermissionError → {rc:None, timeout:False}.

    Не-timeout сбой запуска launchctl — тоже НЕИЗВЕСТНО (None), не «выгружен» (регресс-гард раунда 1).
    """
    runner = _print_result_runner({"rc": None, "out": "", "err": "FileNotFoundError: launchctl",
                                   "timeout": False})
    assert install_lib._launchd_is_loaded(install_lib.LAUNCHAGENT_LABEL, runner=runner) is None


def test_is_loaded_None_on_timeout():
    """print timeout → None (fail-safe), держим явно рядом с rc-сбоями."""
    runner = _print_result_runner({"rc": None, "out": "", "err": "timeout", "timeout": True})
    assert install_lib._launchd_is_loaded(install_lib.LAUNCHAGENT_LABEL, runner=runner) is None


def test_is_loaded_queries_explicit_domain():
    """Проверка идёт по ЯВНОМУ таргету `print <domain>/<label>` (герметичность vs домен-mismatch)."""
    seen = []

    def runner(cmd, timeout):
        seen.append(list(cmd))
        return {"rc": 113, "out": "", "err": "", "timeout": False}

    install_lib._launchd_is_loaded(install_lib.LAUNCHAGENT_LABEL,
                                   domain="gui/501", runner=runner)
    assert seen == [[install_lib.LAUNCHCTL, "print", f"gui/501/{install_lib.LAUNCHAGENT_LABEL}"]], \
        "домен-осознанный print по явному таргету, НЕ legacy list"
