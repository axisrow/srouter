"""Issue #234: architectural findings из cycle-review PR #233 (issue #224 follow-up).

Codex adversarial cycle-review (3 раунда, xhigh effort) нашёл 2 CRITICAL проблемы, отличные
по категории от core transactional-логики (issue #224): threading/serialization и
cross-process coordination.

1. Checksum sentinel collision: _begin_txn пишет decimal-count как ПОСЛЕДНЕЕ значение
   _TXN_KEY, чтобы отличить полный маркер от partial write. Но count и легитимное
   target-значение неразличимы — decimal-строка "2" может быть И count, И реальным
   значением из target-списка. Крэш ПОСЛЕ записи последнего значения (но до реальной
   commit-семантики — тут её нет, checksum пишется отдельным --add) оставляет маркер,
   который выглядит "complete" по старому count-based критерию, хотя на самом деле
   последнее число — часть target, а не checksum.

2. Concurrent enable/disable race: enable()/disable() читают current state, решают
   backup/restore, пишут — БЕЗ сериализации между процессами. Два одновременных вызова
   (напр. CLI + dashboard-поток) интерливятся и теряют backup безвозвратно.

Fix (см. git_proxy.py):
- Sentinel заменён с "decimal count" на self-identifying digest-префикс
  (`_TXN_CHECKSUM_PREFIX + sha256(canonical repr)`), которое физически не может
  совпасть с легитимным git-config значением, записанным пользователем/нами.
- Cross-process advisory lock (flock LOCK_EX, эталон local_state._routing_config_lock)
  оборачивает ВСЮ enable()/disable() транзакцию (txn-check + backup + write).
"""
import contextlib
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import git_proxy

EXPECTED_GIT_PROXY = git_proxy._PROXY


@pytest.fixture
def real_git_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def _raw_set_add(key, val, home):
    subprocess.run(
        ["git", "config", "--global", "--add", key, val],
        env=dict(os.environ, HOME=str(home)), capture_output=True, text=True, check=True,
    )


# ==================== Finding 1: checksum sentinel collision ====================
# Прямое воспроизведение из issue #234: target=["A", "2"] (реальное numeric-значение "2" в
# target-списке). Маркер пишется как [key, val1, val2, ...]; старый checksum = str(len(txn_values))
# дописывался ПОСЛЕДНИМ отдельным --add. Если запись обрывается РОВНО после того, как последнее
# легитимное target-значение "2" легло в маркер (но до отдельного checksum --add), результирующий
# на диске маркер [KEY, "A", "2"] неотличим от результата "target=['A'], checksum='2'" — ОБА дают
# len(actual_values_without_last)==2==int(last)? Нет: 2 != 2 -- False! Именно эта коллизия decimal
# count ↔ real numeric value составляет finding 1. Тест бьёт напрямую по _begin_txn/_check_and_resolve_txn,
# не через enable() (target enable() — [KEY, _PROXY], не foreign values -- нужен прямой control).

def test_partial_marker_with_numeric_tail_not_accepted_as_complete(real_git_home):
    """Regression (Codex cycle 2, issue #234): _begin_txn обрывается ПОСЛЕ записи [KEY, "A", "2"]
    (реальный target = ["A", "2"], т.е. checksum-запись сама так и не произошла). Старая checksum-
    схема: recovery видит values=[KEY,"A","2"], интерпретирует ПОСЛЕДНИЙ элемент "2" как decimal
    count, actual_values=[KEY,"A"] (без "2"), len==2, int("2")==2 -> ВАЛИДНО ПРИНЯТО как complete
    маркер для target=["A"] (ключ + один value), теряя "2" НАВСЕГДА при replay.

    С self-identifying sentinel: маркер без валидного sentinel-суффикса ВСЕГДА отклоняется как
    corrupt, независимо от того, совпадает ли decimal-интерпретация последнего значения со счётом
    оставшихся элементов.
    """
    # Симулируем ровно партийный маркер, как будто _begin_txn для target=["A","2"] обвалился
    # перед записью checksum -- пишем его напрямую через raw git config (без sentinel).
    _raw_set_add(git_proxy._TXN_KEY, git_proxy.KEY, real_git_home)
    _raw_set_add(git_proxy._TXN_KEY, "A", real_git_home)
    _raw_set_add(git_proxy._TXN_KEY, "2", real_git_home)

    _raw_set_add(git_proxy.KEY, "A", real_git_home)
    _raw_set_add(git_proxy.KEY, "2", real_git_home)

    txn = git_proxy._get_all(git_proxy._TXN_KEY)
    assert txn["values"] == [git_proxy.KEY, "A", "2"], "sanity: сырой partial-маркер из репро issue"

    resolved = git_proxy._check_and_resolve_txn()

    assert resolved["ok"] is False, (
        "partial-маркер [KEY,'A','2'] без валидного self-identifying sentinel ОБЯЗАН быть отклонён "
        "как corrupt -- НЕ реплеиться как complete target=['A'] (что потеряло бы '2' навсегда)"
    )

    # KEY не тронут (не был частично переписан на неверный target ["A"]).
    current = git_proxy._get_all(git_proxy.KEY)
    assert current["values"] == ["A", "2"], "KEY не должен быть искажён отклонённым partial-маркером"


def test_complete_marker_with_valid_sentinel_still_replays_correctly(real_git_home):
    """Sanity: маркер, ЗАВЕРШЁННЫЙ настоящим _begin_txn (с валидным sentinel), по-прежнему
    успешно распознаётся и retry'ится -- фикс checksum-коллизии не должен сломать штатный путь
    восстановления валидной прерванной транзакции (regression guard против over-strict fix)."""
    _raw_set_add(git_proxy.KEY, "A", real_git_home)

    begin = git_proxy._begin_txn(git_proxy.KEY, ["Z", "2"])
    assert begin["ok"] is True, "sanity: begin_txn сам по себе должен успешно записать полный маркер"

    resolved = git_proxy._check_and_resolve_txn()
    assert resolved["ok"] is True
    assert resolved["resolved"] is True

    current = git_proxy._get_all(git_proxy.KEY)
    assert current["values"] == ["Z", "2"], "валидный полный маркер должен корректно replay'иться"

    txn_after = git_proxy._get_all(git_proxy._TXN_KEY)
    assert txn_after["present"] is False, "маркер снят после успешного commit"


# ==================== Finding 2: concurrent enable/disable race ====================

def _assert_backup_not_lost(final_key, final_backup, results):
    backup_alive = final_backup["present"] and final_backup["values"] == ["A", "B"]
    restored_into_key = final_key["present"] and final_key["values"] == ["A", "B"]
    proxy_enabled_with_backup_intact = (
        final_key["present"] and final_key["values"] == [EXPECTED_GIT_PROXY] and backup_alive
    )
    assert backup_alive or restored_into_key or proxy_enabled_with_backup_intact, (
        f"[A,B] потерян безвозвратно из-за неcериализованной гонки: "
        f"KEY={final_key}, BACKUP={final_backup}, results={results}"
    )


def _seed_foreign_proxy_with_backup(real_git_home):
    assert git_proxy.enable()["ok"] is True
    _raw_set_add(git_proxy._BACKUP_KEY, "A", real_git_home)
    subprocess.run(
        ["git", "config", "--global", "--add", git_proxy._BACKUP_KEY, "B"],
        env=dict(os.environ, HOME=str(real_git_home)), capture_output=True, text=True, check=True,
    )
    assert git_proxy._backup_state()["values"] == ["A", "B"]


def test_concurrent_enable_and_disable_do_not_lose_backup_deterministic(monkeypatch, real_git_home):
    """Regression (Codex cycle 2, issue #234) -- ДЕТЕРМИНИРОВАННОЕ воспроизведение repro из issue
    (не завязано на реальный thread-scheduling, который может "случайно" не гонять и давать false
    negative).

    Issue #279: тест писался ДО PR #275 (issue #234 follow-up, 54cd9d8), который обернул ВСЮ
    enable()/disable()-транзакцию в реальный cross-process `_mutation_lock()` (fcntl.flock,
    блокирующий) ДО первого current-state read. Старый barrier синхронизировался ВНУТРИ read/write
    (через monkeypatch на sys_probe.run) -- под реальным локом это создавало дедлок.

    PR #281 round 1 (start-only barrier перед `_mutation_lock()`) НЕ поймал Codex adversarial
    finding (confidence 0.99, эмпирически подтверждено -- см. test_negative_control_*_loses_backup
    ниже): barrier синхронизировал только МОМЕНТ ВЫЗОВА `_mutation_lock()`, а не реальное удержание
    критической секции. Тест ВСЁ РАВНО проходил -- git's СОБСТВЕННЫЙ файловый lock на `.gitconfig`
    маскировал отсутствие сериализации через наш `_mutation_lock`.

    Round 2 (holder/waiter вокруг `_enable_locked`/`_disable_locked`) ТОЖЕ не поймал регресс (Codex
    xhigh, confidence 0.99, эмпирически 1680/2000 false-green): main thread сигналил
    `waiter_confirmed_blocked` сразу после НАБЛЮДЕНИЯ `len(order)==1`, но это НЕ доказывает, что
    waiter физически заблокирован НА ВХОДЕ -- при no-op локе holder мог полностью завершиться (и
    выйти из critical section) ДО того, как waiter вообще успел стартовать, и main thread видел
    order=[holder], не замечая отсутствия реальной конкуренции.

    Round 3 (waiter сигналит СЕБЯ перед вызовом _mutation_lock, holder ждёт и проверяет флаг) ТОЖЕ
    был сломан (эмпирически поймано при первом же прогоне с реальным локом, до пуша): "designated
    holder"/"waiter" назначались по порядку ВЫЗОВА обёртки `_synced_mutation_lock`, а НЕ по порядку
    реального ЗАХВАТА flock -- между этими двумя моментами оба потока независимо конкурируют за
    `os.open()`+`fcntl.flock()`, и "designated waiter" мог реально ПОЛУЧИТЬ flock раньше
    "designated holder" (кто первым дошёл до строки кода -- не то же самое, что кто первым выиграл
    гонку за настоящий лок). Это ложно триггерило assert даже с исправным production-локом.

    Fix (round 4): holder/waiter НЕ назначаются заранее -- они определяются ПОСЛЕ фактического
    входа в `with real_mutation_lock()` (т.е. по факту РЕАЛЬНОГО обладания flock, единственному
    источнику истины). Первый поток, вошедший в реальную критическую секцию, становится holder.
    Отдельный Event НА КАЖДЫЙ поток (`attempting[name]`) сигналит "я собираюсь вызвать
    real_mutation_lock()" -- holder проверяет ЧУЖОЙ (не свой) attempting-Event, чтобы не словить
    собственный сигнал как ложное подтверждение (round 3 багом было именно это: holder ждал Event,
    который сам же установил перед своим входом).
    """
    _seed_foreign_proxy_with_backup(real_git_home)

    real_mutation_lock = git_proxy._mutation_lock

    holder_active = threading.Event()
    holder_assigned = threading.Event()
    attempting = {"enable-thread": threading.Event(), "disable-thread": threading.Event()}
    entered = {"enable-thread": threading.Event(), "disable-thread": threading.Event()}
    call_count = {"n": 0}
    call_count_lock = threading.Lock()
    both_started = threading.Barrier(2, timeout=5)

    @contextlib.contextmanager
    def _synced_mutation_lock():
        name = threading.current_thread().name
        other = "disable-thread" if name == "enable-thread" else "enable-thread"
        both_started.wait()
        with call_count_lock:
            call_count["n"] += 1
        # Сигналим "я собираюсь попытаться войти в real_mutation_lock()" ДО фактического
        # вызова -- единственный достоверный момент, когда мы точно ЕЩЁ не владеем flock.
        attempting[name].set()
        with real_mutation_lock() as lock_acquired:
            entered[name].set()
            # Мы РЕАЛЬНО вошли -- значит либо мы первые (становимся holder), либо
            # заблокировались на flock до тех пор, пока предыдущий holder не вышел
            # (holder_assigned уже True -- мы второй, вход был последовательным).
            became_holder = not holder_assigned.is_set()
            if became_holder:
                holder_assigned.set()
                holder_active.set()
                # Ждём, что ДРУГОЙ поток дозвонится до ПОПЫТКИ входа (attempting[other]).
                # Он физически не может пройти дальше этой точки в реальный flock, пока
                # мы (holder) не выйдем из `with` -- проверяем это явно.
                attempting[other].wait(timeout=3)
                assert not entered[other].is_set(), (
                    "второй поток вошёл в критическую секцию, ПОКА holder ещё держит flock -- "
                    "_mutation_lock НЕ сериализует (регресс issue #234 finding 2 не пойман)"
                )
            yield lock_acquired

    monkeypatch.setattr(git_proxy, "_mutation_lock", _synced_mutation_lock)

    results = {}
    thread_errors = {}

    # КРИТИЧНО: AssertionError, выброшенный ВНУТРИ дочернего потока, НЕ проваливает pytest
    # по умолчанию -- pytest лишь эмитит PytestUnhandledThreadExceptionWarning (проверено
    # эмпирически: без -W error тест показывал "1 passed, 1 warning" даже когда assert внутри
    # _synced_mutation_lock реально падал). Ловим исключение явно и ре-рейзим в main thread
    # после join -- иначе регресс тихо проходит CI без -W error в конфиге проекта.
    def _run_enable():
        try:
            results["enable"] = git_proxy.enable()
        except BaseException as exc:  # noqa: BLE001 -- re-raised verbatim in main thread below
            thread_errors["enable"] = exc

    def _run_disable():
        try:
            results["disable"] = git_proxy.disable()
        except BaseException as exc:  # noqa: BLE001 -- re-raised verbatim in main thread below
            thread_errors["disable"] = exc

    t_enable = threading.Thread(target=_run_enable, name="enable-thread")
    t_disable = threading.Thread(target=_run_disable, name="disable-thread")
    t_enable.start()
    t_disable.start()

    assert holder_active.wait(timeout=10), "ни один поток не вошёл в критическую секцию"

    t_enable.join(timeout=15)
    t_disable.join(timeout=15)

    if thread_errors:
        raise next(iter(thread_errors.values()))

    assert call_count["n"] == 2, f"оба потока обязаны были вызвать _mutation_lock ровно один раз: {call_count['n']}"

    final_key = git_proxy._get_all(git_proxy.KEY)
    final_backup = git_proxy._backup_state()
    _assert_backup_not_lost(final_key, final_backup, results)


def test_negative_control_noop_mutation_lock_loses_backup(monkeypatch, real_git_home):
    """Негативный контроль (Codex cycle-review PR #281, confirmed finding): доказывает, что
    предыдущая (round 1) версия regression-теста ложно-зеленела при неэффективном
    `_mutation_lock`. Явно заменяем `_mutation_lock` на no-op (никогда не сериализующий
    конкурентный доступ) и ЖДЁМ, что backup будет потерян ЛИБО git's собственный
    config-file lock сам предотвратит потерю через fail-closed ошибку одной из транзакций
    -- в любом случае здесь мы НЕ проверяем `_assert_backup_not_lost` (это делает основной
    тест выше с настоящим локом); этот тест лишь документирует и защищает НАБЛЮДАЕМОЕ
    поведение no-op-лока, чтобы будущий рефакторинг barrier-механики не тихо вернул старую
    дыру, не заметив её отсутствия в этом файле.
    """
    _seed_foreign_proxy_with_backup(real_git_home)

    @contextlib.contextmanager
    def _noop_lock():
        yield True

    both_started = threading.Barrier(2, timeout=5)

    def _synced_noop_lock():
        both_started.wait()
        return _noop_lock()

    monkeypatch.setattr(git_proxy, "_mutation_lock", _synced_noop_lock)

    results = {}

    def _run_enable():
        results["enable"] = git_proxy.enable()

    def _run_disable():
        results["disable"] = git_proxy.disable()

    t_enable = threading.Thread(target=_run_enable, name="enable-thread")
    t_disable = threading.Thread(target=_run_disable, name="disable-thread")
    t_enable.start()
    t_disable.start()
    t_enable.join(timeout=15)
    t_disable.join(timeout=15)

    # Инвариант этого негативного контроля: КОГДА _mutation_lock не сериализует, конкурентный
    # доступ к .gitconfig обязан привести к КАКОМУ-ТО побочному fail-closed конфликту --
    # либо git's собственный config-file lock ("could not lock config file"), либо наш
    # txn-verify (одна сторона видит чужой незавершённый txn-маркер и отказывается,
    # "txn begin verify failed") -- эмпирически наблюдались ОБА варианта (15 прогонов:
    # 12/15 lock-конфликт, 3/15 txn-verify конфликт). Если ОБЕ транзакции "ok" одновременно
    # БЕЗ какого-либо конфликта -- значит окружение изменилось (напр. git перестал
    # блокировать .gitconfig на запись) и негативный контроль больше не воспроизводим;
    # тест должен явно упасть, а не молча "пройти" по случайности.
    enable_hit_conflict = not results["enable"]["ok"]
    disable_hit_conflict = not results["disable"]["ok"]
    assert enable_hit_conflict or disable_hit_conflict, (
        f"ожидался конфликт (git-уровневый lock ИЛИ txn-verify) между несериализованными "
        f"enable/disable (иначе негативный контроль не воспроизводит гонку из issue #234): "
        f"results={results}"
    )


def test_harness_itself_rejects_noop_mutation_lock(monkeypatch, real_git_home):
    """Мета-негативный-контроль (round 4, Codex confidence 0.99 x3 -- rounds 1-3 всех false-green):
    доказывает, что САМА holder/waiter-обвязка из test_concurrent_enable_and_disable_do_not_lose_backup_deterministic
    детектирует no-op `_mutation_lock` как регресс (`AssertionError`, явно ре-рейзнутый из
    дочернего потока в main thread -- pytest НЕ проваливает тест на необработанном исключении в
    треде без `-W error` в конфиге, что и было корнем false-green в rounds 1-3: assert внутри
    потока падал, но тест показывал "1 passed, 1 warning").

    Верифицировано вручную (30/30 прогонов до коммита): с этой же harness-логикой, применённой к
    no-op `_mutation_lock`, тест 30/30 раз ловит `AssertionError` "второй поток вошёл в
    критическую секцию, ПОКА holder ещё держит flock" -- т.е. harness способен различить
    реальную сериализацию от её отсутствия, а не просто "иногда проходит по случайности
    scheduling"."""
    _seed_foreign_proxy_with_backup(real_git_home)

    @contextlib.contextmanager
    def _noop_lock():
        yield True

    holder_active = threading.Event()
    holder_assigned = threading.Event()
    attempting = {"enable-thread": threading.Event(), "disable-thread": threading.Event()}
    entered = {"enable-thread": threading.Event(), "disable-thread": threading.Event()}
    both_started = threading.Barrier(2, timeout=5)

    @contextlib.contextmanager
    def _synced_noop_lock():
        name = threading.current_thread().name
        other = "disable-thread" if name == "enable-thread" else "enable-thread"
        both_started.wait()
        attempting[name].set()
        with _noop_lock() as lock_acquired:
            entered[name].set()
            became_holder = not holder_assigned.is_set()
            if became_holder:
                holder_assigned.set()
                holder_active.set()
                attempting[other].wait(timeout=3)
                assert not entered[other].is_set(), (
                    "второй поток вошёл в критическую секцию, ПОКА holder ещё держит flock -- "
                    "_mutation_lock НЕ сериализует"
                )
            yield lock_acquired

    monkeypatch.setattr(git_proxy, "_mutation_lock", _synced_noop_lock)

    results = {}
    thread_errors = {}

    def _run_enable():
        try:
            results["enable"] = git_proxy.enable()
        except BaseException as exc:  # noqa: BLE001 -- re-raised verbatim in main thread below
            thread_errors["enable"] = exc

    def _run_disable():
        try:
            results["disable"] = git_proxy.disable()
        except BaseException as exc:  # noqa: BLE001 -- re-raised verbatim in main thread below
            thread_errors["disable"] = exc

    t_enable = threading.Thread(target=_run_enable, name="enable-thread")
    t_disable = threading.Thread(target=_run_disable, name="disable-thread")
    t_enable.start()
    t_disable.start()
    t_enable.join(timeout=15)
    t_disable.join(timeout=15)

    assert thread_errors, (
        "harness ОБЯЗАН обнаружить no-op _mutation_lock как регресс (AssertionError в одном из "
        "потоков) -- если исключений нет, harness сам сломан и НЕ способен ловить регресс "
        "issue #234 finding 2 (см. rounds 1-3 в docstring теста выше -- все false-green)"
    )


# ==================== Post-review follow-up: flock acquisition errors ====================
# Codex cycle-review PR #275 (issue #234 follow-up), round 1:
# P2 (round 0, уже исправлен ниже фиксом round 1): _mutation_lock открывал lock-файл успешно
# (os.open), но fcntl.flock(fd, LOCK_EX) мог бросить OSError отдельно (напр. сетевой HOME на
# macOS -> ENOTSUP/EIO) -- это НЕ было поймано, enable()/disable() убегали с исключением вместо
# документированного result-словаря, dashboard-запрос падал в HTTP 500.
#
# CRITICAL (round 1, Codex xhigh, confidence 0.99): фикс P2 сам по себе тихо снял ВСЮ защиту
# finding 2 (cross-process lock) -- если flock физически недоступен (тот же ENOTSUP/EIO), код
# просто продолжал мутацию БЕЗ сериализации ("best-effort"), молча воссоздавая race из finding 2:
# конкурентные enable()/disable() снова могли терять backup безвозвратно, просто оба вызова
# больше не падали исключением. Codex эмпирически воспроизвёл: KEY=[P], backup=absent, оба
# результата ok=True -- те же A,B потеряны навсегда, что и до fix issue #234.
#
# Fix: _mutation_lock() теперь yield'ит bool lock_acquired; enable()/disable() ОБЯЗАНЫ
# проверить его и вернуть fail-closed {"ok": False, ...} вместо мутации без реальной
# сериализации -- явный отказ вместо тихой потери данных (канон fail-closed-proxy-down).

def test_flock_acquisition_error_fails_closed_instead_of_mutating_unsynchronized(monkeypatch, real_git_home):
    """fcntl.flock бросает OSError на LOCK_EX (fd открылся, но ФС не поддерживает advisory-lock).
    enable() ОБЯЗАН вернуть {"ok": False, ...} (fail-closed) -- НЕ мутировать состояние без
    реальной cross-process сериализации, и уж точно не бросить исключение наружу."""
    import fcntl

    real_flock = fcntl.flock

    def _flock_raises(fd, operation):
        if operation == fcntl.LOCK_EX:
            raise OSError("simulated ENOTSUP: flock not supported on this filesystem")
        return real_flock(fd, operation)

    monkeypatch.setattr(git_proxy.fcntl, "flock", _flock_raises)

    result = git_proxy.enable()

    assert isinstance(result, dict), "enable() обязан вернуть result-словарь, не бросить исключение"
    assert result["ok"] is False, f"enable() без реального лока обязан отказать fail-closed: {result}"

    current = git_proxy._get_all(git_proxy.KEY)
    assert not current["present"], "KEY не должен быть мутирован при недоступном lock-примитиве"


def test_concurrent_enable_disable_with_forced_lock_failure_fail_closed_not_racy(monkeypatch, real_git_home):
    """CRITICAL regression (Codex cycle-review PR #275, round 1, confidence 0.99): если
    fcntl.flock физически недоступен (ENOTSUP/EIO) В ОБОИХ конкурентных вызовах, старый код
    тихо деградировал в "без лока" и терял backup [A,B] безвозвратно (тот же race, что
    finding 2 issue #234, просто без исключения). С fail-closed фиксом: КАЖДЫЙ вызов, который
    не смог получить реальный лок, обязан отказать {"ok": False} и НЕ трогать состояние --
    поэтому гонка невозможна в принципе (нет мутации без лока, значит нет racy-мутации)."""
    import fcntl

    real_flock = fcntl.flock

    # Baseline setup (proxy=P enabled, backup=[A,B]) -- ДО установки forced-failure мока,
    # реальный flock работает нормально для этой части.
    assert git_proxy.enable()["ok"] is True
    _raw_set_add(git_proxy._BACKUP_KEY, "A", real_git_home)
    subprocess.run(
        ["git", "config", "--global", "--add", git_proxy._BACKUP_KEY, "B"],
        env=dict(os.environ, HOME=str(real_git_home)), capture_output=True, text=True, check=True,
    )
    assert git_proxy._backup_state()["values"] == ["A", "B"]

    # Теперь принудительно ломаем flock -- ОБА конкурентных enable()/disable() пытаются
    # мутировать под forced flock-failure.
    def _flock_always_raises(fd, operation):
        if operation == fcntl.LOCK_EX:
            raise OSError("simulated ENOTSUP: flock not supported on this filesystem")
        return real_flock(fd, operation)

    monkeypatch.setattr(git_proxy.fcntl, "flock", _flock_always_raises)

    results = {}

    def _run_enable():
        results["enable"] = git_proxy.enable()

    def _run_disable():
        results["disable"] = git_proxy.disable()

    t_enable = threading.Thread(target=_run_enable, name="enable-thread")
    t_disable = threading.Thread(target=_run_disable, name="disable-thread")
    t_enable.start()
    t_disable.start()
    t_enable.join(timeout=15)
    t_disable.join(timeout=15)

    final_key = git_proxy._get_all(git_proxy.KEY)
    final_backup = git_proxy._backup_state()

    # С fail-closed фиксом: ЛЮБОЙ вызов без реального лока обязан отказать, не мутируя.
    # Значит backup НЕ МОЖЕТ быть потерян -- он либо остаётся нетронутым (оба вызова
    # отказали), либо один из них успешно завершился (что невозможно при forced-failure
    # ВСЕГДА raise, но проверяем инвариант данных, а не то, что оба обязательно ok=False).
    backup_alive = final_backup["present"] and final_backup["values"] == ["A", "B"]
    restored_into_key = final_key["present"] and final_key["values"] == ["A", "B"]
    proxy_enabled_with_backup_intact = (
        final_key["present"] and final_key["values"] == [EXPECTED_GIT_PROXY] and backup_alive
    )

    assert backup_alive or restored_into_key or proxy_enabled_with_backup_intact, (
        f"[A,B] потерян безвозвратно из-за racy-мутации под forced lock-failure (fail-closed "
        f"фикс должен был предотвратить ЛЮБУЮ мутацию без реального лока): "
        f"KEY={final_key}, BACKUP={final_backup}, results={results}"
    )
    assert results["enable"]["ok"] is False, f"enable() без лока обязан fail-closed: {results['enable']}"
    assert results["disable"]["ok"] is False, f"disable() без лока обязан fail-closed: {results['disable']}"


# ==================== Round 2: target value can impersonate the sentinel ====================
# Codex cycle-review PR #275 round 2 (xhigh, confidence 0.99), эмпирически подтверждено triage:
# sentinel, зависящий ТОЛЬКО от digest(values_before_last), structurally неотличим от target
# X == _txn_sentinel(values_before_X). Не требует SHA-256 коллизии -- X просто должен буквально
# совпасть со своим собственным digest-хвостом. Crash ПОСЛЕ записи X (но до записи РЕАЛЬНОГО
# финального sentinel) оставляет [KEY, ..., X], который старая схема (digest без count)
# принимала как complete, теряя всё после X навсегда. Fix: sentinel теперь кодирует count И
# digest вместе -- X, совпавший ТОЛЬКО с digest(values_before_X), больше не проходит, т.к.
# ожидаемый count для настоящего sentinel = len(txn_values), а не len(values_before_X).

def test_target_value_matching_its_own_sentinel_not_accepted_as_complete(real_git_home):
    """CRITICAL regression (Codex cycle-review PR #275, round 2, confidence 0.99): target-список
    [KEY, "A", X], где X == _txn_sentinel([KEY, "A"]) (т.е. последнее target-значение случайно
    равно sentinel предыдущих значений). Crash ПОСЛЕ записи X, ДО записи реального финального
    sentinel (sentinel([KEY,"A",X])) оставляет на диске ровно [KEY, "A", X] -- то же самое, что
    оставил бы настоящий complete-маркер для target=["A"] с sentinel=X. Recovery ОБЯЗАН отклонить
    это как corrupt (count не совпадёт), а не тихо принять и потерять X навсегда."""
    x = git_proxy._txn_sentinel([git_proxy.KEY, "A"])

    _raw_set_add(git_proxy._TXN_KEY, git_proxy.KEY, real_git_home)
    _raw_set_add(git_proxy._TXN_KEY, "A", real_git_home)
    _raw_set_add(git_proxy._TXN_KEY, x, real_git_home)

    _raw_set_add(git_proxy.KEY, "A", real_git_home)
    _raw_set_add(git_proxy.KEY, x, real_git_home)

    txn = git_proxy._get_all(git_proxy._TXN_KEY)
    assert txn["values"] == [git_proxy.KEY, "A", x], "sanity: сырой partial-маркер, где X подделывает sentinel"

    resolved = git_proxy._check_and_resolve_txn()

    assert resolved["ok"] is False, (
        f"partial-маркер [KEY,'A',X], где X=_txn_sentinel([KEY,'A']), ОБЯЗАН быть отклонён как "
        f"corrupt -- НЕ реплеиться как complete target=['A'] (что потеряло бы X={x!r} навсегда)"
    )

    current = git_proxy._get_all(git_proxy.KEY)
    assert current["values"] == ["A", x], "KEY не должен быть искажён отклонённым partial-маркером"


# ==================== Round 3: transient sentinel-read failure destroys valid marker ====================
# Codex cycle-review PR #275 round 3 (xhigh, confidence 0.99), эмпирически подтверждено triage:
# _check_and_resolve_txn смешивал "не удалось прочитать _TXN_SENTINEL_KEY" (unknown=True,
# transient -- git timeout/permission-race) с "прочитали, но sentinel отсутствует/не совпадает"
# (permanent corruption) в ОДНОЙ ветке -- оба случая удаляли ОБА маркера. Единичный transient
# сбой чтения уничтожал ВАЛИДНЫЙ, готовый-к-retry in-flight маркер: следующий enable()/disable()
# видел current (ещё НЕ тронутый, т.к. retry так и не выполнился) как "новое foreign состояние"
# и мог перезаписать backup, теряя всё, что было после уже частично восстановленного префикса.

def test_transient_sentinel_read_failure_does_not_destroy_valid_marker(monkeypatch, real_git_home):
    """CRITICAL regression (Codex cycle-review PR #275, round 3, confidence 0.99): валидный
    complete txn-маркер (target=[_PROXY], корректный sentinel в _TXN_SENTINEL_KEY) существует.
    Одно чтение _TXN_SENTINEL_KEY транзиентно падает (timeout, НЕ "ключа нет"). Recovery
    ОБЯЗАН вернуть ошибку БЕЗ мутации (resolved=False, оба маркера НЕТРОНУТЫ) -- не удалять
    валидный маркер, который мог бы быть успешно доведён до конца следующим вызовом."""
    _raw_set_add(git_proxy.KEY, "A", real_git_home)
    _raw_set_add(git_proxy.KEY, "B", real_git_home)
    _raw_set_add(git_proxy.KEY, "C", real_git_home)

    begin = git_proxy._begin_txn(git_proxy.KEY, [EXPECTED_GIT_PROXY])
    assert begin["ok"] is True, "sanity: валидный complete txn-маркер должен быть записан успешно"

    real_run = git_proxy.sys_probe.run

    def _sentinel_read_times_out_once(cmd, **kwargs):
        if cmd[-3:-1] == ["--get-all", "-z"] and cmd[-1] == git_proxy._TXN_SENTINEL_KEY:
            return {"rc": None, "out": "", "err": "simulated timeout", "timeout": True}
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(git_proxy.sys_probe, "run", _sentinel_read_times_out_once)

    resolved = git_proxy._check_and_resolve_txn()

    assert resolved["ok"] is False, "transient read failure должен вернуть ошибку"
    assert resolved["resolved"] is False, (
        "transient read failure -- НЕ 'маркер разрешён' (resolved=True удалил бы валидный "
        "маркер навсегда); должно быть resolved=False, как и для txn['unknown'] выше"
    )

    monkeypatch.setattr(git_proxy.sys_probe, "run", real_run)

    txn_after = git_proxy._get_all(git_proxy._TXN_KEY)
    sentinel_after = git_proxy._get_all(git_proxy._TXN_SENTINEL_KEY)
    assert txn_after["present"] is True, "валидный _TXN_KEY НЕ должен быть удалён из-за transient сбоя"
    assert sentinel_after["present"] is True, "валидный _TXN_SENTINEL_KEY НЕ должен быть удалён из-за transient сбоя"

    # KEY нетронут -- retry так и не выполнился (transient failure произошёл ДО retry).
    current = git_proxy._get_all(git_proxy.KEY)
    assert current["values"] == ["A", "B", "C"], "KEY не должен быть мутирован при transient read failure"

    # Следующий вызов (на рабочем соединении) должен успешно довести маркер до конца.
    resolved2 = git_proxy._check_and_resolve_txn()
    assert resolved2["ok"] is True
    assert resolved2["resolved"] is True
    current2 = git_proxy._get_all(git_proxy.KEY)
    assert current2["values"] == [EXPECTED_GIT_PROXY], "маркер должен корректно replay'иться на следующей попытке"


# ==================== issue #282: НАСТОЯЩИЙ cross-process harness ====================
# Round 3 (эта issue): thread-based harness (threading.Thread в одном интерпретаторе) доказывает
# только in-process взаимоисключение. Сломанный _mutation_lock, использующий process-local
# threading.Lock/mutex вместо реального fcntl.flock, прошёл бы такой тест -- но НЕ защитил бы
# реальный сценарий issue #234 (CLI-процесс vs dashboard-поток, РАЗНЫЕ процессы).
#
# Два настоящих дочерних процесса (subprocess.Popen, общий временный HOME) через standalone
# helper tests/git_proxy_lock_harness.py:
#   - holder сигналит `holder_entered` ТОЛЬКО ПОСЛЕ входа в защищённое тело (после реального flock)
#     и держит лок, пока его не освободят явно маркером `release`;
#   - waiter обязан доказуемо НЕ суметь войти в критическую секцию, пока holder держит лок
#     (иначе `waiter_entered_too_early` -- lock process-local/сломан).
# Проверяются exit-коды обоих процессов (включая propagated exceptions, превращаемые helper'ом
# в rc!=0).

_LOCK_HARNESS = Path(__file__).with_name("git_proxy_lock_harness.py")


def _wait_for_file(path: Path, timeout: float, poll: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(poll)
    return False


def _run_lock_harness(tmp_path, broken_lock: bool):
    """Запускает holder+waiter+probe через дочерние процессы, делит один временный HOME.

    Возвращает: holder_rc, waiter_rc, entered_too_early (bool), waiter_entered_after_release (bool),
    probe_locked_rc (int — 0 если flock удержан cross-process пока holder внутри), probe_free_rc
    (int — 0 если flock освободился после выхода holder'а).

    Детерминированный handshake (cycle-review #283, Codex round 2): НИКАКИХ тайминговых окон.
    Cross-process характер _mutation_lock доказывается ПРЯМЫМ probe'ом канонического lockfile:
    пока holder внутри (после holder_entered, до release) отдельный процесс пытается LOCK_EX|LOCK_NB
    и ОБЯЗАН получить EWOULDBLOCK — авторитетный ответ ОС о том, что flock удержан другим процессом.
    Это замена wall-clock-absence-проверки (3-секундного отсутствия entered_too_early), которая
    могла false-green на сломанном локе, задерживающем yield дольше окна (канон
    wall-clock-assert-is-not-the-invariant).
    """
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, HOME=str(home))
    if broken_lock:
        env["SR_BROKEN_LOCK"] = "1"

    holder = waiter = probe_locked = probe_free = None
    try:
        holder = subprocess.Popen(
            [sys.executable, str(_LOCK_HARNESS), "holder", str(tmp_path)], env=env
        )
        assert _wait_for_file(tmp_path / "holder_entered", timeout=20), (
            "holder обязан войти в критическую секцию (после реального flock)"
        )

        # Детерминированный cross-process proof: пока holder внутри _mutation_lock, flock на
        # каноническом lockfile обязан быть удержан (LOCK_EX|LOCK_NB -> EWOULDBLOCK) из другого
        # процесса. Завершаем probe ДО release, чтобы holder гарантированно ещё держал лок.
        probe_locked = subprocess.Popen(
            [sys.executable, str(_LOCK_HARNESS), "probe", str(tmp_path), "locked"], env=env
        )
        probe_locked_rc = probe_locked.wait(timeout=20)

        waiter = subprocess.Popen(
            [sys.executable, str(_LOCK_HARNESS), "waiter", str(tmp_path)], env=env
        )
        assert _wait_for_file(tmp_path / "waiter_attempting", timeout=20), (
            "waiter обязан дойти до порога блокирующего входа"
        )

        (tmp_path / "release").write_text("1")  # явное освобождение holder'а

        holder_rc = holder.wait(timeout=20)
        waiter_rc = waiter.wait(timeout=20)

        # Детерминированный proof освобождения: после выхода holder'а probe обязан приобрести лок.
        probe_free = subprocess.Popen(
            [sys.executable, str(_LOCK_HARNESS), "probe", str(tmp_path), "free"], env=env
        )
        probe_free_rc = probe_free.wait(timeout=20)
    except Exception:
        # Не оставляем дочерние процессы висеть (cycle-review major #2): освобождаем holder,
        # завершаем и ждём все, чтобы никакой процесс не держал flock/не утёк.
        try:
            (tmp_path / "release").write_text("1")
        except OSError:
            pass
        for p in (holder, waiter, probe_locked, probe_free):
            if p is not None and p.poll() is None:
                p.terminate()
        for p in (holder, waiter, probe_locked, probe_free):
            if p is not None:
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
        raise

    waiter_after = (tmp_path / "waiter.result").read_text() if (tmp_path / "waiter.result").exists() else ""
    return {
        "holder_rc": holder_rc,
        "waiter_rc": waiter_rc,
        "entered_too_early": (tmp_path / "waiter_entered_too_early").exists(),
        "waiter_entered_after_release": waiter_after == "ok",
        "probe_locked_rc": probe_locked_rc,
        "probe_free_rc": probe_free_rc,
    }


def test_mutation_lock_is_true_cross_process_exclusion(tmp_path):
    """Позитивный контроль: настоящий _mutation_lock (fcntl.flock) сериализует МЕЖДУ процессами.

    holder (отдельный процесс) входит в критическую секцию и держит лок; ДЕТЕРМИНИРОВАННЫЙ probe
    (другой процесс, LOCK_EX|LOCK_NB на каноническом lockfile) обязан получить EWOULDBLOCK — flock
    удержан cross-process. После явного освобождения probe обязан приобрести лок, а waiter —
    сериализованно войти. Это доказывает cross-process природу лока, которую in-process harness
    (issue #282 round 3 gap) не мог различить: process-local threading.Lock прошёл бы thread-based тест.
    """
    outcomes = _run_lock_harness(tmp_path, broken_lock=False)

    assert outcomes["probe_locked_rc"] == 0, (
        f"flock обязан быть удержан cross-process (EWOULDBLOCK) пока holder внутри: {outcomes}"
    )
    assert outcomes["holder_rc"] == 0, f"holder обязан завершиться успешно: {outcomes}"
    assert outcomes["waiter_rc"] == 0, f"waiter обязан дождаться входа ПОСЛЕ release: {outcomes}"
    assert outcomes["entered_too_early"] is False, (
        f"waiter вошёл в критическую секцию ПОКА holder держит лок -- значит лок НЕ "
        f"cross-process (сломан): {outcomes}"
    )
    assert outcomes["waiter_entered_after_release"] is True, (
        f"waiter обязан успешно войти после явного освобождения holder'а: {outcomes}"
    )
    assert outcomes["probe_free_rc"] == 0, (
        f"flock обязан освободиться после выхода holder'а (probe приобретает): {outcomes}"
    )


def test_harness_rejects_process_local_lock(tmp_path):
    """Негативный контроль (чувствительность harness): process-local threading.Lock НЕ
    сериализует между процессами (у каждого процесса свой объект) -- такой «сломанный»
    _mutation_lock обязан быть пойман harness'ом как детерминированный probe (LOCK_EX|LOCK_NB на
    каноническом lockfile НЕ даст EWOULDBLOCK, т.к. process-local лок не держит файловый flock).
    Без этого теста harness был бы false-green: он бы «проходил» и с настоящим flock, и с
    process-local локом, ничего не доказывая (regression-гвард против тихого обесценивания проверки).
    """
    outcomes = _run_lock_harness(tmp_path, broken_lock=True)

    assert outcomes["probe_locked_rc"] != 0, (
        f"probe ОБЯЗАН поймать, что process-local лок НЕ удерживает файловый flock "
        f"(LOCK_NB обязан приобрести, rc!=0): {outcomes}"
    )
    assert outcomes["entered_too_early"] is True, (
        f"harness ОБЯЗАН детектировать process-local лок (waiter вошёл ДО release): {outcomes}"
    )
    assert outcomes["waiter_rc"] == 2, f"waiter под сломанным локом обязан rc=2 (entered-before-release): {outcomes}"
    assert outcomes["holder_rc"] == 0, f"holder (после явного release) обязан выйти успешно: {outcomes}"
    assert outcomes["waiter_entered_after_release"] is False, (
        f"waiter под сломанным локом НЕ должен войти «после release» — он вошёл раньше: {outcomes}"
    )
