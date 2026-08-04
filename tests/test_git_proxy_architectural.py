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
import os
import subprocess
import sys
import threading
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

def test_concurrent_enable_and_disable_do_not_lose_backup_deterministic(monkeypatch, real_git_home):
    """Regression (Codex cycle 2, issue #234) -- ДЕТЕРМИНИРОВАННОЕ воспроизведение repro из issue
    (не завязано на реальный thread-scheduling, который может "случайно" не гонять и давать false
    negative). Two-thread interleaving воспроизводится явно через barrier, вставленный ВНУТРЬ
    enable()/disable() между read current-state и write, точно в шаге, который issue называет
    неcериализованным: "Transaction check, current-state read, backup decision, and write are NOT
    serialized".

    Сценарий из issue: managed proxy P включен, backup=[A,B].
    1. enable-thread читает current=[P] (is_foreign=False).
    2. disable-thread ПОЛНОСТЬЮ выполняется: restore [A,B] в KEY, удаляет backup.
    3. enable-thread (с уже устаревшим read current=[P] с шага 1) продолжает: раз is_foreign=False
       (по СТАРОМУ read), backup НЕ трогает и пишет [P] в KEY поверх [A,B] -- [A,B] уже потерян
       из KEY, а backup тоже пуст (удалён на шаге 2) -> [A,B] потерян НАВСЕГДА.

    С lock: enable-thread не может прочитать current ДО того как disable-thread полностью
    завершит свою транзакцию (или наоборот) -- итог детерминирован и не теряет данные.
    """
    assert git_proxy.enable()["ok"] is True
    _raw_set_add(git_proxy._BACKUP_KEY, "A", real_git_home)
    subprocess.run(
        ["git", "config", "--global", "--add", git_proxy._BACKUP_KEY, "B"],
        env=dict(os.environ, HOME=str(real_git_home)), capture_output=True, text=True, check=True,
    )
    assert git_proxy._backup_state()["values"] == ["A", "B"]

    real_run = git_proxy.sys_probe.run
    enable_read_done = threading.Event()
    disable_finished = threading.Event()

    def _interleaved_run(cmd, **kwargs):
        # enable-thread: сразу после его первого current-state read (--get-all KEY, ПОСЛЕ
        # разрешения txn) -- сигналим и ждём, пока disable-thread полностью не закончит.
        if (
            threading.current_thread().name == "enable-thread"
            and cmd[-3:-1] == ["--get-all", "-z"]
            and cmd[-1] == git_proxy.KEY
        ):
            result = real_run(cmd, **kwargs)
            if not enable_read_done.is_set():
                enable_read_done.set()
                disable_finished.wait(timeout=10)
            return result
        if threading.current_thread().name == "disable-thread":
            enable_read_done.wait(timeout=10)  # disable стартует ПОСЛЕ read enable-thread
            result = real_run(cmd, **kwargs)
            return result
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(git_proxy.sys_probe, "run", _interleaved_run)

    results = {}

    def _run_enable():
        results["enable"] = git_proxy.enable()

    def _run_disable():
        results["disable"] = git_proxy.disable()
        disable_finished.set()

    t_enable = threading.Thread(target=_run_enable, name="enable-thread")
    t_disable = threading.Thread(target=_run_disable, name="disable-thread")
    t_enable.start()
    t_disable.start()
    t_enable.join(timeout=15)
    t_disable.join(timeout=15)

    monkeypatch.setattr(git_proxy.sys_probe, "run", real_run)

    final_key = git_proxy._get_all(git_proxy.KEY)
    final_backup = git_proxy._backup_state()

    backup_alive = final_backup["present"] and final_backup["values"] == ["A", "B"]
    restored_into_key = final_key["present"] and final_key["values"] == ["A", "B"]
    proxy_enabled_with_backup_intact = (
        final_key["present"] and final_key["values"] == [EXPECTED_GIT_PROXY] and backup_alive
    )

    assert backup_alive or restored_into_key or proxy_enabled_with_backup_intact, (
        f"[A,B] потерян безвозвратно из-за неcериализованной гонки: "
        f"KEY={final_key}, BACKUP={final_backup}, results={results}"
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
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(poll)
    return False


def _run_lock_harness(tmp_path, broken_lock: bool):
    """Запускает holder+waiter через два дочерних процесса, делит один временный HOME.

    Возвращает: holder_rc, waiter_rc, entered_too_early (bool — waiter вошёл ДО release,
    т.е. лок НЕ cross-process), waiter_entered_after_release (bool).
    """
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, HOME=str(home))
    if broken_lock:
        env["SR_BROKEN_LOCK"] = "1"

    holder = subprocess.Popen(
        [sys.executable, str(_LOCK_HARNESS), "holder", str(tmp_path)], env=env
    )
    assert _wait_for_file(tmp_path / "holder_entered", timeout=20), (
        "holder обязан войти в критическую секцию (после реального flock)"
    )

    waiter = subprocess.Popen(
        [sys.executable, str(_LOCK_HARNESS), "waiter", str(tmp_path)], env=env
    )
    assert _wait_for_file(tmp_path / "waiter_attempting", timeout=20), (
        "waiter обязан дойти до порога блокирующего входа"
    )

    # Короткий буфер: если waiter вошёл ДО release (lock не сериализует между процессами) —
    # маркер появится здесь. При настоящем flock waiter заблокирован и НЕ входит.
    entered_too_early = _wait_for_file(tmp_path / "waiter_entered_too_early", timeout=0.5, poll=0.02)

    (tmp_path / "release").write_text("1")  # явное освобождение holder'а

    holder_rc = holder.wait(timeout=20)
    waiter_rc = waiter.wait(timeout=20)

    waiter_after = (tmp_path / "waiter.result").read_text() if (tmp_path / "waiter.result").exists() else ""
    return {
        "holder_rc": holder_rc,
        "waiter_rc": waiter_rc,
        "entered_too_early": entered_too_early,
        "waiter_entered_after_release": waiter_after == "ok",
    }


def test_mutation_lock_is_true_cross_process_exclusion(tmp_path):
    """Позитивный контроль: настоящий _mutation_lock (fcntl.flock) сериализует МЕЖДУ процессами.

    holder (отдельный процесс) входит в критическую секцию и держит лок; waiter (другой
    процесс) обязан быть заблокирован на входе и НЕ войти, пока holder не освободит лок явно.
    Это доказывает cross-process природу лока, которую in-process harness (issue #282 round 3
    gap) не мог различить: process-local threading.Lock прошёл бы thread-based тест.
    """
    outcomes = _run_lock_harness(tmp_path, broken_lock=False)

    assert outcomes["holder_rc"] == 0, f"holder обязан завершиться успешно: {outcomes}"
    assert outcomes["waiter_rc"] == 0, f"waiter обязан дождаться входа ПОСЛЕ release: {outcomes}"
    assert outcomes["entered_too_early"] is False, (
        f"waiter вошёл в критическую секцию ПОКА holder держит лок -- значит лок НЕ "
        f"cross-process (сломан): {outcomes}"
    )
    assert outcomes["waiter_entered_after_release"] is True, (
        f"waiter обязан успешно войти после явного освобождения holder'а: {outcomes}"
    )


def test_harness_rejects_process_local_lock(tmp_path):
    """Негативный контроль (чувствительность harness): process-local threading.Lock НЕ
    сериализует между процессами (у каждого процесса свой объект) -- такой «сломанный»
    _mutation_lock обязан быть пойман harness'ом как `entered_too_early`. Без этого теста
    harness был бы false-green: он бы «проходил» и с настоящим flock, и с process-local локом,
    ничего не доказывая (regression-гвард против тихого обесценивания проверки).
    """
    outcomes = _run_lock_harness(tmp_path, broken_lock=True)

    assert outcomes["entered_too_early"] is True, (
        f"harness ОБЯЗАН детектировать process-local лок (waiter вошёл ДО release): {outcomes}"
    )
    assert outcomes["waiter_rc"] == 2, f"waiter под сломанным локом обязан rc=2 (entered-before-release): {outcomes}"
