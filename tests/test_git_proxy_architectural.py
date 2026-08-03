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
import threading

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
    negative).

    Issue #279: тест писался ДО PR #275 (issue #234 follow-up, 54cd9d8), который обернул ВСЮ
    enable()/disable()-транзакцию в реальный cross-process `_mutation_lock()` (fcntl.flock,
    блокирующий) ДО первого current-state read. Старый barrier синхронизировался ВНУТРИ read/write
    (через monkeypatch на sys_probe.run) -- под реальным локом это создавало дедлок: enable-thread
    держит flock и ждёт `disable_finished`, а disable-thread физически не может дойти до своего
    первого sys_probe.run()-вызова (и просигналить `disable_finished`), пока не получит тот же
    flock, который занят enable-thread. Разрешалось только по wait(timeout=10) -- 10.5s balласт
    на каждый прогон.

    Fix: barrier синхронизирует СТАРТ обоих потоков ПЕРЕД входом в _mutation_lock() (гарантирует,
    что оба потока реально конкурируют за лок, а не гоняются по чистой случайности планировщика),
    а не interleaving ВНУТРИ locked-тела. Реальный flock после этого сериализует транзакции сам --
    именно это и есть проверяемый инвариант (issue #234 finding 2), никакого искусственного
    ожидания под локом не требуется.

    Сценарий: managed proxy P включен, backup=[A,B]. Оба потока стартуют одновременно и конкурируют
    за _mutation_lock; какой бы порядок flock ни выбрал, каждая транзакция видит консистентный
    read/write без interleaving -- backup не теряется НИ В ОДНОМ порядке выполнения.
    """
    assert git_proxy.enable()["ok"] is True
    _raw_set_add(git_proxy._BACKUP_KEY, "A", real_git_home)
    subprocess.run(
        ["git", "config", "--global", "--add", git_proxy._BACKUP_KEY, "B"],
        env=dict(os.environ, HOME=str(real_git_home)), capture_output=True, text=True, check=True,
    )
    assert git_proxy._backup_state()["values"] == ["A", "B"]

    real_mutation_lock = git_proxy._mutation_lock
    both_started = threading.Barrier(2, timeout=5)

    def _synced_mutation_lock():
        # Гарантируем, что оба потока реально стартуют одновременно и конкурируют за flock --
        # без этого один поток мог бы полностью завершиться до старта второго (false negative
        # на быстрой машине), не воспроизводя ситуацию из issue #234 вовсе.
        both_started.wait()
        return real_mutation_lock()

    monkeypatch.setattr(git_proxy, "_mutation_lock", _synced_mutation_lock)

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

    monkeypatch.setattr(git_proxy, "_mutation_lock", real_mutation_lock)

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
