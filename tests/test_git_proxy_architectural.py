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
    finding (confidence 0.99, эмпирически подтверждено негативным контролем -- see
    test_negative_control_noop_mutation_lock_loses_backup ниже): barrier синхронизировал только МОМЕНТ
    ВЫЗОВА `_mutation_lock()`, а не реальное удержание критической секции. С `_mutation_lock`,
    заменённым на no-op (никогда не сериализующий), тест ВСЁ РАВНО проходил 20/20 -- потому что
    git's СОБСТВЕННЫЙ файловый lock на `.gitconfig` (`could not lock config file ...: File exists`)
    заставлял ОДИН из потоков упасть в `_begin_txn` с fail-closed ошибкой, а другой -- завершиться
    последовательно. Тест валидировал побочный git-native lock, а не наш `_mutation_lock`.

    Fix (round 2): holder/waiter внутри САМОЙ критической секции. `_enable_locked`/`_disable_locked`
    -- внутренние функции, вызываемые ТОЛЬКО под `_mutation_lock()` (см. enable()/disable() выше) --
    monkeypatch'аются так, что holder (первый вошедший под лок) сигналит `holder_entered` и ждёт
    `waiter_confirmed`, ДАВАЯ waiter'у шанс убедиться, что он НЕ может продвинуться, пока holder не
    выйдет. Это доказывает, что _mutation_lock реально сериализует -- если бы лок был no-op, waiter
    вошёл бы в свою locked-функцию одновременно с holder, а не заблокировался бы снаружи.
    """
    _seed_foreign_proxy_with_backup(real_git_home)

    real_enable_locked = git_proxy._enable_locked
    real_disable_locked = git_proxy._disable_locked

    holder_entered = threading.Event()
    waiter_confirmed_blocked = threading.Event()
    order = []
    order_lock = threading.Lock()

    def _mark_and_call(name, real_fn):
        with order_lock:
            is_holder = not order
            order.append(name)
        if is_holder:
            holder_entered.set()
            # Дать waiter'у время попытаться войти -- если лок реально сериализует, waiter
            # физически не может дойти до своей _locked-функции здесь (она вызывается ТОЛЬКО
            # под _mutation_lock, который holder сейчас держит).
            waiter_confirmed_blocked.wait(timeout=2)
        return real_fn()

    def _traced_enable_locked():
        return _mark_and_call("enable", real_enable_locked)

    def _traced_disable_locked():
        return _mark_and_call("disable", real_disable_locked)

    monkeypatch.setattr(git_proxy, "_enable_locked", _traced_enable_locked)
    monkeypatch.setattr(git_proxy, "_disable_locked", _traced_disable_locked)

    both_started = threading.Barrier(2, timeout=5)
    real_mutation_lock = git_proxy._mutation_lock

    def _synced_mutation_lock():
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

    # Holder вошёл в locked-секцию -- waiter ЕЩЁ НЕ должен быть внутри своей _locked-функции
    # (иначе оба вошли одновременно -- лок не сериализует, регресс issue #234 не пойман).
    assert holder_entered.wait(timeout=10), "ни один поток не вошёл в критическую секцию"
    with order_lock:
        assert len(order) == 1, (
            f"ОБА потока вошли в critical section одновременно ({order}) -- "
            f"_mutation_lock НЕ сериализует (регресс issue #234 finding 2 не пойман)"
        )
    waiter_confirmed_blocked.set()

    t_enable.join(timeout=15)
    t_disable.join(timeout=15)

    assert order == ["enable", "disable"] or order == ["disable", "enable"], (
        f"holder/waiter должны были войти строго последовательно, получили: {order}"
    )

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
