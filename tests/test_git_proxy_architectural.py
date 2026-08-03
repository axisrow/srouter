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
# Codex cycle-review PR #275 (issue #234 follow-up), P2: _mutation_lock открывал lock-файл
# успешно (os.open), но fcntl.flock(fd, LOCK_EX) мог бросить OSError отдельно (напр. сетевой
# HOME на macOS -> ENOTSUP/EIO) -- это НЕ было поймано, enable()/disable() убегали с исключением
# вместо документированного result-словаря, dashboard-запрос падал в HTTP 500.

def test_flock_acquisition_error_degrades_instead_of_raising(monkeypatch, real_git_home):
    """fcntl.flock бросает OSError на LOCK_EX (fd открылся, но ФС не поддерживает advisory-lock).
    enable() должен деградировать без lock (best-effort), а не пробрасывать исключение наружу."""
    import fcntl

    real_flock = fcntl.flock

    def _flock_raises(fd, operation):
        if operation == fcntl.LOCK_EX:
            raise OSError("simulated ENOTSUP: flock not supported on this filesystem")
        return real_flock(fd, operation)

    monkeypatch.setattr(git_proxy.fcntl, "flock", _flock_raises)

    result = git_proxy.enable()

    assert isinstance(result, dict), "enable() обязан вернуть result-словарь, не бросить исключение"
    assert result["ok"] is True, f"enable() должен успешно завершиться без lock: {result}"

    current = git_proxy._get_all(git_proxy.KEY)
    assert current["values"] == [EXPECTED_GIT_PROXY]
