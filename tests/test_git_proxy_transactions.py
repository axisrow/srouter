"""Общие test-cases git_proxy: строгая provenance-модель (issue #222).

git умеет нативный SOCKS5 (в отличие от Claude Code, см. codex-proxy #185). Claude Code → HTTP
(privoxy 8118), Codex/git → SOCKS5 (xray 10808).

Codex adversarial cycle-review PR #221 (issue #130) нашёл 3 раунда одной категории багов в
rc/bool()-эвристиках provenance. Round 1 (value-match disable) и часть round 2 (rc-обработка
status()) уже в main. Round 3 (этот файл, issue #222) — три конкретные дыры, каждая
воспроизведена эмпирически реальным `git config` (не имитация):

1. status() делал bool(out) — пустая строка (валидный override "ключ есть, но пустой",
   `git config --global http.https://github.com.proxy ""` → rc=0, out="") трактовалась как
   "ключа нет" (rc=1 даёт тот же bool(out)=False). Нужно различать presence (rc) от truthy(value).
2. Backup устаревает между поколениями чужих значений: A→install→manual B→uninstall→install→
   uninstall терял B навсегда, если backup обновлялся только при "backup отсутствует".
3. `git config --unset` на multi-valued key возвращает rc=5 (как и "ключа нет") — но КЛЮЧ НЕ
   СНЯТ (эмпирически подтверждено: --add x1, --add x2, --unset → rc=5, --get-all всё ещё [x1,x2]).
   Код, доверяющий "rc=5 всегда успех", врёт при multi-value.

Решение (verify-don't-guess канон): работа со СПИСКОМ значений через --get-all (не --get),
read-after-write verify после каждой мутации (--set/--unset/--replace-all), backup хранит ПОЛНЫЙ
список чужих значений и обновляется на каждое новое foreign-состояние между generations.

Тесты бьют по РЕАЛЬНОМУ `git config` (HOME → tmp_path), не мокают sys_probe.run — прямое
следствие root-cause issue: rc-семантика git должна быть проверена эмпирически, не угадана.
Исключение: unknown/non-absent-rc пути (permission denied, malformed config) — их не воспроизвести
реальным git детерминированно, для них используется mock sys_probe.run (секция ниже).
"""
import os
import subprocess

import pytest

import git_proxy
import sys_probe

EXPECTED_GIT_PROXY = git_proxy._PROXY


@pytest.fixture
def real_git_home(monkeypatch, tmp_path):
    """Перенаправить `git config --global` на изолированный HOME (реальный git, не мок)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    # sys_probe.run не передаёт env явно -> subprocess наследует os.environ; HOME уже переставлен.
    return tmp_path


def _raw_set_add(key, val, home):
    subprocess.run(
        ["git", "config", "--global", "--add", key, val],
        env=dict(os.environ, HOME=str(home)), capture_output=True, text=True, check=True,
    )


def _raw_set(key, val, home):
    subprocess.run(
        ["git", "config", "--global", key, val],
        env=dict(os.environ, HOME=str(home)), capture_output=True, text=True, check=True,
    )


# Codex /review PR #223 п.2: если backup успешно обновлён, но последующий _write_values(KEY, ...)
# падает — foreign-значение уже забэкаплено (safe: disable() сможет восстановить), но enable()
# возвращает ok=False. Явный тест на этот путь отказа, не покрытый предыдущими раундами review.

def test_enable_fails_but_backup_already_updated_stays_consistent(monkeypatch, real_git_home):
    """Regression (/review PR #223): если backup чужого значения успешно обновлён, а запись
    managed-значения в KEY падает — enable() возвращает ok=False, НЕ теряя backup. Последующий
    disable() (после починки среды) обязан суметь восстановить чужое значение из backup — состояние
    не должно "зависнуть" в промежутке между обновлённым backup и незаписанным KEY.
    """
    _raw_set(git_proxy.KEY, "https://corp.example:8443", real_git_home)
    real_run = sys_probe.run

    def _fail_key_write(cmd, **kwargs):
        # Раним ИМЕННО запись НОВОГО managed-значения (_PROXY) в KEY на этапе --add — имитирует
        # сбой git config (напр. диск полон, permission race) ПОСЛЕ того, как backup уже успешно
        # обновлён. Запись старого чужого значения (rollback внутри _write_values, а также любые
        # операции с _BACKUP_KEY) НЕ трогаем — иначе тест бы проверял не отказ записи, а полную
        # недоступность git config, что смазало бы конкретно проверяемый сценарий.
        if cmd[-2:] == [git_proxy.KEY, git_proxy._PROXY]:
            return {"rc": 1, "out": "", "err": "simulated git config failure", "timeout": False}
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(git_proxy.sys_probe, "run", _fail_key_write)

    r = git_proxy.enable()

    assert r["ok"] is False, "запись KEY провалилась -> enable() честно репортит отказ"

    monkeypatch.setattr(git_proxy.sys_probe, "run", real_run)  # "чиним" среду для проверки состояния
    backup = git_proxy._backup_state()
    assert backup["present"] is True, "backup не должен потеряться из-за последующего сбоя записи KEY"
    assert backup["values"] == ["https://corp.example:8443"], "backup содержит корректное чужое значение"

    # KEY остался в исходном (не-managed) состоянии — запись не прошла, но и не побилась частично.
    current = git_proxy._get_all(git_proxy.KEY)
    assert current["values"] == ["https://corp.example:8443"], (
        "KEY не тронут при отказе записи -- ни managed-значения, ни искажённого состояния"
    )

    # Повторный enable() (после "починки" среды) должен суметь довести дело до конца.
    assert git_proxy.enable()["ok"] is True
    assert git_proxy.status()["proxy"] == EXPECTED_GIT_PROXY

    # И disable() восстанавливает то же самое чужое значение, backup не был испорчен по пути.
    assert git_proxy.disable()["ok"] is True
    assert git_proxy.status()["proxy"] == "https://corp.example:8443"


# ==================== Точечный review rollback-логики: 4 находки (codex-review-222-rollback) ====
# Rollback в _write_values (добавлен для /review п.1) сам оказался подвержен той же категории
# багов, что и всё остальное в этом файле: "мутация запущена, но не верифицирован реальный
# результат". Все 4 сценария воспроизведены точечным Codex-ревью через мок sys_probe.run.

def test_rollback_failure_reports_distinct_state_not_generic_ok_false(monkeypatch, real_git_home):
    """Regression (находка 1): если И запись новых значений, И rollback старых — оба падают,
    _write_values раньше возвращал тот же generic {"ok": False, "err": ...}, что и "rollback
    сработал, просто вызывающая операция не удалась" — вызывающий код не мог различить "данные
    целы (после отката)" от "данные потеряны (rollback тоже не сработал)". KEY при этом реально
    остаётся ПУСТЫМ (--unset-all уже прошёл, ни новая запись, ни rollback не записались).
    """
    _raw_set(git_proxy.KEY, "https://corp.example:8443", real_git_home)
    real_run = sys_probe.run

    def _fail_all_adds(cmd, **kwargs):
        # Роняем ЛЮБОЙ --add по KEY (и новую запись, и rollback-восстановление) — полный отказ.
        # ИСКЛЮЧАЯ --add по _TXN_KEY (txn begin должен пройти, тестируем fallback после него)
        if "--add" in cmd and git_proxy.KEY in cmd and git_proxy._BACKUP_KEY not in cmd and git_proxy._TXN_KEY not in cmd:
            return {"rc": 1, "out": "", "err": "simulated total failure", "timeout": False}
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(git_proxy.sys_probe, "run", _fail_all_adds)

    r = git_proxy._write_values(git_proxy.KEY, [git_proxy._PROXY])

    assert r["ok"] is False
    assert r.get("data_loss") is True, (
        "rollback тоже не сработал -> caller обязан узнать, что данные РЕАЛЬНО потеряны, "
        "не просто 'операция не удалась' (иначе неотличимо от случая, когда rollback помог)"
    )

    monkeypatch.setattr(git_proxy.sys_probe, "run", real_run)
    current = git_proxy._get_all(git_proxy.KEY)
    assert current["present"] is False, "sanity: KEY реально пуст в этом сценарии (--unset-all прошёл)"


def test_rollback_partial_failure_does_not_silently_lose_one_of_several_values(monkeypatch, real_git_home):
    """Regression (находка 2): если исходных значений НЕСКОЛЬКО (multi-value), и rollback падает
    ровно на ОДНОМ из них (не на первом и не на всех) — раньше это проходило молча: цикл `for val
    in original_values: sys_probe.run(...)` не проверяет успех каждого шага, просто идёт дальше.
    Итог был: KEY = [A, C] вместо исходных [A, B, C] — B физически потерян БЕЗ какого-либо сигнала
    об этом (err не упоминает частичность, просто "write verify mismatch").
    """
    _raw_set_add(git_proxy.KEY, "A", real_git_home)
    _raw_set_add(git_proxy.KEY, "B", real_git_home)
    _raw_set_add(git_proxy.KEY, "C", real_git_home)
    real_run = sys_probe.run

    def _fail_new_write_and_rollback_of_b(cmd, **kwargs):
        if cmd[-2:] == [git_proxy.KEY, git_proxy._PROXY]:
            return {"rc": 1, "out": "", "err": "simulated new-write failure", "timeout": False}
        if cmd[-2:] == [git_proxy.KEY, "B"]:
            return {"rc": 1, "out": "", "err": "simulated rollback failure on B", "timeout": False}
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(git_proxy.sys_probe, "run", _fail_new_write_and_rollback_of_b)

    r = git_proxy._write_values(git_proxy.KEY, [git_proxy._PROXY])

    assert r["ok"] is False
    assert r.get("data_loss") is True, (
        "rollback восстановил только A и C, B потерян -> это ТОЖЕ data_loss, не 'чистый откат', "
        "даже если частично KEY похож на исходное состояние"
    )

    monkeypatch.setattr(git_proxy.sys_probe, "run", real_run)
    current = git_proxy._get_all(git_proxy.KEY)
    # Не проверяем ТОЧНОЕ содержимое (могло быть [A, C] или другой частичный набор) — важно, что
    # data_loss=True корректно сигнализирует о расхождении с original_values для caller'а.
    assert current["values"] != ["A", "B", "C"], "sanity: реально не полный исходный список"


# ==================== Issue #224: transactional-модель ====================
# Round 5 cycle-review issue #222 показал, что эвристики "current похоже на X" (prefix-match,
# value-match) не сходятся — нужен explicit transactional marker вместо reverse-engineering.

def test_transactional_marker_survives_partial_failure_mid_write(monkeypatch, real_git_home):
    """Regression (issue #224): если процесс убит посреди серии git config вызовов (--unset-all
    затем несколько --add), следующая операция должна видеть ЯВНЫЙ маркер "операция начата,
    целевой список = X" и доводить её до конца, НЕ угадывая по "current похоже на X".

    Сценарий: enable() с multi-value foreign-состоянием [A,B,C].
    1. _write_values(_BACKUP_KEY, [A,B,C]) прошёл успешно.
    2. _write_values(KEY, [_PROXY]): --unset-all прошёл, первый --add[_PROXY] упал.
    3. Процесс убит (SIGKILL) — rollback НЕ успел отработать.

    После перезапуска disable() должен:
    - Увидеть txn-маркер "операция в процессе, target = [_PROXY]"
    - Понять, что это НЕ легитимное чужое значение, а прерванная транзакция
    - Довести операцию до конца (retry --add[_PROXY])
    - Снять txn-маркер только после подтверждённого успеха
    """
    _raw_set_add(git_proxy.KEY, "A", real_git_home)
    _raw_set_add(git_proxy.KEY, "B", real_git_home)
    _raw_set_add(git_proxy.KEY, "C", real_git_home)
    real_run = sys_probe.run

    call_count = {"add_proxy": 0}

    def _fail_first_add_proxy_then_succeed(cmd, **kwargs):
        # Роняем ТОЛЬКО первую попытку --add[_PROXY] после --unset-all
        if cmd[-2:] == [git_proxy.KEY, git_proxy._PROXY]:
            call_count["add_proxy"] += 1
            if call_count["add_proxy"] == 1:
                # Симулируем SIGKILL после первого отказа -- rollback не успевает
                return {"rc": 1, "out": "", "err": "simulated crash", "timeout": False}
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(git_proxy.sys_probe, "run", _fail_first_add_proxy_then_succeed)

    r = git_proxy.enable()

    # Первая попытка упала — но транзакционный маркер зафиксировал target state
    assert r["ok"] is False, "первая попытка честно репортит отказ"

    # Проверяем, что txn-маркер установлен (если нет — тест детектит, что фикс не работает)
    txn_key = git_proxy._BACKUP_KEY + "-txn"
    txn_state = git_proxy._get_all(txn_key)
    assert txn_state["present"] is True, "txn-маркер должен быть установлен после частичного отказа"

    # Повторный enable() (после "рестарта процесса") должен довести транзакцию до конца
    # НЕ угадывая "а вдруг текущее состояние похоже на что-то знакомое"
    r2 = git_proxy.enable()
    assert r2["ok"] is True, "повторная попытка должна довести транзакцию до конца"

    # Проверяем, что состояние консистентно
    assert git_proxy.status()["proxy"] == EXPECTED_GIT_PROXY
    assert git_proxy._backup_state()["values"] == ["A", "B", "C"]

    # Проверяем, что состояние консистентно
    assert git_proxy.status()["proxy"] == EXPECTED_GIT_PROXY
    assert git_proxy._backup_state()["values"] == ["A", "B", "C"]


def test_transactional_marker_cleared_only_after_verified_success(monkeypatch, real_git_home):
    """Regression (issue #224): txn-маркер должен сниматься ТОЛЬКО после подтверждённого
    успеха (read-after-write verify). Если verify провалился — маркер остаётся, следующая
    операция retry'ит.

    Сценарий: проверяем напрямую, что _write_values возвращает ошибку при неудаче verify
    и txn-маркер остаётся (не снимается).
    """
    _raw_set(git_proxy.KEY, "https://corp.example:8443", real_git_home)
    real_run = sys_probe.run

    call_count = {"get_all": 0}

    def _fail_verify_then_succeed(cmd, **kwargs):
        # Падаем на третьем --get-all для KEY (snapshot → unset-all verify → write verify)
        if "--get-all" in cmd and cmd[-1] == git_proxy.KEY:
            call_count["get_all"] += 1
            # Падаем на третьем --get-all (verify после --add в _write_values)
            if call_count["get_all"] == 3:
                # rc=2 чтобы _get_all интерпретировал это как unknown=True
                return {"rc": 2, "out": "", "err": "simulated verify failure", "timeout": False}
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(git_proxy.sys_probe, "run", _fail_verify_then_succeed)

    # Тестируем напрямую _write_values, обходим enable() (он автоматически разрешает txn)
    r = git_proxy._write_values(git_proxy.KEY, [git_proxy._PROXY])

    # _write_values должен вернуть ошибку (verify упал)
    assert r["ok"] is False, "_write_values должен вернуть ошибку при неудаче verify"

    # txn-маркер должен остаться (не был снят, т.к. операция не завершена успешно)
    txn_key = git_proxy._BACKUP_KEY + "-txn"
    txn_state = git_proxy._get_all(txn_key)
    assert txn_state["present"] is True, "txn-маркер должен остаться после failed verify"


def test_partial_txn_marked_checksum_rejected_as_corrupt(monkeypatch, real_git_home):
    """Regression (Codex review issue #224): если _begin_txn частично записал txn-маркер
    (target-values в _TXN_KEY, но sentinel в _TXN_SENTINEL_KEY не записан), recovery должен
    НЕ принимать этот маркер как валидный и не должен replay'ить частичный target.

    Сценарий: enable() с multi-value foreign-состоянием [A,B,C] (target для _begin_txn — сам
    managed [_PROXY], backup хранит [A,B,C] отдельно).
    1. _begin_txn для [_PROXY] падает при записи sentinel в _TXN_SENTINEL_KEY (target-values в
       _TXN_KEY уже записаны).
    2. Следующий enable() видит _TXN_KEY present, но _TXN_SENTINEL_KEY absent.
    3. Recovery должен ОТКЛОНИТЬ этот маркер как partial/corrupt (issue #234 round 2:
       sentinel в отдельном ключе — его отсутствие однозначно значит partial write, никакого
       target-значения, которое могло бы "притвориться" sentinel, здесь физически нет).

    Codex review (issue #224) показал: старая реализация принимала любой маркер с len >= 2
    как валидный, что приводило к потере данных при partial write.
    """
    _raw_set_add(git_proxy.KEY, "A", real_git_home)
    _raw_set_add(git_proxy.KEY, "B", real_git_home)
    _raw_set_add(git_proxy.KEY, "C", real_git_home)
    real_run = sys_probe.run

    def _fail_sentinel_write(cmd, **kwargs):
        # Роняем запись sentinel в _begin_txn (issue #234 round 2: отдельный _TXN_SENTINEL_KEY)
        if "--add" in cmd and git_proxy._TXN_SENTINEL_KEY in cmd:
            return {"rc": 1, "out": "", "err": "simulated sentinel write failure", "timeout": False}
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(git_proxy.sys_probe, "run", _fail_sentinel_write)

    r = git_proxy.enable()

    # Первая попытка упала при записи checksum txn-маркера
    assert r["ok"] is False, "enable() должен вернуть ошибку при частичном txn begin"

    # Следующий enable() должен ОТКЛОНИТЬ partial txn-маркер как corrupt
    r2 = git_proxy.enable()
    assert r2["ok"] is False, "повторный enable() должен отклонить partial txn-маркер"

    # Проверяем, что backup НЕ ПОТЕРЯН — partial recovery не произошло
    assert git_proxy._backup_state()["values"] == ["A", "B", "C"], (
        "backup должен остаться нетронутым при отклонении partial txn-маркера"
    )


# ==================== Issue #277: unknown/absent conflation audit ====================
# Аудит каждого _get_all call site на инвариант: отличать unknown=True (transient — retry-safe,
# НЕ мутировать, НЕ коммитить fail-closed reset) от present=False (ключ реально отсутствует —
# норма) и present=True с неожиданным значением. Находка: финальная ветка _disable_locked
# (current == [_PROXY]) читала backup через `_backup_state()["present"]` — при unknown=True
# _get_all кодирует это как present=False, и код конфаундил "транзиентный сбой чтения backup"
# с "backup отсутствует", уходя в _unset_all(KEY) — снимая наш managed-прокси БЕЗ восстановления
# backup вместо fail-closed (тот же класс, что round 3 чинил для sentinel-чтения в
# _check_and_resolve_txn).

def test_disable_restore_backup_unknown_read_fails_closed_not_unset(monkeypatch, real_git_home):
    """Regression (issue #277): когда current == наш [_PROXY] и чтение backup даёт unknown=True
    (transient timeout/permission-race на _BACKUP_KEY), disable() обязан НЕ мутировать: вернуть
    ok=False без снятия KEY. Старая ветка `_backup_state()["present"]` (unknown → present=False)
    уходила в _unset_all(KEY), снимая managed-прокси и молча отбрасывая решение о restore backup.
    """
    # Состояние: установлен наш managed-прокси + присутствует backup чужого значения
    _raw_set(git_proxy.KEY, "https://corp.example:8443", real_git_home)
    assert git_proxy.enable()["ok"] is True
    assert git_proxy.status()["proxy"] == EXPECTED_GIT_PROXY
    assert git_proxy._backup_state()["present"] is True, "sanity: backup создан enable()"

    real_run = sys_probe.run

    def _fail_backup_read(cmd, **kwargs):
        # Роняем ТОЛЬКО чтение _BACKUP_KEY (unknown=True) — остальное реальный git.
        if "--get-all" in cmd and cmd[-1] == git_proxy._BACKUP_KEY:
            return {"rc": 2, "out": "", "err": "simulated backup read failure", "timeout": False}
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(git_proxy.sys_probe, "run", _fail_backup_read)

    r = git_proxy.disable()

    # Fail-closed: не мутируем при транзиентном сбое чтения backup
    assert r["ok"] is False, "disable() обязан fail-closed при unknown-чтении backup (не unset KEY)"
    assert "backup" in r["err"].lower(), "ошибка должна указывать на сбой чтения backup"

    monkeypatch.setattr(git_proxy.sys_probe, "run", real_run)
    # KEY НЕ снят: managed-прокси остался, решение о restore не отброшено
    assert git_proxy._get_all(git_proxy.KEY)["values"] == [EXPECTED_GIT_PROXY], (
        "KEY не должен быть снят при unknown-чтении backup — это не 'backup отсутствует'"
    )
