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



def test_disable_self_heals_orphan_backup_after_interrupted_restore(real_git_home):
    """Regression: если restore значения прошёл, но cleanup backup-ключа прерван (напр. процесс
    убит между двумя git config вызовами), backup-ключ раньше оставался мусором НАВСЕГДА — все
    последующие disable() видели current.values != [_PROXY] (уже restored) → ветка "чужое
    значение, не трогаем" → ok=True, но backup никогда не убирался. disable() должен
    самовосстанавливаться: если backup всё ещё существует и содержит РОВНО текущее значение KEY
    (= restore уже произошёл раньше, просто cleanup не завершился) — доубрать backup.
    """
    _raw_set(git_proxy.KEY, "https://corp.example:8443", real_git_home)
    assert git_proxy.enable()["ok"] is True  # backup = ["https://corp.example:8443"]

    # Симулируем restore, прошедший наполовину: KEY уже восстановлен на чужое значение, но
    # backup-ключ не подчищен (как будто disable() упал между restore и cleanup).
    assert git_proxy._write_values(git_proxy.KEY, ["https://corp.example:8443"])["ok"] is True
    backup_before = git_proxy._backup_state()
    assert backup_before["present"] is True, "backup ещё стоит (симулируем прерванный cleanup)"

    r = git_proxy.disable()

    assert r["ok"] is True
    assert git_proxy.status()["proxy"] == "https://corp.example:8443", "значение не тронуто"
    assert git_proxy._backup_state()["present"] is False, (
        "orphan backup-ключ должен быть самостоятельно убран, а не остаться мусором навсегда"
    )


# ============================== Read-after-write verify ==============================

def test_enable_verifies_write_landed(real_git_home):
    r = git_proxy.enable()
    assert r["ok"] is True
    # Read-after-write: реальное содержимое файла, не просто rc от git.
    s = git_proxy.status()
    assert s["proxy"] == EXPECTED_GIT_PROXY
    assert s["present"] is True


def test_disable_verifies_key_actually_removed(real_git_home):
    assert git_proxy.enable()["ok"] is True

    r = git_proxy.disable()

    assert r["ok"] is True
    s = git_proxy.status()
    assert s["present"] is False, "read-after-write verify: ключ реально отсутствует, не просто rc=0"


# ============================== Базовые / round-trip (не регрессировать) ==============================

def test_enable_writes_socks5_url(real_git_home):
    r = git_proxy.enable()
    assert r["ok"] is True
    assert r["proxy"] == EXPECTED_GIT_PROXY
    assert git_proxy.status()["proxy"] == EXPECTED_GIT_PROXY


def test_disable_idempotent_when_key_absent(real_git_home):
    r = git_proxy.disable()
    assert r["ok"] is True


def test_disable_preserves_foreign_value_set_after_install(real_git_home):
    """disable() НЕ трогает чужой прокси, если он появился ПОСЛЕ нашего managed-значения."""
    _raw_set(git_proxy.KEY, "https://corp.example:8443", real_git_home)

    r = git_proxy.disable()

    assert r["ok"] is True
    assert git_proxy.status()["proxy"] == "https://corp.example:8443"


def test_disable_removes_own_managed_value(real_git_home):
    assert git_proxy.enable()["ok"] is True

    r = git_proxy.disable()

    assert r["ok"] is True
    assert git_proxy.status()["present"] is False


def test_round_trip_enable_disable_status(real_git_home):
    assert git_proxy.status()["enabled"] is False
    assert git_proxy.enable()["ok"] is True
    assert git_proxy.status()["enabled"] is True
    assert git_proxy.status()["proxy"] == EXPECTED_GIT_PROXY
    assert git_proxy.disable()["ok"] is True
    assert git_proxy.status()["enabled"] is False


def test_full_lifecycle_preserves_pre_existing_foreign_proxy(real_git_home):
    """install->uninstall lifecycle возвращает ИСХОДНЫЙ чужой прокси (created/overwrote-канон)."""
    _raw_set(git_proxy.KEY, "https://corp.example:8443", real_git_home)

    assert git_proxy.enable()["ok"] is True
    assert git_proxy.status()["proxy"] == EXPECTED_GIT_PROXY

    assert git_proxy.disable()["ok"] is True
    assert git_proxy.status()["proxy"] == "https://corp.example:8443", (
        "uninstall обязан вернуть исходный чужой прокси"
    )
    backup_check = subprocess.run(
        ["git", "config", "--global", "--get", git_proxy._BACKUP_KEY],
        env=dict(os.environ, HOME=str(real_git_home)), capture_output=True, text=True, check=False,
    )
    assert backup_check.returncode == 1, "backup-ключ убран после restore (не остаётся мусором)"


def test_full_lifecycle_created_from_scratch_removes_cleanly(real_git_home):
    assert git_proxy.enable()["ok"] is True
    assert git_proxy.status()["proxy"] == EXPECTED_GIT_PROXY

    assert git_proxy.disable()["ok"] is True
    assert git_proxy.status()["present"] is False


# ============ Mock-покрытие unknown/non-absent-rc путей (не воспроизвести реальным git) ============
# permission denied / malformed config — состояния окружения, которые нельзя детерминированно
# воссоздать через реальный git config в тестах; здесь оправдан mock sys_probe.run.

def test_status_reports_unknown_on_nonzero_non_absent_rc(monkeypatch):
    """Regression (Codex cycle-review PR #221): status() должен различать rc=1 (ключа нет,
    задокументированное поведение git config --get-all) от других ненулевых rc (реальная ошибка —
    permission denied, malformed config, отсутствующий git). Раньше любой rc с пустым out →
    enabled=False, маскируя реальный сбой как "прокси выключен" — disable() затем врал ok=True
    без проверки.
    """
    monkeypatch.setattr(git_proxy.sys_probe, "run",
                        lambda cmd, **k: {"rc": 128, "out": "", "err": "fatal: bad config"})

    s = git_proxy.status()

    assert s["status"] == "unknown", "rc=128 (реальная ошибка) — unknown, НЕ enabled=False"


def test_status_enabled_false_on_documented_absent_rc1(monkeypatch):
    """Контроль: rc=1 + пустой out — задокументированное «ключа нет», enabled=False (не unknown)."""
    monkeypatch.setattr(git_proxy.sys_probe, "run",
                        lambda cmd, **k: {"rc": 1, "out": "", "err": ""})

    s = git_proxy.status()

    assert s.get("status") != "unknown"
    assert s["enabled"] is False


def test_disable_fails_closed_when_status_unknown(monkeypatch):
    """disable() при status()==unknown (реальная ошибка git config) возвращает ok=False —
    НЕ маскирует сбой как успешную очистку (cmd_uninstall полагается на ok для fail-closed rc)."""
    monkeypatch.setattr(git_proxy.sys_probe, "run",
                        lambda cmd, **k: {"rc": 128, "out": "", "err": "fatal: bad config"})

    r = git_proxy.disable()

    assert r["ok"] is False


# ==================== enable() partial-failure: backup обновлён, запись KEY падает (/review) ====
# ==== disable() self-healing недостижима, когда KEY absent (не просто "чужое значение") ====

def test_disable_self_heals_when_key_absent_but_backup_matches_history(real_git_home):
    """Regression (находка 4, самая серьёзная): если предыдущий enable() обновил backup (на B),
    но затем запись нового managed-значения в KEY УПАЛА и rollback ТОЖЕ не сработал — KEY становится
    absent (present=False), а backup остаётся [B]. Старый disable() на строке "if not
    current['present']: return {'ok': True}" срабатывает РАНЬШЕ self-healing проверки (которая
    сравнивает backup со значением КОГДА КЛЮЧ ПРИСУТСТВУЕТ) — backup остаётся orphan-мусором
    НАВСЕГДА, а B потерян безвозвратно (никогда не восстановлен в KEY).

    disable() должен: если KEY absent, но backup present — восстановить backup в KEY (данные не
    должны "телепортироваться" в никуда только потому что KEY оказался пуст в момент запроса).
    """
    _raw_set(git_proxy.KEY, "https://corp-B.example:9443", real_git_home)
    assert git_proxy.enable()["ok"] is True  # backup = ["https://corp-B.example:9443"]

    # Симулируем "и новая запись, и rollback упали" -> KEY становится пустым, backup остаётся.
    assert git_proxy._unset_all(git_proxy.KEY)["ok"] is True
    assert git_proxy._get_all(git_proxy.KEY)["present"] is False
    assert git_proxy._backup_state()["values"] == ["https://corp-B.example:9443"]

    r = git_proxy.disable()

    assert r["ok"] is True
    restored = git_proxy.status()
    assert restored["proxy"] == "https://corp-B.example:9443", (
        "backup обязан восстановиться в KEY, даже если KEY был ПОЛНОСТЬЮ absent (не просто чужой) "
        "-- иначе self-healing недостижима именно в этом (реальном, воспроизведённом) сценарии"
    )
    assert git_proxy._backup_state()["present"] is False, "backup убран после успешного восстановления"
# ==== Round 5 (codex-review-222-round5): partial restore внутри self-healing застревает навсегда ====

def test_disable_self_heal_partial_restore_does_not_get_stuck_permanently(monkeypatch, real_git_home):
    """Regression (round 5, confirmed воспроизведённый баг): self-healing-when-absent ветка вызывает
    `_write_values(KEY, backup["values"])`. Если ЭТА запись частично падает (multi-value backup
    [A,B,C], --add B падает после успешного --add A) — `_write_values`'s собственный rollback
    целится в PRE-CALL snapshot KEY (который был absent), а не в backup — rollback с пустым
    original_values не убирает уже записанное A. KEY застревает на ["A"] (не absent, не [_PROXY],
    не полный backup) — ни self-healing-when-absent (KEY уже present), ни self-healing-orphan
    (backup=[A,B,C] != current=[A], строгое равенство ложно) больше не срабатывают. Следующие
    disable() навсегда классифицируют ["A"] как "чужое значение, не трогаем" -- backup остаётся
    orphan-мусором, B и C потеряны безвозвратно.

    Фикс: self-healing распознаёт "current — частично восстановленный backup" (а не просто "backup
    == current") и ПОВТОРЯЕТ restore вместо капитуляции в "чужое, не трогаем".
    """
    _raw_set_add(git_proxy.KEY, "A", real_git_home)
    _raw_set_add(git_proxy.KEY, "B", real_git_home)
    _raw_set_add(git_proxy.KEY, "C", real_git_home)
    assert git_proxy.enable()["ok"] is True  # backup = [A, B, C]

    # Симулируем крэш: KEY снят целиком (как будто процесс убит после _unset_all, до восстановления).
    assert git_proxy._unset_all(git_proxy.KEY)["ok"] is True
    assert git_proxy._get_all(git_proxy.KEY)["present"] is False
    assert git_proxy._backup_state()["values"] == ["A", "B", "C"]

    real_run = sys_probe.run

    def _fail_add_b_once(cmd, **kwargs):
        if cmd[-2:] == [git_proxy.KEY, "B"]:
            monkeypatch.setattr(git_proxy.sys_probe, "run", real_run)  # только один раз
            return {"rc": 1, "out": "", "err": "simulated failure on B", "timeout": False}
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(git_proxy.sys_probe, "run", _fail_add_b_once)

    r1 = git_proxy.disable()  # self-healing-when-absent пытается restore, частично падает на B
    assert r1["ok"] is False, "частичный restore внутри self-healing -> честный отказ, не ok=True"

    # KEY теперь в частично-восстановленном состоянии (не absent, не полный backup).
    stuck = git_proxy._get_all(git_proxy.KEY)
    assert stuck["present"] is True
    assert stuck["values"] != ["A", "B", "C"], "sanity: реально частичное состояние, не полный backup"

    # Повторный disable() (среда уже "починилась", мок был one-shot) ДОЛЖЕН довести дело до конца,
    # а не классифицировать частично-восстановленный backup как "чужое значение, никогда не трогаем".
    r2 = git_proxy.disable()
    assert r2["ok"] is True, "повторный disable() обязан суметь довершить прерванный restore"

    final = git_proxy.status()
    assert final["values"] == ["A", "B", "C"], (
        "backup должен быть полностью восстановлен, ничего не потеряно безвозвратно"
    )
    assert git_proxy._backup_state()["present"] is False, "backup убран после успешного восстановления"

