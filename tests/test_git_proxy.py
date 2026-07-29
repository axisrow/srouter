"""ТДД-тесты git_proxy: строгая provenance-модель (issue #222, verify-don't-guess).

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


def test_default_proxy_is_socks5_xray():
    """Regression #130: git-прокси обязан быть SOCKS5 (xray 10808), НЕ HTTP (privoxy 8118)."""
    from dashboard_common import SOCKS_PROXY_URL
    assert SOCKS_PROXY_URL == EXPECTED_GIT_PROXY
    assert git_proxy._PROXY == EXPECTED_GIT_PROXY


# ============================== 1. Presence vs truthy (empty value) ==============================

def test_empirical_empty_value_has_rc0_not_rc1(real_git_home):
    """Verify-don't-guess: подтверждаем сырое поведение git ПЕРЕД тем как полагаться на него."""
    _raw_set(git_proxy.KEY, "", real_git_home)
    r = subprocess.run(
        ["git", "config", "--global", "--get", git_proxy.KEY],
        env=dict(os.environ, HOME=str(real_git_home)), capture_output=True, text=True, check=False,
    )
    assert r.returncode == 0, "пустое значение -> rc=0, НЕ rc=1 (ключ присутствует)"
    assert r.stdout.strip() == ""


def test_status_reports_present_when_value_empty(real_git_home):
    """Regression (issue #222 finding 1): пустая строка — валидный override, ключ ПРИСУТСТВУЕТ.

    bool(out) не может различить "ключа нет" (rc=1) от "ключ есть, значение пустое" (rc=0, out="").
    status() обязан репортить presence отдельно от truthy-значения.
    """
    _raw_set(git_proxy.KEY, "", real_git_home)

    s = git_proxy.status()

    assert s["present"] is True, "пустое значение всё ещё присутствующий ключ, не 'ключа нет'"
    assert s["proxy"] == ""
    assert s["enabled"] is False, "пустое значение != наш managed _PROXY, enabled=False корректно"


def test_status_reports_absent_when_key_never_set(real_git_home):
    s = git_proxy.status()
    assert s["present"] is False
    assert s["proxy"] == ""
    assert s["enabled"] is False


def test_disable_does_not_treat_empty_foreign_value_as_absent(real_git_home):
    """Пустой чужой override (--get даёт rc=0/out="") НЕ должен быть перезаписан/удалён при disable —
    это валидное чужое значение (fail-closed value-match: "" != _PROXY, не трогаем)."""
    _raw_set(git_proxy.KEY, "", real_git_home)

    r = git_proxy.disable()

    assert r["ok"] is True
    assert git_proxy.status()["present"] is True
    assert git_proxy.status()["proxy"] == "", "пустой чужой override сохранён, не превращён в absent"


# ============================== 2. Backup устаревает между поколениями ==============================

def test_backup_updates_on_new_foreign_value_between_generations(real_git_home):
    """Regression (issue #222 finding 2): A -> install -> manual B -> uninstall -> install -> uninstall
    должен вернуть B, а не устаревший A.

    Старый guard "backup отсутствует -> бэкапим" бэкапит только ПЕРВОЕ чужое значение (A) и никогда
    не обновляет его на B, потому что backup к этому моменту уже существует (= A).
    """
    _raw_set(git_proxy.KEY, "https://corp-A.example:8443", real_git_home)

    assert git_proxy.enable()["ok"] is True
    assert git_proxy.status()["proxy"] == EXPECTED_GIT_PROXY

    # Пользователь вручную меняет прокси на B (между generations нашего managed-состояния).
    _raw_set(git_proxy.KEY, "https://corp-B.example:9443", real_git_home)

    assert git_proxy.disable()["ok"] is True, "текущее значение (B) чужое -> не трогаем (value-match)"
    assert git_proxy.status()["proxy"] == "https://corp-B.example:9443"

    # Второй install: B — текущее чужое значение, ДОЛЖНО стать новым backup (не A).
    assert git_proxy.enable()["ok"] is True
    assert git_proxy.status()["proxy"] == EXPECTED_GIT_PROXY

    assert git_proxy.disable()["ok"] is True

    assert git_proxy.status()["proxy"] == "https://corp-B.example:9443", (
        "backup должен был обновиться на B при втором enable(), а не остаться A"
    )


def test_backup_survives_repeated_idempotent_enable(real_git_home):
    """Повторный enable() без смены чужого значения между вызовами НЕ должен затирать backup
    нашим же managed-значением (идемпотентный install)."""
    _raw_set(git_proxy.KEY, "https://corp.example:8443", real_git_home)

    assert git_proxy.enable()["ok"] is True
    assert git_proxy.enable()["ok"] is True  # повторный install, идемпотентно

    assert git_proxy.disable()["ok"] is True
    assert git_proxy.status()["proxy"] == "https://corp.example:8443"


# ============================== 3. multi-value rc=5 ==============================

def test_empirical_unset_on_multivalue_key_returns_rc5_without_removing(real_git_home):
    """Verify-don't-guess: подтверждаем эмпирически двусмысленность rc=5 ПЕРЕД тем как её обрабатывать."""
    _raw_set_add(git_proxy.KEY, "val1", real_git_home)
    _raw_set_add(git_proxy.KEY, "val2", real_git_home)

    r = subprocess.run(
        ["git", "config", "--global", "--unset", git_proxy.KEY],
        env=dict(os.environ, HOME=str(real_git_home)), capture_output=True, text=True, check=False,
    )
    assert r.returncode == 5, "multi-value --unset -> rc=5, та же цифра что и 'ключа нет'"

    remaining = subprocess.run(
        ["git", "config", "--global", "--get-all", git_proxy.KEY],
        env=dict(os.environ, HOME=str(real_git_home)), capture_output=True, text=True, check=False,
    )
    assert remaining.stdout.split() == ["val1", "val2"], "мутация ОТКАЗАЛА, оба значения на месте"


def test_status_detects_multivalued_key(real_git_home):
    """status() обязан видеть multi-value key и не притворяться, что там одно скалярное значение."""
    _raw_set_add(git_proxy.KEY, "https://corp1.example:8443", real_git_home)
    _raw_set_add(git_proxy.KEY, "https://corp2.example:9443", real_git_home)

    s = git_proxy.status()

    assert s["present"] is True
    assert s.get("multi") is True
    assert s["values"] == ["https://corp1.example:8443", "https://corp2.example:9443"]


def test_disable_on_multivalued_foreign_key_does_not_report_false_success(real_git_home):
    """disable() не должен врать ok=True если под нашим KEY многозначный чужой конфиг —
    fail-closed: не наше значение (текущее не совпадает с _PROXY) -> не трогаем, ok=True,
    но состояние ДОЛЖНО остаться нетронутым (verify), не частично отмутированным."""
    _raw_set_add(git_proxy.KEY, "https://corp1.example:8443", real_git_home)
    _raw_set_add(git_proxy.KEY, "https://corp2.example:9443", real_git_home)

    r = git_proxy.disable()

    assert r["ok"] is True
    s = git_proxy.status()
    assert s["values"] == ["https://corp1.example:8443", "https://corp2.example:9443"], (
        "multi-value чужой конфиг остаётся полностью нетронутым"
    )


def test_disable_removes_own_value_verified_when_key_was_multivalued_before_install(real_git_home):
    """enable() перезаписывает multi-value чужой конфиг единственным managed-значением
    (git config KEY VAL без --add схлопывает на одно значение); backup хранит ИСХОДНЫЙ список.
    disable() обязан восстановить весь список, не только последнее значение."""
    _raw_set_add(git_proxy.KEY, "https://corp1.example:8443", real_git_home)
    _raw_set_add(git_proxy.KEY, "https://corp2.example:9443", real_git_home)

    assert git_proxy.enable()["ok"] is True
    s = git_proxy.status()
    assert s["multi"] is False
    assert s["proxy"] == EXPECTED_GIT_PROXY

    assert git_proxy.disable()["ok"] is True

    restored = git_proxy.status()
    assert restored["values"] == ["https://corp1.example:8443", "https://corp2.example:9443"], (
        "restore обязан вернуть ВЕСЬ исходный multi-value список, не одно значение"
    )


# ==================== 4. Пустые значения на краях multi-value списка (cycle-review round 1) ====================
# Codex adversarial review PR #221 round 3 (issue #222 cycle-review): sys_probe.run's `.strip()`
# (sys_probe.py:41, `proc.stdout.strip()`) применяется к сырому git-выводу ДО того, как git_proxy
# его парсит. `--get-all` без `-z` разделяет значения `\n` — если крайнее (первое/последнее)
# значение в списке пустая строка, ведущий/замыкающий `\n` съедается вместе с ним при `.strip()`,
# и `_get_all` теряет это значение молча (тот же класс бага, что finding 1 issue #222, только на
# уровне multi-value списка, а не одиночного `--get`).

def test_empirical_strip_eats_leading_empty_value_in_multivalue_list(real_git_home):
    """Verify-don't-guess: подтверждаем сырое поведение sys_probe.run ПЕРЕД тем как полагаться на него."""
    _raw_set_add(git_proxy.KEY, "", real_git_home)
    _raw_set_add(git_proxy.KEY, "A", real_git_home)
    _raw_set_add(git_proxy.KEY, "B", real_git_home)

    raw = subprocess.run(
        ["git", "config", "--global", "--get-all", git_proxy.KEY],
        env=dict(os.environ, HOME=str(real_git_home)), capture_output=True, text=True, check=False,
    )
    assert raw.stdout == "\nA\nB\n", "сырой git-вывод: ведущий '\\n' от пустого первого значения"

    r = sys_probe.run([git_proxy.GIT, "config", "--global", "--get-all", git_proxy.KEY], timeout=4)
    assert r["out"] == "A\nB", ".strip() съедает ведущий '\\n' вместе с пустым значением"


def test_get_all_preserves_leading_empty_value(real_git_home):
    """Regression: пустое значение ПЕРВЫМ в multi-value списке не должно теряться."""
    _raw_set_add(git_proxy.KEY, "", real_git_home)
    _raw_set_add(git_proxy.KEY, "A", real_git_home)
    _raw_set_add(git_proxy.KEY, "B", real_git_home)

    r = git_proxy._get_all(git_proxy.KEY)

    assert r["present"] is True
    assert r["values"] == ["", "A", "B"], "ведущее пустое значение должно сохраниться"


def test_get_all_preserves_trailing_empty_value(real_git_home):
    """Regression: пустое значение ПОСЛЕДНИМ в multi-value списке не должно теряться."""
    _raw_set_add(git_proxy.KEY, "A", real_git_home)
    _raw_set_add(git_proxy.KEY, "B", real_git_home)
    _raw_set_add(git_proxy.KEY, "", real_git_home)

    r = git_proxy._get_all(git_proxy.KEY)

    assert r["present"] is True
    assert r["values"] == ["A", "B", ""], "замыкающее пустое значение должно сохраниться"


def test_full_lifecycle_preserves_leading_empty_foreign_value(real_git_home):
    """Полный цикл install->uninstall не должен терять исходное чужое пустое значение,
    стоявшее первым в multi-value списке (Codex round 1, confirmed data-loss bug)."""
    _raw_set_add(git_proxy.KEY, "", real_git_home)
    _raw_set_add(git_proxy.KEY, "A", real_git_home)

    assert git_proxy.enable()["ok"] is True
    assert git_proxy.status()["proxy"] == EXPECTED_GIT_PROXY

    assert git_proxy.disable()["ok"] is True

    restored = git_proxy.status()
    assert restored["values"] == ["", "A"], (
        "restore обязан вернуть исходный список включая пустое значение, не терять его"
    )


def test_get_all_multiline_single_value_not_confused_with_multiple_values(real_git_home):
    """Regression (Codex round 1, наблюдение B): одно значение с embedded '\\n' НЕ должно
    читаться как несколько отдельных значений — `-z` разделяет РЕАЛЬНЫЕ записи по NUL,
    embedded '\\n' внутри значения остаётся частью значения."""
    _raw_set_add(git_proxy.KEY, "line1\nline2", real_git_home)

    r = git_proxy._get_all(git_proxy.KEY)

    assert r["present"] is True
    assert r["values"] == ["line1\nline2"], "embedded newline — часть ОДНОГО значения"
    assert r["multi"] is False, "одно значение с переносом строки — не multi-value"


# ========== 5. Orphan backup-ключ при прерванном restore (Codex round 1, наблюдение C) ==========

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
        if "--add" in cmd and git_proxy.KEY in cmd and git_proxy._BACKUP_KEY not in cmd:
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
