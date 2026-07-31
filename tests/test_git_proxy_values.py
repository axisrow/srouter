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
