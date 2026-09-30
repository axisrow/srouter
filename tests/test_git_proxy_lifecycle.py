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
    assert git_proxy.enable(force=True)["ok"] is True  # backup = ["https://corp.example:8443"]

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

    assert git_proxy.enable(force=True)["ok"] is True
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
    assert git_proxy.enable(force=True)["ok"] is True  # backup = ["https://corp-B.example:9443"]

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
    assert git_proxy.enable(force=True)["ok"] is True  # backup = [A, B, C]

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


# ============================ effective_proxy: композер слоёв (2026-09-30) ============================
# Мотивация: git резолвит прокси по ЛЕСТНИЦЕ слоёв (local urlmatch > global urlmatch > global
# generic http.proxy/https.proxy > env), а status() читал только один слой — doctor рапортовал
# «github идёт напрямую», пока бесхозный глобальный http.proxy=8118 реально проксировал git
# (живой факт машины 2026-09-30). effective_proxy() вычисляет ЭФФЕКТИВНОЕ значение.

@pytest.fixture
def no_proxy_env(monkeypatch):
    """Убрать ambient env-прокси (канон ambient-env-poisons-env-parameterized-stubs):
    effective_proxy читает env последним слоем — shell-переменные хоста ломали бы лестницу."""
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


def _raw_local_set(repo, key, val):
    subprocess.run(
        ["git", "-C", str(repo), "config", "--local", key, val],
        env=dict(os.environ), capture_output=True, text=True, check=True,
    )


@pytest.fixture
def tmp_repo(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, capture_output=True)
    return tmp_path


def test_effective_local_urlmatch_beats_global(no_proxy_env, real_git_home, tmp_repo):
    """Пустой local urlmatch = ОСОЗНАННЫЙ direct в этом репо — побеждает global managed-ключ."""
    assert git_proxy.enable(force=True)["ok"] is True
    _raw_local_set(tmp_repo, git_proxy.KEY, "")
    eff = git_proxy.effective_proxy(repo=tmp_repo)
    assert eff["layer"] == "local-urlmatch"
    assert eff["proxy"] == "", "пустой local override = direct, а не socks"


def test_effective_global_urlmatch_beats_generic(no_proxy_env, real_git_home):
    """Managed urlmatch-ключ побеждает бесхозный общий http.proxy (приоритет git)."""
    _raw_set_add("http.proxy", "http://127.0.0.1:8118", real_git_home)
    assert git_proxy.enable(force=True)["ok"] is True
    nonrepo = real_git_home / "not-a-repo"
    nonrepo.mkdir()  # существующий каталог вне репо (несуществующий дал бы честный unknown)
    eff = git_proxy.effective_proxy(repo=nonrepo)  # вне репо — локальный слой отсутствует
    assert eff["layer"] == "global-urlmatch"
    assert eff["proxy"] == EXPECTED_GIT_PROXY


def test_effective_generic_fires_when_urlmatch_absent(no_proxy_env, real_git_home):
    """БЕЗ urlmatch-ключа бесхозный глобальный http.proxy=8118 реально проксирует git — слой
    global-generic. Ровно живое состояние машины 2026-09-30, которое doctor называл «напрямую»."""
    _raw_set_add("https.proxy", "http://127.0.0.1:8118", real_git_home)
    eff = git_proxy.effective_proxy()
    assert eff["layer"] == "global-generic"
    assert eff["proxy"] == "http://127.0.0.1:8118"


def test_effective_env_is_last_layer(no_proxy_env, real_git_home):
    """Env-прокси работает только при пустом git-config (нижняя ступень лестницы)."""
    no_proxy_env.setenv("HTTPS_PROXY", "http://wprp.example:3128")
    eff = git_proxy.effective_proxy()
    assert eff["layer"] == "env"
    assert eff["proxy"] == "http://wprp.example:3128"


def test_effective_direct_when_nothing_set(no_proxy_env, real_git_home, tmp_repo):
    eff = git_proxy.effective_proxy(repo=tmp_repo)
    assert eff["layer"] == "direct"
    assert eff["proxy"] == ""


def test_effective_foreign_urlmatch_passthrough(no_proxy_env, real_git_home):
    _raw_set(git_proxy.KEY, "http://corp.example:8080", real_git_home)
    eff = git_proxy.effective_proxy()
    assert eff["layer"] == "global-urlmatch"
    assert eff["proxy"] == "http://corp.example:8080"


def test_effective_never_raises(no_proxy_env, real_git_home, monkeypatch):
    """Мусор от status()/env → layer в {"unknown", "direct", ...}, не бросает (probe-канон)."""
    monkeypatch.setattr(git_proxy, "status", lambda: None)
    eff = git_proxy.effective_proxy()
    assert isinstance(eff, dict) and "layer" in eff


# ============================ stray_global: бесхозные глобальные ключи ============================

def test_stray_global_absent(no_proxy_env, real_git_home):
    s = git_proxy.stray_global()
    assert s["http"]["present"] is False and s["https"]["present"] is False


def test_stray_global_present(no_proxy_env, real_git_home):
    _raw_set_add("http.proxy", "http://127.0.0.1:8118", real_git_home)
    _raw_set_add("https.proxy", "http://127.0.0.1:8118", real_git_home)
    s = git_proxy.stray_global()
    assert s["http"]["values"] == ["http://127.0.0.1:8118"]
    assert s["https"]["values"] == ["http://127.0.0.1:8118"]


def test_stray_global_multi_value(no_proxy_env, real_git_home):
    _raw_set_add("http.proxy", "http://a:1", real_git_home)
    _raw_set_add("http.proxy", "http://b:2", real_git_home)
    s = git_proxy.stray_global()
    assert s["http"]["multi"] is True
    assert s["http"]["values"] == ["http://a:1", "http://b:2"]


# ============================ local_override: пер-репо .git/config ============================

def test_local_override_present_empty_value(tmp_repo):
    _raw_local_set(tmp_repo, git_proxy.KEY, "")
    lo = git_proxy.local_override(repo=tmp_repo)
    assert lo["present"] is True
    assert lo["values"] == [""]


def test_local_override_absent_clean_repo(tmp_repo):
    assert git_proxy.local_override(repo=tmp_repo)["present"] is False


def test_local_override_outside_repo_is_absent_not_unknown(tmp_path):
    """Вне репо `git config --local` даёт rc=128 — это «слоя нет», а не сбой чтения."""
    assert git_proxy.local_override(repo=tmp_path)["present"] is False
    assert git_proxy.local_override(repo=tmp_path)["unknown"] is False


def test_effective_multi_value_last_wins_local(no_proxy_env, real_git_home, tmp_repo):
    """Code-review #386: git при multi-value одного ключа берёт ПОСЛЕДНЕЕ значение (last-wins),
    не первое. ["", "socks://x:1"] → эффективно socks, а не ложный direct."""
    subprocess.run(["git", "-C", str(tmp_repo), "config", "--local", "--add", git_proxy.KEY, ""],
                   check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_repo), "config", "--local", "--add", git_proxy.KEY,
                    "socks5h://x.example:1080"], check=True, capture_output=True)
    eff = git_proxy.effective_proxy(repo=tmp_repo)
    assert eff["layer"] == "local-urlmatch"
    assert eff["proxy"] == "socks5h://x.example:1080"


def test_effective_multi_value_last_wins_generic(no_proxy_env, real_git_home):
    """Last-wins и для бесхозного generic-ключа: последний URL побеждает."""
    _raw_set_add("http.proxy", "http://a.example:1", real_git_home)
    _raw_set_add("http.proxy", "http://b.example:2", real_git_home)
    eff = git_proxy.effective_proxy()
    assert eff["proxy"] == "http://b.example:2"


def test_local_override_rc128_fatal_is_unknown(no_proxy_env, real_git_home, monkeypatch, tmp_path):
    """Code-review #386: rc=128 — не только «вне репо», но и фатальные ошибки (битый config,
    permission denied). Только stderr «not a git repositor*/not in a git dir» = absent; прочий
    rc=128 — unknown (fail-closed: нечитаемый конфиг не превращается в «direct»)."""
    real = git_proxy.sys_probe.run

    def _fatal(cmd, **kwargs):
        return {"rc": 128, "out": "", "err": "fatal: bad config line 1 in .git/config",
                "timeout": False}

    monkeypatch.setattr(git_proxy.sys_probe, "run", _fatal)
    lo = git_proxy.local_override(repo=tmp_path)
    assert lo["unknown"] is True and lo["present"] is False

