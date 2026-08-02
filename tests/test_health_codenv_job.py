"""ТДД-тесты issue #250: doctor детектит МЁРТВЫЙ codenv launchd-job по первоисточнику.

Инцидент 2026-07-30: job `com.srouter.codenv` загружен в launchd, plist с диска УДАЛЁН, job живёт
осиротевшим и падает с `last exit code = 127` (ProgramArguments указывает в стёртый AO-worktree
`.ao/data/worktrees/srouter/srouter-117/launchagents/srouter-codex-env.sh`). 1419 падений подряд —
doctor молчал, потому что `_codenv_managed()` читал ТОЛЬКО артефакт (plist-файл + маркер), а не
состояние job'а (`state` / `last exit code` / `runs` / `ProgramArguments`).

Канон: verify-dont-guess (loaded-job + exit-code — первоисточник, plist — артефакт),
noisy-log-better-than-no-log (1419 падений в тишине), fail-closed-proxy-down (без codenv Codex
идёт напрямую → утечка реального IP за GFW), srouter-critical-infra-24-7.
"""
import health


# ============================ фикстуры: реалистичный вывод `launchctl print` =====================
#
# Формат взят с живой машины (`launchctl print gui/501/com.srouter.dashboard`) — табы, `key = value`,
# блок `arguments = { ... }` со строками-аргументами по одной на строку. НЕ выдуманный формат.

def _print_out(*, path="/Users/u/Library/LaunchAgents/com.srouter.codenv.plist",
               state="running", runs=3, last_exit_code=0,
               script="/Users/u/Projects/srouter/launchagents/srouter-codex-env.sh"):
    exit_line = f"\tlast exit code = {last_exit_code}\n" if last_exit_code is not None else ""
    return (
        f"gui/501/{health._CODENV_LABEL} = {{\n"
        f"\tactive count = 0\n"
        f"\tpath = {path}\n"
        f"\ttype = LaunchAgent\n"
        f"\tstate = {state}\n"
        f"\n"
        f"\tprogram = /bin/sh\n"
        f"\targuments = {{\n"
        f"\t\t/bin/sh\n"
        f"\t\t{script}\n"
        f"\t}}\n"
        f"\n"
        f"\tstdout path = /tmp/codenv.out\n"
        f"\tstderr path = /tmp/codenv.err\n"
        f"\tdomain = gui/501 [100004]\n"
        f"\truns = {runs}\n"
        f"{exit_line}"
        f"}}\n"
    )


def _runner(out, *, rc=0, timeout=False):
    return lambda cmd, tmo=5, **kw: {"rc": rc, "out": out, "err": "", "timeout": timeout}


def _codenv_env(monkeypatch, tmp_path, *, plist_exists=True, stderr_tail=""):
    """Изолируем HOME (plist-файл) и /tmp/codenv.err-хвост от реальной машины."""
    plist = tmp_path / "Library" / "LaunchAgents" / f"{health._CODENV_LABEL}.plist"
    plist.parent.mkdir(parents=True, exist_ok=True)
    if plist_exists:
        plist.write_text(health._CODENV_MARKER, encoding="utf-8")
    monkeypatch.setattr(health.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(health, "_codenv_stderr_tail", lambda path=None, **kw: stderr_tail)
    return plist


# ============================ 1. job загружен + last exit code = 127 → down =====================

def test_codenv_down_when_last_exit_code_nonzero(monkeypatch, tmp_path):
    """job загружен + `last exit code = 127` → down; detail содержит exit-код и путь из stderr.

    Ровно инцидент #250: RunAtLoad+StartInterval=300 перезапускают скрипт каждые 5 мин, он падает
    с 127 (`/bin/sh: ...: No such file or directory`), env в gui-домене не обновляется. После ребута
    Codex останется без SOCKS5 МОЛЧА → прямой трафик за GFW (fail-closed-proxy-down).
    """
    _codenv_env(monkeypatch, tmp_path, stderr_tail=(
        "/bin/sh: /Users/u/.ao/data/worktrees/srouter/srouter-117/launchagents/"
        "srouter-codex-env.sh: No such file or directory"))
    runner = _runner(_print_out(state="not running", runs=1419, last_exit_code=127))
    res = health._codenv_job_check(runner=runner)
    assert res["status"] == "down", f"exit 127 → down; got {res}"
    assert "127" in res["detail"], f"detail содержит exit-код; got {res}"
    assert "srouter-117" in res["detail"], f"detail содержит путь из stderr; got {res}"


def test_codenv_down_detail_mentions_runs_flap(monkeypatch, tmp_path):
    """Большой `runs` при ненулевом exit — сигнал ФЛАПА, не разовой ошибки (issue #250 п.4)."""
    _codenv_env(monkeypatch, tmp_path)
    runner = _runner(_print_out(state="not running", runs=1419, last_exit_code=127))
    res = health._codenv_job_check(runner=runner)
    assert res["status"] == "down"
    assert "1419" in res["detail"], f"runs в detail (флап vs разовая ошибка); got {res}"


# ============================ 2. job загружен + plist отсутствует → down (осиротевший) ===========

def test_codenv_down_when_job_loaded_but_plist_missing(monkeypatch, tmp_path):
    """job загружен, plist на диске отсутствует → down (осиротевший job).

    Осиротевший job переживает удаление своего plist: launchd держит его в памяти, StartInterval
    продолжает запуски. `_codenv_managed()` (маркер-в-plist) читал бы False → doctor трактовал
    SOCKS5 как ЧУЖОЙ и указывал не туда (Desktop App #127) вместо реальной аварии.
    Лечится `launchctl bootout gui/<uid>/com.srouter.codenv`.
    """
    _codenv_env(monkeypatch, tmp_path, plist_exists=False)
    runner = _runner(_print_out(state="running", runs=5, last_exit_code=0))
    res = health._codenv_job_check(runner=runner)
    assert res["status"] == "down", f"loaded + нет plist → down (осиротевший); got {res}"
    assert "bootout" in res["detail"], f"detail даёт команду лечения; got {res}"


# ============================ 3. ProgramArguments → несуществующий файл → down ==================

def test_codenv_down_when_program_arguments_path_missing(monkeypatch, tmp_path):
    """ProgramArguments указывает на несуществующий файл → down, путь в detail.

    Причина exit 127 ДО того, как job успел упасть (свежий bootstrap, `runs = 0`): скрипт стёрт
    вместе с worktree. Первоисточник — сам блок `arguments` из `launchctl print`, не догадки.
    """
    _codenv_env(monkeypatch, tmp_path)
    missing = str(tmp_path / "gone" / "srouter-codex-env.sh")
    runner = _runner(_print_out(state="running", runs=0, last_exit_code=0, script=missing))
    res = health._codenv_job_check(runner=runner)
    assert res["status"] == "down", f"несуществующий ProgramArguments → down; got {res}"
    assert missing in res["detail"], f"сам путь в detail; got {res}"


def test_codenv_down_highlights_ao_worktree_path(monkeypatch, tmp_path):
    """Путь LaunchAgent внутри `.ao/data/worktrees/` подсвечивается отдельно (мина установки).

    Эфемерный AO-worktree как цель ПОСТОЯННОГО LaunchAgent — всегда баг установки
    (канон ao-worktree-vs-main-worktree-confusion). Даже если файл ещё существует, это мина.
    """
    _codenv_env(monkeypatch, tmp_path)
    wt = tmp_path / ".ao" / "data" / "worktrees" / "srouter" / "srouter-117" / "launchagents"
    wt.mkdir(parents=True)
    script = wt / "srouter-codex-env.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    runner = _runner(_print_out(state="running", runs=1, last_exit_code=0, script=str(script)))
    res = health._codenv_job_check(runner=runner)
    assert res["status"] == "down", f"путь в AO-worktree → down (мина установки); got {res}"
    assert "worktree" in res["detail"].lower(), f"detail называет worktree; got {res}"


# ============================ 4. здоровый job → info (канон #135, шум НЕ возвращается) ==========

def test_codenv_info_when_healthy_job_and_socks5(monkeypatch, tmp_path):
    """job загружен + exit 0 + существующий скрипт → info (канон #135 — шум НЕ возвращается).

    Нормальная установка с codenv не должна вечно светиться degraded (тот же компромисс, что PR #135
    для PF и #189 для SOCKS5 в launchctl).
    """
    script = tmp_path / "Projects" / "srouter" / "launchagents" / "srouter-codex-env.sh"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    _codenv_env(monkeypatch, tmp_path)
    runner = _runner(_print_out(state="running", runs=42, last_exit_code=0, script=str(script)))
    res = health._codenv_job_check(runner=runner)
    assert res["status"] == "info", f"здоровый codenv → info (канон #135); got {res}"


def test_codenv_check_all_healthy_job_not_driver(monkeypatch, tmp_path):
    """Интеграция: здоровый codenv-job НЕ роняет вердикт check_all (info-only, канон #135)."""
    script = tmp_path / "Projects" / "srouter" / "launchagents" / "srouter-codex-env.sh"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    _codenv_env(monkeypatch, tmp_path)
    monkeypatch.setattr(health, "_codenv_job_check",
                        lambda **kw: {"status": "info", "detail": "codenv job здоров"})
    checks = _codenv_checks(monkeypatch)
    row = _find_check(checks, "codenv")
    assert row.get("info") is True, f"здоровый codenv — info-only, не driver; got {row}"


def test_codenv_check_all_dead_job_is_driver(monkeypatch, tmp_path):
    """Интеграция: мёртвый codenv-job — DRIVER (ok=False), не info-шёпот.

    Ядро issue #250: 1419 падений в тишине. down обязан ронять вердикт doctor'а, иначе авария
    снова остаётся невидимой (noisy-log-better-than-no-log).
    """
    monkeypatch.setattr(health, "_codenv_job_check",
                        lambda **kw: {"status": "down", "detail": "codenv падает (exit 127, runs 1419)"})
    checks = _codenv_checks(monkeypatch)
    row = _find_check(checks, "codenv")
    assert row["ok"] is False, f"мёртвый codenv → driver down; got {row}"
    assert not row.get("info"), f"down НЕ info-only; got {row}"


def test_codenv_check_all_unknown_not_driver(monkeypatch, tmp_path):
    """Интеграция: unknown (launchctl недоступен) — info-only, не ложный down (probe-канон)."""
    monkeypatch.setattr(health, "_codenv_job_check",
                        lambda **kw: {"status": "unknown", "detail": "launchctl print недоступен"})
    checks = _codenv_checks(monkeypatch)
    row = _find_check(checks, "codenv")
    assert row.get("info") is True, f"unknown — info-only; got {row}"


def _codenv_checks(monkeypatch):
    from test_health import _all_up_monkey  # rootdir-insertion pytest: tests/ в sys.path
    _all_up_monkey(monkeypatch)
    return health.check_all()["checks"]


def _find_check(checks, needle):
    rows = [c for c in checks if needle in c["name"] and "app" not in c["name"]]
    assert rows, f"чек с '{needle}' не зарегистрирован в check_all; got {[c['name'] for c in checks]}"
    return rows[0]


# ============================ 5. launchctl недоступен/таймаут → unknown, не бросает =============

def test_codenv_unknown_on_launchctl_timeout(monkeypatch, tmp_path):
    """`launchctl print` таймаут → unknown, НЕ бросает (probe-канон, fail-soft граница doctor)."""
    _codenv_env(monkeypatch, tmp_path)
    def runner(cmd, tmo=5, **kw):
        return {"rc": None, "out": "", "err": "timeout", "timeout": True}

    res = health._codenv_job_check(runner=runner)
    assert res["status"] == "unknown", f"timeout → unknown; got {res}"


def test_codenv_unknown_when_job_not_loaded(monkeypatch, tmp_path):
    """job НЕ загружен (rc=113 service-not-found) → unknown, не down.

    codenv опционален (не все ставят #189-фикс). Отсутствие job'а — не авария: down зарезервирован
    для ЗАГРУЖЕННОГО, но сломанного job'а. Иначе doctor вечно красный на машинах без codenv (шум).
    """
    _codenv_env(monkeypatch, tmp_path, plist_exists=False)
    runner = _runner("Could not find service", rc=113)
    res = health._codenv_job_check(runner=runner)
    assert res["status"] == "unknown", f"job не загружен → unknown (codenv опционален); got {res}"


def test_codenv_unknown_on_unparseable_output(monkeypatch, tmp_path):
    """rc=0, но вывод без узнаваемых полей → unknown (не выдумываем down из мусора, fail-closed)."""
    _codenv_env(monkeypatch, tmp_path)
    runner = _runner("Bad request.\nCould not find service in domain for user gui: 501")
    res = health._codenv_job_check(runner=runner)
    assert res["status"] == "unknown", f"нераспознанный вывод → unknown; got {res}"


def test_codenv_job_check_never_raises(monkeypatch, tmp_path):
    """Любой сбой runner'а (исключение) → unknown, не пробрасывается в check_all.

    check_all — общий doctor/watchdog путь: одно исключение из codenv-чека уронило бы ВЕСЬ health
    (fail-open, нарушение srouter-critical-infra-24-7).
    """
    _codenv_env(monkeypatch, tmp_path)

    def _boom(cmd, tmo=5, **kw):
        raise OSError("launchctl отсутствует")

    res = health._codenv_job_check(runner=_boom)
    assert res["status"] == "unknown", f"исключение runner'а → unknown; got {res}"


# ============================ парсер `launchctl print` (первоисточник) ==========================

def test_codenv_job_state_parses_primary_source_fields(monkeypatch, tmp_path):
    """Парсер вытаскивает path/state/runs/last exit code/ProgramArguments из `launchctl print`."""
    st = health._codenv_job_state(runner=_runner(_print_out(
        path="/Users/u/Library/LaunchAgents/com.srouter.codenv.plist",
        state="not running", runs=1419, last_exit_code=127,
        script="/Users/u/.ao/data/worktrees/srouter/srouter-117/launchagents/srouter-codex-env.sh")))
    assert st["loaded"] is True
    assert st["state"] == "not running"
    assert st["runs"] == 1419
    assert st["last_exit_code"] == 127
    assert st["path"].endswith("com.srouter.codenv.plist")
    assert st["arguments"][-1].endswith("srouter-codex-env.sh")


def test_codenv_job_state_last_exit_code_absent_is_none(monkeypatch, tmp_path):
    """`last exit code` отсутствует (job ни разу не завершался) → None, НЕ 0.

    Разница критична: None = «нет данных», 0 = «доказанно завершился успешно». Подмена None→0
    вернула бы fail-open (молчание там, где состояние неизвестно).
    """
    st = health._codenv_job_state(runner=_runner(_print_out(last_exit_code=None)))
    assert st["last_exit_code"] is None
