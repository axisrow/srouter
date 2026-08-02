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


# ============================ 4. здоровый job → ok (канон #135, шум НЕ возвращается) ============

def test_codenv_ok_when_healthy_job_and_socks5(monkeypatch, tmp_path):
    """job загружен + exit 0 + существующий скрипт → ok (канон #135 — шум НЕ возвращается).

    Нормальная установка с codenv не должна вечно светиться degraded (тот же компромисс, что PR #135
    для PF и #189 для SOCKS5 в launchctl). Именно "ok", а не "info": cycle-review PR #262 показал,
    что _print_report красит КАЖДЫЙ info-чек жёлтым ⚠️ — «info для здорового» и есть тот шум.
    """
    script = tmp_path / "Projects" / "srouter" / "launchagents" / "srouter-codex-env.sh"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    _codenv_env(monkeypatch, tmp_path)
    runner = _runner(_print_out(state="running", runs=42, last_exit_code=0, script=str(script)))
    res = health._codenv_job_check(runner=runner)
    assert res["status"] == "ok", f"здоровый codenv → ok (канон #135); got {res}"


def test_codenv_check_all_healthy_job_not_driver(monkeypatch, tmp_path):
    """Интеграция: здоровый codenv-job НЕ роняет вердикт check_all и НЕ добавляет ⚠️-шум."""
    script = tmp_path / "Projects" / "srouter" / "launchagents" / "srouter-codex-env.sh"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    _codenv_env(monkeypatch, tmp_path)
    monkeypatch.setattr(health, "_codenv_job_check",
                        lambda **kw: {"status": "ok", "detail": "codenv job здоров"})
    checks = _codenv_checks(monkeypatch)
    row = _find_check(checks, "codenv")
    assert row["ok"] is True and not row.get("info"), \
        f"здоровый codenv — ✅ без info-флага (канон #135); got {row}"


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


# ============ cycle-review PR #262 (Codex): fail-open дыры классификации ==========================
#
# Пять дефектов, найденных адверсариальным ревью. Общий класс: парсер отдавал корректные данные,
# но КЛАССИФИКАТОР трактовал «нет данных» как «доказанно здоров» — ровно тот fail-open, который
# докстринг обещал не допускать (канон verify-dont-guess: отсутствие доказательства ≠ доказательство).

def test_codenv_unknown_when_exit_code_absent_not_healthy(monkeypatch, tmp_path):
    """`last exit code` ОТСУТСТВУЕТ (job ни разу не завершался) → unknown, НЕ info.

    Cycle-review дефект #2 (Codex): парсер честно клал None, но классификатор проверял `if exit_code`
    — None проваливался в здоровую ветку, а detail ЛГАЛ «last exit code = 0». «Нет данных» выдавалось
    за «доказанно завершился успешно» — fail-open, который докстринг явно обещал исключить.
    """
    script = tmp_path / "s.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    _codenv_env(monkeypatch, tmp_path)
    runner = _runner(_print_out(state="running", runs=3, last_exit_code=None, script=str(script)))
    res = health._codenv_job_check(runner=runner)
    assert res["status"] == "unknown", f"нет данных об exit code → unknown, не info; got {res}"
    assert "= 0" not in res["detail"], f"detail НЕ должен утверждать exit code = 0; got {res}"


def test_codenv_unknown_when_exit_code_non_numeric(monkeypatch, tmp_path):
    """`last exit code = (never exited)` — launchctl печатает и такое → unknown, не выдуманный 0."""
    script = tmp_path / "s.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    _codenv_env(monkeypatch, tmp_path)
    out = _print_out(state="running", runs=1, last_exit_code=0,
                     script=str(script)).replace("last exit code = 0", "last exit code = (never exited)")
    res = health._codenv_job_check(runner=_runner(out))
    assert res["status"] == "unknown", f"нечисловой exit code → unknown; got {res}"


def test_codenv_unknown_when_output_partial(monkeypatch, tmp_path):
    """rc=0, но вывод УСЕЧЁН (только `path`, без state/runs/exit/arguments) → unknown, НЕ info.

    Cycle-review дефект #1 (Codex): loaded=True выставлялся по ЛЮБОМУ узнанному полю, включая
    одинокий `path`. Дальше все проверки падений пропускались → info «здоров». Неполный
    первоисточник — это «не смогли спросить», а не «спросили и всё хорошо» (fail-closed).
    """
    _codenv_env(monkeypatch, tmp_path)
    res = health._codenv_job_check(runner=_runner(
        f"gui/501/{health._CODENV_LABEL} = {{\n\tpath = /tmp/p.plist\n}}\n"))
    assert res["status"] == "unknown", f"усечённый вывод → unknown, не info; got {res}"


def test_codenv_job_state_never_raises_on_malformed_runner_result(monkeypatch, tmp_path):
    """runner вернул не-словарь (None) → unknown, НЕ AttributeError.

    Cycle-review дефект #5 (Codex): try охватывал только ВЫЗОВ runner'а, а разбор результата был
    снаружи → `None.get` ронял весь check_all. check_all — общий doctor/watchdog путь; одно
    исключение здесь = fail-open по всему стеку (srouter-critical-infra-24-7).
    """
    _codenv_env(monkeypatch, tmp_path)
    assert health._codenv_job_state(runner=lambda *a, **k: None)["loaded"] is None
    assert health._codenv_job_check(runner=lambda *a, **k: None)["status"] == "unknown"
    assert health._codenv_job_check(runner=lambda *a, **k: "не словарь")["status"] == "unknown"


def test_codenv_healthy_job_is_ok_not_warning_noise(monkeypatch, tmp_path):
    """Здоровый codenv → check_all даёт ✅ (ok, НЕ info) — канон #135 буквально.

    Cycle-review дефект #3 (Codex): _print_report рендерит КАЖДЫЙ info-чек жёлтым ⚠️
    (health.py `mark = "⚠️" if c.get("info")`). То есть «info для здорового» возвращало ровно тот
    шум, который #135 запрещает — просто в другом цвете. Здоровый job обязан быть ✅ и не-driver'ом
    по определению (ok=True), а info оставлен для «не смогли проверить»/«намеренный tradeoff».
    """
    script = tmp_path / "Projects" / "srouter" / "launchagents" / "srouter-codex-env.sh"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    _codenv_env(monkeypatch, tmp_path)
    runner = _runner(_print_out(state="running", runs=42, last_exit_code=0, script=str(script)))
    assert health._codenv_job_check(runner=runner)["status"] == "ok"

    monkeypatch.setattr(health, "_codenv_job_check",
                        lambda **kw: {"status": "ok", "detail": "codenv job здоров"})
    row = _find_check(_codenv_checks(monkeypatch), "codenv")
    assert row["ok"] is True and not row.get("info"), \
        f"здоровый codenv = ✅, НЕ ⚠️ (канон #135 — никакого шума); got {row}"


def test_codenv_job_state_ignores_nested_block_fields(monkeypatch, tmp_path):
    """Вложенные блоки (`jetsam coalition = { state = active }`) НЕ перетирают top-level поля.

    Cycle-review PR #262: парсер строил `key = value` на ПЛОСКОМ уровне, срезая отступы. Реальный
    `launchctl print` содержит вложенные блоки (`resource coalition`, `jetsam coalition`), внутри
    которых свои `state = active` — и они шли ПОСЛЕ настоящего top-level `state`, затирая его.
    Воспроизведено на живом выводе `launchctl print gui/501/com.srouter.dashboard`: истинное
    `state = spawn scheduled` читалось как `active` (state коалиции, к job'у отношения не имеет).

    Критично вдвойне: `state` — это ГЕЙТ loaded=True. Обрывок вывода, заканчивающийся внутри
    coalition-блока, иначе выдал бы себя за полноценно загруженный job (fail-open).
    """
    out = (
        "gui/501/com.srouter.codenv = {\n"
        "\tpath = /Users/u/Library/LaunchAgents/com.srouter.codenv.plist\n"
        "\tstate = spawn scheduled\n"
        "\targuments = {\n"
        "\t\t/bin/sh\n"
        "\t\t/Users/u/Projects/srouter/launchagents/srouter-codex-env.sh\n"
        "\t}\n"
        "\truns = 357\n"
        "\tlast exit code = 1\n"
        "\tresource coalition = {\n"
        "\t\tID = 913\n"
        "\t\tstate = active\n"
        "\t\truns = 999\n"
        "\t}\n"
        "\tjetsam coalition = {\n"
        "\t\tstate = active\n"
        "\t\tlast exit code = 0\n"
        "\t}\n"
        "}\n"
    )
    st = health._codenv_job_state(runner=_runner(out))
    assert st["state"] == "spawn scheduled", f"top-level state не перетёрт коалицией; got {st}"
    assert st["runs"] == 357, f"runs из top-level, не из coalition; got {st}"
    assert st["last_exit_code"] == 1, f"exit code из top-level, не из coalition; got {st}"


def test_codenv_job_state_unknown_when_only_nested_block_seen(monkeypatch, tmp_path):
    """Обрывок вывода, где `state` встречается ТОЛЬКО внутри вложенного блока → loaded не True.

    state — гейт loaded. Значение из coalition-блока не доказывает, что job загружен (fail-closed)."""
    out = ("gui/501/com.srouter.codenv = {\n"
           "\tjetsam coalition = {\n"
           "\t\tstate = active\n"
           "\t}\n"
           "}\n")
    assert health._codenv_job_state(runner=_runner(out))["loaded"] is not True


def test_codenv_job_state_rc_semantics_match_launchd_is_loaded():
    """Парити-гвард: rc-семантика _codenv_job_state == install_plist._launchd_is_loaded.

    Cycle-review PR #262: _codenv_job_state ПОВТОРЯЕТ tristate-контракт `launchctl print`
    (rc=0 загружен / rc=113 not-found / иначе unknown) вместо вызова _launchd_is_loaded. Вызвать
    его напрямую нельзя — он отдаёт голый tristate, а нам нужен САМ вывод для разбора state/runs/
    exit code, и второй вызов означал бы ВТОРОЙ идентичный subprocess за прогон doctor'а.
    Дублирование осознанное, поэтому его удерживает гвард: обе стороны обязаны отвечать одинаково
    на один и тот же rc, иначе детекторы разъедутся молча (канон post-review-catches-detector-
    duplication + parity-гвард _CODENV_LABEL).
    """
    from install_lib import _launchd_is_loaded

    for rc, timeout, expected in [(0, False, True), (113, False, False), (112, False, None),
                                  (None, True, None), (1, False, None)]:
        def runner(cmd, tmo=5, _rc=rc, _to=timeout, **kw):
            # rc=0 требует узнаваемого вывода — иначе _codenv_job_state честно скажет unknown.
            out = _print_out() if _rc == 0 else ""
            return {"rc": _rc, "out": out, "err": "", "timeout": _to}

        assert _launchd_is_loaded(health._CODENV_LABEL, runner=runner) is expected, \
            f"эталон _launchd_is_loaded для rc={rc}"
        assert health._codenv_job_state(runner=runner)["loaded"] is expected, \
            f"_codenv_job_state разошёлся с эталоном на rc={rc}"


def test_codenv_label_marker_parity_with_codex_wrappers():
    """Парити-гвард литералов: health._CODENV_* == codex_wrappers.CODEX_ENV_*.

    health.py дублирует label/marker намеренно (импорт codex_wrappers дал бы цикл — тот сам
    импортирует health). Комментарий-гвард в health.py указывал на srouter.py :273-274, но PR #258
    перенёс определения в codex_wrappers.py — указатель протух, а расхождение значений так и
    осталось бы незамеченным до прода. Проверяем машиной, а не комментарием.
    """
    import codex_wrappers

    assert health._CODENV_LABEL == codex_wrappers.CODEX_ENV_LABEL
    assert health._CODENV_MARKER == codex_wrappers.CODEX_ENV_MARKER


# ============ cycle-review round 2 (Codex sol/xhigh + /review): остаточные fail-open ============

def test_codenv_down_when_managed_plist_on_disk_but_job_unloaded(monkeypatch, tmp_path):
    """srouter-managed plist НА ДИСКЕ + job выгружен (rc=113) → down, НЕ «опционален».

    Cycle-review round 2 (Codex, critical): rc=113 безусловно давал «codenv опционален» → info-only.
    Но маркерный plist на диске ДОКАЗЫВАЕТ, что установка была: значит это не «не ставили», а
    «поставили и job сдох/не забутстрапился». Зеркало осиротевшего job'а (тот случай — job без
    plist, этот — plist без job'а), и ровно тот класс, что issue #250 просил ловить: codenv
    сконфигурирован, но мёртв → после ребута Codex молча без SOCKS5 (fail-closed-proxy-down).
    """
    plist = _codenv_env(monkeypatch, tmp_path, plist_exists=True)
    assert health._CODENV_MARKER in plist.read_text(encoding="utf-8")
    res = health._codenv_job_check(runner=_runner("Could not find service", rc=113))
    assert res["status"] == "down", f"managed plist + выгруженный job → down; got {res}"
    assert "bootstrap" in res["detail"] or "install" in res["detail"], \
        f"detail даёт путь лечения; got {res}"


def test_codenv_unknown_when_no_plist_and_job_unloaded(monkeypatch, tmp_path):
    """Регресс-гард: НЕТ plist + job не загружен → unknown (codenv правда не ставили).

    Граница предыдущего теста: down только когда есть доказательство установки. Иначе doctor
    вечно красный на машинах без codenv — тот самый шум, который канон #135 запрещает.
    """
    _codenv_env(monkeypatch, tmp_path, plist_exists=False)
    res = health._codenv_job_check(runner=_runner("Could not find service", rc=113))
    assert res["status"] == "unknown", f"нет установки → unknown (опционален); got {res}"


def test_codenv_unknown_when_foreign_plist_and_job_unloaded(monkeypatch, tmp_path):
    """ЧУЖОЙ plist (без нашего маркера) + job выгружен → unknown, не down.

    Provenance-граница (канон fail-closed provenance #112): чужой com.srouter.codenv.plist — не
    наша установка, мы про неё ничего не утверждаем и не зовём чинить чужое.
    """
    plist = tmp_path / "Library" / "LaunchAgents" / f"{health._CODENV_LABEL}.plist"
    plist.parent.mkdir(parents=True, exist_ok=True)
    plist.write_text("<plist>чужой, без маркера</plist>", encoding="utf-8")
    monkeypatch.setattr(health.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(health, "_codenv_stderr_tail", lambda path=None, **kw: "")
    res = health._codenv_job_check(runner=_runner("Could not find service", rc=113))
    assert res["status"] == "unknown", f"чужой plist → не наша забота, unknown; got {res}"


def test_codenv_worktree_mark_is_case_insensitive(monkeypatch, tmp_path):
    """`.AO/data/worktrees/` (иной регистр) детектится как worktree — macOS APFS case-insensitive.

    Cycle-review round 2 (Codex, critical): проверка вхождения была регистрозависимой. Эмпирически
    на этом APFS `.AO` и `.ao` — ОДИН каталог (`samefile=True`), но `resolve()` сохраняет исходное
    написание → подстрока промахивалась, и мина проходила мимо guard'а и мимо детектора.
    Канон loose-validator: сверяем по свойствам ФС, а не по написанию строки.
    """
    _codenv_env(monkeypatch, tmp_path)
    wt = tmp_path / ".AO" / "data" / "worktrees" / "srouter" / "s1" / "launchagents"
    wt.mkdir(parents=True)
    script = wt / "srouter-codex-env.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    runner = _runner(_print_out(state="running", runs=1, last_exit_code=0, script=str(script)))
    res = health._codenv_job_check(runner=runner)
    assert res["status"] == "down", f"'.AO' — тот же каталог, что '.ao' → down; got {res}"
    assert "worktree" in res["detail"].lower(), f"detail называет worktree; got {res}"


def test_codenv_job_state_no_leak_after_top_level_block_closes(monkeypatch, tmp_path):
    """Поля соседнего блока ПОСЛЕ закрытия top-level не читаются как поля job'а.

    Cycle-review round 2 (/review): depth возвращался к 0 на закрывающей скобке, и следующий
    блок-сосед снова входил на depth==1 → его `state`/`last exit code` читались как свои. Тот же
    класс утечки, что чинила depth-трекинг, просто смещённый за первую `}`. На живом выводе
    недостижимо (там один top-level блок), но парсер обязан быть строгим к своему первоисточнику.
    """
    out = ("gui/501/com.srouter.codenv = {\n"
           "\tstate = running\n"
           "\tlast exit code = 0\n"
           "}\n"
           "resource coalition = {\n"
           "\tstate = active\n"
           "\tlast exit code = 99\n"
           "}\n")
    st = health._codenv_job_state(runner=_runner(out))
    assert st["state"] == "running", f"state не из соседнего блока; got {st}"
    assert st["last_exit_code"] == 0, f"exit code не из соседнего блока (99 = утечка); got {st}"


def test_codenv_stderr_tail_default_matches_template(monkeypatch, tmp_path):
    """Дефолтный путь stderr-лога согласован с тем, что подставляет генератор шаблона.

    Cycle-review round 2 (/review): fallback был захардкожен в `/tmp/codenv.err`, а шаблон
    рендерит `__SROUTER_LOG_ERR__` → `~/Library/Logs/...`. Мёртвый дефолт: когда `launchctl print`
    не отдал `stderr path`, читался несуществующий файл и причина падения молча терялась
    (канон config-contract-is-the-generator).
    """
    import install_config
    expected = str(install_config.InstallEnv().log_err)
    monkeypatch.setattr(health.Path, "home", lambda: tmp_path)
    assert health._codenv_default_stderr_path() == expected, \
        "дефолт stderr совпадает с log_err генератора"


def test_in_ao_worktree_never_raises_on_non_path_input():
    """_in_ao_worktree не бросает ни на каком входе — докстринг обещает «не бросает».

    Cycle-review round 2 (/review): except охватывал resolve(), но `Path(path)` бросает TypeError
    РАНЬШЕ — на None/int/bytes. Оба текущих вызова защищены (`if script:` в детекторе, `env.root/...`
    в guard'е), так что сейчас недостижимо. Но это ОБЩИЙ предикат двух подсистем: следующий вызывающий
    справедливо поверит докстрингу, а исключение отсюда уходит в check_all (fail-open по всему стеку,
    ровно то, что чинил дефект #5 раунда 1). Контракт должен быть правдой, а не почти-правдой.
    """
    from pathlib import Path as _P

    for bad in (None, 1234, b"/tmp/x", object()):
        assert health._in_ao_worktree(bad) is False, f"нераспознанный вход → False, не бросок: {bad!r}"
    # Валидные входы по-прежнему решаются по существу, а не глушатся except'ом.
    assert health._in_ao_worktree("/Users/u/.AO/data/worktrees/s1/x.sh") is True
    assert health._in_ao_worktree(_P("/Users/u/Projects/srouter/x.sh")) is False
