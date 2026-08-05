"""Crash-окна вокруг in-place overwrite: durability оригинального конфига (issue #124).

PR #119 вводил two-phase backup (WAL). Cloud cycle-review (@codex) за 3 раунда нашёл 6 P1 — все
одного класса: потеря/orphaning пользовательского оригинала при обрыве apply в одном из окон вокруг
overwrite. Каждый патч закрывал одно окно и обнажал следующее → WAL вынесен из #119, issue #124
требует архитектурного пересмотра.

КОРЕНЬ (не тот, что предполагала issue). Issue рекомендовала «Вариант A: write-to-temp + atomic
rename» — но он УЖЕ реализован (_write_text_atomic install_plist.py, gen_xray_config.write_config —
оба tmp+replace), то есть закрывает окно «target полузаписан», которого не существует. Настоящий
корень — рассогласование двух независимо-атомарных артефактов: backup-файла на диске и entry в state.
`backups` — ЛОКАЛЬНЫЙ dict в apply_install (install_config.py), state пишется ОДИН раз в самом конце
(_write_state_after_apply). Между ними: до трёх `brew install` (timeout 180s), три _restart_component
(stop+poll+start+poll), _apply_dns, _install_launchagent. Окно — МИНУТЫ.

Критично (и это доказывает T4): дефект эксплуатируется БЕЗ всякого crash. Любой ранний return внутри
цикла минует _write_state_after_apply, и локальный dict испаряется вместе со ссылкой на backup.

Канон verify-dont-guess: каждое crash-окно должно быть ДОКАЗАНО закрытым эмпирически, а не
предположено. Именно отсутствие таких тестов в #119 и позволило шести P1 дожить до внешнего ревью.
"""
import json

import pytest

import install_config
import install_lib

from test_install_flow import (
    FakeRunner,
    _env,
    _port_checker_managed_up,
    _write_config_without_marker,
)


class _Crash(RuntimeError):
    """Модель mid-apply crash: строки apply_install ПОСЛЕ точки броска не выполняются.

    Единственное, что нас интересует в SIGKILL, — что продолжение (в частности финальный
    _write_state_after_apply) не состоялось. Исключение даёт ровно это и проходит сквозь
    apply_install наружу: широких `except Exception` там нет (только конкретные типы в
    _inspect_component/_discover_probe_readiness), поэтому подавления не будет.
    """


def _crash_after(monkeypatch, func_name, *, component=None, calls=1):
    """Дать install_config.<func_name> отработать по-настоящему, затем бросить _Crash.

    Побочный эффект (backup-файл, запись конфига, рестарт) УСПЕВАЕТ случиться на диске — падаем уже
    после него, симулируя обрыв ровно в этом окне. component/calls прицеливаются в конкретную
    итерацию цикла по COMPONENTS (у _write_component_config/_restart_component первый позиционный
    аргумент — имя компонента).
    """
    original = getattr(install_config, func_name)
    state = {"n": 0}

    def wrapper(*args, **kwargs):
        result = original(*args, **kwargs)
        if component is not None and (not args or args[0] != component):
            return result
        state["n"] += 1
        if state["n"] >= calls:
            raise _Crash(f"crash after {func_name} (component={component})")
        return result

    monkeypatch.setattr(install_config, func_name, wrapper)
    return state


def _foreign_privoxy(tmp_path):
    """Чужой privoxy-конфиг + окружение: сценарий overwrite (есть что терять)."""
    env = _env(tmp_path)
    config_path = _write_config_without_marker(env, "privoxy", content="foreign config\n")
    return env, config_path


def _apply_overwrite_privoxy(env):
    runner = FakeRunner()
    return install_lib.apply_install(
        env=env,
        confirm=True,
        choices={"privoxy": "overwrite", "xray": "skip", "dnsmasq": "skip"},
        runner=runner,
        port_checker=_port_checker_managed_up(runner.calls),
    )


def _entry(env, name="privoxy"):
    """detected_environment-entry компонента; {} если state вовсе не записан (тоже валидный исход)."""
    if not env.state_path.exists():
        return {}
    state = json.loads(env.state_path.read_text(encoding="utf-8"))
    detected = state.get("detected_environment") or {}
    return detected.get(name) or {}


# ============================ T1/T4: install фиксирует backup ДО потери ============================


def test_crash_after_config_write_leaves_state_knowing_backup(tmp_path, monkeypatch):
    """W4 (главное окно, часть 2/2 — ФИКС): обрыв после записи target → state уже знает про backup.

    _record_backup_intent пишет ссылку на backup СРАЗУ после _backup, до _write_component_config —
    поэтому обрыв в этом окне уже не теряет её (было: backup жил только в локальном dict до финального
    _write_state_after_apply, который при обрыве не достигался). Это F1/P1-3 в install-половине.
    """
    env, config_path = _foreign_privoxy(tmp_path)
    _crash_after(monkeypatch, "_write_component_config", component="privoxy")

    with pytest.raises(_Crash):
        _apply_overwrite_privoxy(env)

    backups = list(config_path.parent.glob("config.srouter-backup-*"))
    assert backups, "backup обязан быть создан до перезаписи target"
    assert backups[0].read_text(encoding="utf-8") == "foreign config\n", "backup = оригинал пользователя"
    entry = _entry(env)
    assert entry.get("backup") == str(backups[0]), (
        "state обязан знать про backup ДО мутации target — иначе ссылка теряется при обрыве "
        "и uninstall не сможет восстановить оригинал (issue #124, W4)"
    )


def test_second_component_failure_preserves_first_component_backup(tmp_path, monkeypatch):
    """Дефект (часть 2/2 — ФИКС) воспроизводился БЕЗ crash: штатный ранний return терял backup.

    privoxy успешно перезаписан (backup создан + _record_backup_intent зафиксировал ссылку сразу),
    затем `brew install dnsmasq` штатно падает → apply_install делает ранний return
    `dnsmasq_install_failed`. Локальный dict `backups` испаряется, но ссылка в state уже записана —
    ранний return из-за ДРУГОГО компонента больше не теряет backup privoxy. Никаких исключений,
    никакого SIGKILL — рутинный сбой brew. Это доказывает, что окно было не экзотикой.
    """
    env, config_path = _foreign_privoxy(tmp_path)
    original_ensure = install_config._ensure_package

    def fake_ensure(name, runner):
        if name == "dnsmasq":
            return False  # штатный сбой brew install на ВТОРОМ компоненте
        return original_ensure(name, runner)

    monkeypatch.setattr(install_config, "_ensure_package", fake_ensure)

    runner = FakeRunner()
    result = install_lib.apply_install(
        env=env,
        confirm=True,
        choices={"privoxy": "overwrite", "xray": "skip"},
        runner=runner,
        port_checker=_port_checker_managed_up(runner.calls),
    )

    assert result["ok"] is False and "dnsmasq_install_failed" in result["blocked"]
    backups = list(config_path.parent.glob("config.srouter-backup-*"))
    assert backups, "backup privoxy создан до перезаписи"
    entry = _entry(env)
    assert entry.get("backup") == str(backups[0]), (
        "ранний return из-за сбоя ДРУГОГО компонента не должен терять backup уже перезаписанного "
        "privoxy — иначе uninstall удалит srouter-конфиг вместо restore оригинала (issue #124)"
    )


def test_retry_with_skip_after_interrupted_overwrite_keeps_backup(tmp_path, monkeypatch):
    """F3/P1-2 (часть 2/2 — ФИКС, требует ОБА дефекта A+B): обрыв overwrite, потом retry со skip.

    Первая попытка перезаписала конфиг, обрывается ПОСЛЕ _record_backup_intent (дефект A уже чинит
    W4). Повторный apply со skip раньше терял ссылку через preserve-логику, гейтившую backup=='managed'
    (дефект B) — _write_state_after_apply теперь несёт carried_backup независимо от режима.
    """
    env, config_path = _foreign_privoxy(tmp_path)
    _crash_after(monkeypatch, "_write_component_config", component="privoxy")
    with pytest.raises(_Crash):
        _apply_overwrite_privoxy(env)
    backups = list(config_path.parent.glob("config.srouter-backup-*"))
    assert backups, "первая попытка создала backup"

    monkeypatch.undo()
    runner = FakeRunner()
    install_lib.apply_install(
        env=env, confirm=True,
        choices={"privoxy": "skip", "xray": "skip", "dnsmasq": "skip"},
        runner=runner, port_checker=_port_checker_managed_up(runner.calls))

    assert _entry(env).get("backup") == str(backups[0]), (
        "повторный apply со skip не должен терять ссылку на backup оборванной попытки (F3/P1-2)"
    )


def test_crash_between_backup_and_config_write_leaves_original_intact(tmp_path, monkeypatch):
    """W2/W3 (регресс-гвард, зелёный и до фикса): обрыв сразу после _backup не трогает оригинал.

    Единственная мутация в этом окне — создание нового файла (shutil.copy2 аддитивна), поэтому
    target побайтово тот же. Тест обязан остаться зелёным после введения state-first: он доказывает,
    что порядок «backup → state → write» не начал писать target раньше фиксации backup.
    """
    env, config_path = _foreign_privoxy(tmp_path)
    _crash_after(monkeypatch, "_backup")

    with pytest.raises(_Crash):
        _apply_overwrite_privoxy(env)

    assert config_path.read_text(encoding="utf-8") == "foreign config\n", (
        "обрыв до записи target обязан оставить оригинал пользователя нетронутым"
    )
    assert install_lib.MARKER not in config_path.read_text(encoding="utf-8")


# ================== часть 2/2: форма intent-entry, fail-closed, дефект B изолированно ==================


def test_crash_between_intent_and_target_write_leaves_clean_system(tmp_path, monkeypatch):
    """Регресс-гвард на форму intent-entry: голый {config_path, backup}, БЕЗ management.

    Если бы _record_backup_intent писал entry в managed-форме ДО мутации target, обрыв ровно в этом
    зазоре объявил бы владение файлом, который ещё не тронут — на чистой системе (оригинал цел, рядом
    лишь аддитивная копия) uninstall докладывал бы leftover rc=2. Это ровно stale-managed из issue #110
    Дефект 1 — ложь оператору про то, что что-то не докатилось, хотя не докатилось НИЧЕГО.
    Голый entry без management инертен для всех предикатов состояния (_is_managed_entry и т.д.),
    поэтому на обоих концах окна component_facts классифицирует верно: target нетронут → none,
    target перезаписан → orphaned_backup (см. test_crash_after_config_write_leaves_state_knowing_backup).
    """
    env, config_path = _foreign_privoxy(tmp_path)
    _crash_after(monkeypatch, "_record_backup_intent")
    with pytest.raises(_Crash):
        _apply_overwrite_privoxy(env)

    assert config_path.read_text(encoding="utf-8") == "foreign config\n", (
        "state знает про backup, но target ещё не мутирован в момент обрыва"
    )
    result = install_lib.apply_uninstall(
        env=env, confirmations={"configs": True}, runner=FakeRunner())
    assert result["ok"] is True
    assert result["leftover"] == [], (
        "конфиг пользователя нетронут — intent-entry не должен объявлять владение файлом, который "
        "ещё не перезаписан (иначе stale-managed, issue #110 Дефект 1)"
    )


def test_backup_state_write_failure_blocks_before_touching_target(tmp_path, monkeypatch):
    """Fail-closed: не удалось записать state → apply обязан остановиться ДО мутации target.

    Если бы порядок был обратным (сначала target, потом state), отказ save_state потерял бы ссылку
    на уже созданный backup при живой перезаписи оригинала — тот же дефект A, просто без crash.
    """
    env, config_path = _foreign_privoxy(tmp_path)
    monkeypatch.setattr(install_config.local_state, "save_state", lambda *a, **k: None)

    result = _apply_overwrite_privoxy(env)

    assert result["ok"] is False
    assert "privoxy_backup_state_write_failed" in result["blocked"]
    assert config_path.read_text(encoding="utf-8") == "foreign config\n", (
        "target не должен мутироваться, если state не смог зафиксировать ссылку на backup"
    )
    assert install_lib.MARKER not in config_path.read_text(encoding="utf-8")


def test_unreadable_state_blocks_backup_intent_and_preserves_file(tmp_path):
    """readable=False (битый state) блокирует apply и не перезаписывает битый файл вслепую."""
    env, config_path = _foreign_privoxy(tmp_path)
    env.state_path.write_text("{ broken json", encoding="utf-8")

    result = _apply_overwrite_privoxy(env)

    assert result["ok"] is False
    assert env.state_path.read_text(encoding="utf-8") == "{ broken json", (
        "битый state не должен быть перезаписан вслепую — оператор ещё может его восстановить"
    )
    assert config_path.read_text(encoding="utf-8") == "foreign config\n"


def test_skip_after_completed_overwrite_keeps_backup_reference(tmp_path):
    """Дефект B изолированно (без crash): skip ПОСЛЕ завершённого overwrite не должен стирать backup.

    В отличие от test_retry_with_skip_after_interrupted_overwrite_keeps_backup (который требует ОБА
    фикса — A и B), здесь backup+managed/overwrote уже в state с самого начала (как после штатного
    completed apply), обрыва нет вовсе. Единственная переменная — снятие гейта mode=='managed' с
    backup-ветки preserve-логики (дефект B). Не должен зависеть от _record_backup_intent.
    """
    env, config_path = _foreign_privoxy(tmp_path)
    backup_path = config_path.with_name("config.srouter-backup-2026-06-29T000000Z")
    backup_path.write_text("foreign config\n", encoding="utf-8")
    env.state_path.write_text(json.dumps({
        "schema_version": 1, "nodes": [], "active_node": {"name": None, "pending": None},
        "probes": {}, "network": {"channels": {"wifi_service": "Wi-Fi"}},
        "traffic_guard": {"mode": "off", "domains": {}},
        "detected_environment": {"privoxy": {
            "config_path": str(config_path),
            "backup": str(backup_path),
            "management": {"mode": "managed", "managed": True, "provenance": "overwrote"},
        }},
        "runtime": {},
    }), encoding="utf-8")

    runner = FakeRunner()
    result = install_lib.apply_install(
        env=env, confirm=True,
        choices={"privoxy": "skip", "xray": "skip", "dnsmasq": "skip"},
        runner=runner, port_checker=_port_checker_managed_up(runner.calls))

    assert result["ok"] is True
    entry = _entry(env)
    assert entry.get("backup") == str(backup_path), (
        "skip после завершённого overwrite не должен терять ссылку на backup — файл на диске никуда "
        "не делся, смена режима не отменяет его существования (issue #124 F3/P1-2)"
    )
    assert "provenance" not in entry.get("management", {}), (
        "provenance — свойство ТЕКУЩЕГО apply (создали/перезаписали); при skip действия не было, "
        "поле неприменимо (сохраняет tests/test_install_flow.py::test_install_skipped_has_no_provenance)"
    )


def test_adopted_keeps_backup_but_uninstall_leaves_file_untouched(tmp_path):
    """adopted сохраняет ссылку на backup (симметрично skipped), но не даёт uninstall прав на файл.

    Граница: backup — память о прошлом, она не исчезает при adopt. Но adopt — осознанное заявление
    пользователя «это мой файл», и component_facts обязан уважать его вне зависимости от backup.
    """
    env, config_path = _foreign_privoxy(tmp_path)
    backup_path = config_path.with_name("config.srouter-backup-2026-06-29T000000Z")
    backup_path.write_text("foreign config\n", encoding="utf-8")
    env.state_path.write_text(json.dumps({
        "schema_version": 1, "nodes": [], "active_node": {"name": None, "pending": None},
        "probes": {}, "network": {"channels": {"wifi_service": "Wi-Fi"}},
        "traffic_guard": {"mode": "off", "domains": {}},
        "detected_environment": {"privoxy": {
            "config_path": str(config_path),
            "backup": str(backup_path),
            "management": {"mode": "managed", "managed": True, "provenance": "overwrote"},
        }},
        "runtime": {},
    }), encoding="utf-8")

    runner = FakeRunner()
    result = install_lib.apply_install(
        env=env, confirm=True,
        choices={"privoxy": "adopt", "xray": "skip", "dnsmasq": "skip"},
        runner=runner, port_checker=_port_checker_managed_up(runner.calls))
    assert result["ok"] is True
    assert _entry(env).get("backup") == str(backup_path), "adopt сохраняет ссылку на backup (память о прошлом)"

    un_result = install_lib.apply_uninstall(
        env=env, confirmations={"configs": True}, runner=FakeRunner())
    assert un_result["ok"] is True
    assert un_result["leftover"] == []
    assert config_path.read_text(encoding="utf-8") == "foreign config\n", (
        "adopt — осознанное заявление владения; uninstall не трогает файл вне зависимости от backup"
    )


def test_prefix_change_after_skip_does_not_carry_backup(tmp_path):
    """T9-гвард, расширенный на skipped: смена --prefix не переносит backup даже при снятом managed-гейте.

    Симметрично test_reinstall_does_not_carry_backup_across_config_paths (tests/test_install_flow.py),
    но для mode='skipped' — доказывает, что единственный ограничитель preserve-логики после дефекта B
    (prev_same_path) держит path-ownership независимо от режима.
    """
    env = _env(tmp_path)
    new_config_path = env.component_paths("privoxy")["config"]
    new_config_path.parent.mkdir(parents=True)
    new_config_path.write_text("# srouter-managed-config-v1\nlisten-address 127.0.0.1:8118\n", encoding="utf-8")
    old_config_path = tmp_path / "old-prefix" / "privoxy" / "config"
    backup_of_old = tmp_path / "old-prefix-backup"
    backup_of_old.write_text("foreign config from prefix A\n", encoding="utf-8")
    env.state_path.write_text(json.dumps({
        "schema_version": 1, "nodes": [], "active_node": {"name": None, "pending": None},
        "probes": {}, "network": {"channels": {"wifi_service": "Wi-Fi"}},
        "traffic_guard": {"mode": "off", "domains": {}},
        "detected_environment": {"privoxy": {
            "config_path": str(old_config_path),  # ДРУГОЙ путь (prefix A)
            "backup": str(backup_of_old),
            "management": {"mode": "managed", "managed": True, "provenance": "overwrote"},
        }},
        "runtime": {},
    }), encoding="utf-8")

    runner = FakeRunner()
    result = install_lib.apply_install(
        env=env, confirm=True, choices={"privoxy": "skip", "xray": "skip", "dnsmasq": "skip"},
        runner=runner, port_checker=_port_checker_managed_up(runner.calls))
    assert result["ok"] is True

    entry = _entry(env)
    assert entry.get("backup") != str(backup_of_old), (
        "backup с ДРУГОГО config_path не переносится при skip — path-ownership guard держит "
        "независимо от режима (cycle-review #111 finding 1)"
    )


def test_protected_privoxy_does_not_record_backup_intent(tmp_path, monkeypatch):
    """protected privoxy (system-domain root-транзакция) не должен вызывать _record_backup_intent.

    mode='protected' уходит в continue до _backup — это доказывает, что root-транзакция
    privoxy_system остаётся единственным писателем backup/previous для protected-компонента.
    """
    calls = []
    original = install_config._record_backup_intent

    def spy(*args, **kwargs):
        calls.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(install_config, "_record_backup_intent", spy)
    monkeypatch.setattr(install_config, "_privoxy_protected_for_env", lambda env: True)

    env = _env(tmp_path)
    runner = FakeRunner()
    install_lib.apply_install(
        env=env, confirm=True, choices={"xray": "skip", "dnsmasq": "skip"},
        runner=runner, port_checker=_port_checker_managed_up(runner.calls))

    assert calls == [], "protected privoxy не должен проходить через _record_backup_intent"


@pytest.mark.parametrize("mode", ["managed", "skipped", "adopted"])
def test_backup_reference_survives_any_mode_at_same_config_path(tmp_path, mode):
    """Инвариант: _write_state_after_apply никогда не теряет backup для того же config_path.

    Ссылка может появиться или быть заменена новой, но не исчезает при простой смене режима —
    единственный легитимный конец её жизни лежит в uninstall (_mark_component_removed/_restored).
    """
    env, config_path = _foreign_privoxy(tmp_path)
    backup_path = config_path.with_name("config.srouter-backup-2026-06-29T000000Z")
    backup_path.write_text("foreign config\n", encoding="utf-8")
    config_path.write_text("# srouter-managed-config-v1\nlisten-address 127.0.0.1:8118\n", encoding="utf-8")
    env.state_path.write_text(json.dumps({
        "schema_version": 1, "nodes": [], "active_node": {"name": None, "pending": None},
        "probes": {}, "network": {"channels": {"wifi_service": "Wi-Fi"}},
        "traffic_guard": {"mode": "off", "domains": {}},
        "detected_environment": {"privoxy": {
            "config_path": str(config_path),
            "backup": str(backup_path),
            "management": {"mode": "managed", "managed": True, "provenance": "overwrote"},
        }},
        "runtime": {},
    }), encoding="utf-8")

    runner = FakeRunner()
    choice = {"managed": None, "skipped": "skip", "adopted": "adopt"}[mode]
    choices = {"xray": "skip", "dnsmasq": "skip"}
    if choice:
        choices["privoxy"] = choice
    result = install_lib.apply_install(
        env=env, confirm=True, choices=choices,
        runner=runner, port_checker=_port_checker_managed_up(runner.calls))
    assert result["ok"] is True
    assert _entry(env).get("backup") == str(backup_path), f"mode={mode} обязан сохранить backup"


def test_backup_reference_does_not_survive_config_path_change(tmp_path):
    """Негативный близнец инварианта: другой config_path — backup НЕ переносится (path-ownership)."""
    env = _env(tmp_path)
    new_config_path = env.component_paths("privoxy")["config"]
    new_config_path.parent.mkdir(parents=True)
    new_config_path.write_text("# srouter-managed-config-v1\nlisten-address 127.0.0.1:8118\n", encoding="utf-8")
    old_config_path = tmp_path / "old-prefix" / "privoxy" / "config"
    backup_of_old = tmp_path / "old-prefix-backup"
    backup_of_old.write_text("foreign config from prefix A\n", encoding="utf-8")
    env.state_path.write_text(json.dumps({
        "schema_version": 1, "nodes": [], "active_node": {"name": None, "pending": None},
        "probes": {}, "network": {"channels": {"wifi_service": "Wi-Fi"}},
        "traffic_guard": {"mode": "off", "domains": {}},
        "detected_environment": {"privoxy": {
            "config_path": str(old_config_path),
            "backup": str(backup_of_old),
            "management": {"mode": "managed", "managed": True, "provenance": "overwrote"},
        }},
        "runtime": {},
    }), encoding="utf-8")

    runner = FakeRunner()
    result = install_lib.apply_install(
        env=env, confirm=True, choices={"xray": "skip", "dnsmasq": "skip"},
        runner=runner, port_checker=_port_checker_managed_up(runner.calls))
    assert result["ok"] is True
    assert _entry(env).get("backup") != str(backup_of_old)


# ============================ T2/T3/T6: uninstall восстанавливает, а не теряет ============================


def test_uninstall_after_mid_apply_crash_restores_original(tmp_path, monkeypatch):
    """P1-3 дословно: обрыв mid-apply → uninstall ОБЯЗАН восстановить оригинал, не бросить orphaned.

    Сегодня: state-entry нет → managed=False → restorable=False → статус «unmanaged — left untouched»
    → srouter-конфиг остаётся на месте, а оригинал пользователя навсегда orphaned в backup-файле,
    про который никто не знает. Это самый дорогой из 6 P1 — молчаливая потеря чужого конфига.
    """
    env, config_path = _foreign_privoxy(tmp_path)
    _crash_after(monkeypatch, "_write_component_config", component="privoxy")
    with pytest.raises(_Crash):
        _apply_overwrite_privoxy(env)
    assert install_lib.MARKER in config_path.read_text(encoding="utf-8"), "target перезаписан srouter'ом"

    result = install_lib.apply_uninstall(
        env=env, confirmations={"configs": True}, runner=FakeRunner())

    assert result["ok"] is True, f"uninstall не должен падать на остатках оборванного apply: {result}"
    assert config_path.read_text(encoding="utf-8") == "foreign config\n", (
        "оригинал пользователя обязан быть восстановлен: backup лежит рядом с target и доказывает "
        "overwrite даже при пустом state (issue #124, P1-3)"
    )


def test_uninstall_never_deletes_config_when_backup_exists_on_disk(tmp_path):
    """F2/P1-1: state деградировал до provenance='created', но диск доказывает overwrite → restore.

    Сценарий: прошлый apply перезаписал чужой конфиг (backup на диске), затем idempotent reinstall /
    обрыв деградировал entry до 'created' без ссылки на backup. Сегодня removable=True →
    _delete_component_config УДАЛЯЕТ srouter-конфиг, и оригинал остаётся orphaned навсегда.
    Диск — доказательство, state — память; при расхождении побеждает доказательство.
    """
    env = _env(tmp_path)
    config_path = env.component_paths("privoxy")["config"]
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        "# srouter-managed-config-v1\nlisten-address 127.0.0.1:8118\n", encoding="utf-8")
    backup = config_path.with_name("config.srouter-backup-2026-06-29T000000Z")
    backup.write_text("foreign config\n", encoding="utf-8")
    env.state_path.write_text(json.dumps({
        "schema_version": 1, "nodes": [], "active_node": {"name": None, "pending": None},
        "probes": {}, "network": {"channels": {"wifi_service": "Wi-Fi"}},
        "traffic_guard": {"mode": "off", "domains": {}},
        "detected_environment": {"privoxy": {
            "config_path": str(config_path),
            # backup ПОТЕРЯН из state, provenance деградировал до 'created'
            "management": {"mode": "managed", "managed": True, "provenance": "created"},
        }},
        "runtime": {},
    }), encoding="utf-8")

    result = install_lib.apply_uninstall(
        env=env, confirmations={"configs": True}, runner=FakeRunner())

    assert result["ok"] is True
    assert config_path.exists(), (
        "нельзя УДАЛЯТЬ конфиг, когда рядом лежит валидный backup: это доказательство overwrite, "
        "а не created (issue #124, F2/P1-1)"
    )
    assert config_path.read_text(encoding="utf-8") == "foreign config\n", (
        "диск доказывает overwrote → restore оригинала, а не delete по деградировавшему state"
    )


def test_multiple_disk_backups_block_uninstall_as_ambiguous(tmp_path):
    """Политика >1 backup: НЕ угадывать «самый свежий», а сообщить оператору (fail-closed).

    Автовыбор свежего терял бы оригинал молча: при обрыве во ВТОРОМ install самый свежий backup — это
    копия srouter-конфига, а оригинал пользователя лежит в самом СТАРОМ. Угадывание здесь имеет ровно
    тот же класс последствий, что и дефект, который мы чиним.
    """
    env = _env(tmp_path)
    config_path = env.component_paths("privoxy")["config"]
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        "# srouter-managed-config-v1\nlisten-address 127.0.0.1:8118\n", encoding="utf-8")
    older = config_path.with_name("config.srouter-backup-2026-06-01T000000Z")
    older.write_text("original user config\n", encoding="utf-8")
    newer = config_path.with_name("config.srouter-backup-2026-06-29T000000Z")
    newer.write_text("# srouter-managed-config-v1\nsrouter copy\n", encoding="utf-8")
    env.state_path.write_text(json.dumps({
        "schema_version": 1, "nodes": [], "active_node": {"name": None, "pending": None},
        "probes": {}, "network": {"channels": {"wifi_service": "Wi-Fi"}},
        "traffic_guard": {"mode": "off", "domains": {}},
        # state МОЛЧИТ про backup — не на что опереться как на tie-breaker
        "detected_environment": {},
        "runtime": {},
    }), encoding="utf-8")

    result = install_lib.apply_uninstall(
        env=env, confirmations={"configs": True}, runner=FakeRunner())

    assert result["ok"] is True, "неоднозначность не должна крашить uninstall"
    assert any(item["name"] == "privoxy" for item in result.get("leftover") or []), (
        "неоднозначный набор backup'ов обязан попасть в leftover (rc=2), а не разрешаться угадыванием"
    )
    assert config_path.read_text(encoding="utf-8").startswith("# srouter-managed-config-v1"), \
        "при неоднозначности конфиг не трогаем"
    assert older.read_text(encoding="utf-8") == "original user config\n", "backup'ы не удаляются"
    assert newer.exists()


def test_uninstall_reports_leftover_when_state_backup_vanished(tmp_path):
    """cycle-review: state обещает backup, которого нет на диске → leftover (rc=2), не молчание.

    Молчание здесь — обман того же класса, что #110 Дефект 1: оператор увидел бы «Откат завершён»,
    а srouter-конфиг остался бы лежать поверх невосстановимого оригинала. Восстанавливать нечем,
    удалять вслепую нельзя — единственный честный исход громко сообщить.
    """
    env = _env(tmp_path)
    config_path = env.component_paths("privoxy")["config"]
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        "# srouter-managed-config-v1\nlisten-address 127.0.0.1:8118\n", encoding="utf-8")
    env.state_path.write_text(json.dumps({
        "schema_version": 1, "nodes": [], "active_node": {"name": None, "pending": None},
        "probes": {}, "network": {"channels": {"wifi_service": "Wi-Fi"}},
        "traffic_guard": {"mode": "off", "domains": {}},
        "detected_environment": {"privoxy": {
            "config_path": str(config_path),
            "backup": str(tmp_path / "vanished.backup"),  # файла НЕТ
            "management": {"mode": "managed", "managed": True, "provenance": "overwrote"},
        }},
        "runtime": {},
    }), encoding="utf-8")

    result = install_lib.apply_uninstall(
        env=env, confirmations={"configs": True}, runner=FakeRunner())

    assert result["ok"] is True
    assert any(item["name"] == "privoxy" for item in result["leftover"]), (
        "мёртвая ссылка на backup обязана попасть в leftover (rc=2) — молчание = ложный «откат завершён»"
    )
    assert config_path.exists(), "конфиг не удаляем: восстановить нечем, но и терять нельзя"


def test_dead_state_backup_is_not_substituted_by_stray_neighbour(tmp_path):
    """cycle-review P1: state НАЗВАЛ backup, файл мёртв → НЕ подставлять случайного соседа молча.

    Дыра была в `len(discovered) == 1`: ветка возвращала единственного найденного кандидата, ни разу
    не сверившись с тем, что назвал state. Сценарий реален — старые .srouter-backup-* никто не
    удаляет (build_uninstall_plan сам декларирует их в user_data_retained), поэтому ровно один
    посторонний сосед — рядовая ситуация. Итог: uninstall восстанавливал ЧУЖОЙ контент поверх
    конфига и докладывал ok=True с пустым leftover — «откат завершён» вместо правды.

    Discovery существует, чтобы восполнить МОЛЧАНИЕ state (обрыв до записи), а не переспорить его.
    """
    env = _env(tmp_path)
    config_path = env.component_paths("privoxy")["config"]
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("# srouter-managed-config-v1\nsrouter current\n", encoding="utf-8")
    stale = config_path.with_name("config.srouter-backup-2020-01-01T000000Z")
    stale.write_text("STALE UNRELATED CONTENT\n", encoding="utf-8")
    env.state_path.write_text(json.dumps({
        "schema_version": 1, "nodes": [], "active_node": {"name": None, "pending": None},
        "probes": {}, "network": {"channels": {"wifi_service": "Wi-Fi"}},
        "traffic_guard": {"mode": "off", "domains": {}},
        "detected_environment": {"privoxy": {
            "config_path": str(config_path),
            "backup": str(tmp_path / "vanished.backup"),  # state назвал ДРУГОЙ файл, и его нет
            "management": {"mode": "managed", "managed": True, "provenance": "overwrote"},
        }},
        "runtime": {},
    }), encoding="utf-8")

    result = install_lib.apply_uninstall(
        env=env, confirmations={"configs": True}, runner=FakeRunner())

    assert result["ok"] is True
    assert config_path.read_text(encoding="utf-8") != "STALE UNRELATED CONTENT\n", (
        "посторонний сосед НЕ должен подменять названный state backup — это тихое восстановление "
        "чужого контента под видом успешного отката"
    )
    assert any(item["name"] == "privoxy" for item in result["leftover"]), (
        "мёртвая ссылка обязана попасть в leftover (rc=2), а не маскироваться подстановкой"
    )


def test_uninstall_reports_leftover_for_marked_config_without_any_history(tmp_path):
    """Регресс-гвард: маркер жив, записи в state нет, backup'ов нет → leftover, не молчание.

    Эту ветку потеряла правка предыдущего раунда cycle-review (условие сузилось на
    state_backup_missing и перестало ловить «истории нет вообще»). Классификация редьюсера была
    верной всё это время — терялся именно доклад оператору, то есть ровно то, что чиним.
    """
    env = _env(tmp_path)
    config_path = env.component_paths("privoxy")["config"]
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("# srouter-managed-config-v1\nours\n", encoding="utf-8")
    env.state_path.write_text(json.dumps({
        "schema_version": 1, "nodes": [], "active_node": {"name": None, "pending": None},
        "probes": {}, "network": {"channels": {"wifi_service": "Wi-Fi"}},
        "traffic_guard": {"mode": "off", "domains": {}},
        "detected_environment": {},  # записи нет вовсе
        "runtime": {},
    }), encoding="utf-8")

    result = install_lib.apply_uninstall(
        env=env, confirmations={"configs": True}, runner=FakeRunner())

    assert result["ok"] is True
    assert any(item["name"] == "privoxy" for item in result["leftover"]), (
        "наш конфиг (маркер) без истории — не откатан; молчание = ложный «Откат завершён»"
    )
    assert config_path.exists(), "удалять вслепую нельзя — восстанавливать нечем"


def test_uninstall_does_not_report_foreign_config_with_stray_backups(tmp_path):
    """Граница #110 сквозь весь поток: чужой конфиг + похожие по имени файлы → НЕ leftover, rc=0.

    Регресс-гвард к порядку проверок в component_facts: ambiguous не должен срабатывать раньше, чем
    подтверждено право трогать файл. Иначе «чужое рядом» шумело бы как частичный откат.
    """
    env = _env(tmp_path)
    config_path = _write_config_without_marker(env, "privoxy", content="foreign config\n")
    for stamp in ("2026-06-01T000000Z", "2026-06-29T000000Z"):
        config_path.with_name(f"config.srouter-backup-{stamp}").write_text("stray\n", encoding="utf-8")
    env.state_path.write_text(json.dumps({
        "schema_version": 1, "nodes": [], "active_node": {"name": None, "pending": None},
        "probes": {}, "network": {"channels": {"wifi_service": "Wi-Fi"}},
        "traffic_guard": {"mode": "off", "domains": {}},
        "detected_environment": {}, "runtime": {},
    }), encoding="utf-8")

    result = install_lib.apply_uninstall(
        env=env, confirmations={"configs": True}, runner=FakeRunner())

    assert result["ok"] is True
    assert result["leftover"] == [], "true-foreign не становится partial-откатом из-за соседних файлов"
    assert config_path.read_text(encoding="utf-8") == "foreign config\n", "чужой конфиг не тронут"


# ============================ T7: discovery не принимает чужое за своё ============================


def test_backup_discovery_rejects_lookalikes(tmp_path):
    """discover_backups fail-closed: похожее имя ещё не делает файл нашим backup'ом.

    glob('config.srouter-backup-*') поймал бы и хвостовой .tmp от атомарной записи, и вложенный
    двойной суффикс. Симлинк с валидным именем — вектор подмены: restore записал бы содержимое по
    чужому пути. Поэтому: fullmatch с якорем + парсящийся timestamp формата _backup + regular file.
    """
    target = tmp_path / "config"
    target.write_text("x\n", encoding="utf-8")
    (tmp_path / "config.srouter-backup-2026-06-29T000000Z.tmp").write_text("t\n", encoding="utf-8")
    (tmp_path / "config.srouter-backup-notatimestamp").write_text("n\n", encoding="utf-8")
    (tmp_path / "config.json.srouter-backup-2026-06-29T000000Z").write_text("o\n", encoding="utf-8")
    (tmp_path / "config.srouter-backup-2026-06-29T000001Z").mkdir()
    victim = tmp_path / "victim"
    victim.write_text("secret\n", encoding="utf-8")
    (tmp_path / "config.srouter-backup-2026-06-29T000002Z").symlink_to(victim)

    found = install_lib.discover_backups(target)

    assert found == [], f"ни один lookalike не должен быть принят за backup: {found}"


def test_backup_discovery_finds_real_backup(tmp_path):
    """Позитивный контроль к предыдущему: настоящий backup обязан находиться (иначе гвард false-green)."""
    target = tmp_path / "config"
    target.write_text("x\n", encoding="utf-8")
    real = tmp_path / "config.srouter-backup-2026-06-29T000000Z"
    real.write_text("foreign config\n", encoding="utf-8")

    assert install_lib.discover_backups(target) == [real]
