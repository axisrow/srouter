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


# ============= cycle-review этого PR (Codex + /review независимо): retained backup через два ============
# ============================ полных install→uninstall→install→uninstall цикла ============================


def test_two_full_lifecycles_do_not_resurrect_stale_config(tmp_path):
    """P1: retained backup от ЗАВЕРШЁННОГО цикла не должен всплыть в СЛЕДУЮЩЕМ цикле как «оригинал».

    End-to-end через реальные apply_install/apply_uninstall (не мок редьюсера напрямую — доказывает,
    что фикс держится по всей цепочке: _backup → _write_state_after_apply(created_at) →
    component_facts(not_before) → apply_uninstall).

    Цикл 1: install перезаписывает чужой config A (backup создан) → uninstall восстанавливает A,
    backup остаётся на диске (user_data_retained — политика намеренная, не баг).
    Пользователь вручную удаляет восстановленный A.
    Цикл 2: install создаёт конфиг с нуля (provenance='created', backup не пишется — нечего было
    бэкапить). БЕЗ фикса: uninstall нашёл бы retained backup цикла 1 как единственного кандидата и
    восстановил бы устаревшее содержимое A вместо удаления свежесозданного конфига.
    """
    env1 = _env(tmp_path)
    config_path = _write_config_without_marker(env1, "privoxy", content="FOREIGN-CONTENT-A\n")

    runner1 = FakeRunner()
    result1 = install_lib.apply_install(
        env=env1, confirm=True,
        choices={"privoxy": "overwrite", "xray": "skip", "dnsmasq": "skip"},
        runner=runner1, port_checker=_port_checker_managed_up(runner1.calls))
    assert result1["ok"] is True
    retained_backups = list(config_path.parent.glob("config.srouter-backup-*"))
    assert retained_backups, "цикл 1 обязан создать backup оригинала A"

    result_restore = install_lib.apply_uninstall(
        env=env1, confirmations={"configs": True}, runner=FakeRunner())
    assert result_restore["ok"] is True
    assert config_path.read_text(encoding="utf-8") == "FOREIGN-CONTENT-A\n"
    assert retained_backups[0].exists(), "backup остаётся на диске после restore (user_data_retained)"

    config_path.unlink()  # пользователь вручную удалил восстановленный файл

    env2 = install_lib.InstallEnv(
        root=env1.root, prefix=env1.prefix, state_path=env1.state_path,
        launchagent_dir=env1.launchagent_dir, now="2026-07-15T00:00:00Z")
    runner2 = FakeRunner()
    result2 = install_lib.apply_install(
        env=env2, confirm=True,
        choices={"privoxy": "overwrite", "xray": "skip", "dnsmasq": "skip"},
        runner=runner2, port_checker=_port_checker_managed_up(runner2.calls))
    assert result2["ok"] is True
    state2 = json.loads(env2.state_path.read_text(encoding="utf-8"))
    entry2 = state2["detected_environment"]["privoxy"]
    assert entry2["management"]["provenance"] == "created", entry2
    # После слияния с частью 2/2: preserve-логика carried_backup переносит backup НЕЗАВИСИМО от
    # provenance (round-2 фикс F3/P1-2 — backup не исчезает от смены РЕЖИМА). Здесь меняется не
    # режим, а сам ЖИЗНЕННЫЙ ЦИКЛ конфига (created = target создан с нуля), поэтому entry2 честно
    # несёт УСТАРЕВШИЙ backup_1 как «память» — но это безопасно: _resolve_backup применяет
    # not_before (created_at) СИММЕТРИЧНО к stated-ветке (не только к discovered), поэтому при
    # чтении entry для recovery-решения устаревший pointer отбрасывается. Проверяем это напрямую.
    facts = install_lib.component_facts("privoxy", env2, entry2)
    assert facts["recovery"] == "remove", (
        f"not_before обязан отсечь устаревший backup_1 из entry2 при вычислении recovery: {facts}"
    )
    assert facts["backup"] == "", "устаревший stated backup не должен считаться доказательством"

    result_uninstall2 = install_lib.apply_uninstall(
        env=env2, confirmations={"configs": True}, runner=FakeRunner())
    assert result_uninstall2["ok"] is True
    assert not config_path.exists(), (
        "свежесозданный конфиг обязан быть УДАЛЁН (provenance='created'), а не заменён устаревшим "
        "содержимым retained-backup'а из ЗАВЕРШЁННОГО предыдущего install-цикла (issue #124 cycle-review P1)"
    )


# ============= cycle-review этого PR, round 2 (Codex): устаревший adopted/restored и ============
# ============= services/DNS, оставленные активными для orphaned_backup-компонента ============


def test_overwrite_after_adopt_survives_crash_before_state_write(tmp_path, monkeypatch):
    """P1 (Codex round 2): explicit overwrite ПОСЛЕ adopt не должен теряться на устаревшем entry.

    Компонент был adopted (state.mode='adopted') → пользователь ЯВНО выбирает overwrite в следующем
    apply (choices не смотрят на prev-state — adopted НЕ блокирует выбор overwrite, mode строится
    только из choices.get(name)) → target реально перезаписан srouter'ом (маркер жив), backup
    adopted-оригинала создан → crash ДО финальной _write_state_after_apply оставляет entry со старым
    mode='adopted'. Без фикса component_facts короткое замыкание на устаревшем adopted=True
    игнорировало бы живой маркер и backup — uninstall репортил бы «adopted — left untouched»,
    оставляя srouter-конфиг и осиротив backup истинного adopted-оригинала НАВСЕГДА.
    """
    env = _env(tmp_path)
    config_path = env.component_paths("privoxy")["config"]
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("ADOPTED-BY-USER\n", encoding="utf-8")

    runner1 = FakeRunner()
    result1 = install_lib.apply_install(
        env=env, confirm=True,
        choices={"privoxy": "adopt", "xray": "skip", "dnsmasq": "skip"},
        runner=runner1, port_checker=_port_checker_managed_up(runner1.calls))
    assert result1["ok"] is True

    _crash_after(monkeypatch, "_write_component_config", component="privoxy")
    runner2 = FakeRunner()
    with pytest.raises(_Crash):
        install_lib.apply_install(
            env=env, confirm=True,
            choices={"privoxy": "overwrite", "xray": "skip", "dnsmasq": "skip"},
            runner=runner2, port_checker=_port_checker_managed_up(runner2.calls))

    assert install_lib.MARKER in config_path.read_text(encoding="utf-8"), "target перезаписан srouter'ом"
    stale_backups = list(config_path.parent.glob("config.srouter-backup-*"))
    assert stale_backups, "overwrite создал backup adopted-оригинала перед перезаписью"

    result = install_lib.apply_uninstall(
        env=env, confirmations={"configs": True}, runner=FakeRunner())
    assert result["ok"] is True
    assert config_path.read_text(encoding="utf-8") == "ADOPTED-BY-USER\n", (
        "живой маркер + backup обязаны перебить устаревший adopted=True — иначе adopted-оригинал "
        "orphaned навсегда, а srouter-конфиг остаётся на месте без единого предупреждения"
    )


def test_uninstall_stops_service_and_resets_dns_for_orphaned_backup(tmp_path, monkeypatch):
    """P1 (Codex round 2): orphaned_backup обязан останавливать сервис/сбрасывать DNS, не только конфиг.

    Обрыв ПОСЛЕ _restart_component (сервис реально перезапущен на srouter-конфиг), но ДО финальной
    записи state — entry пуст, managed=False. Секции services/dns apply_uninstall раньше гейтились
    ТОЛЬКО на managed, который для orphaned_backup всегда False (пустой state-entry, не отсутствие
    реального restart/apply_dns). Итог без фикса: configs-секция восстанавливает файл (restorable=True
    работает), а сервис остаётся крутиться на только что удалённый с диска srouter-конфиг, DNS — на
    127.0.0.1, при report ok=True — тихий privacy/availability риск поверх «успешного» отката.
    """
    env, config_path = _foreign_privoxy(tmp_path)
    _crash_after(monkeypatch, "_restart_component", component="privoxy")
    runner = FakeRunner()
    with pytest.raises(_Crash):
        install_lib.apply_install(
            env=env, confirm=True,
            choices={"privoxy": "overwrite", "xray": "skip", "dnsmasq": "skip"},
            runner=runner, port_checker=_port_checker_managed_up(runner.calls))

    restart_calls = [c for c in runner.calls if "services" in c]
    assert restart_calls, "install реально перезапустил privoxy до обрыва"
    # После слияния с частью 2/2 (state-first): _record_backup_intent пишет ГОЛЫЙ entry
    # ({config_path, backup}, без management) сразу после _backup, до мутации target — entry уже НЕ
    # пуст на этой точке обрыва. managed по-прежнему False (голый entry инертен для _is_managed_entry),
    # так что orphaned_backup-классификация и весь сценарий теста остаются в силе — изменилось только
    # ЧТО именно лежит в state к моменту обрыва, не смысл проверки managed/restorable гейта ниже.
    entry_at_crash = _entry(env)
    assert entry_at_crash.get("backup"), "state-first (часть 2/2) уже знает про backup к этой точке"
    assert "management" not in entry_at_crash, "голый intent-entry не несёт management (часть 2/2)"

    uninstall_runner = FakeRunner()
    result = install_lib.apply_uninstall(
        env=env, confirmations={"configs": True, "services": True, "dns": True},
        runner=uninstall_runner)
    assert result["ok"] is True
    assert config_path.read_text(encoding="utf-8") == "foreign config\n"

    stop_calls = [c for c in uninstall_runner.calls if "stop" in c and "privoxy" in c]
    assert stop_calls, (
        "restorable=True (orphaned_backup) обязан останавливать реально запущенный сервис, а не "
        "оставлять его крутиться на конфиг, которого только что не стало на диске (Codex round 2 P1)"
    )


class _WifiAwareRunner(FakeRunner):
    """FakeRunner + Wi-Fi service в _discover_network — иначе _apply_dns/_restore_dns короткое
    замыкание на "wifi service not found" ДО проверки managed/restorable гейта, и мутация,
    ломающая именно этот гейт, останется незамеченной."""

    def __call__(self, cmd, timeout):
        if list(cmd) == [install_config.NETWORKSETUP, "-listallnetworkservices"]:
            self.calls.append(list(cmd))
            return {"rc": 0, "out": "Wi-Fi\n", "err": "", "timeout": False}
        return super().__call__(cmd, timeout)


def test_uninstall_resets_dns_for_orphaned_backup_dnsmasq(tmp_path, monkeypatch):
    """P1 (Codex round 2), симметрично сервисам: orphaned_backup dnsmasq обязан сбрасывать DNS.

    _restore_dns раньше гейтился ТОЛЬКО на managed, который для orphaned_backup всегда False (пустой
    state-entry — обрыв ДО финальной записи, а не отсутствие реального _apply_dns). Обрыв ПОСЛЕ
    _apply_dns (DNS реально указывает на 127.0.0.1), но до финальной записи state → без фикса
    uninstall восстановил бы конфиг, но НЕ сбросил DNS — privacy-риск поверх report ok=True.

    Требует bootstrap-шаг (успешный apply ДО обрыва): state['network']['channels']['wifi_service']
    пишется ТОЛЬКО в финальном _write_state_after_apply, поэтому «холодный» первый-ever apply без
    предыстории не даёт _restore_dns узнать сервис вообще — отдельное, более глубокое ограничение
    (build_uninstall_plan осознанно read-only, `del runner`, не переоткрывает network заново), не
    входящее в scope этого фикса. Здесь тестируется типичный случай: N-ный apply после хотя бы
    одного успешного bootstrap, что и покрывает заявленный Codex сценарий.
    """
    env, _config_path = _foreign_privoxy(tmp_path)
    dnsmasq_config = env.component_paths("dnsmasq")["config"]
    dnsmasq_config.parent.mkdir(parents=True, exist_ok=True)
    dnsmasq_config.write_text("foreign dnsmasq config\n", encoding="utf-8")

    # Bootstrap: успешный apply, фиксирующий wifi_service в state.network (симметрично тому, что
    # в реальном deployment apply уже происходил хотя бы раз до нового overwrite/reinstall).
    bootstrap_runner = _WifiAwareRunner()
    bootstrap = install_lib.apply_install(
        env=env, confirm=True,
        choices={"privoxy": "skip", "xray": "skip", "dnsmasq": "skip"},
        runner=bootstrap_runner, port_checker=_port_checker_managed_up(bootstrap_runner.calls))
    assert bootstrap["ok"] is True

    _crash_after(monkeypatch, "_apply_dns")
    runner = _WifiAwareRunner()
    with pytest.raises(_Crash):
        install_lib.apply_install(
            env=env, confirm=True,
            choices={"privoxy": "skip", "xray": "skip", "dnsmasq": "overwrite"},
            runner=runner, port_checker=_port_checker_managed_up(runner.calls))

    dns_calls_during_install = [c for c in runner.calls
                                 if install_config.NETWORKSETUP in c and "127.0.0.1" in c]
    assert dns_calls_during_install, "install реально применил DNS=127.0.0.1 до обрыва"
    stale_entry = _entry(env, "dnsmasq")
    assert stale_entry.get("management", {}).get("mode") == "skipped", (
        "state-entry несёт mode ИЗ BOOTSTRAP'а (skipped) — второй apply оборвался ДО финальной "
        "записи, значит его managed='overwrote' entry не попал в state вовсе"
    )

    uninstall_runner = _WifiAwareRunner()
    result = install_lib.apply_uninstall(
        env=env, confirmations={"configs": True, "services": True, "dns": True},
        runner=uninstall_runner)
    assert result["ok"] is True
    assert dnsmasq_config.read_text(encoding="utf-8") == "foreign dnsmasq config\n"

    dns_reset_calls = [c for c in uninstall_runner.calls
                        if install_config.NETWORKSETUP in c and "Empty" in c]
    assert dns_reset_calls, (
        "restorable=True (orphaned_backup) обязан сбрасывать DNS, а не оставлять его указывать на "
        "127.0.0.1 после того, как srouter-конфиг уже удалён с диска (Codex round 2 P1)"
    )


# ==================================================================================================
# cycle-review этого PR, round 3 (Codex): ТРЕТИЙ подряд FIX-цикл того же класса дефекта — устаревшее
# ИЛИ неполное state, оставшееся от обрыва ДО финальной _write_state_after_apply, трактуется как
# истина без проверки актуальности. Round 1 закрыл это для backup discovery (not_before/created_at),
# round 2 — для adopted/restored mode и managed-гейта в services/dns. Round 3 нашёл ТУ ЖЕ болезнь в
# ДВУХ полях, которые предыдущие раунды не трогали: (а) сам backup-pointer в state.entry может быть
# УСТАРЕВШИМ (указывать не на последний backup, а на backup из более раннего цикла) даже когда режим
# уже корректно распознан как orphaned_backup; (б) state['network']['channels'] пуст на «холодном»
# первом-ever apply, обрывающемся до финальной записи, — DNS-сброс no-op'ится молча.
#
# По канону cycle-review "3-cycle cap = сигнал, не просто лимит": это НЕ 7-й точечный патч, а сигнал
# нарушенного ИНВАРИАНТА — batched-at-tail-end запись state трактуется как proof of recency для полей,
# чей реальный side-effect произошёл РАНЬШЕ этой записи. Каждый раунд закрывал ОДНО конкретное поле
# (backup-приоритет → mode-устаревание → и вот снова: backup-freshness + network-cache) — это открытое
# перечисление полей, а не структурное решение. Согласно правилу, здесь остановка на диагнозе, а не
# четвёртый патч: xfail(strict=True) пиннит обе находки для решения пользователем (закрыть точечно /
# перейти на per-effect durability вместо batched-записи / вынести в explicit follow-up issue).


def test_stale_restored_backup_pointer_loses_user_edits_after_manual_edit(tmp_path, monkeypatch):
    """round-3 P1a — ЗАКРЫТ композицией части 2/2 (state-first) + доп. фикс not_before на stated.

    Найден Codex round 3 как незакрытый P1 в install-половине (часть 1/2 одна). После слияния с
    частью 2/2: _record_backup_intent пишет ссылку на backup СРАЗУ после создания backup_2 (до
    финальной записи state) — entry больше не остаётся «замороженным» на backup_1. Плюс: not_before
    (created_at) в _resolve_backup применяется теперь СИММЕТРИЧНО и к названному state backup (не
    только к discovered) — устаревший stated-pointer из более раннего цикла того же пути отсекается
    так же, как retained-relic в discovery. xfail-маркер снят: тест был XPASS(strict) после слияния —
    исходный docstring ниже описывает сценарий-нарушитель, который теперь не воспроизводится.

    Сценарий: install overwrite foreign A (backup_1) → uninstall restore A (entry: mode='restored',
    backup=backup_1) → пользователь ВРУЧНУЮ редактирует восстановленный файл (не через install) →
    новый apply overwrite создаёт backup_2 (копию правок пользователя) → crash ДО финальной записи
    state. Раньше: entry всё ещё указывал на backup_1, _resolve_backup брал его безусловно. Теперь:
    _record_backup_intent уже обновил ссылку на backup_2 до крэша.
    """
    env = _env(tmp_path)
    config_path = env.component_paths("privoxy")["config"]
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("ORIGINAL-FOREIGN\n", encoding="utf-8")

    runner1 = FakeRunner()
    result1 = install_lib.apply_install(
        env=env, confirm=True,
        choices={"privoxy": "overwrite", "xray": "skip", "dnsmasq": "skip"},
        runner=runner1, port_checker=_port_checker_managed_up(runner1.calls))
    assert result1["ok"] is True
    backup_1 = _entry(env).get("backup")
    assert backup_1, "backup_1 обязан быть записан после первого overwrite"

    result2 = install_lib.apply_uninstall(
        env=env, confirmations={"configs": True}, runner=FakeRunner())
    assert result2["ok"] is True
    assert config_path.read_text(encoding="utf-8") == "ORIGINAL-FOREIGN\n"

    config_path.write_text("EDITED-BY-USER\n", encoding="utf-8")  # пользователь редактирует вручную

    env2 = install_lib.InstallEnv(
        root=env.root, prefix=env.prefix, state_path=env.state_path,
        launchagent_dir=env.launchagent_dir, now="2026-06-29T00:10:00Z")
    _crash_after(monkeypatch, "_write_component_config", component="privoxy")
    runner3 = FakeRunner()
    with pytest.raises(_Crash):
        install_lib.apply_install(
            env=env2, confirm=True,
            choices={"privoxy": "overwrite", "xray": "skip", "dnsmasq": "skip"},
            runner=runner3, port_checker=_port_checker_managed_up(runner3.calls))

    backups_on_disk = install_config.discover_backups(config_path)
    assert len(backups_on_disk) == 2, "backup_1 (ORIGINAL) и backup_2 (EDITED) обязаны сосуществовать"
    backup_2_path = next(p for p in backups_on_disk if str(p) != backup_1)
    assert backup_2_path.read_text(encoding="utf-8") == "EDITED-BY-USER\n"

    install_lib.apply_uninstall(env=env2, confirmations={"configs": True}, runner=FakeRunner())

    assert config_path.read_text(encoding="utf-8") == "EDITED-BY-USER\n", (
        "самый свежий backup (пользовательские правки) обязан быть восстановлен, а не устаревший "
        "pointer из предыдущего restored-цикла"
    )


@pytest.mark.xfail(strict=True, reason=(
    "cycle-review round 3 (Codex), issue #124: на «холодном» первом-ever apply (нет state-файла "
    "вовсе до этого apply) crash после _apply_dns оставляет DNS указывающим на 127.0.0.1, а "
    "state['network']['channels'] никогда не был записан (пишется только финальной "
    "_write_state_after_apply). apply_uninstall останавливает dnsmasq (services-гейт round 2 работает "
    "корректно через restorable), но _restore_dns не может найти wifi_service в пустых channels → "
    "no-op, DNS не сбрасывается, при этом report ok=True — полный DNS outage под видом успеха. "
    "3-й подряд FIX-цикл того же класса — остановка на диагнозе по правилу 3-cycle cap."))
def test_cold_start_crash_after_apply_dns_leaves_dns_broken_reported_ok(tmp_path, monkeypatch):
    """round-3 P1: холодный старт (нет state вовсе) — DNS не сбрасывается, хотя сервис остановлен.

    В отличие от test_uninstall_resets_dns_for_orphaned_backup_dnsmasq (есть bootstrap-шаг, поэтому
    state.network уже заполнен от предыдущего успешного apply), здесь state_path вообще не существует
    до этого apply — типичный первый запуск install на чистой машине.
    """
    env = _env(tmp_path)
    assert not env.state_path.exists(), "precondition: ни одного успешного apply раньше не было"

    _write_config_without_marker(env, "privoxy")
    dnsmasq_config = env.component_paths("dnsmasq")["config"]
    dnsmasq_config.parent.mkdir(parents=True, exist_ok=True)
    dnsmasq_config.write_text("foreign dnsmasq config\n", encoding="utf-8")

    _crash_after(monkeypatch, "_apply_dns")
    runner = _WifiAwareRunner()
    with pytest.raises(_Crash):
        install_lib.apply_install(
            env=env, confirm=True,
            choices={"privoxy": "skip", "xray": "skip", "dnsmasq": "overwrite"},
            runner=runner, port_checker=_port_checker_managed_up(runner.calls))

    dns_calls_during_install = [c for c in runner.calls
                                 if install_config.NETWORKSETUP in c and "127.0.0.1" in c]
    assert dns_calls_during_install, "install реально применил DNS=127.0.0.1 до обрыва"
    assert not env.state_path.exists(), "холодный старт: state-файл вообще не создан"

    uninstall_runner = _WifiAwareRunner()
    result = install_lib.apply_uninstall(
        env=env, confirmations={"configs": True, "services": True, "dns": True},
        runner=uninstall_runner)

    stop_calls = [c for c in uninstall_runner.calls if "stop" in c and "dnsmasq" in c]
    dns_reset_calls = [c for c in uninstall_runner.calls
                        if install_config.NETWORKSETUP in c and "Empty" in c]
    assert result["ok"] is True
    assert stop_calls, "dnsmasq реально остановлен (restorable=True путь работает)"
    assert dns_reset_calls, (
        "DNS обязан быть сброшен даже когда state['network']['channels'] пуст (холодный старт) — "
        "иначе dnsmasq остановлен, а DNS всё ещё указывает на 127.0.0.1, при report ok=True"
    )
