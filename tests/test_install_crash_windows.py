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


@pytest.mark.xfail(strict=True, reason=(
    "install-половина issue #124 (state-first): backup фиксируется в state ДО мутации target. "
    "Чинится в следующем PR; здесь тест закреплён как доказательство окна W4 в install-слое. "
    "strict=True — когда фикс приедет, xfail станет XPASS и заставит снять маркер."))
def test_crash_after_config_write_leaves_state_knowing_backup(tmp_path, monkeypatch):
    """W4 (главное окно): обрыв после записи target → state ОБЯЗАН уже знать про backup.

    Сегодня backup живёт только в локальном dict до финального _write_state_after_apply, который при
    обрыве не достигается: state-файл вообще не создаётся → ссылка на backup утеряна, хотя сам
    backup-файл лежит на диске. Это F1/P1-3 в install-половине.
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


@pytest.mark.xfail(strict=True, reason=(
    "install-половина issue #124 (state-first), тот же корень, что и у W4-теста выше: локальный dict "
    "backups испаряется при раннем return. Чинится в следующем PR; strict=True не даст забыть."))
def test_second_component_failure_preserves_first_component_backup(tmp_path, monkeypatch):
    """Дефект воспроизводится БЕЗ crash: штатный ранний return теряет backup уже обработанного.

    privoxy успешно перезаписан (backup создан), затем `brew install dnsmasq` штатно падает →
    apply_install делает ранний return `dnsmasq_install_failed`, минуя _write_state_after_apply.
    Локальный dict `backups` испаряется вместе с ссылкой на backup privoxy. Никаких исключений,
    никакого SIGKILL — рутинный сбой brew. Это доказывает, что окно не экзотика.
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
