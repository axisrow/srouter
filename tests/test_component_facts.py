"""Таблица вывода component_facts: три факта о мире → безопасное действие (issue #124).

Каждый кейс — строка таблицы из докстринга component_facts. Именно здесь доказывается, что шесть P1
issue #124 закрыты не шестью патчами, а одним правилом на каждую комбинацию: crash перестал быть
отдельным случаем — редьюсер вообще не знает, был ли он.

Канон verify-dont-guess: таблица проверяется целиком, включая строки, где правильный ответ —
«ничего не делать» (их пропуск и создавал бы молчаливую потерю).
"""
from pathlib import Path

import pytest

import install_lib

MANAGED_CONFIG = "# srouter-managed-config-v1\nlisten-address 127.0.0.1:8118\n"
FOREIGN_CONFIG = "foreign config\n"


def _env(tmp_path):
    return install_lib.InstallEnv(
        root=Path(__file__).resolve().parent.parent,
        prefix=tmp_path / "homebrew",
        state_path=tmp_path / "srouter.local.json",
        launchagent_dir=tmp_path / "LaunchAgents",
        now="2026-06-29T00:00:00Z",
    )


def _target(env, content=MANAGED_CONFIG, name="privoxy"):
    path = env.component_paths(name)["config"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _backup_next_to(target, stamp="2026-06-29T000000Z", content=FOREIGN_CONFIG):
    backup = target.with_name(f"{target.name}.srouter-backup-{stamp}")
    backup.write_text(content, encoding="utf-8")
    return backup


def _entry(target, *, mode="managed", managed=True, provenance=None, backup=None):
    management = {"mode": mode, "managed": managed}
    if provenance is not None:
        management["provenance"] = provenance
    entry = {"config_path": str(target), "management": management}
    if backup is not None:
        entry["backup"] = str(backup)
    return entry


def _facts(env, entry, name="privoxy"):
    return install_lib.component_facts(name, env, entry)


# ============================ строки таблицы ============================


def test_no_config_no_state_is_none(tmp_path):
    """Файла нет, истории нет — трогать нечего."""
    env = _env(tmp_path)
    assert _facts(env, {})["recovery"] == "none"


def test_foreign_config_without_state_is_none(tmp_path):
    """Чужой конфиг без нашей истории — легитимное соседство, не наше дело (канон «не adopt молча»)."""
    env = _env(tmp_path)
    _target(env, FOREIGN_CONFIG)
    assert _facts(env, {})["recovery"] == "none"


def test_managed_with_live_backup_is_restore(tmp_path):
    """Штатный overwrite: маркер + managed + живой backup → вернуть оригинал."""
    env = _env(tmp_path)
    target = _target(env)
    backup = _backup_next_to(target)
    facts = _facts(env, _entry(target, provenance="overwrote", backup=backup))
    assert facts["recovery"] == "restore"
    assert facts["backup"] == str(backup)


def test_managed_with_dead_backup_reference_is_leftover(tmp_path):
    """state обещает backup, которого на диске нет → не удалять вслепую, сообщить (fail-closed)."""
    env = _env(tmp_path)
    target = _target(env)
    entry = _entry(target, provenance="overwrote", backup=tmp_path / "gone.backup")
    facts = _facts(env, entry)
    assert facts["recovery"] == "leftover"
    assert facts["state_backup_missing"] is True


def test_dead_state_pointer_is_not_replaced_by_single_discovered(tmp_path):
    """cycle-review P1: state назвал backup и соврал → единственный найденный сосед НЕ подставляется.

    Приоритет: названное state сильнее найденного на диске. Discovery восполняет МОЛЧАНИЕ state,
    но не переспаривает его — иначе восстановился бы чужой контент под видом успешного отката.
    """
    env = _env(tmp_path)
    target = _target(env)
    _backup_next_to(target, "2020-01-01T000000Z", "STALE UNRELATED\n")
    entry = _entry(target, provenance="overwrote", backup=tmp_path / "vanished.backup")

    facts = _facts(env, entry)

    assert facts["state_backup_missing"] is True
    assert facts["recovery"] == "leftover", "мёртвая ссылка → доклад оператору, не тихая подстановка"
    assert facts["backup"] == "", "посторонний сосед не становится «тем самым» backup'ом"


def test_state_pointer_wins_over_discovered_when_alive(tmp_path):
    """Обратная сторона того же приоритета: живой названный backup используется, даже если рядом есть другой."""
    env = _env(tmp_path)
    target = _target(env)
    _backup_next_to(target, "2020-01-01T000000Z", "NOT THE ONE\n")
    stated = tmp_path / "explicit.backup"
    stated.write_text(FOREIGN_CONFIG, encoding="utf-8")

    facts = _facts(env, _entry(target, provenance="overwrote", backup=stated))

    assert facts["recovery"] == "restore"
    assert facts["backup"] == str(stated)


def test_managed_created_without_backup_is_remove(tmp_path):
    """Штатный created: srouter создал конфиг с нуля, восстанавливать нечего → удалить (issue #112)."""
    env = _env(tmp_path)
    target = _target(env)
    assert _facts(env, _entry(target, provenance="created"))["recovery"] == "remove"


def test_managed_created_but_backup_on_disk_is_restore(tmp_path):
    """F2/P1-1: state деградировал до 'created', но диск доказывает overwrite → restore, НЕ remove.

    Именно этот кейс сегодня удаляет srouter-конфиг и навсегда осиротяет оригинал пользователя.
    Диск — доказательство, state — память; при расхождении побеждает доказательство.
    """
    env = _env(tmp_path)
    target = _target(env)
    backup = _backup_next_to(target)
    facts = _facts(env, _entry(target, provenance="created"))
    assert facts["recovery"] == "restore", "backup на диске опровергает provenance='created'"
    assert facts["backup"] == str(backup)


def test_marker_and_backup_without_state_entry_is_orphaned_backup(tmp_path):
    """P1-3/F1: обрыв ДО записи state. Маркер доказывает «файл наш», backup — «было что перезаписать»."""
    env = _env(tmp_path)
    target = _target(env)
    backup = _backup_next_to(target)
    facts = _facts(env, {})
    assert facts["recovery"] == "orphaned_backup"
    assert facts["backup"] == str(backup)


def test_marker_without_state_and_without_backup_is_leftover(tmp_path):
    """Наш конфиг, но истории нет и backup нет — не гадаем: ни удалять, ни восстанавливать."""
    env = _env(tmp_path)
    _target(env)
    assert _facts(env, {})["recovery"] == "leftover"


def test_multiple_backups_without_state_hint_is_ambiguous(tmp_path):
    """>1 backup и state молчит → ambiguous. «Самый свежий» может быть копией srouter-конфига."""
    env = _env(tmp_path)
    target = _target(env)
    _backup_next_to(target, "2026-06-01T000000Z", "original user config\n")
    _backup_next_to(target, "2026-06-29T000000Z", MANAGED_CONFIG)
    facts = _facts(env, {})
    assert facts["recovery"] == "ambiguous"
    assert facts["backup"] == "", "при неоднозначности не выбираем кандидата"
    assert len(facts["discovered_backups"]) == 2


def test_multiple_backups_with_state_pointer_resolves(tmp_path):
    """>1 backup, но state указывает на конкретный → он и есть tie-breaker (не единственный источник)."""
    env = _env(tmp_path)
    target = _target(env)
    older = _backup_next_to(target, "2026-06-01T000000Z", "original user config\n")
    _backup_next_to(target, "2026-06-29T000000Z", MANAGED_CONFIG)
    facts = _facts(env, _entry(target, provenance="overwrote", backup=older))
    assert facts["recovery"] == "restore"
    assert facts["backup"] == str(older), "state разрешает неоднозначность в пользу СТАРОГО backup"


def test_true_foreign_with_stray_lookalike_backups_is_none(tmp_path):
    """cycle-review: маркера НЕТ и записи в state нет → none, СКОЛЬКО БЫ backup'ов рядом ни лежало.

    Порядок проверок — часть контракта: marker_present раньше ambiguous. Иначе чужой конфиг, рядом с
    которым остались похожие по имени файлы от давнего install по этому пути, классифицировался бы
    ambiguous → leftover → rc=2. Это нарушает границу #110 / cycle-review #111 cycle 2 finding B:
    «true-foreign (srouter не ставил) → НЕ leftover, чужое рядом легитимно».
    """
    env = _env(tmp_path)
    target = _target(env, FOREIGN_CONFIG)  # без srouter-маркера
    _backup_next_to(target, "2026-06-01T000000Z")
    _backup_next_to(target, "2026-06-29T000000Z")

    facts = _facts(env, {})

    assert facts["recovery"] == "none", "чужой файл не становится нашим из-за соседних файлов"


def test_marker_without_state_and_two_backups_is_ambiguous(tmp_path):
    """Граница строки таблицы «entry НЕТ»: orphaned_backup только при РОВНО одном кандидате.

    С двумя кандидатами и молчащим state выбрать оригинал нечем → ambiguous (не orphaned_backup).
    Докстринг-таблица обязана совпадать с кодом построчно, иначе она вводит в заблуждение.
    """
    env = _env(tmp_path)
    target = _target(env)
    _backup_next_to(target, "2026-06-01T000000Z", "original user config\n")
    _backup_next_to(target, "2026-06-29T000000Z", MANAGED_CONFIG)

    assert _facts(env, {})["recovery"] == "ambiguous"


def test_stale_managed_without_marker_is_leftover(tmp_path):
    """#110 Дефект 1 сохранён: state managed, маркер пропал → leftover, файл не трогаем."""
    env = _env(tmp_path)
    target = _target(env, FOREIGN_CONFIG)
    backup = _backup_next_to(target)
    facts = _facts(env, _entry(target, provenance="overwrote", backup=backup))
    assert facts["recovery"] == "leftover", "без живого маркера писать по файлу нельзя"


@pytest.mark.parametrize("mode", ["adopted", "restored"])
def test_adopted_and_restored_are_never_touched(tmp_path, mode):
    """adopted/restored — srouter намеренно не владеет файлом; даже backup рядом не даёт прав."""
    env = _env(tmp_path)
    target = _target(env)
    _backup_next_to(target)
    facts = _facts(env, _entry(target, mode=mode, managed=False))
    assert facts["recovery"] == "none"


def test_facts_never_write_anything(tmp_path):
    """Редьюсер обязан быть чистым: ни файлов, ни state — иначе он не годится обоим потокам."""
    env = _env(tmp_path)
    target = _target(env)
    backup = _backup_next_to(target)
    before = {p: p.read_bytes() for p in sorted(target.parent.iterdir())}

    _facts(env, _entry(target, provenance="overwrote", backup=backup))

    after = {p: p.read_bytes() for p in sorted(target.parent.iterdir())}
    assert before == after, "component_facts не должна ничего писать/менять на диске"
    assert not env.state_path.exists(), "component_facts не должна создавать state"


def test_facts_respect_state_config_path_over_default(tmp_path):
    """Path-ownership: смотрим по пути ИЗ state, а не по дефолтному (смена --prefix, #111 finding 1)."""
    env = _env(tmp_path)
    elsewhere = tmp_path / "other-prefix" / "privoxy" / "config"
    elsewhere.parent.mkdir(parents=True, exist_ok=True)
    elsewhere.write_text(MANAGED_CONFIG, encoding="utf-8")
    backup = _backup_next_to(elsewhere)

    facts = _facts(env, _entry(elsewhere, provenance="overwrote", backup=backup))

    assert facts["config_path"] == str(elsewhere)
    assert facts["recovery"] == "restore"


def test_backup_discovery_is_scoped_to_its_own_config_path(tmp_path):
    """backup валиден только для того config_path, рядом с которым лежит — path-ownership физически.

    Регресс-гвард к #111 finding 1: backup xray не должен «подойти» к privoxy лишь потому, что лежит
    в общей директории. Имя backup'а несёт имя своего target — перепутать невозможно by construction.
    """
    env = _env(tmp_path)
    privoxy = _target(env, MANAGED_CONFIG, name="privoxy")
    xray = env.component_paths("xray")["config"]
    xray.parent.mkdir(parents=True, exist_ok=True)
    xray.write_text('{"srouter": {"marker": "srouter-managed"}}\n', encoding="utf-8")
    _backup_next_to(xray)  # backup ТОЛЬКО для xray

    assert install_lib.discover_backups(privoxy) == [], "чужой backup не виден для privoxy"
    assert _facts(env, {}, name="privoxy")["recovery"] == "leftover"


# ==================== cycle-review: retained backup от прошлого install-цикла (P1) ====================
#
# Codex и /review НЕЗАВИСИМО нашли один и тот же дефект: retained backup (сохраняется НАМЕРЕННО,
# user_data_retained в build_uninstall_plan) от давно завершённого install→uninstall цикла физически
# неотличим от backup'а ТЕКУЩЕГО цикла — оба лежат рядом с config_path и парсятся как валидный
# timestamp. Без границы not_before/created_at единственный retained-relic проходил бы через
# "state молчит, ровно 1 кандидат" и выдавал бы себя за доказательство overwrite СВЕЖЕГО created-конфига.


def test_stale_retained_backup_does_not_hijack_fresh_created_config(tmp_path):
    """P1 cycle-review (Codex+/review): backup СТАРШЕ created_at — не кандидат, даже если единственный.

    Сценарий: backup остался от прошлого install-цикла (retained), пользователь вручную удалил тогда
    восстановленный файл, новый install создал конфиг с нуля (provenance='created', created_at
    зафиксирован в момент создания). Без фильтра единственный retained backup прошёл бы через
    len(discovered)==1 → restore, восстанавливая устаревший чужой контент поверх свежего конфига.
    """
    env = _env(tmp_path)
    target = _target(env)
    # backup СТАРШЕ created_at — доказанный remnant предыдущего цикла, а не этого install'а.
    _backup_next_to(target, "2020-01-01T000000Z", "STALE FROM PREVIOUS CYCLE\n")
    entry = _entry(target, provenance="created")
    entry["created_at"] = "2026-06-29T00:00:00Z"

    facts = _facts(env, entry)

    assert facts["recovery"] == "remove", (
        "backup старше created_at — retained relic предыдущего цикла, не доказательство ЭТОГО overwrite"
    )
    assert facts["backup"] == "", "retained-relic не должен становиться «тем самым» backup'ом"


def test_backup_created_after_created_at_still_counts(tmp_path):
    """Граница not_before не режет валидные кейсы: backup ПОЗЖЕ created_at — легитимный кандидат.

    F2/P1-1 не должен сломаться этим фильтром: если backup появился уже ПОСЛЕ того, как текущий
    конфиг был создан (например, crash между backup и записью state в рамках ТЕКУЩЕГО install'а),
    он обязан по-прежнему приниматься как доказательство overwrite.
    """
    env = _env(tmp_path)
    target = _target(env)
    backup = _backup_next_to(target, "2026-06-29T000000Z", "original from THIS cycle\n")
    entry = _entry(target, provenance="created")
    entry["created_at"] = "2026-06-01T00:00:00Z"  # раньше backup'а

    facts = _facts(env, entry)

    assert facts["recovery"] == "restore", "backup после created_at — легитимное доказательство overwrite"
    assert facts["backup"] == str(backup)


def test_missing_created_at_does_not_narrow_discovery(tmp_path):
    """Fail-open по границе (не по данным): нет created_at — фильтр не сужает discovery.

    Legacy state (записан до этого фикса) не несёт created_at. Отсутствие границы НЕ должно ложно
    отбрасывать настоящих кандидатов — иначе фикс регрессировал бы уже закрытый P1-3/F1.
    """
    env = _env(tmp_path)
    target = _target(env)
    backup = _backup_next_to(target, "2020-01-01T000000Z", "legacy backup\n")
    entry = _entry(target, provenance="created")  # created_at отсутствует (legacy entry)

    facts = _facts(env, entry)

    assert facts["recovery"] == "restore", "без created_at граница не применяется — legacy-поведение цело"
    assert facts["backup"] == str(backup)


def test_backup_exactly_at_created_at_boundary_still_counts(tmp_path):
    """Граничный случай: backup СОВПАДАЕТ по timestamp'у с created_at — считается валидным (>=, не >).

    created_at пишется ТОЛЬКО когда backups[name] пуст в этом apply — то есть _backup() не вызывался
    для этого компонента в цикле, который зафиксировал created_at. Совпадение timestamp'ов означает
    секундную коллизию, не порядок «раньше». Отбрасывать по строгому > — терять легитимного кандидата
    без всякой причины; граница обязана быть fail-open в сторону «не сузить лишнего».
    """
    env = _env(tmp_path)
    target = _target(env)
    backup = _backup_next_to(target, "2026-06-29T000000Z", "boundary case\n")
    entry = _entry(target, provenance="created")
    entry["created_at"] = "2026-06-29T00:00:00Z"  # ровно тот же момент, что и backup

    facts = _facts(env, entry)

    assert facts["recovery"] == "restore", "backup ровно на границе not_before обязан приниматься (>=)"
    assert facts["backup"] == str(backup)


def test_idempotent_created_reinstall_preserves_original_created_at(tmp_path):
    """created_at НЕ обновляется на повторном install с тем же provenance='created' по тому же пути.

    Если бы created_at сбрасывался на новый env.now при каждом idempotent reinstall, окно доверия
    молча расширялось бы, и тот самый retained backup, что фильтр обязан отсекать, снова прошёл бы.
    Регресс-гвард на конкретное поведение _write_state_after_apply (не component_facts напрямую).
    """
    import json

    import install_lib as lib

    env = lib.InstallEnv(
        root=Path(__file__).resolve().parent.parent,
        prefix=tmp_path / "homebrew",
        state_path=tmp_path / "srouter.local.json",
        launchagent_dir=tmp_path / "LaunchAgents",
        now="2026-07-01T00:00:00Z",
    )
    target = _target(env)
    stale_backup = _backup_next_to(target, "2020-01-01T000000Z", "ancient retained backup\n")
    env.state_path.write_text(json.dumps({
        "schema_version": 1, "nodes": [], "active_node": {"name": None, "pending": None},
        "probes": {}, "network": {"channels": {"wifi_service": "Wi-Fi"}},
        "traffic_guard": {"mode": "off", "domains": {}},
        "detected_environment": {"privoxy": {
            "config_path": str(target),
            "management": {"mode": "managed", "managed": True, "provenance": "created"},
            "created_at": "2026-01-01T00:00:00Z",  # оригинальный момент создания — РАНЬШЕ backup'а
        }},
        "runtime": {},
    }), encoding="utf-8")

    from test_install_flow import FakeRunner, _port_checker_managed_up

    runner = FakeRunner()
    result = lib.apply_install(
        env=env, confirm=True, choices={"xray": "skip", "dnsmasq": "skip"},
        runner=runner, port_checker=_port_checker_managed_up(runner.calls))
    assert result["ok"] is True

    state = json.loads(env.state_path.read_text(encoding="utf-8"))
    entry = state["detected_environment"]["privoxy"]
    assert entry.get("created_at") == "2026-01-01T00:00:00Z", (
        "idempotent reinstall не должен сдвигать created_at — иначе окно доверия молча расширяется "
        "и старый backup снова становится «доказательством» для нового окна"
    )
    assert entry["management"]["provenance"] == "created"

    facts = lib.component_facts("privoxy", env, entry)
    assert facts["recovery"] == "remove", (
        f"stale backup {stale_backup} старше сохранённого created_at — не должен подменять remove"
    )
