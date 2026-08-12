#!/usr/bin/env python3
"""Uninstall/rollback-логика install (issue #229, экстракция из install_lib.py).

build_uninstall_plan/apply_uninstall и всё, что нужно только на пути отката: restore backup'ов,
удаление created-конфигов, остановка сервисов, DNS-восстановление, выгрузка LaunchAgent. Discovery
компонентов и InstallEnv — в install_config.py, plist/launchd-примитивы — в install_plist.py.
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from sys_probe import run

from install_config import (
    BREW,
    CHOICES,
    COMPONENTS,
    InstallEnv,
    NETWORKSETUP,
    SUDO,
    _BACKUP_INFIX,
    _discover_network,
    _has_marker,
    _is_adopted_entry,
    _is_managed_entry,
    _is_restored_entry,
    _provenance_of,
    apply_install,
    build_plan,
    component_facts,
    format_plan,
)
from install_plist import (
    LAUNCHAGENT_LABEL,
    _has_launchagent_marker,
    _unload_launchagent,
)

import local_state


UNINSTALL_CATEGORIES = ("configs", "services", "dns", "launchagent")


def _component_uninstall_item(name, env, detected):
    """Uninstall-представление компонента: перевод recovery из component_facts в поля плана.

    До issue #124 здесь жила ВТОРАЯ, независимая реализация вывода состояния (первая —
    _inspect_component на стороне install). Именно расхождение двух реализаций было корнем #110
    («install верил файлу, uninstall верил state») и рецидивом стало в #124 на третьем факте: install
    знал про backup, а uninstall узнать не мог — ссылка терялась при обрыве, и пользовательский
    оригинал оставался orphaned навсегда (P1-3). Теперь оба слоя читают ОДИН редьюсер.

    Что uninstall узнаёт: факты о мире (маркер в файле, backup'ы на диске, запись в state). Чего НЕ
    узнаёт: механику записи install'а — был ли обрыв, в какой фазе, существуют ли промежуточные
    состояния. Утечка этой механики сюда и провалила PR #119 (гвард — tests/test_install_layering.py).
    """
    entry = detected.get(name) if isinstance(detected.get(name), dict) else {}
    facts = component_facts(name, env, entry)
    recovery = facts["recovery"]
    managed = facts["managed"]
    marker_present = facts["marker_present"]
    provenance = facts["provenance"]

    # restore покрывает и штатный overwrite (recovery='restore'), и обрыв ДО записи state
    # (recovery='orphaned_backup'): для действия они неразличимы — есть доказанный backup нашего
    # конфига, оригинал пользователя подлежит возврату. Различие лишь в происхождении знания, и оно
    # отражается в status для оператора, а не в правах.
    restorable = recovery in ("restore", "orphaned_backup")
    # removable (issue #112 Часть 2, fail-closed двойной арбитраж): created-конфиг удаляется ТОЛЬКО
    # при подтверждении двумя арбитрами — provenance='created' в state И живой srouter-маркер в файле.
    # Плюс третий, добавленный #124: рядом НЕТ backup'а. Backup доказывает, что overwrite всё-таки
    # был (state деградировал) — тогда восстанавливаем, а не удаляем (F2/P1-1).
    removable = recovery == "remove"

    if recovery == "none":
        if facts["adopted"]:
            status = "adopted — left untouched"
        elif facts["restored"]:
            status = "restored — left untouched"
        else:
            status = "unmanaged — left untouched"
    elif recovery == "remove":
        status = "managed — created config, remove available"
    elif recovery == "restore":
        status = "managed — restore available"
    elif recovery == "orphaned_backup":
        status = "orphaned backup — interrupted install, restore available"
    elif recovery == "ambiguous":
        status = "ambiguous backups — operator must choose, left untouched"
    elif managed and provenance == "created" and not marker_present:
        status = "managed — created config, marker missing (fail-safe leftover)"
    else:
        status = "managed — no safe backup/marker, left untouched"
    return {
        "name": name,
        "config_path": facts["config_path"],
        "backup": facts["backup"],
        "managed": managed,
        "adopted": facts["adopted"],
        "restored": facts["restored"],
        "provenance": provenance,
        "marker_present": marker_present,
        "restorable": restorable,
        "removable": removable,
        "recovery": recovery,
        "discovered_backups": facts["discovered_backups"],
        # state обещал backup, а файла нет — повод громко доложить (leftover), см. apply_uninstall.
        "state_backup_missing": facts["state_backup_missing"],
        "status": status,
    }


def _leftover_reason(item):
    """Почему компонент не откатился — текст для оператора, либо "" если докладывать нечего.

    ЕДИНСТВЕННЫЙ вход — item['recovery'], который вычислил component_facts. Раньше apply_uninstall
    пересобирал условия сам (managed/marker_present/provenance/state_backup_missing), и cycle-review
    этого PR дважды поймал одно и то же следствие: ветка срабатывала не на том случае, а её правка
    молча теряла соседний. Это ровно корневой класс #110/#124 — две реализации одной истины.

    Молчание здесь = обман (#110 Дефект 1): оператор увидел бы «Откат завершён», а конфиг остался бы
    лежать. Поэтому докладываем ВСЕ неоткатившиеся состояния. Единственное исключение — 'none'
    (srouter к файлу непричастен: adopted/restored/true-foreign; «чужое рядом» легитимно) и 'remove'/
    'restore' (сюда не попадают — они обрабатываются как действия выше по потоку).
    """
    recovery = item.get("recovery")
    if recovery == "ambiguous":
        # Автовыбор «самого свежего» — ловушка: при обрыве второго install свежий backup является
        # копией srouter-конфига, а оригинал пользователя лежит в самом старом. Отдаём выбор оператору.
        return ("несколько backup-кандидатов, state не указывает оригинал — выберите вручную: "
                + ", ".join(item.get("discovered_backups") or []))
    if recovery != "leftover":
        return ""
    if item.get("state_backup_missing"):
        return ("state ссылается на backup, которого нет на диске — оригинал невосстановим, "
                "конфиг оставлен без изменений")
    if item.get("managed") and not item.get("marker_present"):
        # created БЕЗ маркера (двойной арбитраж #112 не пройден) / stale-managed (#110 Дефект 1).
        if item.get("provenance") == "created":
            return "created-config: marker missing (обрыв install / подмена) — fail-safe, не удалено"
        return "stale-managed: not restorable and marker missing"
    # Маркер жив, но истории нет: ни backup рядом, ни записи в state. Восстанавливать нечем, удалять
    # вслепую нельзя. ГРАНИЦА #111 cycle 2 finding B: legacy marker-managed БЕЗ provenance — состояние
    # ОПРЕДЕЛЁННОЕ (конфиг наш и валиден), это не partial → rc=0, не leftover.
    if item.get("managed"):
        return ""
    return "srouter-маркер в конфиге, но ни backup, ни записи в state — не откатано"


def _launchagent_uninstall_item(env, detected):
    entry = detected.get("launchagent") if isinstance(detected.get("launchagent"), dict) else {}
    plist_path = Path(entry.get("plist_path") or env.launchagent_path())
    marker_present = plist_path.exists() and _has_launchagent_marker(plist_path)
    managed = _is_managed_entry(entry) or marker_present
    adopted = _is_adopted_entry(entry)
    if adopted:
        status = "adopted — left untouched"
    elif managed and marker_present:
        status = "managed — unload/remove available"
    elif managed:
        status = "managed — marker missing, left untouched"
    else:
        status = "unmanaged — left untouched"
    return {
        "label": entry.get("label") or LAUNCHAGENT_LABEL,
        "plist_path": str(plist_path),
        "managed": managed,
        "adopted": adopted,
        "marker_present": marker_present,
        "removable": managed and marker_present,
        "status": status,
    }


def build_uninstall_plan(env=None, runner=run):
    """Rollback discovery-only: не вызывает subprocess и не пишет файлы."""
    del runner
    env = env or InstallEnv.from_env()
    state, readable = local_state.load_state_checked(path=env.state_path)
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    network = state.get("network") if isinstance(state.get("network"), dict) else {}
    return {
        "mode": "uninstall-plan",
        "state_path": str(env.state_path),
        "state_readable": readable,
        "categories": list(UNINSTALL_CATEGORIES),
        "components": [_component_uninstall_item(name, env, detected) for name in COMPONENTS],
        "network": network,
        "launchagent": _launchagent_uninstall_item(env, detected),
        "user_data_retained": [
            "srouter.local.json",
            "generated key/deploy bundles",
            # шаблон из источника правды (install_config) — не дублируем литерал имени backup:
            # его формат задаёт _backup, и расхождение копии молча соврало бы оператору.
            f"*{_BACKUP_INFIX}*",
        ],
    }


def format_uninstall_plan(plan):
    lines = [
        "srouter uninstall rollback plan",
        f"- state: {plan.get('state_path')}",
        "- plan ничего не меняет; apply спрашивает подтверждение по категориям.",
        "- user-data остаются на месте: " + ", ".join(plan.get("user_data_retained", [])),
        "",
        "Категории apply:",
        "- configs: restore из #5 backup только если текущий config всё ещё srouter-managed",
        "- services: stop только srouter-managed brew services",
        "- dns: networksetup Empty только для srouter-managed dnsmasq/Wi-Fi",
        "- launchagent: bootout/unload и удаление plist только если есть srouter marker",
        "",
        "Компоненты:",
    ]
    for item in plan.get("components", []):
        lines.append(
            f"- {item.get('name')}: {item.get('status')}; "
            f"config={item.get('config_path')}; backup={item.get('backup') or '-'}"
        )
    launchagent = plan.get("launchagent") or {}
    lines.extend(
        [
            "",
            f"LaunchAgent: {launchagent.get('status')}; plist={launchagent.get('plist_path')}",
            "",
            "Для применения: ./uninstall.sh apply и подтвердить нужные категории.",
        ]
    )
    return "\n".join(lines)


def _restore_backup(backup_path, target_path):
    tmp = target_path.with_name(target_path.name + ".srouter-restore-tmp")
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup_path, tmp)
        tmp.replace(target_path)
        return True
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False


def _delete_component_config(config_path):
    """Удалить created-config (provenance='created', issue #112 Часть 2).

    Симметрично _restore_backup (для overwrote): вместо restore прежнего контента — удалить файл целиком,
    т.к. created-конфиг полностью принадлежит srouter (нечего восстанавливать). missing_ok=True (idempotent:
    повторный uninstall на уже удалённом — не ошибка). Fail-closed: OSError → False (не маскировать сбой).
    """
    try:
        Path(config_path).unlink(missing_ok=True)
        return True
    except OSError:
        return False


def _mark_component_restored(env, item):
    state, readable = local_state.load_state_checked(path=env.state_path)
    if not readable:
        return "state_unreadable"
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    entry = detected.get(item["name"]) if isinstance(detected.get(item["name"]), dict) else {}
    entry["config_path"] = item.get("config_path")
    if item.get("backup"):
        entry["backup"] = item["backup"]
        entry["restored_from_backup"] = item["backup"]
    # После restore текущий config снова принадлежит пользователю/системе.
    # Это фиксирует прогресс rollback и не даёт повторному apply остановить foreign service.
    entry["management"] = {"mode": "restored", "managed": False}
    entry["restored_at"] = env.now
    detected[item["name"]] = entry
    state["detected_environment"] = detected

    runtime = state.get("runtime") if isinstance(state.get("runtime"), dict) else {}
    runtime["last_uninstall_restore"] = env.now
    state["runtime"] = runtime
    if local_state.save_state(state, path=env.state_path) is None:
        return "state_write_failed"
    return ""


def _mark_component_removed(env, item):
    """После DELETE created-config: пометить mode='removed', managed=False (issue #112 Часть 2).

    Симметрично _mark_component_restored (для overwrote→restore), но без restored_from_backup
    (created-конфиг удалён, не восстановлен). mode='removed' → следующий install видит чистое место
    (нет reclaimable/foreign) → create заново. Замыкает идемпотентность цикла (issue #110 корень).
    """
    state, readable = local_state.load_state_checked(path=env.state_path)
    if not readable:
        return "state_unreadable"
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    entry = detected.get(item["name"]) if isinstance(detected.get(item["name"]), dict) else {}
    entry["config_path"] = item.get("config_path")
    # created-конфиг удалён — нечего восстанавливать. Чистим backup-ссылку (её не было для created,
    # но defensive: state-drift мог оставить). provenance=None (больше не managed).
    # issue #124: снятые здесь ранее pending_backup/pending_written_at были мёртвым остатком WAL из
    # PR #119 — их никто не писал. Их присутствие означало, что uninstall знает про промежуточные
    # фазы записи install'а; новая архитектура такого знания не требует (см. component_facts).
    entry.pop("backup", None)
    entry["management"] = {"mode": "removed", "managed": False, "provenance": None}
    entry["removed_at"] = env.now
    detected[item["name"]] = entry
    state["detected_environment"] = detected

    runtime = state.get("runtime") if isinstance(state.get("runtime"), dict) else {}
    runtime["last_uninstall_remove"] = env.now
    state["runtime"] = runtime
    if local_state.save_state(state, path=env.state_path) is None:
        return "state_write_failed"
    return ""


def _stop_service(name, runner):
    if name == "dnsmasq":
        return runner([SUDO, BREW, "services", "stop", "dnsmasq"], 40)
    return runner([BREW, "services", "stop", name], 40)


def _restore_dns(plan, runner):
    dnsmasq = next((item for item in plan.get("components", []) if item.get("name") == "dnsmasq"), {})
    # cycle-review этого PR (Codex, round 2): managed в одиночку — не тот вопрос. managed приходит
    # ТОЛЬКО из state-entry, который для recovery='orphaned_backup' пуст (обрыв ДО финальной записи) —
    # но _apply_dns install реально мог успеть выполнить ДО обрыва (apply_install зовёт _apply_dns
    # сразу после _restart_component, задолго до финальной _write_state_after_apply). Гейтить
    # restorable-компонент на managed=False значило бы восстановить конфиг (секция configs это
    # делает), но оставить DNS указывать на 127.0.0.1 — молчаливый privacy/availability риск поверх
    # успешного «ok» отката. item.get("restorable") — тот же признак, которым apply_uninstall уже
    # решает, восстанавливать ли configs; DNS обязан следовать той же логике, а не своей отдельной.
    if not (dnsmasq.get("managed") or dnsmasq.get("restorable")):
        return {"rc": 0, "out": "", "err": "dnsmasq unmanaged", "timeout": False}
    channels = plan.get("network", {}).get("channels") if isinstance(plan.get("network"), dict) else {}
    service = channels.get("wifi_service") if isinstance(channels, dict) else ""
    if not service:
        # issue #293 (P1b, cycle-review round 3 PR #290): холодный старт — на первом-ever apply
        # state-файл ещё не существует, поэтому state['network']['channels'] никогда не был записан
        # (пишется только финальной _write_state_after_apply в конце apply_install), хотя _apply_dns
        # реально мог успеть выполниться до обрыва. Симметрично тому, как discover_backups уже
        # переоткрывает backup'ы вживую вместо доверия одной state-записи: здесь для restorable/managed
        # компонента переоткрываем wifi_service вживую через runner, а не молча no-op'имся на пустой
        # кэш — иначе dnsmasq останавливается, а DNS так и указывает на 127.0.0.1 под видом успеха.
        service = _discover_network(runner).get("channels", {}).get("wifi_service", "")
    if not service:
        return {"rc": 0, "out": "", "err": "wifi service not found", "timeout": False}
    return runner([NETWORKSETUP, "-setdnsservers", service, "Empty"], 20)


def apply_uninstall(env=None, *, confirmations=None, runner=run):
    """Apply rollback. Каждая категория должна быть явно подтверждена вызывающим кодом."""
    env = env or InstallEnv.from_env()
    confirmations = confirmations or {}
    plan = build_uninstall_plan(env=env)
    if not plan.get("state_readable"):
        return {"ok": False, "blocked": ["state_unreadable"], "actions": [], "plan": plan}

    actions = []
    components = []
    # leftover (issue #110 Дефект 1): stale-managed компоненты — srouter СТАВИЛ (item['managed']=True из
    # state), НО состояние неопределённое: не restorable (нет backup) И маркер пропал (marker_present=False).
    # Это и есть «своё не откатилось» — обман, если промолчать; cmd_uninstall меняет headline + rc=2.
    # Границы (cycle-review #111 cycle 2 finding B — сужение, чтобы не ломать базовый workflow):
    #   - true-foreign (managed=False — srouter не ставил, «чужое рядом») → НЕ leftover (легитимное соседство).
    #   - свежий install (managed=True, маркер ЕСТЬ, нет backup) → НЕ leftover: это нормальный managed-конфиг,
    #     srouter им владеет; restore-only-uninstall оставляет его (deep remove-фикс — отдельный follow-up),
    #     НО это не partial (состояние определённое: конфиг валиден, с маркером). leftover только для stale.
    leftover = []
    if confirmations.get("configs"):
        for item in plan["components"]:
            components.append(item)
            # ГИБРИД по provenance (issue #112 Часть 2, РЕШЕНИЕ 1):
            #   removable  (created + живой маркер)  → УДАЛИТЬ (created-конфиг полностью наш).
            #   restorable (overwrote + backup+маркер) → RESTORE прежнего контента.
            #   created БЕЗ маркера                   → fail-safe leftover (state drift / crash / подмена).
            #   stale-managed (legacy, маркер пропал) → leftover (как #110 Дефект 1).
            # Порядок: removable РАНЬШЕ restorable (они взаимоисключающие: created → нет backup → не restorable).
            if item.get("removable"):
                if not _delete_component_config(Path(item["config_path"])):
                    return {"ok": False, "blocked": [f"{item['name']}_delete_failed"], "actions": actions, "plan": plan}
                state_error = _mark_component_removed(env, item)
                if state_error:
                    return {"ok": False, "blocked": [state_error], "actions": actions, "plan": plan}
                actions.append({"category": "configs", "component": item["name"], "changed": True})
                continue
            if not item.get("restorable"):
                # Классификацию УЖЕ сделал component_facts — здесь только перевод её в текст для
                # оператора. Не пересобираем условия заново: две реализации одной истины и есть
                # корневой класс #110/#124, и в cycle-review этого PR он воспроизвёлся дважды
                # (ветка ловила не тот случай, а её правка потеряла соседний). Единственный вход —
                # item['recovery'].
                reason = _leftover_reason(item)
                if reason:
                    leftover.append({"name": item["name"], "status": item.get("status", "unknown"),
                                     "reason": reason})
                continue
            if not _restore_backup(Path(item["backup"]), Path(item["config_path"])):
                return {"ok": False, "blocked": [f"{item['name']}_restore_failed"], "actions": actions, "plan": plan}
            state_error = _mark_component_restored(env, item)
            if state_error:
                return {"ok": False, "blocked": [state_error], "actions": actions, "plan": plan}
            actions.append({"category": "configs", "component": item["name"], "changed": True})
    else:
        components.extend(plan["components"])

    if confirmations.get("services"):
        for item in plan["components"]:
            # cycle-review этого PR (Codex, round 2), симметрично _restore_dns: managed=False на
            # orphaned_backup — свойство ПУСТОГО state-entry (обрыв ДО финальной записи), а не
            # доказательство того, что _restart_component не выполнялся. apply_install зовёт
            # _restart_component для каждого компонента задолго до финальной записи — реальный сервис
            # мог быть остановлен/запущен на новый (srouter) конфиг, который configs-секция уже
            # восстановила выше. Гейтить stop только на managed оставляло бы этот сервис работающим
            # на образ, которого только что не стало на диске, при report ok=True — тихий availability
            # риск поверх успешного отката.
            if not (item.get("managed") or item.get("restorable")):
                continue
            stopped = _stop_service(item["name"], runner)
            if stopped.get("timeout") or stopped.get("rc") != 0:
                return {"ok": False, "blocked": [f"{item['name']}_stop_failed"], "actions": actions, "plan": plan}
            actions.append({"category": "services", "component": item["name"], "changed": True})

    if confirmations.get("dns"):
        restored = _restore_dns(plan, runner)
        if restored.get("timeout") or restored.get("rc") != 0:
            return {"ok": False, "blocked": ["dns_restore_failed"], "actions": actions, "plan": plan}
        if not restored.get("err"):
            actions.append({"category": "dns", "component": "networksetup", "changed": True})

    if confirmations.get("launchagent"):
        unloaded = _unload_launchagent(plan["launchagent"], runner)
        if not unloaded["ok"]:
            return {"ok": False, "blocked": [unloaded["blocked"]], "actions": actions, "plan": plan}
        if unloaded.get("changed"):
            actions.append({"category": "launchagent", "component": LAUNCHAGENT_LABEL, "changed": True})

    return {"ok": True, "blocked": [], "actions": actions, "components": components,
            "leftover": leftover, "plan": plan}


def _prompt_bool(label):
    answer = input(f"{label} [y/N]: ").strip().lower()
    return answer in {"y", "yes", "д", "да"}


def _collect_uninstall_confirmations(args, plan):
    confirmations = {
        "configs": bool(args.restore_configs),
        "services": bool(args.stop_services),
        "dns": bool(args.restore_dns),
        "launchagent": bool(args.unload_launchagent),
    }
    if any(confirmations.values()):
        return confirmations
    if not sys.stdin.isatty():
        return None
    print(format_uninstall_plan(plan))
    print("")
    return {
        "configs": _prompt_bool("Восстановить managed service-конфиги из #5 backup?"),
        "services": _prompt_bool("Остановить только srouter-managed brew services?"),
        "dns": _prompt_bool("Сбросить DNS через networksetup для srouter-managed dnsmasq?"),
        "launchagent": _prompt_bool("Выгрузить и удалить srouter-managed LaunchAgent?"),
    }


def main(argv=None, *, runner=run):
    """CLI entrypoint (install.sh/uninstall.sh apply). runner=run по умолчанию (issue #269): та же
    DI-точка, что у build_plan/build_uninstall_plan/apply_uninstall/apply_install — main прокидывает
    её дальше вместо того, чтобы обрывать цепочку (как уже делает srouter_cli.cmd_uninstall)."""
    parser = argparse.ArgumentParser(description="Локальный установщик srouter")
    parser.add_argument("mode", nargs="?", choices=("plan", "apply", "init", "uninstall-plan", "uninstall-apply"), default="plan")
    parser.add_argument("-y", "--yes", action="store_true", help="Явное подтверждение apply/init")
    parser.add_argument("--state", default=None, help="Путь к srouter.local.json")
    parser.add_argument("--prefix", default=None, help="Homebrew prefix, по умолчанию /opt/homebrew")
    parser.add_argument("--launchagents-dir", default=None, help="Каталог LaunchAgents для тестов/нестандартного HOME")
    parser.add_argument("--restore-configs", action="store_true", help="uninstall apply: restore managed configs from backups")
    parser.add_argument("--stop-services", action="store_true", help="uninstall apply: stop managed brew services")
    parser.add_argument("--restore-dns", action="store_true", help="uninstall apply: reset DNS for managed dnsmasq")
    parser.add_argument("--unload-launchagent", action="store_true", help="uninstall apply: unload/remove managed LaunchAgent")
    for name in COMPONENTS:
        parser.add_argument(f"--{name}", choices=CHOICES, default=None, help=f"Выбор для конфликтов {name}")
    args = parser.parse_args(argv)

    env = InstallEnv.from_env(state_path=args.state, prefix=args.prefix)
    if args.launchagents_dir:
        env.launchagent_dir = Path(args.launchagents_dir)
    if args.mode == "plan":
        print(format_plan(build_plan(env=env, runner=runner)))
        return 0
    if args.mode == "uninstall-plan":
        print(format_uninstall_plan(build_uninstall_plan(env=env, runner=runner)))
        return 0
    if args.mode == "uninstall-apply":
        plan = build_uninstall_plan(env=env, runner=runner)
        confirmations = _collect_uninstall_confirmations(args, plan)
        if confirmations is None:
            print(format_uninstall_plan(plan), file=sys.stderr)
            print("uninstall apply остановлен: нужно подтвердить категории restore/stop/unload", file=sys.stderr)
            return 2
        result = apply_uninstall(env=env, confirmations=confirmations, runner=runner)
        if result["ok"]:
            leftover = result.get("leftover") or []
            if leftover:
                # partial (issue #110 Дефект 1, cycle-review #111 cycle 2 finding A): srouter ставил, но не
                # откатил (stale-managed). main — это uninstall.sh apply entrypoint, параллельный srouter
                # uninstall; без этой проверки partial молча exit 0 (не маскировать, как cmd_uninstall).
                names = ", ".join(item["name"] for item in leftover)
                print(f"uninstall apply выполнен частично: конфиги оставлены ({names}) — не найден backup/маркер.",
                      file=sys.stderr)
                return 2
            print("uninstall apply завершён успешно: изменены подтверждённые srouter-managed категории.")
            return 0
        print("uninstall apply остановлен: " + ", ".join(result.get("blocked") or ["unknown"]), file=sys.stderr)
        return 2

    choices = {name: getattr(args, name) for name in COMPONENTS if getattr(args, name)}
    install_launchagent = True
    if args.mode == "init":
        choices = {name: "skip" for name in COMPONENTS} | choices
        install_launchagent = False
    result = apply_install(env=env, confirm=args.yes, choices=choices,
                            install_launchagent=install_launchagent, runner=runner)
    if result["ok"]:
        print("apply завершён успешно: изменения сохранены (подтверждено через --yes).")
        return 0
    print("apply остановлен: " + ", ".join(result.get("blocked") or ["unknown"]), file=sys.stderr)
    if "plan" in result:
        print(format_plan(result["plan"]), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
