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
    _has_marker,
    _is_adopted_entry,
    _is_managed_entry,
    _is_restored_entry,
    _provenance_of,
    apply_install,
    build_plan,
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
    entry = detected.get(name) if isinstance(detected.get(name), dict) else {}
    config_path = Path(entry.get("config_path") or env.component_paths(name)["config"])
    backup_path = Path(entry["backup"]) if entry.get("backup") else None
    marker_present = config_path.exists() and _has_marker(config_path)
    managed = _is_managed_entry(entry)
    adopted = _is_adopted_entry(entry)
    restored = _is_restored_entry(entry)
    provenance = _provenance_of(entry)
    restorable = managed and marker_present and bool(backup_path and backup_path.exists())
    # removable (issue #112 Часть 2, РЕШЕНИЕ 1 — fail-closed двойной арбитраж): created-конфиг удаляется
    # ТОЛЬКО при подтверждении двумя арбитрами — provenance='created' (из state: srouter создал с нуля)
    # И живой srouter-маркер в файле (файл действительно наш, не подменён). Без маркера → НЕ удалять
    # (state drift / crash-during-install / подмена) — fail-safe leftover. Канон «никогда молча не adopt».
    removable = managed and provenance == "created" and marker_present
    if adopted:
        status = "adopted — left untouched"
    elif restored:
        status = "restored — left untouched"
    elif removable:
        status = "managed — created config, remove available"
    elif restorable:
        status = "managed — restore available"
    elif managed and provenance == "created" and not marker_present:
        status = "managed — created config, marker missing (fail-safe leftover)"
    elif managed:
        status = "managed — no safe backup/marker, left untouched"
    else:
        status = "unmanaged — left untouched"
    return {
        "name": name,
        "config_path": str(config_path),
        "backup": str(backup_path) if backup_path else "",
        "managed": managed,
        "adopted": adopted,
        "restored": restored,
        "provenance": provenance,
        "marker_present": marker_present,
        "restorable": restorable,
        "removable": removable,
        "status": status,
    }


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
            "*.srouter-backup-*",
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
    entry.pop("backup", None)
    entry.pop("pending_backup", None)
    entry.pop("pending_written_at", None)
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
    if not dnsmasq.get("managed"):
        return {"rc": 0, "out": "", "err": "dnsmasq unmanaged", "timeout": False}
    channels = plan.get("network", {}).get("channels") if isinstance(plan.get("network"), dict) else {}
    service = channels.get("wifi_service") if isinstance(channels, dict) else ""
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
                # created БЕЗ маркера (двойной арбитраж не пройден) → fail-safe leftover, не удалять.
                # stale-managed (legacy без provenance, маркер пропал) → leftover (как #110 Дефект 1).
                # Маркер на месте для legacy-without-provenance → НЕ leftover (определённое состояние, оставляем).
                if item.get("managed") and not item.get("marker_present"):
                    if item.get("provenance") == "created":
                        reason = "created-config: marker missing (crash-during-install / подмена) — fail-safe, не удалено"
                    else:
                        reason = "stale-managed: not restorable and marker missing"
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
            if not item.get("managed"):
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


def main(argv=None):
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
        print(format_plan(build_plan(env=env)))
        return 0
    if args.mode == "uninstall-plan":
        print(format_uninstall_plan(build_uninstall_plan(env=env)))
        return 0
    if args.mode == "uninstall-apply":
        plan = build_uninstall_plan(env=env)
        confirmations = _collect_uninstall_confirmations(args, plan)
        if confirmations is None:
            print(format_uninstall_plan(plan), file=sys.stderr)
            print("uninstall apply остановлен: нужно подтвердить категории restore/stop/unload", file=sys.stderr)
            return 2
        result = apply_uninstall(env=env, confirmations=confirmations)
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
    result = apply_install(env=env, confirm=args.yes, choices=choices, install_launchagent=install_launchagent)
    if result["ok"]:
        print("apply завершён успешно: изменения сохранены (подтверждено через --yes).")
        return 0
    print("apply остановлен: " + ", ".join(result.get("blocked") or ["unknown"]), file=sys.stderr)
    if "plan" in result:
        print(format_plan(result["plan"]), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
