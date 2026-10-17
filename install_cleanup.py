#!/usr/bin/env python3
"""Uninstall/rollback-логика install (issue #229, экстракция из install_lib.py).

build_uninstall_plan/apply_uninstall и всё, что нужно только на пути отката: restore backup'ов,
удаление created-конфигов, остановка сервисов, DNS-восстановление, выгрузка LaunchAgent. Discovery
компонентов и InstallEnv — в install_config.py, plist/launchd-примитивы — в install_plist.py.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import shlex
import shutil
import sys
import tempfile
import time
from pathlib import Path

from sys_probe import run

import backup_lib  # purge_user_backups: чистка USER_BACKUPS_DIR при uninstall (PR-2 #339)

from install_config import (
    BREW,
    CHOICES,
    COMPONENTS,
    InstallEnv,
    NETWORKSETUP,
    SUDO,
    _BACKUP_INFIX,
    _brew_service_path_allowed,
    _discover_network,
    _dnsmasq_service_status,
    _has_marker,
    _is_adopted_entry,
    _is_managed_entry,
    _is_restored_entry,
    _provenance_of,
    _package_names,
    _read_dns_servers,
    owned_packages,
    _record_state_effect,
    _parse_brew_services,
    apply_install,
    build_plan,
    component_facts,
    discover_backups,
    format_plan,
)
from install_plist import (
    LAUNCHAGENT_LABEL,
    _has_launchagent_marker,
    _unload_launchagent,
    _launchd_domain,
    _launchd_unload,
)

import local_state
import install_restore


UNINSTALL_CATEGORIES = ("configs", "services", "dns", "launchagent")

_SYSTEM_DATA_PATHS = tuple(map(Path, (
    "/Library/Application Support/srouter/backups/privoxy",
    "/Library/Application Support/srouter/privoxy/audit",
    "/Library/Logs/srouter/privoxy",
    "/Library/Logs/srouter/privoxy-audit",
)))


def _extra_launchagents(env):
    agents = []
    markers = {
        "com.srouter.watchdog": "srouter-managed-watchdog-v1",
        "com.srouter.netprobe": "srouter-managed-netprobe-v1",
        "com.srouter.codenv": "srouter-managed-codex-env-v1",
        "com.srouter.isolate": "__SROUTER_ISOLATE_STRICT_MARKER__",
        "com.srouter.isolate-escape": "__SROUTER_ISOLATE_ESCAPE_MARKER__",
        "com.srouter.isolate-refresh": "__SROUTER_ISOLATE_REFRESH_MARKER__",
    }
    for label, marker in markers.items():
        path = env.launchagent_dir / f"{label}.plist"
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError):
            agents.append({"label": label, "error": "launchagent_read_failed"})
            continue
        agents.append({"label": label, "plist_path": str(path), "removable": marker in text,
                       "keep_plist": label == "com.srouter.codenv"})
    return agents


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
        "service_restore": entry.get("service_restore") if isinstance(entry.get("service_restore"), dict) and entry["service_restore"].get("config_path") == facts["config_path"] else None,
        "backup_metadata": entry.get("backup_metadata"),
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
        "extra_launchagents": _extra_launchagents(env),
        "dependencies": (detected.get("packages") or {}).get("owned", []),
        "purge_paths": [str(path) for path in [*user_data_paths(env), *_SYSTEM_DATA_PATHS]],
        "user_data_retained": [
            "srouter.local.json",
            "generated key/deploy bundles",
            # шаблон из источника правды (install_config) — не дублируем литерал имени backup:
            # его формат задаёт _backup, и расхождение копии молча соврало бы оператору.
            f"*{_BACKUP_INFIX}*",
        ],
    }


def user_data_paths(env):
    paths = [env.root / "srouter_config.py", env.root / "srouter.hot_routes.json",
             env.root / "srouter.proxy_errors.json", env.log_out, env.log_err,
             backup_lib.USER_BACKUPS_DIR]
    paths.extend(env.root / "server" / name for name in (".generated", "generated", "rendered", "deploy-bundles"))
    for component in COMPONENTS:
        paths.extend(Path(path) for path in discover_backups(env.component_paths(component)["config"]))
    paths.extend(Path(path) for path in discover_backups(Path.home() / ".zshrc"))
    logs = Path.home() / "Library/Logs"
    for name in ("srouter-watchdog.metrics.jsonl", "srouter-net-marks.jsonl", "srouter-netprobe.jsonl",
                 "srouter-speedtest.jsonl", "srouter-watchdog.notify.log", "srouter-watchdog.lifecycle.jsonl",
                 "srouter-watchdog.status.jsonl"):
        paths.append(logs / name)
        paths.extend(logs.glob(name + ".*"))
    paths.extend(Path("/tmp") / name for name in (
        "srouter-watchdog.last", "srouter-watchdog.launchd.json", "srouter-watchdog.metrics.last.json"))
    # State (including recovery data) is always the last deletion.
    paths = list(dict.fromkeys(Path(path) for path in paths if Path(path) != env.state_path))
    paths.append(env.state_path)
    return paths


def purge_user_data(env, paths=None):
    allowed = set(user_data_paths(env))
    requested = list(paths) if paths is not None else user_data_paths(env)
    if any(Path(path) not in allowed for path in requested):
        return {"ok": False, "err": "purge_path_out_of_scope"}
    requested = [path for path in requested if Path(path) != env.state_path] + ([env.state_path] if env.state_path in map(Path, requested) else [])
    # macOS system aliases are trusted; application directories must not redirect purge.
    aliases = {Path('/tmp'): Path('/private/tmp'), Path('/var'): Path('/private/var'),
               Path('/etc'): Path('/private/etc')}
    for path in map(Path, requested):
        for parent in path.parents:
            if parent.is_symlink() and aliases.get(parent) != parent.resolve():
                return {"ok": False, "err": "purge_parent_symlink: " + str(path)}
    removed = []
    for path in map(Path, requested):
        try:
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
            removed.append(str(path))
        except OSError as exc:
            return {"ok": False, "err": f"purge_failed: {path}: {exc}", "removed": removed}
    return {"ok": True, "removed": removed}


def purge_system_data(runner=run):
    """Только fixed data/log paths srouter, после полного отката служб и настроек."""
    from privileged_ops import build_osascript
    paths = []
    try:
        for path in _SYSTEM_DATA_PATHS:
            if any(parent.is_symlink() for parent in path.parents):
                return {"ok": False, "err": "system_data_parent_symlink: " + str(path)}
            if path.exists() or path.is_symlink():
                paths.append(path)
        if not paths:
            return {"ok": True}
        result = runner(build_osascript(["/bin/rm", "-rf", "--", *map(str, paths)]), 60)
        if result.get("timeout") or result.get("rc") != 0:
            return {"ok": False, "err": "system_data_purge_failed"}
        if any(path.exists() or path.is_symlink() for path in paths):
            return {"ok": False, "err": "system_data_purge_unverified"}
    except OSError as exc:
        return {"ok": False, "err": "system_data_purge_failed: " + str(exc)}
    return {"ok": True}


def format_uninstall_plan(plan):
    lines = [
        "srouter uninstall rollback plan",
        f"- state: {plan.get('state_path')}",
        "- plan ничего не меняет. Перед удалением — выбор данных, зависимостей и общее подтверждение.",
        "- по умолчанию сохраняются конфиги, ключи, журналы, бэкапы и зависимости.",
        "",
        "Действия:",
        "- сначала выгрузить собственные фоновые агенты, затем остановить managed-сервисы.",
        "- вернуть исходные файлы и прежнее состояние сервисов из истории установки.",
        "- вернуть сохранённый список DNS; автоматический DNS — только если он был исходным.",
        "- снять собственные маршруты, PF и интеграции; чужие изменения сохранить и сообщить о конфликте.",
        "- без достоверной истории не угадывать прежние настройки; при сбое сохранить данные отката.",
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
            "Для применения: srouter uninstall или ./uninstall.sh apply.",
            "-y сохраняет данные и зависимости; --purge и --remove-deps выбираются независимо.",
        ]
    )
    return "\n".join(lines)


def _restore_backup(backup_path, target_path, metadata=None):
    try:
        if metadata is not None and (not isinstance(metadata, dict) or
                not all(type(metadata.get(k)) is int for k in ("mode", "uid", "gid"))):
            return False
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".srouter-restore-", dir=target_path.parent) as staging:
            tmp = Path(staging) / "original"
            if metadata and "link" in metadata:
                tmp.symlink_to(metadata["link"])
            else:
                shutil.copy2(backup_path, tmp)
            if metadata:
                if not 0 <= metadata["mode"] <= 0o7777 or min(metadata["uid"], metadata["gid"]) < 0:
                    return False
                info = tmp.lstat()
                if (info.st_uid, info.st_gid) != (metadata["uid"], metadata["gid"]):
                    os.chown(tmp, metadata["uid"], metadata["gid"], follow_symlinks=False)
                install_restore._restore_metadata(tmp, metadata)
            tmp.replace(target_path)
        return True
    except (OSError, ValueError, TypeError, KeyError):
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
        result = runner([SUDO, BREW, "services", "stop", "dnsmasq"], 40)
    else:
        result = runner([BREW, "services", "stop", name], 40)
    if result.get("timeout") or result.get("rc") != 0:
        return result
    domain = "system" if name == "dnsmasq" else _launchd_domain()
    for prefix in ("homebrew.mxcl.", "sh.brew."):
        if _launchd_unload(domain, prefix + name, runner=runner)["state"] is not False:
            return {"rc": 1, "err": "service_stop_unverified"}
    return result


def _resume_service(name, runner):
    command = [BREW, "services", "start", name]
    if name == "dnsmasq":
        command.insert(0, SUDO)
    result = runner(command, 40)
    if result.get("timeout") or result.get("rc") != 0:
        return False
    deadline = time.monotonic() + 3
    while True:
        listed = runner([BREW, "services", "list"], 8) if name != "dnsmasq" else {}
        if (name == "dnsmasq" and _dnsmasq_service_status(runner) == "started") or (
                name != "dnsmasq" and not listed.get("timeout") and listed.get("rc") == 0
                and _parse_brew_services(listed.get("out") or "").get(name) == "started"):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.2)


def _service_restore_phase(env, name, phase):
    def mutate(state):
        entry = state.get("detected_environment", {}).get(name, {})
        if phase is None:
            entry.pop("service_restore", None)
        elif isinstance(entry.get("service_restore"), dict):
            entry["service_restore"]["phase"] = phase
    return _record_state_effect(env, mutate)


def _restore_brew_service_paths(env, name, runner):
    """brew services под root меняет владельцев formula/opt; вернуть их до brew uninstall."""
    from privileged_ops import build_osascript
    state, readable = local_state.load_state_checked(path=env.state_path)
    if not readable:
        return "state_unreadable"
    records = state.get("detected_environment", {}).get(name, {}).get("brew_paths_restore")
    if records is None:
        return ""
    if not isinstance(records, list):
        return "brew_paths_invalid"
    steps = []
    for record in sorted(records, key=lambda value: len(str(value.get("path", ""))) if isinstance(value, dict) else 0):
        if (not isinstance(record, dict) or not _brew_service_path_allowed(env, record.get("path", ""))
                or any(type(record.get(key)) is not int or record[key] < 0 for key in ("uid", "gid", "mode", "inode"))
                or record["mode"] > 0o7777):
            return "brew_paths_invalid"
        try:
            info = Path(record["path"]).lstat()
        except FileNotFoundError:
            continue
        except PermissionError:
            info = None  # root-owned parent: identity is checked in the privileged command.
        if info is not None:
            if (info.st_uid, info.st_gid, info.st_mode & 0o7777) == (record["uid"], record["gid"], record["mode"]):
                continue
            if info.st_ino != record["inode"]:
                return "brew_paths_changed"
        path = shlex.quote(record["path"])
        steps.append(f"if [ -e {path} ] || [ -L {path} ]; then "
                     f"[ \"$(/usr/bin/stat -f %i {path})\" = {record['inode']} ] || exit 1; "
                     f"/usr/sbin/chown -h {record['uid']}:{record['gid']} {path} && "
                     f"/bin/chmod -h {record['mode']:o} {path} || exit 1; fi")
    if steps:
        result = runner(build_osascript(["/bin/sh", "-c", "; ".join(steps)]), 60)
        if result.get("timeout") or result.get("rc") != 0:
            return "brew_ownership_restore_failed"
    try:
        for record in records:
            try:
                info = Path(record["path"]).lstat()
            except FileNotFoundError:
                continue
            if (info.st_uid, info.st_gid, info.st_mode & 0o7777) != (record["uid"], record["gid"], record["mode"]):
                return "brew_ownership_restore_unverified"
    except OSError:
        return "brew_ownership_restore_unverified"
    return _record_state_effect(env, lambda state: state["detected_environment"][name].pop("brew_paths_restore", None))


def remove_installed_dependencies(env, runner=run):
    """Remove recorded formulae only; Homebrew dependents always win over ownership."""
    ownership = owned_packages(env, runner)
    if not ownership["ok"]:
        return ownership
    queue = list(reversed(ownership["owned"]))
    removed, kept = [], []
    while queue:
        progress = False
        for name in list(queue):
            inventory = _package_names(runner([BREW, "list", "--formula"], 30))
            if inventory is None:
                return {"ok": False, "err": "package_inventory_failed", "removed": removed}
            users = (_package_names(runner([BREW, "uses", "--installed", "--recursive", name], 30))
                     if name in inventory else [])
            if users is None:
                return {"ok": False, "err": "package_dependents_unknown: " + name, "removed": removed}
            if name in COMPONENTS and name in inventory:
                if name == "dnsmasq":
                    status = _dnsmasq_service_status(runner)
                else:
                    listed = runner([BREW, "services", "list"], 15)
                    status = (_parse_brew_services(listed.get("out") or "").get(name, "none")
                              if not listed.get("timeout") and listed.get("rc") == 0 else "unknown")
                if status == "started":
                    users.append("работающий сервис")
                elif status not in ("none", "stopped"):
                    return {"ok": False, "err": "package_service_unknown: " + name, "removed": removed}
            if set(users) & set(queue):
                continue
            queue.remove(name)
            progress = True
            if users:
                kept.append({"name": name, "used_by": users})
                continue
            if name in inventory:
                result = runner(["/usr/bin/env", "HOMEBREW_NO_AUTOREMOVE=1", BREW, "uninstall", "--formula", name], 120)
                if result.get("timeout") or result.get("rc") != 0:
                    return {"ok": False, "err": "package_remove_failed: " + name, "removed": removed}
                remaining = _package_names(runner([BREW, "list", "--formula"], 30))
                if remaining is None or name in remaining:
                    return {"ok": False, "err": "package_remove_unverified: " + name, "removed": removed}
            def forget(state):
                current = state["detected_environment"]["packages"]["owned"]
                if name in current:
                    current.remove(name)
            error = _record_state_effect(env, forget)
            if error:
                return {"ok": False, "err": error, "removed": removed}
            removed.append(name)
        if not progress:
            return {"ok": False, "err": "package_dependency_cycle", "removed": removed}
    return {"ok": True, "removed": removed, "kept": kept}


def _restore_dns(plan, runner):
    network = plan.get("network") or {}
    leases = network.get("dns_restore") or {}
    dnsmasq = next((item for item in plan.get("components", []) if item.get("name") == "dnsmasq"), {})
    if not leases:
        if not (dnsmasq.get("managed") or dnsmasq.get("restorable")):
            return {"rc": 0, "err": "dnsmasq unmanaged"}
        service = (network.get("channels") or {}).get("wifi_service")
        if not service:
            discovered = _discover_network(runner)
            if not discovered.get("services_probe", {}).get("ok", False):
                return {"rc": 1, "err": "dns_service_discovery_failed"}
            service = discovered.get("channels", {}).get("wifi_service")
        if not service:
            return {"rc": 0, "err": "wifi service not found"}
        current = _read_dns_servers(service, runner)
        # Legacy installs have no evidence of the previous setting. Never invent DHCP.
        if current is None or "127.0.0.1" in current:
            return {"rc": 1, "err": "dns_original_unknown: сохраните DNS вручную; backup отсутствует"}
        return {"rc": 0, "err": "DNS изменён извне; сохранён"}
    for service, lease in leases.items():
        previous = lease.get("servers") if isinstance(lease, dict) else None
        if not isinstance(previous, list):
            return {"rc": 1, "err": "dns_backup_invalid"}
        try:
            for server in previous:
                ipaddress.ip_address(server)
        except (ValueError, TypeError):
            return {"rc": 1, "err": "dns_backup_invalid"}
        current = _read_dns_servers(service, runner)
        if current is None:
            return {"rc": 1, "err": "dns_read_failed"}
        if current != previous:
            if current != ["127.0.0.1"]:
                return {"rc": 1, "err": "dns_changed_externally: " + service}
            restored = runner([NETWORKSETUP, "-setdnsservers", service, *(previous or ["Empty"])], 20)
            if restored.get("timeout") or restored.get("rc") != 0:
                return restored
            if _read_dns_servers(service, runner) != previous:
                return {"rc": 1, "err": "dns_restore_verify_failed"}
    return {"rc": 0, "out": "", "err": "", "restored": list(leases)}


def stop_uninstall_agents(env, runner=run, *, plan=None):
    plan = plan or build_uninstall_plan(env=env)
    if not plan.get("state_readable"):
        return {"ok": False, "blocked": ["state_unreadable"], "actions": []}
    actions = []
    for agent in [plan["launchagent"], *plan["extra_launchagents"]]:
        if agent.get("error"):
            return {"ok": False, "blocked": [agent["error"]], "actions": actions}
        unloaded = _unload_launchagent(agent, runner)
        if not unloaded["ok"]:
            return {"ok": False, "blocked": [unloaded["blocked"]], "agent": agent["label"], "actions": actions}
        if unloaded.get("changed"):
            actions.append({"category": "launchagent", "component": agent["label"], "changed": True})
    return {"ok": True, "actions": actions}


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
    if confirmations.get("launchagent"):
        agents = stop_uninstall_agents(env, runner, plan=plan)
        actions.extend(agents["actions"])
        if not agents["ok"]:
            return {"ok": False, "blocked": agents["blocked"], "actions": actions, "plan": plan}

    stopped_names = set()
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
            original = item.get("service_restore") or {}
            if not (item.get("managed") or item.get("restorable") or item.get("removable") or original.get("phase") == "stopped"):
                continue
            stopped = _stop_service(item["name"], runner)
            if stopped.get("timeout") or stopped.get("rc") != 0:
                return {"ok": False, "blocked": [f"{item['name']}_stop_failed"], "actions": actions, "plan": plan}
            ownership_error = _restore_brew_service_paths(env, item["name"], runner)
            if ownership_error:
                return {"ok": False, "blocked": [ownership_error], "actions": actions, "plan": plan}
            error = _service_restore_phase(env, item["name"], "stopped")
            if error:
                return {"ok": False, "blocked": [error], "actions": actions, "plan": plan}
            stopped_names.add(item["name"])
            actions.append({"category": "services", "component": item["name"], "changed": True})


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
            if not _restore_backup(Path(item["backup"]), Path(item["config_path"]), item.get("backup_metadata")):
                return {"ok": False, "blocked": [f"{item['name']}_restore_failed"], "actions": actions, "plan": plan}
            state_error = _mark_component_restored(env, item)
            if state_error:
                return {"ok": False, "blocked": [state_error], "actions": actions, "plan": plan}
            actions.append({"category": "configs", "component": item["name"], "changed": True})
    else:
        components.extend(plan["components"])

    if confirmations.get("configs") and confirmations.get("services"):
        for item in plan["components"]:
            original = item.get("service_restore") or {}
            if item["name"] not in stopped_names or not original:
                continue
            if _leftover_reason(item):
                continue
            if original.get("status") == "started":
                if not _resume_service(item["name"], runner):
                    return {"ok": False, "blocked": [f"{item['name']}_resume_failed"], "actions": actions, "plan": plan}
            elif original.get("status") not in ("none", "stopped"):
                leftover.append({"name": item["name"], "reason": "исходное состояние службы неизвестно"})
                continue
            error = _service_restore_phase(env, item["name"], None)
            if error:
                return {"ok": False, "blocked": [error], "actions": actions, "plan": plan}

    if confirmations.get("dns"):
        restored = _restore_dns(plan, runner)
        if restored.get("timeout") or restored.get("rc") != 0:
            return {"ok": False, "blocked": ["dns_restore_failed"], "error": restored.get("err"), "actions": actions, "plan": plan}
        if restored.get("restored"):
            def clear_dns(state):
                leases = state.get("network", {}).get("dns_restore", {})
                for service in restored["restored"]:
                    leases.pop(service, None)
            error = _record_state_effect(env, clear_dns)
            if error:
                return {"ok": False, "blocked": [error], "actions": actions, "plan": plan}
        if not restored.get("err"):
            actions.append({"category": "dns", "component": "networksetup", "changed": True})


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
    parser.add_argument("--python", default=None, help="Python для LaunchAgent")
    parser.add_argument("--purge", action="store_true", help="Удалить данные после полного успешного отката")
    parser.add_argument("--remove-deps", action="store_true", help="Удалить только собственные неиспользуемые зависимости")
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
        selective = any((args.restore_configs, args.stop_services, args.restore_dns, args.unload_launchagent))
        if not selective:
            import srouter_cli
            return srouter_cli.cmd_uninstall(args, runner=srouter_cli.make_privileged_runner(runner))
        if args.purge or args.remove_deps:
            print("Выборочные категории нельзя совмещать с --purge/--remove-deps: нужен полный откат.", file=sys.stderr)
            return 2
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
