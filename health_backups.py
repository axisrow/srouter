"""Health-грань «бэкап-слоты консистентны» (issue #339, контракт v2 §6, PR-3).

Пять чеков контракта (каждый — читаемая пара «нашёл/ожидал», silent при чистоте):
1. Сирота-sidecar: `<settings><SIDECAR_SUFFIX>` существует, а managed-ключа в settings
   нет (crash-окно force-enable: backup записан, settings-save упал) → warn. НЕ удалять
   молча — данные чужие.
2. Stale-pointer: state `detected_environment[*].backup` указывает на несуществующий
   файл → warn `state_backup_missing` (P1a #293 — оригинал невосстановим).
3. Orphaned backup: валидное поколение рядом с config, state молчит (нет ни backup, ни
   restored_from_backup) → warn `orphaned_backup` (P1-3 #124). Retained-после-restore
   (restored_from_backup) сиротой НЕ является — оставлен намеренно.
4. Накопление: >ACCUMULATION_WARN поколений у одного target → warn (rotation не работала).
5. Смешение слотов: generation-имена и lease-sidecar у одного target одновременно —
   ошибка уровня контракта (два класса записи для одного носителя).

Канон уровня чека — persists-across-boot #330: info-only в health.check_all (не driver:
бэкап-слоты не влияют на канал в моменте), warn виден оператору. State unreadable →
unknown (не угадываем), не warn. Модуль ничего не мутирует и не бросает.
"""
import json
import logging
import os
from pathlib import Path

import backup_lib

_log = logging.getLogger("srouter.health")

# Порог накопления (§6-4): окно ротации 3 (backup_lib.DEFAULT_BACKUP_KEEP) + допуск на
# protected-поинтеры (state вправе держать лишнее поколение неприкосновенным).
ACCUMULATION_WARN = backup_lib.DEFAULT_BACKUP_KEEP + 2

__all__ = ["check_backup_slots", "_backup_slots_probe", "ACCUMULATION_WARN"]


def _load_json(path):
    """JSON-объект или None (нет/битый/не-object — unknown-семантика #307). Не бросает."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _sidecar_findings(target, managed_key_present, findings):
    """Чеки 1 и 5 для sidecar-lease target: сирота и смешение слотов."""
    sidecar = backup_lib.sidecar_path(target)
    try:
        has_sidecar = sidecar.is_file()
    except OSError:
        return
    if not has_sidecar:
        return
    generations = backup_lib.discover(target)
    if generations:
        findings.append(
            f"смешение слотов: у {target} одновременно generation-бэкапы "
            f"({len(generations)} шт.) и lease-sidecar {sidecar.name} — "
            "два класса записи для одного носителя (контракт #339 §6-5)")
    if not managed_key_present:
        findings.append(
            f"сиротский sidecar {sidecar} при отсутствии managed-ключа в {target} — "
            "crash-окно force-enable (restore не требуется, но проверь содержимое; "
            "НЕ удалять молча, данные чужие)")


def _claude_settings_target(path=None):
    """(target, managed-ключ-присутствует|None). None = unreadable → не оцениваем.

    Путь: явный path > env SROUTER_CLAUDE_SETTINGS (канон more-options-better, review
    #351: детерминированная интеграция без monkeypatch) > claude_proxy.SETTINGS (прод)."""
    try:
        import claude_proxy
    except ImportError as exc:
        _log.debug("claude_proxy недоступен: %s — sidecar-чек пропущен", exc)
        return None
    settings = Path(path or os.environ.get("SROUTER_CLAUDE_SETTINGS")
                    or claude_proxy.SETTINGS)
    data = _load_json(settings)
    if data is None and settings.exists():
        return (settings, None)  # битый settings — не угадываем (#307 unknown-семантика)
    env = data.get("env") if isinstance(data, dict) else {}
    env = env if isinstance(env, dict) else {}
    return (settings, any(k in env for k in claude_proxy.ENV_KEYS))


def _vscode_settings_targets(paths=None):
    """[(target, managed|None)]. paths: явный override > vscode_proxy._settings_paths
    (который сам чтит env SROUTER_VSCODE_SETTINGS — канон more-options-better)."""
    if not paths:
        try:
            import vscode_proxy
        except ImportError as exc:
            _log.debug("vscode_proxy недоступен: %s — sidecar-чек пропущен", exc)
            return []
        paths = vscode_proxy._settings_paths()
    settings_list = [Path(p) for p in paths]
    out = []
    for settings in settings_list:
        data = _load_json(settings)
        if data is None and settings.exists():
            out.append((settings, None))
            continue
        out.append((settings, "http.proxy" in data if isinstance(data, dict) else False))
    return out


def check_backup_slots(state_path=None, *, claude_settings=None, vscode_settings=None):
    """{status: ok|warn|unknown, detail, findings}. Доктор-грань контракта #339 §6.

    Read-only: ничего не удаляет и не чинит — только докладывает (образец
    persists-across-boot #330: warn требует внимания, но канал в моменте работает).

    claude_settings/vscode_settings — явные override целей sidecar-чеков (для
    детерминированного тестирования; иначе env SROUTER_CLAUDE_SETTINGS /
    SROUTER_VSCODE_SETTINGS, потом прод-дефолты модулей)."""
    import local_state

    findings = []

    # ---- install-слой: чеки 2/3/4 по detected_environment ----
    state, readable = local_state.load_state_checked(path=state_path)
    if not readable:
        return {"status": "unknown",
                "detail": "state нечитаем — консистентность бэкап-слотов не определить",
                "findings": []}
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    for name, entry in sorted(detected.items()):
        if not isinstance(entry, dict):
            continue
        config_path = entry.get("config_path")
        if not config_path:
            continue
        generations = backup_lib.discover(config_path)
        pointer = entry.get("backup")
        if pointer and not _path_exists(pointer):
            findings.append(
                f"state_backup_missing: {name} — state называет {pointer}, файла нет "
                "(оригинал невосстановим, #293)")
        accounted = {str(pointer), str(entry.get("restored_from_backup") or "")}
        unaccounted = [g for g in generations if str(g) not in accounted]
        # Review #351: «state молчит» бывает полным (поинтера нет вовсе — warn на любое
        # неучтённое поколение) и ЧАСТИЧНЫМ (свежий pointer + неучтённые реликты — crash
        # между двумя install'ами). Частичное молчание оцениваем только СВЕРХ окна
        # ротации: здоровая машина при окне KEEP легально держит KEEP-1 неучтённых
        # реликта (окно хранит новейшие, поинтер — новейший из них) — без допуска чек
        # ложно срабатывал бы на каждом штатном install'е. Ротация выключена
        # (SROUTER_BACKUP_KEEP=0) → реликты легальны по выбору оператора, молчим.
        if unaccounted:
            names = ", ".join(g.name for g in unaccounted)
            keep = backup_lib._resolve_keep(None)
            has_pointer = bool(pointer or entry.get("restored_from_backup"))
            if not has_pointer:
                findings.append(
                    f"orphaned_backup: {name} — {len(unaccounted)} поколение(й) рядом с "
                    f"{config_path}, state молчит (crash-окно install, #124); "
                    f"disk-доказательство: {names}")
            elif keep >= 1 and len(unaccounted) > max(keep - 1, 0):
                findings.append(
                    f"orphaned_backup: {name} — {len(unaccounted)} поколение(й) рядом с "
                    f"{config_path} не учтены state сверх окна ротации (поинтер ссылается "
                    f"лишь на одно; crash-окно между install'ами): {names}")
        if len(generations) > ACCUMULATION_WARN:
            findings.append(
                f"накопление: {name} — {len(generations)} поколений у {config_path} "
                f"(>{ACCUMULATION_WARN}; сигнал, что rotation не работала — PR-2 #339)")

    # ---- A5 root-snapshots: накопление без manifest-ссылки (PR-4 #339, count-only) ----
    # Read-only: /Library/.../backups/privoxy из user-процесса обычно 0700-root → report
    # вернёт error и грань молчит (fail-soft); root-контекст (helper) увидит картину.
    try:
        import privoxy_system
        snap = privoxy_system.snapshot_accumulation_report()
        if not snap.get("error") and snap.get("old_unreferenced"):
            findings.append(
                f"накопление root-snapshots: {len(snap['old_unreferenced'])} каталогов "
                f"старше {snap['older_than_days']}d без manifest-ссылки (PR-4 #339; "
                "count-only — удаление только явное решение оператора)")
    except ImportError as exc:
        _log.debug("privoxy_system недоступен: %s — A5-чек пропущен", exc)

    # ---- sidecar-lease: чеки 1/5 (claude/vscode) ----
    probes = [_claude_settings_target(claude_settings)]
    probes.extend(_vscode_settings_targets(vscode_settings))
    for probe in probes:
        if probe is None:
            continue
        target, managed = probe
        if managed is None:
            continue  # битый settings → не угадываем
        _sidecar_findings(target, managed, findings)

    if not findings:
        return {"status": "ok", "detail": "бэкап-слоты консистентны", "findings": []}
    return {"status": "warn",
            "detail": "; ".join(findings),
            "findings": findings}


def _backup_slots_probe():
    """Точка для health.check_all (info-only warn-чек, канон #330). Не бросает."""
    try:
        return check_backup_slots()
    except Exception as exc:  # noqa: BLE001 — грань не должна ронять doctor
        _log.debug("backup-slots probe сбой: %s", exc)
        return {"status": "unknown", "detail": f"backup-slots probe сбой: {exc}", "findings": []}


def _path_exists(pointer):
    try:
        return Path(pointer).exists()
    except OSError:
        return False
