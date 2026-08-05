"""#136: routing-domains в production xray-config (hybrid adopt).

Извлечено из local_state.py (issue #158, декомпозиция крупных файлов). Обращается к core state
I/O через фасад `local_state` (facade-lookup, канон moving-caller-inverts-mock-ownership —
см. docstring local_state_traffic_guard.py).

srouter управляет routing.rules секцией reality-out: adopt существующего rule (маркер
_srouter_managed на уровне rule, НЕ top-level — foreign-конфиг не захватывается целиком), домены
хранит в state (active + last_applied_hash для drift-detection). Two-phase: backup → modify →
restart → promote. Эталон read-xray: local_state_xray._read_xray_vless_address; atomic-save:
local_state.save_state; restart: install_lib._restart_component.
"""
import json
from pathlib import Path

import local_state

ROUTING_MARKER = "_srouter_managed"  # ключ в rule (xray игнорирует неизвестные ключи — безопасно)
DEFAULT_ROUTING_OUTBOUND = "reality-out"


def routing_plan(current_domains, hosts, action="add"):
    """Построить новый домен-список: добавить/убрать hosts в current_domains. Чистая функция, без записи.

    hosts — bare hostnames ('telegram.org'); нормализуются в 'domain:<host>' (xray exact+subdomains).
    action='add' — добавить недостающие (idempotent: дубль игнорируется);
    action='remove' — убрать совпадающие.
    Возвращает новый список (сохраняя порядок current + new в конце для add).
    """
    if not isinstance(current_domains, list):
        current_domains = []
    if not isinstance(hosts, list):
        hosts = [hosts] if isinstance(hosts, str) else []
    norm = [f"domain:{h}" if not str(h).startswith("domain:") else str(h) for h in hosts if h]
    if action == "remove":
        rm = set(norm)
        return [d for d in current_domains if d not in rm]
    # add: сохранить порядок, дубли пропустить
    existing = set(current_domains)
    out = list(current_domains)
    for d in norm:
        if d not in existing:
            out.append(d)
            existing.add(d)
    return out


def _routing_find_managed_rule(rules):
    """Найти индекс rule с _srouter_managed:true. -1 если нет..Raise если их >1 (ambiguous)."""
    idxs = [i for i, r in enumerate(rules)
            if isinstance(r, dict) and r.get(ROUTING_MARKER) is True]
    if len(idxs) > 1:
        return -2  # ambiguous — несколько managed-секций, отказать
    return idxs[0] if idxs else -1


def _routing_domains_hash(domains):
    """Стабильный hash домен-списка для drift-detection (сортировка → не зависит от порядка)."""
    import hashlib
    ordered = "\n".join(sorted(domains))
    return hashlib.sha256(ordered.encode("utf-8")).hexdigest()[:16]


def routing_apply(hosts, *, action="add", adopt=False, outbound=DEFAULT_ROUTING_OUTBOUND,
                  config_path=None, state_path=None, runner=None,
                  port_checker=None):
    """Применить изменение routing-доменов в production xray-config + restart xray (two-phase).

    Hybrid adopt: foreign-config без маркера → требует adopt=True (захватить секцию). После adopt
    rule помечается _srouter_managed, домены + hash пишутся в state. Locate по маркеру, не по tag
    (защита от переименования outbound). Hash-drift (конфиг меняли руками) → refuse.
    Транзакционность: state пишется ДО restart xray; при провале ЛЮБОГО шага (unreadable state,
    state-write, restart) — откат к исходному config (и state, если restart упал после успешной
    записи state), никогда не оставляя config и state рассинхронизированными. Существующий, но
    битый state-файл никогда не заменяется дефолтом (data-loss guard).
    Concurrency/atomicity (#139): критическая секция (read backup-snapshot → modify → restart)
    под process-safe flock на xray-config.json — конкурирующие apply сериализуются, нет lost-update.
    Все записи конфига (modify + ОБОИ rollback-ветки) атомарны (_atomic_write_text: tmp+fsync+rename),
    ENOSPC/IO-error при rollback не повреждают production-файл.

    Возвращает {ok, changed, err}. Не бросает (fail-soft как sync_route_ip_from_xray).
    """
    # config_path=None (default) резолвится тут, а не в сигнатуре: local_state.XRAY_CONFIG_PATH
    # определён в local_state_xray, который facade собирает ПОСЛЕ этого модуля — default-параметр,
    # вычисляемый на момент импорта, поймал бы partially-initialized module (circular import).
    if config_path is None:
        config_path = local_state.XRAY_CONFIG_PATH

    # lazy import чтобы не тащить зависимость модуля при простом чтении state
    try:
        import install_lib
    except ImportError:
        install_lib = None

    # ВСЯ транзакция (read config → read state → backup → modify → restart) под process-safe
    # exclusive flock на xray-config: критическая секция начинается С ЧТЕНИЯ config, не с записи —
    # иначе второй apply успевает закешировать stale snapshot ДО блокировки и затирает первый при
    # своей записи (lost-update). flock сериализует конкурирующие apply (ручной `srouter routing` ×
    # install/будущий gen_xray_config). #139 Finding 2.
    try:
        with local_state._routing_config_lock(config_path):
            return _routing_apply_locked(
                config_path, state_path, outbound, hosts, action, adopt, runner, port_checker,
                install_lib,
            )
    except OSError:
        # lockfile не создался/не открылся — fail-closed: не мутируем config без сериализации.
        return {"ok": False, "changed": False, "err": "config_lock_failed"}


def _routing_apply_locked(config_path, state_path, outbound, hosts, action, adopt, runner,
                          port_checker, install_lib):
    """Шаги 1..6 routing_apply под _routing_config_lock. Вынесено, чтобы lock держался от чтения
    config до завершения restart/recovery (включая все stale-snapshot-чувствительные шаги).

    Внутри lock: read config/state → backup → atomic modify → state-write → restart (с atomic
    rollback при провале). Rollback-записи атомарны (_atomic_write_text), не truncate+write —
    #139 Finding 1. Возвращает {ok, changed, err}. Не бросает (fail-soft)."""
    # 1. читать config (fail-soft)
    try:
        data = json.loads(Path(config_path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        # OSError: ошибки файла/чтения; ValueError: невалидные данные (JSONDecodeError — подкласс ValueError);
        # TypeError: ошибки типа данных
        return {"ok": False, "changed": False, "err": "config_unreadable"}
    if not isinstance(data, dict):
        return {"ok": False, "changed": False, "err": "config_not_dict"}
    routing = data.get("routing")
    if not isinstance(routing, dict):
        return {"ok": False, "changed": False, "err": "no_routing_section"}
    rules = routing.get("rules")
    if not isinstance(rules, list) or not rules:
        return {"ok": False, "changed": False, "err": "no_routing_rules"}

    idx = _routing_find_managed_rule(rules)
    if idx == -2:
        return {"ok": False, "changed": False, "err": "ambiguous_managed_rules"}

    if idx == -1:
        # нет managed-секции
        if not adopt:
            return {"ok": False, "changed": False, "err": "foreign_config_needs_adopt"}
        # adopt: найти rule по outboundTag (ровно один)
        matches = [i for i, r in enumerate(rules)
                   if isinstance(r, dict) and r.get("outboundTag") == outbound
                   and isinstance(r.get("domain"), list)]
        if len(matches) != 1:
            return {"ok": False, "changed": False, "err": f"adopt_needs_one_{outbound}_rule"}
        idx = matches[0]

    rule = rules[idx]
    current_domains = list(rule.get("domain") or [])

    # 2. читать state ОДИН раз здесь (readable проверяем всегда, drift — только когда есть с чем
    #    сравнивать). Битый существующий state-файл → fail-closed ДО любых мутаций конфига: не смеем
    #    ни читать активный набор для drift-сравнения, ни (ниже, в state-write) заменять его дефолтом
    #    (data-loss — теряет nodes/active_node/traffic_guard/isolate пользователя).
    try:
        state, state_readable = local_state._load_state_checked(state_path)
    except (OSError, ValueError, TypeError):
        # OSError: ошибки файла; ValueError: ошибки структуры; TypeError: ошибки типа данных
        state, state_readable = None, False
    if not state_readable or not isinstance(state, dict):
        return {"ok": False, "changed": False, "err": "state_unreadable"}
    if adopt is False or rule.get(ROUTING_MARKER) is True:
        rt = state.get("routing") if isinstance(state.get("routing"), dict) else {}
        stored_hash = rt.get("last_applied_hash")
        if stored_hash and _routing_domains_hash(current_domains) != stored_hash:
            return {"ok": False, "changed": False, "err": "hash_drift_config_changed_externally"}

    new_domains = routing_plan(current_domains, hosts, action=action)
    if new_domains == current_domains:
        return {"ok": True, "changed": False, "err": ""}  # idempotent, restart не нужен

    # 3. backup (two-phase: восстановим при ошибке restart) — читаем СВЕЖИЙ config под lock.
    #    state_text — raw-снимок state ДО любых мутаций (шаг 5 может добавить секцию routing в
    #    legacy-state без неё; реконструкция только routing-полей при rollback оставила бы state
    #    мутированным → byte-exact rollback через raw-снимок, как для config. Codex round-3 P2).
    config_p = Path(config_path)
    backup_text = config_p.read_text(encoding="utf-8")
    state_p = Path(state_path) if state_path else local_state._DEFAULT_PATH
    state_existed = state_p.exists()
    original_state_text = state_p.read_text(encoding="utf-8") if state_existed else ""

    # 4. modify rule in-place copy + atomic write (tmp+fsync+replace — единый _atomic_write_text)
    new_rule = dict(rule)
    new_rule["domain"] = new_domains
    new_rule[ROUTING_MARKER] = True
    new_rules = list(rules)
    new_rules[idx] = new_rule
    new_data = dict(data)
    new_data["routing"] = dict(routing)
    new_data["routing"]["rules"] = new_rules
    if not local_state._atomic_write_text(config_p, json.dumps(new_data, ensure_ascii=False, indent=2) + "\n"):
        return {"ok": False, "changed": False, "err": "config_write_failed"}

    # 5. state-write ДО restart (транзакционность: если state не запишется — откатываем config и НЕ
    #    трогаем xray вовсе, не оставляя рассинхрон config↔state). state гарантированно readable dict
    #    (шаг 2 fail-closed на unreadable state ДО этой точки — исключений здесь не бывает).
    try:
        if not isinstance(state.get("routing"), dict):
            state["routing"] = {}
        state["routing"]["active"] = new_domains
        state["routing"]["outbound"] = outbound
        state["routing"]["last_applied_hash"] = _routing_domains_hash(new_domains)
        state_write_ok = local_state.save_state(state, state_path) is not None
    except (OSError, ValueError, TypeError):
        # OSError: ошибки записи; ValueError: ошибки структуры; TypeError: ошибки типа данных
        state_write_ok = False
    if not state_write_ok:
        # atomic rollback: tmp+fsync+replace, не truncate+write (ENOSPC не повредит production).
        # ПРОВЕРЯЕМ результат rollback (Codex P1): провал rollback-replace оставляет config новым,
        # а state не записан → рассинхрон config↔state. Явно сообщаем rollback_failed, не маскируем
        # под state_write_failed (иначе хранитель рассинхрона в неведении о реальном состоянии config).
        rollback_ok = local_state._atomic_write_text(config_p, backup_text)
        err = "state_write_failed" if rollback_ok else "state_write_failed_rollback_failed"
        return {"ok": False, "changed": not rollback_ok, "err": err}

    # 6. restart xray (fail-closed: при провале — восстановить config+state И повторно перезапустить
    #    xray СО СТАРЫМ восстановленным конфигом. _restart_component уже сделал stop к моменту провала
    #    start — без recovery-рестарта xray остаётся down до ручного вмешательства, превращая рутинную
    #    неудачную операцию routing add-domain в постоянный простой всего прокси, Codex round 2).
    if runner is not None and install_lib is not None:
        try:
            res = install_lib._restart_component("xray", runner, port_checker=port_checker)
        except Exception:  # noqa: BLE001 — транзакционная граница, осознанно широкий (issue #238 шаг 3)
            # _restart_component делает stop ДО start и дёргает ИНЖЕКТИРУЕМЫЙ runner напрямую, поэтому
            # тип исключения здесь не под нашим контролем (RuntimeError из runner'а — реальный кейс).
            # Любая утечка отсюда фатальна: config+state уже записаны, xray уже остановлен → прокси
            # лежит без откатов и без recovery-рестарта (каноны fail-closed-proxy-down,
            # srouter-critical-infra-24-7). Ловим всё и уходим в штатный rollback ниже.
            res = {"rc": 1, "err": "restart_exception"}
        if res.get("rc") != 0 or res.get("timeout"):
            # atomic rollback к backup (tmp+fsync+replace); провал записи не оставляет config
            # усечённым/молча неоткаченным — #139 Finding 1. ПРОВЕРЯЕМ результат config-rollback
            # (Codex P1 round-1): если rollback не удался — config остаётся новым. Тогда state НЕ
            # откатываем (иначе рассинхрон в обратную сторону: config новый, state откатан).
            # ПРОВЕРЯЕМ результат state-rollback (Codex P1 round-2): save_state может вернуть None
            # (ENOSPC) → config старый, state новый → рассинхрон. Оба исхода отражаются в err,
            # changed = False только при ПОЛНОМ успешном rollback (durable == исходное).
            config_rollback_ok = local_state._atomic_write_text(config_p, backup_text)
            # state-rollback: byte-exact восстановление raw-снимка original_state_text (а не
            # реконструкция routing-полей — иначе legacy-state без секции routing остаётся
            # мутированным после успешной записи, changed=False лжив. Codex round-3 P2).
            # Если state-файла изначально не было — удаляем созданный шагом-5.
            state_rollback_ok = False
            if config_rollback_ok:
                try:
                    if state_existed:
                        state_rollback_ok = local_state._atomic_write_text(state_p, original_state_text)
                    else:
                        state_p.unlink(missing_ok=True)
                        state_rollback_ok = True
                except OSError:
                    state_rollback_ok = False
            # err-признаки рассинхрона
            note = ""
            if not config_rollback_ok:
                note = "; rollback_failed_config_kept_new"
            elif not state_rollback_ok:
                note = "; rollback_failed_state_kept_new"
            recovery_err = ""
            try:
                recovery = install_lib._restart_component("xray", runner, port_checker=port_checker)
                if recovery.get("rc") != 0 or recovery.get("timeout"):
                    recovery_err = f"; recovery_restart_failed:{recovery.get('err', 'unknown')}"
            except Exception:  # noqa: BLE001 — last-resort recovery, осознанно широкий (issue #238 шаг 3)
                # Симметрично основному restart-catch: утечка отсюда оставила бы xray down с уже
                # откаченным config'ом и без диагностики в err. Recovery — последний шанс поднять
                # прокси, он обязан пережить любой тип сбоя runner'а.
                recovery_err = "; recovery_restart_exception"
            # changed=True если что-то осталось изменённым (не полный rollback); False при полном откате
            changed = not (config_rollback_ok and state_rollback_ok)
            return {"ok": False, "changed": changed,
                    "err": f"restart_failed:{res.get('err', 'unknown')}{note}{recovery_err}"}

    return {"ok": True, "changed": True, "err": ""}
