#!/usr/bin/env python3
"""Flask-роуты дашборда (issue #227): все @app.get/@app.post + приватные хелперы фич.

Экстракция из dashboard.py (эпик #107/#158, канон no-hidden-magic-follow-canon): чистый
перенос кода, без редизайна. Flask app/gather_status/guard'ы — в dashboard_app.py, общие
статус-хелперы — в dashboard_common.py. dashboard.py остаётся тонким фасадом.
"""
import logging
import re
import time
from flask import jsonify, request

import local_state
from dashboard_app import app, gather_status
from dashboard_common import BREW, CHANNEL_TARGETS, GATEWAY, OSASCRIPT, ROUTE, _active_route_ip, _ip_literal
from dashboard_connectivity import switch_channel
from dashboard_nodes import probe_nodes, probe_nodes_snapshot
from dashboard_traffic import probe_traffic_guard
import node_selector
import sys_probe
import traffic_shape  # throttle-движок (#13): зовём через атрибут (traffic_shape.apply_throttle)
import isolate_firewall  # PF-изоляция доменов: зовём через атрибут
import git_proxy  # вкл/откл git-прокси для github (через git config --global)
import claude_proxy  # вкл/откл HTTPS_PROXY для Claude Code (~/.claude/settings.json)
import health  # check_all для /health эндпоинта
import proxy_registry  # единая картина прокси: кто настроен + идёт ли трафик
import concurrent.futures  # bounded-ожидание apply: git_proxy берёт БЛОКИРУЮЩИЙ flock
import privoxy_system  # protected system-service gate (#122)

_log = logging.getLogger("srouter.dashboard_routes")


# ============================ privileged: osascript-мост ============================
def _route_result(r):
    r = r or {}
    rc = r.get("rc")
    err = r.get("err") or ""
    timeout = bool(r.get("timeout"))
    cancelled = rc == -128 or (rc not in (0, None) and "-128" in err)
    return {
        "ok": rc == 0 and not timeout,
        "cancelled": cancelled,
        "rc": rc,
        "out": r.get("out") or "",
        "err": err,
        "timeout": timeout,
    }


def _sudo_route_ip(action, route_ip):
    if not _ip_literal(route_ip):
        return {"rc": None, "out": "", "err": "Нет active route_ip: настрой srouter.local.json", "timeout": False}
    if action == "add":
        shell_cmd = f"{ROUTE} -n add -host {route_ip} {GATEWAY}"
    elif action == "remove":
        shell_cmd = f"{ROUTE} -n delete -host {route_ip}"
    else:
        raise ValueError("bad action")        # глубокая защита
    # ВАЖНО: shell_cmd собран из констант и validated local_state, ввод запроса сюда не попадает никогда.
    # Если кто-то добавит динамическую команду — обязан добавить вайтлист + экранирование.
    applescript = f'do shell script "{shell_cmd}" with administrator privileges'
    return sys_probe.run([OSASCRIPT, "-e", applescript], timeout=60)


def sudo_route(action):
    return _sudo_route_ip(action, _active_route_ip())


def _active_host_route_ip():
    """Manual route endpoint может резолвить DNS; status hot path это не делает."""
    try:
        active = local_state.active_node() or {}
        route_ip = local_state.resolve_route_ip(active)
    except (AttributeError, TypeError, KeyError) as exc:
        _log.debug("_active_host_route_ip: local_state недоступен (%s) — route_ip неприменим", exc)
        route_ip = ""
    return route_ip if _ip_literal(route_ip) else ""


def _host_route_action():
    body = request.get_json(silent=True)
    action = body.get("action", "") if isinstance(body, dict) else ""
    action = action or request.form.get("action", "") or request.args.get("action", "")
    if not isinstance(action, str):
        return ""
    return {"add": "add", "remove": "remove", "del": "remove"}.get(action, "")


def _guard_payload():
    """Достать {mode, domains} из тела запроса Traffic Guard. Defensive: не бросает.

    Возвращает dict как есть (валидацию делает local_state.validate_traffic_guard);
    None означает не-объектное/битое тело — роут отдаёт 400.
    """
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return None
    # Берём только известные v1-ключи: mode + domains. Всё остальное игнорируем,
    # чтобы клиент не мог протащить служебные поля state в секцию traffic_guard.
    return {"mode": body.get("mode", "off"), "domains": body.get("domains", {})}


def _throttle_payload():
    """Достать {action, domain, rate} из тела запроса throttle. Defensive: не бросает.

    Возвращает dict с сырыми значениями (валидацию делает роут через
    local_state.validate_throttle_request); None означает не-объектное/битое тело.
    """
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return None
    return {"action": body.get("action"), "domain": body.get("domain"), "rate": body.get("rate")}


_THROTTLE_PUBLIC_REDACTIONS = (
    (re.compile(r"Token\s*:\s*\d+"), "Token : [redacted]"),
    (re.compile(r"-X\s+\d+"), "-X [redacted]"),
)


def _redact_throttle_text(value):
    """Убрать pf release-token из публичной диагностики throttle.

    Raw token остаётся только в server-side result["token"] и state lease; err/out/rollback
    уходят в JSON/UI, поэтому чистим оба известных представления из traffic_shape (#68).
    """
    if value is None:
        text = ""
    elif isinstance(value, str):
        text = value
    else:
        text = str(value)
    for pattern, replacement in _THROTTLE_PUBLIC_REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def _throttle_result(r):
    """Свести dict от traffic_shape.{apply,clear}_throttle к ПУБЛИЧНОЙ форме для UI.

    Движок возвращает {ok, cancelled, rc, out, err, timeout, token?, rollback?}.
    token (pf enable-ref) наружу НЕ отдаём — он нужен только серверу для pfctl -X;
    роут читает его напрямую из result. Наружу — только статус/диагностика.
    """
    r = r or {}
    return {
        "ok": bool(r.get("ok")),
        "cancelled": bool(r.get("cancelled")),
        "rc": r.get("rc"),
        "out": _redact_throttle_text(r.get("out")),
        "err": _redact_throttle_text(r.get("err")),
    }


# ============================ non-privileged: сервисы ============================
def service_control(name, action):
    if name == "privoxy" and privoxy_system.protection_present():
        return {
            "rc": 77,
            "out": "",
            "err": "privoxy_protected: используйте `srouter privoxy start|stop|restart`",
            "timeout": False,
        }
    return sys_probe.run([BREW, "services", action, name], timeout=20)


# ============================ Flask-роуты ============================
@app.get("/api/status")
def api_status():
    return jsonify(gather_status())


@app.get("/api/probe/nodes")
def api_probe_nodes():
    return jsonify(probe_nodes())


@app.get("/api/nodes/ranking")
def api_nodes_ranking():
    metrics = probe_nodes_snapshot()
    active = (local_state.active_node() or {}).get("name")
    return jsonify(node_selector.recommendation(metrics, active))


@app.post("/api/node/select/<name>")
def api_node_select(name):
    enabled = {n.get("name") for n in local_state.enabled_nodes()}
    if name not in enabled:
        return jsonify({"ok": False, "err": "node not enabled or unknown"}), 400
    result = node_selector.select_node(name, enabled_names=enabled, runner=sys_probe.run, state_path=None)
    return jsonify(result), (200 if result.get("ok") else 500)


@app.post("/api/route/host")
def api_route_host():
    action = _host_route_action()
    if action not in ("add", "remove"):
        return jsonify({"ok": False, "err": "bad action"}), 400
    route_ip = _active_host_route_ip()
    r = _sudo_route_ip(action, route_ip)
    return jsonify({"action": action, "route_ip": route_ip, **_route_result(r)})


@app.post("/api/route/<action>")
def api_route(action):
    if action not in ("add", "remove"):
        return jsonify({"ok": False, "err": "bad action"}), 400
    r = sudo_route(action)
    return jsonify(_route_result(r))


@app.post("/api/channel")
@app.post("/api/channel/")
def api_channel_empty():
    return jsonify({"ok": False, "err": "bad channel target"}), 400


@app.post("/api/channel/<target>")
def api_channel(target):
    if target not in CHANNEL_TARGETS:
        return jsonify({"ok": False, "err": "bad channel target"}), 400
    result = switch_channel(target)
    return jsonify(result), (200 if result.get("ok") or result.get("cancelled") else 500)


@app.post("/api/service/<name>/<action>")
def api_service(name, action):
    if name not in ("xray", "privoxy") or action not in ("start", "stop", "restart"):
        return jsonify({"ok": False, "err": "not allowed"}), 400
    r = service_control(name, action)
    status = 409 if r.get("rc") == 77 else 200
    return jsonify({"ok": r["rc"] == 0, **r}), status


@app.get("/api/guard")
def api_guard_get():
    """Текущая секция Traffic Guard для UI-редактора: {mode, editable, domains, counts}.

    Возвращает ЧЕСТНЫЙ mode (on|off|auto). auto (#23, channel-семантика) v1-редактор
    не редактирует, поэтому editable=false и domains={} — плоскую проекцию активного
    канала НЕ отдаём: иначе пользователь сохранил бы её обратно легальным on/off-POST
    и затёр channel-map (round-trip потеря). fail-closed зеркалится в POST → 409.
    """
    guard = local_state.traffic_guard_config()
    raw_mode = guard.get("mode")
    mode = raw_mode if raw_mode in ("on", "off", "auto") else "off"
    editable = mode in ("on", "off")
    # Для редактируемых режимов отдаём реальные block/allow правила; для auto — пусто.
    domains = guard.get("domains") if (editable and isinstance(guard.get("domains"), dict)) else {}
    return jsonify(
        {
            "mode": mode,
            "editable": editable,
            "domains": domains,
            "guard": probe_traffic_guard(),
            # Активный throttle-lease для UI после перезагрузки страницы. token наружу
            # НЕ отдаём (он нужен только серверу для pfctl -X) — лишь domain+rate.
            "throttle": _public_active_throttle(),
        }
    )


def _public_throttle(entry):
    """Публичная (без token) проекция throttle-lease или None.

    token наружу НЕ отдаём (он нужен только серверу для pfctl -X) — лишь
    domain/rate/applied_at + cleanup-маркеры. entry=None -> None.
    """
    if not entry:
        return None
    needs_cleanup = bool(entry.get("needs_cleanup"))
    cleanup_persisted = bool(entry.get("cleanup_persisted")) if "cleanup_persisted" in entry else needs_cleanup
    if not needs_cleanup:
        cleanup_persisted = False
    return {
        "domain": entry.get("domain"),
        "rate": entry.get("rate"),
        "applied_at": entry.get("applied_at"),
        "needs_cleanup": needs_cleanup,
        "cleanup_persisted": cleanup_persisted,
    }


def _public_active_throttle():
    """Публичная проекция ТЕКУЩЕГО активного lease из state (re-read) — для GET-роута."""
    return _public_throttle(local_state.load_active_throttle())


@app.post("/api/guard")
def api_guard():
    """Редактор Traffic Guard (#15): записать {mode, domains} в unified state.

    Scope v1-редактора — только on/off + block/allow. auto (#23, channel-семантика)
    и throttle (#13) здесь не поддерживаются и режутся ПРЯМО в роуте, до общего
    валидатора: local_state.validate_traffic_guard эволюционирует (#56 разрешил
    auto+channel-карты), поэтому scope роута нельзя привязывать к нему. Дальше
    validate_traffic_guard ловит невалидные block/allow/parent-child. Пишем через
    atomic save_state; при невалидном/битом вводе state не перезаписывается.
    """
    guard = _guard_payload()
    if guard is None:
        return jsonify({"ok": False, "errors": ["traffic_guard payload must be an object"]}), 400

    # Жёсткая scope-граница редактора: mode строго on/off. auto/throttle/прочее reject
    # здесь, независимо от того, что общий валидатор мог их начать принимать.
    if guard.get("mode") not in ("on", "off"):
        return jsonify(
            {"ok": False, "errors": ['traffic_guard.mode must be "on" or "off" (auto/throttle not supported in editor)']}
        ), 400

    errors = local_state.validate_traffic_guard(guard)
    if errors:
        return jsonify({"ok": False, "errors": errors}), 400

    # Читаем текущий state и не трогаем файл, если его нельзя безопасно перезаписать.
    state, readable = local_state.load_state_checked()
    if not readable:
        return jsonify({"ok": False, "errors": ["local state is not safely writable"]}), 409

    # Round-trip fail-closed: если ТЕКУЩИЙ state в auto (#23, channel-map), v1-редактор
    # его не перезаписывает даже легальным on/off — иначе затрёт channel-семантику,
    # которую редактор не умеет представлять. Это отдельная граница от payload-mode выше.
    current = state.get("traffic_guard")
    if isinstance(current, dict) and current.get("mode") == "auto":
        return jsonify(
            {"ok": False, "errors": ["traffic_guard is in auto mode; v1 editor cannot overwrite it"]}
        ), 409

    state["traffic_guard"] = guard
    if local_state.save_state(state) is None:
        return jsonify({"ok": False, "errors": ["failed to persist traffic_guard"]}), 500

    # Свежий probe для UI: обновлённый rule/blocked count из только что записанного state.
    return jsonify({"ok": True, "errors": [], "guard": probe_traffic_guard()})


@app.post("/api/guard/throttle")
def api_guard_throttle():
    """Traffic Guard throttle (#13/#22): apply/clear per-domain шейпинга через traffic_shape.

    EXPERIMENTAL: движок ещё не валидирован вручную на реальном pf (automation ladder
    issue #22) — UI помечает throttle experimental.

    Тело: {action:"apply", domain, rate} | {action:"clear"}. Валидация ВХОДА — ПРЯМО
    в роуте (fail-closed, канон #60): невалидный domain/rate -> 400, движок НЕ зван.

    Одно-pipe'овый движок (PIPE_NUM один -> один активный throttle за раз). Повторный
    apply при активном lease -> 409 (НЕ скрытый auto-clear+apply: тот при сбое clear
    потерял бы токен/оставил pipe — магия на привилегированной границе; канон no-hidden-magic).
    Пользователь сначала явно clear.

    Токен pf enable-ref из apply ОБЯЗАН персиститься (issue #61): без него clear после
    рестарта дашборда не отдаст токен в pfctl -X и enable-ref потечёт. Session-lease
    (кого clear'ить) — ответственность роута (traffic_shape.clear_throttle docstring).

    cancelled (rc -128, отмена пароля osascript) -> структурированный ответ, НЕ 500.
    """
    payload = _throttle_payload()
    if payload is None:
        return jsonify({"ok": False, "err": "throttle payload must be an object"}), 400

    action = payload.get("action")
    if action == "clear":
        return _throttle_clear()
    if action == "apply":
        return _throttle_apply(payload)
    return jsonify({"ok": False, "err": 'action must be "apply" or "clear"'}), 400


def _throttle_apply(payload):
    """apply-ветка /api/guard/throttle: валидация -> preflight -> lease-guard -> движок -> персист.

    Privileged-граница (pf enable-ref, cycle-2 review): token pf переживает сбой только
    если он durably recoverable в state. Поэтому:
    - preflight writability ДО apply_throttle: state неперезаписываем -> отказ ДО того,
      как движок создаст enable-ref (token ещё не родился, нечего терять);
    - при apply ok:False С распарсенным token (post--E failure): проверяем внутренний
      rollback движка. rollback.ok:True -> enable-ref уже свободен, token персистить НЕ
      надо (мусорный lease для уже-освобождённого ref). rollback отсутствует/ok:False ->
      persist cleanup-lease (token recoverable) + needs_cleanup для оператора/UI.
    """
    # Валидация входа В РОУТЕ: невалидный domain/rate -> 400, движок не зовём.
    domain, rate = local_state.validate_throttle_request(payload.get("domain"), payload.get("rate"))
    if domain is None:
        return jsonify(
            {"ok": False, "err": "domain must be a valid host and rate a positive integer (Kbit/s)"}
        ), 400

    # Один активный throttle за раз (движок одно-pipe'овый). Активный lease -> 409,
    # без скрытого авто-clear (fail-closed: не рискуем потерять токен при сбое clear).
    active = local_state.load_active_throttle()
    if active is not None:
        return jsonify(
            {
                "ok": False,
                "err": "throttle already active for '%s'; clear it first" % active.get("domain"),
                "active": _public_throttle(active),
            }
        ), 409

    # Preflight writability (#68): readable state ещё не доказывает, что atomic-write
    # exact save-path работает. Под mutation-lock делаем no-op save ДО privileged apply.
    if not local_state.preflight_state_write():
        return jsonify(
            {"ok": False, "err": "local state is not safely writable; cannot manage throttle lease"}
        ), 409

    result = traffic_shape.apply_throttle(domain, rate)
    body = {"action": "apply", "domain": domain, "rate": rate, **_throttle_result(result)}
    token = (result or {}).get("token")

    if body.get("cancelled"):
        # Отмена пароля osascript: не ошибка сервера, движок ничего не включил.
        return jsonify(body), 200

    if body.get("ok"):
        # apply с ok:true. На привилегированной границе не доверяем контракту движка как
        # инварианту этого слоя: ok БЕЗ token -> fail-closed 500 (clear_throttle(None) НЕ
        # зовёт pfctl -X, enable-ref бы тёк, маскировать под 'rolled back' нельзя — #61).
        if not token:
            body["ok"] = False
            body["err"] = "throttle applied but pf release-token missing — cannot persist lease"
            return jsonify(body), 500
        return _persist_active_or_cleanup(body, domain, rate, token)

    # apply ok:False С распарсенным token (post--E failure): pf включён, enable-ref жив.
    # Проверяем внутренний rollback движка — он уже мог освободить enable-ref.
    if token:
        rollback = (result or {}).get("rollback")
        if isinstance(rollback, dict) and rollback.get("ok"):
            # Движок сам подтвердил cleanup ok -> enable-ref свободен, token освобождён.
            # Честно рапортуем 'rolled back', cleanup-lease НЕ нужен (мусорный был бы).
            body["ok"] = False
            body["err"] = (body.get("err") + "; " if body.get("err") else "") + "rolled back by engine"
            body["rollback"] = _throttle_result(rollback)
            return jsonify(body), 500
        # Внутреннего rollback не было ИЛИ он не ok (fail/cancel/timeout) — token жив на
        # pf, не освобождён. Persist cleanup-lease, чтобы он был recoverable после рестарта.
        return _persist_cleanup_lease(body, domain, rate, token)

    # apply ok:False без token (fail до -E, напр. busy pipe/probe-fail): pf не включён,
    # enable-ref не создан -> нечего персистить. Структурированный 500.
    return jsonify(body), 500


def _persist_active_or_cleanup(body, domain, rate, token):
    """apply ok:true: персист активный lease. При провале записи — откатываем throttle,
    проверяя rollback.ok (cycle-2 FIX): rollback подтверждён -> 'rolled back'; rollback
    cancel/fail -> cleanup-lease + needs_cleanup (token recoverable).
    """
    saved = local_state.save_active_throttle(
        {"domain": domain, "rate": rate, "token": token, "applied_at": int(time.time())}
    )
    if saved is not None:
        body["throttle"] = _public_throttle(saved)
        return jsonify(body), 200

    # Токен не удалось персистить — критично: clear его больше не найдёт в обычном lease.
    # Откатываем throttle ВАЛИДНЫМ токеном.
    rollback = traffic_shape.clear_throttle(token)
    body["ok"] = False
    if isinstance(rollback, dict) and rollback.get("ok"):
        # rollback подтверждён -> enable-ref освобождён, честно 'rolled back'.
        body["err"] = "throttle applied but token persist failed; rolled back"
        body["rollback"] = _throttle_result(rollback)
    else:
        # rollback cancel/fail -> enable-ref УТЁК. Token НЕ освобождён — persist cleanup-lease
        # (token recoverable) и structured needs_cleanup для оператора. Не маскируем под успех.
        body["err"] = "throttle applied, token persist failed AND rollback did not succeed"
        body["rollback"] = _throttle_result(rollback)
        cleanup = local_state.save_active_throttle(
            {"domain": domain, "rate": rate, "token": token, "applied_at": int(time.time())},
            needs_cleanup=True,
        )
        body["needs_cleanup"] = True
        body["cleanup_persisted"] = cleanup is not None
        body["throttle"] = _public_throttle(cleanup) if cleanup else None
    return jsonify(body), 500


def _persist_cleanup_lease(body, domain, rate, token):
    """apply ok:False (post--E failure) без подтверждённого внутреннего rollback:
    pf-токен ЖИВ, не освобождён. Persist cleanup-lease, чтобы token был recoverable
    для последующего clear (cycle-2 FIX #2). Structured needs_cleanup.
    """
    cleanup = local_state.save_active_throttle(
        {"domain": domain, "rate": rate, "token": token, "applied_at": int(time.time())},
        needs_cleanup=True,
    )
    body["ok"] = False
    body["err"] = (body.get("err") + "; " if body.get("err") else "") + (
        "pf enable-ref is live (apply failed post--E); token persisted for cleanup"
    )
    body["needs_cleanup"] = True
    body["cleanup_persisted"] = cleanup is not None
    body["throttle"] = _public_throttle(cleanup) if cleanup else None
    return jsonify(body), 500


def _throttle_clear():
    """clear-ветка /api/guard/throttle: снять активный throttle сохранённым токеном.

    cycle-2 FIX #1: нет активного lease -> NO-OP (409), движок НЕ зовётся ВООБЩЕ.
    clear_throttle(None) всё равно flush'ит throttle-anchor + удаляет PIPE_NUM без
    доказательства владения -> разрушил бы ЧУЖОЙ pipe при stale/corrupt/missing lease
    или Clear на неактивном дашборде. Orphan-repair (если нужен) — отдельный action.
    """
    active = local_state.load_active_throttle()
    if active is None:
        # Нечего снимать, И нельзя звать движок с token=None (деструктивный cleanup
        # чужого pipe). Честный no-op без privileged-вызова.
        return jsonify(
            {"ok": False, "err": "no active throttle to clear", "action": "clear"}
        ), 409

    # Токен из lease обязателен для pfctl -X (issue #61).
    token = active.get("token")
    result = traffic_shape.clear_throttle(token)
    body = {"action": "clear", **_throttle_result(result)}

    if body.get("cancelled"):
        # Отмена пароля: lease НЕ трогаем (throttle всё ещё активен на pf).
        return jsonify(body), 200

    if body.get("ok"):
        # Снято успешно (enable-ref освобождён) — сбрасываем lease. Если персист None
        # провалился (битый/неперезаписываемый state), lease остаётся — честно сообщаем
        # partial (throttle снят, но state рассинхрон; не маскируем под чистый успех).
        cleared = local_state.clear_active_throttle()
        if cleared:
            body["throttle"] = None
        else:
            body["err"] = (body.get("err") + "; " if body.get("err") else "") + (
                "throttle cleared on pf, but active-lease state could not be persisted — "
                "it may reappear after restart"
            )
        return jsonify(body), 200

    # Сбой clear: lease оставляем (throttle всё ещё активен на pf) — явный сигнал для UI,
    # чтобы пользователь понял, что нужно повторить. ok:false, status 500 (серверная ошибка).
    body["still_active"] = True
    body["throttle"] = _public_throttle(active)
    return jsonify(body), 500


# ============================ PF-изоляция доменов (/api/isolate/*) ============================
def _isolate_result(r):
    """Свести dict от isolate_firewall к публичной форме для UI (как _throttle_result)."""
    r = r or {}
    return {
        "ok": bool(r.get("ok")),
        "cancelled": bool(r.get("cancelled")),
        "rc": r.get("rc"),
        "err": r.get("err") or "",
        "out": r.get("out") or "",
        "timeout": bool(r.get("timeout")),
    }


def _public_isolate(lease):
    """Публичный вид isolate-lease (БЕЗ token наружу — он идёт в pfctl -X)."""
    if not isinstance(lease, dict):
        return None
    return {
        "domains": lease.get("domains", []),
        "ips": lease.get("ips", {}),
        "unresolved": lease.get("unresolved", []),
        "ports": lease.get("ports", [80, 443]),
        "phase": lease.get("phase", "working"),
        "applied_at": lease.get("applied_at"),
    }


@app.get("/api/isolate")
def api_isolate_get():
    """Текущий isolate-lease (публичный, без token) + config."""
    active = local_state.load_active_isolate()
    cfg = (local_state.load_state() or {}).get("isolate") or {}
    return jsonify({"active": _public_isolate(active), "config": cfg})


@app.post("/api/isolate/enable")
def api_isolate_enable():
    """Включить PF-изоляцию: dig домены → pfctl -T replace. Валидация → preflight → lease-guard → движок → персист.

    Симметрично _throttle_apply, но проще: isolate_firewall.enable_isolation не делает внутренний
    rollback (упрощён vs throttle), поэтому cleanup-lease только при ok:False С token. fail-closed:
    ok без token = 500 (enable-ref бы тёк). cancelled = 200 (не ошибка сервера).
    """
    payload = request.get_json(silent=True) or {}
    cfg = (local_state.load_state() or {}).get("isolate") or {}
    domains = payload.get("domains") or cfg.get("domains") or isolate_firewall.DEFAULT_DOMAINS
    ports = payload.get("ports") or cfg.get("ports") or list(isolate_firewall.DEFAULT_PORTS)

    # Валидация В РОУТЕ: невалидные домены/порты → 400, движок не зовём.
    norm, errs = local_state.validate_isolate({"enabled": True, "domains": list(domains), "ports": list(ports)})
    if norm is None:
        return jsonify({"ok": False, "err": "; ".join(errs)}), 400
    domains, ports = norm["domains"], norm["ports"]

    # Один активный isolate за раз. Активный lease → 409 без скрытого авто-disable.
    active = local_state.load_active_isolate()
    if active is not None:
        return jsonify({"ok": False, "err": "isolate already active; disable it first",
                        "active": _public_isolate(active)}), 409

    # Preflight writability: state неперезаписываем → отказ ДО pf enable-ref.
    if not local_state.preflight_state_write():
        return jsonify({"ok": False, "err": "local state is not safely writable; cannot manage isolate lease"}), 409

    result = isolate_firewall.enable_isolation(domains, ports=ports)
    body = {"action": "enable", **_isolate_result(result),
            "domains": result.get("domains", {}), "unresolved": result.get("unresolved", []),
            "ports": result.get("ports", ports)}
    token = (result or {}).get("token")

    if body.get("cancelled"):
        return jsonify(body), 200  # отмена пароля osascript — не ошибка сервера

    if body.get("ok"):
        if not token:
            body["ok"] = False
            body["err"] = "isolate enabled but pf release-token missing — cannot persist lease"
            return jsonify(body), 500
        saved = local_state.save_active_isolate(
            {"domains": domains, "ips": result.get("domains", {}), "unresolved": result.get("unresolved", []),
             "ports": ports, "token": token, "applied_at": int(time.time()), "phase": "working"}
        )
        if saved is None:
            # token не персистился — критично. Cleanup валидным token, рапортуем partial.
            isolate_firewall.disable_isolation(token=token)
            body["ok"] = False
            body["err"] = "isolate enabled on pf but lease could not be persisted; rolled back"
            return jsonify(body), 500
        body["isolate"] = _public_isolate(saved)
        return jsonify(body), 200

    # ok:False С token (post--E failure): enable-ref жив. Persist cleanup-lease (token recoverable).
    if token:
        local_state.save_active_isolate(
            {"domains": domains, "ips": {}, "unresolved": result.get("unresolved", []),
             "ports": ports, "token": token, "applied_at": int(time.time()), "phase": "working"}
        )
        body["err"] = (body.get("err") + "; " if body.get("err") else "") + "pf enable-ref live — cleanup-lease persisted"
    return jsonify(body), 500


@app.post("/api/isolate/disable")
def api_isolate_disable():
    """Снять PF-изоляцию. Нет активного lease → no-op 409 (движок не зовём — fail-closed)."""
    active = local_state.load_active_isolate()
    if active is None:
        return jsonify({"ok": False, "err": "no active isolate to disable", "action": "disable"}), 409
    token = active.get("token")
    result = isolate_firewall.disable_isolation(token=token)
    body = {"action": "disable", **_isolate_result(result)}
    if body.get("cancelled"):
        return jsonify(body), 200  # отмена пароля — lease НЕ трогаем (изоляция ещё активна)
    if body.get("ok"):
        cleared = local_state.clear_active_isolate()
        body["isolate"] = None if cleared else _public_isolate(active)
        if not cleared:
            body["err"] = (body.get("err") + "; " if body.get("err") else "") + (
                "isolate disabled on pf, but lease state could not be persisted — may reappear after restart")
        return jsonify(body), 200
    body["still_active"] = True
    body["isolate"] = _public_isolate(active)
    return jsonify(body), 500


@app.post("/api/isolate/refresh")
def api_isolate_refresh():
    """Re-dig домены → pfctl -T replace (token из lease). IP меняются → обновление таблицы."""
    active = local_state.load_active_isolate()
    if active is None:
        return jsonify({"ok": False, "err": "no active isolate to refresh", "action": "refresh"}), 409
    domains = active.get("domains", [])
    ports = active.get("ports", [80, 443])
    token = active.get("token")
    result = isolate_firewall.refresh_isolation_ips(domains, ports=ports, token=token)
    body = {"action": "refresh", **_isolate_result(result),
            "domains": result.get("domains", {}), "unresolved": result.get("unresolved", [])}
    if body.get("ok"):
        # Обновим IP-снимок в lease (token/phase сохраняются).
        saved = local_state.save_active_isolate(
            {"domains": domains, "ips": result.get("domains", {}), "unresolved": result.get("unresolved", []),
             "ports": ports, "token": token, "applied_at": active.get("applied_at"), "phase": "working"}
        )
        body["isolate"] = _public_isolate(saved)
        return jsonify(body), 200
    return jsonify(body), 500


# ============================ git-proxy для github (/api/git-proxy) ============================
@app.get("/api/git-proxy")
def api_git_proxy_get():
    """Текущее состояние git-прокси для github (читает ~/.gitconfig)."""
    return jsonify(git_proxy.status())


@app.post("/api/git-proxy/enable")
def api_git_proxy_enable():
    """Прописать http.https://github.com.proxy = SOCKS5 xray (scoped github.com)."""
    return jsonify(git_proxy.enable()), 200


@app.post("/api/git-proxy/disable")
def api_git_proxy_disable():
    """Снять http.https://github.com.proxy (--unset). Идемпотентно."""
    return jsonify(git_proxy.disable()), 200


# ============================ Claude Code proxy (/api/claude-proxy) ============================
@app.get("/api/claude-proxy")
def api_claude_proxy_get():
    """Текущее состояние HTTPS_PROXY для Claude Code (читает ~/.claude/settings.json)."""
    return jsonify(claude_proxy.status())


@app.post("/api/claude-proxy/enable")
def api_claude_proxy_enable():
    """Прописать env.HTTPS_PROXY/HTTP_PROXY = privoxy в ~/.claude/settings.json."""
    return jsonify(claude_proxy.enable()), 200


@app.post("/api/claude-proxy/disable")
def api_claude_proxy_disable():
    """Удалить env proxy-ключи из ~/.claude/settings.json. Идемпотентно."""
    return jsonify(claude_proxy.disable()), 200


# ============================ единая картина прокси (/api/proxy/overview) ============================
# Зачем отдельный роут, а не поле в /api/status или /health: /health документирован как
# «мгновенный, лёгкий» (внешний мониторинг), а gather_status живёт с бюджетом 12s и кэшем
# 1.5s на телеметрию. Парный замер direct-vs-proxy стоит секунды и нужен ПО ТРЕБОВАНИЮ.
# GET (не POST) -> не попадает под _MUTATION_LOCK: чтение картины не должно ловить 409.
@app.get("/api/proxy/overview")
def api_proxy_overview():
    """Кто куда настроен + идёт ли трафик физически.

    ?probe=1 — включить runtime-пробы и парный замер (секунды). Без параметра —
    только чтение конфигов, чтобы открытие страницы оставалось лёгким.
    """
    # Вайтлист значения, а не bool(строки): "0"/"false" — это ВЫКЛ, а не «непустая строка».
    probe = (request.args.get("probe") or "").strip().lower() in ("1", "true", "yes")
    return jsonify(proxy_registry.overview(probe=probe))


# ============================ единый write-путь прокси (/api/proxy/<action>) ============================
# Заменяет разрозненные /api/git-proxy/* и /api/claude-proxy/*: одна точка на всех
# управляемых потребителей реестра.
#
# Бюджет на мутацию. git_proxy берёт БЛОКИРУЮЩИЙ cross-process flock (fcntl.LOCK_EX): если
# лок занят CLI-процессом (`srouter install`), прямой вызов повесил бы HTTP-запрос навсегда —
# lock_hierarchy этот путь не покрывает (там только threading.Lock, а flock межпроцессный).
# Поэтому apply уходит в отдельный поток с ограниченным ожиданием: превышение бюджета — это
# честный ok=false с причиной, а не бесконечный висяк на глазах у пользователя.
_PROXY_APPLY_TIMEOUT_SEC = 25

_PROXY_ACTIONS = ("enable", "disable")


@app.post("/api/proxy/<action>")
def api_proxy_apply(action):
    """Включить/выключить прокси у потребителей реестра. {ok, results:[{id, ok, err}]}.

    Тело: {"ids": ["git", ...]} либо {} — все управляемые. Вайтлист action в роуте
    (канон: мутирующий роут валидирует сам, не полагаясь на нижний слой).
    """
    if action not in _PROXY_ACTIONS:
        return jsonify({"ok": False, "err": f"unknown action: {action}"}), 404

    payload = request.get_json(silent=True) or {}
    ids = payload.get("ids")
    if ids is not None and not isinstance(ids, list):
        return jsonify({"ok": False, "err": "ids must be a list"}), 400
    if isinstance(ids, list) and not all(isinstance(i, str) for i in ids):
        return jsonify({"ok": False, "err": "ids must be strings"}), 400

    # Зовём через атрибут модуля (proxy_registry.apply), а не через from-import: тесты
    # подменяют именно атрибут — канон moving-caller-inverts-mock-ownership.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(lambda: proxy_registry.apply(ids, action=action))
        try:
            result = future.result(timeout=_PROXY_APPLY_TIMEOUT_SEC)
        except concurrent.futures.TimeoutError:
            # Поток остаётся висеть на flock — прервать его нельзя, но запрос отпускаем.
            return jsonify({
                "ok": False,
                "err": (f"таймаут {_PROXY_APPLY_TIMEOUT_SEC}s: операция не завершилась — "
                        "вероятно, конфиг занят другим процессом (srouter install?)"),
                "results": [],
            }), 504

    return jsonify(result), (200 if result.get("ok") else 500)


# ============================ /health (лёгкий healthcheck) ============================
@app.get("/health")
def health_endpoint():
    """Лёгкий healthcheck для внешнего мониторинга. 200 ok / 503 degraded|down.

    Мгновенный, без gather_status (не телеметрия). Используется uptime-мониторингом/balancer'ами.
    """
    h = health.check_all()
    code = 200 if h["status"] == "ok" else 503
    return jsonify(h), code
