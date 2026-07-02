#!/usr/bin/env python3
"""Локальный дашборд: мониторинг и управление цепочкой privoxy→xray→Reality + VPN/маршруты.

Запуск:  python3 dashboard.py   →   http://127.0.0.1:8787
Только loopback, debug=False. Privileged-действия (route) спрашивают пароль macOS через osascript.
"""
import threading
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, wait
from flask import Flask, jsonify, Response, request

import local_state
from dashboard_common import *
from dashboard_connectivity import *
from dashboard_geo import *
from dashboard_network import *
from dashboard_nodes import *
from dashboard_traffic import *
import node_selector
import sys_probe

# Активный узел нельзя замораживать на import: #8 меняет srouter.local.json в рантайме.
# Эти имена оставлены только для совместимости старых импорт-тестов; рабочий код ниже
# каждый раз вызывает _active_route_ip().
ACTIVE_ENDPOINT = ""
VPS_IP = ""

PORT = 8787
STATUS_CACHE_TTL_SEC = 1.5
STATUS_PROBE_BUDGET_SEC = 12

app = Flask(__name__)


# ============================ сборка статуса ============================
_cache = {"ts": 0.0, "data": None, "active_route_ip": "", "active_route_key": None}
_lock = threading.Lock()


def _run_status_probe_set(probes, budget_sec):
    """Запустить быстрые probes с общим бюджетом и не ждать зависшие futures после timeout."""
    if not probes:
        return {}
    out = {}
    ex = ThreadPoolExecutor(max_workers=len(probes))
    futs = {k: ex.submit(fn) for k, fn in probes.items()}
    try:
        done, _pending = wait(futs.values(), timeout=max(0.0, float(budget_sec)))
        for k, f in futs.items():
            if f not in done:
                out[k] = {"status": "unknown", "error": "timeout"}
                continue
            try:
                out[k] = f.result()
            except Exception as e:
                out[k] = {"status": "unknown", "error": str(e) or e.__class__.__name__}
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return out


def gather_status():
    now = time.time()
    active_route = _active_route_context()
    active_route_ip = active_route["route_ip"]
    active_route_key = active_route["key"]
    with _lock:
        if (
            _cache["data"]
            and _cache.get("active_route_key") == active_route_key
            and now - _cache["ts"] < STATUS_CACHE_TTL_SEC
        ):
            return _cache["data"]

    probes = {
        "services": probe_services,
        "tunnel": probe_tunnel,
        "exit_ip": lambda: probe_exit_ip(route_ip=active_route_ip),
        "vpn": probe_vpn,
        "route": lambda: probe_route_to_vps(route_ip=active_route_ip),
        "direct": probe_direct,
        "traffic_guard": probe_traffic_guard,
        "connectivity": probe_connectivity,
        # --- киношная телеметрия ---
        "ips": lambda: probe_ips(route_ip=active_route_ip),
        "ping": lambda: probe_ping(route_ip=active_route_ip),
        "dns": probe_dns,
        "ifaces": probe_ifaces,
        "geo_distance": lambda: probe_geo_distance(route_ip=active_route_ip),
    }
    out = _run_status_probe_set(probes, STATUS_PROBE_BUDGET_SEC)
    out["nodes"] = probe_nodes_snapshot()
    out["ts"] = now
    with _lock:
        _cache.update(ts=now, data=out, active_route_ip=active_route_ip, active_route_key=active_route_key)
    return out


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
    except Exception:
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


# ============================ non-privileged: сервисы ============================
def service_control(name, action):
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
    return jsonify({"ok": r["rc"] == 0, **r})


@app.get("/api/guard")
def api_guard_get():
    """Текущая секция Traffic Guard для UI-редактора: {mode, domains, counts}.

    Возвращает нормализованные block/allow правила из unified state. auto-режим
    (#23) в v1-редакторе не показываем — деградируем в off с пустой картой,
    чтобы UI-таблица не пыталась рисовать channel-семантику.
    """
    guard = local_state.traffic_guard_config()
    mode = guard.get("mode") if guard.get("mode") in ("on", "off") else "off"
    domains = guard.get("domains") if isinstance(guard.get("domains"), dict) else {}
    return jsonify({"mode": mode, "domains": domains, "guard": probe_traffic_guard()})


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

    state["traffic_guard"] = guard
    if local_state.save_state(state) is None:
        return jsonify({"ok": False, "errors": ["failed to persist traffic_guard"]}), 500

    # Свежий probe для UI: обновлённый rule/blocked count из только что записанного state.
    return jsonify({"ok": True, "errors": [], "guard": probe_traffic_guard()})


@app.get("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")


# ============================ одностраничный UI ============================
INDEX_HTML = (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")


# ============================ запуск ============================
if __name__ == "__main__":
    print(f"Dashboard: http://127.0.0.1:{PORT}")
    app.run(host="127.0.0.1", port=PORT, threaded=True, debug=False)  # loopback, debug OFF!
