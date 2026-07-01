#!/usr/bin/env python3
"""Локальный дашборд: мониторинг и управление цепочкой privoxy→xray→Reality + VPN/маршруты.

Запуск:  python3 dashboard.py   →   http://127.0.0.1:8787
Только loopback, debug=False. Privileged-действия (route) спрашивают пароль macOS через osascript.
"""
import threading
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, wait
from flask import Flask, jsonify, Response

import local_state
from dashboard_common import *
from dashboard_connectivity import *
from dashboard_geo import *
from dashboard_network import *
from dashboard_nodes import *
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


# ============================ probe-функции ============================
def probe_traffic_guard(state_path=None):
    """Только status probe: редактор Traffic Guard остаётся scope #15."""
    guard = local_state.traffic_guard_config(path=state_path)
    errors = guard.get("errors") if isinstance(guard.get("errors"), list) else []
    if guard.get("valid") is not True:
        return {
            "mode": "off",
            "config_status": "invalid",
            "configured_domains": 0,
            "blocked_domains": 0,
            "allowed_domains": 0,
            "rule_count": 0,
            "errors": errors,
            "status": "warn",
        }
    mode = guard.get("mode") if guard.get("mode") in ("on", "off") else "off"
    domains = guard.get("domains") if isinstance(guard.get("domains"), dict) else {}
    enabled = mode == "on"
    blocked = [domain for domain, policy in domains.items() if policy == "block"]
    allowed = [domain for domain, policy in domains.items() if policy == "allow"]
    return {
        "mode": mode,
        "config_status": mode,
        "configured_domains": len(domains),
        "blocked_domains": len(blocked) if enabled else 0,
        "allowed_domains": len(allowed) if enabled else 0,
        "rule_count": len(blocked) if enabled else 0,
        "errors": [],
        "status": "ok",
    }


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
def sudo_route(action):
    route_ip = _active_route_ip()
    if not route_ip:
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


@app.post("/api/route/<action>")
def api_route(action):
    if action not in ("add", "remove"):
        return jsonify({"ok": False, "err": "bad action"}), 400
    r = sudo_route(action)
    cancelled = r["rc"] not in (0, None) and "-128" in (r["err"] or "")
    return jsonify({"ok": r["rc"] == 0, "cancelled": cancelled, **r})


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


@app.get("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")


# ============================ одностраничный UI ============================
INDEX_HTML = (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")


# ============================ запуск ============================
if __name__ == "__main__":
    print(f"Dashboard: http://127.0.0.1:{PORT}")
    app.run(host="127.0.0.1", port=PORT, threaded=True, debug=False)  # loopback, debug OFF!
