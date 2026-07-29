#!/usr/bin/env python3
"""Flask app-фабрика + статус-кэш + CSRF/Host/mutation-lock guards для дашборда (issue #227).

Экстракция из dashboard.py (эпик #107/#158, канон no-hidden-magic-follow-canon): чистый
перенос кода, без редизайна. Роуты — в dashboard_routes.py (импортирует `app` отсюда).
dashboard.py остаётся тонким фасадом и точкой входа (python3 dashboard.py).
"""
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor, wait
from flask import Flask, g, jsonify, Response, request

from dashboard_common import _active_route_context
from dashboard_connectivity import probe_connectivity, probe_exit_ips_per_iface, probe_ifaces
from dashboard_geo import probe_geo_distance, probe_ips
from dashboard_hotroutes import probe_hot_routes
from dashboard_isolate import probe_isolate
from dashboard_network import (
    probe_direct,
    probe_exit_ip,
    probe_ping,
    probe_route_to_vps,
    probe_services,
    probe_tunnel,
    probe_vpn,
)
from dashboard_nodes import probe_dns, probe_nodes_snapshot
from dashboard_traffic import probe_traffic_guard
import lock_hierarchy

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
    # issue #159: bounded acquire (уровень CACHE). Read-точка: таймаут = cache miss,
    # пробы пересчитаются ниже. Default timeout=0 ≡ `with _lock:`.
    try:
        with lock_hierarchy.bounded_acquire(
            _lock, name="status-cache", level=lock_hierarchy.LEVEL_CACHE
        ):
            if (
                _cache["data"]
                and _cache.get("active_route_key") == active_route_key
                and now - _cache["ts"] < STATUS_CACHE_TTL_SEC
            ):
                return _cache["data"]
    except lock_hierarchy.LockAcquireTimeout:
        pass  # cache miss — пересчитаем пробы ниже

    probes = {
        "services": probe_services,
        "tunnel": probe_tunnel,
        "exit_ip": lambda: probe_exit_ip(route_ip=active_route_ip),
        "vpn": probe_vpn,
        "route": lambda: probe_route_to_vps(route_ip=active_route_ip),
        "direct": probe_direct,
        "traffic_guard": probe_traffic_guard,
        "hot_routes": probe_hot_routes,
        "isolate": probe_isolate,
        "connectivity": probe_connectivity,
        # --- киношная телеметрия ---
        "ips": lambda: probe_ips(route_ip=active_route_ip),
        "ping": lambda: probe_ping(route_ip=active_route_ip),
        "dns": probe_dns,
        "ifaces": probe_ifaces,
        "exit_ips": probe_exit_ips_per_iface,
        "geo_distance": lambda: probe_geo_distance(route_ip=active_route_ip),
    }
    out = _run_status_probe_set(probes, STATUS_PROBE_BUDGET_SEC)
    out["nodes"] = probe_nodes_snapshot()
    out["ts"] = now
    # issue #159: bounded acquire (уровень CACHE). Write-точка: таймаут → пропускаем
    # запись кэша (следующий /api/status пересчитает).
    try:
        with lock_hierarchy.bounded_acquire(
            _lock, name="status-cache", level=lock_hierarchy.LEVEL_CACHE
        ):
            _cache.update(ts=now, data=out, active_route_ip=active_route_ip, active_route_key=active_route_key)
    except lock_hierarchy.LockAcquireTimeout:
        pass  # skip-write; кэш не критичен
    return out


# ============================ CSRF/Origin-guard (issue #42) ============================
# Сервис слушает только loopback, но loopback НЕ защищает от browser-origin CSRF:
# любой сайт, открытый в браузере, может сделать form-POST/fetch на 127.0.0.1:8787
# и триггерить привилегированное действие (osascript admin-prompt, route add/del,
# brew services). Поэтому все POST-мутации проходят через общий guard ДО handler.
#
# Подход: defense-in-depth из двух сигналов. Явно чужой Origin — это сигнал атаки,
# и на привилегированной границе он должен резаться БЕЗУСЛОВНО (fail-closed), а не
# перекрываться доверием к Sec-Fetch-Site. Поэтому порядок проверок такой:
#   1) Origin ПРИСУТСТВУЕТ и НЕ в _allowed_origins() -> 403 (чужой origin бьёт первым,
#      независимо от Sec-Fetch-Site — иначе атакующий выставил бы Sec-Fetch-Site: none
#      и обошёл guard; см. cycle-review PR #58).
#   2) Origin отсутствует ИЛИ разрешён -> решает Fetch-Metadata: Sec-Fetch-Site
#      cross-site/same-site -> 403; same-origin/none/отсутствует -> пропускаем.
# Sec-Fetch-Site браузер выставляет сам и подделать из JS нельзя (forbidden header),
# поэтому он надёжен для отличия cross-site КОГДА Origin не изобличает атаку.
#
# Итог: browser cross-origin POST -> 403; same-origin UI и curl/non-browser -> проходят.
# Легитимные origin: http(s)://127.0.0.1:8787 и http(s)://localhost:8787.

# Хосты сервиса (loopback). Порт добавляется динамически из PORT ниже.
_GUARD_HOSTS = ("127.0.0.1", "localhost")


def _allowed_origins():
    """Легитимные same-origin значения Origin-заголовка (http/https, оба хоста, порт PORT).

    ТОЛЬКО с портом PORT: порт — часть origin (http://localhost != http://localhost:8787),
    сервис слушает лишь :PORT, а браузер всегда шлёт порт в Origin. Беспортовые записи
    (порт 80/443) соответствовали бы чужому loopback-приложению атакующего и открывали бы
    bypass на привилегированные роуты (cycle-review PR #58) — поэтому их тут нет.
    """
    return {f"{scheme}://{host}:{PORT}" for scheme in ("http", "https") for host in _GUARD_HOSTS}


def _is_cross_origin_post():
    """True только для ЯВНО cross-origin браузерного POST.

    Defensive: не бросает, при любой неоднозначности НЕ блокирует (чтобы не сломать
    curl/non-browser). Блокируем лишь то, что явно изобличает чужой origin.
    """
    # 1) Origin ПРИСУТСТВУЕТ — он и решает, безусловно (fail-closed на привилегированной
    #    границе). Чужой -> 403 (не даём Sec-Fetch-Site: none перекрыть атаку); наш
    #    loopback-origin -> pass (доказанно same-origin, противоречивый Sec-Fetch-Site
    #    не ломает легит).
    origin = request.headers.get("Origin")
    if origin:
        return origin not in _allowed_origins()

    # 2) Origin отсутствует (curl, прямой ввод, старый браузер) — решает Fetch-Metadata.
    #    Sec-Fetch-Site браузер выставляет сам, JS его подделать не может.
    site = request.headers.get("Sec-Fetch-Site")
    if site in ("cross-site", "same-site"):
        return True

    # 3) Нет Origin и Sec-Fetch-Site same-origin/none/отсутствует — curl/non-browser: pass.
    return False


# ============================ DNS-rebinding guard (issue #82, находка #2) ============================
# Сервис слушает loopback, но DNS-rebinding обходит Same-Origin Policy: атакующий резолвит
# evil.com → 127.0.0.1, страница на его домене делает fetch('/api/status') как СВОЙ same-origin
# (браузер шлёт Host: evil.com:8787), и читает статус/IP/гео пользователя. CSRF/Origin-guard тут
# бесполезен — он режет только POST и только по Origin; при rebinding Origin атакующего "легитимен"
# для его же страницы, а GET read-only не гардится вовсе.
#
# Единственная защита — сервер знает СВОЙ Host: обращаться к нему легитимно лишь по loopback-hostname
# (127.0.0.1/localhost/::1). Чужой hostname в Host → 403 БЕЗУСЛОВНО (привилегированная граница,
# fail-closed); неоднозначный/непарсимый Host → тоже 403.
#
# Порт в Host НЕ валидируем: атакующий всё равно бьёт в :8787 (там сервис), поэтому его rebinding-Host
# будет ".:8787" — сигнал даёт hostname, не порт. К тому же легит-клиенты шлют голый hostname без порта
# (curl 127.0.0.1:8787 → Host: 127.0.0.1:8787, прямой ввод/закладка → разные формы), а werkzeug
# в тестах по умолчанию ставит Host: localhost без порта. Привязка к порту сломала бы легит, не добавив
# защиты от rebinding.
# `::1` включён намеренно (не мёртвая запись): сервис по умолчанию слушает 127.0.0.1, но
# обращение по IPv6-loopback-литералу (`http://[::1]:8787` → `Host: [::1]:8787`,
# hostname нормализуется в `::1`) — валидный сценарий, в т.ч. при запуске на IPv6/dual-stack.
# Любой loopback не подвержен DNS-rebinding, поэтому его наличие в allow-list безопасно и не
# расширяет поверхность атаки. (Путь `localhost`, резолвящийся в IPv6, покрыт записью `localhost`:
# браузер шлёт в Host саму строку `localhost`, а не адрес.)
# ВАЖНО: это allow-list только для Host-rebinding guard (GET-доступ). CSRF-origin allow-list
# (`_allowed_origins()` / `_GUARD_HOSTS`) намеренно уже — только 127.0.0.1/localhost, поэтому
# мутации (POST) с `Origin: http://[::1]:8787` по-прежнему отклоняются 403 (fail-closed by design).
_ALLOWED_HOSTNAMES = frozenset({"127.0.0.1", "localhost", "::1"})


def _is_allowed_host(raw_host):
    """True только если Host однозначно указывает на loopback-hostname сервиса.

    Fail-closed: при ЛЮБОЙ неоднозначности парсинга → False (reject). Не полагаемся на
    "доброту" urlsplit (он прощает userinfo `@`, path `/`, query `?` — формы, которых в
    легитимном Host-заголовке не бывает и которыми маскируют обход): такие символы режем
    ДО парсинга, иначе `127.0.0.1@evil.com` дал бы hostname=evil.com в обход allow-list.
    """
    if not raw_host:
        return False
    # Символы, которых в валидном host[:port] быть не может — явная аномалия/обход.
    # (пробел/таб/перевод строки, userinfo, path, query, fragment, обратный слэш).
    if any(c in raw_host for c in " \t\r\n@/?#\\"):
        return False
    try:
        parts = urlsplit("//" + raw_host)
        hostname = parts.hostname  # нормализован (lowercase, IPv6 без скобок), userinfo отброшен
        _ = parts.port  # доступ форсит валидацию порта: непарсимый/вне диапазона → ValueError
    except ValueError:
        return False
    if hostname is None:
        return False
    return hostname in _ALLOWED_HOSTNAMES


@app.before_request
def _host_rebinding_guard():
    """Режет DNS-rebinding: любой запрос с не-loopback/неоднозначным Host → 403.

    Общий для ВСЕХ роутов и методов (GET+POST) и зарегистрирован ПЕРВЫМ среди before_request —
    Flask зовёт хуки в порядке регистрации и останавливается на первом ответе, поэтому Host-guard
    отбивает чужой Host раньше, чем CSRF- или mutation-lock-guard что-либо сделают.
    """
    if not _is_allowed_host(request.headers.get("Host")):
        return jsonify({"ok": False, "err": "host not allowed"}), 403
    return None


@app.before_request
def _csrf_origin_guard():
    """Режет cross-origin браузерные мутации до привилегированного handler.

    Гардим только POST (все мутации — POST); GET read-only роуты не трогаем.
    """
    if request.method != "POST":
        return None
    if _is_cross_origin_post():
        return jsonify({"ok": False, "err": "cross-origin request rejected"}), 403
    return None


# ============================ mutation-лок (issue #57) ============================
# app.run(threaded=True): каждый POST — отдельный поток. Клиентский MUTATION-лок (#14)
# сериализует одну вкладку браузера, но multi-tab/прямые POST бьют в хендлеры
# конкурентно: route-мутация может пересечься со сменой активного узла, guard-запись —
# с channel-переключением. node_selector._SELECT_LOCK сериализует только select между
# собой. Поэтому одно мутирующее действие за раз на весь сервер: общий non-blocking
# лок для ВСЕХ POST (все POST в приложении — мутации; GET read-only не трогаем).
#
# Занято → структурированный 409 сразу, без ожидания (defensive, как остальные отказы).
# Побочный (желанный) эффект: read-modify-write /api/guard (load_state_checked →
# проверка mode==auto → save_state; TOCTOU, задокументирован в issue #57) целиком
# выполняется под этим локом — окно check→save закрыто.
_MUTATION_LOCK = threading.Lock()


@app.before_request
def _mutation_lock_guard():
    """Берёт глобальный mutation-лок для POST; занято → 409, не ждём.

    Зарегистрирован ПОСЛЕ _csrf_origin_guard: Flask зовёт before_request в порядке
    регистрации и останавливается на первом же ответе, поэтому CSRF-403 никогда
    не захватывает лок. Владение помечаем флагом в g — teardown отпускает ТОЛЬКО
    лок, взятый этим запросом, и 409-отказ не освобождает чужой лок.
    """
    if request.method != "POST":
        return None
    # URL не маршрутизируется (404/405): мутации не будет — лок не трогаем,
    # пусть Flask отдаст честный код, а не 409 занятого лока (local review PR #62).
    if request.routing_exception is not None:
        return None
    if not _MUTATION_LOCK.acquire(blocking=False):
        return jsonify({"ok": False, "err": "another mutation is in progress"}), 409
    g.mutation_lock_owned = True
    return None


@app.teardown_request
def _mutation_lock_release(exc):
    """Гарантированно отпускает лок владельца — и при исключении в handler."""
    if g.pop("mutation_lock_owned", False):
        _MUTATION_LOCK.release()


@app.get("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")


# ============================ одностраничный UI ============================
INDEX_HTML = (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")


# ============================ запуск ============================
def main():
    """Точка входа: loopback, debug=False, threaded. Используется srouter run и -m."""
    print(f"Dashboard: http://127.0.0.1:{PORT}")
    app.run(host="127.0.0.1", port=PORT, threaded=True, debug=False)  # loopback, debug OFF!
