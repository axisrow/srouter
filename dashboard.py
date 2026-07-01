#!/usr/bin/env python3
"""Локальный дашборд: мониторинг и управление цепочкой privoxy→xray→Reality + VPN/маршруты.

Запуск:  python3 dashboard.py   →   http://127.0.0.1:8787
Только loopback, debug=False. Privileged-действия (route) спрашивают пароль macOS через osascript.
"""
import threading
import time
import re
import json
import math
import ipaddress
import shlex
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, wait
from flask import Flask, jsonify, Response

import local_state
from dashboard_common import *
from dashboard_network import *
import node_selector
from sys_probe import run, port_open

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
def _parse_hardware_ports(text):
    """networksetup -> device -> hardware port. Битый вывод просто даёт пустую карту."""
    ports = {}
    current = {}

    def flush():
        device = current.get("device", "")
        if device:
            ports[device] = dict(current)

    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            flush()
            current = {}
            continue
        if line.startswith("Hardware Port:"):
            if current:
                flush()
                current = {}
            current["hardware_port"] = line.split(":", 1)[1].strip()
        elif line.startswith("Device:"):
            current["device"] = line.split(":", 1)[1].strip()
        elif line.startswith("Ethernet Address:"):
            current["ethernet_address"] = line.split(":", 1)[1].strip()
    flush()
    return ports


def _hardware_ports():
    r = run([NETWORKSETUP, "-listallhardwareports"], timeout=4)
    if r["timeout"] or not r["out"]:
        return {}
    return _parse_hardware_ports(r["out"])


def _channel_for_iface(name, hardware_port, ifconfig_block):
    """Классификация канала без угадывания: Wi-Fi и известный USB-tether, иначе other/unknown."""
    text = f"{hardware_port or ''}\n{ifconfig_block or ''}".lower()
    if "wi-fi" in text or "wifi" in text or "airport" in text:
        return "wifi"
    usb_tether_tokens = ("iphone usb", "android", "rndis", "usb tether", "tether")
    if any(token in text for token in usb_tether_tokens):
        return "usb_tether"
    if not name and not hardware_port and not ifconfig_block:
        return "unknown"
    return "other"


def _parse_ifconfig_ifaces(text, default_iface, hardware_ports):
    ifaces = []
    if not text:
        return ifaces
    for b in re.split(r"\n(?=\S)", text):
        head = re.match(r"^(\w[\w.]*?):\s.*?mtu\s+(\d+)", b)
        if not head:
            continue
        name, mtu = head.group(1), head.group(2)
        if not re.match(r"(en\d|ppp\d|utun\d)", name):
            continue
        addr = _first(r"inet\s+(\d+\.\d+\.\d+\.\d+)", b)
        if not addr and name not in (default_iface, "ppp0"):
            continue
        port = hardware_ports.get(name, {}) if isinstance(hardware_ports, dict) else {}
        hardware_port = port.get("hardware_port", "") if isinstance(port, dict) else ""
        ifaces.append({"name": name, "addr": addr or "", "mtu": mtu,
                       "is_default": name == default_iface,
                       "hardware_port": hardware_port,
                       "channel": _channel_for_iface(name, hardware_port, b)})
    ifaces.sort(key=lambda x: (not x["is_default"], x["name"]))
    return ifaces


def _connectivity_target():
    try:
        targets = _probe_options().get("reachability_targets", [])
    except Exception:
        targets = []
    for target in targets:
        if _http_url(target):
            return target
    return "https://api.ip.sb/ip"


def _probe_direct_reachability():
    """Реальная проверка интернета: curl до HTTP target, а не только link-up интерфейса."""
    target = _connectivity_target()
    cmd = [CURL, "-sS", "-o", "/dev/null", "--connect-timeout", "4", "--max-time", "8",
           "-w", "%{http_code} %{time_total}", target]
    r = run(cmd, timeout=10)
    base = {"target": target, "code": "000", "ms": None, "reachable": None, "status": "unknown"}
    if r["timeout"]:
        return base
    if not r["out"]:
        return base
    parts = r["out"].split()
    if len(parts) < 2:
        return base
    code, elapsed = parts[0], parts[1]
    try:
        ms = round(float(elapsed) * 1000)
    except (TypeError, ValueError):
        ms = None
    if code == "000":
        return {"target": target, "code": code, "ms": ms, "reachable": False, "status": "down"}
    try:
        code_int = int(code)
    except (TypeError, ValueError):
        return base
    if 100 <= code_int < 600:
        return {"target": target, "code": code, "ms": ms, "reachable": True, "status": "ok"}
    return base


def _metered_guess(channel):
    # На macOS нет стабильного metered API; честно отмечаем только очевидный USB-tether.
    if channel == "usb_tether":
        return True, "usb_tether"
    return None, "unknown"


def probe_connectivity():
    """Активный канал + real reachability. Наблюдает, ничего не переключает."""
    try:
        dr = run([ROUTE, "-n", "get", "default"], timeout=3)
        default_iface = _first(r"interface:\s*(\S+)", dr["out"]) if not dr["timeout"] else ""
        hardware_ports = _hardware_ports()
        ic = run([IFCONFIG], timeout=4)
        ifaces = _parse_ifconfig_ifaces(ic["out"] if not ic["timeout"] else "", default_iface, hardware_ports)
        active = next((item for item in ifaces if item["name"] == default_iface), None)
        port = hardware_ports.get(default_iface, {}) if default_iface else {}
        hardware_port = ""
        if isinstance(port, dict):
            hardware_port = port.get("hardware_port", "") or ""
        if active and not hardware_port:
            hardware_port = active.get("hardware_port", "") or ""
        channel = active.get("channel", "") if active else _channel_for_iface(default_iface, hardware_port, "")
        if (not default_iface or (not active and not hardware_port)) and channel == "other":
            channel = "unknown"

        reach = _probe_direct_reachability()
        metered, reason = _metered_guess(channel)
        status = reach.get("status", "unknown")
        if channel == "unknown" and status == "ok":
            status = "unknown"
        return {
            "active_iface": default_iface,
            "default_iface": default_iface,
            "addr": active.get("addr", "") if active else "",
            "hardware_port": hardware_port,
            "channel": channel,
            "link_up": bool(active),
            "reachable": reach.get("reachable"),
            "reachability": reach,
            "metered": metered,
            "limited": metered,
            "metered_reason": reason,
            "status": status,
        }
    except Exception as e:
        return {
            "active_iface": "",
            "default_iface": "",
            "addr": "",
            "hardware_port": "",
            "channel": "unknown",
            "link_up": False,
            "reachable": None,
            "reachability": {"target": "", "code": "000", "ms": None,
                             "reachable": None, "status": "unknown"},
            "metered": None,
            "limited": None,
            "metered_reason": "unknown",
            "status": "unknown",
            "error": str(e) or e.__class__.__name__,
        }


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


# ============================ киношная телеметрия: гео-кэш + хелперы ============================
_GEO_TTL = 3600
_geo_cache = {}            # ip -> {"ts": float, "data": dict}
_geo_lock = threading.Lock()

_DNS_KNOWN = {
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "8.8.8.8": "Google", "8.8.4.4": "Google",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard",
    "223.5.5.5": "AliDNS", "223.6.6.6": "AliDNS",
    "119.29.29.29": "DNSPod", "180.76.76.76": "Baidu",
}
# публичные DNS для проверки доступности
_DNS_PUBLIC = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222",
               "94.140.14.14", "223.5.5.5", "119.29.29.29"]


def _country_flag(cc):
    if not cc or len(cc) != 2 or not cc.isalpha():
        return ""
    cc = cc.upper()
    return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)


def _geo_lookup(ip):
    """{country_code,country,city,isp,asn,asn_org,lat,lon,flag}. Кэш _GEO_TTL. Всегда dict."""
    if not ip:
        return {}
    now = time.time()
    with _geo_lock:
        c = _geo_cache.get(ip)
        if c and now - c["ts"] < _GEO_TTL:
            return c["data"]
    r = run([CURL, "-sS", "-A", "Mozilla/5.0", "--connect-timeout", "3", "--max-time", "5",
             "https://api.ip.sb/geoip/" + ip], timeout=6)   # UA обязателен (без него 403); вызов ВНЕ lock
    data = {}
    if not r["timeout"] and r["out"]:
        try:
            j = json.loads(r["out"])
            cc = j.get("country_code", "") or ""
            data = {"country_code": cc, "country": j.get("country", "") or "",
                    "city": j.get("city", "") or "", "isp": j.get("isp", "") or "",
                    "asn": j.get("asn", "") or "", "asn_org": j.get("asn_organization", "") or "",
                    "lat": j.get("latitude"), "lon": j.get("longitude"), "flag": _country_flag(cc)}
        except (ValueError, TypeError):
            data = {}
    with _geo_lock:
        _geo_cache[ip] = {"ts": now, "data": data}   # кэшируем даже пустой (нет retry-штормов)
    return data


def _exit_ip(via_proxy):
    cmd = [CURL, "-sS", "--connect-timeout", "4", "--max-time", "8"]
    if via_proxy:
        cmd += ["-x", HTTP_PROXY_URL]
    cmd.append("https://api.ip.sb/ip")
    r = run(cmd, timeout=10)
    ip = r["out"].strip() if not r["timeout"] else ""
    return ip if (ip and len(ip) <= 45 and (":" in ip or ip.count(".") == 3)) else ""


def probe_ips(route_ip=None):
    """3 IP (прямой/VPN, выход цепочки, VPS) + гео каждого."""
    chain_ip = _exit_ip(via_proxy=True)
    direct_ip = _exit_ip(via_proxy=False)
    if route_ip is None:
        route_ip = _active_route_ip()

    def node(ip, role):
        g = _geo_lookup(ip) if ip else {}
        return {"ip": ip or "", "role": role, "flag": g.get("flag", ""),
                "country_code": g.get("country_code", ""), "country": g.get("country", ""),
                "city": g.get("city", ""), "isp": g.get("isp", ""), "asn": g.get("asn", ""),
                "asn_org": g.get("asn_org", ""), "lat": g.get("lat"), "lon": g.get("lon")}

    if chain_ip and route_ip and chain_ip == route_ip:
        status = "ok"
    elif chain_ip and direct_ip and chain_ip == direct_ip:
        status = "warn"
    elif not chain_ip and not direct_ip:
        status = "down"
    else:
        status = "warn"
    return {"direct": node(direct_ip, "direct"), "chain": node(chain_ip, "chain"),
            "vps": node(route_ip, "vps"), "status": status}


def _parse_http_code(text):
    if not text:
        return None
    first = text.split()[0]
    try:
        return int(first)
    except (TypeError, ValueError):
        return None


def _http_code_ok(text):
    code = _parse_http_code(text)
    return code is not None and 200 <= code < 400


def _parse_throughput_output(text, expected_bytes):
    """Разобрать curl -w 'code time size' и вернуть kbps. Битый вывод -> None."""
    if not text:
        return None
    parts = text.split()
    if len(parts) < 2 or not _http_code_ok(parts[0]):
        return None
    try:
        elapsed = float(parts[1])
        downloaded = float(parts[2]) if len(parts) >= 3 else float(expected_bytes)
    except (TypeError, ValueError):
        return None
    if elapsed <= 0:
        return None
    if downloaded <= 0:
        try:
            downloaded = float(expected_bytes)
        except (TypeError, ValueError):
            return None
    if downloaded <= 0:
        return None
    return round(downloaded * 8 / elapsed / 1000)


def _probe_proxy_arg(port):
    return f"socks5h://{PROBE_SOCKS_HOST}:{port}"


def _curl_reachable_via_socks(port, opts):
    """Лёгкая проверка, что per-node SOCKS вообще ведёт наружу."""
    proxy = _probe_proxy_arg(port)
    connect_timeout = _seconds_arg(opts["connect_timeout_sec"])
    max_time = _seconds_arg(opts["max_time_sec"])
    for url in opts["reachability_targets"]:
        cmd = [CURL, "-sS", "-o", "/dev/null", "-x", proxy,
               "--connect-timeout", connect_timeout, "--max-time", max_time,
               "-w", "%{http_code}", url]
        r = run(cmd, timeout=opts["max_time_sec"] + 2)
        if not r["timeout"] and _http_code_ok(r["out"]):
            return True
    return False


def _curl_throughput_via_socks(port, opts):
    """Скорость через уже поднятый per-node SOCKS inbound; xray тут не трогаем."""
    proxy = _probe_proxy_arg(port)
    connect_timeout = _seconds_arg(opts["connect_timeout_sec"])
    max_time = _seconds_arg(opts["max_time_sec"])
    for target in opts["throughput_targets"]:
        cmd = [CURL, "-sS", "-o", "/dev/null", "-x", proxy,
               "--connect-timeout", connect_timeout, "--max-time", max_time,
               "-w", "%{http_code} %{time_total} %{size_download}", target["url"]]
        r = run(cmd, timeout=opts["max_time_sec"] + 2)
        if r["timeout"]:
            continue
        kbps = _parse_throughput_output(r["out"], target["bytes"])
        if kbps is not None:
            return kbps
    return None


def _node_probe_status(ping_ms, loss, throughput_kbps, *, has_socks, socks_open, reachable):
    if not has_socks:
        return "unknown"
    if throughput_kbps is not None:
        if ping_ms is None or (loss is not None and loss >= 50) or ping_ms > 250:
            return "warn"
        return "ok"
    if socks_open and reachable:
        return "warn"
    return "down"


def _empty_node_probe(node):
    endpoint = node.get("endpoint_host", "") if isinstance(node, dict) else ""
    route_ip = node.get("route_ip", "") if isinstance(node, dict) else ""
    return {"name": node.get("name", "") if isinstance(node, dict) else "",
            "endpoint_host": endpoint or "", "route_ip": route_ip or endpoint or "",
            "ping_ms": None, "loss": None, "throughput_kbps": None, "geo": {}, "status": "unknown"}


_nodes_cache = {"ts": 0.0, "data": None}
_nodes_lock = threading.Lock()


def _store_node_probe_cache(data):
    with _nodes_lock:
        _nodes_cache.update(ts=time.time(), data=data)


def probe_nodes_snapshot(state_path=None):
    """Быстрый snapshot для /api/status: не запускает ping/curl/geo и не тратит трафик."""
    now = time.time()
    if state_path is None:
        with _nodes_lock:
            data = _nodes_cache.get("data")
            if data is not None and now - _nodes_cache.get("ts", 0.0) <= NODE_PROBE_TTL_SEC:
                return data
            if data is not None:
                return data  # лучше отдать stale snapshot, чем жечь throughput из status poll.
    try:
        return [_empty_node_probe(n) for n in local_state.enabled_nodes(path=state_path)]
    except Exception:
        return []


def _probe_node(node, opts):
    out = _empty_node_probe(node)
    target = out["route_ip"] or out["endpoint_host"]
    ping_ms, loss = _ping_avg(target)
    out["ping_ms"], out["loss"] = ping_ms, loss
    out["geo"] = _geo_lookup(target) if target else {}

    probe = node.get("probe") if isinstance(node.get("probe"), dict) else {}
    socks_port = _safe_port(probe.get("socks_port"))
    if socks_port is None:
        out["status"] = _node_probe_status(ping_ms, loss, None, has_socks=False, socks_open=False, reachable=False)
        return out

    socks_open = port_open(PROBE_SOCKS_HOST, socks_port, timeout=min(1.0, float(opts["connect_timeout_sec"])))
    reachable = False
    throughput_kbps = None
    if socks_open:
        reachable = _curl_reachable_via_socks(socks_port, opts)
        throughput_kbps = _curl_throughput_via_socks(socks_port, opts)
    out["throughput_kbps"] = throughput_kbps
    out["status"] = _node_probe_status(ping_ms, loss, throughput_kbps,
                                       has_socks=True, socks_open=socks_open, reachable=reachable)
    return out


def probe_nodes(state_path=None):
    """Multi-node probes из unified local state. READ-ONLY: state не мутируется."""
    try:
        nodes = local_state.enabled_nodes(path=state_path)
        opts = _probe_options(state_path=state_path)
    except Exception:
        return []
    if not nodes:
        return []

    def safe_probe(node):
        # Один битый узел не должен ломать весь dashboard: деградируем по ячейке.
        try:
            return _probe_node(node, opts)
        except Exception:
            item = _empty_node_probe(node)
            item["status"] = "unknown"
            return item

    with ThreadPoolExecutor(max_workers=min(8, len(nodes))) as ex:
        data = list(ex.map(safe_probe, nodes))
    if state_path is None:
        _store_node_probe_cache(data)
    return data


def _dns_check(ip):
    """TCP :53 доступность + грубый ms."""
    t0 = time.time()
    up = port_open(ip, 53, timeout=1.5)
    ms = round((time.time() - t0) * 1000) if up else None
    return {"ip": ip, "name": _DNS_KNOWN.get(ip, ""), "up": up, "ms": ms}


def probe_dns():
    """Системные резолверы (scutil) + проверка доступности публичных DNS."""
    r = run([SCUTIL, "--dns"], timeout=4)
    seen, servers = set(), []
    if not r["timeout"]:
        for line in r["out"].splitlines():
            m = re.search(r"nameserver\[\d+\]\s*:\s*(\S+)", line)
            if m and m.group(1) not in seen:
                seen.add(m.group(1))
                servers.append({"ip": m.group(1), "name": _DNS_KNOWN.get(m.group(1), "")})
            if len(servers) >= 6:
                break
    with ThreadPoolExecutor(max_workers=len(_DNS_PUBLIC)) as ex:
        public = list(ex.map(_dns_check, _DNS_PUBLIC))
    return {"servers": servers, "public": public, "count": len(servers),
            "status": "ok" if servers else "down"}


def probe_ifaces():
    """Активные интерфейсы (en0/ppp0/utunN) addr+MTU, маркер default-маршрута."""
    dr = run([ROUTE, "-n", "get", "default"], timeout=3)
    default_iface = _first(r"interface:\s*(\S+)", dr["out"]) if not dr["timeout"] else ""
    hardware_ports = _hardware_ports()
    r = run([IFCONFIG], timeout=4)
    ifaces = _parse_ifconfig_ifaces(r["out"] if not r["timeout"] else "", default_iface, hardware_ports)
    return {"ifaces": ifaces[:8], "default": default_iface,
            "status": "ok" if ifaces else "down"}


def probe_geo_distance(route_ip=None):
    """Великокружная дистанция (км) от локального выхода до VPS (haversine)."""
    if route_ip is None:
        route_ip = _active_route_ip()
    here = _geo_lookup(_exit_ip(via_proxy=False))
    there = _geo_lookup(route_ip)
    la1, lo1, la2, lo2 = here.get("lat"), here.get("lon"), there.get("lat"), there.get("lon")
    if la1 is None or lo1 is None or la2 is None or lo2 is None:
        return {"km": None, "from_city": here.get("city", ""),
                "to_city": there.get("city", ""), "status": "down"}
    la1, lo1, la2, lo2 = float(la1), float(lo1), float(la2), float(lo2)
    R = 6371.0
    p1, p2 = math.radians(la1), math.radians(la2)
    dp, dl = math.radians(la2 - la1), math.radians(lo2 - lo1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    km = round(2 * R * math.asin(min(1.0, math.sqrt(a))))
    return {"km": km, "from_city": here.get("city", ""), "from_flag": here.get("flag", ""),
            "to_city": there.get("city", ""), "to_flag": there.get("flag", ""), "status": "ok"}


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
def _parse_network_services(text):
    """networksetup -listallnetworkservices -> ordered service names, disabled marker stripped."""
    services = []
    for raw in (text or "").splitlines():
        name = raw.strip()
        if not name or name.startswith("An asterisk"):
            continue
        if name.startswith("*"):
            name = name[1:].strip()
        if name:
            services.append(name)
    return services


def _known_service_name(name, services):
    if not isinstance(name, str):
        return ""
    wanted = name.strip()
    if not wanted:
        return ""
    for service in services:
        if service == wanted:
            return service
    wanted_low = wanted.lower()
    for service in services:
        if service.lower() == wanted_low:
            return service
    return ""


def _configured_channel_service(target, services):
    try:
        state = local_state.load_state()
    except Exception:
        state = {}
    network = state.get("network") if isinstance(state, dict) else {}
    channels = network.get("channels") if isinstance(network, dict) else {}
    if not isinstance(channels, dict):
        return ""
    return _known_service_name(channels.get(CHANNEL_SERVICE_KEYS[target], ""), services)


def _hardware_channel_service(target, services):
    expected = "usb_tether" if target == "usb" else target
    for port in _hardware_ports().values():
        if not isinstance(port, dict):
            continue
        hardware_port = port.get("hardware_port", "") or ""
        device = port.get("device", "") or ""
        if _channel_for_iface(device, hardware_port, "") != expected:
            continue
        service = _known_service_name(hardware_port, services)
        if service:
            return service
    return ""


def _channel_service_name(target, services):
    return (
        _configured_channel_service(target, services)
        or _hardware_channel_service(target, services)
    )


def _channel_result(target, result, service=""):
    err = result.get("err") or ""
    cancelled = result.get("rc") == -128 or bool(re.search(r"\(-128\)\s*\Z", err))
    timeout = bool(result.get("timeout"))
    return {
        "ok": result.get("rc") == 0 and not timeout,
        "rc": result.get("rc"),
        "out": result.get("out") or "",
        "err": err,
        "cancelled": cancelled,
        "timeout": timeout,
        "target": target,
        "service": service,
    }


def _shell_join(args):
    return " ".join(shlex.quote(str(arg)) for arg in args)


def _applescript_text(text):
    return str(text).replace("\\", "\\\\").replace('"', '\\"')


def switch_channel(target):
    if target not in CHANNEL_TARGETS:
        return _channel_result(target, {"rc": None, "out": "", "err": "bad channel target", "timeout": False})

    listed = run([NETWORKSETUP, "-listallnetworkservices"], timeout=4)
    if listed["timeout"] or listed["rc"] != 0:
        return _channel_result(target, listed)

    services = _parse_network_services(listed["out"])
    service = _channel_service_name(target, services)
    if not service:
        return _channel_result(
            target,
            {"rc": None, "out": "", "err": f"network service not found for channel: {target}", "timeout": False},
        )

    ordered_services = [service] + [item for item in services if item != service]
    enable_cmd = _shell_join([NETWORKSETUP, "-setnetworkserviceenabled", service, "on"])
    reorder_cmd = _shell_join([NETWORKSETUP, "-ordernetworkservices", *ordered_services])
    shell_cmd = f"{enable_cmd} && {reorder_cmd}"

    # ВАЖНО: target проходит strict whitelist, а shell_cmd собран только из констант,
    # флагов-литералов и network-service names, подтверждённых networksetup. Ввод
    # запроса в shell-строку не попадает; новые динамические части требуют whitelist + escaping.
    applescript = f'do shell script "{_applescript_text(shell_cmd)}" with administrator privileges'
    result = run([OSASCRIPT, "-e", applescript], timeout=60)
    return _channel_result(target, result, service=service)


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
    return run([OSASCRIPT, "-e", applescript], timeout=60)


# ============================ non-privileged: сервисы ============================
def service_control(name, action):
    return run([BREW, "services", action, name], timeout=20)


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
    result = node_selector.select_node(name, enabled_names=enabled, runner=run, state_path=None)
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
