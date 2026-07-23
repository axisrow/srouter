"""Node/DNS probe-хелперы dashboard без импорта Flask/dashboard."""

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import dashboard_geo
import dashboard_network
import local_state
import sys_probe
from dashboard_common import (
    CURL,
    NODE_PROBE_TTL_SEC,
    PROBE_SOCKS_HOST,
    SCUTIL,
    _probe_options,
    _safe_port,
    _seconds_arg,
)

import lock_hierarchy


__all__ = [
    "_DNS_KNOWN",
    "_DNS_PUBLIC",
    "_nodes_cache",
    "_nodes_lock",
    "_parse_http_code",
    "_http_code_ok",
    "_parse_throughput_output",
    "_probe_proxy_arg",
    "_curl_reachable_via_socks",
    "_curl_throughput_via_socks",
    "_node_probe_status",
    "_empty_node_probe",
    "_store_node_probe_cache",
    "probe_nodes_snapshot",
    "_probe_node",
    "probe_nodes",
    "_dns_check",
    "probe_dns",
]


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
        r = sys_probe.run(cmd, timeout=opts["max_time_sec"] + 2)
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
        r = sys_probe.run(cmd, timeout=opts["max_time_sec"] + 2)
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
    # issue #159: bounded acquire (уровень CACHE). Write-точка: таймаут → пропускаем
    # запись snapshot-кэша (следующий status пересчитает).
    try:
        with lock_hierarchy.bounded_acquire(
            _nodes_lock, name="nodes", level=lock_hierarchy.LEVEL_CACHE
        ):
            _nodes_cache.update(ts=time.time(), data=data)
    except lock_hierarchy.LockAcquireTimeout:
        pass  # skip-write; snapshot пересчитается в следующий раз


def probe_nodes_snapshot(state_path=None):
    """Быстрый snapshot для /api/status: не запускает ping/curl/geo и не тратит трафик."""
    now = time.time()
    if state_path is None:
        # issue #159: bounded acquire (уровень CACHE). Таймаут → stale snapshot
        # (как существующий fallback «лучше stale, чем жечь throughput» ниже).
        try:
            with lock_hierarchy.bounded_acquire(
                _nodes_lock, name="nodes", level=lock_hierarchy.LEVEL_CACHE
            ):
                data = _nodes_cache.get("data")
                if data is not None and now - _nodes_cache.get("ts", 0.0) <= NODE_PROBE_TTL_SEC:
                    return data
                if data is not None:
                    return data  # лучше отдать stale snapshot, чем жечь throughput из status poll.
        except lock_hierarchy.LockAcquireTimeout:
            stale = _nodes_cache.get("data")
            if stale is not None:
                return stale  # лучше stale snapshot, чем жечь throughput из status poll.
    try:
        return [_empty_node_probe(n) for n in local_state.enabled_nodes(path=state_path)]
    except Exception:
        return []


def _probe_node(node, opts):
    out = _empty_node_probe(node)
    target = out["route_ip"] or out["endpoint_host"]
    ping_ms, loss = dashboard_network._ping_avg(target)
    out["ping_ms"], out["loss"] = ping_ms, loss
    out["geo"] = dashboard_geo._geo_lookup(target) if target else {}

    probe = node.get("probe") if isinstance(node.get("probe"), dict) else {}
    socks_port = _safe_port(probe.get("socks_port"))
    if socks_port is None:
        out["status"] = _node_probe_status(ping_ms, loss, None, has_socks=False, socks_open=False, reachable=False)
        return out

    socks_open = sys_probe.port_open(PROBE_SOCKS_HOST, socks_port, timeout=min(1.0, float(opts["connect_timeout_sec"])))
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
    up = sys_probe.port_open(ip, 53, timeout=1.5)
    ms = round((time.time() - t0) * 1000) if up else None
    return {"ip": ip, "name": _DNS_KNOWN.get(ip, ""), "up": up, "ms": ms}


def probe_dns():
    """Системные резолверы (scutil) + проверка доступности публичных DNS."""
    r = sys_probe.run([SCUTIL, "--dns"], timeout=4)
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
