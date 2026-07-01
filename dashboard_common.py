import ipaddress
import re

import local_state

__all__ = [
    "_first",
    "_http_url",
    "_safe_seconds",
    "_seconds_arg",
    "_safe_port",
    "_probe_defaults",
    "_normalize_reachability_targets",
    "_normalize_throughput_targets",
    "_probe_options",
    "_ip_literal",
    "_active_route_context",
    "_active_route_ip",
]


def _first(pattern, text):
    m = re.search(pattern, text)
    return m.group(1) if m else ""


def _http_url(value):
    """Только http(s)-targets из local state; curl всё равно вызывается списком args."""
    return isinstance(value, str) and value.startswith(("http://", "https://"))


def _safe_seconds(value, default):
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return default
    if seconds <= 0 or seconds > 120:
        return default
    return int(seconds) if seconds.is_integer() else seconds


def _seconds_arg(value):
    return str(int(value)) if isinstance(value, int) or float(value).is_integer() else str(value)


def _safe_port(value):
    if isinstance(value, bool):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _probe_defaults():
    try:
        return local_state._DEFAULT_STATE.get("probes", {})
    except Exception:
        return {
            "reachability_targets": ["https://api.ip.sb/ip"],
            "throughput_targets": [{"url": "https://speed.cloudflare.com/__down?bytes=1048576", "bytes": 1048576}],
            "connect_timeout_sec": 4,
            "max_time_sec": 8,
        }


def _normalize_reachability_targets(raw, defaults):
    items = raw if isinstance(raw, list) else defaults.get("reachability_targets", [])
    targets = [x for x in items if _http_url(x)]
    return targets or [x for x in defaults.get("reachability_targets", []) if _http_url(x)]


def _normalize_throughput_targets(raw, defaults):
    items = raw if isinstance(raw, list) else defaults.get("throughput_targets", [])
    targets = []
    for item in items:
        if not isinstance(item, dict) or not _http_url(item.get("url")):
            continue
        try:
            expected_bytes = int(item.get("bytes"))
        except (TypeError, ValueError):
            continue
        if expected_bytes > 0:
            targets.append({"url": item["url"], "bytes": expected_bytes})
    if targets:
        return targets
    if raw is defaults.get("throughput_targets"):
        return []
    return _normalize_throughput_targets(defaults.get("throughput_targets", []), defaults)


def _probe_options(state_path=None):
    """Прочитать probes из local state без записи; битые значения заменяются defaults."""
    defaults = _probe_defaults()
    state = local_state.load_state(path=state_path)
    raw = state.get("probes") if isinstance(state, dict) and isinstance(state.get("probes"), dict) else {}
    connect_timeout = _safe_seconds(raw.get("connect_timeout_sec"), defaults.get("connect_timeout_sec", 4))
    max_time = _safe_seconds(raw.get("max_time_sec"), defaults.get("max_time_sec", 8))
    if max_time < connect_timeout:
        max_time = connect_timeout
    return {
        "reachability_targets": _normalize_reachability_targets(raw.get("reachability_targets"), defaults),
        "throughput_targets": _normalize_throughput_targets(raw.get("throughput_targets"), defaults),
        "connect_timeout_sec": connect_timeout,
        "max_time_sec": max_time,
    }


def _ip_literal(value):
    if not isinstance(value, str) or not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _active_route_context():
    """Свежий route target без DNS. Hostname без route_ip не блокирует status path."""
    try:
        active = local_state.active_node() or {}
    except Exception:
        active = {}
    if not isinstance(active, dict):
        active = {}
    name = active.get("name", "") if isinstance(active.get("name"), str) else ""
    endpoint = active.get("endpoint_host", "") if isinstance(active.get("endpoint_host"), str) else ""
    explicit_route_ip = active.get("route_ip", "") if isinstance(active.get("route_ip"), str) else ""
    # Dashboard hot path не делает DNS: иначе /api/status может зависнуть на gethostbyname.
    # Для split-route нужен явный route_ip; IP endpoint допустим как safe fallback.
    route_ip = explicit_route_ip if _ip_literal(explicit_route_ip) else ""
    if not route_ip and _ip_literal(endpoint):
        route_ip = endpoint
    return {"key": (name, explicit_route_ip, endpoint), "route_ip": route_ip}


def _active_route_ip():
    """Свежий route_ip активного узла. Empty/broken/hostname-only state -> ""."""
    return _active_route_context()["route_ip"]
