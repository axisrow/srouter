"""Узлы (nodes) — CRUD, активный узел, resolve_route_ip.

Извлечено из local_state.py (issue #158, декомпозиция крупных файлов). Обращается к core state
I/O через фасад `local_state` (facade-lookup, канон moving-caller-inverts-mock-ownership —
см. docstring local_state_traffic_guard.py).
"""
import socket

import local_state

_is_valid_host = local_state._is_valid_host


def _is_valid_node(n):
    """Запись узла валидна, если это dict с name + валидными endpoint_host/route_ip."""
    if not isinstance(n, dict):
        return False
    if not isinstance(n.get("name"), str) or not n.get("name"):
        return False
    if not _is_valid_host(n.get("endpoint_host")):
        return False
    # route_ip может отсутствовать (вычисляется через resolve_route_ip),
    # но если есть — обязан быть валидным хостом.
    rip = n.get("route_ip")
    if rip is not None and not _is_valid_host(rip):
        return False
    return True


def load_nodes(path=None):
    """Список валидных узлов; невалидные отбрасываются. Никогда не бросает."""
    state = local_state.load_state(path)
    return _nodes_from_state(state)


def _nodes_from_state(state):
    nodes = state.get("nodes")
    if not isinstance(nodes, list):
        return []
    return [n for n in nodes if _is_valid_node(n)]


def enabled_nodes(path=None):
    """Только узлы с enabled is True (строго)."""
    return [n for n in load_nodes(path) if n.get("enabled") is True]


def get_node(name, path=None):
    """Узел по имени или {} если нет."""
    if not isinstance(name, str):
        return {}
    for n in load_nodes(path):
        if n.get("name") == name:
            return n
    return {}


def active_node(path=None):
    """Активный узел. active_name обязан разрешаться в enabled узел;
    иначе fallback на первый enabled; иначе {}.
    """
    enabled = enabled_nodes(path)
    if not enabled:
        return {}
    state = local_state.load_state(path)
    an = state.get("active_node") or {}
    name = an.get("name") if isinstance(an, dict) else None
    for n in enabled:
        if n.get("name") == name:
            return n
    return enabled[0]  # fallback на первый enabled


def begin_active_node_change(name, path=None):
    """Записать pending intent только для валидного enabled узла. Возвращает state."""
    state, readable = local_state._load_state_checked(path)
    if not readable:
        return state
    an = state.get("active_node")
    if not isinstance(an, dict):
        an = {"name": None, "pending": None}
    if any(n.get("name") == name and n.get("enabled") is True for n in _nodes_from_state(state)):
        an["pending"] = name
    state["active_node"] = an
    local_state.save_state(state, path)
    return state


def commit_active_node_change(name, path=None):
    """Промотировать pending -> active только если pending совпадает с name.
    Вызывается ТОЛЬКО после успеха generator/restart (#8).
    """
    state, readable = local_state._load_state_checked(path)
    if not readable:
        return
    an = state.get("active_node")
    if not isinstance(an, dict):
        return
    if an.get("pending") == name:
        an["name"] = name
        an["pending"] = None
        state["active_node"] = an
        local_state.save_state(state, path)


def clear_pending(path=None):
    """Сбросить pending intent (после неудачи generator/restart)."""
    state, readable = local_state._load_state_checked(path)
    if not readable:
        return
    an = state.get("active_node")
    if isinstance(an, dict) and an.get("pending") is not None:
        an["pending"] = None
        state["active_node"] = an
        local_state.save_state(state, path)


def _looks_like_ip(host):
    """True если строка — IPv4/IPv6-подобная (без DNS-запроса)."""
    if not isinstance(host, str) or not host:
        return False
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        if any(len(p) > 1 and p.startswith("0") for p in parts):
            return False
        return True
    return ":" in host  # грубый IPv6-эвристик


def resolve_route_ip(node, path=None):
    """route_ip узла. Приоритет: уже заданный route_ip -> DNS-resolve endpoint_host
    -> fallback на endpoint_host -> ''. D1: никогда не бросает.
    """
    if not isinstance(node, dict):
        return ""
    rip = node.get("route_ip")
    if isinstance(rip, str) and rip and _is_valid_host(rip):
        return rip
    host = node.get("endpoint_host")
    if not isinstance(host, str) or not host or not _is_valid_host(host):
        return ""
    if _looks_like_ip(host):
        return host  # уже IP — passthrough
    try:
        resolved = socket.gethostbyname(host)
        if resolved and _is_valid_host(resolved):
            return resolved
    except (OSError, ValueError):
        # OSError: сетевые/DNS ошибки (gaierror/herror — подклассы OSError); ValueError: невалидный host
        pass
    return host  # fallback на endpoint_host
