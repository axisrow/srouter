"""Defensive stdlib-only helper над unified local state `srouter.local.json`.

Контракт (#2): функции НИКОГДА не бросают; невалидный ввод деградирует в empty/default.
Path по умолчанию — рядом с модулем (не cwd), чтобы работал под launchd.
Каждая public функция принимает path= для тестов (tmp_path fixture).
"""
import json
import re
import socket
from pathlib import Path

# Путь к локальному state по умолчанию — рядом с этим модулем, не cwd.
_DEFAULT_PATH = Path(__file__).resolve().parent / "srouter.local.json"

# D2: валидация хоста — только безопасные символы, shell-метасимволы запрещены.
# Переиспользовано из закрытого PR #19; закреплено в #2.
_HOST_RE = re.compile(r"^[A-Za-z0-9.:_-]+$")


def _is_valid_host(host):
    """True если строка содержит только безопасные для shell символы."""
    return bool(isinstance(host, str) and _HOST_RE.match(host))


# Safe-default state: секции v1 (#2). probes — эталонные defaults (G3);
# реальную запись делает #5 setup/check на реальной машине.
_DEFAULT_STATE = {
    "schema_version": 1,
    "nodes": [],
    "active_node": {"name": None, "pending": None},
    "probes": {
        "reachability_targets": ["https://api.ip.sb/ip", "https://www.cloudflare.com/cdn-cgi/trace"],
        "throughput_targets": [{"url": "https://speed.cloudflare.com/__down?bytes=1048576", "bytes": 1048576}],
        "connect_timeout_sec": 4,
        "max_time_sec": 8,
    },
    "network": {"gateway": "", "vpn_server": "", "vpn_exit_ip": "", "channels": {}},
    "traffic_guard": {"mode": "off", "domains": {}},
    "detected_environment": {"last_checked_at": None, "brew": None, "xray": None, "privoxy": None, "dnsmasq": None},
    "runtime": {"last_apply": None, "last_error": None},
}


def load_state(path=None):
    """Загрузить state. Missing/broken/non-object -> безопасный _DEFAULT_STATE (копия).
    Никогда не бросает.
    """
    state, _readable = _load_state_checked(path)
    return state


def _load_state_checked(path=None):
    """Загрузить state и отличить missing file от битого existing file.

    readable=False значит: файл был найден, но его нельзя безопасно перезаписывать мутатором.
    """
    p = Path(path) if path else _DEFAULT_PATH
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return _copy_default(), True
    except (OSError, ValueError):
        return _copy_default(), False
    if not isinstance(data, dict):
        return _copy_default(), False
    # Не возвращаем мутируемый _DEFAULT_STATE напрямую — глубокая копия секций.
    merged = _copy_default()
    for k, v in data.items():
        merged[k] = v
    return merged, True


def save_state(state, path=None):
    """Атомарная запись (temp + rename). Возвращает записанный state. Не бросает."""
    p = Path(path) if path else _DEFAULT_PATH
    tmp = p.with_suffix(p.suffix + ".tmp")
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        tmp.replace(p)  # atomic rename
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
    return state


def _copy_default():
    """Глубокая копия дефолтного state, чтобы тесты/мутирующие вызовы не портили константу."""
    import copy

    return copy.deepcopy(_DEFAULT_STATE)


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
    state = load_state(path)
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
    state = load_state(path)
    an = state.get("active_node") or {}
    name = an.get("name") if isinstance(an, dict) else None
    for n in enabled:
        if n.get("name") == name:
            return n
    return enabled[0]  # fallback на первый enabled


def begin_active_node_change(name, path=None):
    """Записать pending intent только для валидного enabled узла. Возвращает state."""
    state, readable = _load_state_checked(path)
    if not readable:
        return state
    an = state.get("active_node")
    if not isinstance(an, dict):
        an = {"name": None, "pending": None}
    if any(n.get("name") == name and n.get("enabled") is True for n in _nodes_from_state(state)):
        an["pending"] = name
    state["active_node"] = an
    save_state(state, path)
    return state


def commit_active_node_change(name, path=None):
    """Промотировать pending -> active только если pending совпадает с name.
    Вызывается ТОЛЬКО после успеха generator/restart (#8).
    """
    state, readable = _load_state_checked(path)
    if not readable:
        return
    an = state.get("active_node")
    if not isinstance(an, dict):
        return
    if an.get("pending") == name:
        an["name"] = name
        an["pending"] = None
        state["active_node"] = an
        save_state(state, path)


def clear_pending(path=None):
    """Сбросить pending intent (после неудачи generator/restart)."""
    state, readable = _load_state_checked(path)
    if not readable:
        return
    an = state.get("active_node")
    if isinstance(an, dict) and an.get("pending") is not None:
        an["pending"] = None
        state["active_node"] = an
        save_state(state, path)


def _looks_like_ip(host):
    """True если строка — IPv4/IPv6-подобная (без DNS-запроса)."""
    if not isinstance(host, str) or not host:
        return False
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
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
    except Exception:
        pass
    return host  # fallback на endpoint_host
