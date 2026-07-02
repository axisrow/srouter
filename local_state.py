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
_HOST_RE = re.compile(r"^[A-Za-z0-9.:_-]+\Z")
_TRAFFIC_GUARD_MODES = {"on", "off", "auto"}
_TRAFFIC_GUARD_POLICIES = {"block", "allow"}
_TRAFFIC_GUARD_CHANNELS = {"wifi", "usb_tether", "metered"}
_TRAFFIC_GUARD_AUTO_DOMAINS_ERROR = "traffic_guard.domains must define channel policies for auto mode"


def _is_valid_host(host):
    """True если строка содержит только безопасные для shell символы."""
    return bool(isinstance(host, str) and _HOST_RE.match(host))


def _normalize_traffic_guard_domain(domain):
    """Нормализовать domain-rule для exact+subdomain match; пустая строка значит reject."""
    if not isinstance(domain, str):
        return ""
    normalized = domain.strip().lower().rstrip(".")
    if not normalized or normalized.startswith(".") or ".." in normalized:
        return ""
    # Traffic Guard принимает домены, не host:port/IPv6; shell-символы всё равно режет _HOST_RE.
    if ":" in normalized or not _is_valid_host(normalized):
        return ""
    return normalized


def _traffic_guard_domain_matches(candidate, rule_domain):
    """Xray `domain:example.com` матчится на example.com и любые *.example.com."""
    candidate_norm = _normalize_traffic_guard_domain(candidate)
    rule_norm = _normalize_traffic_guard_domain(rule_domain)
    if not candidate_norm or not rule_norm:
        return False
    return candidate_norm == rule_norm or candidate_norm.endswith("." + rule_norm)


def _normalize_traffic_guard_channel(channel):
    """Нормализовать канал из #10/#11; пустая строка значит reject/unknown."""
    if not isinstance(channel, str):
        return ""
    normalized = channel.strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in {"wifi", "wi_fi"}:
        return "wifi"
    if normalized in {"usb", "usb_tether", "usbtether"}:
        return "usb_tether"
    if normalized == "metered":
        return "metered"
    return ""


def _validate_traffic_guard_domain_map(domains, errors, context):
    if domains is None:
        return {}
    if not isinstance(domains, dict):
        errors.append(f"{context} must be an object")
        return {}

    normalized = {}
    for domain, policy in domains.items():
        domain_norm = _normalize_traffic_guard_domain(domain)
        if not domain_norm:
            errors.append(f"{context} domain is invalid: {domain!r}")
            continue
        if policy == "throttle":
            errors.append(f'{context} policy "throttle" is not supported in v1: {domain_norm}')
            continue
        if not isinstance(policy, str) or policy not in _TRAFFIC_GUARD_POLICIES:
            errors.append(f'{context} policy must be "block" or "allow": {domain_norm}')
            continue
        previous = normalized.get(domain_norm)
        if previous is not None and previous != policy:
            errors.append(f"conflicting {context} policies for {domain_norm}: {previous} vs {policy}")
            continue
        normalized[domain_norm] = policy

    ordered = sorted(normalized.items(), key=lambda item: item[0].count("."))
    for index, (parent, parent_policy) in enumerate(ordered):
        for child, child_policy in ordered[index + 1 :]:
            if parent_policy != child_policy and _traffic_guard_domain_matches(child, parent):
                errors.append(f"conflicting {context} policies: {parent}={parent_policy} vs {child}={child_policy}")
    return normalized


def _validate_traffic_guard_channel_domains(domains, errors):
    if domains is None:
        return {}
    if not isinstance(domains, dict):
        errors.append("traffic_guard.domains must be an object")
        return {}

    normalized = {}
    for channel, channel_domains in domains.items():
        channel_norm = _normalize_traffic_guard_channel(channel)
        if not channel_norm:
            errors.append(f"traffic_guard channel is invalid: {channel!r}")
            continue
        if channel_norm in normalized:
            errors.append(f"duplicate traffic_guard channel: {channel_norm}")
            continue
        context = f"traffic_guard.domains.{channel_norm}"
        if not isinstance(channel_domains, dict):
            errors.append(f"{context} must be an object")
            continue
        before_error_count = len(errors)
        channel_map = _validate_traffic_guard_domain_map(channel_domains, errors, context)
        if not channel_map and len(errors) == before_error_count:
            errors.append(f"{context} must define at least one policy")
            continue
        normalized[channel_norm] = channel_map
    return normalized


def _normalized_traffic_guard_domain_map(domains):
    normalized = {}
    if not isinstance(domains, dict):
        return normalized
    for domain, policy in domains.items():
        domain_norm = _normalize_traffic_guard_domain(domain)
        if domain_norm and policy in _TRAFFIC_GUARD_POLICIES:
            normalized[domain_norm] = policy
    return normalized


def _normalized_traffic_guard_channel_domains(domains):
    normalized = {}
    if not isinstance(domains, dict):
        return normalized
    for channel, channel_domains in domains.items():
        channel_norm = _normalize_traffic_guard_channel(channel)
        if not channel_norm or channel_norm in normalized:
            continue
        normalized[channel_norm] = _normalized_traffic_guard_domain_map(channel_domains)
    return normalized


def _traffic_guard_state_channel(guard, state, channel):
    for candidate in (channel, guard.get("channel"), guard.get("active_channel")):
        channel_norm = _normalize_traffic_guard_channel(candidate)
        if channel_norm:
            return channel_norm
    network = state.get("network") if isinstance(state, dict) else {}
    if isinstance(network, dict):
        for candidate in (
            network.get("traffic_guard_channel"),
            network.get("active_channel"),
            network.get("channel"),
        ):
            channel_norm = _normalize_traffic_guard_channel(candidate)
            if channel_norm:
                return channel_norm
    return ""


def _traffic_guard_domains_for_channel(channels, channel):
    if not isinstance(channels, dict):
        return {}
    channel_norm = _normalize_traffic_guard_channel(channel)
    if not channel_norm:
        return {}
    if isinstance(channels.get(channel_norm), dict):
        return dict(channels[channel_norm])
    # USB tether в #10 является очевидно metered; общий metered-набор служит fallback.
    if channel_norm == "usb_tether" and isinstance(channels.get("metered"), dict):
        return dict(channels["metered"])
    return {}


def validate_traffic_guard(guard):
    """Вернуть список явных ошибок Traffic Guard v1. Не бросает.

    mode:auto opt-in: domains становится картой channel -> domain policies.
    throttle по-прежнему отклоняется валидацией, а не молча приводится к другой семантике.
    """
    errors = []
    if guard is None or guard is False:
        return errors
    if not isinstance(guard, dict):
        return ["traffic_guard must be an object"]

    mode = guard.get("mode", "off")
    if not isinstance(mode, str) or mode not in _TRAFFIC_GUARD_MODES:
        errors.append('traffic_guard.mode must be "on", "off", or "auto"')

    if mode == "auto":
        domains = guard.get("domains")
        if domains is None or domains == {}:
            errors.append(_TRAFFIC_GUARD_AUTO_DOMAINS_ERROR)
            return errors
        _validate_traffic_guard_channel_domains(domains, errors)
    else:
        domains = guard.get("domains", {})
        if domains is None:
            return errors
        _validate_traffic_guard_domain_map(domains, errors, "traffic_guard.domains")
    return errors


def traffic_guard_config(path=None, state=None, channel=None):
    """Нормализованный Traffic Guard для generator/probe.

    Возвращает dict с valid/errors; при ошибках безопасно отключает правила, но
    сохраняет явную причину для status/apply-слоёв.
    """
    if state is None:
        state = load_state(path)
    guard = state.get("traffic_guard") if isinstance(state, dict) else {}
    errors = validate_traffic_guard(guard)
    if errors:
        return {"mode": "off", "domains": {}, "channels": {}, "channel": "", "valid": False, "errors": errors}
    if not isinstance(guard, dict):
        guard = {}
    domains = guard.get("domains") if isinstance(guard.get("domains"), dict) else {}
    mode = guard.get("mode", "off")
    mode = mode if mode in _TRAFFIC_GUARD_MODES else "off"
    if mode == "auto":
        channels = _normalized_traffic_guard_channel_domains(domains)
        active_channel = _traffic_guard_state_channel(guard, state, channel)
        return {
            "mode": "auto",
            "domains": _traffic_guard_domains_for_channel(channels, active_channel),
            "channels": channels,
            "channel": active_channel,
            "valid": True,
            "errors": [],
        }
    return {
        "mode": mode,
        "domains": _normalized_traffic_guard_domain_map(domains),
        "channels": {},
        "channel": "",
        "valid": True,
        "errors": [],
    }


# ============================ Traffic Guard throttle runtime (#13/#22) ============================
# Throttle — плоский v1 (без auto-каналов) поверх одно-pipe'ового движка traffic_shape.
# Валидация ВХОДА (domain/rate) — не policy-конфиг, а параметры privileged-вызова:
# держим её здесь, чтобы роут и любой другой вызывающий резали невалидное одинаково
# (fail-closed) ДО того, как значения дойдут до shell traffic_shape.


def _valid_throttle_rate(rate):
    """Положительное целое (int или строка из одних цифр) -> int, иначе None.

    Согласовано с traffic_shape._valid_rate (Kbit/s), но без импорта движка (иначе
    цикл import). bool отсекаем явно: True/False — не rate. Ноль/отрицательное — None.
    """
    if isinstance(rate, bool):
        return None
    if isinstance(rate, int):
        n = rate
    elif isinstance(rate, str) and rate.isdigit():
        n = int(rate)
    else:
        return None
    return n if n > 0 else None


def validate_throttle_request(domain, rate):
    """Свести пользовательский (domain, rate) к (domain_norm, rate_int) или (None, None).

    Единый fail-closed валидатор для apply-запроса throttle: domain нормализуется тем
    же _normalize_traffic_guard_domain (exact+subdomain семантика, shell-небезопасное
    режется), rate — положительное целое. Любая невалидность -> (None, None), чтобы
    вызывающий не звал движок. Не бросает.
    """
    domain_norm = _normalize_traffic_guard_domain(domain)
    rate_int = _valid_throttle_rate(rate)
    if not domain_norm or rate_int is None:
        return None, None
    return domain_norm, rate_int


def _valid_active_throttle(entry):
    """True если entry — валидная запись активного throttle-lease.

    Требуем ровно те поля, что нужны clear после рестарта: domain (нормализуемый),
    rate (положит. целое), token (числовой — идёт в pfctl -X). applied_at
    необязателен по типу (метка времени), но при наличии обязан быть числом/строкой.
    """
    if not isinstance(entry, dict):
        return False
    if not _normalize_traffic_guard_domain(entry.get("domain")):
        return False
    if _valid_throttle_rate(entry.get("rate")) is None:
        return False
    token = entry.get("token")
    # Токен pf enable-ref: только цифры (или int>=0) — он попадёт в shell (pfctl -X).
    if isinstance(token, bool) or not (
        (isinstance(token, int) and token >= 0) or (isinstance(token, str) and token.isdigit())
    ):
        return False
    return True


def load_active_throttle(path=None):
    """Активный throttle-lease ({domain, rate, token, applied_at}) или None.

    None когда throttle не активен ИЛИ запись битая/невалидная (fail-safe: лучше
    считать «нет активного», чем отдать мусорный token в pfctl -X). Не бросает.
    """
    state = load_state(path)
    runtime = state.get("runtime") if isinstance(state, dict) else {}
    if not isinstance(runtime, dict):
        return None
    entry = runtime.get("active_throttle")
    return entry if _valid_active_throttle(entry) else None


def save_active_throttle(entry, path=None):
    """Записать активный throttle-lease в runtime.active_throttle. Возвращает entry|None.

    Валидирует entry (fail-closed: невалидное НЕ пишем — иначе clear получит мусорный
    token). Остальной state сохраняется (read-modify-write через save_state, atomic).
    readable=False (битый существующий файл) -> не перезаписываем вслепую, вернём None.
    Не бросает.
    """
    if not _valid_active_throttle(entry):
        return None
    state, readable = _load_state_checked(path)
    if not readable:
        return None
    runtime = state.get("runtime")
    if not isinstance(runtime, dict):
        runtime = {}
    # Нормализуем на запись: те же поля, никакого лишнего пользовательского мусора.
    runtime["active_throttle"] = {
        "domain": _normalize_traffic_guard_domain(entry.get("domain")),
        "rate": _valid_throttle_rate(entry.get("rate")),
        "token": str(entry.get("token")),
        "applied_at": entry.get("applied_at"),
    }
    state["runtime"] = runtime
    return None if save_state(state, path) is None else runtime["active_throttle"]


def clear_active_throttle(path=None):
    """Сбросить runtime.active_throttle в None (после успешного clear_throttle).

    Возвращает True при успешной записи, False при сбое/неперезаписываемом файле.
    Идемпотентно: уже None -> просто перезапишет None. Не бросает.
    """
    state, readable = _load_state_checked(path)
    if not readable:
        return False
    runtime = state.get("runtime")
    if not isinstance(runtime, dict):
        runtime = {}
    runtime["active_throttle"] = None
    state["runtime"] = runtime
    return save_state(state, path) is not None


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
    "detected_environment": {
        "last_checked_at": None,
        "brew": None,
        "xray": None,
        "privoxy": None,
        "dnsmasq": None,
        "launchagent": None,
    },
    # active_throttle — runtime-lease активного Traffic Guard throttle (#13/#22).
    # None когда throttle не активен. При активном: {domain, rate, token, applied_at}.
    # Персист именно token обязателен — без него clear_throttle не освободит pf
    # enable-ref (pfctl -X) после рестарта дашборда (issue #61). Это чистый runtime,
    # НЕ policy: держим отдельно от traffic_guard.domains (одно-pipe'овый движок,
    # один активный throttle за раз). Секретов нет; Reality-ключи/конфиги не трогаем.
    "runtime": {"last_apply": None, "last_error": None, "active_throttle": None},
}


def load_state(path=None):
    """Загрузить state. Missing/broken/non-object -> безопасный _DEFAULT_STATE (копия).
    Никогда не бросает.
    """
    state, _readable = _load_state_checked(path)
    return state


def load_state_checked(path=None):
    """Загрузить state и вернуть (state, readable) для мутирующих операций.

    readable=False означает: файл существует, но его нельзя безопасно
    перезаписывать без явного backup/решения вызывающего кода.
    """
    return _load_state_checked(path)


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
    """Атомарная запись (temp + rename). Возвращает state при успехе, None при ошибке. Не бросает."""
    p = Path(path) if path else _DEFAULT_PATH
    tmp = p.with_suffix(p.suffix + ".tmp")
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        tmp.replace(p)  # atomic rename
    except (OSError, TypeError, ValueError):
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return None
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
    except Exception:
        pass
    return host  # fallback на endpoint_host
