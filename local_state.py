"""Defensive stdlib-only helper над unified local state `srouter.local.json`.

Контракт (#2): функции НИКОГДА не бросают; невалидный ввод деградирует в empty/default.
Path по умолчанию — рядом с модулем (не cwd), чтобы работал под launchd.
Каждая public функция принимает path= для тестов (tmp_path fixture).
"""
import json
import os
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
    # applied_at — метка времени; необязателен (None), но при наличии обязан быть
    # числом/строкой, иначе мусорное значение попадёт в публичный GET-ответ.
    applied_at = entry.get("applied_at")
    if applied_at is not None and not isinstance(applied_at, (int, float, str)):
        return False
    # needs_cleanup — опциональный булев маркер cleanup-lease (token жив на pf, но
    # throttle не активен как политика — ждёт освобождения). При наличии обязан быть bool.
    needs_cleanup = entry.get("needs_cleanup")
    if needs_cleanup is not None and not isinstance(needs_cleanup, bool):
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


def save_active_throttle(entry, path=None, needs_cleanup=False):
    """Записать активный throttle-lease в runtime.active_throttle. Возвращает entry|None.

    Валидирует entry (fail-closed: невалидное НЕ пишем — иначе clear получит мусорный
    token). Остальной state сохраняется (read-modify-write через save_state, atomic).
    readable=False (битый существующий файл) -> не перезаписываем вслепую, вернём None.
    needs_cleanup=True маркирует cleanup-lease: pf-токен ЖИВ на pf, но throttle не
    активирован как политика (apply упал post--E, либо rollback не подтверждён) — lease
    нужен, чтобы token был recoverable для последующего clear. Не бросает.
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
        "needs_cleanup": bool(needs_cleanup),
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


# ============================ PF-изоляция доменов (isolate) ============================
# Lease симметричен throttle: {domains, ips, unresolved, token, applied_at, ports, phase}.
# token обязателен к персисту — без него disable_isolation не освободит pf enable-ref
# (pfctl -X) после рестарта. phase: "strict" (страховка подсетей) | "working" (конкретные IP).
def _valid_isolate_ports(ports):
    """Список портов 1..65535 или None. Только положительные целые — попадут в shell."""
    if not isinstance(ports, list) or not ports:
        return None
    out = []
    for p in ports:
        if isinstance(p, bool) or not isinstance(p, int) or not (1 <= p <= 65535):
            return None
        out.append(p)
    return out if out else None


def validate_isolate(isolate):
    """Валидация секции isolate из state. Возвращает (normalized, errors).

    domains: список валидных host (через _is_valid_host). ports: список int 1..65535.
    enabled: bool. Никаких лишних полей. Не бросает.
    """
    errors = []
    if not isinstance(isolate, dict):
        return None, ["isolate должен быть объектом"]
    domains = isolate.get("domains")
    if not isinstance(domains, list) or not domains:
        errors.append("isolate.domains должен быть непустым списком доменов")
        domains = []
    else:
        norm = []
        for d in domains:
            if isinstance(d, str) and _is_valid_host(d):
                norm.append(d)
            else:
                errors.append(f"невалидный домен: {d!r}")
        domains = norm
    ports = _valid_isolate_ports(isolate.get("ports"))
    if ports is None:
        if "ports" in isolate and isolate.get("ports") is not None:
            errors.append("isolate.ports должен быть списком целых 1..65535")
        ports = [80, 443]
    enabled = bool(isolate.get("enabled", False))
    if errors:
        return None, errors
    return {"enabled": enabled, "domains": domains, "ports": ports}, []


def _valid_active_isolate(entry):
    """True если entry — валидный isolate-lease для recover после рестарта.

    Требуем token (числовой — pfctl -X), domains (список host), ports, applied_at, phase.
    ips/unresolved опциональны (снимок для дашборда).
    """
    if not isinstance(entry, dict):
        return False
    token = entry.get("token")
    if isinstance(token, bool) or not (
        (isinstance(token, int) and token >= 0) or (isinstance(token, str) and token.isdigit())
    ):
        return False
    domains = entry.get("domains")
    if not isinstance(domains, list) or not all(
        isinstance(d, str) and _is_valid_host(d) for d in domains
    ):
        return False
    if _valid_isolate_ports(entry.get("ports")) is None:
        return False
    phase = entry.get("phase")
    if phase not in ("strict", "working"):
        return False
    applied_at = entry.get("applied_at")
    if applied_at is not None and not isinstance(applied_at, (int, float, str)):
        return False
    return True


def load_active_isolate(path=None):
    """Активный isolate-lease или None. Fail-safe: битая запись → None (нет мусорного token)."""
    state = load_state(path)
    runtime = state.get("runtime") if isinstance(state, dict) else {}
    if not isinstance(runtime, dict):
        return None
    entry = runtime.get("active_isolate")
    return entry if _valid_active_isolate(entry) else None


def save_active_isolate(entry, path=None):
    """Записать isolate-lease в runtime.active_isolate. Возвращает entry|None.

    fail-closed: невалидное НЕ пишем (иначе disable получит мусорный token). Atomic.
    """
    if not _valid_active_isolate(entry):
        return None
    state, readable = _load_state_checked(path)
    if not readable:
        return None
    runtime = state.get("runtime")
    if not isinstance(runtime, dict):
        runtime = {}
    runtime["active_isolate"] = {
        "domains": list(entry.get("domains", [])),
        "ips": entry.get("ips", {}) if isinstance(entry.get("ips"), dict) else {},
        "unresolved": list(entry.get("unresolved", [])),
        "ports": list(entry.get("ports", [80, 443])),
        "token": str(entry.get("token")),
        "applied_at": entry.get("applied_at"),
        "phase": entry.get("phase", "working"),
    }
    state["runtime"] = runtime
    return None if save_state(state, path) is None else runtime["active_isolate"]


def clear_active_isolate(path=None):
    """Сброс runtime.active_isolate в None (после disable_isolation). Идемпотентно."""
    state, readable = _load_state_checked(path)
    if not readable:
        return False
    runtime = state.get("runtime")
    if not isinstance(runtime, dict):
        runtime = {}
    runtime["active_isolate"] = None
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
    # PF-изоляция Proxy-доменов: прямой путь к этим доменам отрезается в ядре PF.
    # domains — дефолт Claude (меняется в дашборде). ports 80/443 (CloudFront IP хостят
    # много доменов). enabled=False по умолчанию — изоляция включается явно через UI/CLI.
    "isolate": {
        "enabled": False,
        "domains": ["api.anthropic.com", "console.anthropic.com", "claude.ai"],
        "ports": [80, 443],
    },
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
    "runtime": {"last_apply": None, "last_error": None, "active_throttle": None,
                 "active_isolate": None},
    # auto_route_sync — opt-in split-route до VPS через en0 (мимо VPN). Top-level ключ (читается
    # node_selector._auto_route_sync_enabled строго is True). По умолчанию ON — «пофигу VPN»:
    # watchdog (ensure_split_route) держит route через физический шлюз при любом состоянии VPN.
    "auto_route_sync": True,
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
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(p)  # atomic rename
        _fsync_parent_dir(p)
    except (OSError, TypeError, ValueError):
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return None
    return state


def _fsync_parent_dir(path):
    """Best-effort fsync каталога после atomic rename; не все FS это поддерживают."""
    try:
        fd = os.open(path.parent, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _atomic_write_text(path, text):
    """Атомарная запись произвольного текста в path (tmp + flush + fsync + rename + fsync_dir).

    Канон atomic-save (эталон save_state): никогда не truncate production-файл напрямую — пишем во
    временный файл, затем atomic-rename. Если диск откажет (ENOSPC/IO-error) на любой стадии —
    production-файл остаётся НЕТРОНУТЫМ (либо старое содержимое целиком, либо успешно заменённое
    новое), никогда не в промежуточном/truncated состоянии. #139: единый примитив для шага modify
    И обоих rollback-веток routing_apply, чтобы откат конфига тоже был атомарным.

    Возвращает True при успехе, False при OSError/любом провале записи (не бросает)."""
    p = Path(path)
    tmp = p.with_suffix(p.suffix + ".tmp")
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)  # atomic rename
        _fsync_parent_dir(p)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False
    return True


def _routing_config_lock(config_path):
    """Context-manager process-safe exclusive lock на xray-config.json (flock LOCK_EX).

    #139 Finding 2: serialize concurrent routing_apply (ручной `srouter routing` + install/future
    gen_xray_config). Канон — однопользовательский CLI, не демон; реалистичный race — два
    одновременных вызова в узкое окно read->write. flock блокирующий: второй apply ждёт отпускания
    lock первым, не читая stale snapshot -> нет lost-update (затирания доменов). Блокировка
    намеренно держится через restart xray, т.к. stale-snapshot замена после restart — ядро дыры.

    Адаптивный lockfile: создаётся .lock рядом с config. Файл НЕ читается/не пишется как данные —
    только flock по fd; содержимое не валидируется (наследует failure-mode flock: lock-файл может
    остаться на диске, но это безобидно — следующий apply открывает и flock'ит его же)."""
    import contextlib
    import fcntl

    lock_p = Path(config_path).with_name(Path(config_path).name + ".lock")

    @contextlib.contextmanager
    def _cm():
        lock_p.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(lock_p, os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)  # блокирует до отпускания другим процессом/потоком
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)

    return _cm()


def preflight_state_write(path=None):
    """Проверить реальный atomic-write путь для state до privileged throttle apply.

    load_state_checked() доказывает только parse/read. Для throttle этого мало:
    pf enable-ref нельзя создавать, пока не доказано, что тот же save_state path
    способен записать recoverable lease. Под dashboard mutation-lock делаем no-op
    rewrite текущего state через точный save_state.
    """
    state, readable = load_state_checked(path)
    if not readable:
        return False
    return save_state(state, path) is not None


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


# Куда gen_xray_config пишет рабочий конфиг (источник истины address узла).
XRAY_CONFIG_PATH = "/opt/homebrew/etc/xray/config.json"


def _read_xray_vless_address(config_path=XRAY_CONFIG_PATH):
    """Прочитать address Reality-узла из РЕАБОЧЕГО xray-конфига (outbounds → vless → vnext[0].address).

    xray-конфиг = источник истины: gen_xray_config._vless_outbound пишет туда resolve_route_ip(node).
    Если state рассинхронизирован (placeholder), xray держит реальный рабочий IP. Не бросает.
    Возвращает address (строка) или '' при отсутствии/сбое/битом JSON.
    """
    try:
        data = json.loads(Path(config_path).read_text(encoding="utf-8"))
    except Exception:
        return ""
    if not isinstance(data, dict):
        return ""
    for ob in data.get("outbounds") or []:
        if not isinstance(ob, dict) or ob.get("protocol") != "vless":
            continue
        vnext = (ob.get("settings") or {}).get("vnext") or []
        if vnext and isinstance(vnext[0], dict):
            addr = vnext[0].get("address")
            if isinstance(addr, str) and _is_valid_host(addr):
                return addr
    return ""


def sync_route_ip_from_xray(name, xray_config_path=XRAY_CONFIG_PATH, path=None):
    """Синхронизировать route_ip узла <name> из рабочего xray-конфига.

    xray-конфиг — источник истины (туда gen_xray_config пишет resolve_route_ip). Если state держит
    placeholder/rассинхрон — берём реальный address из xray и пишем в node.route_ip. После этого и
    gen_xray, и node_selector._route_node_ip читают консистентный IP. Не бросает.

    Возвращает {ok: bool, route_ip: str}. ok=False если xray-конфига нет / узел не найден / битый.
    """
    address = _read_xray_vless_address(xray_config_path)
    if not address:
        return {"ok": False, "route_ip": ""}
    try:
        state, readable = _load_state_checked(path)
        if not readable:
            return {"ok": False, "route_ip": ""}
    except Exception:
        return {"ok": False, "route_ip": ""}
    nodes = _nodes_from_state(state)
    updated = False
    for n in nodes:
        if isinstance(n, dict) and n.get("name") == name:
            if n.get("route_ip") != address:
                n["route_ip"] = address
                updated = True
            break
    else:
        return {"ok": False, "route_ip": ""}  # узел не найден
    if updated:
        try:
            save_state(state, path)
        except Exception:
            return {"ok": False, "route_ip": ""}
    return {"ok": True, "route_ip": address}


# ============================ #136: routing-domains в production xray-config (hybrid adopt) ============================
# srouter управляет routing.rules секцией reality-out: adopt существующего rule (маркер _srouter_managed
# на уровне rule, НЕ top-level — foreign-конфиг не захватывается целиком), домены хранит в state
# (active + last_applied_hash для drift-detection). Two-phase: backup → modify → restart → promote.
# Эталон read-xray: _read_xray_vless_address; atomic-save: save_state; restart: install_lib._restart_component.

ROUTING_MARKER = "_srouter_managed"  # ключ в rule (xray игнорирует неизвестные ключи — безопасно)
DEFAULT_ROUTING_OUTBOUND = "reality-out"


def routing_plan(current_domains, hosts, action="add"):
    """Построить новый домен-список: добавить/убрать hosts в current_domains. Чистая функция, без записи.

    hosts — bare hostnames ('telegram.org'); нормализуются в 'domain:<host>' (xray exact+subdomains).
    action='add' — добавить недостающие (idempotent: дубль игнорируется);
    action='remove' — убрать совпадающие.
    Возвращает новый список (сохраняя порядок current + new в конце для add).
    """
    if not isinstance(current_domains, list):
        current_domains = []
    if not isinstance(hosts, list):
        hosts = [hosts] if isinstance(hosts, str) else []
    norm = [f"domain:{h}" if not str(h).startswith("domain:") else str(h) for h in hosts if h]
    if action == "remove":
        rm = set(norm)
        return [d for d in current_domains if d not in rm]
    # add: сохранить порядок, дубли пропустить
    existing = set(current_domains)
    out = list(current_domains)
    for d in norm:
        if d not in existing:
            out.append(d)
            existing.add(d)
    return out


def _routing_find_managed_rule(rules):
    """Найти индекс rule с _srouter_managed:true. -1 если нет..Raise если их >1 (ambiguous)."""
    idxs = [i for i, r in enumerate(rules)
            if isinstance(r, dict) and r.get(ROUTING_MARKER) is True]
    if len(idxs) > 1:
        return -2  # ambiguous — несколько managed-секций, отказать
    return idxs[0] if idxs else -1


def _routing_domains_hash(domains):
    """Стабильный hash домен-списка для drift-detection (сортировка → не зависит от порядка)."""
    import hashlib
    ordered = "\n".join(sorted(domains))
    return hashlib.sha256(ordered.encode("utf-8")).hexdigest()[:16]


def routing_apply(hosts, *, action="add", adopt=False, outbound=DEFAULT_ROUTING_OUTBOUND,
                  config_path=XRAY_CONFIG_PATH, state_path=None, runner=None, port_checker=None):
    """Применить изменение routing-доменов в production xray-config + restart xray (two-phase).

    Hybrid adopt: foreign-config без маркера → требует adopt=True (захватить секцию). После adopt
    rule помечается _srouter_managed, домены + hash пишутся в state. Locate по маркеру, не по tag
    (защита от переименования outbound). Hash-drift (конфиг меняли руками) → refuse.
    Транзакционность: state пишется ДО restart xray; при провале ЛЮБОГО шага (unreadable state,
    state-write, restart) — откат к исходному config (и state, если restart упал после успешной
    записи state), никогда не оставляя config и state рассинхронизированными. Существующий, но
    битый state-файл никогда не заменяется дефолтом (data-loss guard).
    Concurrency/atomicity (#139): критическая секция (read backup-snapshot → modify → restart)
    под process-safe flock на xray-config.json — конкурирующие apply сериализуются, нет lost-update.
    Все записи конфига (modify + ОБОИ rollback-ветки) атомарны (_atomic_write_text: tmp+fsync+rename),
    ENOSPC/IO-error при rollback не повреждают production-файл.

    Возвращает {ok, changed, err}. Не бросает (fail-soft как sync_route_ip_from_xray).
    """
    # lazy import чтобы не тащить зависимость модуля при простом чтении state
    try:
        import install_lib
    except Exception:
        install_lib = None

    # ВСЯ транзакция (read config → read state → backup → modify → restart) под process-safe
    # exclusive flock на xray-config: критическая секция начинается С ЧТЕНИЯ config, не с записи —
    # иначе второй apply успевает закешировать stale snapshot ДО блокировки и затирает первый при
    # своей записи (lost-update). flock сериализует конкурирующие apply (ручной `srouter routing` ×
    # install/будущий gen_xray_config). #139 Finding 2.
    try:
        with _routing_config_lock(config_path):
            return _routing_apply_locked(
                config_path, state_path, outbound, hosts, action, adopt, runner, port_checker,
                install_lib,
            )
    except OSError:
        # lockfile не создался/не открылся — fail-closed: не мутируем config без сериализации.
        return {"ok": False, "changed": False, "err": "config_lock_failed"}


def _routing_apply_locked(config_path, state_path, outbound, hosts, action, adopt, runner,
                          port_checker, install_lib):
    """Шаги 1..6 routing_apply под _routing_config_lock. Вынесено, чтобы lock держался от чтения
    config до завершения restart/recovery (включая все stale-snapshot-чувствительные шаги).

    Внутри lock: read config/state → backup → atomic modify → state-write → restart (с atomic
    rollback при провале). Rollback-записи атомарны (_atomic_write_text), не truncate+write —
    #139 Finding 1. Возвращает {ok, changed, err}. Не бросает (fail-soft)."""
    # 1. читать config (fail-soft)
    try:
        data = json.loads(Path(config_path).read_text(encoding="utf-8"))
    except Exception:
        return {"ok": False, "changed": False, "err": "config_unreadable"}
    if not isinstance(data, dict):
        return {"ok": False, "changed": False, "err": "config_not_dict"}
    routing = data.get("routing")
    if not isinstance(routing, dict):
        return {"ok": False, "changed": False, "err": "no_routing_section"}
    rules = routing.get("rules")
    if not isinstance(rules, list) or not rules:
        return {"ok": False, "changed": False, "err": "no_routing_rules"}

    idx = _routing_find_managed_rule(rules)
    if idx == -2:
        return {"ok": False, "changed": False, "err": "ambiguous_managed_rules"}

    if idx == -1:
        # нет managed-секции
        if not adopt:
            return {"ok": False, "changed": False, "err": "foreign_config_needs_adopt"}
        # adopt: найти rule по outboundTag (ровно один)
        matches = [i for i, r in enumerate(rules)
                   if isinstance(r, dict) and r.get("outboundTag") == outbound
                   and isinstance(r.get("domain"), list)]
        if len(matches) != 1:
            return {"ok": False, "changed": False, "err": f"adopt_needs_one_{outbound}_rule"}
        idx = matches[0]

    rule = rules[idx]
    current_domains = list(rule.get("domain") or [])

    # 2. читать state ОДИН раз здесь (readable проверяем всегда, drift — только когда есть с чем
    #    сравнивать). Битый существующий state-файл → fail-closed ДО любых мутаций конфига: не смеем
    #    ни читать активный набор для drift-сравнения, ни (ниже, в state-write) заменять его дефолтом
    #    (data-loss — теряет nodes/active_node/traffic_guard/isolate пользователя).
    try:
        state, state_readable = _load_state_checked(state_path)
    except Exception:
        state, state_readable = None, False
    if not state_readable or not isinstance(state, dict):
        return {"ok": False, "changed": False, "err": "state_unreadable"}
    if adopt is False or rule.get(ROUTING_MARKER) is True:
        rt = state.get("routing") if isinstance(state.get("routing"), dict) else {}
        stored_hash = rt.get("last_applied_hash")
        if stored_hash and _routing_domains_hash(current_domains) != stored_hash:
            return {"ok": False, "changed": False, "err": "hash_drift_config_changed_externally"}

    new_domains = routing_plan(current_domains, hosts, action=action)
    if new_domains == current_domains:
        return {"ok": True, "changed": False, "err": ""}  # idempotent, restart не нужен

    # 3. backup (two-phase: восстановим при ошибке restart) — читаем СВЕЖИЙ config под lock
    config_p = Path(config_path)
    backup_text = config_p.read_text(encoding="utf-8")

    # 4. modify rule in-place copy + atomic write (tmp+fsync+replace — единый _atomic_write_text)
    new_rule = dict(rule)
    new_rule["domain"] = new_domains
    new_rule[ROUTING_MARKER] = True
    new_rules = list(rules)
    new_rules[idx] = new_rule
    new_data = dict(data)
    new_data["routing"] = dict(routing)
    new_data["routing"]["rules"] = new_rules
    if not _atomic_write_text(config_p, json.dumps(new_data, ensure_ascii=False, indent=2) + "\n"):
        return {"ok": False, "changed": False, "err": "config_write_failed"}

    # 5. state-write ДО restart (транзакционность: если state не запишется — откатываем config и НЕ
    #    трогаем xray вовсе, не оставляя рассинхрон config↔state). state гарантированно readable dict
    #    (шаг 2 fail-closed на unreadable state ДО этой точки — исключений здесь не бывает).
    try:
        if not isinstance(state.get("routing"), dict):
            state["routing"] = {}
        state["routing"]["active"] = new_domains
        state["routing"]["outbound"] = outbound
        state["routing"]["last_applied_hash"] = _routing_domains_hash(new_domains)
        state_write_ok = save_state(state, state_path) is not None
    except Exception:
        state_write_ok = False
    if not state_write_ok:
        # atomic rollback: tmp+fsync+replace, не truncate+write (ENOSPC не повредит production)
        _atomic_write_text(config_p, backup_text)
        return {"ok": False, "changed": False, "err": "state_write_failed"}

    # 6. restart xray (fail-closed: при провале — восстановить config+state И повторно перезапустить
    #    xray СО СТАРЫМ восстановленным конфигом. _restart_component уже сделал stop к моменту провала
    #    start — без recovery-рестарта xray остаётся down до ручного вмешательства, превращая рутинную
    #    неудачную операцию routing add-domain в постоянный простой всего прокси, Codex round 2).
    if runner is not None and install_lib is not None:
        try:
            res = install_lib._restart_component("xray", runner, port_checker=port_checker)
        except Exception:
            res = {"rc": 1, "err": "restart_exception"}
        if res.get("rc") != 0 or res.get("timeout"):
            # atomic rollback к backup (tmp+fsync+replace); провал записи не оставляет config
            # усечённым/молча неоткаченным — #139 Finding 1
            _atomic_write_text(config_p, backup_text)
            try:
                state["routing"]["active"] = current_domains
                state["routing"]["outbound"] = outbound
                state["routing"]["last_applied_hash"] = _routing_domains_hash(current_domains)
                save_state(state, state_path)
            except Exception:
                pass
            recovery_err = ""
            try:
                recovery = install_lib._restart_component("xray", runner, port_checker=port_checker)
                if recovery.get("rc") != 0 or recovery.get("timeout"):
                    recovery_err = f"; recovery_restart_failed:{recovery.get('err', 'unknown')}"
            except Exception:
                recovery_err = "; recovery_restart_exception"
            return {"ok": False, "changed": False,
                    "err": f"restart_failed:{res.get('err', 'unknown')}{recovery_err}"}

    return {"ok": True, "changed": True, "err": ""}

