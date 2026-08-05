"""PF-изоляция доменов (isolate) + codex-изоляция (#168) — runtime-lease и валидация.

Извлечено из local_state.py (issue #158, декомпозиция крупных файлов). Обращается к core state
I/O через фасад `local_state` (см. docstring local_state_traffic_guard.py — тот же паттерн
facade-lookup, канон moving-caller-inverts-mock-ownership).

Lease симметричен throttle: {domains, ips, unresolved, token, applied_at, ports, phase}.
token обязателен к персисту — без него disable_isolation не освободит pf enable-ref
(pfctl -X) после рестарта. phase: "strict" (страховка подсетей) | "working" (конкретные IP).
"""
import local_state


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
            if isinstance(d, str) and local_state._is_valid_host(d):
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
        isinstance(d, str) and local_state._is_valid_host(d) for d in domains
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
    state = local_state.load_state(path)
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
    state, readable = local_state._load_state_checked(path)
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
    return None if local_state.save_state(state, path) is None else runtime["active_isolate"]


def clear_active_isolate(path=None):
    """Сброс runtime.active_isolate в None (после disable_isolation). Идемпотентно."""
    state, readable = local_state._load_state_checked(path)
    if not readable:
        return False
    runtime = state.get("runtime")
    if not isinstance(runtime, dict):
        runtime = {}
    runtime["active_isolate"] = None
    state["runtime"] = runtime
    return local_state.save_state(state, path) is not None


def _valid_active_codex_isolate(entry):
    """True если entry — валидный codex-isolate-lease (PF codex-изоляция, issue #168).

    Отдельный от _valid_active_isolate: codex-изоляция по source-UID (не по доменам),
    поэтому НЕ содержит domains/ports/phase — только token (pfctl -X, числовой) и
    applied_at (опциональный снимок). fail-closed: невалидное → None (нет мусорного token).
    """
    if not isinstance(entry, dict):
        return False
    token = entry.get("token")
    if isinstance(token, bool) or not (
        (isinstance(token, int) and token >= 0) or (isinstance(token, str) and token.isdigit())
    ):
        return False
    applied_at = entry.get("applied_at")
    if applied_at is not None and not isinstance(applied_at, (int, float, str)):
        return False
    return True


def load_active_codex_isolate(path=None):
    """Активный codex-isolate-lease или None. Fail-safe: битая запись → None."""
    state = local_state.load_state(path)
    runtime = state.get("runtime") if isinstance(state, dict) else {}
    if not isinstance(runtime, dict):
        return None
    entry = runtime.get("active_codex_isolate")
    return entry if _valid_active_codex_isolate(entry) else None


def save_active_codex_isolate(entry, path=None):
    """Записать codex-isolate-lease в runtime.active_codex_isolate. Возвращает entry|None.

    fail-closed: невалидное НЕ пишем (иначе disable получит мусорный token). Atomic.
    """
    if not _valid_active_codex_isolate(entry):
        return None
    state, readable = local_state._load_state_checked(path)
    if not readable:
        return None
    runtime = state.get("runtime")
    if not isinstance(runtime, dict):
        runtime = {}
    runtime["active_codex_isolate"] = {
        "token": str(entry.get("token")),
        "applied_at": entry.get("applied_at"),
    }
    state["runtime"] = runtime
    return None if local_state.save_state(state, path) is None else runtime["active_codex_isolate"]


def clear_active_codex_isolate(path=None):
    """Сброс runtime.active_codex_isolate в None (после disable_codex_isolation). Идемпотентно."""
    state, readable = local_state._load_state_checked(path)
    if not readable:
        return False
    runtime = state.get("runtime")
    if not isinstance(runtime, dict):
        runtime = {}
    runtime["active_codex_isolate"] = None
    state["runtime"] = runtime
    return local_state.save_state(state, path) is not None
