"""Traffic Guard (#10/#11/#13/#22) — валидация конфигурации + throttle runtime-lease.

Извлечено из local_state.py (issue #158, декомпозиция крупных файлов). local_state.py остаётся
тонким фасадом с полным ре-экспортом (канон star-import-reexport-contract) — внешние потребители
продолжают писать `local_state.traffic_guard_config(...)` и т.п.

Core state I/O (_load_state_checked/save_state/load_state/_DEFAULT_PATH) физически живёт в
local_state.py. Этот модуль обращается к нему ЧЕРЕЗ фасад (`import local_state`,
`local_state._load_state_checked(...)`), а не напрямую — так тесты, патчащие
`local_state._load_state_checked`/`local_state.save_state`, продолжают перехватывать вызовы отсюда
(канон moving-caller-inverts-mock-ownership: caller и callee физически разъехались, поэтому caller
обязан резолвить callee через module-attribute lookup на фасаде, а не забинженной ссылкой на другой
подмодуль). Цикла импорта нет: `import local_state` только регистрирует модуль, атрибуты читаются
в момент вызова функции (к тому времени local_state.py полностью инициализирован — он импортирует
этот модуль последним, в самом низу файла).
"""
import local_state

_TRAFFIC_GUARD_MODES = {"on", "off", "auto"}
_TRAFFIC_GUARD_POLICIES = {"block", "allow"}
_TRAFFIC_GUARD_CHANNELS = {"wifi", "usb_tether", "metered"}
_TRAFFIC_GUARD_AUTO_DOMAINS_ERROR = "traffic_guard.domains must define channel policies for auto mode"


def _normalize_traffic_guard_domain(domain):
    """Нормализовать domain-rule для exact+subdomain match; пустая строка значит reject."""
    if not isinstance(domain, str):
        return ""
    normalized = domain.strip().lower().rstrip(".")
    if not normalized or normalized.startswith(".") or ".." in normalized:
        return ""
    # Traffic Guard принимает домены, не host:port/IPv6; shell-символы всё равно режет _HOST_RE.
    if ":" in normalized or not local_state._is_valid_host(normalized):
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
        state = local_state.load_state(path)
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
    state = local_state.load_state(path)
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
    state, readable = local_state._load_state_checked(path)
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
    return None if local_state.save_state(state, path) is None else runtime["active_throttle"]


def clear_active_throttle(path=None):
    """Сбросить runtime.active_throttle в None (после успешного clear_throttle).

    Возвращает True при успешной записи, False при сбое/неперезаписываемом файле.
    Идемпотентно: уже None -> просто перезапишет None. Не бросает.
    """
    state, readable = local_state._load_state_checked(path)
    if not readable:
        return False
    runtime = state.get("runtime")
    if not isinstance(runtime, dict):
        runtime = {}
    runtime["active_throttle"] = None
    state["runtime"] = runtime
    return local_state.save_state(state, path) is not None
