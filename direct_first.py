"""direct-first (#197): динамический NO_PROXY — домены, доступные напрямую (мимо GFW), идут мимо
прокси вместо статичного захардкоженного NO_PROXY.

Candidate-домены = BUILTIN z.ai (канон zai-direct-no-proxy, всегда) + user `direct_domains` из
srouter.local.json (opt-in — реальный IP виден домену). Каждый candidate проверяется честным прямым
TLS-test (sys_probe.direct_probe, базовый слой, вынесен из #206 GFW per-domain — канон
verify-dont-guess: один probe, не дублируем). Reachable → в NO_PROXY; timeout/reset (GFW режет) →
через прокси. Resilience (srouter-critical-infra-24-7): смерть VPS не роняет direct-домены — z.ai
всегда в NO_PROXY независимо от результата detect (BUILTIN_FALLBACK_NO_PROXY при любом сбое).

Не бросает нигде (probe-канон) — health.py/srouter-codex-env.sh зовут это в периодическом re-check
(codenv StartInterval=300) и в install-time; исключение здесь не должно ронять env-слой.
"""
from __future__ import annotations

import local_state
import sys_probe

# z.ai всегда candidate независимо от user-config — канон zai-direct-no-proxy: moonbridge ходит
# напрямую к api.z.ai, не GFW-target. Не убирается из NO_PROXY, даже если detect ошибётся.
BUILTIN_DIRECT_DOMAINS = ("z.ai",)

LOOPBACK_NO_PROXY = "localhost,127.0.0.1,::1"

# Fallback при любом сбое detect()/candidate_domains() (Python недоступен, state битый, сеть нет
# при install) — z.ai остаётся direct безусловно (resilience, канон srouter-critical-infra-24-7).
BUILTIN_FALLBACK_NO_PROXY = "localhost,127.0.0.1,::1,z.ai,.z.ai"

# Резервный лимит на количество candidate-доменов (BUILTIN + user direct_domains). detect() бьёт
# per-domain честный curl СЕРИАЛЬНО (без concurrency) с connect_timeout/max_time по несколько
# секунд — bulk-paste/ошибочный конфиг с тысячами доменов иначе блокирует периодический env-refresh
# (codenv StartInterval=300) на часы. Канон srouter-critical-infra-24-7: скорость восстановления/
# отзывчивость важнее полноты покрытия — BUILTIN z.ai всегда попадает в срез (добавляется первым).
MAX_CANDIDATE_DOMAINS = 50


def candidate_domains(path=None):
    """BUILTIN z.ai + validated user `direct_domains` (srouter.local.json), деduped (lowercase),
    порядок сохранён, срезано до MAX_CANDIDATE_DOMAINS. Невалидные (shell-metachars, leading dot)
    отбрасываются через local_state._is_valid_host + leading-dot guard (симметрично
    local_state._normalize_traffic_guard_domain — канон loose-validator-recurring-leak: один
    shell-safe валидатор + одна и та же dot-семантика, не новый расходящийся валидатор). Не бросает."""
    try:
        state = local_state.load_state(path)
        user_domains = state.get("direct_domains") if isinstance(state, dict) else None
        if not isinstance(user_domains, list):
            user_domains = []
    except Exception:
        user_domains = []
    seen, out = set(), []
    for host in (*BUILTIN_DIRECT_DOMAINS, *user_domains):
        if len(out) >= MAX_CANDIDATE_DOMAINS:
            break
        if not isinstance(host, str):
            continue
        h = host.strip()
        # leading dot ('.example.com') не отбрасывается _is_valid_host (символ '.' разрешён), но
        # build_no_proxy добавляет f'.{h}' — для leading-dot host это дало бы '..example.com'
        # (malformed NO_PROXY). Симметрично local_state._normalize_traffic_guard_domain.
        if not h or h.startswith(".") or not local_state._is_valid_host(h):
            continue
        if h.lower() in seen:
            continue
        seen.add(h.lower())
        out.append(h)
    return out


def direct_reachable(host):
    """Честный direct TLS-test одного домена — делегирует sys_probe.direct_probe (базовый слой,
    прямой curl мимо прокси, вынесен из #206). Возвращает (reachable: bool, kind: str). Не бросает.

    Тесты мокают sys_probe.direct_probe напрямую (monkeypatch.setattr(direct_first.sys_probe,
    "direct_probe", ...)) — тот же паттерн, что health._direct_domain_probe/sys_probe.run везде
    в проекте (мокается на уровне модульной ссылки, не через параметр-инъекцию)."""
    r = sys_probe.direct_probe(host)
    return bool(r.get("reachable")), r.get("kind", "connection-failed")


def detect(*, path=None):
    """Для каждого candidate-домена — direct_reachable. Возвращает
    {"reachable": [...], "blocked": [...], "details": {host: kind}}. Никогда не бросает: любой сбой
    (candidate_domains/probe) деградирует в «всё через прокси», НЕ роняет вызывающий env-слой."""
    try:
        domains = candidate_domains(path)
    except Exception:
        domains = list(BUILTIN_DIRECT_DOMAINS)
    reachable, blocked, details = [], [], {}
    for host in domains:
        try:
            ok, kind = direct_reachable(host)
        except Exception:
            ok, kind = False, "probe-error"
        details[host] = kind
        (reachable if ok else blocked).append(host)
    return {"reachable": reachable, "blocked": blocked, "details": details}


def build_no_proxy(reachable_hosts):
    """LOOPBACK + z.ai,.z.ai (БЕЗУСЛОВНО — канон zai-direct-no-proxy) + host,.host для каждого
    reachable-домена (exact + subdomains). Дедуп по lowercase, порядок сохранён."""
    seen, out = set(), []
    for h in LOOPBACK_NO_PROXY.split(","):
        if h.lower() not in seen:
            seen.add(h.lower())
            out.append(h)
    for host in (*BUILTIN_DIRECT_DOMAINS, *reachable_hosts):
        # rstrip trailing dots И lstrip leading dots — defense-in-depth: candidate_domains уже
        # отбрасывает leading-dot хосты, но build_no_proxy может быть вызван напрямую с сырым
        # списком (тесты, будущие вызывающие). Без lstrip('.') host='.example.com' дал бы
        # f'.{h}' == '..example.com' (malformed NO_PROXY entry).
        h = host.strip().strip(".").lower()
        if not h:
            continue
        for candidate in (h, f".{h}"):
            if candidate not in seen:
                seen.add(candidate)
                out.append(candidate)
    return ",".join(out)


def no_proxy_string(*, path=None):
    """Главная функция для shell/install-вызова: detect() → build_no_proxy(reachable). При ЛЮБОМ
    исключении → BUILTIN_FALLBACK_NO_PROXY (resilience — env-слой не должен остаться без NO_PROXY)."""
    try:
        det = detect(path=path)
        return build_no_proxy(det["reachable"])
    except Exception:
        return BUILTIN_FALLBACK_NO_PROXY


def merge_with_existing(existing_no_proxy, *, path=None):
    """detect() → build_no_proxy → merge с existing (claude_proxy._merge_no_proxy — не перезаписывает
    чужой NO_PROXY, канон merge-dont-overwrite). Для install-time/интерактивного применения."""
    import claude_proxy
    built = no_proxy_string(path=path)
    return claude_proxy._merge_no_proxy(existing_no_proxy, built)
