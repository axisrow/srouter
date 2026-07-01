"""Traffic Guard helpers dashboard без импорта Flask/dashboard."""

import local_state


__all__ = [
    "probe_traffic_guard",
]


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
