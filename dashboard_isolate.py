"""Probe-хелпер для PF-изоляции доменов (без Flask/dashboard-зависимостей).

probe_isolate — state-only (БЕЗ pfctl, root не нужен): lease + IP-снимок + phase.
Контракт probe-слоя: всегда dict со status (ok|warn|down|unknown), не бросает.
"""
import isolate_firewall

__all__ = ["probe_isolate"]


def probe_isolate(state_path=None):
    """Статус изоляции для gather_status. Делегирует в isolate_firewall.probe_isolation."""
    return isolate_firewall.probe_isolation(state_path=state_path)
