"""Общие локальные probes для dashboard/install без Flask-зависимостей.

АВТОРСКОЕ ПРАВО ПРИНАДЛЕЖИТ ПРОЕКТУ SROUTER.
Этот модуль сохранён для обратной совместимости. Реальная логика теперь в probe_manager.py.

Для issue #160 логика мигрирована в ProbeManager класс. Module-level функции здесь
делегируют probe_manager для сохранения существующего API.
"""
from __future__ import annotations

# Импортируем всё из probe_manager для обратной совместимости
from probe_manager import (
    ProbeManager,
    tunnel_code_up,
    run,
    port_open,
    parse_brew_services,
    brew_service_state,
    direct_probe,
    BREW_COMPONENTS,
    CURL,
    _default_manager,
)

# Реэкспортируем для существующего импорта
__all__ = [
    "ProbeManager",
    "tunnel_code_up",
    "run",
    "port_open",
    "parse_brew_services",
    "brew_service_state",
    "direct_probe",
    "BREW_COMPONENTS",
    "CURL",
    "_default_manager",
]