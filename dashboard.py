#!/usr/bin/env python3
"""Локальный дашборд: мониторинг и управление цепочкой privoxy→xray→Reality + VPN/маршруты.

Запуск:  python3 dashboard.py   →   http://127.0.0.1:8787
Только loopback, debug=False. Privileged-действия (route) спрашивают пароль macOS через osascript.

Issue #227 (эпик #107/#158): файл разбит на dashboard_app.py (Flask app-фабрика, статус-кэш,
CSRF/Host/mutation-lock guards) + dashboard_routes.py (все @app.* роуты и их приватные хелперы).
Этот модуль остаётся точкой входа (`python3 dashboard.py`) и тонким фасадом, реэкспортирующим
public API обоих модулей для обратной совместимости — тесты и другие модули обращаются к именам
как dashboard.<name> (канон no-hidden-magic-follow-canon: экстракция, не редизайн).
"""
import threading  # noqa: F401  (реэкспорт: dashboard.threading использовался как транзитивное имя)
import re  # noqa: F401  (реэкспорт: dashboard.re — транзитивное имя из dashboard_routes)
import time  # noqa: F401  (реэкспорт: dashboard.time — транзитивное имя)
from pathlib import Path  # noqa: F401
from urllib.parse import urlsplit  # noqa: F401
from concurrent.futures import ThreadPoolExecutor, wait  # noqa: F401
from flask import Flask, g, jsonify, Response, request  # noqa: F401

import local_state
from dashboard_common import (
    BREW,
    CHANNEL_TARGETS,
    CURL,
    GATEWAY,
    IFCONFIG,
    NETWORKSETUP,
    OSASCRIPT,
    PING,
    ROUTE,
    _active_route_context,
    _active_route_ip,
    _ip_literal,
)
from dashboard_connectivity import (
    _known_service_name,
    _parse_network_services,
    _probe_direct_reachability,
    probe_connectivity,
    probe_exit_ips_per_iface,
    probe_ifaces,
    switch_channel,
)
from dashboard_geo import probe_geo_distance, probe_ips
from dashboard_network import (
    _parse_ping_stats,
    probe_direct,
    probe_exit_ip,
    probe_ping,
    probe_route_to_vps,
    probe_services,
    probe_tunnel,
    probe_vpn,
)
from dashboard_nodes import (
    _nodes_cache,
    _parse_throughput_output,
    probe_dns,
    probe_nodes,
    probe_nodes_snapshot,
)
from dashboard_traffic import probe_traffic_guard
from dashboard_hotroutes import probe_hot_routes
from dashboard_isolate import probe_isolate
import node_selector
import sys_probe
import traffic_shape  # throttle-движок (#13): зовём через атрибут (traffic_shape.apply_throttle)
import isolate_firewall  # PF-изоляция доменов: зовём через атрибут
import lock_hierarchy
import git_proxy  # вкл/откл git-прокси для github (через git config --global)
import claude_proxy  # вкл/откл HTTPS_PROXY для Claude Code (~/.claude/settings.json)
import health  # check_all для /health эндпоинта
import privoxy_system  # protected system-service gate (#122)

# dashboard_app.py: Flask app-фабрика, статус-кэш, CSRF/Host/mutation-lock guards.
from dashboard_app import (
    PORT,
    STATUS_CACHE_TTL_SEC,
    STATUS_PROBE_BUDGET_SEC,
    INDEX_HTML,
    app,
    _ALLOWED_HOSTNAMES,
    _GUARD_HOSTS,
    _MUTATION_LOCK,
    _cache,
    _lock,
    _allowed_origins,
    _csrf_origin_guard,
    _host_rebinding_guard,
    _is_allowed_host,
    _is_cross_origin_post,
    _mutation_lock_guard,
    _mutation_lock_release,
    _run_status_probe_set,
    gather_status,
    index,
    main,
)

# dashboard_routes.py: все @app.* роуты и приватные хелперы конкретных фич.
# Импортируется РАДИ ПОБОЧНОГО ЭФФЕКТА регистрации роутов на `app` (dashboard_app.app) —
# сам dashboard_routes ничего не возвращает в module namespace автоматически, поэтому
# нужные тестам/потребителям имена перечислены явно ниже.
from dashboard_routes import (  # noqa: F401  (регистрация роутов на app — побочный эффект импорта)
    _THROTTLE_PUBLIC_REDACTIONS,
    _active_host_route_ip,
    _guard_payload,
    _host_route_action,
    _isolate_result,
    _persist_active_or_cleanup,
    _persist_cleanup_lease,
    _public_active_throttle,
    _public_isolate,
    _public_throttle,
    _redact_throttle_text,
    _route_result,
    _sudo_route_ip,
    _throttle_apply,
    _throttle_clear,
    _throttle_payload,
    _throttle_result,
    api_channel,
    api_channel_empty,
    api_claude_proxy_disable,
    api_claude_proxy_enable,
    api_claude_proxy_get,
    api_git_proxy_disable,
    api_git_proxy_enable,
    api_git_proxy_get,
    api_proxy_apply,
    api_proxy_overview,
    api_guard,
    api_guard_get,
    api_guard_throttle,
    api_isolate_disable,
    api_isolate_enable,
    api_isolate_get,
    api_isolate_refresh,
    api_node_select,
    api_nodes_ranking,
    api_probe_nodes,
    api_route,
    api_route_host,
    api_service,
    api_status,
    health_endpoint,
    service_control,
    sudo_route,
)

# Явный re-export-контракт (issue #157, issue #227): до чистки star imports эти имена попадали
# в namespace dashboard неявно через `from <submodule> import *` и тесты обращаются
# к ним как dashboard.<name>. `__all__` декларирует этот контракт явно (вместо магии
# star import) и одновременно гасит ruff F401 на умышленно неиспользуемых в коде
# dashboard.py, но публично реэкспортируемых именах.
__all__ = [
    # dashboard_common
    "BREW",
    "CHANNEL_TARGETS",
    "CURL",
    "GATEWAY",
    "IFCONFIG",
    "NETWORKSETUP",
    "OSASCRIPT",
    "PING",
    "ROUTE",
    "_active_route_context",
    "_active_route_ip",
    "_ip_literal",
    # dashboard_connectivity
    "_known_service_name",
    "_parse_network_services",
    "_probe_direct_reachability",
    "probe_connectivity",
    "probe_exit_ips_per_iface",
    "probe_ifaces",
    "switch_channel",
    # dashboard_geo
    "probe_geo_distance",
    "probe_ips",
    # dashboard_network
    "_parse_ping_stats",
    "probe_direct",
    "probe_exit_ip",
    "probe_ping",
    "probe_route_to_vps",
    "probe_services",
    "probe_tunnel",
    "probe_vpn",
    # dashboard_nodes
    "_nodes_cache",
    "_parse_throughput_output",
    "probe_dns",
    "probe_nodes",
    "probe_nodes_snapshot",
    # dashboard_traffic
    "probe_traffic_guard",
    # dashboard_hotroutes
    "probe_hot_routes",
    # dashboard_isolate
    "probe_isolate",
    # node_selector
    "node_selector",
    # sys_probe
    "sys_probe",
    # traffic_shape
    "traffic_shape",
    # isolate_firewall
    "isolate_firewall",
    # lock_hierarchy
    "lock_hierarchy",
    # git_proxy
    "git_proxy",
    # claude_proxy
    "claude_proxy",
    # health
    "health",
    # privoxy_system
    "privoxy_system",
    # local_state
    "local_state",
    # dashboard_app
    "PORT",
    "STATUS_CACHE_TTL_SEC",
    "STATUS_PROBE_BUDGET_SEC",
    "INDEX_HTML",
    "app",
    "_ALLOWED_HOSTNAMES",
    "_GUARD_HOSTS",
    "_MUTATION_LOCK",
    "_cache",
    "_lock",
    "_allowed_origins",
    "_csrf_origin_guard",
    "_host_rebinding_guard",
    "_is_allowed_host",
    "_is_cross_origin_post",
    "_mutation_lock_guard",
    "_mutation_lock_release",
    "_run_status_probe_set",
    "gather_status",
    "index",
    "main",
    # dashboard_routes (все @app.* роуты и приватные хелперы)
    "_THROTTLE_PUBLIC_REDACTIONS",
    "_active_host_route_ip",
    "_guard_payload",
    "_host_route_action",
    "_isolate_result",
    "_persist_active_or_cleanup",
    "_persist_cleanup_lease",
    "_public_active_throttle",
    "_public_isolate",
    "_public_throttle",
    "_redact_throttle_text",
    "_route_result",
    "_sudo_route_ip",
    "_throttle_apply",
    "_throttle_clear",
    "_throttle_payload",
    "_throttle_result",
    "api_channel",
    "api_channel_empty",
    "api_claude_proxy_disable",
    "api_claude_proxy_enable",
    "api_claude_proxy_get",
    "api_git_proxy_disable",
    "api_git_proxy_enable",
    "api_git_proxy_get",
    "api_proxy_apply",
    "api_proxy_overview",
    "api_guard",
    "api_guard_get",
    "api_guard_throttle",
    "api_isolate_disable",
    "api_isolate_enable",
    "api_isolate_get",
    "api_isolate_refresh",
    "api_node_select",
    "api_nodes_ranking",
    "api_probe_nodes",
    "api_route",
    "api_route_host",
    "api_service",
    "api_status",
    "health_endpoint",
    "service_control",
    "sudo_route",
]

# Активный узел нельзя замораживать на import: #8 меняет srouter.local.json в рантайме.
# Эти имена оставлены только для совместимости старых импорт-тестов; рабочий код ниже
# каждый раз вызывает _active_route_ip().
ACTIVE_ENDPOINT = ""
VPS_IP = ""


if __name__ == "__main__":
    raise SystemExit(main())
