"""Regress-гвард (issue #227, эпик #158/#107): public API dashboard.py не меняется при экстракции.

dashboard.py разбивается на dashboard_app.py (Flask app-фабрика/статус/guard'ы) +
dashboard_routes.py (роуты) + общие хелперы остаются в dashboard_common.py. Это ЧИСТАЯ
экстракция (канон no-hidden-magic-follow-canon), не редизайн: любой атрибут/роут,
существовавший на dashboard ДО рефакторинга, обязан существовать и ПОСЛЕ — тесты и
внешние модули (srouter.py, install_lib.py, node_selector.py, tests/test_node_selector.py
и др.) обращаются к ним как dashboard.<name>.

Списки ниже — снимок, сделанный ДО экстракции (baseline). Если появится намеренное
изменение public API — обнови оба списка ЯВНО и опиши причину в PR/коммите.
"""
import dashboard

# Явные атрибуты модуля dashboard (функции/роуты/приватные хелперы/структуры данных),
# на которые полагаются тесты и другие модули через `dashboard.<name>`. Сюда НЕ включены
# сторонние модули (threading, re, Flask, health, node_selector...) и re-экспортированные
# из dashboard_common/dashboard_connectivity/... имена — их проверяет отдельный
# __all__-контракт (issue #157) и импорт-тесты соответствующих модулей.
EXPECTED_FUNCTIONS_AND_ROUTES = {
    "_active_host_route_ip",
    "_active_route_context",
    "_active_route_ip",
    "_allowed_origins",
    "_csrf_origin_guard",
    "_guard_payload",
    "_host_rebinding_guard",
    "_host_route_action",
    "_ip_literal",
    "_is_allowed_host",
    "_is_cross_origin_post",
    "_isolate_result",
    "_known_service_name",
    "_mutation_lock_guard",
    "_mutation_lock_release",
    "_parse_network_services",
    "_parse_ping_stats",
    "_parse_throughput_output",
    "_persist_active_or_cleanup",
    "_persist_cleanup_lease",
    "_probe_direct_reachability",
    "_public_active_throttle",
    "_public_isolate",
    "_public_throttle",
    "_redact_throttle_text",
    "_route_result",
    "_run_status_probe_set",
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
    "api_metrics_tunnel",
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
    "gather_status",
    "health_endpoint",
    "index",
    "main",
    "probe_connectivity",
    "probe_direct",
    "probe_dns",
    "probe_exit_ip",
    "probe_exit_ips_per_iface",
    "probe_geo_distance",
    "probe_hot_routes",
    "probe_ifaces",
    "probe_ips",
    "probe_isolate",
    "probe_nodes",
    "probe_nodes_snapshot",
    "probe_ping",
    "probe_route_to_vps",
    "probe_services",
    "probe_traffic_guard",
    "probe_tunnel",
    "probe_vpn",
    "service_control",
    "sudo_route",
    "switch_channel",
}

# Модули/объекты, зовущиеся напрямую как dashboard.<name> в тестах через monkeypatch
# (dashboard.sys_probe, dashboard.local_state, ...) или как рантайм-состояние
# (dashboard._cache, dashboard._nodes_cache, dashboard._MUTATION_LOCK, dashboard.app).
EXPECTED_MODULE_AND_STATE_ATTRS = {
    "app",
    "claude_proxy",
    "git_proxy",
    "health",
    "isolate_firewall",
    "local_state",
    "lock_hierarchy",
    "node_selector",
    "privoxy_system",
    "sys_probe",
    "traffic_shape",
    "_cache",
    "_nodes_cache",
    "_lock",
    "_MUTATION_LOCK",
    "_ALLOWED_HOSTNAMES",
    "_GUARD_HOSTS",
    "_THROTTLE_PUBLIC_REDACTIONS",
    # legacy-совместимость (см. dashboard.py: "оставлены только для старых импорт-тестов")
    "ACTIVE_ENDPOINT",
    "VPS_IP",
}

# Константы, реэкспортированные из dashboard_common для обратной совместимости
# (уже задекларированы в dashboard.__all__, issue #157) — проверяем и их тоже.
EXPECTED_CONSTANTS = {
    "BREW",
    "CURL",
    "ROUTE",
    "IFCONFIG",
    "OSASCRIPT",
    "PING",
    "NETWORKSETUP",
    "GATEWAY",
    "CHANNEL_TARGETS",
    "PORT",
    "STATUS_CACHE_TTL_SEC",
    "STATUS_PROBE_BUDGET_SEC",
}

# Flask-роуты: (rule, methods без HEAD/OPTIONS). Полный снимок app.url_map ДО экстракции.
EXPECTED_ROUTES = {
    ("/", "GET"),
    ("/api/channel", "POST"),
    ("/api/channel/", "POST"),
    ("/api/channel/<target>", "POST"),
    ("/api/claude-proxy", "GET"),
    ("/api/claude-proxy/disable", "POST"),
    ("/api/claude-proxy/enable", "POST"),
    ("/api/git-proxy", "GET"),
    ("/api/metrics/tunnel", "GET"),
    ("/api/proxy/overview", "GET"),
    ("/api/proxy/<action>", "POST"),
    ("/api/git-proxy/disable", "POST"),
    ("/api/git-proxy/enable", "POST"),
    ("/api/guard", "GET"),
    ("/api/guard", "POST"),
    ("/api/guard/throttle", "POST"),
    ("/api/isolate", "GET"),
    ("/api/isolate/disable", "POST"),
    ("/api/isolate/enable", "POST"),
    ("/api/isolate/refresh", "POST"),
    ("/api/node/select/<name>", "POST"),
    ("/api/nodes/ranking", "GET"),
    ("/api/probe/nodes", "GET"),
    ("/api/route/<action>", "POST"),
    ("/api/route/host", "POST"),
    ("/api/service/<name>/<action>", "POST"),
    ("/api/status", "GET"),
    ("/health", "GET"),
    ("/static/<path:filename>", "GET"),
}


def test_dashboard_module_exposes_expected_functions_and_routes():
    """Все функции/роут-хендлеры, существовавшие на dashboard ДО экстракции, остаются доступны."""
    missing = sorted(name for name in EXPECTED_FUNCTIONS_AND_ROUTES if not hasattr(dashboard, name))
    assert not missing, f"dashboard.<name> пропали после рефакторинга: {missing}"


def test_dashboard_module_exposes_expected_modules_and_state():
    """Рантайм-состояние и импортированные модули, на которые monkeypatch'ат тесты, доступны."""
    missing = sorted(name for name in EXPECTED_MODULE_AND_STATE_ATTRS if not hasattr(dashboard, name))
    assert not missing, f"dashboard.<name> (модуль/состояние) пропали после рефакторинга: {missing}"


def test_dashboard_module_exposes_expected_constants():
    missing = sorted(name for name in EXPECTED_CONSTANTS if not hasattr(dashboard, name))
    assert not missing, f"dashboard.<константа> пропала после рефакторинга: {missing}"


def test_dashboard_flask_routes_unchanged():
    """app.url_map (rule + non-HEAD/OPTIONS methods) идентичен снимку до экстракции."""
    actual = {
        (str(rule), method)
        for rule in dashboard.app.url_map.iter_rules()
        for method in sorted((rule.methods or set()) - {"HEAD", "OPTIONS"})
    }
    missing = EXPECTED_ROUTES - actual
    extra = actual - EXPECTED_ROUTES
    assert not missing, f"роуты пропали после рефакторинга: {sorted(missing)}"
    assert not extra, f"неожиданные новые роуты (обнови EXPECTED_ROUTES, если намеренно): {sorted(extra)}"


def test_dashboard_app_is_flask_instance():
    """dashboard.app остаётся тем же Flask-приложением, к которому привязаны все роуты выше."""
    from flask import Flask

    assert isinstance(dashboard.app, Flask)
