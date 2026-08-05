#!/usr/bin/env python3
"""Тестируемое ядро install.sh: plan/apply, discovery и conflict-detection.

Фасад-модуль (issue #229): реализация разнесена по install_plist.py (LaunchAgent plist-генерация и
launchd-управление), install_config.py (InstallEnv, discovery, build_plan/apply_install) и
install_cleanup.py (build_uninstall_plan/apply_uninstall, rollback). install_lib реэкспортирует ВСЁ
публичное и приватное API этих модулей без изменений — потребители (srouter.py, health.py,
privileged_ops.py, тесты) продолжают писать `install_lib.X` / `from install_lib import X`, как раньше.
Экстракция, не редизайн (канон no-hidden-magic-follow-canon): поведение и сигнатуры идентичны.
"""
from __future__ import annotations

import os  # noqa: F401  (реэкспорт — install_lib.os.getuid() используется в тестах)

from sys_probe import parse_brew_services as _parse_brew_services  # noqa: F401  (реэкспорт)
from sys_probe import port_open, run  # noqa: F401  (реэкспорт — install_lib.run/.port_open в тестах)

from install_plist import (  # noqa: F401  (реэкспорт — фасад install_lib)
    LAUNCHCTL,
    LAUNCHAGENT_LABEL,
    LAUNCHAGENT_FILE,
    LAUNCHAGENT_MARKER,
    _BOOTOUT_SETTLE_MAX_WAIT,
    _BOOTOUT_POLL_INTERVAL,
    _BOOTSTRAP_MAX_RETRIES,
    _BOOTSTRAP_RETRY_DELAY,
    _LAUNCHCTL_SERVICE_NOT_FOUND,
    _has_launchagent_marker,
    _launchd_domain,
    _launchagent_template_path,
    _render_launchagent_plist,
    _write_launchagent,
    _write_text_atomic,
    _launchd_is_loaded,
    _launchd_unload,
    _launchd_reload,
    _install_launchagent,
    _render_generic_launchagent,
    _install_generic_launchagent,
    _unload_launchagent,
)
from install_config import (  # noqa: F401  (реэкспорт — фасад install_lib)
    MARKER,
    TEXT_MARKER,
    ROOT,
    PRIVOXY_KNOWN_DIRECTIVES,
    BREW,
    CURL,
    ROUTE,
    LSOF,
    NETWORKSETUP,
    SUDO,
    COMPONENTS,
    CHOICES,
    PORTS,
    _PRIVOXY_PORT,
    _XRAY_SOCKS_PORT,
    _PORT_SETTLE_POLL_INTERVAL,
    _PORT_SETTLE_MAX_WAIT,
    _PORT_UP_MAX_WAIT,
    RECLAIMABLE_RESOLVES,
    InstallEnv,
    _now,
    _read_head,
    _json_has_marker,
    _has_marker,
    load_known_markers,
    populate_known_markers,
    _port_owner,
    _reclaimable_resolves_all_conflicts,
    _inspect_component,
    _discover_network,
    _discover_probe_readiness,
    _homebrew_available,
    _privoxy_protected_for_env,
    build_plan,
    format_plan,
    _backup,
    discover_backups,
    _write_component_config,
    _traffic_guard_preflight_error,
    _ensure_package,
    _restart_component,
    _apply_dns,
    _management_for,
    _write_state_after_apply,
    apply_install,
    _is_managed_entry,
    _is_adopted_entry,
    _is_restored_entry,
    _provenance_of,
    _is_created_entry,
    _resolve_backup,
    component_facts,
)
from install_cleanup import (  # noqa: F401  (реэкспорт — фасад install_lib)
    UNINSTALL_CATEGORIES,
    _component_uninstall_item,
    _launchagent_uninstall_item,
    build_uninstall_plan,
    format_uninstall_plan,
    _restore_backup,
    _delete_component_config,
    _mark_component_restored,
    _mark_component_removed,
    _stop_service,
    _restore_dns,
    apply_uninstall,
    _prompt_bool,
    _collect_uninstall_confirmations,
    main,
)


if __name__ == "__main__":
    raise SystemExit(main())
