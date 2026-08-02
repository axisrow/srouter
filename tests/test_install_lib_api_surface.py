"""Regress-гвард (issue #229): install_lib.py разбивается на install_plist.py + install_config.py +
install_cleanup.py. install_lib остаётся фасадом (реэкспортирует всё) — экстракция, не редизайн (канон
no-hidden-magic-follow-canon). Этот тест фиксирует public/private API ДО экстракции: набор имён,
сигнатуры функций, значения ключевых констант. Любой дрейф после разбиения — регрессия.
"""
import inspect

import install_lib

# Снимок набора имён модуля (без dunder и без сторонних импортируемых модулей типа os/json/Path —
# они естественно останутся доступны через фасад после `from . import *`-style ре-экспорта, но explicit
# whitelist ниже проверяет именно СВОИ имена: функции/классы/константы, определённые в install_lib).
EXPECTED_OWN_NAMES = {
    # константы
    "MARKER", "TEXT_MARKER", "ROOT", "PRIVOXY_KNOWN_DIRECTIVES",
    "BREW", "CURL", "ROUTE", "LSOF", "NETWORKSETUP", "SUDO", "LAUNCHCTL",
    "COMPONENTS", "CHOICES", "PORTS",
    "LAUNCHAGENT_LABEL", "LAUNCHAGENT_FILE", "LAUNCHAGENT_MARKER", "UNINSTALL_CATEGORIES",
    "_BOOTOUT_SETTLE_MAX_WAIT", "_BOOTOUT_POLL_INTERVAL",
    "_BOOTSTRAP_MAX_RETRIES", "_BOOTSTRAP_RETRY_DELAY",
    "_PORT_SETTLE_POLL_INTERVAL", "_PORT_SETTLE_MAX_WAIT", "_PORT_UP_MAX_WAIT",
    "_LAUNCHCTL_SERVICE_NOT_FOUND",
    "RECLAIMABLE_RESOLVES",
    "_PRIVOXY_PORT", "_XRAY_SOCKS_PORT",
    # классы
    "InstallEnv",
    # функции — plist/launchd
    "_has_launchagent_marker", "_launchd_domain", "_launchagent_template_path",
    "_render_launchagent_plist", "_write_launchagent", "_launchd_is_loaded", "_launchd_unload",
    "_launchd_reload", "_install_launchagent", "_render_generic_launchagent",
    "_install_generic_launchagent", "_unload_launchagent", "_launchagent_uninstall_item",
    # функции — config/discovery/apply
    "_now", "_read_head", "_json_has_marker", "_has_marker",
    "load_known_markers", "populate_known_markers",
    "_port_owner", "_reclaimable_resolves_all_conflicts", "_inspect_component",
    "_discover_network", "_discover_probe_readiness", "_homebrew_available",
    "_privoxy_protected_for_env", "build_plan", "format_plan",
    "_backup", "_write_text_atomic", "_write_component_config", "_traffic_guard_preflight_error",
    "_ensure_package", "_restart_component", "_apply_dns", "_management_for",
    "_write_state_after_apply", "apply_install",
    "_is_managed_entry", "_is_adopted_entry", "_is_restored_entry", "_provenance_of",
    "_is_created_entry",
    # функции — cleanup/uninstall
    "_component_uninstall_item", "build_uninstall_plan", "format_uninstall_plan",
    "_restore_backup", "_delete_component_config", "_mark_component_restored",
    "_mark_component_removed", "_stop_service", "_restore_dns", "apply_uninstall",
    "_prompt_bool", "_collect_uninstall_confirmations",
    # CLI entrypoint
    "main",
}

EXPECTED_CONSTANTS = {
    "MARKER": "srouter-managed",
    "TEXT_MARKER": "srouter-managed-config-v1",
    "BREW": "/opt/homebrew/bin/brew",
    "CURL": "/usr/bin/curl",
    "ROUTE": "/sbin/route",
    "LSOF": "/usr/sbin/lsof",
    "NETWORKSETUP": "/usr/sbin/networksetup",
    "SUDO": "/usr/bin/sudo",
    "LAUNCHCTL": "/bin/launchctl",
    "CHOICES": ("adopt", "overwrite", "skip"),
    "LAUNCHAGENT_LABEL": "com.srouter.dashboard",
    "LAUNCHAGENT_FILE": "com.srouter.dashboard.plist",
    "LAUNCHAGENT_MARKER": "srouter-managed-launchagent-v1",
    "UNINSTALL_CATEGORIES": ("configs", "services", "dns", "launchagent"),
    "_LAUNCHCTL_SERVICE_NOT_FOUND": 113,
    "RECLAIMABLE_RESOLVES": frozenset({"foreign_config", "foreign_port"}),
}


def test_all_expected_names_present():
    missing = EXPECTED_OWN_NAMES - set(dir(install_lib))
    assert not missing, f"install_lib потерял имена (регрессия public API): {sorted(missing)}"


def test_no_unexpected_own_names_removed_by_accident():
    # Позитивная проверка: каждое ожидаемое имя реально резолвится (не только числится в dir()).
    for name in EXPECTED_OWN_NAMES:
        assert hasattr(install_lib, name), f"install_lib.{name} недоступен"


def test_constant_values_unchanged():
    for name, expected in EXPECTED_CONSTANTS.items():
        actual = getattr(install_lib, name)
        assert actual == expected, f"install_lib.{name} изменился: {actual!r} != {expected!r}"


def test_ports_dict_shape_unchanged():
    ports = install_lib.PORTS
    assert set(ports) == {"xray", "privoxy", "dnsmasq"}
    assert ports["dnsmasq"] == ("udp", 53)
    assert ports["xray"][0] == "tcp"
    assert ports["privoxy"][0] == "tcp"


def test_privoxy_known_directives_is_frozenset_and_nonempty():
    assert isinstance(install_lib.PRIVOXY_KNOWN_DIRECTIVES, frozenset)
    assert "forward-socks5" in install_lib.PRIVOXY_KNOWN_DIRECTIVES


def test_install_env_dataclass_fields_unchanged():
    fields = {f.name for f in install_lib.InstallEnv.__dataclass_fields__.values()}
    assert fields == {
        "root", "prefix", "state_path", "launchagent_dir",
        "python_bin", "log_out", "log_err", "now",
    }


# Сигнатуры публичных (не namemangled) функций — единственный контракт, на который опираются
# потребители (srouter.py, health.py, privileged_ops.py, тесты). Экстракция обязана сохранить их
# байт-в-байт (число параметров, имена, keyword-only маркеры, дефолты по значению).
EXPECTED_SIGNATURES = {
    "load_known_markers": "(state_path, surface, current_markers)",
    "populate_known_markers": "(state_path, surface, markers)",
    "build_plan": "(env=None, runner=<function run at " ,  # частичное совпадение (см. ниже)
    "apply_install": "(env=None, *, confirm=False, choices=None, runner=<function run at ",
    "apply_uninstall": "(env=None, *, confirmations=None, runner=<function run at ",
    "build_uninstall_plan": "(env=None, runner=<function run at ",
    "format_plan": "(plan)",
    "format_uninstall_plan": "(plan)",
    # issue #269: main получил runner=run — та же DI-точка, что у build_plan/apply_install/
    # apply_uninstall/build_uninstall_plan (см. их записи выше), main её теперь прокидывает,
    # а не обрывает цепочку на реальный subprocess.
    "main": "(argv=None, *, runner=<function run at ",
}


def test_public_function_signatures_unchanged():
    for name, expected_prefix in EXPECTED_SIGNATURES.items():
        func = getattr(install_lib, name)
        sig = str(inspect.signature(func))
        assert sig.startswith(expected_prefix), (
            f"install_lib.{name} сигнатура изменилась: {sig!r} (ожидался префикс {expected_prefix!r})"
        )


def test_apply_install_keyword_only_params_unchanged():
    sig = inspect.signature(install_lib.apply_install)
    params = sig.parameters
    assert list(params) == [
        "env", "confirm", "choices", "runner", "port_checker",
        "install_launchagent", "force_endpoint_overwrite",
    ]
    assert params["confirm"].kind == inspect.Parameter.KEYWORD_ONLY
    assert params["install_launchagent"].default is True
    assert params["force_endpoint_overwrite"].default is False


def test_restart_component_keyword_only_port_checker():
    sig = inspect.signature(install_lib._restart_component)
    assert list(sig.parameters) == ["name", "runner", "port_checker"]
    assert sig.parameters["port_checker"].kind == inspect.Parameter.KEYWORD_ONLY


def test_module_still_runnable_as_cli_entrypoint():
    # main() существует и принимает argv — srouter.py/install.sh не зовут install_lib напрямую как
    # скрипт в тестах, но `if __name__ == "__main__": raise SystemExit(main())` — контракт CLI.
    assert callable(install_lib.main)
    assert inspect.signature(install_lib.main).parameters["argv"].default is None
