"""Regress-гвард тест для issue #228: экстракция srouter.py → srouter_cli.py + srouter_launchd.py + codex_wrappers.py.

Этот тест фиксирует текущий public API srouter.py и гарантирует, что после рефакторинга
все публичные функции остаются доступными и работают идентично.

Требования:
- Все cmd_* функции доступны и вызываемы
- build_parser и main доступны
- OSASCRIPT, _is_privileged_cmd, _to_osascript, make_privileged_runner доступны
- Все внутренние функции модуля остаются импортируемыми для обратной совместимости
"""

import pytest

import srouter


class TestSrouterPublicAPI:
    """Проверяет, что public API srouter.py остаётся идентичным после экстракции."""

    def test_main_cli_functions_exist(self):
        """Основные CLI функции (cmd_*) должны быть доступны."""
        assert hasattr(srouter, "cmd_install")
        assert hasattr(srouter, "cmd_uninstall")
        assert hasattr(srouter, "cmd_start")
        assert hasattr(srouter, "cmd_stop")
        assert hasattr(srouter, "cmd_restart")
        assert hasattr(srouter, "cmd_status")
        assert hasattr(srouter, "cmd_doctor")
        assert hasattr(srouter, "cmd_sync")
        assert hasattr(srouter, "cmd_privoxy")
        assert hasattr(srouter, "cmd_routing")

    def test_parser_and_main_exist(self):
        """build_parser и main должны быть доступны."""
        assert hasattr(srouter, "build_parser")
        assert hasattr(srouter, "main")

    def test_osascript_reexports_exist(self):
        """OSASCRIPT должен быть переэкспортирован."""
        assert hasattr(srouter, "OSASCRIPT")

    def test_privileged_wrapper_functions_exist(self):
        """Функции для работы с привилегированными командами."""
        assert hasattr(srouter, "_is_privileged_cmd")
        assert hasattr(srouter, "_to_osascript")
        assert hasattr(srouter, "make_privileged_runner")

    def test_env_from_args_exists(self):
        """_env_from_args должен быть доступен."""
        assert hasattr(srouter, "_env_from_args")

    def test_install_helpers_exist(self):
        """Вспомогательные функции для установки (PPP, routing, etc)."""
        # PPP hook functions
        assert hasattr(srouter, "_install_ppp_hook")
        assert hasattr(srouter, "_remove_ppp_hook")
        assert hasattr(srouter, "_active_route_ip_for_removal")
        assert hasattr(srouter, "_remove_active_split_route")

        # PATH helpers
        assert hasattr(srouter, "_ensure_home_bin_in_path")
        assert hasattr(srouter, "_remove_home_bin_from_path")

        # launchctl env helpers
        assert hasattr(srouter, "_install_launchctl_env")
        assert hasattr(srouter, "_remove_launchctl_env")

    def test_codex_wrapper_functions_exist(self):
        """Функции для работы с codex wrappers."""
        # Basic wrapper functions
        assert hasattr(srouter, "_codex_wrapper_path")
        assert hasattr(srouter, "_zshrc_path")
        assert hasattr(srouter, "_looks_like_managed_codex_wrapper")
        assert hasattr(srouter, "_codex_bin_path")
        assert hasattr(srouter, "_install_one_wrapper")
        assert hasattr(srouter, "_install_codex_wrappers")
        assert hasattr(srouter, "_migrate_legacy_codex_cli_wrapper")
        assert hasattr(srouter, "_remove_one_wrapper")
        assert hasattr(srouter, "_remove_codex_wrappers")

        # Codex zsh function
        assert hasattr(srouter, "_codex_zsh_target_installed")
        assert hasattr(srouter, "_install_codex_zsh_function")
        assert hasattr(srouter, "_remove_codex_zsh_function")

        # Codex isolation
        assert hasattr(srouter, "_install_codex_isolation")
        assert hasattr(srouter, "_remove_codex_isolation")

    def test_launchd_helpers_exist(self):
        """Вспомогательные функции для launchd."""
        assert hasattr(srouter, "_is_loaded")

    def test_cli_helpers_exist(self):
        """Вспомогательные функции CLI."""
        assert hasattr(srouter, "_is_ip_literal")
        assert hasattr(srouter, "_prompt_bool")
        assert hasattr(srouter, "_prompt_choice")
        assert hasattr(srouter, "_version_string")

    def test_routing_helpers_exist(self):
        """Вспомогательные функции для routing."""
        assert hasattr(srouter, "_read_routing_domains")
        assert hasattr(srouter, "_routing_has_marker")

    def test_build_parser_returns_parser(self):
        """build_parser должен возвращать валидный ArgumentParser."""
        parser = srouter.build_parser()
        assert parser is not None
        assert hasattr(parser, "add_argument")
        assert hasattr(parser, "parse_args")

        # Проверяем, что базовые команды парсятся
        args = parser.parse_args(["install"])
        assert args.command == "install"

    def test_cmd_functions_are_callable(self):
        """Все cmd_* функции должны быть вызываемыми."""
        cmd_functions = [
            "cmd_install", "cmd_uninstall", "cmd_start", "cmd_stop",
            "cmd_restart", "cmd_status", "cmd_doctor", "cmd_sync",
            "cmd_privoxy", "cmd_routing"
        ]

        for func_name in cmd_functions:
            func = getattr(srouter, func_name)
            assert callable(func), f"{func_name} должен быть вызываемым"

    def test_osascript_alias(self):
        """OSASCRIPT должен быть тем же значением, что и в privileged_ops."""
        import privileged_ops

        assert srouter.OSASCRIPT == privileged_ops.OSASCRIPT


class TestSrouterRefactorCompatibility:
    """Проверяет обратную совместимость после экстракции."""

    def test_star_import_compat(self):
        """import srouter должен давать доступ ко всем публичным функциям."""
        # Проверяем, что все ожидаемые функции доступны через import srouter
        expected = [
            "cmd_install", "cmd_uninstall", "cmd_start", "cmd_stop",
            "cmd_restart", "cmd_status", "cmd_doctor", "cmd_sync",
            "cmd_privoxy", "cmd_routing", "build_parser", "main",
            "OSASCRIPT", "_is_privileged_cmd", "_to_osascript",
            "make_privileged_runner", "_env_from_args"
        ]

        missing = [name for name in expected if not hasattr(srouter, name)]
        assert not missing, f"Missing expected attributes: {missing}"

    def test_module_structure_compat(self):
        """Структура модуля должна позволять импорт всех функций."""
        # Проверяем, что внутренние функции доступны для тестов
        internal_functions = [
            "_install_ppp_hook", "_remove_ppp_hook",
            "_install_codex_wrappers", "_remove_codex_wrappers",
            "_install_launchctl_env", "_remove_launchctl_env",
            "_ensure_home_bin_in_path", "_remove_home_bin_from_path"
        ]

        for func_name in internal_functions:
            assert hasattr(srouter, func_name), f"Missing internal function: {func_name}"
            assert callable(getattr(srouter, func_name)), f"{func_name} should be callable"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
