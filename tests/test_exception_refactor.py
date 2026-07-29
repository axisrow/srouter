#!/usr/bin/env python3
"""
Regress-гвард тесты для рефакторинга except Exception (issue #161).

Проверяют что рефакторинг не изменил поведение в critical path:
- Error handling продолжает работать корректно
- Specific exceptions не ломают fallback логику
- CLI/API guards продолжают catching всё что нужно
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch


class TestLocalStateExceptions:
    """Тесты для local_state.py exception handling."""

    def test_load_state_json_error_fallback(self):
        """load_state должен обрабатывать JSON ошибки."""
        import local_state

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "corrupt.json"
            state_path.write_text("invalid json {", encoding='utf-8')

            result = local_state.load_state(path=str(state_path))
            assert result is not None, "load_state должен возвращать fallback при JSON error"


class TestProxyConfigExceptions:
    """Тесты для proxy конфигурационных файлов."""

    def test_vscode_proxy_file_error(self):
        """vscode_proxy должен обрабатывать файловые ошибки."""
        import vscode_proxy
        from pathlib import Path

        # При отсутствии файла должен возвращать fallback
        result = vscode_proxy._load(Path("/nonexistent/settings.json"))
        assert result is None or isinstance(result, dict), "Должен возвращать fallback при FileNotFoundError"


class TestCriticalPathBehavior:
    """Тесты что critical path поведение не изменилось."""

    def test_install_command_error_handling(self):
        """install команда должна обрабатывать ошибки корректно."""
        from srouter import cmd_install
        from argparse import Namespace

        args = Namespace(
            state=None,
            prefix=None,
            python=None,
            launchagents_dir=None,
            yes=True
        )

        # Mock для ошибки в build_plan
        with patch('srouter.build_plan', side_effect=OSError("Test error")):
            result = cmd_install(args)
            assert result == 2, "install должен возвращать rc=2 при discovery error"




class TestDirectFirstExceptions:
    """Тесты для direct_first.py exception handling."""

    def test_candidate_domains_os_error_fallback(self):
        """OS error в candidate_domains возвращает fallback на BUILTIN domains."""
        import direct_first

        with patch('direct_first.local_state.load_state', side_effect=OSError("State file not found")):
            result = direct_first.candidate_domains("/tmp/test.json")
            assert "z.ai" in result, "BUILTIN domains должны включаться при OSError"

    def test_candidate_domains_json_error_fallback(self):
        """JSON parsing error в candidate_domains возвращает fallback."""
        import direct_first

        with patch('direct_first.local_state.load_state', side_effect=ValueError("Invalid JSON")):
            result = direct_first.candidate_domains("/tmp/test.json")
            assert "z.ai" in result, "BUILTIN domains должны включаться при ValueError"

    def test_direct_reachable_probe_error_fallback(self):
        """Probe error в direct_reachable возвращает (False, 'probe-error')."""
        import direct_first

        # Mock возвращающий ошибку
        mock_result = {"reachable": False, "kind": "test-error"}
        with patch('direct_first.sys_probe.direct_probe', return_value=mock_result):
            result = direct_first.direct_reachable("example.com")
            assert result == (False, "test-error"), "Должен возвращать результат из probe"

    def test_no_proxy_string_fallback_on_error(self):
        """no_proxy_string возвращает BUILTIN_FALLBACK_NO_PROXY при любой ошибке."""
        import direct_first

        with patch('direct_first.detect', side_effect=KeyError("Missing key")):
            result = direct_first.no_proxy_string(path="/tmp/test.json")
            assert "localhost,127.0.0.1,::1,z.ai,.z.ai" == result, "Должен возвращать BUILTIN_FALLBACK_NO_PROXY"


class TestTrafficShapeExceptionsBasic:
    """Базовые тесты для traffic_shape.py без импорта модуля."""

    def test_socket_imports_available(self):
        """Модуль socket должен быть доступен."""
        import socket
        assert hasattr(socket, 'gaierror'), "socket.gaierror должен быть доступен"
        assert hasattr(socket, 'timeout'), "socket.timeout должен быть доступен"

# class TestTrafficShapeExceptions:
#     """Тесты для traffic_shape.py exception handling."""
#
#     def test_resolve_domain_ip_dns_failure(self):
#         """DNS resolution failure в resolve_domain_ip возвращает пустую строку."""
#         import traffic_shape
#         import socket
#
#         # Mock для DNS failure
#         with patch('traffic_shape.socket.gethostbyname', side_effect=socket.gaierror("DNS lookup failed")):
#             result = traffic_shape.resolve_domain_ip("example.com")
#             assert result == "", "Должен возвращать пустую строку при DNS failure"
#
#     def test_apply_throttle_gaierror_fallback(self):
#         """socket.gaierror в resolve_domain_ip обрабатывается корректно."""
#         import traffic_shape
#         import socket
#
#         with patch('traffic_shape.socket.gethostbyname', side_effect=socket.gaierror("DNS lookup failed")):
#             result = traffic_shape.resolve_domain_ip("example.com")
#             assert result == "", "Должен возвращать пустую строку при gaierror"
#
#     def test_deep_exception_defense_in_apply(self):
#         """Глубокая защита в apply_throttle не бросает исключения."""
#         import traffic_shape
#
#         # Вызов с невалидными параметрами должен возвращать error dict, а не бросать
#         result = traffic_shape.apply_throttle("", "invalid")
#         assert isinstance(result, dict), "Должен возвращать dict при любой ошибке"
#         assert "ok" in result, "Result должен содержать ключ 'ok'"
#         assert result["ok"] is False, "ok должен быть False при невалидных параметрах"
#
#     def test_deep_exception_defense_in_clear(self):
#         """Глубокая защита в clear_throttle не бросает исключения."""
#         import traffic_shape
#
#         # Вызов с любым токеном (даже None) не должен бросать
#         result = traffic_shape.clear_throttle(None)
#         assert isinstance(result, dict), "Должен возвращать dict при любой ошибке"
#         assert "ok" in result, "Result должен содержать ключ 'ok'"

class TestTrafficShapeExceptions:
    """Тесты для traffic_shape.py exception handling."""

    def test_resolve_domain_ip_dns_failure(self):
        """DNS resolution failure в resolve_domain_ip возвращает пустую строку."""
        import traffic_shape
        import socket

        # Mock для DNS failure
        with patch('traffic_shape.socket.gethostbyname', side_effect=socket.gaierror("DNS lookup failed")):
            result = traffic_shape.resolve_domain_ip("example.com")
            assert result == "", "Должен возвращать пустую строку при DNS failure"

    def test_apply_throttle_gaierror_fallback(self):
        """socket.gaierror в resolve_domain_ip обрабатывается корректно."""
        import traffic_shape
        import socket

        with patch('traffic_shape.socket.gethostbyname', side_effect=socket.gaierror("DNS lookup failed")):
            result = traffic_shape.resolve_domain_ip("example.com")
            assert result == "", "Должен возвращать пустую строку при gaierror"

    def test_deep_exception_defense_in_apply(self):
        """Глубокая защита в apply_throttle не бросает исключения."""
        import traffic_shape

        # Вызов с невалидными параметрами должен возвращать error dict, а не бросать
        result = traffic_shape.apply_throttle("", "invalid")
        assert isinstance(result, dict), "Должен возвращать dict при любой ошибке"
        assert "ok" in result, "Result должен содержать ключ 'ok'"
        assert result["ok"] is False, "ok должен быть False при невалидных параметрах"

    def test_deep_exception_defense_in_clear(self):
        """Глубокая защита в clear_throttle не бросает исключения."""
        import traffic_shape

        # Вызов с любым токеном (даже None) не должен бросать
        result = traffic_shape.clear_throttle(None)
        assert isinstance(result, dict), "Должен возвращать dict при любой ошибке"
        assert "ok" in result, "Result должен содержать ключ 'ok'"


class TestVSCodeProxyExceptions:
    """Тесты для vscode_proxy.py exception handling."""

    def test_load_file_not_found_fallback(self):
        """_load возвращает None при отсутствии файла."""
        import vscode_proxy

        result = vscode_proxy._load(Path("/nonexistent/settings.json"))
        assert result is None, "Должен возвращать None при отсутствии файла"

    def test_load_json_decode_error_fallback(self):
        """_load возвращает None при malformed JSON."""
        import vscode_proxy

        with tempfile.TemporaryDirectory() as tmpdir:
            invalid_path = Path(tmpdir) / "invalid.json"
            invalid_path.write_text("{invalid json}", encoding='utf-8')

            result = vscode_proxy._load(invalid_path)
            assert result is None, "Должен возвращать None при JSON decode error"

    def test_save_os_error_handling(self):
        """_save обрабатывает OS ошибки и возвращает structured error."""
        import vscode_proxy

        # Попытка записи в readonly путь
        result = vscode_proxy._save(Path("/root/settings.json"), {"test": "data"})
        assert isinstance(result, dict), "Должен возвращать dict"
        assert result.get("ok") is False, "ok должен быть False при OS error"
        assert "err" in result, "Result должен содержать ключ 'err'"

    def test_enable_does_not_create_nonexistent_file(self):
        """enable не создаёт файл, если его не было."""
        import vscode_proxy

        with tempfile.TemporaryDirectory() as tmpdir:
            # Указываем на несуществующий файл в tmpdir
            test_path = Path(tmpdir) / "Code" / "User" / "settings.json"

            with patch('vscode_proxy.SETTINGS_PATHS', [test_path]):
                result = vscode_proxy.enable()
                assert result.get("ok") is True, "enable должен succeed без файла"
                assert not test_path.exists(), "Файл не должен быть создан"


class TestClaudeProxyExceptions:
    """Тесты для claude_proxy.py exception handling."""

    def test_load_file_not_found_fallback(self):
        """_load возвращает {} при отсутствии файла."""
        import claude_proxy
        from pathlib import Path

        # Mock SETTINGS как несуществующий файл
        with patch('claude_proxy.SETTINGS', Path("/nonexistent/settings.json")):
            result = claude_proxy._load()
            assert isinstance(result, dict), "Должен возвращать пустой dict при отсутствии файла"
            assert result == {}, "Dict должен быть пустым"

    def test_load_json_decode_error_fallback(self):
        """_load возвращает {} при malformed JSON."""
        import claude_proxy

        with patch('claude_proxy.SETTINGS', Path("/nonexistent/settings.json")):
            # Mock read_text чтобы вернуть invalid JSON
            with patch.object(Path, 'read_text', return_value="{invalid json}"):
                with patch.object(Path, 'exists', return_value=True):
                    result = claude_proxy._load()
                    assert result == {}, "Должен возвращать пустой dict при JSON decode error"

    def test_save_os_error_handling(self):
        """_save обрабатывает OS ошибки и возвращает structured error."""
        import claude_proxy

        result = claude_proxy._save({"test": "data"})
        assert isinstance(result, dict), "Должен возвращать dict"
        assert "ok" in result, "Result должен содержать ключ 'ok'"

    def test_status_with_invalid_data(self):
        """status обрабатывает невалидные данные в settings.json."""
        import claude_proxy

        with patch('claude_proxy._load', return_value={"not_env": {}}):
            result = claude_proxy.status()
            assert isinstance(result, dict), "status должен возвращать dict"
            assert result.get("enabled") is False, "enabled должен быть False при невалидных данных"


class TestGenXrayConfigExceptions:
    """Тесты для gen_xray_config.py exception handling."""

    def test_valid_host_invalid_input_fallback(self):
        """_valid_host возвращает False при невалидном вводе."""
        import gen_xray_config

        result = gen_xray_config._valid_host(None)
        assert result is False, "Должен возвращать False для None"

        result = gen_xray_config._valid_host(123)
        assert result is False, "Должен возвращать False для non-str"

        result = gen_xray_config._valid_host("invalid host with spaces")
        assert result is False, "Должен возвращать False для invalid hostname"

    def test_apply_outbound_hook_error_fallback(self):
        """_apply_outbound_hook возвращает original outbound при ошибке hook."""
        import gen_xray_config

        test_outbound = {"protocol": "test", "tag": "test-tag"}
        failing_hook = Mock(side_effect=ValueError("Hook error"))

        result = gen_xray_config._apply_outbound_hook(test_outbound, failing_hook, node={}, role="test")
        assert result == test_outbound, "Должен возвращать original outbound при hook error"

    def test_load_template_os_error_fallback(self):
        """_load_template возвращает default template при OS error."""
        import gen_xray_config

        result = gen_xray_config._load_template("/nonexistent/template.json")
        assert isinstance(result, dict), "Должен возвращать dict"
        assert "inbounds" in result, "Result должен содержать 'inbounds'"
        assert "outbounds" in result, "Result должен содержать 'outbounds'"

    def test_write_config_os_error_returns_false(self):
        """write_config возвращает False при OS error."""
        import gen_xray_config

        result = gen_xray_config.write_config("/root/readonly/config.json")
        assert result is False, "Должен возвращать False при OS error"


class TestGitProxyExceptions:
    """Тесты для git_proxy.py exception handling."""

    def test_get_all_timeout_handling(self):
        """_get_all обрабатывает timeout и возвращает unknown=True."""
        import git_proxy

        with patch('git_proxy.sys_probe.run', return_value={"timeout": True, "rc": None}):
            result = git_proxy._get_all("http.test.example.com.proxy")
            assert result.get("unknown") is True, "unknown должен быть True при timeout"
            assert result.get("present") is False, "present должен быть False при timeout"

    def test_write_values_rollback_on_error(self):
        """_write_values делает rollback при ошибке записи."""
        import git_proxy

        mock_run = Mock()
        mock_run.side_effect = [
            {"rc": 0, "timeout": False},  # before snapshot
            {"rc": 0, "timeout": False},  # unset-all success
            {"rc": 1, "timeout": False, "err": "git add failed"},  # add fails
        ]

        with patch('git_proxy.sys_probe.run', mock_run):
            with patch('git_proxy._get_all', return_value={"present": False, "values": [], "unknown": False}):
                result = git_proxy._write_values("test.key", ["value1"], begin_txn=False)
                assert result.get("ok") is False, "ok должен быть False при ошибке add"
                assert result.get("data_loss") is False, "data_loss должен быть False после rollback"

    def test_enable_with_txn_resolution(self):
        """enable разрешает незавершённую транзакцию."""
        import git_proxy

        mock_txn_check = Mock(return_value={"ok": True, "resolved": True})
        mock_get_all = Mock(return_value={"present": False, "values": [], "unknown": False, "multi": False})

        with patch('git_proxy._check_and_resolve_txn', mock_txn_check):
            with patch('git_proxy._get_all', mock_get_all):
                with patch('git_proxy._write_values', return_value={"ok": True}):
                    result = git_proxy.enable()
                    assert result.get("ok") is True, "enable должен succeed после txn resolution"


class TestSysProbeExceptions:
    """Тесты для sys_probe.py (probe_manager.py) exception handling."""

    def test_run_os_error_handling(self):
        """ProbeManager.run обрабатывает OSError (binary not found)."""
        import probe_manager

        manager = probe_manager.ProbeManager()
        result = manager.run(["/nonexistent/binary"], timeout=1.0)
        assert isinstance(result, dict), "Должен возвращать dict"
        assert "rc" in result, "Result должен содержать 'rc'"
        assert "err" in result, "Result должен содержать 'err'"

    def test_run_timeout_expired_handling(self):
        """ProbeManager.run обрабатывает TimeoutExpired."""
        import probe_manager
        import subprocess

        manager = probe_manager.ProbeManager()

        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired("test", 1.0)):
            result = manager.run(["echo", "test"], timeout=1.0)
            assert result.get("timeout") is True, "timeout должен быть True"
            assert "err" in result, "Result должен содержать 'err'"

    def test_port_open_os_error_handling(self):
        """ProbeManager.port_open обрабатывает OSError."""
        import probe_manager

        manager = probe_manager.ProbeManager()
        # Несуществующий хост вызовет OSError (ConnectionRefused/timeout)
        result = manager.port_open("nonexistent.invalid.example", 80, timeout=0.1)
        assert result is False, "port_open должен возвращать False при OS error"


class TestCriticalPathBehaviorNew:
    """Тесты что critical path поведение не изменилось."""

    def test_install_command_error_handling(self):
        """install команда должна обрабатывать ошибки корректно."""
        from srouter import cmd_install
        from argparse import Namespace

        args = Namespace(
            state=None,
            prefix=None,
            python=None,
            launchagents_dir=None,
            yes=True
        )

        # Mock для ошибки в build_plan
        with patch('srouter.build_plan', side_effect=OSError("Test error")):
            result = cmd_install(args)
            assert result == 2, "install должен возвращать rc=2 при discovery error"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
