#!/usr/bin/env python3
"""
Regress-гвард тесты для рефакторинга except Exception (issue #161).

Проверяют что рефакторинг не изменил поведение в critical path:
- Error handling продолжает работать корректно
- Specific exceptions не ломают fallback логику
- CLI/API guards продолжают catching всё что нужно
"""

import pytest
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch


class TestSrouterExceptions:
    """Тесты для srouter.py exception handling."""

    def test_active_route_ip_for_removal_os_error(self):
        """OS ошибка в _active_route_ip_for_removal возвращает fallback."""
        from srouter import _active_route_ip_for_removal
        import local_state

        with patch.object(local_state, 'active_node', side_effect=OSError("File not found")):
            result = _active_route_ip_for_removal("/tmp/test.json")
            assert result == "", "Должен возвращать пустую строку при OSError"

    def test_install_ppp_hook_subprocess_error(self):
        """subprocess ошибка в _install_ppp_hook возвращает error message."""
        from srouter import _install_ppp_hook
        from install_lib import InstallEnv

        env = InstallEnv.from_env()
        mock_runner = Mock()
        mock_runner.return_value = {"rc": -1, "err": "timeout"}

        result = _install_ppp_hook(env, mock_runner)
        assert "не установлен" in result.lower(), "Должен возвращать ошибку установки"


class TestHealthExceptions:
    """Тесты для health.py exception handling."""

    def test_import_fallback_values(self):
        """При отсутствии dashboard_common используются fallback значения."""
        import health

        assert health.PRIVOXY_PORT == 8118, "Fallback порт Privoxy"
        assert health.XRAY_PORT == 10808, "Fallback порт Xray"
        assert health._PROXY == "http://127.0.0.1:8118", "Fallback proxy URL"


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

        # При отсутствии файла должен возвращать fallback
        result = vscode_proxy._load("/nonexistent/settings.json")
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])