#!/usr/bin/env python3
"""
Regress-гвард тесты для рефакторинга except Exception (issue #161).

Проверяют что рефакторинг не изменил поведение в critical path:
- Error handling продолжает работать корректно
- Specific exceptions не ломают fallback логику
- CLI/API guards продолжают catching всё что нужно
"""

import subprocess
import pytest
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


class TestIsolateFirewallExceptions:
    """Тесты для isolate_firewall.py exception handling (issue #240)."""

    def test_enable_strict_subprocess_timeout_returns_error(self):
        """timeout в enable_strict возвращает structured error, не крашит."""
        import isolate_firewall

        with patch('isolate_firewall._admin_run', side_effect=subprocess.TimeoutExpired("pfctl -E", 60)):
            result = isolate_firewall.enable_strict()
            assert result["ok"] is False, "timeout должен возвращать ok=False"
            assert "timeout" in str(result["err"]).lower() or "failed" in result["err"].lower()

    def test_enable_strict_oserror_returns_error(self):
        """OSError в enable_strict возвращает structured error."""
        import isolate_firewall

        with patch('isolate_firewall._admin_run', side_effect=OSError("pfctl not found")):
            result = isolate_firewall.enable_strict()
            assert result["ok"] is False, "OSError должен возвращать ok=False"
            assert "failed" in result["err"]

    def test_disable_strict_handles_oserror(self):
        """OSError в disable_strict возвращает structured error."""
        import isolate_firewall

        with patch('isolate_firewall._admin_run', side_effect=OSError("Permission denied")):
            result = isolate_firewall.disable_strict()
            assert result["ok"] is False, "OSError должен возвращать ok=False"

    def test_enable_isolation_value_error_returns_error(self):
        """ValueError при валидации портов в enable_isolation возвращает error."""
        import isolate_firewall

        with patch('isolate_firewall._ports_spec', side_effect=ValueError("Invalid port")):
            result = isolate_firewall.enable_isolation(["api.anthropic.com"])
            assert result["ok"] is False, "ValueError должен возвращать ok=False"

    def test_enable_isolation_type_error_on_malformed_domains(self):
        """TypeError при malformed domains (целое число вместо списка) возвращает error (Codex P2)."""
        import isolate_firewall

        # Мокаем resolve_domain_ips чтобы выбросить TypeError при получении integer вместо списка
        with patch('isolate_firewall.resolve_domain_ips', side_effect=TypeError("expected iterable, got int")):
            result = isolate_firewall.enable_isolation(42)  # malformed: integer instead of list
            assert result["ok"] is False, "TypeError на malformed domains должен возвращать ok=False"
            assert "failed" in result["err"] or "type" in str(result["err"]).lower()

    def test_probe_isolation_type_error_returns_unknown_status(self):
        """TypeError в probe_isolation возвращает status=unknown (FAIL-CLOSED)."""
        import isolate_firewall

        # Мокаем load_active_isolate чтобы вернуть не-dict (вызовет TypeError/AttributeError)
        with patch('isolate_firewall.local_state.load_active_isolate', return_value="not a dict"):
            result = isolate_firewall.probe_isolation()
            # FAIL-CLOSED: при ошибке типа данных НЕ возвращаем ok/warn, только unknown
            assert result["status"] == "unknown", "Type error должен возвращать status=unknown"

    def test_probe_codex_isolation_oserror_returns_unknown(self):
        """OSError в probe_codex_isolation возвращает status=unknown."""
        import isolate_firewall

        with patch('isolate_firewall.local_state.load_active_codex_isolate', side_effect=OSError("No state file")):
            result = isolate_firewall.probe_codex_isolation()
            assert result["status"] == "unknown", "OSError должен возвращать status=unknown"

    def test_probe_codex_user_parse_error_returns_not_provisioned(self):
        """Ошибка парсинга в probe_codex_user возвращает provisioned=False."""
        import isolate_firewall

        with patch('isolate_firewall.sys_probe.run', return_value={"out": "malformed dscl output"}):
            result = isolate_firewall.probe_codex_user()
            # FAIL-CLOSED: при ошибке чтения считаем пользователя не provisioned
            assert result["provisioned"] is False, "Parse error должен возвращать provisioned=False"

    def test_uid_in_use_exception_returns_true(self):
        """ЛЮБАЯ ошибка в _uid_in_use возвращает True (FAIL-CLOSED: не создаём поверх неизвестного)."""
        import isolate_firewall

        with patch('isolate_firewall.sys_probe.run', side_effect=Exception("Unexpected error")):
            result = isolate_firewall._uid_in_use("503")
            # FAIL-CLOSED: при любой ошибке считаем uid заняты
            assert result is True, "Любая ошибка должна возвращать True (uid занят)"

    def test_provision_codex_user_oserror_returns_error(self):
        """OSError в provision_codex_user возвращает structured error."""
        import isolate_firewall

        with patch('isolate_firewall.probe_codex_user', return_value={"provisioned": False}):
            with patch('isolate_firewall._uid_in_use', return_value=False):
                with patch('isolate_firewall._admin_run', side_effect=OSError("dscl failed")):
                    result = isolate_firewall.provision_codex_user()
                    assert result["ok"] is False, "OSError должен возвращать ok=False"


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
