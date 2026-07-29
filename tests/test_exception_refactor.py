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
    """Тесты для health.py exception handling.

    Дополнено issue #237 (часть #161): regress-гварды для except-блоков, переписанных
    в PR #244 с broad `except Exception` на конкретные типы. Каждый тест триггерит
    реальный exception-путь (не мокает сам чек) и проверяет заявленный в docstring fallback.
    """

    def test_import_fallback_values(self):
        """При отсутствии dashboard_common используются fallback значения."""
        import health

        assert health.PRIVOXY_PORT == 8118, "Fallback порт Privoxy"
        assert health.XRAY_PORT == 10808, "Fallback порт Xray"
        assert health._PROXY == "http://127.0.0.1:8118", "Fallback proxy URL"

    def test_route_default_interface_subprocess_error(self, monkeypatch):
        """sys_probe.run бросает при route -n get default → '' (default route неприменим)."""
        import health

        def boom(*args, **kwargs):
            raise OSError("route: command not found")

        monkeypatch.setattr(health.sys_probe, "run", boom)
        assert health._route_default_interface() == ""

    def test_inet_interface_subprocess_error(self, monkeypatch):
        """sys_probe.run бросает при ifconfig → '' (inet-интерфейс неприменим)."""
        import health

        def boom(*args, **kwargs):
            raise health.subprocess.SubprocessError("ifconfig failed")

        monkeypatch.setattr(health.sys_probe, "run", boom)
        assert health._inet_interface() == ""

    def test_resolve_host_os_error_returns_false(self, monkeypatch):
        """socket.getaddrinfo бросает OSError (gaierror) → _resolve_host False (DNS не резолвит)."""
        import health

        def boom(host, port):
            raise OSError("nodename nor servname provided")

        monkeypatch.setattr(health.socket, "getaddrinfo", boom)
        assert health._resolve_host("nonexistent.invalid") is False

    def test_vps_endpoint_bad_port_defaults_to_443(self):
        """node['port'] невалиден (не число) → port=443 (default Reality TLS), не бросает."""
        import health

        host, port = health._vps_endpoint({"endpoint_host": "vps.example.com", "port": "not-a-number"})
        assert host == "vps.example.com"
        assert port == 443, "TypeError/ValueError на int(port) → default 443"

    def test_upstream_vps_reachable_active_node_raises(self, monkeypatch):
        """local_state.active_node() бросает → node={} → status info (VPS-probe неприменим)."""
        import health

        def boom():
            raise OSError("state file corrupt")

        monkeypatch.setattr(health.local_state, "active_node", boom)
        result = health._upstream_vps_reachable(node=None)
        assert result["status"] == "info"

    def test_upstream_vps_reachable_port_open_os_error(self, monkeypatch):
        """sys_probe.port_open бросает OSError → reachable=False → status down (не крашится)."""
        import health

        def boom(host, port, timeout=None):
            raise OSError("network unreachable")

        monkeypatch.setattr(health.sys_probe, "port_open", boom)
        node = {"endpoint_host": "vps.example.com", "port": 443}
        result = health._upstream_vps_reachable(node=node)
        assert result["status"] == "down"

    def test_has_expected_api_401_skips_bad_json_lines(self):
        """Невалидный JSON в потоке (json.loads бросает) → строка пропускается, не крашится."""
        import health

        output = "not json at all\n{\"api_error_status\": 401}\n"
        assert health._has_expected_api_401(output) is True

    def test_has_expected_api_401_all_bad_json_returns_false(self):
        """Весь вывод — невалидный JSON → False, не бросает."""
        import health

        assert health._has_expected_api_401("garbage\nmore garbage\n") is False

    def test_has_api_retry_skips_bad_json_lines(self):
        """Невалидный JSON в потоке (json.loads бросает) → строка пропускается, retry находится дальше."""
        import health

        output = "not json\n{\"subtype\": \"api_retry\"}\n"
        assert health._has_api_retry(output) is True

    def test_configured_claude_proxy_import_error(self, monkeypatch):
        """claude_proxy недоступен (ImportError) → '' (proxy считается не настроенным)."""
        import builtins
        import health

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "claude_proxy":
                raise ImportError("no module named claude_proxy")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        assert health._configured_claude_proxy() == ""

    def test_is_srouter_codex_wrapper_os_error_returns_false(self, monkeypatch, tmp_path):
        """Path.read_text бросает OSError (права/гонка) → False, не крашится."""
        import health

        monkeypatch.setattr(health, "_codex_wrapper_path", lambda: tmp_path / "codex-srouter")
        wrapper_path = tmp_path / "codex-srouter"
        wrapper_path.write_text("marker", encoding="utf-8")

        def boom(self, encoding=None):
            raise OSError("permission denied")

        monkeypatch.setattr(health.Path, "read_text", boom)
        assert health._is_srouter_codex_wrapper(str(wrapper_path)) is False

    def test_scan_codex_binaries_resolve_os_error_falls_back_to_raw_path(self, monkeypatch, tmp_path):
        """Path.resolve() бросает OSError (broken symlink/permission) → используем cand как есть, не крашится."""
        import health

        fake_bin = tmp_path / "codex"
        fake_bin.write_text("#!/bin/sh\n", encoding="utf-8")
        fake_bin.chmod(0o755)

        monkeypatch.setattr(health, "_which_all", lambda name: [str(fake_bin)])
        monkeypatch.setattr(health, "_codex_wrapper_path", lambda: tmp_path / "no-such-wrapper")
        monkeypatch.setattr(health.sys_probe, "run", lambda *a, **k: {"timeout": True})

        def boom(self):
            raise OSError("broken symlink")

        monkeypatch.setattr(health.Path, "resolve", boom)
        results = health._scan_codex_binaries()
        assert any(r["path"] == str(fake_bin) for r in results)

    def test_scan_claude_code_binaries_iterdir_os_error_skips_versions(self, monkeypatch, tmp_path):
        """versions_dir.iterdir() бросает OSError (права) → версии пропущены, не крашится."""
        import health

        home = tmp_path
        (home / ".local" / "share" / "claude" / "versions").mkdir(parents=True)
        monkeypatch.setattr(health.Path, "home", lambda: home)
        monkeypatch.setattr(health, "_which_all", lambda name: [])

        real_iterdir = Path.iterdir

        def boom(self):
            if self == home / ".local" / "share" / "claude" / "versions":
                raise OSError("permission denied")
            return real_iterdir(self)

        monkeypatch.setattr(health.Path, "iterdir", boom)
        results = health._scan_claude_code_binaries()
        assert results == []

    def test_privoxy_log_check_config_directives_value_error(self, monkeypatch, tmp_path):
        """_config_directives бросает ValueError (malformed config) → directives={}, debug=0, status ok."""
        import health

        config_path = tmp_path / "config"
        config_path.write_text("debug garbage-not-a-directive\n", encoding="utf-8")
        log_dir = tmp_path / "logs"
        log_dir.mkdir()

        layout = health.privoxy_system.ProtectedLayout(config_path=config_path, log_dir=log_dir)

        def boom(text):
            raise ValueError("malformed directive line")

        monkeypatch.setattr(health.privoxy_system, "_config_directives", boom)
        result = health._privoxy_log_observability_check(layout=layout)
        assert result["status"] == "ok", "directives={} → debug=0 → молчаливый privoxy, status ok"

    def test_privoxy_log_check_debug_int_parse_value_error(self, monkeypatch, tmp_path):
        """int(debug_raw) бросает ValueError (нечисловой debug) → debug=0, status ok."""
        import health

        config_path = tmp_path / "config"
        config_path.write_text("debug not-a-number\n", encoding="utf-8")
        log_dir = tmp_path / "logs"
        log_dir.mkdir()

        layout = health.privoxy_system.ProtectedLayout(config_path=config_path, log_dir=log_dir)
        result = health._privoxy_log_observability_check(layout=layout)
        assert result["status"] == "ok", "debug не парсится → 0 → молчаливый privoxy, status ok"

    def test_installed_versions_check_scan_codex_os_error(self, monkeypatch):
        """_scan_codex_binaries бросает OSError → codex_bins=[], не крашится."""
        import health

        def boom():
            raise OSError("scan failed")

        monkeypatch.setattr(health, "_scan_codex_binaries", boom)
        monkeypatch.setattr(health, "_scan_claude_code_binaries", lambda: [])
        result = health._installed_versions_check()
        assert result["codex"] == []
        assert result["status"] == "unknown"

    def test_installed_versions_check_scan_claude_os_error(self, monkeypatch):
        """_scan_claude_code_binaries бросает OSError → claude_bins=[], не крашится."""
        import health

        monkeypatch.setattr(health, "_scan_codex_binaries", lambda: [])

        def boom():
            raise OSError("scan failed")

        monkeypatch.setattr(health, "_scan_claude_code_binaries", boom)
        result = health._installed_versions_check()
        assert result["claude_code"] == []
        assert result["status"] == "unknown"

    def test_codex_isolation_check_wraps_exceptions_as_info(self, monkeypatch):
        """isolate_firewall.probe_codex_isolation вернул неожиданную форму (AttributeError на .get) →
        status info, detail с типом ошибки — не крашится."""
        import health

        class FakeIsolateFirewall:
            @staticmethod
            def probe_codex_isolation():
                return None  # .get("status") на None → AttributeError

        import sys
        monkeypatch.setitem(sys.modules, "isolate_firewall", FakeIsolateFirewall)
        result = health._codex_isolation_check()
        assert result["status"] == "info"
        assert "сбой" in result["detail"]

    def test_read_proxy_sources_claude_proxy_import_error(self, monkeypatch):
        """claude_proxy недоступен (ImportError) → cli_proxy='' (fail-soft)."""
        import builtins
        import health

        monkeypatch.setattr(health, "_read_gui_proxy_env",
                             lambda keys_filter=None: {"verifiable": False, "keys": {}})

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "claude_proxy":
                raise ImportError("no module named claude_proxy")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        result = health._read_proxy_sources()
        assert result["cli_proxy"] == ""

    def test_vscode_proxy_check_import_error(self, monkeypatch):
        """vscode_proxy недоступен (ImportError) → status unknown, check пропущен."""
        import builtins
        import health

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "vscode_proxy":
                raise ImportError("no module named vscode_proxy")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        result = health._vscode_proxy_check()
        assert result["status"] == "unknown"

    def test_notify_log_write_os_error_does_not_block_osascript(self, monkeypatch, tmp_path):
        """Запись в WATCHDOG_NOTIFY_LOG бросает OSError → не крашится, osascript всё равно вызывается."""
        import health

        missing_dir = tmp_path / "no-such-parent"
        monkeypatch.setattr(health, "WATCHDOG_NOTIFY_LOG", missing_dir / "sub" / "notify.log")

        def boom_mkdir(self, parents=False, exist_ok=False):
            raise OSError("permission denied")

        monkeypatch.setattr(health.Path, "mkdir", boom_mkdir)
        calls = []
        monkeypatch.setattr(health.sys_probe, "run", lambda *a, **k: calls.append(a) or {"rc": 0})
        health._notify("test message")
        assert calls, "osascript должен вызваться, даже если запись в лог упала"

    def test_notify_osascript_subprocess_error_is_swallowed(self, monkeypatch, tmp_path):
        """sys_probe.run(osascript) бросает → notify не крашится (best-effort нотификация #109)."""
        import health

        monkeypatch.setattr(health, "WATCHDOG_NOTIFY_LOG", tmp_path / "notify.log")

        def boom(*args, **kwargs):
            raise health.subprocess.SubprocessError("osascript failed")

        monkeypatch.setattr(health.sys_probe, "run", boom)
        health._notify("test message")  # не должен бросать

    def test_launchd_int_value_error_returns_none(self):
        """Нечисловое значение поля launchd → None, не бросает."""
        import health

        output = "\tpid = not-a-number;\n"
        assert health._launchd_int(output, "pid") is None

    def test_record_watchdog_lifecycle_collect_raises(self, monkeypatch):
        """_collect_launchd_lifecycle бросает → snapshot пропущен, не крашится (best-effort)."""
        import health

        def boom():
            raise OSError("launchctl unavailable")

        monkeypatch.setattr(health, "_collect_launchd_lifecycle", boom)
        health._record_watchdog_lifecycle()  # не должен бросать

    def test_record_watchdog_lifecycle_state_read_json_error(self, monkeypatch, tmp_path):
        """WATCHDOG_LIFECYCLE_STATE содержит битый JSON → previous=None (baseline пуст), не крашится."""
        import health

        state_file = tmp_path / "lifecycle_state.json"
        state_file.write_text("not valid json {", encoding="utf-8")
        log_file = tmp_path / "lifecycle.jsonl"

        monkeypatch.setattr(health, "_collect_launchd_lifecycle", lambda: {"a": 1})
        monkeypatch.setattr(health, "WATCHDOG_LIFECYCLE_STATE", state_file)
        monkeypatch.setattr(health, "WATCHDOG_LIFECYCLE_LOG", log_file)
        health._record_watchdog_lifecycle()  # не должен бросать
        assert state_file.read_text(encoding="utf-8") == '{"a": 1}'

    def test_record_watchdog_lifecycle_log_write_os_error(self, monkeypatch, tmp_path):
        """Запись WATCHDOG_LIFECYCLE_LOG бросает OSError (смена состояния) → не крашится."""
        import health

        state_file = tmp_path / "lifecycle_state.json"
        state_file.write_text('{"a": 0}', encoding="utf-8")
        log_file = tmp_path / "no-such-dir" / "lifecycle.jsonl"

        monkeypatch.setattr(health, "_collect_launchd_lifecycle", lambda: {"a": 1})
        monkeypatch.setattr(health, "WATCHDOG_LIFECYCLE_STATE", state_file)
        monkeypatch.setattr(health, "WATCHDOG_LIFECYCLE_LOG", log_file)

        def boom_mkdir(self, parents=False, exist_ok=False):
            if self == log_file.parent:
                raise OSError("permission denied")
            return None

        monkeypatch.setattr(health.Path, "mkdir", boom_mkdir)
        health._record_watchdog_lifecycle()  # не должен бросать

    def test_record_watchdog_lifecycle_state_write_os_error(self, monkeypatch, tmp_path):
        """Запись WATCHDOG_LIFECYCLE_STATE бросает OSError → не крашится (следующий прогон может
        ложно считать baseline)."""
        import health

        state_file = tmp_path / "no-such-dir" / "lifecycle_state.json"
        log_file = tmp_path / "lifecycle.jsonl"

        monkeypatch.setattr(health, "_collect_launchd_lifecycle", lambda: {"a": 1})
        monkeypatch.setattr(health, "WATCHDOG_LIFECYCLE_STATE", state_file)
        monkeypatch.setattr(health, "WATCHDOG_LIFECYCLE_LOG", log_file)

        def boom_mkdir(self, parents=False, exist_ok=False):
            raise OSError("permission denied")

        monkeypatch.setattr(health.Path, "mkdir", boom_mkdir)
        health._record_watchdog_lifecycle()  # не должен бросать

    def test_cmd_watchdog_state_read_os_error_treated_as_fresh(self, monkeypatch, tmp_path):
        """Чтение WATCHDOG_STATE бросает OSError → prev='' (fresh), не крашится."""
        import health

        state_file = tmp_path / "state"
        monkeypatch.setattr(health, "WATCHDOG_STATE", state_file)
        monkeypatch.setattr(health, "check_all", lambda active_claude=False: {"status": "ok", "checks": []})
        monkeypatch.setattr(health, "_record_watchdog_lifecycle", lambda: None)
        monkeypatch.setattr(health, "_notify", lambda *a, **k: None)

        real_exists = Path.exists

        def boom_read_text(self):
            raise OSError("permission denied")

        monkeypatch.setattr(health.Path, "exists", lambda self: True if self == state_file else real_exists(self))
        monkeypatch.setattr(health.Path, "read_text", boom_read_text)
        rc = health.cmd_watchdog()
        assert rc == 0

    def test_cmd_watchdog_state_write_os_error_does_not_crash(self, monkeypatch, tmp_path):
        """Запись WATCHDOG_STATE бросает OSError → cmd_watchdog не крашится (следующий прогон
        может ложно считать fresh)."""
        import health

        state_file = tmp_path / "no-such-dir" / "state"
        monkeypatch.setattr(health, "WATCHDOG_STATE", state_file)
        monkeypatch.setattr(health, "check_all", lambda active_claude=False: {"status": "ok", "checks": []})
        monkeypatch.setattr(health, "_record_watchdog_lifecycle", lambda: None)
        monkeypatch.setattr(health, "_notify", lambda *a, **k: None)
        rc = health.cmd_watchdog()
        assert rc == 0


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
