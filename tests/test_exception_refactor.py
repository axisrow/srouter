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


class TestNodeSelectorExceptions:
    """Тесты для node_selector.py exception handling."""

    def test_default_runner_subprocess_error(self):
        """_default_runner должен обрабатывать subprocess ошибки."""
        from node_selector import _default_runner

        # Timeout
        result = _default_runner(["sleep", "10"], timeout=0.01)
        assert result["timeout"] is True, "Должен возвращать timeout=True при TimeoutExpired"

        # Несуществующая команда
        result = _default_runner(["nonexistent_command_12345"], timeout=5)
        assert result["rc"] is None, "Должен возвращать rc=None при сбое запуска"

    def test_active_name_local_state_error(self):
        """_active_name должен обрабатывать local_state ошибки."""
        from node_selector import _active_name
        import local_state

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            state_path.write_text("invalid json", encoding='utf-8')

            result = _active_name(state_path=str(state_path))
            assert result is None, "Должен возвращать None при ошибке чтения state"

    def test_run_restart_runner_error(self):
        """_run_restart должен обрабатывать runner ошибки."""
        from node_selector import _run_restart

        # Mock runner который бросает исключение
        def failing_runner(cmd, timeout):
            raise RuntimeError("Runner failed")

        result = _run_restart(failing_runner)
        assert result["timeout"] is True, "Должен возвращать timeout=True при runner error"

    def test_rollback_local_state_error(self):
        """_rollback должен обрабатывать local_state ошибки."""
        from node_selector import _rollback
        import gen_xray_config

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            config_path = Path(tmpdir) / "config.json"
            state_path.write_text('{"active_node": {"name": "test"}}', encoding='utf-8')

            # Mock gen_xray_config.write_config который возвращает False (ошибка)
            with patch('gen_xray_config.write_config', return_value=False):
                # Mock runner который возвращает success
                def mock_runner(cmd, timeout):
                    return {"rc": 0, "out": "", "err": "", "timeout": False}

                result = _rollback(str(state_path), str(config_path), mock_runner)
                assert result["ok"] is False, "Должен возвращать ok=False при ошибке rollback"

    def test_auto_route_sync_enabled_state_error(self):
        """_auto_route_sync_enabled должен обрабатывать state ошибки."""
        from node_selector import _auto_route_sync_enabled

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            # Создаем валидный JSON но без auto_route_sync
            state_path.write_text('{"nodes": []}', encoding='utf-8')

            result = _auto_route_sync_enabled(str(state_path))
            assert result is False, "Должен возвращать False когда auto_route_sync не true"

    def test_route_node_ip_error(self):
        """_route_node_ip должен обрабатывать ошибки."""
        from node_selector import _route_node_ip

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            state_path.write_text('{"nodes": []}', encoding='utf-8')

            result = _route_node_ip("nonexistent", str(state_path))
            assert result == "", "Должен возвращать пустую строку при ошибке"

    def test_gateway_literal_import_error(self):
        """_gateway_literal должен обрабатывать ошибки import."""
        from node_selector import _gateway_literal

        # Mock ImportError
        with patch('builtins.__import__', side_effect=ImportError("No module")):
            result = _gateway_literal()
            assert result == "", "Должен возвращать пустую строку при import error"

    def test_physical_iface_prefixes_error(self):
        """_physical_iface_prefixes должен обрабатывать ошибки."""
        from node_selector import _physical_iface_prefixes

        # Mock ошибку
        with patch('builtins.__import__', side_effect=OSError("Import failed")):
            result = _physical_iface_prefixes()
            assert isinstance(result, tuple), "Должен возвращать tuple при ошибке"
            assert "en" in result, "Должен возвращать fallback tuple"

    def test_sync_split_route_error(self):
        """_sync_split_route должен обрабатывать ошибки."""
        from node_selector import _sync_split_route

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            state_path.write_text('{"nodes": [], "active_node": {"name": null}}', encoding='utf-8')

            result = _sync_split_route("previous", "new", str(state_path))
            assert "error" in result or result.get("enabled") is True, "Должен обрабатывать ошибки без исключения"

    def test_route_get_gateway_error(self):
        """_route_get_gateway должен обрабатывать sys_probe ошибки."""
        from node_selector import _route_get_gateway

        # Mock sys_probe.run который бросает исключение
        with patch('sys_probe.run', side_effect=OSError("Route command failed")):
            result = _route_get_gateway("192.0.2.1")
            assert result["ok"] is False, "Должен возвращать ok=False при sys_probe error"

    def test_ensure_split_route_error(self):
        """ensure_split_route должен обрабатывать все ошибки."""
        from node_selector import ensure_split_route

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            state_path.write_text('{"nodes": [], "active_node": {"name": null}}', encoding='utf-8')

            result = ensure_split_route(str(state_path))
            assert "error" in result or "enabled" in result, "Должен возвращать dict с ошибкой или статусом"
            assert result.get("enabled") in [True, False], "Должен иметь корректный статус enabled"


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

    def test_load_state_oserror_fallback(self):
        """load_state должен обрабатывать OSError."""
        import local_state

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "unreadable.json"
            state_path.write_bytes(b'\x00\x01\x02')  # Невалидные UTF-8 данные

            result = local_state.load_state(path=str(state_path))
            assert result is not None, "load_state должен возвращать fallback при OSError"

    def test_resolve_route_ip_dns_error(self):
        """resolve_route_ip должен обрабатывать DNS ошибки."""
        import local_state

        node = {"endpoint_host": "nonexistent.invalid.test.example.com"}
        result = local_state.resolve_route_ip(node)
        # Должен возвращать fallback (host или пустую строку)
        assert isinstance(result, str), "resolve_route_ip должен возвращать строку при DNS error"

    def test_save_state_type_error(self):
        """save_state должен обрабатывать TypeError."""
        import local_state

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            # Передаем невалидный state (не dict)
            result = local_state.save_state(None, path=str(state_path))
            assert result is None, "save_state должен возвращать None при TypeError"

    def test_read_xray_active_address_json_error(self):
        """read_xray_active_address должен обрабатывать JSON ошибки."""
        import local_state

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text("invalid json", encoding='utf-8')

            result = local_state.read_xray_active_address(str(config_path))
            assert result["status"] == "unreadable", "Должен возвращать unreadable при JSON error"

    def test_sync_endpoint_from_xray_error(self):
        """sync_endpoint_from_xray должен обрабатывать ошибки."""
        import local_state

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            state_path = Path(tmpdir) / "state.json"

            # Пустой config и state
            config_path.write_text("{}", encoding='utf-8')
            state_path.write_text('{"nodes": [], "active_node": {"name": null}}', encoding='utf-8')

            result = local_state.sync_endpoint_from_xray(str(config_path), str(state_path))
            assert result["ok"] is False, "Должен возвращать ok=False при ошибке"

    def test_routing_apply_lock_error(self):
        """routing_apply должен обрабатывать ошибки блокировки."""
        import local_state

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            state_path = Path(tmpdir) / "state.json"

            # Создаем валидные файлы
            config_path.write_text('{"routing": {"rules": [{"domain": [], "outboundTag": "reality-out"}]}}', encoding='utf-8')
            state_path.write_text('{"nodes": [], "active_node": {"name": null}}', encoding='utf-8')

            # Mock для OSError при создании lockfile
            with patch('local_state._routing_config_lock', side_effect=OSError("Lock error")):
                result = local_state.routing_apply(["example.com"], config_path=str(config_path), state_path=str(state_path))
                assert result["ok"] is False, "Должен возвращать ok=False при lock error"
                assert "config_lock_failed" in result["err"], "Должен сообщать о неудаче блокировки"


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
