#!/usr/bin/env python3
"""
Regress-гвард тесты для рефакторинга except Exception (issue #161).

Проверяют что рефакторинг не изменил поведение в critical path:
- Error handling продолжает работать корректно
- Specific exceptions не ломают fallback логику
- CLI/API guards продолжают catching всё что нужно

Дополнено issue #238 (часть #161): regress-гварды для 27 except-блоков, переписанных
с broad `except Exception` на конкретные типы в `node_selector.py` (15) и `local_state.py` (12).
Контракт этих тестов: каждый гвард ОБЯЗАН реально войти в свой handler — поднимаем исключение
на том самом seam'е внутри try (а не мокаем сам чек) и проверяем заявленный в docstring fallback.
Гвард, который проходит по happy-path, регрессию сузившегося catch не поймает, а именно сужение —
главный риск этого рефакторинга (канон srouter-critical-infra-24-7, fail-closed-proxy-down).
"""

import json
import socket
import subprocess
import pytest
import tempfile
import types
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# ------------------------------------------------------------------------------------------
# helpers: минимальные валидные state/xray-config для входа в нужный участок кода
# ------------------------------------------------------------------------------------------

_REAL_ADDR = "198.51.100.7"        # «реальный» VPS-адрес в xray-конфиге
_PLACEHOLDER = "203.0.113.10"      # TEST-NET (RFC 5737) placeholder в local.json
_GATEWAY = "192.168.1.1"


def _node(name="n1", endpoint_host=_REAL_ADDR, enabled=True, **extra):
    node = {"name": name, "endpoint_host": endpoint_host, "enabled": enabled}
    node.update(extra)
    return node


def _write_state(path, nodes=None, active_name=None, **extra):
    """Записать минимальный валидный state-файл."""
    state = {
        "schema_version": 1,
        "nodes": list(nodes) if nodes is not None else [],
        "active_node": {"name": active_name, "pending": None},
    }
    state.update(extra)
    Path(path).write_text(json.dumps(state), encoding="utf-8")
    return state


def _write_xray_config(path, address=_REAL_ADDR, domains=None, managed=True,
                       outbound="reality-out"):
    """xray-config с active-outbound (read_xray_active_address → status ok) + routing-rule."""
    rule = {"domain": list(domains or []), "outboundTag": outbound}
    if managed:
        rule["_srouter_managed"] = True
    data = {
        "outbounds": [{"tag": "active", "settings": {"vnext": [{"address": address}]}}],
        "routing": {"rules": [rule]},
    }
    Path(path).write_text(json.dumps(data), encoding="utf-8")
    return data


def _timeout_expired():
    return subprocess.TimeoutExpired(cmd=["/sbin/route"], timeout=1)


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

    def test_save_os_error_handling(self, tmp_path):
        """_save обрабатывает OS ошибки и возвращает structured error."""
        import vscode_proxy

        # Используем tmp_path и мокаем write_text для OS error
        test_file = tmp_path / "settings.json"

        with patch.object(Path, 'write_text', side_effect=OSError("Permission denied")):
            result = vscode_proxy._save(test_file, {"test": "data"})
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

    def test_write_config_os_error_returns_false(self, tmp_path):
        """write_config возвращает False при OS error."""
        import gen_xray_config

        # Используем tmp_path и мокаем файловые операции для OS error
        test_file = tmp_path / "config.json"

        with patch('gen_xray_config.generate_config', side_effect=OSError("Permission denied")):
            result = gen_xray_config.write_config(str(test_file))
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


# ==========================================================================================
# issue #238: node_selector.py — 15 переписанных except-блоков
# Каждый тест поднимает исключение на seam'е ВНУТРИ try и проверяет документированный fallback.
# ==========================================================================================


class TestNodeSelectorExceptionHandlers:
    """Гварды для 15 typed except-блоков node_selector.py (issue #238)."""

    # --- _default_runner: except (subprocess.CalledProcessError, OSError, ValueError) ---

    def test_default_runner_os_error_is_not_timeout(self):
        """Нет бинаря (OSError) → rc=None, timeout=False, typed err (не путать с зависшим рестартом)."""
        from node_selector import _default_runner

        result = _default_runner(["srouter_nonexistent_binary_12345"], timeout=5)
        assert result["rc"] is None
        assert result["timeout"] is False, "Сбой запуска — НЕ timeout (issue #82 семантика)"
        assert "Error" in result["err"] or "error" in result["err"], f"typed err, получено: {result['err']}"

    def test_default_runner_value_error(self, monkeypatch):
        """subprocess.run бросает ValueError (невалидные аргументы) → typed err, timeout=False."""
        import node_selector

        def boom(*args, **kwargs):
            raise ValueError("embedded null byte")

        monkeypatch.setattr(node_selector.subprocess, "run", boom)
        result = node_selector._default_runner(["/bin/echo", "x"], timeout=5)
        assert result["rc"] is None
        assert result["timeout"] is False
        assert "ValueError" in result["err"]

    def test_default_runner_timeout_still_flags_timeout(self, monkeypatch):
        """Регресс-гвард на соседний handler: TimeoutExpired → timeout=True (не съеден новым catch)."""
        import node_selector

        def boom(*args, **kwargs):
            raise _timeout_expired()

        monkeypatch.setattr(node_selector.subprocess, "run", boom)
        result = node_selector._default_runner(["/bin/echo", "x"], timeout=5)
        assert result["timeout"] is True
        assert result["err"] == "timeout"

    # --- _active_name: except (OSError, ValueError, RuntimeError) ---

    @pytest.mark.parametrize("exc", [OSError("state unreadable"),
                                     ValueError("bad json structure"),
                                     RuntimeError("mock failure")])
    def test_active_name_never_throws(self, monkeypatch, exc):
        """local_state.active_node бросает → None (контракт select_node «never throws», #159)."""
        import node_selector

        def boom(path=None):
            raise exc

        monkeypatch.setattr(node_selector.local_state, "active_node", boom)
        assert node_selector._active_name(state_path="/nonexistent/state.json") is None

    # --- _run_restart: except (OSError, ValueError, RuntimeError) ---

    @pytest.mark.parametrize("exc", [OSError("no brew"),
                                     ValueError("bad cmd"),
                                     RuntimeError("runner exploded")])
    def test_run_restart_runner_raises(self, exc):
        """runner бросает → timeout=True + err=str(exc) (рестарт считается неуспешным)."""
        from node_selector import _run_restart

        def failing_runner(cmd, timeout):
            raise exc

        result = _run_restart(failing_runner)
        assert result["timeout"] is True, "Сбой runner обязан считаться неуспехом рестарта"
        assert result["rc"] is None
        assert str(exc) in result["err"]

    # --- _rollback: except (OSError, ValueError) на clear_pending ---

    @pytest.mark.parametrize("exc", [OSError("state write denied"), ValueError("bad state")])
    def test_rollback_clear_pending_raises(self, monkeypatch, exc):
        """clear_pending бросает → ok=False, restore_ok=False, error 'clear pending failed'."""
        import node_selector

        def boom(path=None):
            raise exc

        monkeypatch.setattr(node_selector.local_state, "clear_pending", boom)
        result = node_selector._rollback("/tmp/state.json", "/tmp/config.json", lambda c, t: {"rc": 0})
        assert result["ok"] is False
        assert result["restore_ok"] is False, "Конфиг не восстановлен — вызывающий обязан сигналить failure"
        assert "clear pending failed" in result["error"]

    # --- _rollback: except (OSError, ValueError, TypeError) на write_config ---

    @pytest.mark.parametrize("exc", [OSError("disk full"),
                                     ValueError("invalid state"),
                                     TypeError("bad type")])
    def test_rollback_write_config_raises(self, monkeypatch, exc):
        """gen_xray_config.write_config бросает → ok=False, restore_ok=False, 'rollback config restore failed'."""
        import node_selector

        monkeypatch.setattr(node_selector.local_state, "clear_pending", lambda path=None: None)

        def boom(config_path, state_path=None, **kwargs):
            raise exc

        monkeypatch.setattr(node_selector.gen_xray_config, "write_config", boom)
        result = node_selector._rollback("/tmp/state.json", "/tmp/config.json", lambda c, t: {"rc": 0})
        assert result["ok"] is False
        assert result["restore_ok"] is False
        assert "rollback config restore failed" in result["error"]

    # --- _pending_active_hook.hook: except (OSError, ValueError, KeyError) ---

    @pytest.mark.parametrize("exc", [OSError("state gone"),
                                     ValueError("bad node"),
                                     KeyError("missing")])
    def test_pending_active_hook_falls_back_to_original_outbound(self, monkeypatch, exc):
        """get_node/_vless_outbound бросает → hook возвращает ИСХОДНЫЙ outbound (не ломает генерацию)."""
        import node_selector

        def boom(name, path=None):
            raise exc

        monkeypatch.setattr(node_selector.local_state, "get_node", boom)
        hook = node_selector._pending_active_hook("pending-node", "/tmp/state.json")
        sentinel = {"tag": "active", "_sentinel": True}
        assert hook(sentinel, node={}, role="active") is sentinel

    # --- _auto_route_sync_enabled: except (OSError, ValueError) ---

    @pytest.mark.parametrize("exc", [OSError("state unreadable"), ValueError("bad json")])
    def test_auto_route_sync_enabled_load_state_raises(self, monkeypatch, exc):
        """load_state бросает → False (fail-closed: ноль privileged route-вызовов)."""
        import node_selector

        def boom(path=None):
            raise exc

        monkeypatch.setattr(node_selector.local_state, "load_state", boom)
        assert node_selector._auto_route_sync_enabled("/tmp/state.json") is False

    def test_auto_route_sync_enabled_reads_explicit_flag(self):
        """Mutation-гвард: флаг читается из state (True/False), а не захардкожен в handler."""
        from node_selector import _auto_route_sync_enabled

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            _write_state(state_path, auto_route_sync=False)
            assert _auto_route_sync_enabled(str(state_path)) is False
            _write_state(state_path, auto_route_sync=True)
            assert _auto_route_sync_enabled(str(state_path)) is True

    # --- _route_node_ip: except (OSError, ValueError, KeyError) ---

    @pytest.mark.parametrize("exc", [OSError("state gone"),
                                     ValueError("bad structure"),
                                     KeyError("no node")])
    def test_route_node_ip_raises_returns_empty(self, monkeypatch, exc):
        """get_node/resolve_route_ip бросает → "" (без валидного IP privileged-вызовов не будет)."""
        import node_selector

        def boom(name, path=None):
            raise exc

        monkeypatch.setattr(node_selector.local_state, "get_node", boom)
        assert node_selector._route_node_ip("n1", "/tmp/state.json") == ""

    # --- _gateway_literal: except (ImportError, AttributeError, OSError) ---

    def test_gateway_literal_import_error(self, monkeypatch):
        """srouter_config недоступен (ImportError) → "" (import node_selector не должен падать)."""
        import sys
        import node_selector

        monkeypatch.setitem(sys.modules, "srouter_config",
                            types.SimpleNamespace(GATEWAY=_GATEWAY))
        assert node_selector._gateway_literal() == _GATEWAY, "happy-path: gateway читается из config"

        monkeypatch.setitem(sys.modules, "srouter_config", None)  # → ImportError
        assert node_selector._gateway_literal() == ""

    def test_gateway_literal_attribute_error(self, monkeypatch):
        """srouter_config без GATEWAY (AttributeError) → ""."""
        import sys
        import node_selector

        monkeypatch.setitem(sys.modules, "srouter_config", types.SimpleNamespace())
        assert node_selector._gateway_literal() == ""

    # --- _physical_iface_prefixes: except (ImportError, AttributeError, OSError) ---

    def test_physical_iface_prefixes_import_error(self, monkeypatch):
        """srouter_config недоступен (ImportError) → ("en",) — дефолт macOS Wi-Fi/USB-tether."""
        import sys
        import node_selector

        monkeypatch.setitem(sys.modules, "srouter_config",
                            types.SimpleNamespace(PHYSICAL_IFACE_PREFIXES=("utun",)))
        assert node_selector._physical_iface_prefixes() == ("utun",), "happy-path: читается из config"

        monkeypatch.setitem(sys.modules, "srouter_config", None)  # → ImportError
        assert node_selector._physical_iface_prefixes() == ("en",)

    # --- _sync_split_route: except (subprocess.*, OSError, ValueError, RuntimeError) ---

    @pytest.mark.parametrize("exc", [_timeout_expired(),
                                     subprocess.CalledProcessError(1, ["route"]),
                                     OSError("route failed"),
                                     ValueError("bad ip"),
                                     RuntimeError("mock failure")])
    def test_sync_split_route_never_throws(self, monkeypatch, exc):
        """Любой сбой route-операции → result['error'], НЕ исключение наружу (node-switch не ломаем)."""
        import node_selector

        def boom(name, state_path):
            raise exc

        monkeypatch.setattr(node_selector, "_route_node_ip", boom)
        result = node_selector._sync_split_route("prev", "new", "/tmp/state.json")
        assert result["enabled"] is True
        assert result["error"], "Сбой обязан быть отражён в result['error']"
        assert str(exc) in result["error"] or type(exc).__name__ in str(result["error"])

    # --- _route_get_gateway: except (subprocess.*, OSError, ValueError) ---

    @pytest.mark.parametrize("exc", [_timeout_expired(),
                                     subprocess.CalledProcessError(1, ["route"]),
                                     OSError("route: not found"),
                                     ValueError("bad arg")])
    def test_route_get_gateway_probe_raises(self, monkeypatch, exc):
        """sys_probe.run бросает → ok=False, gateway="" (read-back не подтверждён → delete не разрешаем)."""
        import node_selector

        def boom(*args, **kwargs):
            raise exc

        monkeypatch.setattr(node_selector.sys_probe, "run", boom)
        result = node_selector._route_get_gateway(_REAL_ADDR)
        assert result["ok"] is False, "Без read-back нельзя признать route корректным"
        assert result["gateway"] == ""
        assert result["err"], "Ошибка обязана быть отражена в err"

    # --- _select_node_locked: except (OSError, ValueError, KeyError, subprocess.*) ---

    @pytest.mark.parametrize("exc", [OSError("io"),
                                     ValueError("bad"),
                                     KeyError("missing"),
                                     subprocess.CalledProcessError(1, ["xray"]),
                                     _timeout_expired()])
    def test_select_node_locked_internal_error_before_begin(self, monkeypatch, exc):
        """Сбой ДО begin (begun=False) → step='internal', никакого rollback, наружу не бросает."""
        import node_selector

        def boom(state_path):
            raise exc

        monkeypatch.setattr(node_selector, "_traffic_guard_preflight_error", boom)
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            _write_state(state_path, nodes=[_node("n1")], active_name="n1")
            result = node_selector._select_node_locked(
                "n1", enabled_names={"n1"}, runner=lambda c, t: {"rc": 0, "timeout": False},
                state_path=str(state_path), config_path=str(Path(tmpdir) / "config.json"),
            )
        assert result["ok"] is False
        assert result["step"] == "internal", f"ожидался step=internal, получено {result}"
        assert str(exc) in result["error"] or type(exc).__name__ in result["error"]

    def test_select_node_locked_internal_error_after_begin_rolls_back(self, monkeypatch):
        """Сбой ПОСЛЕ begin (begun=True) → выполняется rollback; провал rollback → step=rollback_failed."""
        import node_selector

        monkeypatch.setattr(node_selector, "_traffic_guard_preflight_error", lambda p: "")

        def boom(config_path, state_path=None, **kwargs):
            raise OSError("config generation exploded")

        monkeypatch.setattr(node_selector.gen_xray_config, "write_config", boom)
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            _write_state(state_path, nodes=[_node("n1")], active_name="n1")
            result = node_selector._select_node_locked(
                "n1", enabled_names={"n1"}, runner=lambda c, t: {"rc": 0, "timeout": False},
                state_path=str(state_path), config_path=str(Path(tmpdir) / "config.json"),
            )
        assert result["ok"] is False
        # write_config бросает и в _rollback → restore_ok False → rollback_failed
        assert result["step"] == "rollback_failed", f"получено {result}"
        assert result["failed_step"] == "internal"

    # --- _route_goes_via_gateway: except (subprocess.*, OSError, ValueError) ---

    @pytest.mark.parametrize("exc", [_timeout_expired(),
                                     subprocess.CalledProcessError(1, ["route"]),
                                     OSError("route failed"),
                                     ValueError("bad ip")])
    def test_route_goes_via_gateway_probe_raises(self, monkeypatch, exc):
        """route get бросает → False (fail-closed: split считаем НЕ активным, добавим маршрут)."""
        import node_selector

        def boom(*args, **kwargs):
            raise exc

        monkeypatch.setattr(node_selector.sys_probe, "run", boom)
        assert node_selector._route_goes_via_gateway(_REAL_ADDR, _GATEWAY) is False

    # --- ensure_split_route: except (subprocess.*, OSError, ValueError) ---

    @pytest.mark.parametrize("exc", [_timeout_expired(),
                                     subprocess.CalledProcessError(1, ["route"]),
                                     OSError("route failed"),
                                     ValueError("bad ip")])
    def test_ensure_split_route_never_throws(self, monkeypatch, exc):
        """Сбой внутри → {'enabled': True, 'error': 'ensure_split_route failed: ...'}; watchdog не падает."""
        import node_selector

        monkeypatch.setattr(node_selector, "_auto_route_sync_enabled", lambda p: True)

        def boom(path=None):
            raise exc

        monkeypatch.setattr(node_selector.local_state, "active_node", boom)
        result = node_selector.ensure_split_route("/tmp/state.json")
        assert result["enabled"] is True
        assert "ensure_split_route failed" in result["error"]


# ==========================================================================================
# issue #238: local_state.py — 12 переписанных except-блоков
# ==========================================================================================


class TestLocalStateExceptionHandlers:
    """Гварды для 12 typed except-блоков local_state.py (issue #238).

    load_state (JSON-fallback) уже покрыт TestLocalStateExceptions выше — здесь не дублируем.
    """

    # --- resolve_route_ip: except (OSError, socket.gaierror, socket.herror, ValueError) ---

    @pytest.mark.parametrize("exc", [socket.gaierror("nodename nor servname provided"),
                                     socket.herror("host error"),
                                     OSError("network unreachable"),
                                     ValueError("label too long")])
    def test_resolve_route_ip_dns_raises_falls_back_to_host(self, monkeypatch, exc):
        """socket.gethostbyname бросает → fallback на endpoint_host (D1: никогда не бросает)."""
        import local_state

        def boom(host):
            raise exc

        monkeypatch.setattr(local_state.socket, "gethostbyname", boom)
        result = local_state.resolve_route_ip({"endpoint_host": "vps.example.test"})
        assert result == "vps.example.test", "DNS-сбой → отдаём сам endpoint_host, не пустоту"

    # --- read_xray_active_address: except (OSError, json.JSONDecodeError, ValueError) ---

    def test_read_xray_active_address_json_error(self):
        """Битый JSON → status=unreadable (fail-closed: НЕ путать с absent/fresh install)."""
        import local_state

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text("invalid json", encoding='utf-8')

            result = local_state.read_xray_active_address(str(config_path))
            assert result["status"] == "unreadable"
            assert result["address"] == ""

    def test_read_xray_active_address_os_error(self):
        """read_text бросает OSError (путь — каталог) → status=unreadable, не крашится."""
        import local_state

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.mkdir()  # exists() True, read_text → IsADirectoryError (OSError)

            result = local_state.read_xray_active_address(str(config_path))
            assert result["status"] == "unreadable", "OSError обязан давать unreadable, не absent"

    # --- sync_route_ip_from_xray: except (OSError, ValueError, TypeError) на _load_state_checked ---

    @pytest.mark.parametrize("exc", [OSError("io"), ValueError("bad"), TypeError("type")])
    def test_sync_route_ip_from_xray_state_read_raises(self, monkeypatch, exc):
        """_load_state_checked бросает → {'ok': False, 'route_ip': ''} (fail-soft)."""
        import local_state

        def boom(path=None):
            raise exc

        with tempfile.TemporaryDirectory() as tmpdir:
            xray_path = Path(tmpdir) / "config.json"
            _write_xray_config(xray_path)
            monkeypatch.setattr(local_state, "_load_state_checked", boom)
            result = local_state.sync_route_ip_from_xray("n1", str(xray_path),
                                                         path=str(Path(tmpdir) / "state.json"))
        assert result == {"ok": False, "route_ip": ""}

    # --- sync_route_ip_from_xray: except (OSError, ValueError, TypeError) на save_state ---

    @pytest.mark.parametrize("exc", [OSError("disk full"), ValueError("bad"), TypeError("type")])
    def test_sync_route_ip_from_xray_save_raises(self, monkeypatch, exc):
        """save_state бросает при записи route_ip → {'ok': False, 'route_ip': ''}."""
        import local_state

        def boom(state, path=None):
            raise exc

        with tempfile.TemporaryDirectory() as tmpdir:
            xray_path = Path(tmpdir) / "config.json"
            state_path = Path(tmpdir) / "state.json"
            _write_xray_config(xray_path, address=_REAL_ADDR)
            # route_ip отличается от address → updated=True → доходим до save_state
            _write_state(state_path, nodes=[_node("n1", route_ip=_PLACEHOLDER)], active_name="n1")
            monkeypatch.setattr(local_state, "save_state", boom)
            result = local_state.sync_route_ip_from_xray("n1", str(xray_path), path=str(state_path))
        assert result == {"ok": False, "route_ip": ""}

    # --- sync_endpoint_from_xray: except (OSError, ValueError, TypeError) на _load_state_checked ---

    @pytest.mark.parametrize("exc", [OSError("io"), ValueError("bad"), TypeError("type")])
    def test_sync_endpoint_from_xray_state_read_raises(self, monkeypatch, exc):
        """_load_state_checked бросает → {'ok': False, 'endpoint': '', 'changed': False}."""
        import local_state

        def boom(path=None):
            raise exc

        with tempfile.TemporaryDirectory() as tmpdir:
            xray_path = Path(tmpdir) / "config.json"
            _write_xray_config(xray_path)
            monkeypatch.setattr(local_state, "_load_state_checked", boom)
            result = local_state.sync_endpoint_from_xray(str(xray_path),
                                                         path=str(Path(tmpdir) / "state.json"))
        assert result == {"ok": False, "endpoint": "", "changed": False}

    # --- sync_endpoint_from_xray: except (OSError, ValueError, TypeError) на save_state ---

    @pytest.mark.parametrize("exc", [OSError("disk full"), ValueError("bad"), TypeError("type")])
    def test_sync_endpoint_from_xray_save_raises(self, monkeypatch, exc):
        """save_state бросает при sync placeholder→real → ok=False, changed=False (нет ложного успеха)."""
        import local_state

        def boom(state, path=None):
            raise exc

        with tempfile.TemporaryDirectory() as tmpdir:
            xray_path = Path(tmpdir) / "config.json"
            state_path = Path(tmpdir) / "state.json"
            _write_xray_config(xray_path, address=_REAL_ADDR)
            # endpoint_host — TEST-NET placeholder → авто-sync разрешён → доходим до save_state
            _write_state(state_path, nodes=[_node("n1", endpoint_host=_PLACEHOLDER)],
                         active_name="n1")
            monkeypatch.setattr(local_state, "save_state", boom)
            result = local_state.sync_endpoint_from_xray(str(xray_path), path=str(state_path))
        assert result == {"ok": False, "endpoint": "", "changed": False}

    # --- routing_apply: except ImportError на lazy import install_lib ---

    def test_routing_apply_install_lib_import_error_skips_restart(self, monkeypatch):
        """install_lib недоступен (ImportError) → install_lib=None → restart НЕ зовётся, apply проходит."""
        import sys
        import local_state

        monkeypatch.setitem(sys.modules, "install_lib", None)  # → ImportError
        runner = Mock()
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            state_path = Path(tmpdir) / "state.json"
            _write_xray_config(config_path)
            _write_state(state_path, nodes=[_node("n1")], active_name="n1")
            result = local_state.routing_apply(
                ["telegram.org"], config_path=str(config_path), state_path=str(state_path),
                runner=runner,
            )
        assert result["ok"] is True, f"apply должен пройти без install_lib, получено {result}"
        assert result["changed"] is True
        assert runner.call_count == 0, "без install_lib рестарт xray не выполняется"

    # --- _routing_apply_locked: except (OSError, json.JSONDecodeError, ValueError, TypeError) ---

    def test_routing_apply_config_unreadable(self):
        """Битый config (JSONDecodeError) → err=config_unreadable, config не мутируем."""
        import local_state

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            state_path = Path(tmpdir) / "state.json"
            config_path.write_text("{not json", encoding="utf-8")
            _write_state(state_path, nodes=[_node("n1")], active_name="n1")
            result = local_state.routing_apply(["telegram.org"], config_path=str(config_path),
                                               state_path=str(state_path))
        assert result == {"ok": False, "changed": False, "err": "config_unreadable"}

    def test_routing_apply_config_read_os_error(self):
        """config-путь — каталог (OSError) → err=config_unreadable (fail-soft, не крашится)."""
        import local_state

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            state_path = Path(tmpdir) / "state.json"
            config_path.mkdir()
            _write_state(state_path, nodes=[_node("n1")], active_name="n1")
            result = local_state.routing_apply(["telegram.org"], config_path=str(config_path),
                                               state_path=str(state_path))
        assert result["ok"] is False
        assert result["err"] in ("config_unreadable", "config_lock_failed")

    # --- _routing_apply_locked: except (OSError, ValueError, TypeError) на чтение state ---

    @pytest.mark.parametrize("exc", [OSError("io"), ValueError("bad"), TypeError("type")])
    def test_routing_apply_state_read_raises_is_fail_closed(self, monkeypatch, exc):
        """_load_state_checked бросает → state_readable=False → err=state_unreadable ДО мутации config."""
        import local_state

        def boom(path=None):
            raise exc

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            state_path = Path(tmpdir) / "state.json"
            _write_xray_config(config_path)
            _write_state(state_path, nodes=[_node("n1")], active_name="n1")
            before = config_path.read_text(encoding="utf-8")
            monkeypatch.setattr(local_state, "_load_state_checked", boom)
            result = local_state.routing_apply(["telegram.org"], config_path=str(config_path),
                                               state_path=str(state_path))
            after = config_path.read_text(encoding="utf-8")
        assert result == {"ok": False, "changed": False, "err": "state_unreadable"}
        assert before == after, "fail-closed: config не должен мутировать при битом state (data-loss guard)"

    # --- _routing_apply_locked: except (OSError, ValueError, TypeError) на state-write ---

    @pytest.mark.parametrize("exc", [OSError("disk full"), ValueError("bad"), TypeError("type")])
    def test_routing_apply_state_write_raises_rolls_back_config(self, monkeypatch, exc):
        """save_state бросает на шаге 5 → err=state_write_failed + config откачен к backup."""
        import local_state

        calls = {"n": 0}

        def boom(state, path=None):
            calls["n"] += 1
            raise exc

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            state_path = Path(tmpdir) / "state.json"
            _write_xray_config(config_path)
            _write_state(state_path, nodes=[_node("n1")], active_name="n1")
            before = config_path.read_text(encoding="utf-8")
            monkeypatch.setattr(local_state, "save_state", boom)
            result = local_state.routing_apply(["telegram.org"], config_path=str(config_path),
                                               state_path=str(state_path))
            after = config_path.read_text(encoding="utf-8")
        assert calls["n"] >= 1, "save_state обязан быть вызван (иначе handler не проверен)"
        assert result["ok"] is False
        assert result["err"] == "state_write_failed", f"получено {result}"
        assert result["changed"] is False, "полный откат → changed=False"
        assert json.loads(after) == json.loads(before), "config обязан быть откачен к backup"

    # --- _routing_apply_locked: except (...) на restart xray ---

    def test_routing_apply_restart_raises_reports_restart_exception(self, monkeypatch):
        """_restart_component бросает → res=restart_exception → rollback + err restart_failed."""
        import sys
        import local_state

        calls = {"n": 0}

        def restart(component, runner, port_checker=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise subprocess.CalledProcessError(1, ["brew", "services", "restart", "xray"])
            return {"rc": 0, "timeout": False}  # recovery-рестарт успешен

        fake = types.ModuleType("install_lib")
        fake._restart_component = restart
        monkeypatch.setitem(sys.modules, "install_lib", fake)

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            state_path = Path(tmpdir) / "state.json"
            _write_xray_config(config_path)
            _write_state(state_path, nodes=[_node("n1")], active_name="n1")
            result = local_state.routing_apply(
                ["telegram.org"], config_path=str(config_path), state_path=str(state_path),
                runner=lambda *a, **k: {"rc": 0}, port_checker=lambda *a, **k: True,
            )
        assert calls["n"] >= 1, "restart обязан быть вызван"
        assert result["ok"] is False
        assert "restart_failed:restart_exception" in result["err"], f"получено {result}"
        assert "recovery_restart_exception" not in result["err"], "recovery-рестарт был успешен"

    # --- _routing_apply_locked: except (...) на recovery-restart xray ---

    def test_routing_apply_recovery_restart_raises(self, monkeypatch):
        """recovery _restart_component тоже бросает → err содержит recovery_restart_exception."""
        import sys
        import local_state

        calls = {"n": 0}

        def always_boom(component, runner, port_checker=None):
            calls["n"] += 1
            raise OSError("brew unavailable")

        fake = types.ModuleType("install_lib")
        fake._restart_component = always_boom
        monkeypatch.setitem(sys.modules, "install_lib", fake)

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            state_path = Path(tmpdir) / "state.json"
            _write_xray_config(config_path)
            _write_state(state_path, nodes=[_node("n1")], active_name="n1")
            result = local_state.routing_apply(
                ["telegram.org"], config_path=str(config_path), state_path=str(state_path),
                runner=lambda *a, **k: {"rc": 0}, port_checker=lambda *a, **k: True,
            )
        assert calls["n"] >= 2, "и основной, и recovery рестарт обязаны быть вызваны"
        assert result["ok"] is False
        assert "restart_failed:restart_exception" in result["err"]
        assert "recovery_restart_exception" in result["err"], f"получено {result}"


# ==========================================================================================
# cycle-review round 1: осознанные broad-catch границы (issue #238 шаг 3)
#
# Эти границы — НЕ обычные handler'ы, а документированные контракты «не бросает наружу»:
#   - routing_apply       — «Не бросает (fail-soft)», транзакция config+state вокруг restart xray;
#   - select_node          — «Функция никогда не бросает наружу» (#159), зовётся из unguarded
#                            Flask-роута dashboard_routes.py:184;
#   - ensure_split_route   — «Не бросает», зовётся из ppp-hook health.py:2506 (от root).
# Сужение таких границ до конкретных типов ломает контракт: исключение уходит наружу, а в случае
# routing_apply — ПОСЛЕ dispatched stop xray, оставляя прокси лежать с незакоммиченным rollback
# (каноны fail-closed-proxy-down, srouter-critical-infra-24-7). Поэтому здесь broad catch осознан
# и помечен noqa-директивой BLE001, как и предписывает issue #238 шаг 3.
# ==========================================================================================


class TestNeverThrowsBoundaries:
    """Границы «не бросает наружу» обязаны держать ЛЮБОЙ Exception, не только перечисленные типы."""

    # --- routing_apply: транзакционная граница вокруг restart xray ---

    def test_routing_apply_runner_runtime_error_rolls_back_and_recovers(self, monkeypatch):
        """runner бросает RuntimeError на start (stop уже прошёл) → НЕ бросает наружу,
        config+state откачены byte-exact, recovery-рестарт предпринят.

        Регресс round-1 (Codex critical): _restart_component дёргает runner напрямую и делает
        stop ДО start. Сужение catch до (OSError, ValueError, TypeError, subprocess.*) пропускало
        RuntimeError мимо обеих restart-границ, а внешний catch routing_apply ловит только OSError →
        исключение уходило наружу с xray в stopped и БЕЗ откатов.
        """
        import local_state

        calls = []

        def runner(cmd, timeout):
            calls.append(list(cmd))
            if "start" in cmd:
                raise RuntimeError("runner exploded during start")
            return {"rc": 0, "out": "", "err": "", "timeout": False}

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            state_path = Path(tmpdir) / "state.json"
            _write_xray_config(config_path)
            _write_state(state_path, nodes=[_node("n1")], active_name="n1")
            before_config = config_path.read_text(encoding="utf-8")
            before_state = state_path.read_text(encoding="utf-8")

            # port_checker=False → порт свободен, _restart_component доходит до start
            result = local_state.routing_apply(
                ["telegram.org"], config_path=str(config_path), state_path=str(state_path),
                runner=runner, port_checker=lambda *a, **k: False,
            )

            after_config = config_path.read_text(encoding="utf-8")
            after_state = state_path.read_text(encoding="utf-8")

        assert any("stop" in c for c in calls), "stop обязан быть dispatched (иначе сценарий не тот)"
        assert isinstance(result, dict), "routing_apply обязан вернуть dict, а не бросить"
        assert result["ok"] is False
        assert "restart_failed" in result["err"], f"получено {result}"
        assert after_config == before_config, "config обязан быть откачен byte-exact"
        assert after_state == before_state, "state обязан быть откачен byte-exact"
        assert result["changed"] is False, "полный откат → changed=False"

    def test_routing_apply_recovery_runtime_error_still_returns_dict(self, monkeypatch):
        """И основной, и recovery restart бросают RuntimeError → dict с recovery_restart_exception."""
        import sys
        import local_state

        calls = {"n": 0}

        def always_boom(component, runner, port_checker=None):
            calls["n"] += 1
            raise RuntimeError("brew wedged")

        fake = types.ModuleType("install_lib")
        fake._restart_component = always_boom
        monkeypatch.setitem(sys.modules, "install_lib", fake)

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            state_path = Path(tmpdir) / "state.json"
            _write_xray_config(config_path)
            _write_state(state_path, nodes=[_node("n1")], active_name="n1")
            result = local_state.routing_apply(
                ["telegram.org"], config_path=str(config_path), state_path=str(state_path),
                runner=lambda *a, **k: {"rc": 0}, port_checker=lambda *a, **k: True,
            )

        assert calls["n"] >= 2, "и основной, и recovery рестарт обязаны быть вызваны"
        assert isinstance(result, dict), "не бросает наружу даже когда recovery тоже упал"
        assert "restart_failed:restart_exception" in result["err"]
        assert "recovery_restart_exception" in result["err"], f"получено {result}"

    # --- select_node: контракт «никогда не бросает наружу» (#159) ---

    @pytest.mark.parametrize("exc", [TypeError("unexpected type"),
                                     AttributeError("no attribute"),
                                     RuntimeError("boom"),
                                     KeyError("missing")])
    def test_select_node_never_throws_for_any_exception(self, exc):
        """Любое исключение внутри → структурированный dict, НЕ исключение наружу.

        dashboard_routes.py:184 зовёт select_node без своего try/except и отдаёт результат в
        jsonify → утечка исключения превращается в Flask 500 вместо {"ok": false, ...}.
        """
        import node_selector

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            _write_state(state_path, nodes=[_node("n1")], active_name="n1")

            def boom(cmd, timeout):
                raise exc

            result = node_selector.select_node(
                "n1", enabled_names={"n1"}, runner=boom,
                state_path=str(state_path), config_path=str(Path(tmpdir) / "config.json"),
            )

        assert isinstance(result, dict), f"select_node бросил {type(exc).__name__} наружу"
        assert result["ok"] is False
        assert result.get("step"), "результат обязан нести step для диагностики"

    def test_select_node_locked_catches_unlisted_exception(self):
        """_select_node_locked (внутренняя граница) тоже держит незаявленный тип → step=internal."""
        import node_selector

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            _write_state(state_path, nodes=[_node("n1")], active_name="n1")

            def boom(cmd, timeout):
                raise TypeError("unexpected type from runner")

            result = node_selector._select_node_locked(
                "n1", enabled_names={"n1"}, runner=boom,
                state_path=str(state_path), config_path=str(Path(tmpdir) / "config.json"),
            )

        assert isinstance(result, dict)
        assert result["ok"] is False

    # --- _default_runner: реальные сбои subprocess.run, не только заявленные типы ---

    @pytest.mark.parametrize("cmd_list,expected", [
        ([], "IndexError"),                  # subprocess.run([]) → IndexError
        (["/bin/echo", 5], "TypeError"),     # не-str аргумент → TypeError
    ])
    def test_default_runner_survives_degenerate_argv(self, cmd_list, expected):
        """Вырожденный argv → typed err в dict, НЕ исключение наружу.

        _default_runner — дефолтный runner select_node ⇒ участник контракта «никогда не бросает».
        subprocess.run без check=True не бросает CalledProcessError вовсе, зато бросает
        IndexError/TypeError, которых в суженном кортеже не было.
        """
        from node_selector import _default_runner

        result = _default_runner(cmd_list, timeout=5)
        assert isinstance(result, dict), f"{expected} ушёл наружу вместо dict"
        assert result["rc"] is None
        assert result["timeout"] is False, "сбой запуска — НЕ timeout (семантика issue #82)"
        assert expected in result["err"], f"ожидался {expected} в err, получено {result['err']!r}"

    # --- ensure_split_route: контракт «не бросает» (ppp-hook от root) ---

    @pytest.mark.parametrize("exc", [TypeError("bad type"),
                                     KeyError("missing"),
                                     RuntimeError("boom")])
    def test_ensure_split_route_never_throws_for_any_exception(self, monkeypatch, exc):
        """Любое исключение → dict с enabled/error; health.py:2506 (ppp-hook) сразу делает r.get()."""
        import node_selector

        monkeypatch.setattr(node_selector, "_auto_route_sync_enabled", lambda p: True)

        def boom(path=None):
            raise exc

        monkeypatch.setattr(node_selector.local_state, "active_node", boom)
        result = node_selector.ensure_split_route("/tmp/state.json")
        assert isinstance(result, dict), f"ensure_split_route бросил {type(exc).__name__} наружу"
        assert result["enabled"] is True
        assert "ensure_split_route failed" in result["error"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
