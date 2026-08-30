"""Regression #127: proxy transport доказывает настоящий Claude Code, а не mock/lsof."""
import json

import dashboard
import health
import srouter


HTTP_PROXY = "http://127.0.0.1:8118"
SOCKS_PROXY = "socks5h://127.0.0.1:10808"


def _result(**overrides):
    result = {"rc": 1, "out": "", "err": "", "timeout": False}
    result.update(overrides)
    return result


def test_real_cli_401_proves_transport_and_environment_is_isolated(monkeypatch):
    """401 от API — положительный transport proof; user settings/NO_PROXY не участвуют."""
    seen = {}
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://api.z.ai/api/anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "real-user-key-must-not-leak")
    monkeypatch.setenv("NO_PROXY", "z.ai,.z.ai,api.anthropic.com")
    monkeypatch.setenv("no_proxy", "z.ai,.z.ai,api.anthropic.com")
    monkeypatch.setenv("ALL_PROXY", SOCKS_PROXY)
    monkeypatch.setattr(health, "_find_claude_binary", lambda: "/fake/claude")

    def fake_run(cmd, timeout, *, env=None):
        seen.update({"cmd": cmd, "timeout": timeout, "env": env})
        payload = {"type": "result", "is_error": True, "api_error_status": 401,
                   "terminal_reason": "api_error"}
        return _result(out=json.dumps(payload))

    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    result = health._claude_transport_once(HTTP_PROXY)

    assert result["status"] == "ok"
    assert result["api_status"] == 401
    assert "expected 401" in result["detail"]
    assert seen["cmd"][0] == "/fake/claude"
    assert "--bare" in seen["cmd"]
    assert seen["env"]["ANTHROPIC_BASE_URL"] == "https://api.anthropic.com"
    assert seen["env"]["ANTHROPIC_API_KEY"] != "real-user-key-must-not-leak"
    assert seen["env"]["HOME"] == seen["env"]["CLAUDE_CONFIG_DIR"].rsplit("/", 1)[0]
    for key in ("NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"):
        assert not seen["env"].get(key), f"{key} must not bypass the probe proxy"
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        assert seen["env"][key] == HTTP_PROXY


def test_unsupported_proxy_protocol_is_preserved(monkeypatch):
    monkeypatch.setattr(health, "_find_claude_binary", lambda: "/fake/claude")
    raw = "API Error: Unable to connect to API (UnsupportedProxyProtocol)"
    monkeypatch.setattr(
        health.sys_probe,
        "run",
        lambda cmd, timeout, *, env=None: _result(err=raw),
    )

    result = health._claude_transport_once(SOCKS_PROXY)

    assert result["status"] == "down"
    assert result["error"] == "UnsupportedProxyProtocol"
    assert "UnsupportedProxyProtocol" in result["detail"]


def test_connection_retries_and_timeout_without_http_are_down(monkeypatch):
    monkeypatch.setattr(health, "_find_claude_binary", lambda: "/fake/claude")
    retry = {"type": "system", "subtype": "api_retry", "error": "Connection error"}
    monkeypatch.setattr(
        health.sys_probe,
        "run",
        lambda cmd, timeout, *, env=None: _result(
            out=json.dumps(retry), err="timeout", timeout=True, rc=None
        ),
    )

    result = health._claude_transport_once(SOCKS_PROXY)

    assert result["status"] == "down"
    assert result["api_status"] is None
    assert "Connection error" in result["detail"]
    assert "timeout" in result["detail"]


def test_completed_api_retries_without_http_are_normalized(monkeypatch):
    """Если Claude исчерпал retries до нашего timeout, doctor всё равно пишет transport error."""
    monkeypatch.setattr(health, "_find_claude_binary", lambda: "/fake/claude")
    retry = {"type": "system", "subtype": "api_retry", "error": "unknown"}
    monkeypatch.setattr(
        health.sys_probe,
        "run",
        lambda cmd, timeout, *, env=None: _result(out=json.dumps(retry), rc=1),
    )

    result = health._claude_transport_once(SOCKS_PROXY)

    assert result["status"] == "down"
    assert result["error"] == "Connection error / timeout"


def test_socks_failure_with_http_401_control_is_proxy_specific(monkeypatch):
    calls = []

    def fake_once(proxy, timeout=None):
        calls.append(proxy)
        if proxy == HTTP_PROXY:
            return {"status": "ok", "proxy": proxy, "api_status": 401,
                    "error": "", "detail": "API returned expected 401"}
        return {"status": "down", "proxy": proxy, "api_status": None,
                "error": "UnsupportedProxyProtocol", "detail": "UnsupportedProxyProtocol"}

    monkeypatch.setattr(health, "_claude_transport_once", fake_once)
    result = health._claude_transport_probe(SOCKS_PROXY)

    assert calls == [SOCKS_PROXY, HTTP_PROXY]
    assert result["status"] == "down"
    assert result["error"] == "UnsupportedProxyProtocol"
    assert "HTTP control" in result["detail"]
    assert "expected 401" in result["detail"]
    assert "HTTP bridge" in result["detail"]


def _passive_health(monkeypatch):
    monkeypatch.setattr(health, "_port_up", lambda port: True)
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200", False, None))
    monkeypatch.setattr(
        health, "_claude_proxy_probe",
        lambda: {"status": "unknown", "source": "runtime", "detail": "idle"},
    )
    monkeypatch.setattr(
        health, "_codex_proxy_probe",
        lambda: {"status": "unknown", "source": "runtime", "detail": "idle"},
    )
    # #252 perf: check_all(active_claude=True) без этих моков бьёт по реальному ps/launchctl/curl
    # (GFW/direct-first делают настоящий curl к github.com/z.ai — секунды сетевого I/O на вызов).
    # См. tests/test_health.py::_all_up_monkey для канона этих же моков.
    monkeypatch.setattr(health, "_codex_app_proxy_check",
                        lambda: {"status": "unknown", "source": "n/a", "detail": "App не запущен (mock)"})
    monkeypatch.setattr(health, "_desktop_proxy_check",
                        lambda: {"status": "unknown", "detail": "launchctl (mock)"})
    monkeypatch.setattr(health, "_resolve_host", lambda host: True)
    monkeypatch.setattr(health, "_service_running", lambda label, domain=None: "running")
    monkeypatch.setattr(health, "_installed_versions_check",
                        lambda: {"status": "ok", "detail": "mock", "codex": [], "claude_code": []})
    monkeypatch.setattr(health, "_runtime_model_override_check",
                        lambda: {"status": "ok", "detail": "mock"})
    monkeypatch.setattr(health, "_privoxy_log_observability_check",
                        lambda **kw: {"status": "ok", "detail": "mock"})
    monkeypatch.setattr(health, "_codex_isolation_check",
                        lambda: {"status": "info", "detail": "mock"})
    monkeypatch.setattr(health, "_gfw_domain_check",
                        lambda *a, **kw: {"status": "ok", "detail": "mock: GFW не режет"})
    monkeypatch.setattr(health, "_direct_first_check",
                        lambda: {"status": "ok", "detail": "mock: direct-first reachable"})
    import local_state
    monkeypatch.setattr(local_state, "active_node", lambda path=None: {})


def test_check_all_runs_real_cli_only_when_explicit(monkeypatch):
    _passive_health(monkeypatch)
    calls = []
    monkeypatch.setattr(
        health, "_claude_transport_probe",
        lambda: calls.append(True) or {
            "status": "ok", "detail": "API returned expected 401", "api_status": 401,
        },
    )

    passive = health.check_all()
    active = health.check_all(active_claude=True)

    assert calls == [True]
    assert not any("real CLI" in c["name"] for c in passive["checks"])
    assert any("real CLI" in c["name"] and c["ok"] for c in active["checks"])


def test_srouter_doctor_requests_active_probe(monkeypatch):
    seen = []
    report = {"status": "ok", "checks": []}
    monkeypatch.setattr(srouter.health, "check_all",
                        lambda *, active_claude=False: seen.append(active_claude) or report)
    monkeypatch.setattr(srouter.health, "_print_report", lambda result: None)

    assert srouter.cmd_doctor(None) == 0
    assert seen == [True]


def test_dashboard_health_and_watchdog_never_request_active_probe(monkeypatch, tmp_path):
    seen = []
    report = {"status": "ok", "checks": []}

    def fake_check_all(*, active_claude=False):
        seen.append(active_claude)
        return report

    monkeypatch.setattr(health, "check_all", fake_check_all)
    monkeypatch.setattr(health, "WATCHDOG_STATE", tmp_path / "watchdog.last")
    monkeypatch.setattr(health, "_notify", lambda *args: None)

    response = dashboard.app.test_client().get("/health")
    assert response.status_code == 200
    assert health.cmd_watchdog() == 0
    assert seen == [False, False]


# --- Regression: детектор 401 разошёлся с реальным форматом stream-json ------------------
#
# Захвачено с живого Claude Code 2.1.250 (замер 2026-08-28): успешный транспорт приходит
# СТРОКОЙ api_retry с полем error_status, а НЕ result-строкой с api_error_status.
# Исходный детектор (#127, ac99000) искал api_error_status — ключ, которого CLI не пишет:
# grep -c api_error_status по живому выводу = 0. Успешная ветка была недостижима ПРИ ЛЮБОМ
# состоянии сети, а сам 401 поглощался веткой _has_api_retry → "Connection error / timeout".
# Моки старых тестов воспроизводили несуществующий формат и консервировали дефект.
_REAL_CLI_401_LINE = json.dumps({
    "type": "system", "subtype": "api_retry", "attempt": 1, "max_retries": 10,
    "retry_delay_ms": 523, "error_status": 401, "error": "authentication_failed",
    "session_id": "1aa59d24-10b4-4c71-a0f2-477e9fa9a0d1",
})
# Тот же CLI, но прокси мёртв (контроль, порт 9): error_status=null, error=unknown.
_REAL_CLI_DEAD_PROXY_LINE = json.dumps({
    "type": "system", "subtype": "api_retry", "attempt": 1, "max_retries": 10,
    "retry_delay_ms": 532, "error_status": None, "error": "unknown",
    "session_id": "1aa59d24-10b4-4c71-a0f2-477e9fa9a0d1",
})


def test_real_cli_stream_json_401_is_transport_proof(monkeypatch):
    """error_status=401 внутри api_retry = транспорт работает.

    Регрессия: детектор искал api_error_status (CLI такого не пишет) и классифицировал
    успешный 401 как "Connection error / timeout" — ложноотрицательный ❌ в srouter doctor
    при полностью исправном канале.
    """
    monkeypatch.setattr(health, "_find_claude_binary", lambda: "/fake/claude")
    monkeypatch.setattr(
        health.sys_probe, "run",
        lambda cmd, timeout, *, env=None: _result(out=_REAL_CLI_401_LINE, timeout=True),
    )

    result = health._claude_transport_once(HTTP_PROXY)

    assert result["status"] == "ok", result["detail"]
    assert result["api_status"] == 401
    assert "Connection error" not in result["detail"]


def test_real_cli_retry_without_api_response_stays_down(monkeypatch):
    """error_status=null (мёртвый прокси) — по-прежнему down. Защита от переусердствования."""
    monkeypatch.setattr(health, "_find_claude_binary", lambda: "/fake/claude")
    monkeypatch.setattr(
        health.sys_probe, "run",
        lambda cmd, timeout, *, env=None: _result(out=_REAL_CLI_DEAD_PROXY_LINE, timeout=True),
    )

    result = health._claude_transport_once(HTTP_PROXY)

    assert result["status"] == "down"
    assert "Connection error" in result["detail"]


def test_legacy_api_error_status_401_still_accepted(monkeypatch):
    """Старый формат result/api_error_status не ломаем — версии CLI могут отличаться."""
    monkeypatch.setattr(health, "_find_claude_binary", lambda: "/fake/claude")
    payload = json.dumps({"type": "result", "is_error": True, "api_error_status": 401})
    monkeypatch.setattr(
        health.sys_probe, "run",
        lambda cmd, timeout, *, env=None: _result(out=payload),
    )

    assert health._claude_transport_once(HTTP_PROXY)["status"] == "ok"
