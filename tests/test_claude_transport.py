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
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200"))
    monkeypatch.setattr(
        health, "_claude_proxy_probe",
        lambda: {"status": "unknown", "source": "runtime", "detail": "idle"},
    )
    monkeypatch.setattr(
        health, "_codex_proxy_probe",
        lambda: {"status": "unknown", "source": "runtime", "detail": "idle"},
    )


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
