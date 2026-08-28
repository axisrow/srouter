"""TDD: doctor covers ChatGPT.app Chromium via active macOS system SOCKS."""
import health
import system_proxy_control


NETWORK_PROCESS = (
    "96016 /Applications/ChatGPT.app/Contents/Frameworks/Codex Framework.framework/Versions/"
    "151/Helpers/Codex (Service).app/Contents/MacOS/Codex (Service) "
    "--type=utility --utility-sub-type=network.mojom.NetworkService\n"
)
GPU_PROCESS = (
    "96015 /Applications/ChatGPT.app/Contents/Frameworks/Codex Framework.framework/Versions/"
    "151/Helpers/Codex (Service).app/Contents/MacOS/Codex (Service) --type=gpu-process\n"
)


def _run(ps_out, lsof_out=""):
    def fake(cmd, timeout):
        if cmd[0] == "/bin/ps":
            return {"rc": 0, "out": ps_out, "err": "", "timeout": False}
        if cmd[0] == "/usr/sbin/lsof":
            return {"rc": 0, "out": lsof_out, "err": "", "timeout": False}
        return {"rc": 1, "out": "", "err": "unexpected", "timeout": False}
    return fake


def _route(pid, target):
    return (f"Codex\\x20 {pid} axisrow 60u IPv4 0xABC 0t0 "
            f"TCP 127.0.0.1:55689->{target} (ESTABLISHED)\n")


def _status(*, enabled):
    return {
        "status": "ok", "service": "Wi-Fi", "interface": "en0", "target": enabled,
        "socks": {"enabled": enabled, "server": "127.0.0.1", "port": 10808,
                  "authenticated": False},
    }


def test_chromium_check_reports_disabled_wifi_socks_as_root_cause(monkeypatch):
    monkeypatch.setattr(health.sys_probe, "run", _run(NETWORK_PROCESS, _route("96016", "8.8.8.8:443")))
    monkeypatch.setattr(system_proxy_control, "status", lambda: _status(enabled=False))
    res = health._codex_app_chromium_proxy_check()
    assert res["status"] == "down"
    assert "Wi-Fi" in res["detail"]
    assert "system-proxy repair" in res["detail"]
    assert "codex-app-proxy" not in res["detail"]
    assert "перезапуст" not in res["detail"].lower()


def test_chromium_check_ok_with_system_socks_and_runtime_evidence(monkeypatch):
    monkeypatch.setattr(health.sys_probe, "run",
                        _run(NETWORK_PROCESS, _route("96016", "127.0.0.1:10808")))
    monkeypatch.setattr(system_proxy_control, "status", lambda: _status(enabled=True))
    res = health._codex_app_chromium_proxy_check()
    assert res["status"] == "ok"


def test_chromium_check_still_down_if_configured_but_runtime_direct(monkeypatch):
    monkeypatch.setattr(health.sys_probe, "run", _run(NETWORK_PROCESS, _route("96016", "8.8.8.8:443")))
    monkeypatch.setattr(system_proxy_control, "status", lambda: _status(enabled=True))
    res = health._codex_app_chromium_proxy_check()
    assert res["status"] == "down"
    assert "напрямую" in res["detail"].lower()
    assert "codex-app-proxy" not in res["detail"]


NETWORK_PROCESS_2 = (
    "96017 /Applications/ChatGPT.app/Contents/Frameworks/Codex Framework.framework/Versions/"
    "151/Helpers/Codex (Service).app/Contents/MacOS/Codex (Service) "
    "--type=utility --utility-sub-type=network.mojom.NetworkService\n"
)


def test_chromium_check_down_when_one_network_pid_socks_and_other_external(monkeypatch):
    """codex-review (Codex rescue, PR #314): два NetworkService PID одновременно (перезапуск/апдейт
    App) — один держит SOCKS5, другой течёт external напрямую. Наличие ЛЮБОГО socks-сокета не должно
    маскировать реальный direct-leak другого PID (mixed → down, не ok)."""
    ps_out = NETWORK_PROCESS + NETWORK_PROCESS_2
    lsof_out = _route("96016", "127.0.0.1:10808") + _route("96017", "8.8.8.8:443")
    monkeypatch.setattr(health.sys_probe, "run", _run(ps_out, lsof_out))
    monkeypatch.setattr(system_proxy_control, "status", lambda: _status(enabled=True))
    res = health._codex_app_chromium_proxy_check()
    assert res["status"] == "down", (
        f"один PID external ДОЛЖЕН давать down, даже если другой PID через SOCKS5; got {res}"
    )


def test_non_network_chromium_helpers_are_ignored(monkeypatch):
    monkeypatch.setattr(health.sys_probe, "run", _run(GPU_PROCESS, _route("96015", "8.8.8.8:443")))
    monkeypatch.setattr(system_proxy_control, "status",
                        lambda: (_ for _ in ()).throw(AssertionError("must not inspect system proxy")))
    res = health._codex_app_chromium_proxy_check()
    assert res["status"] == "unknown"


def test_check_all_wires_chromium_system_proxy_as_doctor_driver(monkeypatch):
    monkeypatch.setattr(health, "_codex_app_chromium_proxy_check",
                        lambda: {"status": "down", "detail": "Wi-Fi SOCKS выключен"})
    monkeypatch.setattr(health, "_codex_app_proxy_check",
                        lambda: {"status": "ok", "detail": "Rust SOCKS ok"})
    monkeypatch.setattr(health, "_claude_transport_probe",
                        lambda: {"status": "unknown", "detail": "not running"})
    monkeypatch.setattr(health, "_installed_versions_check",
                        lambda: {"status": "info", "detail": "skip"})
    monkeypatch.setattr(health, "_runtime_model_override_check",
                        lambda: {"status": "info", "detail": "skip"})
    monkeypatch.setattr(health, "_codex_isolation_check",
                        lambda: {"status": "info", "detail": "skip"})
    monkeypatch.setattr(health, "_gfw_domain_check",
                        lambda: {"status": "info", "detail": "skip"})
    monkeypatch.setattr(health, "_direct_first_check",
                        lambda: {"status": "info", "detail": "skip"})
    result = health.check_all(active_claude=True)
    check = next(c for c in result["checks"] if "Chromium" in c["name"])
    assert check["ok"] is False
    assert not check.get("info")
