import os
import socket
import subprocess

import sys_probe
from probe_manager import ProbeManager


class _FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def test_run_returns_dashboard_style_result(monkeypatch):
    def fake_run(cmd, capture_output, text, timeout):
        assert cmd == ["/bin/echo", "ok"]
        assert capture_output is True
        assert text is True
        assert timeout == 3
        return subprocess.CompletedProcess(cmd, 7, stdout=" out \n", stderr=" err \n")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert sys_probe.run(["/bin/echo", "ok"], 3) == {
        "rc": 7,
        "out": "out",
        "err": "err",
        "timeout": False,
    }


def test_run_maps_timeout_to_existing_shape(monkeypatch):
    def fake_run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["slow"], timeout=1)

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert sys_probe.run(["slow"], 1) == {"rc": None, "out": "", "err": "timeout", "timeout": True}


def test_run_file_not_found_is_not_timeout(monkeypatch):
    """FileNotFoundError (нет бинаря) — это НЕ timeout. ДЫРА: сейчас любой Exception → timeout=True."""
    def fake_run(*_args, **_kwargs):
        raise FileNotFoundError(2, "No such file or directory", "/no/such/binary")

    monkeypatch.setattr(subprocess, "run", fake_run)

    r = sys_probe.run(["/no/such/binary"], 3)
    assert r["timeout"] is False, f"отсутствие бинаря ≠ timeout, получили {r}"
    assert r["rc"] is None
    assert r["err"], "err должен содержать причину (не пустой)"
    assert "No such file" in r["err"] or "such" in r["err"]


def test_run_permission_error_is_not_timeout(monkeypatch):
    """PermissionError — не timeout, err с причиной."""
    def fake_run(*_args, **_kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(subprocess, "run", fake_run)

    r = sys_probe.run(["/usr/bin/whatever"], 3)
    assert r["timeout"] is False
    assert "Permission denied" in r["err"]


def test_run_os_error_is_not_timeout(monkeypatch):
    """Общий OSError (например ENOMEM/EMFILE) — не timeout, err с причиной."""
    def fake_run(*_args, **_kwargs):
        raise OSError("Too many open files")

    monkeypatch.setattr(subprocess, "run", fake_run)

    r = sys_probe.run(["/bin/echo"], 3)
    assert r["timeout"] is False
    assert "Too many open files" in r["err"]


def test_run_timeout_expired_stays_timeout(monkeypatch):
    """TimeoutExpired — единственный случай timeout=True (не ломаем существующее)."""
    def fake_run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["slow"], timeout=1)

    monkeypatch.setattr(subprocess, "run", fake_run)

    r = sys_probe.run(["slow"], 1)
    assert r["timeout"] is True
    assert r["err"] == "timeout"


def test_port_open_uses_socket_connection(monkeypatch):
    calls = []

    def fake_create_connection(address, timeout):
        calls.append((address, timeout))
        return _FakeSocket()

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    assert sys_probe.port_open("127.0.0.1", 8118, timeout=0.25) is True
    assert calls == [(("127.0.0.1", 8118), 0.25)]


def test_port_open_returns_false_on_os_error(monkeypatch):
    def fake_create_connection(_address, timeout):
        raise OSError("closed")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    assert sys_probe.port_open("127.0.0.1", 8118) is False


def test_parse_brew_services_filters_requested_components():
    text = "\n".join(
        [
            "Name Status User File",
            "xray started axis ~/Library/LaunchAgents/homebrew.mxcl.xray.plist",
            "privoxy stopped",
            "postgresql@16 started axis ~/Library/LaunchAgents/homebrew.mxcl.postgresql.plist",
            "dnsmasq error 256 root /Library/LaunchDaemons/homebrew.mxcl.dnsmasq.plist",
        ]
    )

    # Теперь по умолчанию фильтруются только brew_components
    result = sys_probe.parse_brew_services(text)
    assert "xray" in result
    assert "privoxy" in result
    assert "dnsmasq" in result
    assert "postgresql@16" not in result  # не в brew_components
    assert "Name" not in result  # заголовок тоже фильтруется


def test_brew_service_state_matches_dashboard_semantics():
    result = {"timeout": False, "out": "xray started axis\nprivoxy stopped\n"}

    assert sys_probe.brew_service_state(result, "xray") == "started"
    assert sys_probe.brew_service_state(result, "dnsmasq") == "none"
    assert sys_probe.brew_service_state({"timeout": True, "out": result["out"]}, "xray") == "unknown"


# ============================ direct_probe (вынесен из health._direct_domain_probe, #206→#197) ============================
# Прямой curl к хосту МИНУЯ прокси (env -u) — базовый слой без config, делят health (#206 GFW
# per-domain) и direct_first (#197 NO_PROXY reachability). Контракт {"reachable": bool, "kind": str}
# сохранён 1:1 из health._direct_domain_probe (health.py:203-255) — regression-гвард на #206 тестах.


def test_direct_probe_http_response_is_reachable(monkeypatch):
    """HTTP < 500 → reachable, kind=ok (сервер ответил, канал до домена работает)."""
    # Создаем тестовый менеджер с замоканным run
    class TestProbeManager(ProbeManager):
        def run(self, cmd_list, timeout, *, env=None):
            return {"rc": 0, "out": "404", "err": "", "timeout": False}

    test_manager = TestProbeManager()
    r = test_manager.direct_probe("github.com")
    assert r["reachable"] is True
    assert r["kind"] == "ok"


def test_direct_probe_timeout_is_not_reachable():
    class TestProbeManager(ProbeManager):
        def run(self, cmd_list, timeout, *, env=None):
            return {"rc": None, "out": "", "err": "", "timeout": True}

    test_manager = TestProbeManager()
    r = test_manager.direct_probe("github.com")
    assert r["reachable"] is False
    assert "timeout" in r["kind"]


def test_direct_probe_connection_failed_is_not_reachable():
    class TestProbeManager(ProbeManager):
        def run(self, cmd_list, timeout, *, env=None):
            return {"rc": 0, "out": "000", "err": "", "timeout": False}

    test_manager = TestProbeManager()
    r = test_manager.direct_probe("github.com")
    assert r["reachable"] is False
    assert r["kind"] == "connection-failed"


def test_direct_probe_5xx_reachable_but_upstream_error():
    """5xx = сервер ответил (домен достижим, не режется), но kind=upstream-error (не ok) — #207 паттерн."""
    class TestProbeManager(ProbeManager):
        def run(self, cmd_list, timeout, *, env=None):
            return {"rc": 0, "out": "503", "err": "", "timeout": False}

    test_manager = TestProbeManager()
    r = test_manager.direct_probe("github.com")
    assert r["reachable"] is True
    assert r["kind"] == "upstream-error"


def test_direct_probe_strips_proxy_env(monkeypatch):
    """Прямой curl идёт МИНУЯ прокси (env -u) — регресс-гвард канона zai-direct-no-proxy.

    sys_probe.direct_probe() зовёт _default_manager.direct_probe(), который зовёт self.run
    (bound method на _default_manager) — патч module-level sys_probe.run не перехватывает
    (issue #252 блокер: тест держался на реальной сети вместо мока).
    """
    captured = {}

    def _fake_run(cmd, timeout, env=None):
        captured["env"] = env
        return {"rc": 0, "out": "404", "err": "", "timeout": False}

    monkeypatch.setattr(sys_probe._default_manager, "run", _fake_run)
    monkeypatch.setattr(os, "environ", {"HTTPS_PROXY": "http://127.0.0.1:8118",
                                        "HTTP_PROXY": "http://127.0.0.1:8118",
                                        "ALL_PROXY": "http://127.0.0.1:8118",
                                        "NO_PROXY": "localhost"})
    sys_probe.direct_probe("github.com")
    env = captured.get("env") or {}
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
        assert key not in env, f"прямой curl минует прокси: {key} не должен попасть в env"


def test_direct_probe_never_raises_on_bad_code():
    class TestProbeManager(ProbeManager):
        def run(self, cmd_list, timeout, *, env=None):
            return {"rc": 0, "out": "garbage", "err": "", "timeout": False}

    test_manager = TestProbeManager()
    r = test_manager.direct_probe("github.com")
    assert r["reachable"] is False
    assert r["kind"] == "connection-failed"
