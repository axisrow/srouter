import subprocess

import sys_probe


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


def test_port_open_uses_socket_connection(monkeypatch):
    calls = []

    def fake_create_connection(address, timeout):
        calls.append((address, timeout))
        return _FakeSocket()

    monkeypatch.setattr(sys_probe.socket, "create_connection", fake_create_connection)

    assert sys_probe.port_open("127.0.0.1", 8118, timeout=0.25) is True
    assert calls == [(("127.0.0.1", 8118), 0.25)]


def test_port_open_returns_false_on_os_error(monkeypatch):
    def fake_create_connection(_address, timeout):
        raise OSError("closed")

    monkeypatch.setattr(sys_probe.socket, "create_connection", fake_create_connection)

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

    assert sys_probe.parse_brew_services(text) == {
        "xray": "started",
        "privoxy": "stopped",
        "dnsmasq": "error",
    }


def test_brew_service_state_matches_dashboard_semantics():
    result = {"timeout": False, "out": "xray started axis\nprivoxy stopped\n"}

    assert sys_probe.brew_service_state(result, "xray") == "started"
    assert sys_probe.brew_service_state(result, "dnsmasq") == "none"
    assert sys_probe.brew_service_state({"timeout": True, "out": result["out"]}, "xray") == "unknown"
