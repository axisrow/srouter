"""TDD: explicit macOS SOCKS repair/restore for normal ChatGPT.app Dock launches."""
from types import SimpleNamespace

import local_state
import system_proxy_control


ROUTE_EN0 = "   route to: default\n  interface: en0\n"
SERVICE_ORDER = """An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)
(2) iPhone USB
(Hardware Port: iPhone USB, Device: en8)
"""


class ProxyRunner:
    def __init__(self, *, enabled=False, server="127.0.0.1", port=10808,
                 authenticated=False, fail_on=None):
        self.enabled = enabled
        self.server = server
        self.port = port
        self.authenticated = authenticated
        self.fail_on = fail_on
        self.calls = []

    def __call__(self, cmd, timeout):
        self.calls.append(list(cmd))
        if self.fail_on and cmd[1] == self.fail_on:
            return {"rc": 1, "out": "", "err": "forced failure", "timeout": False}
        if cmd == [system_proxy_control.ROUTE, "-n", "get", "default"]:
            return {"rc": 0, "out": ROUTE_EN0, "err": "", "timeout": False}
        if cmd[1:] == ["-listnetworkserviceorder"]:
            return {"rc": 0, "out": SERVICE_ORDER, "err": "", "timeout": False}
        if cmd[1:3] == ["-getsocksfirewallproxy", "Wi-Fi"]:
            out = (f"Enabled: {'Yes' if self.enabled else 'No'}\n"
                   f"Server: {self.server}\nPort: {self.port}\n"
                   f"Authenticated Proxy Enabled: {1 if self.authenticated else 0}\n")
            return {"rc": 0, "out": out, "err": "", "timeout": False}
        if cmd[1:3] == ["-setsocksfirewallproxystate", "Wi-Fi"]:
            self.enabled = cmd[3] == "on"
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        if cmd[1:3] == ["-setsocksfirewallproxy", "Wi-Fi"]:
            self.server, self.port = cmd[3], int(cmd[4])
            self.authenticated = False
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        return {"rc": 1, "out": "", "err": f"unexpected: {cmd}", "timeout": False}


def _args(tmp_path, action):
    return SimpleNamespace(system_proxy_action=action, state=str(tmp_path / "state.json"))


def test_status_resolves_active_service_from_default_interface():
    runner = ProxyRunner(enabled=False)
    st = system_proxy_control.status(runner=runner)
    assert st["status"] == "ok"
    assert st["interface"] == "en0"
    assert st["service"] == "Wi-Fi"
    assert st["socks"] == {
        "enabled": False, "server": "127.0.0.1", "port": 10808, "authenticated": False,
    }
    assert st["target"] is False


def test_repair_enables_existing_target_without_install_or_app_restart(tmp_path):
    runner = ProxyRunner(enabled=False)
    res = system_proxy_control.repair(path=tmp_path / "state.json", runner=runner)
    assert res["ok"] is True
    assert runner.enabled is True
    mutations = [c for c in runner.calls if c[1].startswith("-set")]
    assert mutations == [[system_proxy_control.NETWORKSETUP,
                          "-setsocksfirewallproxystate", "Wi-Fi", "on"]]
    saved = local_state.load_state(tmp_path / "state.json")["runtime"]["system_proxy"]
    assert saved["active"]["previous"]["enabled"] is False


def test_repair_backs_up_disabled_foreign_endpoint_then_sets_target(tmp_path):
    runner = ProxyRunner(enabled=False, server="old.proxy", port=1080)
    res = system_proxy_control.repair(path=tmp_path / "state.json", runner=runner)
    assert res["ok"] is True
    assert (runner.server, runner.port, runner.enabled) == ("127.0.0.1", 10808, True)
    active = local_state.load_state(tmp_path / "state.json")["runtime"]["system_proxy"]["active"]
    assert active["previous"]["server"] == "old.proxy"
    assert active["previous"]["port"] == 1080


def test_repair_refuses_enabled_foreign_proxy_without_mutation(tmp_path):
    runner = ProxyRunner(enabled=True, server="corp.proxy", port=1080)
    res = system_proxy_control.repair(path=tmp_path / "state.json", runner=runner)
    assert res["ok"] is False
    assert res["conflict"] is True
    assert not [c for c in runner.calls if c[1].startswith("-set")]


def test_repair_refuses_authenticated_proxy_without_mutation(tmp_path):
    runner = ProxyRunner(enabled=False, server="corp.proxy", port=1080, authenticated=True)
    res = system_proxy_control.repair(path=tmp_path / "state.json", runner=runner)
    assert res["ok"] is False
    assert not [c for c in runner.calls if c[1].startswith("-set")]


def test_repair_rolls_back_endpoint_when_enable_fails(tmp_path):
    runner = ProxyRunner(enabled=False, server="old.proxy", port=1080,
                         fail_on="-setsocksfirewallproxystate")
    res = system_proxy_control.repair(path=tmp_path / "state.json", runner=runner)
    assert res["ok"] is False
    assert (runner.server, runner.port, runner.enabled) == ("old.proxy", 1080, False)
    saved = local_state.load_state(tmp_path / "state.json")["runtime"]["system_proxy"]
    assert saved["active"] is None


def test_restore_returns_previous_state_and_clears_lease(tmp_path):
    runner = ProxyRunner(enabled=False, server="old.proxy", port=1080)
    assert system_proxy_control.repair(path=tmp_path / "state.json", runner=runner)["ok"]
    res = system_proxy_control.restore(path=tmp_path / "state.json", runner=runner)
    assert res["ok"] is True
    assert (runner.server, runner.port, runner.enabled) == ("old.proxy", 1080, False)
    saved = local_state.load_state(tmp_path / "state.json")["runtime"]["system_proxy"]
    assert saved["active"] is None


def test_restore_refuses_external_drift(tmp_path):
    runner = ProxyRunner(enabled=False)
    assert system_proxy_control.repair(path=tmp_path / "state.json", runner=runner)["ok"]
    runner.server = "changed.externally"
    res = system_proxy_control.restore(path=tmp_path / "state.json", runner=runner)
    assert res["ok"] is False
    assert res["conflict"] is True
    assert runner.server == "changed.externally"


def test_repair_fails_closed_when_active_service_unresolved(tmp_path):
    runner = ProxyRunner()

    def no_route(cmd, timeout):
        if cmd[0] == system_proxy_control.ROUTE:
            return {"rc": 1, "out": "", "err": "no route", "timeout": False}
        return runner(cmd, timeout)

    res = system_proxy_control.repair(path=tmp_path / "state.json", runner=no_route)
    assert res["ok"] is False
    assert not [c for c in runner.calls if len(c) > 1 and c[1].startswith("-set")]
