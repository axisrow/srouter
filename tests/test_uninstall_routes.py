import local_state
import srouter_launchd
from install_lib import ROUTE
from test_uninstall_flow import _env, _write_state

IP = "203.0.113.10"
GATEWAY = "192.0.2.1"


class Routes:
    def __init__(self):
        self.routes = {}
        self.calls = []

    def __call__(self, cmd, timeout=5):
        self.calls.append(cmd)
        ip = cmd[4]
        out, rc, err = "", 0, ""
        if cmd[2] == "get":
            if ip in self.routes:
                out = f"destination: {ip}\ngateway: {self.routes[ip]}\nflags: <UP,GATEWAY,HOST,STATIC>\n"
            else:
                out = "destination: default\ngateway: 192.0.2.1\nflags: <UP,GATEWAY,STATIC>\n"
        elif cmd[2] == "add":
            if ip in self.routes:
                rc, err = 1, "File exists"
            else:
                self.routes[ip] = cmd[5]
        elif cmd[2] == "delete":
            self.routes.pop(ip, None)
        return {"rc": rc, "out": out, "err": err, "timeout": False}


def environment(tmp_path):
    env = _env(tmp_path)
    state = _write_state(env)
    state["runtime"]["split_routes"] = {}
    local_state.save_state(state, path=env.state_path)
    return env, Routes()


def add(env, runner, ip=IP):
    return srouter_launchd.tracked_route_action("add", ip, GATEWAY,
                lambda: runner([ROUTE, "-n", "add", "-host", ip, GATEWAY]),
                runner=runner, state_path=env.state_path)


def test_uninstall_preserves_preexisting_and_unrelated_routes(tmp_path):
    env, runner = environment(tmp_path)
    runner.routes = {IP: GATEWAY, "203.0.113.99": "192.0.2.5"}
    assert add(env, runner)["rc"] == 1
    assert srouter_launchd._remove_active_split_route(env.state_path, runner) == 0
    assert runner.routes == {IP: GATEWAY, "203.0.113.99": "192.0.2.5"}


def test_uninstall_removes_all_owned_routes_even_after_active_node_changed(tmp_path):
    env, runner = environment(tmp_path)
    assert add(env, runner)["rc"] == 0
    assert add(env, runner, "203.0.113.11")["rc"] == 0
    assert srouter_launchd._remove_active_split_route(env.state_path, runner) == 0
    assert runner.routes == {}


def test_later_route_change_preserved_and_reported(tmp_path):
    env, runner = environment(tmp_path)
    assert add(env, runner)["rc"] == 0
    runner.routes[IP] = "192.0.2.9"
    assert srouter_launchd._remove_active_split_route(env.state_path, runner) == 2
    assert runner.routes[IP] == "192.0.2.9"


def test_failed_original_state_write_never_adds_route(tmp_path, monkeypatch):
    env, runner = environment(tmp_path)
    monkeypatch.setattr(local_state, "save_state", lambda *a, **k: None)
    assert add(env, runner)["rc"] != 0
    assert runner.routes == {}
    assert not any(cmd[2] == "add" for cmd in runner.calls)


def test_interrupted_ownership_promotion_keeps_route_and_recovery_data(tmp_path, monkeypatch):
    env, runner = environment(tmp_path)
    save = local_state.save_state
    def fail_promotion(state, **kwargs):
        if state.get("runtime", {}).get("split_routes", {}).get(IP, {}).get("owned"):
            return None
        return save(state, **kwargs)
    monkeypatch.setattr(local_state, "save_state", fail_promotion)
    assert add(env, runner)["rc"] != 0
    assert srouter_launchd._remove_active_split_route(env.state_path, runner) == 2
    assert runner.routes[IP] == GATEWAY


def test_legacy_route_is_never_blindly_deleted(tmp_path, monkeypatch):
    env = _env(tmp_path)
    _write_state(env)
    runner = Routes()
    runner.routes[IP] = GATEWAY
    monkeypatch.setattr(srouter_launchd, "_active_route_ip_for_removal", lambda path: IP)
    assert srouter_launchd._remove_active_split_route(env.state_path, runner) == 2
    assert runner.routes[IP] == GATEWAY
