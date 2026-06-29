import re

import local_state


def test_host_regex_accepts_valid():
    assert local_state._is_valid_host("203.0.113.10")
    assert local_state._is_valid_host("node-1.example.com")
    assert local_state._is_valid_host("vps.local")


def test_host_regex_rejects_shell_metachars():
    # D2: shell-метасимволы запрещены в endpoint_host/route_ip
    for bad in ["a;rm -rf /", "$(reboot)", "host|cat", "a b", "x`y", "';--"]:
        assert not local_state._is_valid_host(bad), bad


def test_default_state_has_sections():
    for key in (
        "nodes",
        "active_node",
        "probes",
        "network",
        "traffic_guard",
        "detected_environment",
        "runtime",
    ):
        assert key in local_state._DEFAULT_STATE


def test_load_state_missing_file_returns_default(tmp_path):
    p = tmp_path / "missing.json"
    state = local_state.load_state(path=p)
    assert state["nodes"] == []
    assert state["active_node"] == {"name": None, "pending": None}


def test_load_state_broken_json_returns_default(tmp_path):
    p = tmp_path / "broken.json"
    p.write_text("{ not json", encoding="utf-8")
    state = local_state.load_state(path=p)
    assert state["nodes"] == []  # деградация, не исключение


def test_load_state_non_object_returns_default(tmp_path):
    p = tmp_path / "arr.json"
    p.write_text("[1,2,3]", encoding="utf-8")  # валидный JSON, но не dict
    state = local_state.load_state(path=p)
    assert isinstance(state, dict) and state["nodes"] == []


def test_load_state_valid(tmp_path):
    p = tmp_path / "ok.json"
    p.write_text('{"nodes": [{"name": "x"}], "active_node": {"name": "x"}}', encoding="utf-8")
    state = local_state.load_state(path=p)
    assert state["nodes"][0]["name"] == "x"


def test_save_then_load_roundtrip(tmp_path):
    p = tmp_path / "rt.json"
    local_state.save_state({"nodes": [{"name": "y"}], "active_node": {"name": "y"}}, path=p)
    again = local_state.load_state(path=p)
    assert again["nodes"][0]["name"] == "y"


def test_save_state_atomic_creates_file(tmp_path):
    p = tmp_path / "new.json"
    local_state.save_state({"nodes": []}, path=p)
    assert p.exists()
