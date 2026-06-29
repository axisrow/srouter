import json
import re
from pathlib import Path

import local_state


def test_host_regex_accepts_valid():
    assert local_state._is_valid_host("203.0.113.10")
    assert local_state._is_valid_host("node-1.example.com")
    assert local_state._is_valid_host("vps.local")


def test_host_regex_rejects_shell_metachars():
    # D2: shell-метасимволы запрещены в endpoint_host/route_ip
    for bad in ["a;rm -rf /", "$(reboot)", "host|cat", "a b", "x`y", "';--"]:
        assert not local_state._is_valid_host(bad), bad


def test_host_regex_rejects_trailing_newline():
    assert not local_state._is_valid_host("1.2.3.4\n")


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


def test_load_state_checked_distinguishes_missing_from_broken(tmp_path):
    missing = tmp_path / "missing.json"
    missing_state, missing_readable = local_state.load_state_checked(path=missing)
    assert missing_readable is True
    assert missing_state["nodes"] == []

    broken = tmp_path / "broken.json"
    broken.write_text("{ not json", encoding="utf-8")
    broken_state, broken_readable = local_state.load_state_checked(path=broken)
    assert broken_readable is False
    assert broken_state["nodes"] == []


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


def test_save_state_unserializable_returns_none_and_cleans_tmp(tmp_path):
    p = tmp_path / "bad.json"
    result = local_state.save_state({"nodes": {object()}}, path=p)
    assert result is None
    assert not p.exists()
    assert not (tmp_path / "bad.json.tmp").exists()


def test_load_nodes_drops_invalid(tmp_path):
    p = tmp_path / "n.json"
    p.write_text(
        json.dumps(
            {
                "nodes": [
                    {"name": "ok", "endpoint_host": "203.0.113.10", "route_ip": "203.0.113.10", "enabled": True},
                    {"name": "bad_host", "endpoint_host": "a;rm", "route_ip": "a;rm", "enabled": True},
                    "not-a-dict",
                    {"name": "no_host", "enabled": True},
                ]
            }
        ),
        encoding="utf-8",
    )
    names = [n["name"] for n in local_state.load_nodes(path=p)]
    assert names == ["ok"]


def test_enabled_nodes_strict_true(tmp_path):
    p = tmp_path / "n.json"
    p.write_text(
        json.dumps(
            {
                "nodes": [
                    {"name": "a", "endpoint_host": "203.0.113.10", "route_ip": "203.0.113.10", "enabled": True},
                    {"name": "b", "endpoint_host": "203.0.113.20", "route_ip": "203.0.113.20", "enabled": False},
                    {"name": "c", "endpoint_host": "203.0.113.30", "route_ip": "203.0.113.30"},
                ]
            }
        ),
        encoding="utf-8",
    )
    names = [n["name"] for n in local_state.enabled_nodes(path=p)]
    assert names == ["a"]  # строго enabled is True


def test_get_node_returns_dict_or_empty(tmp_path):
    p = tmp_path / "n.json"
    p.write_text(
        json.dumps(
            {
                "nodes": [
                    {"name": "a", "endpoint_host": "203.0.113.10", "route_ip": "203.0.113.10", "enabled": True},
                ]
            }
        ),
        encoding="utf-8",
    )
    assert local_state.get_node("a", path=p)["name"] == "a"
    assert local_state.get_node("missing", path=p) == {}


def _write(p, state):
    p.write_text(json.dumps(state), encoding="utf-8")


def _base_state(p):
    _write(
        p,
        {
            "nodes": [
                {"name": "a", "endpoint_host": "203.0.113.10", "route_ip": "203.0.113.10", "enabled": True},
                {"name": "b", "endpoint_host": "203.0.113.20", "route_ip": "203.0.113.20", "enabled": True},
            ]
        },
    )


def test_active_node_resolves_enabled(tmp_path):
    p = tmp_path / "n.json"
    _base_state(p)
    _write(p, json.loads(p.read_text(encoding="utf-8")) | {"active_node": {"name": "b", "pending": None}})
    assert local_state.active_node(path=p)["name"] == "b"


def test_active_node_fallback_first_enabled_when_disabled(tmp_path):
    p = tmp_path / "n.json"
    _base_state(p)
    _write(p, json.loads(p.read_text(encoding="utf-8")) | {"active_node": {"name": "b", "pending": None}})
    # запретим b
    st = json.loads(p.read_text(encoding="utf-8"))
    st["nodes"][1]["enabled"] = False
    _write(p, st)
    assert local_state.active_node(path=p)["name"] == "a"  # fallback на первый enabled


def test_active_node_empty_when_no_enabled(tmp_path):
    p = tmp_path / "n.json"
    _write(p, {"nodes": []})
    assert local_state.active_node(path=p) == {}


def test_begin_writes_pending_only_for_valid_enabled(tmp_path):
    p = tmp_path / "n.json"
    _base_state(p)
    local_state.begin_active_node_change("b", path=p)
    st = local_state.load_state(path=p)
    assert st["active_node"]["pending"] == "b"
    assert st["active_node"]["name"] != "b"  # ещё не промотирован


def test_begin_rejects_unknown_node(tmp_path):
    p = tmp_path / "n.json"
    _base_state(p)
    local_state.begin_active_node_change("ghost", path=p)
    assert local_state.load_state(path=p)["active_node"].get("pending") is None


def test_begin_preserves_existing_broken_state_file(tmp_path):
    p = tmp_path / "n.json"
    broken = '{ "nodes": [{"name": "a"}], '
    p.write_text(broken, encoding="utf-8")
    local_state.begin_active_node_change("a", path=p)
    assert p.read_text(encoding="utf-8") == broken


def test_commit_promotes_after_success(tmp_path):
    p = tmp_path / "n.json"
    _base_state(p)
    local_state.begin_active_node_change("b", path=p)
    local_state.commit_active_node_change("b", path=p)
    st = local_state.load_state(path=p)
    assert st["active_node"]["name"] == "b"
    assert st["active_node"]["pending"] is None


def test_commit_does_not_promote_on_mismatch(tmp_path):
    p = tmp_path / "n.json"
    _base_state(p)
    local_state.begin_active_node_change("b", path=p)
    local_state.commit_active_node_change("a", path=p)  # другой name — не продвигаем
    st = local_state.load_state(path=p)
    assert st["active_node"]["name"] != "a"


def test_clear_pending(tmp_path):
    p = tmp_path / "n.json"
    _base_state(p)
    local_state.begin_active_node_change("b", path=p)
    local_state.clear_pending(path=p)
    assert local_state.load_state(path=p)["active_node"]["pending"] is None


def test_resolve_route_ip_ip_passthrough(tmp_path):
    p = tmp_path / "n.json"
    _write(p, {"nodes": []})  # state должен существовать для path-контракта
    assert local_state.resolve_route_ip({"name": "a", "endpoint_host": "203.0.113.10"}, path=p) == "203.0.113.10"


def test_resolve_route_ip_hostname_falls_back_when_offline(monkeypatch, tmp_path):
    # Имитируем offline: socket.gethostbyname бросает -> fallback на endpoint_host
    p = tmp_path / "n.json"
    _write(p, {"nodes": []})
    import socket as _s

    def _boom(host):
        raise _s.gaierror("offline")

    monkeypatch.setattr(_s, "gethostbyname", _boom)
    out = local_state.resolve_route_ip({"name": "a", "endpoint_host": "node.example.com"}, path=p)
    assert out == "node.example.com"  # D1: fallback на endpoint_host, не исключение


def test_resolve_route_ip_empty_for_invalid_node(tmp_path):
    p = tmp_path / "n.json"
    _write(p, {"nodes": []})
    assert local_state.resolve_route_ip({}, path=p) == ""
    assert local_state.resolve_route_ip("not-a-node", path=p) == ""


def test_resolve_route_ip_prefers_existing_route_ip(tmp_path):
    p = tmp_path / "n.json"
    _write(p, {"nodes": []})
    node = {"name": "a", "endpoint_host": "host.example.com", "route_ip": "203.0.113.77"}
    # route_ip уже задан и валиден -> используем его без DNS
    assert local_state.resolve_route_ip(node, path=p) == "203.0.113.77"


def test_looks_like_ip_rejects_ipv4_leading_zero_octet():
    assert not local_state._looks_like_ip("1.2.3.04")
    assert local_state._looks_like_ip("1.2.3.4")
    assert local_state._looks_like_ip("0.2.3.4")


def test_example_json_loads_and_has_enabled_node():
    """srouter.local.example.json — committed шаблон: парсится, 2 узла, ровно 1 enabled."""
    example = Path(__file__).resolve().parent.parent / "srouter.local.example.json"
    nodes = local_state.load_nodes(path=example)
    assert len(nodes) == 2
    assert len(local_state.enabled_nodes(path=example)) == 1


def test_example_json_active_resolves():
    """active_node example разрешается в enabled узел."""
    example = Path(__file__).resolve().parent.parent / "srouter.local.example.json"
    assert local_state.active_node(path=example)["name"] == "sg-1"
