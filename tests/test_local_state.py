import json
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


def test_preflight_state_write_uses_real_save_path(tmp_path, monkeypatch):
    """Issue #68: readable JSON ещё не значит, что atomic-write/replace проходит."""
    p = tmp_path / "srouter.local.json"
    p.write_text(json.dumps({"nodes": []}), encoding="utf-8")
    calls = []

    def fake_save_state(state, path=None):
        calls.append((state, path))
        return None

    monkeypatch.setattr(local_state, "save_state", fake_save_state)

    assert local_state.preflight_state_write(path=p) is False
    assert calls and calls[0][1] == p


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


def test_traffic_guard_validation_accepts_auto_channel_domains():
    guard = {
        "mode": "auto",
        "domains": {
            "wifi": {"video.example.com": "allow"},
            "usb_tether": {"video.example.com": "block"},
            "metered": {"heavy.example.com": "block"},
        },
    }

    assert local_state.validate_traffic_guard(guard) == []

    cfg = local_state.traffic_guard_config(state={"traffic_guard": guard}, channel="usb")

    assert cfg["mode"] == "auto"
    assert cfg["channel"] == "usb_tether"
    assert cfg["domains"] == {"video.example.com": "block"}
    assert cfg["channels"]["wifi"] == {"video.example.com": "allow"}


def test_traffic_guard_validation_rejects_invalid_auto_channel_domains():
    errors = local_state.validate_traffic_guard(
        {
            "mode": "auto",
            "domains": {
                "wifi": ["video.example.com"],
                "bluetooth": {"music.example.com": "block"},
            },
        }
    )

    assert any("wifi" in error and "object" in error for error in errors)
    assert any("channel" in error and "bluetooth" in error for error in errors)


def test_traffic_guard_validation_rejects_null_auto_channel_domains():
    errors = local_state.validate_traffic_guard({"mode": "auto", "domains": {"wifi": None}})

    assert errors == ["traffic_guard.domains.wifi must be an object"]


def test_traffic_guard_validation_rejects_empty_auto_channel_policy_map():
    errors = local_state.validate_traffic_guard({"mode": "auto", "domains": {"wifi": {}}})

    assert errors == ["traffic_guard.domains.wifi must define at least one policy"]


def test_traffic_guard_validation_rejects_empty_auto_domains():
    cases = [
        {"mode": "auto"},
        {"mode": "auto", "domains": None},
        {"mode": "auto", "domains": {}},
    ]

    for guard in cases:
        errors = local_state.validate_traffic_guard(guard)
        assert errors == ["traffic_guard.domains must define channel policies for auto mode"]


def test_traffic_guard_validation_allows_legacy_missing_or_null_domains():
    assert local_state.validate_traffic_guard({"mode": "on"}) == []
    assert local_state.validate_traffic_guard({"mode": "on", "domains": None}) == []
    assert local_state.validate_traffic_guard({"mode": "off"}) == []
    assert local_state.validate_traffic_guard({"mode": "off", "domains": None}) == []

    cfg = local_state.traffic_guard_config(state={"traffic_guard": {"mode": "on", "domains": None}})

    assert cfg["valid"] is True
    assert cfg["domains"] == {}


def test_traffic_guard_validation_rejects_auto_parent_child_conflict_per_channel():
    errors = local_state.validate_traffic_guard(
        {
            "mode": "auto",
            "domains": {
                "wifi": {"example.com": "block", "api.example.com": "allow"},
                "usb_tether": {"example.com": "block", "api.example.com": "block"},
            },
        }
    )

    assert any("wifi" in error and "example.com" in error and "api.example.com" in error for error in errors)


def test_traffic_guard_validation_rejects_throttle_policy():
    errors = local_state.validate_traffic_guard(
        {"mode": "on", "domains": {"video.example.com": "throttle"}}
    )

    assert any("throttle" in error for error in errors)


def test_traffic_guard_validation_rejects_non_string_policy_without_throwing():
    errors = local_state.validate_traffic_guard({"mode": "on", "domains": {"video.example.com": ["block"]}})

    assert any("video.example.com" in error for error in errors)


def test_traffic_guard_validation_rejects_parent_child_policy_conflict():
    errors = local_state.validate_traffic_guard(
        {"mode": "on", "domains": {"example.com": "block", "api.example.com": "allow"}}
    )

    assert any("example.com" in error and "api.example.com" in error for error in errors)


def test_traffic_guard_domain_match_exact_and_subdomain():
    assert local_state._traffic_guard_domain_matches("example.com", "example.com")
    assert local_state._traffic_guard_domain_matches("api.example.com", "example.com")
    assert not local_state._traffic_guard_domain_matches("badexample.com", "example.com")


def test_traffic_guard_validation_rejects_unsafe_domain():
    errors = local_state.validate_traffic_guard(
        {"mode": "on", "domains": {"safe.example.com;touch": "block"}}
    )

    assert any("domain" in error for error in errors)


# ============================ throttle runtime-lease (#13/#22) ============================
def test_validate_throttle_request_accepts_valid():
    domain, rate = local_state.validate_throttle_request("Video.Example.com.", 512)
    assert domain == "video.example.com"  # нормализован (lower, trailing dot снят)
    assert rate == 512


def test_validate_throttle_request_accepts_digit_string_rate():
    domain, rate = local_state.validate_throttle_request("cdn.example.net", "1500")
    assert domain == "cdn.example.net"
    assert rate == 1500


def test_validate_throttle_request_rejects_bad_rate():
    for bad in (0, -1, 1.5, "abc", "10Kbit", True, False, None, "10.5"):
        domain, rate = local_state.validate_throttle_request("example.com", bad)
        assert (domain, rate) == (None, None), bad


def test_validate_throttle_request_rejects_unsafe_domain():
    for bad in ("bad;touch.example.com", "", "..x", ".leading", "host:port", None, 123):
        domain, rate = local_state.validate_throttle_request(bad, 512)
        assert (domain, rate) == (None, None), bad


def test_save_and_load_active_throttle_roundtrip(tmp_path):
    p = tmp_path / "srouter.local.json"
    entry = {"domain": "video.example.com", "rate": 512, "token": "5", "applied_at": 1000}
    saved = local_state.save_active_throttle(entry, path=p)
    assert saved is not None
    loaded = local_state.load_active_throttle(path=p)
    # needs_cleanup=False по умолчанию (активный lease, не cleanup-lease).
    assert loaded == {
        "domain": "video.example.com", "rate": 512, "token": "5",
        "applied_at": 1000, "needs_cleanup": False,
    }


def test_save_active_throttle_preserves_other_sections(tmp_path):
    p = tmp_path / "srouter.local.json"
    base = {"schema_version": 1, "nodes": [{"name": "n1"}], "traffic_guard": {"mode": "on", "domains": {}}}
    p.write_text(json.dumps(base), encoding="utf-8")
    local_state.save_active_throttle(
        {"domain": "x.example.com", "rate": 256, "token": "9"}, path=p
    )
    state = json.loads(p.read_text(encoding="utf-8"))
    # Другие секции не затёрты.
    assert state["nodes"] == [{"name": "n1"}]
    assert state["traffic_guard"] == {"mode": "on", "domains": {}}
    assert state["runtime"]["active_throttle"]["token"] == "9"


def test_save_active_throttle_normalizes_int_token_to_string(tmp_path):
    p = tmp_path / "srouter.local.json"
    local_state.save_active_throttle({"domain": "x.example.com", "rate": 256, "token": 7}, path=p)
    loaded = local_state.load_active_throttle(path=p)
    assert loaded["token"] == "7"  # token хранится строкой (идёт в pfctl -X)


def test_save_active_throttle_rejects_invalid_entry(tmp_path):
    p = tmp_path / "srouter.local.json"
    # Битый token — не число: не пишем (иначе clear отдаст мусор в pfctl -X).
    assert local_state.save_active_throttle(
        {"domain": "x.example.com", "rate": 256, "token": "abc"}, path=p
    ) is None
    assert local_state.load_active_throttle(path=p) is None
    # Отрицательный rate.
    assert local_state.save_active_throttle(
        {"domain": "x.example.com", "rate": -1, "token": "5"}, path=p
    ) is None


def test_load_active_throttle_none_when_absent(tmp_path):
    p = tmp_path / "srouter.local.json"
    assert local_state.load_active_throttle(path=p) is None  # missing file -> default runtime, None


def test_load_active_throttle_none_for_corrupt_entry(tmp_path):
    p = tmp_path / "srouter.local.json"
    base = {"runtime": {"active_throttle": {"domain": "x.example.com", "token": "5"}}}  # нет rate
    p.write_text(json.dumps(base), encoding="utf-8")
    assert local_state.load_active_throttle(path=p) is None


def test_clear_active_throttle_resets_to_none(tmp_path):
    p = tmp_path / "srouter.local.json"
    local_state.save_active_throttle({"domain": "x.example.com", "rate": 256, "token": "5"}, path=p)
    assert local_state.load_active_throttle(path=p) is not None
    assert local_state.clear_active_throttle(path=p) is True
    assert local_state.load_active_throttle(path=p) is None
    state = json.loads(p.read_text(encoding="utf-8"))
    assert state["runtime"]["active_throttle"] is None


def test_clear_active_throttle_idempotent_when_already_none(tmp_path):
    p = tmp_path / "srouter.local.json"
    assert local_state.clear_active_throttle(path=p) is True  # missing file readable -> writes None
    assert local_state.load_active_throttle(path=p) is None


def test_save_active_throttle_refuses_unreadable_state(tmp_path):
    p = tmp_path / "srouter.local.json"
    p.write_text("{ broken json", encoding="utf-8")  # существует, но битый -> readable=False
    assert local_state.save_active_throttle(
        {"domain": "x.example.com", "rate": 256, "token": "5"}, path=p
    ) is None


def test_save_active_throttle_applied_at_optional(tmp_path):
    """applied_at отсутствует -> lease валиден (метка времени необязательна)."""
    p = tmp_path / "srouter.local.json"
    saved = local_state.save_active_throttle(
        {"domain": "x.example.com", "rate": 256, "token": "5"}, path=p  # без applied_at
    )
    assert saved is not None
    loaded = local_state.load_active_throttle(path=p)
    assert loaded["applied_at"] is None


def test_save_active_throttle_applied_at_must_be_scalar(tmp_path):
    """applied_at при наличии обязан быть числом/строкой (не dict/list) — docstring↔код."""
    p = tmp_path / "srouter.local.json"
    for bad in ({"x": 1}, [1, 2]):
        assert local_state.save_active_throttle(
            {"domain": "x.example.com", "rate": 256, "token": "5", "applied_at": bad}, path=p
        ) is None, bad
        assert local_state.load_active_throttle(path=p) is None, bad


def test_save_active_throttle_accepts_int_and_string_applied_at(tmp_path):
    p = tmp_path / "srouter.local.json"
    local_state.save_active_throttle(
        {"domain": "x.example.com", "rate": 256, "token": "5", "applied_at": 1700000000}, path=p
    )
    assert local_state.load_active_throttle(path=p)["applied_at"] == 1700000000


# ============================ sync route_ip из xray-конфига (Часть A) ============================
def _write_xray_config(p, address):
    """Минимальный xray-конфиг с vless-outbound на address (как gen_xray_config пишет)."""
    p.write_text(json.dumps({
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": address, "port": 443}]}},
        ]
    }), encoding="utf-8")


def test_sync_route_ip_from_xray_updates_node(tmp_path):
    """xray-конфиг держит реальный address (85.136.181.198), state — placeholder → sync обновляет route_ip."""
    state_p = tmp_path / "srouter.local.json"
    xray_p = tmp_path / "xray-config.json"
    _write_xray_config(xray_p, "85.136.181.198")
    _write(state_p, {"nodes": [{"name": "sg-1", "endpoint_host": "203.0.113.10",
                                 "route_ip": "203.0.113.10", "enabled": True}]})
    r = local_state.sync_route_ip_from_xray("sg-1", xray_config_path=str(xray_p), path=state_p)
    assert r["ok"] is True
    assert r["route_ip"] == "85.136.181.198"
    # state обновлён:
    node = local_state.get_node("sg-1", path=state_p)
    assert node["route_ip"] == "85.136.181.198"


def test_sync_route_ip_idempotent(tmp_path):
    """route_ip уже = xray address → no-op (ok, unchanged)."""
    state_p = tmp_path / "srouter.local.json"
    xray_p = tmp_path / "xray-config.json"
    _write_xray_config(xray_p, "85.136.181.198")
    _write(state_p, {"nodes": [{"name": "sg-1", "endpoint_host": "85.136.181.198",
                                 "route_ip": "85.136.181.198", "enabled": True}]})
    r = local_state.sync_route_ip_from_xray("sg-1", xray_config_path=str(xray_p), path=state_p)
    assert r["ok"] is True
    assert r["route_ip"] == "85.136.181.198"


def test_sync_route_ip_no_xray_config_returns_false(tmp_path):
    """xray-конфига нет → ok:False (fail-soft), state не тронут."""
    state_p = tmp_path / "srouter.local.json"
    xray_p = tmp_path / "missing-config.json"
    _write(state_p, {"nodes": [{"name": "sg-1", "endpoint_host": "203.0.113.10", "route_ip": "203.0.113.10", "enabled": True}]})
    r = local_state.sync_route_ip_from_xray("sg-1", xray_config_path=str(xray_p), path=state_p)
    assert r["ok"] is False
    assert local_state.get_node("sg-1", path=state_p)["route_ip"] == "203.0.113.10"  # не изменился


def test_sync_route_ip_unknown_node_returns_false(tmp_path):
    """Узла с таким name нет → ok:False."""
    state_p = tmp_path / "srouter.local.json"
    xray_p = tmp_path / "xray-config.json"
    _write_xray_config(xray_p, "85.136.181.198")
    _write(state_p, {"nodes": [{"name": "sg-1", "endpoint_host": "203.0.113.10", "route_ip": "203.0.113.10", "enabled": True}]})
    r = local_state.sync_route_ip_from_xray("other", xray_config_path=str(xray_p), path=state_p)
    assert r["ok"] is False


def test_sync_route_ip_broken_xray_config_returns_false(tmp_path):
    """xray-конфиг битый (не JSON) → ok:False (fail-soft)."""
    state_p = tmp_path / "srouter.local.json"
    xray_p = tmp_path / "xray-config.json"
    xray_p.write_text("{ not valid json", encoding="utf-8")
    _write(state_p, {"nodes": [{"name": "sg-1", "endpoint_host": "203.0.113.10", "route_ip": "203.0.113.10", "enabled": True}]})
    r = local_state.sync_route_ip_from_xray("sg-1", xray_config_path=str(xray_p), path=state_p)
    assert r["ok"] is False


# ============================ auto_route_sync в _DEFAULT_STATE (Часть B) ============================
def test_default_state_has_auto_route_sync_true():
    """auto_route_sync включён по умолчанию (новые инсталляции — с автосинком split-route)."""
    assert local_state._DEFAULT_STATE.get("auto_route_sync") is True
