import copy
import json
from pathlib import Path

import pytest

import gen_xray_config


ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "srouter.local.example.json"


def _dump_state(tmp_path, state):
    path = tmp_path / "srouter.local.json"
    path.write_text(json.dumps(state), encoding="utf-8")
    return path


def test_generate_config_from_example_contains_active_direct_and_probe_socks():
    cfg = gen_xray_config.generate_config(state_path=EXAMPLE)

    assert cfg["srouter"]["marker"] == gen_xray_config.MARKER
    assert cfg["srouter"]["managed"] is True

    inbounds = {item["tag"]: item for item in cfg["inbounds"]}
    assert inbounds["srouter-socks"]["port"] == 10808
    assert inbounds["probe-sg-1"]["port"] == 11080
    assert inbounds["probe-hk-1"]["port"] == 11081

    outbounds = {item["tag"]: item for item in cfg["outbounds"]}
    assert "active" in outbounds
    assert "direct" in outbounds
    assert outbounds["direct"]["protocol"] == "freedom"

    active = outbounds["active"]
    vnext = active["settings"]["vnext"][0]
    assert active["protocol"] == "vless"
    assert vnext["address"] == "203.0.113.10"
    assert vnext["port"] == 443
    assert vnext["users"][0]["id"] == "00000000-0000-4000-8000-000000000000"
    assert vnext["users"][0]["flow"] == "xtls-rprx-vision"
    assert active["streamSettings"]["realitySettings"]["publicKey"] == "PLACEHOLDER"
    assert cfg["srouter"]["active_reality_dest"] == "www.163.com:443"

    routing = cfg["routing"]["rules"]
    assert not any(rule.get("outboundTag") == "active" and rule.get("domain") for rule in routing)
    assert any(rule.get("inboundTag") == ["probe-sg-1"] and rule.get("outboundTag") == "probe-out-sg-1" for rule in routing)


def test_generate_config_sanitizes_unsafe_reality_fields(tmp_path):
    state = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    state["nodes"][0]["reality"]["sni"] = "www.163.com;rm"
    state["nodes"][0]["reality"]["dest"] = "$(touch /tmp/owned)"
    state["nodes"][0]["reality"]["short_id"] = "abc;def"
    path = _dump_state(tmp_path, state)

    rendered = json.dumps(gen_xray_config.generate_config(state_path=path), ensure_ascii=False)

    assert ";rm" not in rendered
    assert "$(touch" not in rendered
    assert "abc;def" not in rendered
    assert "203.0.113.10" in rendered


def test_generate_config_extension_api_adds_inbound_rule_and_hooks_outbound():
    def hook(outbound, *, node, role):
        updated = copy.deepcopy(outbound)
        if role == "active":
            updated["mux"] = {"enabled": False}
        return updated

    cfg = gen_xray_config.generate_config(
        state_path=EXAMPLE,
        extra_inbounds=[{"tag": "extra-socks", "listen": "127.0.0.1", "port": 12080, "protocol": "socks"}],
        extra_rules=[{"type": "field", "inboundTag": ["extra-socks"], "outboundTag": "direct"}],
        outbound_hook=hook,
    )

    assert any(item.get("tag") == "extra-socks" for item in cfg["inbounds"])
    assert any(rule.get("inboundTag") == ["extra-socks"] for rule in cfg["routing"]["rules"])
    assert next(item for item in cfg["outbounds"] if item["tag"] == "active")["mux"] == {"enabled": False}


def test_generate_config_emits_blackhole_only_for_block_domains(tmp_path):
    state = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    state["traffic_guard"] = {
        "mode": "on",
        "domains": {
            "video.example.com": "block",
            "safe.example.com": "allow",
        },
    }
    path = _dump_state(tmp_path, state)

    cfg = gen_xray_config.generate_config(state_path=path)

    outbounds = {item["tag"]: item for item in cfg["outbounds"]}
    assert outbounds["traffic-guard-blackhole"]["protocol"] == "blackhole"

    block_rules = [rule for rule in cfg["routing"]["rules"] if rule.get("outboundTag") == "traffic-guard-blackhole"]
    assert block_rules == [
        {
            "type": "field",
            "inboundTag": ["srouter-socks"],
            "domain": ["domain:video.example.com"],
            "outboundTag": "traffic-guard-blackhole",
        }
    ]
    assert all("domain:safe.example.com" not in rule.get("domain", []) for rule in block_rules)

    active_rules = [rule for rule in cfg["routing"]["rules"] if rule.get("outboundTag") == "active"]
    assert any("domain:safe.example.com" in rule.get("domain", []) for rule in active_rules)


def test_generate_config_auto_uses_explicit_channel_domains(tmp_path):
    state = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    state["traffic_guard"] = {
        "mode": "auto",
        "domains": {
            "wifi": {
                "video.example.com": "allow",
                "wifi-only.example.com": "block",
            },
            "usb_tether": {
                "video.example.com": "block",
                "safe.example.com": "allow",
            },
            "metered": {
                "metered.example.com": "block",
            },
        },
    }
    path = _dump_state(tmp_path, state)

    cfg = gen_xray_config.generate_config(state_path=path, traffic_guard_channel="usb")

    block_rules = [rule for rule in cfg["routing"]["rules"] if rule.get("outboundTag") == "traffic-guard-blackhole"]
    assert block_rules == [
        {
            "type": "field",
            "inboundTag": ["srouter-socks"],
            "domain": ["domain:video.example.com"],
            "outboundTag": "traffic-guard-blackhole",
        }
    ]

    active_rules = [rule for rule in cfg["routing"]["rules"] if rule.get("outboundTag") == "active"]
    assert any("domain:safe.example.com" in rule.get("domain", []) for rule in active_rules)
    rendered = json.dumps(cfg, ensure_ascii=False)
    assert "domain:wifi-only.example.com" not in rendered
    assert "domain:metered.example.com" not in rendered


def test_generate_config_auto_requires_channel_for_generation(tmp_path):
    state = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    state["traffic_guard"] = {
        "mode": "auto",
        "domains": {
            "wifi": {"video.example.com": "block"},
        },
    }
    path = _dump_state(tmp_path, state)
    output = tmp_path / "config.json"

    with pytest.raises(gen_xray_config.TrafficGuardValidationError) as exc:
        gen_xray_config.generate_config(state_path=path)

    assert any("traffic_guard_channel" in error for error in exc.value.errors)
    assert gen_xray_config.write_config(output, state_path=path) is False
    assert not output.exists()


def test_generate_config_auto_rejects_null_channel_domains(tmp_path):
    state = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    state["traffic_guard"] = {
        "mode": "auto",
        "domains": {
            "wifi": None,
        },
    }
    path = _dump_state(tmp_path, state)
    output = tmp_path / "config.json"

    with pytest.raises(gen_xray_config.TrafficGuardValidationError) as exc:
        gen_xray_config.generate_config(state_path=path, traffic_guard_channel="wifi")

    assert any("traffic_guard.domains.wifi must be an object" in error for error in exc.value.errors)
    assert gen_xray_config.write_config(output, state_path=path, traffic_guard_channel="wifi") is False
    assert not output.exists()


@pytest.mark.parametrize(
    "traffic_guard",
    [
        {"mode": "auto"},
        {"mode": "auto", "domains": None},
        {"mode": "auto", "domains": {}},
    ],
)
def test_generate_config_auto_rejects_empty_channel_policies(tmp_path, traffic_guard):
    state = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    state["traffic_guard"] = traffic_guard
    path = _dump_state(tmp_path, state)
    output = tmp_path / "config.json"

    errors = gen_xray_config.traffic_guard_validation_errors(state_path=path, traffic_guard_channel="wifi")

    assert errors == ["traffic_guard.domains must define channel policies for auto mode"]
    with pytest.raises(gen_xray_config.TrafficGuardValidationError) as exc:
        gen_xray_config.generate_config(state_path=path, traffic_guard_channel="wifi")
    assert exc.value.errors == errors
    assert gen_xray_config.write_config(output, state_path=path, traffic_guard_channel="wifi") is False
    assert not output.exists()


def test_generate_config_auto_uses_state_default_channel(tmp_path):
    state = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    state["traffic_guard"] = {
        "mode": "auto",
        "channel": "wifi",
        "domains": {
            "wifi": {"video.example.com": "block"},
            "usb_tether": {"video.example.com": "allow"},
        },
    }
    path = _dump_state(tmp_path, state)

    cfg = gen_xray_config.generate_config(state_path=path)

    block_rules = [rule for rule in cfg["routing"]["rules"] if rule.get("outboundTag") == "traffic-guard-blackhole"]
    assert block_rules[0]["domain"] == ["domain:video.example.com"]


@pytest.mark.parametrize(
    "traffic_guard",
    [
        {"mode": "auto", "domains": {"video.example.com": "block"}},
        {"mode": "on", "domains": {"video.example.com": "throttle"}},
        {"mode": "on", "domains": {"example.com": "block", "api.example.com": "allow"}},
        {"mode": "on", "domains": {"bad.example.com;touch": "block"}},
    ],
)
def test_generate_and_write_config_fail_closed_for_invalid_traffic_guard(tmp_path, traffic_guard):
    state = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    state["traffic_guard"] = traffic_guard
    path = _dump_state(tmp_path, state)
    output = tmp_path / "config.json"

    with pytest.raises(gen_xray_config.TrafficGuardValidationError):
        gen_xray_config.generate_config(state_path=path)

    assert gen_xray_config.write_config(output, state_path=path) is False
    assert not output.exists()


def test_generate_config_mode_off_is_valid_without_guard_rules(tmp_path):
    state = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    state["traffic_guard"] = {"mode": "off", "domains": {"video.example.com": "block"}}
    path = _dump_state(tmp_path, state)

    cfg = gen_xray_config.generate_config(state_path=path)

    rendered = json.dumps(cfg, ensure_ascii=False)
    assert "traffic-guard-blackhole" not in rendered
    assert "domain:video.example.com" not in rendered
