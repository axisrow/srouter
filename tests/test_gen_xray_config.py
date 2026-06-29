import copy
import json
from pathlib import Path

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
    assert any(rule.get("outboundTag") == "active" for rule in routing)
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
