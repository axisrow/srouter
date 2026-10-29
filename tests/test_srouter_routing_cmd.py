"""Тесты `srouter routing list` — marker-based ридеры (канон test_srouter_github_direct_cmd).

Ридеры ищут managed-правило по маркеру, а не по первому outboundTag-match: в конфиге
несколько reality-out правил (strict/github/ip-only) и first-match показывал чужие домены
(на живой машине — strict) и ни одного ip.
"""
import json
from types import SimpleNamespace

import srouter_cli


MANAGED = {"type": "field", "outboundTag": "reality-out", "_srouter_managed": True,
           "domain": ["domain:github.com", "domain:youtube.com"]}
IP_RULE = {"type": "field", "outboundTag": "reality-out", "_srouter_managed_ips": True,
           "ip": ["78.47.183.125", "149.154.160.0/20"]}
STRICT = {"type": "field", "outboundTag": "reality-out",
          "domain": ["domain:anthropic.com", "domain:claude.ai"]}
CATCHALL = {"type": "field", "outboundTag": "direct", "network": "tcp,udp"}


def _write_cfg(p, rules):
    p.write_text(json.dumps({"routing": {"rules": rules}}), encoding="utf-8")
    return str(p)


def _args(config):
    return SimpleNamespace(routing_subcommand="list", state=None, xray_config=config,
                           outbound=None)


def test_list_reads_managed_and_ip_rule(tmp_path, capsys):
    """Канонический конфиг: домены из managed, ip из ip-правила, [managed by srouter]."""
    cfg = _write_cfg(tmp_path / "c.json", [MANAGED, IP_RULE, CATCHALL])

    rc = srouter_cli.cmd_routing(_args(cfg))

    out = capsys.readouterr().out
    assert rc == 0
    assert "[managed by srouter]" in out
    assert "domain:github.com" in out
    assert "ip 149.154.160.0/20" in out
    assert "anthropic" not in out, "чужие (strict) домены не печатаются"


def test_list_legacy_union_dedup(tmp_path, capsys):
    """Legacy-форма (ip[] в managed) + ip-правило-подмножество → union без дублей
    (живая машина до миграции: полный состав в managed, ip-правило — подмножество)."""
    legacy = dict(MANAGED, ip=["78.47.183.125", "149.154.160.0/20"])
    subset = dict(IP_RULE, ip=["78.47.183.125"])
    cfg = _write_cfg(tmp_path / "c.json", [legacy, subset, CATCHALL])

    rc = srouter_cli.cmd_routing(_args(cfg))

    out = capsys.readouterr().out
    assert rc == 0
    assert out.count("ip 78.47.183.125") == 1, "дубль из двух источников схлопнут"
    assert "ip 149.154.160.0/20" in out


def test_list_multi_tag_order_independent(tmp_path, capsys):
    """strict-правило ПЕРЕД managed (github-split, live-форма) → managed-домены, не strict."""
    cfg = _write_cfg(tmp_path / "c.json", [STRICT, MANAGED, CATCHALL])

    rc = srouter_cli.cmd_routing(_args(cfg))

    out = capsys.readouterr().out
    assert rc == 0
    assert "domain:youtube.com" in out
    assert "anthropic" not in out, "первый tag-match (strict) не должен побеждать"


def test_list_foreign_reports_not_found(tmp_path, capsys):
    """Без маркера (foreign) → rc 2 и подсказка adopt, вместо показа чужого правила."""
    foreign = {"type": "field", "outboundTag": "reality-out",
               "domain": ["domain:example.com"]}
    cfg = _write_cfg(tmp_path / "c.json", [foreign, CATCHALL])

    rc = srouter_cli.cmd_routing(_args(cfg))

    err = capsys.readouterr().err
    assert rc == 2
    assert "не найден rule" in err
