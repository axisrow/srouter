"""ТДД-тесты srouter.cmd_sync (#200): импорт endpoint из рабочего xray в local.json.

sync чинит рассинхрон источника правды: local.json (canonical) держит placeholder test-IP
203.0.113.x, а рабочий xray config — реальный VPS-address. gen_xray_config генерит из
active_node() → apply заблокирован #200 защитой. sync импортит реальный address в local.json.

Также: --force-endpoint-overwrite flag регистрируется в install-парсере (escape-hatch #200).
"""
import json
from pathlib import Path
from types import SimpleNamespace

import srouter


def _xray_vless(address):
    return json.dumps({"outbounds": [
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "active", "protocol": "vless",
         "settings": {"vnext": [{"address": address, "port": 443}]}},
    ]})


def _state_placeholder():
    return {"nodes": [{"name": "sg-1", "endpoint_host": "203.0.113.10",
                       "route_ip": "203.0.113.10", "enabled": True}],
            "active_node": {"name": "sg-1", "pending": None}}


def _args(tmp_path, **over):
    base = dict(state=str(tmp_path / "srouter.local.json"),
                xray_config=str(tmp_path / "xray-config.json"))
    base.update(over)
    return SimpleNamespace(**base)


def test_cmd_sync_imports_real_endpoint_into_placeholder(tmp_path, capsys):
    """ТДД #200-3 (CLI): sync импортит реальный address из xray в local.json placeholder."""
    state_p = tmp_path / "srouter.local.json"
    xray_p = tmp_path / "xray-config.json"
    state_p.write_text(json.dumps(_state_placeholder()), encoding="utf-8")
    xray_p.write_text(_xray_vless("85.136.181.198"), encoding="utf-8")

    rc = srouter.cmd_sync(_args(tmp_path))

    assert rc == 0
    state = json.loads(state_p.read_text(encoding="utf-8"))
    assert state["nodes"][0]["endpoint_host"] == "85.136.181.198"  # local.json правдив
    out = capsys.readouterr().out
    assert "85.136.181.198" in out


def test_cmd_sync_noop_when_already_synced(tmp_path, capsys):
    """local уже = xray → rc=0, state не тронут (idempotent)."""
    state_p = tmp_path / "srouter.local.json"
    xray_p = tmp_path / "xray-config.json"
    synced = {"nodes": [{"name": "sg-1", "endpoint_host": "85.136.181.198",
                         "route_ip": "85.136.181.198", "enabled": True}],
              "active_node": {"name": "sg-1", "pending": None}}
    state_p.write_text(json.dumps(synced), encoding="utf-8")
    xray_p.write_text(_xray_vless("85.136.181.198"), encoding="utf-8")

    rc = srouter.cmd_sync(_args(tmp_path))
    assert rc == 0
    # state не изменился
    assert json.loads(state_p.read_text(encoding="utf-8"))["nodes"][0]["endpoint_host"] == "85.136.181.198"


def test_cmd_sync_refuses_both_real_mismatch(tmp_path, capsys):
    """local реальный + xray реальный, разные → rc=1 (НЕ авто-overwrite, выбор пользователя)."""
    state_p = tmp_path / "srouter.local.json"
    xray_p = tmp_path / "xray-config.json"
    state_p.write_text(json.dumps({
        "nodes": [{"name": "sg-1", "endpoint_host": "93.184.216.34",
                   "route_ip": "93.184.216.34", "enabled": True}],
        "active_node": {"name": "sg-1", "pending": None}}), encoding="utf-8")
    xray_p.write_text(_xray_vless("85.136.181.198"), encoding="utf-8")

    rc = srouter.cmd_sync(_args(tmp_path))
    assert rc == 1
    # local.json НЕ тронут
    state = json.loads(state_p.read_text(encoding="utf-8"))
    assert state["nodes"][0]["endpoint_host"] == "93.184.216.34"


def test_cmd_sync_no_xray_config(tmp_path, capsys):
    """xray-конфига нет → rc=1 (нечего импортировать), state не тронут."""
    state_p = tmp_path / "srouter.local.json"
    state_p.write_text(json.dumps(_state_placeholder()), encoding="utf-8")

    rc = srouter.cmd_sync(_args(tmp_path))
    assert rc == 1
    assert json.loads(state_p.read_text(encoding="utf-8"))["nodes"][0]["endpoint_host"] == "203.0.113.10"


def test_cmd_sync_no_active_node(tmp_path, capsys):
    """Нет активного узла → rc=1 (нечего синхронизировать)."""
    state_p = tmp_path / "srouter.local.json"
    xray_p = tmp_path / "xray-config.json"
    state_p.write_text(json.dumps({"nodes": [], "active_node": {"name": None, "pending": None}}),
                       encoding="utf-8")
    xray_p.write_text(_xray_vless("85.136.181.198"), encoding="utf-8")

    rc = srouter.cmd_sync(_args(tmp_path))
    assert rc == 1


def test_install_parser_has_force_endpoint_overwrite_flag():
    """#200: install-парсер регистрирует --force-endpoint-overwrite (escape-hatch от apply-блока)."""
    parser = srouter.build_parser()
    # парсим install с флагом — не должен падать на unknown arg
    ns = parser.parse_args(["install", "--force-endpoint-overwrite", "-y"])
    assert getattr(ns, "force_endpoint_overwrite", False) is True


def test_sync_subcommand_registered():
    """#200: подкоманда sync зарегистрирована и ведёт на cmd_sync."""
    parser = srouter.build_parser()
    ns = parser.parse_args(["sync", "--xray-config", "/tmp/x.json"])
    assert ns.func is srouter.cmd_sync
    assert ns.xray_config == "/tmp/x.json"
