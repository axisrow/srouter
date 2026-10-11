"""Тесты `srouter node use <name>`: canonical → select_node, adopt → select_node_surgical.

Инцидент 2026-10-11: смена узла на adopt-машине была ручной хирургией конфига.
Моки ставим на ВЛАДЕЛЬЦА (node_selector) + srouter_cli.make_privileged_runner —
канон test_srouter_protect_cmd/test_srouter_netprobe_cmd.
"""
import json
from types import SimpleNamespace

import node_selector
import srouter_cli


def _args(name="hk-1", state=None, xray_config=None):
    """args как argparse отдаёт для `srouter node use <name> [--state] [--xray-config]`."""
    return SimpleNamespace(node_subcommand="use", name=name, state=state, xray_config=xray_config)


def _write_state(path, state):
    path.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")


def _state():
    return {
        "schema_version": 1,
        "nodes": [
            {"name": "sg-1", "endpoint_host": "203.0.113.10", "port": 443, "enabled": True},
            {"name": "hk-1", "endpoint_host": "203.0.113.20", "port": 443, "enabled": True},
        ],
        "active_node": {"name": "sg-1", "pending": None},
    }


def _patch_runner(monkeypatch):
    monkeypatch.setattr(srouter_cli, "make_privileged_runner",
                        lambda run=None, **k: (lambda cmd, timeout: {"rc": 0}))


def test_adopt_mode_falls_back_to_surgical(tmp_path, monkeypatch, capsys):
    """select_node вернул adopt-mode → cmd_node падает в surgical с теми же путями."""
    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, _state())
    seen = {}

    def fake_select(name, **kwargs):
        seen["select"] = kwargs
        return {"ok": False, "step": "adopt-mode", "active": "sg-1"}

    monkeypatch.setattr(node_selector, "select_node", fake_select)

    def fake_surgical(name, **kwargs):
        seen["surgical"] = (name, kwargs)
        return {"ok": True, "changed": True, "step": "done", "from": "sg-1", "to": "hk-1"}

    monkeypatch.setattr(node_selector, "select_node_surgical", fake_surgical)
    _patch_runner(monkeypatch)

    rc = srouter_cli.cmd_node(_args("hk-1", state=str(state_path),
                                    xray_config=str(tmp_path / "config.json")))

    assert rc == 0
    assert "select" in seen and "surgical" in seen, "adopt-mode → fallback в surgical"
    assert seen["surgical"][0] == "hk-1"
    assert seen["surgical"][1]["state_path"] == str(state_path)
    assert seen["surgical"][1]["config_path"] == str(tmp_path / "config.json")
    out = capsys.readouterr().out
    assert "sg-1" in out and "hk-1" in out, "печатает from → to"


def test_canonical_ok_never_touches_surgical(tmp_path, monkeypatch, capsys):
    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, _state())
    monkeypatch.setattr(node_selector, "select_node",
                        lambda *a, **k: {"ok": True, "active": "hk-1", "step": "done"})

    def _boom(*a, **k):
        raise AssertionError("surgical не должен зваться на canonical-пути")

    monkeypatch.setattr(node_selector, "select_node_surgical", _boom)
    _patch_runner(monkeypatch)

    rc = srouter_cli.cmd_node(_args("hk-1", state=str(state_path),
                                    xray_config=str(tmp_path / "config.json")))

    assert rc == 0
    assert "hk-1" in capsys.readouterr().out


def test_surgical_refusal_maps_to_rc2_with_hint(tmp_path, monkeypatch, capsys):
    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, _state())
    monkeypatch.setattr(node_selector, "select_node",
                        lambda *a, **k: {"ok": False, "step": "adopt-mode", "active": "sg-1"})
    monkeypatch.setattr(node_selector, "select_node_surgical",
                        lambda name, **k: {"ok": False, "changed": False,
                                           "step": "validate", "err": "placeholder_reality"})
    _patch_runner(monkeypatch)

    rc = srouter_cli.cmd_node(_args("hk-1", state=str(state_path),
                                    xray_config=str(tmp_path / "config.json")))

    assert rc == 2
    captured = capsys.readouterr()
    assert "placeholder_reality" in captured.err
    assert "placeholder" in captured.err.lower(), "человековая подсказка про state"


def test_unknown_node_refuses_before_runner(tmp_path, monkeypatch, capsys):
    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, _state())

    def _boom(*a, **k):
        raise AssertionError("select не должен зваться для неизвестного узла")

    monkeypatch.setattr(node_selector, "select_node", _boom)
    monkeypatch.setattr(srouter_cli, "make_privileged_runner",
                        lambda run=None, **k: (_ for _ in ()).throw(
                            AssertionError("runner не должен создаваться")))

    rc = srouter_cli.cmd_node(_args("zz-9", state=str(state_path),
                                    xray_config=str(tmp_path / "config.json")))

    assert rc == 2
    assert "zz-9" in capsys.readouterr().err


def test_noop_maps_to_rc0(tmp_path, monkeypatch, capsys):
    state_path = tmp_path / "srouter.local.json"
    _write_state(state_path, _state())
    monkeypatch.setattr(node_selector, "select_node",
                        lambda *a, **k: {"ok": False, "step": "adopt-mode", "active": "hk-1"})
    monkeypatch.setattr(node_selector, "select_node_surgical",
                        lambda name, **k: {"ok": True, "changed": False, "step": "noop",
                                           "from": "hk-1", "to": "hk-1"})
    _patch_runner(monkeypatch)

    rc = srouter_cli.cmd_node(_args("hk-1", state=str(state_path),
                                    xray_config=str(tmp_path / "config.json")))

    assert rc == 0
    assert "уже активен" in capsys.readouterr().out
