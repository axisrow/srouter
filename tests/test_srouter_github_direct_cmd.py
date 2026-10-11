"""Тесты `srouter github-direct on|off|status` — моки на владельца (канон protect/netprobe)."""
from types import SimpleNamespace

import local_state
import srouter_cli


def _args(action, state=None, xray_config=None):
    return SimpleNamespace(github_direct_action=action, state=state, xray_config=xray_config)


def _patch_runner(monkeypatch):
    monkeypatch.setattr(srouter_cli, "make_privileged_runner",
                        lambda run=None, **k: (lambda cmd, timeout: {"rc": 0}))


def test_on_calls_transaction_and_reports(tmp_path, monkeypatch, capsys):
    seen = {}

    def fake_github_direct(action, **kwargs):
        seen["call"] = (action, kwargs)
        return {"ok": True, "changed": True, "step": "done", "direct": True}

    monkeypatch.setattr(local_state, "github_direct", fake_github_direct)
    _patch_runner(monkeypatch)

    rc = srouter_cli.cmd_github_direct(_args("on", state=str(tmp_path / "s.json"),
                                             xray_config=str(tmp_path / "c.json")))

    assert rc == 0
    assert seen["call"][0] == "on"
    assert seen["call"][1]["state_path"] == str(tmp_path / "s.json")
    assert "напрямую" in capsys.readouterr().out


def test_off_reports_tunnel(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(local_state, "github_direct",
                        lambda action, **k: {"ok": True, "changed": True,
                                             "step": "done", "direct": False})
    _patch_runner(monkeypatch)

    rc = srouter_cli.cmd_github_direct(_args("off", state=str(tmp_path / "s.json")))

    assert rc == 0
    assert "туннель" in capsys.readouterr().out


def test_noop_maps_to_rc0(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(local_state, "github_direct",
                        lambda action, **k: {"ok": True, "changed": False, "step": "noop"})
    _patch_runner(monkeypatch)

    rc = srouter_cli.cmd_github_direct(_args("on", state=str(tmp_path / "s.json")))

    assert rc == 0
    assert "уже" in capsys.readouterr().out


def test_refusal_maps_to_rc2_with_reason(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(local_state, "github_direct",
                        lambda action, **k: {"ok": False, "changed": False,
                                             "step": "restart",
                                             "err": "restart_failed:xray_port_not_up"})
    _patch_runner(monkeypatch)

    rc = srouter_cli.cmd_github_direct(_args("on", state=str(tmp_path / "s.json")))

    assert rc == 2
    assert "restart_failed" in capsys.readouterr().err


def test_status_prints_path(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(local_state, "github_direct_status",
                        lambda **k: {"ok": True, "split": True, "direct": True})
    _patch_runner(monkeypatch)

    rc = srouter_cli.cmd_github_direct(_args("status", state=str(tmp_path / "s.json")))

    assert rc == 0
    assert "напрямую" in capsys.readouterr().out
