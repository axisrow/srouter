"""Тесты `srouter ssh route|setup|status` (#438) — моки на владельцах (канон github-direct)."""
from types import SimpleNamespace

import local_state
import srouter_cli
import ssh_client_config


def _args_route(action, state=None, xray_config=None):
    return SimpleNamespace(ssh_route_action=action, state=state, xray_config=xray_config)


def _args_setup(config=None, interval=15, countmax=4):
    return SimpleNamespace(config=config, interval=interval, countmax=countmax)


def _args_status(config=None, state=None, xray_config=None):
    return SimpleNamespace(config=config, state=state, xray_config=xray_config)


def _patch_runner(monkeypatch):
    monkeypatch.setattr(srouter_cli, "make_privileged_runner",
                        lambda run=None, **k: (lambda cmd, timeout: {"rc": 0}))


def test_route_on_calls_transaction_and_reports(tmp_path, monkeypatch, capsys):
    seen = {}

    def fake_ssh_route(action, **kwargs):
        seen["call"] = (action, kwargs)
        return {"ok": True, "changed": True, "step": "done", "on": True}

    monkeypatch.setattr(local_state, "ssh_route", fake_ssh_route)
    _patch_runner(monkeypatch)

    rc = srouter_cli.cmd_ssh_route(_args_route(
        "on", state=str(tmp_path / "s.json"), xray_config=str(tmp_path / "c.json")))

    assert rc == 0
    assert seen["call"][0] == "on"
    assert seen["call"][1]["state_path"] == str(tmp_path / "s.json")
    assert "ВКЛ" in capsys.readouterr().out


def test_route_off_reports(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(local_state, "ssh_route",
                        lambda action, **k: {"ok": True, "changed": True, "step": "done"})
    _patch_runner(monkeypatch)

    rc = srouter_cli.cmd_ssh_route(_args_route("off", state=str(tmp_path / "s.json")))

    assert rc == 0
    assert "выкл" in capsys.readouterr().out.lower()


def test_route_noop_maps_to_rc0(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(local_state, "ssh_route",
                        lambda action, **k: {"ok": True, "changed": False, "step": "noop"})
    _patch_runner(monkeypatch)

    rc = srouter_cli.cmd_ssh_route(_args_route("on", state=str(tmp_path / "s.json")))

    assert rc == 0
    assert "уже" in capsys.readouterr().out


def test_route_refusal_maps_to_rc2(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(local_state, "ssh_route",
                        lambda action, **k: {"ok": False, "changed": False, "step": "restart",
                                             "err": "restart_failed:xray_port_not_up"})
    _patch_runner(monkeypatch)

    rc = srouter_cli.cmd_ssh_route(_args_route("on", state=str(tmp_path / "s.json")))

    assert rc == 2
    assert "restart_failed" in capsys.readouterr().err


def test_route_status_prints_state(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(local_state, "ssh_route_status",
                        lambda **k: {"ok": True, "on": True})
    _patch_runner(monkeypatch)

    rc = srouter_cli.cmd_ssh_route(_args_route("status", state=str(tmp_path / "s.json")))

    assert rc == 0
    assert "ВКЛ" in capsys.readouterr().out


def test_setup_calls_owner_with_params(tmp_path, monkeypatch, capsys):
    seen = {}

    def fake_setup(config_path=None, **kwargs):
        seen["call"] = (config_path, kwargs)
        return {"ok": True, "changed": True, "backup": None,
                "managed": str(tmp_path / "srouter.conf")}

    monkeypatch.setattr(ssh_client_config, "setup", fake_setup)
    monkeypatch.setattr(ssh_client_config, "audit",
                        lambda **k: {"status": "ok", "detail": "mock ok"})

    rc = srouter_cli.cmd_ssh_setup(_args_setup(
        config=str(tmp_path / "cfg"), interval=30, countmax=3))

    assert rc == 0
    assert seen["call"][0] == str(tmp_path / "cfg")
    assert seen["call"][1]["interval"] == 30
    assert seen["call"][1]["countmax"] == 3
    assert "ok" in capsys.readouterr().out


def test_setup_failure_maps_to_rc2(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ssh_client_config, "setup",
                        lambda config_path=None, **k: {"ok": False, "changed": False,
                                                       "err": "setup_failed:OSError"})
    rc = srouter_cli.cmd_ssh_setup(_args_setup())

    assert rc == 2
    assert "setup_failed" in capsys.readouterr().err


def test_status_combines_route_and_client(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(local_state, "ssh_route_status",
                        lambda **k: {"ok": True, "on": False})
    monkeypatch.setattr(ssh_client_config, "audit",
                        lambda **k: {"status": "warn", "detail": "нет ServerAlive"})

    rc = srouter_cli.cmd_ssh_status(_args_status(state=str(tmp_path / "s.json")))

    assert rc == 0
    out = capsys.readouterr().out
    assert "route on" in out, "подсказка включения правила"
    assert "ServerAlive" in out, "клиентский аудит в выводе"
