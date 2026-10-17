import pytest

import srouter_cli
from test_srouter_uninstall_cmd import _args, _stub_cmd_uninstall_internals


def test_uninstall_asks_two_independent_choices_then_confirms(monkeypatch):
    _stub_cmd_uninstall_internals(monkeypatch, env_ok=True)
    events = []
    monkeypatch.setattr(srouter_cli, "_prompt_bool", lambda label: (events.append(label), False if len(events) < 3 else True)[1])
    monkeypatch.setattr(srouter_cli, "stop_uninstall_agents", lambda *a: (events.append("mutation"), {"ok": True})[1])
    assert srouter_cli.cmd_uninstall(_args(yes=False)) == 0
    assert len(events) == 4
    assert "данные" in events[0]
    assert "зависимости" in events[1]
    assert "план" in events[2]
    assert events[3] == "mutation"


def test_yes_retains_data_and_dependencies(monkeypatch):
    _stub_cmd_uninstall_internals(monkeypatch, env_ok=True, tty=False)
    def forbidden(*a, **k):
        pytest.fail("-y must neither ask nor delete data/dependencies")
    for name in ("_prompt_bool", "purge_user_data", "remove_installed_dependencies"):
        monkeypatch.setattr(srouter_cli, name, forbidden)
    assert srouter_cli.cmd_uninstall(_args()) == 0


def test_explicit_purge_and_dependency_removal_run_last(monkeypatch):
    _stub_cmd_uninstall_internals(monkeypatch, env_ok=True, tty=False)
    calls = []
    monkeypatch.setattr(srouter_cli, "_remaining_user_artifacts", lambda: (calls.append("verify"), [])[1])
    monkeypatch.setattr(srouter_cli.install_restore, "finish_file_restore", lambda *a: calls.append("history"))
    monkeypatch.setattr(srouter_cli, "remove_installed_dependencies", lambda *a: (calls.append("deps"), {"ok": True})[1])
    monkeypatch.setattr(srouter_cli, "purge_user_data", lambda *a: (calls.append("purge"), {"ok": True})[1])
    assert srouter_cli.cmd_uninstall(_args(purge=True, remove_deps=True)) == 0
    assert calls == ["verify", "history", "deps", "purge"]


@pytest.mark.parametrize("failed", ["route", "claude", "vscode", "optional", "artifact"])
def test_every_cleanup_failure_blocks_purge_and_success(monkeypatch, capsys, failed):
    _stub_cmd_uninstall_internals(monkeypatch, env_ok=True, tty=False)
    if failed == "route":
        monkeypatch.setattr(srouter_cli, "_remove_active_split_route", lambda *a: 2)
    elif failed in ("claude", "vscode"):
        monkeypatch.setattr(getattr(srouter_cli, failed + "_proxy"), "disable", lambda: {"ok": False, "err": "failed"})
    elif failed == "optional":
        monkeypatch.setattr(srouter_cli, "_remove_optional_features", lambda *a: {"ok": False, "errors": ["PF failed"]})
    else:
        monkeypatch.setattr(srouter_cli, "_remaining_user_artifacts", lambda: ["managed wrapper remains"])
    def forbidden(*a):
        pytest.fail("recovery data and dependencies must survive partial rollback")
    monkeypatch.setattr(srouter_cli, "purge_user_data", forbidden)
    monkeypatch.setattr(srouter_cli, "remove_installed_dependencies", forbidden)
    assert srouter_cli.cmd_uninstall(_args(purge=True, remove_deps=True)) == 2
    assert "частично" in capsys.readouterr().out


def test_cancel_and_non_tty_never_mutate(monkeypatch):
    _stub_cmd_uninstall_internals(monkeypatch, env_ok=True, tty=True)
    monkeypatch.setattr(srouter_cli, "_prompt_bool", lambda label: False)
    monkeypatch.setattr(srouter_cli, "stop_uninstall_agents", lambda *a: pytest.fail("cancelled"))
    assert srouter_cli.cmd_uninstall(_args(yes=False)) == 1


def test_parser_exposes_independent_flags():
    args = srouter_cli.build_parser().parse_args(["uninstall", "-y", "--purge", "--remove-deps"])
    assert args.yes and args.purge and args.remove_deps
