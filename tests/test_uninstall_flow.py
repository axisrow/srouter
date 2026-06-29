import json
import plistlib
from pathlib import Path

import install_lib


class FakeRunner:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def __call__(self, cmd, timeout):
        self.calls.append(list(cmd))
        return self.responses.get(tuple(cmd), {"rc": 0, "out": "", "err": "", "timeout": False})


def _env(tmp_path):
    return install_lib.InstallEnv(
        root=Path(__file__).resolve().parent.parent,
        prefix=tmp_path / "homebrew",
        state_path=tmp_path / "srouter.local.json",
        launchagent_dir=tmp_path / "LaunchAgents",
        now="2026-06-29T00:00:00Z",
    )


def _write_state(env, detected=None, network=None):
    state = {
        "schema_version": 1,
        "nodes": [],
        "active_node": {"name": None, "pending": None},
        "probes": {},
        "network": network or {"channels": {"wifi_service": "Wi-Fi"}},
        "traffic_guard": {"mode": "off", "domains": {}},
        "detected_environment": detected or {},
        "runtime": {},
    }
    env.state_path.write_text(json.dumps(state), encoding="utf-8")
    return state


def _managed_component(env, name, backup_path):
    config_path = env.component_paths(name)["config"]
    return {
        "config_path": str(config_path),
        "backup": str(backup_path),
        "management": {"mode": "managed", "managed": True},
    }


def test_uninstall_plan_does_not_call_runner_or_touch_files(tmp_path):
    env = _env(tmp_path)
    backup = tmp_path / "privoxy.backup"
    backup.write_text("foreign config\n", encoding="utf-8")
    config = env.component_paths("privoxy")["config"]
    config.parent.mkdir(parents=True)
    config.write_text("# srouter-managed-config-v1\n", encoding="utf-8")
    _write_state(env, {"privoxy": _managed_component(env, "privoxy", backup)})
    runner = FakeRunner()

    plan = install_lib.build_uninstall_plan(env=env, runner=runner)

    assert plan["mode"] == "uninstall-plan"
    assert runner.calls == []
    assert config.read_text(encoding="utf-8") == "# srouter-managed-config-v1\n"
    assert backup.read_text(encoding="utf-8") == "foreign config\n"
    assert "srouter.local.json" in plan["user_data_retained"]


def test_uninstall_adopted_component_is_left_untouched(tmp_path):
    env = _env(tmp_path)
    config = env.component_paths("privoxy")["config"]
    config.parent.mkdir(parents=True)
    config.write_text("foreign config\n", encoding="utf-8")
    _write_state(
        env,
        {
            "privoxy": {
                "config_path": str(config),
                "management": {"mode": "adopted", "managed": False},
            }
        },
    )
    runner = FakeRunner()

    result = install_lib.apply_uninstall(
        env=env,
        confirmations={"configs": True, "services": True, "dns": True, "launchagent": True},
        runner=runner,
    )

    assert result["ok"] is True
    assert config.read_text(encoding="utf-8") == "foreign config\n"
    assert any(item["status"] == "adopted — left untouched" for item in result["components"])
    assert all("privoxy" not in call for call in runner.calls)


def test_uninstall_skipped_component_is_not_reported_as_adopted(tmp_path):
    env = _env(tmp_path)
    _write_state(
        env,
        {
            "privoxy": {
                "config_path": str(env.component_paths("privoxy")["config"]),
                "management": {"mode": "skipped", "managed": False},
            }
        },
    )

    plan = install_lib.build_uninstall_plan(env=env)
    privoxy = next(item for item in plan["components"] if item["name"] == "privoxy")

    assert privoxy["status"] == "unmanaged — left untouched"


def test_uninstall_restores_managed_config_only_after_category_confirmation(tmp_path):
    env = _env(tmp_path)
    backup = tmp_path / "privoxy.backup"
    backup.write_text("foreign config\n", encoding="utf-8")
    config = env.component_paths("privoxy")["config"]
    config.parent.mkdir(parents=True)
    config.write_text("# srouter-managed-config-v1\nlisten-address 127.0.0.1:8118\n", encoding="utf-8")
    _write_state(env, {"privoxy": _managed_component(env, "privoxy", backup)})

    skipped = install_lib.apply_uninstall(env=env, confirmations={"configs": False}, runner=FakeRunner())
    assert skipped["ok"] is True
    assert "srouter-managed-config-v1" in config.read_text(encoding="utf-8")

    restored = install_lib.apply_uninstall(env=env, confirmations={"configs": True}, runner=FakeRunner())
    assert restored["ok"] is True
    assert config.read_text(encoding="utf-8") == "foreign config\n"


def test_uninstall_does_not_delete_user_data_by_default(tmp_path):
    env = _env(tmp_path)
    backup = tmp_path / "xray.backup"
    backup.write_text('{"foreign": true}\n', encoding="utf-8")
    config = env.component_paths("xray")["config"]
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"srouter": {"marker": install_lib.MARKER}}), encoding="utf-8")
    bundle = tmp_path / "deploy-bundles" / "node.json"
    bundle.parent.mkdir()
    bundle.write_text("bundle\n", encoding="utf-8")
    _write_state(env, {"xray": _managed_component(env, "xray", backup)})

    result = install_lib.apply_uninstall(
        env=env,
        confirmations={"configs": True, "services": True, "dns": True, "launchagent": True},
        runner=FakeRunner(),
    )

    assert result["ok"] is True
    assert env.state_path.exists()
    assert backup.exists()
    assert bundle.exists()


def test_install_apply_writes_loopback_launchagent_and_records_management(tmp_path):
    env = _env(tmp_path)
    runner = FakeRunner()

    result = install_lib.apply_install(
        env=env,
        confirm=True,
        choices={"xray": "skip", "privoxy": "skip", "dnsmasq": "skip"},
        runner=runner,
        port_checker=lambda *_args, **_kwargs: False,
    )

    assert result["ok"] is True
    plist_path = env.launchagent_path()
    assert plist_path.exists()
    plist = plistlib.loads(plist_path.read_bytes())
    assert plist["Label"] == install_lib.LAUNCHAGENT_LABEL
    assert plist["RunAtLoad"] is True
    assert plist["ProgramArguments"] == [env.python_bin, str(env.root / "dashboard.py")]
    assert "0.0.0.0" not in plist_path.read_text(encoding="utf-8")
    assert [install_lib.LAUNCHCTL, "bootstrap", f"gui/{install_lib.os.getuid()}", str(plist_path)] in runner.calls

    state = json.loads(env.state_path.read_text(encoding="utf-8"))
    assert state["detected_environment"]["launchagent"]["management"] == {"mode": "managed", "managed": True}


def test_install_init_style_apply_can_skip_launchagent_lifecycle(tmp_path):
    env = _env(tmp_path)
    runner = FakeRunner()

    result = install_lib.apply_install(
        env=env,
        confirm=True,
        choices={"xray": "skip", "privoxy": "skip", "dnsmasq": "skip"},
        runner=runner,
        port_checker=lambda *_args, **_kwargs: False,
        install_launchagent=False,
    )

    assert result["ok"] is True
    assert not env.launchagent_path().exists()
    assert all(install_lib.LAUNCHCTL not in call for call in runner.calls)
