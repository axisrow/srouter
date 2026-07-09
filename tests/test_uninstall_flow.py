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


def _write_removable_launchagent(env):
    """Реальный srouter-managed plist на диске + detected-entry, дающий removable=True.

    _launchagent_uninstall_item: removable = managed(entry) AND marker_present(plist на диске).
    Пишем plist с LAUNCHAGENT_MARKER по env.launchagent_path() и managed-entry в detected — тогда
    plan['launchagent']['removable'] is True и _unload_launchagent доходит до bootout+poll+unlink.
    Возвращает путь к plist.
    """
    plist_path = env.launchagent_path()
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    plist_path.write_text(
        f"<?xml version='1.0'?>\n<!-- {install_lib.LAUNCHAGENT_MARKER} -->\n"
        "<plist version='1.0'><dict>"
        f"<key>Label</key><string>{install_lib.LAUNCHAGENT_LABEL}</string>"
        "</dict></plist>\n",
        encoding="utf-8")
    return plist_path


class ListRunner:
    """runner с диспетчеризацией по cmd[1]: list гонит loaded-состояния последовательно.

    canned-dict FakeRunner не умеет sequence list-состояний (нужно True→False по каждому list-вызову
    для poll'а _launchd_unload). list_states: [True/False/None,...] на каждый вызов list (держим
    последнее при исчерпании); None → timeout. bootout/unsetenv/прочее → успех.
    """
    def __init__(self, list_states):
        self.list_states = list_states
        self.calls = []
        self._i = 0

    def __call__(self, cmd, timeout):
        self.calls.append(list(cmd))
        sub = cmd[1] if len(cmd) > 1 else ""
        if sub == "list":
            idx = min(self._i, len(self.list_states) - 1)
            self._i += 1
            loaded = self.list_states[idx]
            if loaded is None:
                return {"rc": None, "out": "", "err": "timeout", "timeout": True}
            out = (install_lib.LAUNCHAGENT_LABEL + "\n") if loaded else "999\t0\tcom.other\n"
            return {"rc": 0, "out": out, "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}


def _bootouts(calls):
    return [c for c in calls if len(c) > 1 and c[1] == "bootout"]


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


def test_uninstall_restore_then_separate_stop_services_does_not_stop_restored_component(tmp_path):
    env = _env(tmp_path)
    backup = tmp_path / "privoxy.backup"
    backup.write_text("foreign config\n", encoding="utf-8")
    config = env.component_paths("privoxy")["config"]
    config.parent.mkdir(parents=True)
    config.write_text("# srouter-managed-config-v1\nlisten-address 127.0.0.1:8118\n", encoding="utf-8")
    _write_state(env, {"privoxy": _managed_component(env, "privoxy", backup)})

    restored = install_lib.apply_uninstall(env=env, confirmations={"configs": True}, runner=FakeRunner())
    assert restored["ok"] is True
    state_after_restore = json.loads(env.state_path.read_text(encoding="utf-8"))
    assert state_after_restore["detected_environment"]["privoxy"]["management"] == {
        "mode": "restored",
        "managed": False,
    }

    runner = FakeRunner()
    stopped = install_lib.apply_uninstall(env=env, confirmations={"services": True}, runner=runner)

    assert stopped["ok"] is True
    assert [install_lib.BREW, "services", "stop", "privoxy"] not in runner.calls


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


# ============================ сайт B: _unload_launchagent (bootout-and-confirm-unloaded, issue #84) ============================
def _managed_launchagent_detected():
    """detected-entry для launchagent: managed + дефолтный label (→ item['label']=LAUNCHAGENT_LABEL)."""
    return {"management": {"mode": "managed", "managed": True}}


def test_uninstall_launchagent_unlinks_after_confirmed_unload(tmp_path, monkeypatch):
    """Агент подтверждённо выгрузился (list True→False) → plist удалён, ok+changed."""
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    env = _env(tmp_path)
    plist_path = _write_removable_launchagent(env)
    _write_state(env, {"launchagent": _managed_launchagent_detected()})
    runner = ListRunner(list_states=[True, False])  # ещё висит → выгрузился

    result = install_lib.apply_uninstall(
        env=env, confirmations={"launchagent": True}, runner=runner)

    assert result["ok"] is True
    assert any(a.get("category") == "launchagent" and a.get("changed") for a in result["actions"]), \
        "launchagent-действие changed=True"
    assert not plist_path.exists(), "после подтверждённой выгрузки plist удалён"
    assert len(_bootouts(runner.calls)) == 1, "bootout ровно один раз"


def test_uninstall_launchagent_keeps_plist_when_still_loaded(tmp_path, monkeypatch):
    """ПРАЙМ-ЦЕЛЬ (тест 8): агент ещё загружен после settle → plist НЕ удалён, blocked.

    На СТАРОМ коде B (unlink безусловно после bootout) этот тест ПАДАЕТ — доказывает латентную
    гонку. settle-потолок ≈0 (иначе poll крутил бы 2с), list всегда True → state=True → fail-safe.
    Живой StartInterval-агент иначе пере-применял бы мёртвый конфиг.
    """
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_lib, "_BOOTOUT_SETTLE_MAX_WAIT", 0)
    env = _env(tmp_path)
    plist_path = _write_removable_launchagent(env)
    _write_state(env, {"launchagent": _managed_launchagent_detected()})
    runner = ListRunner(list_states=[True] * 6)  # не выгружается

    result = install_lib.apply_uninstall(
        env=env, confirmations={"launchagent": True}, runner=runner)

    assert result["ok"] is False
    assert result["blocked"] == ["launchagent_unload_failed"]
    assert plist_path.exists(), "агент ещё загружен → plist оставлен (fail-safe)"


def test_uninstall_launchagent_keeps_plist_when_list_timeout(tmp_path, monkeypatch):
    """list timeout (None = неизвестно) → fail-safe: plist НЕ удалён, blocked. None-ветка для B."""
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    env = _env(tmp_path)
    plist_path = _write_removable_launchagent(env)
    _write_state(env, {"launchagent": _managed_launchagent_detected()})
    runner = ListRunner(list_states=[None])  # list timeout → state=None

    result = install_lib.apply_uninstall(
        env=env, confirmations={"launchagent": True}, runner=runner)

    assert result["ok"] is False
    assert result["blocked"] == ["launchagent_unload_failed"]
    assert plist_path.exists(), "list timeout (неизвестно) → plist оставлен (fail-safe)"


def test_uninstall_launchagent_not_removable_is_noop(tmp_path):
    """Non-removable item (нет plist/маркера) → {ok:True, changed:False}, НЕТ bootout (ранний возврат)."""
    env = _env(tmp_path)
    # plist на диске нет → marker_present False → removable False.
    _write_state(env, {"launchagent": _managed_launchagent_detected()})
    runner = ListRunner(list_states=[False])

    result = install_lib.apply_uninstall(
        env=env, confirmations={"launchagent": True}, runner=runner)

    assert result["ok"] is True
    assert not any(a.get("category") == "launchagent" for a in result["actions"]), \
        "non-removable → нет launchagent-действия"
    assert _bootouts(runner.calls) == [], "non-removable → ранний возврат, bootout не вызван"
