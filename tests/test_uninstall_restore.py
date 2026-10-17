"""Регрессии возврата настроек до установки; subprocess всегда подменён."""
import json

import pytest

import install_config
import install_lib
from test_uninstall_flow import FakeRunner, _env, _managed_component, _write_state


class DNSRunner(FakeRunner):
    def __init__(self, servers):
        super().__init__()
        self.servers = list(servers)
        self.fail_read = False
        self.fail_write = False

    def __call__(self, cmd, timeout):
        result = super().__call__(cmd, timeout)
        if cmd[0] == install_lib.NETWORKSETUP:
            if cmd[1] == "-getdnsservers":
                result.update(rc=1 if self.fail_read else 0,
                              out="\n".join(self.servers) if self.servers else
                              "There aren't any DNS Servers set on Wi-Fi.\n")
            elif cmd[1] == "-setdnsservers":
                if self.fail_write:
                    result["rc"] = 1
                else:
                    self.servers = [] if cmd[3:] == ["Empty"] else cmd[3:]
        return result


@pytest.fixture
def dns_env(tmp_path):
    env = _env(tmp_path)
    config = env.component_paths("dnsmasq")["config"]
    config.parent.mkdir(parents=True)
    config.write_text("# srouter-managed-config-v1\n")
    _write_state(env, {"dnsmasq": _managed_component(env, "dnsmasq", "", provenance="created")})
    return env


@pytest.mark.parametrize("original", [[], ["223.5.5.5", "1.1.1.1", "2606:4700:4700::1111"]])
def test_dns_roundtrip_restores_actual_previous_servers(dns_env, original):
    runner = DNSRunner(original)
    plan = {"network": {"channels": {"wifi_service": "Wi-Fi"}}}
    assert install_config._apply_dns(dns_env, plan, runner)["rc"] == 0
    assert runner.servers == ["127.0.0.1"]
    # Повторная установка не должна принять наш DNS за исходный.
    assert install_config._apply_dns(dns_env, plan, runner)["rc"] == 0
    result = install_lib.apply_uninstall(env=dns_env, confirmations={"dns": True}, runner=runner)
    assert result["ok"], result
    assert runner.servers == original


def test_dns_read_failure_never_changes_dns(dns_env):
    runner = DNSRunner(["223.5.5.5"])
    runner.fail_read = True
    result = install_config._apply_dns(dns_env, {"network": {"channels": {"wifi_service": "Wi-Fi"}}}, runner)
    assert result["rc"] != 0
    assert not any("-setdnsservers" in cmd for cmd in runner.calls)


def test_dns_unwritable_state_never_changes_dns(dns_env, monkeypatch):
    runner = DNSRunner(["223.5.5.5"])
    monkeypatch.setattr(install_config.local_state, "save_state", lambda *a, **k: None)
    result = install_config._apply_dns(dns_env, {"network": {"channels": {"wifi_service": "Wi-Fi"}}}, runner)
    assert result["rc"] != 0
    assert runner.servers == ["223.5.5.5"]


def test_dns_external_edit_preserved_and_reported(dns_env):
    runner = DNSRunner(["223.5.5.5"])
    install_config._apply_dns(dns_env, {"network": {"channels": {"wifi_service": "Wi-Fi"}}}, runner)
    runner.servers = ["9.9.9.9"]
    result = install_lib.apply_uninstall(env=dns_env, confirmations={"dns": True}, runner=runner)
    assert not result["ok"]
    assert runner.servers == ["9.9.9.9"]


def test_services_stop_before_restoring_config(tmp_path):
    env = _env(tmp_path)
    config = env.component_paths("privoxy")["config"]
    config.parent.mkdir(parents=True)
    config.write_text("# srouter-managed-config-v1\n")
    backup = tmp_path / "original"
    backup.write_text("foreign original\n")
    _write_state(env, {"privoxy": _managed_component(env, "privoxy", backup, provenance="overwrote")})

    class OrderRunner(FakeRunner):
        def __call__(self, cmd, timeout):
            if "services" in cmd and "stop" in cmd:
                assert "srouter-managed" in config.read_text(), "restore happened while service still running"
            return super().__call__(cmd, timeout)

    result = install_lib.apply_uninstall(env=env, confirmations={"configs": True, "services": True}, runner=OrderRunner())
    assert result["ok"]
    assert config.read_text() == "foreign original\n"


@pytest.mark.parametrize("started", [True, False])
def test_restore_original_service_state_after_reinstall(tmp_path, started):
    env = _env(tmp_path)
    config = env.component_paths("privoxy")["config"]
    config.parent.mkdir(parents=True)
    config.write_text("foreign original\n")
    _write_state(env)

    class ServiceRunner(FakeRunner):
        running = started

        def __call__(self, cmd, timeout):
            result = super().__call__(cmd, timeout)
            if cmd == [install_lib.BREW, "services", "list"]:
                result["out"] = "Name Status User File\nprivoxy " + ("started" if self.running else "none") + "\n"
            if "services" in cmd and "privoxy" in cmd:
                if "stop" in cmd:
                    self.running = False
                elif "start" in cmd:
                    self.running = True
            return result

    runner = ServiceRunner()
    for _ in range(2):
        result = install_lib.apply_install(env=env, confirm=True, install_launchagent=False,
                                          choices={"xray": "skip", "dnsmasq": "skip", "privoxy": "overwrite"},
                                          runner=runner, port_checker=lambda host, port, *a: runner.running and port == install_lib.PORTS["privoxy"][1])
        assert result["ok"], result
    result = install_lib.apply_uninstall(env=env, confirmations={"configs": True, "services": True}, runner=runner)
    assert result["ok"], result
    assert runner.running is started
    assert config.read_text() == "foreign original\n"


def test_system_dnsmasq_state_does_not_depend_on_user_brew_table(tmp_path):
    import install_cleanup
    env = _env(tmp_path)
    _write_state(env)
    class RootDNS(FakeRunner):
        running = True
        def __call__(self, cmd, timeout):
            result = super().__call__(cmd, timeout)
            if cmd[:2] == ['/bin/launchctl', 'print'] and cmd[-1] == 'system/sh.brew.dnsmasq':
                result.update(rc=0 if self.running else 113, out='state = running\n' if self.running else '')
            if cmd == [install_lib.SUDO, install_lib.BREW, 'services', 'start', 'dnsmasq']:
                self.running = True
            return result
    runner = RootDNS()
    item = {'config_path': str(env.component_paths('dnsmasq')['config']), 'service': 'none'}
    assert not install_config._record_service_original(env, 'dnsmasq', item, runner)
    state = install_config.local_state.load_state(path=env.state_path)
    assert state['detected_environment']['dnsmasq']['service_restore']['status'] == 'started'
    runner.running = False
    assert install_cleanup._resume_service('dnsmasq', runner)


def test_uninstall_recognizes_committed_isolation_agent_markers(tmp_path):
    from pathlib import Path
    import install_cleanup
    from test_uninstall_flow import _env
    env = _env(tmp_path)
    env.launchagent_dir.mkdir(parents=True)
    labels = ('com.srouter.isolate', 'com.srouter.isolate-escape', 'com.srouter.isolate-refresh')
    for label in labels:
        (env.launchagent_dir / (label + '.plist')).write_bytes(
            (Path(__file__).resolve().parents[1] / 'launchagents' / (label + '.plist')).read_bytes())
    agents = install_cleanup._extra_launchagents(env)
    assert len(agents) == 3
    assert all(agent['removable'] for agent in agents)
