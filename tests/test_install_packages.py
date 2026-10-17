import install_cleanup
import install_config
import local_state
from test_uninstall_flow import _env, _write_state


class Brew:
    def __init__(self):
        self.packages = {"preexisting"}
        self.users = {"lib": ["xray"]}
        self.calls = []
        self.fail_remove = False
        self.running = set()

    def __call__(self, cmd, timeout):
        self.calls.append(cmd)
        if cmd[:2] == ["/usr/bin/env", "HOMEBREW_NO_AUTOREMOVE=1"]:
            cmd = cmd[2:]
        args = cmd[1:]
        out, rc = "", 0
        if cmd[0] == '/bin/launchctl':
            rc = 0 if 'dnsmasq' in self.running and cmd[-1] == 'system/sh.brew.dnsmasq' else 113
            out = 'state = running\n' if rc == 0 else ''
        elif args == ['services', 'list']:
            out = 'Name Status User File\n' + '\n'.join(name+' started' for name in sorted(self.running))
        elif args == ["list", "--formula"]:
            out = "\n".join(sorted(self.packages))
        elif args[:2] == ["list", "--versions"]:
            out = args[-1] + " 1.0" if args[-1] in self.packages else ""
            rc = 0 if out else 1
        elif args == ["install", "xray"]:
            self.packages.update({"xray", "lib"})
        elif args[:2] == ["deps", "--installed"]:
            out = "lib\npreexisting\n"
        elif args[0] == "uses":
            out = "\n".join(name for name in self.users.get(args[-1], []) if name in self.packages)
        elif args[:2] == ["uninstall", "--formula"]:
            if self.fail_remove or args[-1] not in self.packages:
                rc = 1
            else:
                self.packages.remove(args[-1])
        return {"rc": rc, "out": out, "err": "", "timeout": False}


def installed(tmp_path):
    env = _env(tmp_path)
    _write_state(env)
    runner = Brew()
    assert not install_config._record_package_intent(env, "xray", runner)
    assert install_config._ensure_package("xray", runner)
    assert not install_config._record_package_result(env, "xray", runner)
    return env, runner


def test_remove_only_own_dependencies_and_keep_preexisting(tmp_path):
    env, runner = installed(tmp_path)
    assert local_state.load_state(path=env.state_path)["detected_environment"]["packages"]["owned"] == ["lib", "xray"]
    result = install_cleanup.remove_installed_dependencies(env, runner)
    assert result["ok"], result
    assert runner.packages == {"preexisting"}


def test_shared_dependency_is_preserved(tmp_path):
    env, runner = installed(tmp_path)
    runner.packages.add("foreign-app")
    runner.users["lib"].append("foreign-app")
    result = install_cleanup.remove_installed_dependencies(env, runner)
    assert result["ok"], result
    assert runner.packages == {"preexisting", "lib", "foreign-app"}
    assert result["kept"] == [{"name": "lib", "used_by": ["foreign-app"]}]


def test_homebrew_autoremove_cannot_delete_unowned_unused_formulae(tmp_path):
    env, brew = installed(tmp_path)
    brew.packages.add("foreign-unused")
    def runner(cmd, timeout):
        if cmd[:3] == [install_config.BREW, "uninstall", "--formula"]:
            brew.packages.discard("foreign-unused")
        return brew(cmd, timeout)
    assert install_cleanup.remove_installed_dependencies(env, runner)["ok"]
    assert "foreign-unused" in brew.packages


def test_dependency_removal_preserves_restored_running_service_and_its_libraries(tmp_path):
    env, runner = installed(tmp_path)
    runner.running.add('xray')
    result = install_cleanup.remove_installed_dependencies(env, runner)
    assert result['ok'], result
    assert runner.packages == {'preexisting', 'xray', 'lib'}
    assert not result['removed']
    assert any(item['name']=='xray' and 'работающий сервис' in item['used_by'] for item in result['kept'])


def test_reinstall_does_not_claim_packages_added_by_someone_else(tmp_path):
    env, runner = installed(tmp_path)
    runner.packages.add("foreign-app")
    assert not install_config._record_package_intent(env, "xray", runner)
    assert install_config._ensure_package("xray", runner)
    assert not install_config._record_package_result(env, "xray", runner)
    assert local_state.load_state(path=env.state_path)["detected_environment"]["packages"]["owned"] == ["lib", "xray"]


def test_failed_removal_retains_ownership_for_retry(tmp_path):
    env, runner = installed(tmp_path)
    runner.fail_remove = True
    assert not install_cleanup.remove_installed_dependencies(env, runner)["ok"]
    assert local_state.load_state(path=env.state_path)["detected_environment"]["packages"]["owned"] == ["lib", "xray"]


def test_retry_after_removal_before_state_write(tmp_path):
    env, runner = installed(tmp_path)
    runner.packages.remove("xray")
    result = install_cleanup.remove_installed_dependencies(env, runner)
    assert result["ok"], result
    assert runner.packages == {"preexisting"}


def test_reinstall_recovers_interrupted_package_inventory(tmp_path):
    env = _env(tmp_path)
    _write_state(env)
    runner = Brew()
    assert not install_config._record_package_intent(env, "xray", runner)
    assert install_config._ensure_package("xray", runner)
    # Процесс умер до записи результата; следующий install не должен потерять владение.
    assert not install_config._record_package_intent(env, "privoxy", runner)
    assert local_state.load_state(path=env.state_path)["detected_environment"]["packages"]["owned"] == ["lib", "xray"]


def brew_path_fixture(tmp_path):
    env = _env(tmp_path)
    _write_state(env, {'dnsmasq': {}})
    binary = env.prefix / 'Cellar/dnsmasq/1.0/sbin/dnsmasq'
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b'VM package fixture')
    binary.chmod(0o755)
    assert not install_config._record_brew_service_paths(env, 'dnsmasq')
    return env, binary


def test_root_service_metadata_keeps_first_original_and_verifies_restore(tmp_path):
    env, binary = brew_path_fixture(tmp_path)
    binary.chmod(0o500)
    assert not install_config._record_brew_service_paths(env, 'dnsmasq')
    calls = []
    def restore(cmd, timeout):
        calls.append(cmd)
        binary.chmod(0o755)
        return {'rc': 0}
    assert not install_cleanup._restore_brew_service_paths(env, 'dnsmasq', restore)
    assert calls
    assert binary.stat().st_mode & 0o7777 == 0o755
    assert 'brew_paths_restore' not in local_state.load_state(path=env.state_path)['detected_environment']['dnsmasq']


def test_changed_package_inode_is_preserved(tmp_path):
    env, binary = brew_path_fixture(tmp_path)
    replacement = binary.with_name('replacement')
    replacement.write_bytes(b'foreign replacement')
    replacement.replace(binary)
    calls = []
    assert install_cleanup._restore_brew_service_paths(env, 'dnsmasq', lambda *a: calls.append(a))
    assert not calls
    assert binary.read_bytes() == b'foreign replacement'


def test_state_cannot_expand_privileged_package_path_scope(tmp_path):
    env, binary = brew_path_fixture(tmp_path)
    state = local_state.load_state(path=env.state_path)
    record = state['detected_environment']['dnsmasq']['brew_paths_restore'][0]
    record['path'] = str(tmp_path / 'foreign')
    local_state.save_state(state, path=env.state_path)
    calls = []
    assert install_cleanup._restore_brew_service_paths(env, 'dnsmasq', lambda *a: calls.append(a)) == 'brew_paths_invalid'
    assert not calls


def test_component_reconciliation_keeps_original_package_metadata(tmp_path):
    env, binary = brew_path_fixture(tmp_path)
    state = local_state.load_state(path=env.state_path)
    previous = state['detected_environment']['dnsmasq']
    path = str(env.component_paths('dnsmasq')['config'])
    previous['service_restore'] = {'config_path': path, 'status': 'none'}
    item = {'name': 'dnsmasq', 'config_path': path}
    applied = install_config._applied_component_entry(previous, item, 'managed', '', now=env.now)
    reconciled = install_config._applied_component_entry(applied, item, 'managed', '', now=env.now)
    assert reconciled['brew_paths_restore'] == previous['brew_paths_restore']
