from pathlib import Path
import shutil

import install_cleanup
import local_state
from test_uninstall_flow import _env


def test_user_data_state_is_deleted_last_even_with_explicit_order(tmp_path, monkeypatch):
    env = _env(tmp_path)
    env.state_path.parent.mkdir(parents=True, exist_ok=True)
    env.state_path.write_text('{}')
    blocked = tmp_path / 'blocked'
    blocked.mkdir()
    monkeypatch.setattr(install_cleanup, 'user_data_paths', lambda env: [blocked, env.state_path])
    monkeypatch.setattr(shutil, 'rmtree', lambda path: (_ for _ in ()).throw(OSError('denied')))
    result = install_cleanup.purge_user_data(env, [env.state_path, blocked])
    assert not result['ok']
    assert env.state_path.exists()


def test_system_data_removal_requires_readback(tmp_path, monkeypatch):
    target = tmp_path / 'appdata'
    target.mkdir()
    monkeypatch.setattr(install_cleanup, '_SYSTEM_DATA_PATHS', (target,))
    assert not install_cleanup.purge_system_data(lambda *a: {'rc': 0})['ok']
    def remove(cmd, timeout):
        target.rmdir()
        return {'rc': 0}
    assert install_cleanup.purge_system_data(remove)['ok']


def test_system_data_symlink_parent_never_reaches_privileged_runner(tmp_path, monkeypatch):
    original = tmp_path / 'foreign'
    original.mkdir()
    parent = tmp_path / 'linked'
    parent.symlink_to(original, target_is_directory=True)
    monkeypatch.setattr(install_cleanup, '_SYSTEM_DATA_PATHS', (parent / 'appdata',))
    calls = []
    assert not install_cleanup.purge_system_data(lambda *a: calls.append(a))['ok']
    assert not calls
    assert original.exists()


def test_user_data_symlink_parent_preserves_foreign_data_and_state(tmp_path, monkeypatch):
    env = _env(tmp_path)
    env.state_path.parent.mkdir(parents=True, exist_ok=True)
    env.state_path.write_text('{}')
    foreign = tmp_path / 'foreign'
    generated = foreign / '.generated'
    generated.mkdir(parents=True)
    sentinel = generated / 'keep'
    sentinel.write_text('foreign')
    parent = tmp_path / 'server'
    parent.symlink_to(foreign, target_is_directory=True)
    target = parent / '.generated'
    monkeypatch.setattr(install_cleanup, 'user_data_paths', lambda env: [target, env.state_path])
    result = install_cleanup.purge_user_data(env)
    assert not result['ok']
    assert sentinel.read_text() == 'foreign'
    assert env.state_path.exists()
