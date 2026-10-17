from pathlib import Path
import os
import subprocess
import sys

import pytest

import install_restore
import local_state
from test_uninstall_flow import _env


@pytest.mark.parametrize("original", [None, b"", b"# custom\n\n\nexport X=1\n"])
def test_file_roundtrip_preserves_absence_bytes_and_permissions(tmp_path, original):
    env = _env(tmp_path)
    target = tmp_path / "zshrc"
    if original is not None:
        target.write_bytes(original)
        target.chmod(0o640)
    install_restore.capture_install_files(env, [target])
    target.write_bytes(b"srouter managed content\n")
    target.chmod(0o755)
    install_restore.record_install_files(env, [target])
    # Reinstall must retain the first original.
    install_restore.capture_install_files(env, [target])
    result = install_restore.restore_install_files(env, [target])
    assert result["ok"], result
    if original is None:
        assert not target.exists()
    else:
        assert target.read_bytes() == original
        assert target.stat().st_mode & 0o777 == 0o640
    install_restore.finish_file_restore(env, result["handled"])
    assert not local_state.load_state(path=env.state_path)["detected_environment"]["install_files"]


def test_later_foreign_edit_is_never_replaced(tmp_path):
    env = _env(tmp_path)
    target = tmp_path / "wrapper"
    target.write_text("original\n")
    install_restore.capture_install_files(env, [target])
    target.write_text("managed wrapper\n")
    install_restore.record_install_files(env, [target])
    target.write_text("later foreign edit\n")
    result = install_restore.restore_install_files(env, [target])
    assert not result["ok"]
    assert result["blocked"] == [str(target)]
    assert target.read_text() == "later foreign edit\n"
    assert local_state.load_state(path=env.state_path)["detected_environment"]["install_files"]


def test_mixed_file_with_later_edits_uses_surgical_cleanup(tmp_path):
    env = _env(tmp_path)
    target = tmp_path / "zshrc"
    install_restore.capture_install_files(env, [target])
    target.write_text("managed block\n")
    install_restore.record_install_files(env, [target])
    target.write_text("managed block\nforeign addition\n")
    result = install_restore.restore_install_files(env, [target], mixed=[target])
    assert result["ok"]
    assert result["fallback"] == [str(target)]
    assert "foreign addition" in target.read_text()


def test_interrupted_install_keeps_original_and_reports_ambiguity(tmp_path):
    env = _env(tmp_path)
    target = tmp_path / "config"
    target.write_text("original\n")
    install_restore.capture_install_files(env, [target])
    target.write_text("changed before process died\n")
    result = install_restore.restore_install_files(env, [target])
    assert not result["ok"]
    assert target.read_text() == "changed before process died\n"
    assert local_state.load_state(path=env.state_path)["detected_environment"]["install_files"][str(target)]["previous"]


def test_original_symlink_is_restored_without_writing_its_target(tmp_path):
    env = _env(tmp_path)
    original = tmp_path / "foreign"
    original.write_text("untouched\n")
    target = tmp_path / "config"
    target.symlink_to(original)
    install_restore.capture_install_files(env, [target])
    target.unlink()
    target.write_text("managed\n")
    install_restore.record_install_files(env, [target])
    result = install_restore.restore_install_files(env, [target])
    assert result["ok"], result
    assert target.is_symlink()
    assert original.read_text() == "untouched\n"


def test_state_cannot_expand_restore_scope(tmp_path):
    env = _env(tmp_path)
    foreign = tmp_path / "foreign"
    allowed = tmp_path / "allowed"
    install_restore.capture_install_files(env, [foreign])
    foreign.write_text("do not delete\n")
    install_restore.record_install_files(env, [foreign])
    assert install_restore.restore_install_files(env, [allowed])["ok"]
    assert foreign.read_text() == "do not delete\n"


def test_state_backups_are_private_and_never_follow_predictable_tmp_symlink(tmp_path):
    target = tmp_path / "state.json"
    foreign = tmp_path / "foreign"
    foreign.write_text("untouched\n")
    target.with_suffix(".json.tmp").symlink_to(foreign)
    assert local_state.save_state({"secret": "test-only"}, path=target) is not None
    assert target.stat().st_mode & 0o777 == 0o600
    assert foreign.read_text() == "untouched\n"
    assert not list(tmp_path.glob("state.json.*.tmp"))


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS ACL/xattrs")
def test_restore_keeps_acl_and_extended_attributes(tmp_path):
    import pwd
    env = _env(tmp_path)
    target = tmp_path / "config"
    target.write_bytes(b"original")
    subprocess.run(["/usr/bin/xattr", "-w", "com.srouter.test", "original xattr", str(target)], check=True)
    subprocess.run(["/bin/chmod", "+a", f"user:{pwd.getpwuid(os.getuid()).pw_name} allow read,write", str(target)], check=True)
    previous = install_restore._snapshot(target)
    install_restore.capture_install_files(env, [target])
    target.write_bytes(b"managed")
    subprocess.run(["/usr/bin/xattr", "-w", "com.srouter.test", "managed xattr", str(target)], check=True)
    install_restore.record_install_files(env, [target])
    result = install_restore.restore_install_files(env, [target])
    assert result["ok"], result
    assert install_restore._snapshot(target) == previous


@pytest.mark.skipif(sys.platform != 'darwin', reason='macOS mv -h semantics')
def test_ppp_restore_replaces_link_without_writing_into_foreign_directory(tmp_path, monkeypatch):
    import privileged_ops
    original = tmp_path / 'original'
    original.write_bytes(b'original hook\n')
    previous = install_restore._snapshot(original)
    ppp = tmp_path / 'ppp'
    ppp.mkdir()
    foreign = tmp_path / 'foreign'
    foreign.mkdir()
    sentinel = foreign / 'keep'
    sentinel.write_bytes(b'foreign')
    target = ppp / 'ip-up'
    target.symlink_to(foreign, target_is_directory=True)
    monkeypatch.setattr(privileged_ops, 'build_osascript', lambda argv: argv)

    def runner(argv, timeout):
        argv = [part.replace('/etc/ppp', str(ppp)) for part in argv]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return {'rc': result.returncode, 'err': result.stderr}

    install_restore._restore_ppp(previous, runner)
    assert not target.is_symlink()
    assert target.read_bytes() == b'original hook\n'
    assert list(foreign.iterdir()) == [sentinel]
    assert sentinel.read_bytes() == b'foreign'
