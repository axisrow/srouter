import json
import os
import stat
import subprocess
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "server"

UUID = "00000000-0000-4000-8000-000000000042"
PRIVATE_KEY = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
PUBLIC_KEY = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
SHORT_ID = "0123456789abcdef"


def _write_tool(bin_dir: Path, name: str, body: str) -> Path:
    path = bin_dir / name
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _fake_key_tools(bin_dir: Path, log_path: Path) -> None:
    _write_tool(
        bin_dir,
        "openssl",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf 'openssl %s\\n' "$*" >> "{log_path}"
        if [[ "${{1:-}}" == "rand" && "${{2:-}}" == "-hex" && "${{3:-}}" == "8" ]]; then
          printf '%s\\n' "{SHORT_ID}"
        else
          printf 'unexpected openssl args: %s\\n' "$*" >&2
          exit 64
        fi
        """,
    )


def _fake_xray_source(source_dir: Path, log_path: Path, marker: str, *, test_ok: bool = True) -> None:
    source_dir.mkdir(parents=True, exist_ok=True)
    _write_tool(
        source_dir,
        "xray",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        # marker:{marker}
        printf 'xray-{marker} %s\\n' "$*" >> "{log_path}"
        if [[ "${{1:-}}" == "uuid" ]]; then
          printf '%s\\n' "{UUID}"
        elif [[ "${{1:-}}" == "x25519" && "${{2:-}}" == "-i" ]]; then
          printf 'Private key: %s\\n' "$3"
          printf 'Public key: {PUBLIC_KEY}\\n'
        elif [[ "${{1:-}}" == "x25519" ]]; then
          printf 'Private key: {PRIVATE_KEY}\\n'
          printf 'Public key: {PUBLIC_KEY}\\n'
        elif [[ "${{1:-}}" == "run" && "${{2:-}}" == "-test" ]]; then
          {"exit 0" if test_ok else "exit 88"}
        else
          printf 'unexpected xray args: %s\\n' "$*" >&2
          exit 64
        fi
        """,
    )
    (source_dir / "geoip.dat").write_text(f"geoip-{marker}", encoding="utf-8")
    (source_dir / "geosite.dat").write_text(f"geosite-{marker}", encoding="utf-8")


def _fake_host_tools(bin_dir: Path, apt_log: Path, systemctl_log: Path) -> None:
    _write_tool(
        bin_dir,
        "uname",
        """
        #!/usr/bin/env bash
        set -euo pipefail
        if [[ "${1:-}" == "-s" ]]; then
          printf 'Linux\\n'
        elif [[ "${1:-}" == "-m" ]]; then
          printf 'x86_64\\n'
        else
          printf 'Linux\\n'
        fi
        """,
    )
    _write_tool(
        bin_dir,
        "apt-get",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf 'apt-get %s\\n' "$*" >> "{apt_log}"
        """,
    )
    _write_tool(
        bin_dir,
        "systemctl",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf 'systemctl %s\\n' "$*" >> "{systemctl_log}"
        """,
    )
    _write_tool(
        bin_dir,
        "envsubst",
        """
        #!/usr/bin/env python3
        import os
        import sys

        data = sys.stdin.read()
        for key in (
            "LISTEN_PORT",
            "XRAY_UUID",
            "XRAY_PRIVATE_KEY",
            "XRAY_SHORT_ID",
            "XRAY_DEST",
            "XRAY_SNI",
            "XRAY_FLOW",
        ):
            data = data.replace("${" + key + "}", os.environ[key])
        sys.stdout.write(data)
        """,
    )


def _fake_restore_cp_failure(bin_dir: Path, cp_log: Path, fail_target_suffix: str) -> None:
    _write_tool(
        bin_dir,
        "cp",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf 'cp %s\\n' "$*" >> "{cp_log}"
        source_arg=""
        for arg in "$@"; do
          if [[ "$arg" == -* ]]; then
            continue
          fi
          source_arg="$arg"
          break
        done
        target_arg="${{@: -1}}"
        if [[ "$source_arg" == *"/backups/"* && "$target_arg" == *"{fail_target_suffix}" ]]; then
          printf 'forced restore cp failure\\n' >&2
          exit 77
        fi
        exec /bin/cp "$@"
        """,
    )


def _fake_latest_mv_failure(bin_dir: Path, mv_log: Path) -> None:
    _write_tool(
        bin_dir,
        "mv",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf 'mv %s\\n' "$*" >> "{mv_log}"
        target_arg="${{@: -1}}"
        if [[ "$target_arg" == *"/var/lib/srouter-reality/backups/latest" ]]; then
          printf 'forced latest pointer failure\\n' >&2
          exit 73
        fi
        exec /bin/mv "$@"
        """,
    )


def _write_os_release(root: Path) -> None:
    etc = root / "etc"
    etc.mkdir(parents=True)
    (etc / "os-release").write_text('ID=ubuntu\nID_LIKE=debian\n', encoding="utf-8")


def _env(root: Path, bin_dir: Path, source_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}{os.pathsep}{source_dir}{os.pathsep}{env.get('PATH', '')}"
    env["SROUTER_BARE_ROOT"] = str(root)
    env["SROUTER_XRAY_SOURCE_DIR"] = str(source_dir)
    return env


def _run(args: list[str], *, env: dict[str, str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=check,
    )


def _install_args(bundle: Path) -> list[str]:
    return [
        "bash",
        str(SERVER / "bare-install.sh"),
        "install",
        "--bundle-dir",
        str(bundle),
        "--name",
        "sg-1",
        "--endpoint-host",
        "203.0.113.77",
        "--country-code",
        "SG",
        "--probe-socks-port",
        "11080",
    ]


def test_bare_install_renders_host_config_unit_and_full_node_object(tmp_path):
    root = tmp_path / "root"
    bin_dir = tmp_path / "bin"
    source_dir = tmp_path / "xray-v1"
    bundle = tmp_path / "bundle"
    bin_dir.mkdir()
    key_log = tmp_path / "keys.log"
    xray_log = tmp_path / "xray.log"
    apt_log = tmp_path / "apt.log"
    systemctl_log = tmp_path / "systemctl.log"
    _write_os_release(root)
    _fake_key_tools(bin_dir, key_log)
    _fake_host_tools(bin_dir, apt_log, systemctl_log)
    _fake_xray_source(source_dir, xray_log, "v1")

    proc = _run(_install_args(bundle), env=_env(root, bin_dir, source_dir))

    node = json.loads(proc.stdout)
    assert node == {
        "name": "sg-1",
        "endpoint_host": "203.0.113.77",
        "route_ip": "203.0.113.77",
        "port": 443,
        "country_code": "SG",
        "enabled": True,
        "uuid": UUID,
        "reality": {
            "public_key": PUBLIC_KEY,
            "short_id": SHORT_ID,
            "sni": "www.163.com",
            "dest": "www.163.com:443",
            "flow": "xtls-rprx-vision",
        },
        "probe": {"socks_port": 11080},
    }

    state_env = root / "var/lib/srouter-reality/.env"
    state_node = root / "var/lib/srouter-reality/node_object.json"
    rendered_config = root / "etc/xray/rendered/config.json"
    unit = root / "etc/systemd/system/srouter-reality.service"
    xray_bin = root / "usr/local/bin/xray"

    assert stat.S_IMODE(state_env.stat().st_mode) == 0o600
    assert stat.S_IMODE(state_node.stat().st_mode) == 0o600
    assert stat.S_IMODE(rendered_config.stat().st_mode) == 0o600
    assert json.loads(state_node.read_text(encoding="utf-8")) == node
    assert '"id": "' + UUID + '"' in rendered_config.read_text(encoding="utf-8")
    assert str(xray_bin) in unit.read_text(encoding="utf-8")
    assert str(rendered_config) in unit.read_text(encoding="utf-8")
    assert "marker:v1" in xray_bin.read_text(encoding="utf-8")

    assert key_log.read_text(encoding="utf-8").splitlines() == ["openssl rand -hex 8"]
    assert "apt-get update" in apt_log.read_text(encoding="utf-8")
    assert systemctl_log.read_text(encoding="utf-8").splitlines() == [
        "systemctl daemon-reload",
        "systemctl enable --now srouter-reality.service",
    ]


def test_bare_update_preserves_existing_keys_and_node_defaults(tmp_path):
    root = tmp_path / "root"
    bin_dir = tmp_path / "bin"
    source_v1 = tmp_path / "xray-v1"
    source_v2 = tmp_path / "xray-v2"
    bundle = tmp_path / "bundle"
    bin_dir.mkdir()
    key_log = tmp_path / "keys.log"
    xray_log = tmp_path / "xray.log"
    apt_log = tmp_path / "apt.log"
    systemctl_log = tmp_path / "systemctl.log"
    _write_os_release(root)
    _fake_key_tools(bin_dir, key_log)
    _fake_host_tools(bin_dir, apt_log, systemctl_log)
    _fake_xray_source(source_v1, xray_log, "v1")

    _run(_install_args(bundle), env=_env(root, bin_dir, source_v1))
    _fake_xray_source(source_v2, xray_log, "v2")
    key_log.unlink()
    proc = _run(
        [
            "bash",
            str(SERVER / "bare-install.sh"),
            "update",
            "--bundle-dir",
            str(bundle),
            "--xray-sni",
            "example.com",
            "--xray-dest",
            "example.com:443",
        ],
        env=_env(root, bin_dir, source_v2),
    )

    node = json.loads(proc.stdout)
    assert node["name"] == "sg-1"
    assert node["endpoint_host"] == "203.0.113.77"
    assert node["uuid"] == UUID
    assert node["reality"]["public_key"] == PUBLIC_KEY
    assert node["reality"]["sni"] == "example.com"
    assert node["reality"]["dest"] == "example.com:443"
    assert not key_log.exists()
    assert "marker:v2" in (root / "usr/local/bin/xray").read_text(encoding="utf-8")
    assert (root / "var/lib/srouter-reality/backups/latest").exists()
    assert "systemctl restart srouter-reality.service" in systemctl_log.read_text(encoding="utf-8")


def test_bare_update_failure_restores_previous_binary_and_config(tmp_path):
    root = tmp_path / "root"
    bin_dir = tmp_path / "bin"
    source_v1 = tmp_path / "xray-v1"
    source_bad = tmp_path / "xray-bad"
    bundle = tmp_path / "bundle"
    bin_dir.mkdir()
    key_log = tmp_path / "keys.log"
    xray_log = tmp_path / "xray.log"
    apt_log = tmp_path / "apt.log"
    systemctl_log = tmp_path / "systemctl.log"
    _write_os_release(root)
    _fake_key_tools(bin_dir, key_log)
    _fake_host_tools(bin_dir, apt_log, systemctl_log)
    _fake_xray_source(source_v1, xray_log, "v1")

    _run(_install_args(bundle), env=_env(root, bin_dir, source_v1))
    old_config = (root / "etc/xray/rendered/config.json").read_text(encoding="utf-8")
    _fake_xray_source(source_bad, xray_log, "bad", test_ok=False)

    proc = _run(
        [
            "bash",
            str(SERVER / "bare-install.sh"),
            "update",
            "--bundle-dir",
            str(bundle),
            "--xray-sni",
            "broken.example",
            "--xray-dest",
            "broken.example:443",
        ],
        env=_env(root, bin_dir, source_bad),
        check=False,
    )

    assert proc.returncode == 88
    assert "восстанавливаю backup" in proc.stderr
    assert "marker:v1" in (root / "usr/local/bin/xray").read_text(encoding="utf-8")
    assert (root / "etc/xray/rendered/config.json").read_text(encoding="utf-8") == old_config
    assert "systemctl restart srouter-reality.service" in systemctl_log.read_text(encoding="utf-8")


def test_bare_update_marks_recovery_failed_when_restore_copy_fails(tmp_path):
    root = tmp_path / "root"
    bin_dir = tmp_path / "bin"
    source_v1 = tmp_path / "xray-v1"
    source_bad = tmp_path / "xray-bad"
    bundle = tmp_path / "bundle"
    bin_dir.mkdir()
    key_log = tmp_path / "keys.log"
    xray_log = tmp_path / "xray.log"
    apt_log = tmp_path / "apt.log"
    systemctl_log = tmp_path / "systemctl.log"
    cp_log = tmp_path / "cp.log"
    _write_os_release(root)
    _fake_key_tools(bin_dir, key_log)
    _fake_host_tools(bin_dir, apt_log, systemctl_log)
    _fake_xray_source(source_v1, xray_log, "v1")

    _run(_install_args(bundle), env=_env(root, bin_dir, source_v1))
    _fake_restore_cp_failure(bin_dir, cp_log, "/usr/local/share/xray")
    _fake_xray_source(source_bad, xray_log, "bad", test_ok=False)

    proc = _run(
        [
            "bash",
            str(SERVER / "bare-install.sh"),
            "update",
            "--bundle-dir",
            str(bundle),
            "--xray-sni",
            "broken.example",
            "--xray-dest",
            "broken.example:443",
        ],
        env=_env(root, bin_dir, source_bad),
        check=False,
    )

    assert proc.returncode == 88
    assert "восстанавливаю backup" in proc.stderr
    assert "не удалось восстановить directory" in proc.stderr
    assert "автоматический rollback не удался" in proc.stderr
    assert "/backups/" in cp_log.read_text(encoding="utf-8")
    assert systemctl_log.read_text(encoding="utf-8").splitlines() == [
        "systemctl daemon-reload",
        "systemctl enable --now srouter-reality.service",
    ]


def test_bare_update_rolls_back_when_latest_pointer_write_fails_after_restart(tmp_path):
    root = tmp_path / "root"
    bin_dir = tmp_path / "bin"
    source_v1 = tmp_path / "xray-v1"
    source_v2 = tmp_path / "xray-v2"
    bundle = tmp_path / "bundle"
    bin_dir.mkdir()
    key_log = tmp_path / "keys.log"
    xray_log = tmp_path / "xray.log"
    apt_log = tmp_path / "apt.log"
    systemctl_log = tmp_path / "systemctl.log"
    mv_log = tmp_path / "mv.log"
    _write_os_release(root)
    _fake_key_tools(bin_dir, key_log)
    _fake_host_tools(bin_dir, apt_log, systemctl_log)
    _fake_xray_source(source_v1, xray_log, "v1")

    _run(_install_args(bundle), env=_env(root, bin_dir, source_v1))
    old_config = (root / "etc/xray/rendered/config.json").read_text(encoding="utf-8")
    _fake_latest_mv_failure(bin_dir, mv_log)
    _fake_xray_source(source_v2, xray_log, "v2")

    proc = _run(
        [
            "bash",
            str(SERVER / "bare-install.sh"),
            "update",
            "--bundle-dir",
            str(bundle),
            "--xray-sni",
            "example.com",
            "--xray-dest",
            "example.com:443",
        ],
        env=_env(root, bin_dir, source_v2),
        check=False,
    )

    assert proc.returncode == 73
    assert "восстанавливаю backup" in proc.stderr
    assert "автоматический rollback не удался" not in proc.stderr
    assert "marker:v1" in (root / "usr/local/bin/xray").read_text(encoding="utf-8")
    assert (root / "etc/xray/rendered/config.json").read_text(encoding="utf-8") == old_config
    assert not (root / "var/lib/srouter-reality/backups/latest").exists()
    assert "var/lib/srouter-reality/backups/latest" in mv_log.read_text(encoding="utf-8")
    assert systemctl_log.read_text(encoding="utf-8").splitlines() == [
        "systemctl daemon-reload",
        "systemctl enable --now srouter-reality.service",
        "systemctl daemon-reload",
        "systemctl restart srouter-reality.service",
        "systemctl daemon-reload",
        "systemctl restart srouter-reality.service",
    ]


def test_bare_rollback_restores_latest_successful_update_backup(tmp_path):
    root = tmp_path / "root"
    bin_dir = tmp_path / "bin"
    source_v1 = tmp_path / "xray-v1"
    source_v2 = tmp_path / "xray-v2"
    bundle = tmp_path / "bundle"
    bin_dir.mkdir()
    key_log = tmp_path / "keys.log"
    xray_log = tmp_path / "xray.log"
    apt_log = tmp_path / "apt.log"
    systemctl_log = tmp_path / "systemctl.log"
    _write_os_release(root)
    _fake_key_tools(bin_dir, key_log)
    _fake_host_tools(bin_dir, apt_log, systemctl_log)
    _fake_xray_source(source_v1, xray_log, "v1")
    _fake_xray_source(source_v2, xray_log, "v2")

    _run(_install_args(bundle), env=_env(root, bin_dir, source_v1))
    _run(
        [
            "bash",
            str(SERVER / "bare-install.sh"),
            "update",
            "--bundle-dir",
            str(bundle),
        ],
        env=_env(root, bin_dir, source_v2),
    )
    assert "marker:v2" in (root / "usr/local/bin/xray").read_text(encoding="utf-8")

    proc = _run(
        ["bash", str(SERVER / "bare-install.sh"), "rollback"],
        env=_env(root, bin_dir, source_v2),
    )

    assert json.loads(proc.stdout)["uuid"] == UUID
    assert "marker:v1" in (root / "usr/local/bin/xray").read_text(encoding="utf-8")


def test_bare_shell_syntax_valid():
    for script in ("bare-install.sh", "gen-keys.sh", "deploy.sh"):
        _run(["bash", "-n", str(SERVER / script)], env=os.environ.copy())
