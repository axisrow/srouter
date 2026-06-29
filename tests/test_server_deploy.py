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
        "xray",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf 'xray %s\\n' "$*" >> "{log_path}"
        if [[ "${{1:-}}" == "uuid" ]]; then
          printf '%s\\n' "{UUID}"
        elif [[ "${{1:-}}" == "x25519" && "${{2:-}}" == "-i" ]]; then
          printf 'Private key: %s\\n' "$3"
          printf 'Public key: {PUBLIC_KEY}\\n'
        elif [[ "${{1:-}}" == "x25519" ]]; then
          printf 'Private key: {PRIVATE_KEY}\\n'
          printf 'Public key: {PUBLIC_KEY}\\n'
        else
          printf 'unexpected xray args: %s\\n' "$*" >&2
          exit 64
        fi
        """,
    )
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


def _fake_compact_xray_tool(bin_dir: Path, log_path: Path) -> None:
    _write_tool(
        bin_dir,
        "xray",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf 'xray %s\\n' "$*" >> "{log_path}"
        if [[ "${{1:-}}" == "uuid" ]]; then
          printf '%s\\n' "{UUID}"
        elif [[ "${{1:-}}" == "x25519" && "${{2:-}}" == "-i" ]]; then
          printf 'PrivateKey: %s\\n' "$3"
          printf 'Password (PublicKey): {PUBLIC_KEY}\\n'
          printf 'Hash32: ignored\\n'
        elif [[ "${{1:-}}" == "x25519" ]]; then
          printf 'PrivateKey: {PRIVATE_KEY}\\n'
          printf 'Password (PublicKey): {PUBLIC_KEY}\\n'
          printf 'Hash32: ignored\\n'
        else
          printf 'unexpected xray args: %s\\n' "$*" >&2
          exit 64
        fi
        """,
    )
    _write_tool(
        bin_dir,
        "openssl",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf 'openssl %s\\n' "$*" >> "{log_path}"
        printf '%s\\n' "{SHORT_ID}"
        """,
    )


def _env_with(bin_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
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


def _parse_env(stdout: str) -> dict[str, str]:
    result = {}
    for line in stdout.splitlines():
        key, value = line.split("=", 1)
        result[key] = value
    return result


def test_gen_keys_outputs_entrypoint_compatible_values(tmp_path):
    """gen-keys использует те же команды/форматы, что entrypoint.sh."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls.log"
    _fake_key_tools(bin_dir, calls)

    proc = _run(["bash", str(SERVER / "gen-keys.sh")], env=_env_with(bin_dir))
    values = _parse_env(proc.stdout)

    assert values == {
        "XRAY_UUID": UUID,
        "XRAY_PRIVATE_KEY": PRIVATE_KEY,
        "XRAY_PUBLIC_KEY": PUBLIC_KEY,
        "XRAY_SHORT_ID": SHORT_ID,
    }
    assert values["XRAY_UUID"].count("-") == 4
    assert len(values["XRAY_PRIVATE_KEY"]) == 43
    assert len(values["XRAY_PUBLIC_KEY"]) == 43
    assert len(values["XRAY_SHORT_ID"]) <= 16
    assert len(values["XRAY_SHORT_ID"]) % 2 == 0
    assert calls.read_text(encoding="utf-8").splitlines() == [
        "xray uuid",
        "openssl rand -hex 8",
        "xray x25519",
        f"xray x25519 -i {PRIVATE_KEY}",
    ]


def test_gen_keys_accepts_current_xray_labels(tmp_path):
    """Новые xray builds печатают PrivateKey/Password (PublicKey), не старые labels."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls.log"
    _fake_compact_xray_tool(bin_dir, calls)

    proc = _run(["bash", str(SERVER / "gen-keys.sh")], env=_env_with(bin_dir))
    values = _parse_env(proc.stdout)

    assert values["XRAY_PRIVATE_KEY"] == PRIVATE_KEY
    assert values["XRAY_PUBLIC_KEY"] == PUBLIC_KEY


def test_deploy_requires_explicit_mode(tmp_path):
    proc = _run(["bash", str(SERVER / "deploy.sh")], env=_env_with(tmp_path), check=False)

    assert proc.returncode != 0
    assert "Usage:" in proc.stderr
    assert "mode обязателен" in proc.stderr


def test_generate_renders_bundle_and_full_node_without_docker(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls.log"
    docker_calls = tmp_path / "docker.log"
    bundle = tmp_path / "bundle"
    _fake_key_tools(bin_dir, calls)
    _write_tool(
        bin_dir,
        "docker",
        f"""
        #!/usr/bin/env bash
        printf 'docker %s\\n' "$*" >> "{docker_calls}"
        exit 70
        """,
    )

    proc = _run(
        [
            "bash",
            str(SERVER / "deploy.sh"),
            "generate",
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
        ],
        env=_env_with(bin_dir),
    )

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
    assert (bundle / ".env").exists()
    assert stat.S_IMODE((bundle / ".env").stat().st_mode) == 0o600
    assert json.loads((bundle / "node_object.json").read_text(encoding="utf-8")) == node
    assert (bundle / "docker-compose.yml").exists()
    assert (bundle / "Dockerfile").exists()
    assert not docker_calls.exists()


def test_deploy_requires_docker_compose_before_rendering(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker_calls = tmp_path / "docker.log"
    bundle = tmp_path / "bundle"
    _write_tool(
        bin_dir,
        "docker",
        f"""
        #!/usr/bin/env bash
        printf 'docker %s\\n' "$*" >> "{docker_calls}"
        if [[ "${{1:-}}" == "compose" && "${{2:-}}" == "version" ]]; then
          exit 1
        fi
        exit 70
        """,
    )

    proc = _run(
        [
            "bash",
            str(SERVER / "deploy.sh"),
            "deploy",
            "--bundle-dir",
            str(bundle),
            "--endpoint-host",
            "203.0.113.77",
        ],
        env=_env_with(bin_dir),
        check=False,
    )

    assert proc.returncode != 0
    assert "Docker Compose недоступен" in proc.stderr
    assert not bundle.exists()
    assert docker_calls.read_text(encoding="utf-8").splitlines() == ["docker compose version"]


def test_deploy_runs_compose_wait_and_prints_env_node_object(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    key_calls = tmp_path / "key-calls.log"
    docker_calls = tmp_path / "docker.log"
    bundle = tmp_path / "bundle"
    _fake_key_tools(bin_dir, key_calls)
    _write_tool(
        bin_dir,
        "docker",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf 'docker %s\\n' "$*" >> "{docker_calls}"
        if [[ "${{1:-}}" == "compose" && "${{2:-}}" == "version" ]]; then
          exit 0
        fi
        if [[ "$*" == *" up -d --build --wait --wait-timeout 60" ]]; then
          exit 0
        fi
        exit 70
        """,
    )

    proc = _run(
        [
            "bash",
            str(SERVER / "deploy.sh"),
            "deploy",
            "--bundle-dir",
            str(bundle),
            "--name",
            "sg-1",
            "--endpoint-host",
            "203.0.113.77",
            "--country-code",
            "SG",
        ],
        env=_env_with(bin_dir),
    )

    node = json.loads(proc.stdout)
    assert node["name"] == "sg-1"
    assert node["endpoint_host"] == "203.0.113.77"
    assert node["route_ip"] == "203.0.113.77"
    assert node["country_code"] == "SG"
    assert node["enabled"] is True
    assert node["probe"] == {"socks_port": 11080}
    assert node["uuid"] == UUID
    assert node["reality"]["public_key"] == PUBLIC_KEY
    assert docker_calls.read_text(encoding="utf-8").splitlines() == [
        "docker compose version",
        f"docker compose --env-file {bundle / '.env'} -f {bundle / 'docker-compose.yml'} up -d --build --wait --wait-timeout 60",
    ]


def test_deploy_reuses_generate_bundle_without_second_key_generation(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    key_calls = tmp_path / "key-calls.log"
    docker_calls = tmp_path / "docker.log"
    bundle = tmp_path / "bundle"
    _fake_key_tools(bin_dir, key_calls)

    _run(
        [
            "bash",
            str(SERVER / "deploy.sh"),
            "generate",
            "--bundle-dir",
            str(bundle),
            "--name",
            "sg-1",
            "--endpoint-host",
            "203.0.113.77",
        ],
        env=_env_with(bin_dir),
    )

    _write_tool(
        bin_dir,
        "xray",
        """
        #!/usr/bin/env bash
        printf 'xray must not run in deploy when bundle has keys\\n' >&2
        exit 71
        """,
    )
    _write_tool(
        bin_dir,
        "openssl",
        """
        #!/usr/bin/env bash
        printf 'openssl must not run in deploy when bundle has keys\\n' >&2
        exit 71
        """,
    )
    _write_tool(
        bin_dir,
        "docker",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf 'docker %s\\n' "$*" >> "{docker_calls}"
        if [[ "${{1:-}}" == "compose" && "${{2:-}}" == "version" ]]; then
          exit 0
        fi
        if [[ "$*" == *" up -d --build --wait --wait-timeout 60" ]]; then
          exit 0
        fi
        exit 70
        """,
    )

    proc = _run(
        [
            "bash",
            str(SERVER / "deploy.sh"),
            "deploy",
            "--bundle-dir",
            str(bundle),
            "--name",
            "sg-1",
            "--endpoint-host",
            "203.0.113.77",
        ],
        env=_env_with(bin_dir),
    )

    assert json.loads(proc.stdout)["uuid"] == UUID
    assert key_calls.read_text(encoding="utf-8").splitlines() == [
        "xray uuid",
        "openssl rand -hex 8",
        "xray x25519",
        f"xray x25519 -i {PRIVATE_KEY}",
    ]


def test_deploy_does_not_print_stale_volume_node_object(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    key_calls = tmp_path / "key-calls.log"
    docker_calls = tmp_path / "docker.log"
    bundle = tmp_path / "bundle"
    _fake_key_tools(bin_dir, key_calls)
    old_uuid = "11111111-1111-4111-8111-111111111111"
    old_public_key = "ccccccccccccccccccccccccccccccccccccccccccc"

    _write_tool(
        bin_dir,
        "docker",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf 'docker %s\\n' "$*" >> "{docker_calls}"
        if [[ "${{1:-}}" == "compose" && "${{2:-}}" == "version" ]]; then
          exit 0
        fi
        if [[ "$*" == *" up -d --build --wait --wait-timeout 60" ]]; then
          exit 0
        fi
        if [[ "$*" == *" exec -T reality-node cat /var/lib/srouter-reality/node_object.json" ]]; then
          cat <<'JSON'
        {{
          "port": 443,
          "uuid": "{old_uuid}",
          "reality": {{
            "public_key": "{old_public_key}",
            "short_id": "ffffffffffffffff",
            "sni": "www.163.com",
            "dest": "www.163.com:443",
            "flow": "xtls-rprx-vision"
          }}
        }}
        JSON
          exit 0
        fi
        exit 70
        """,
    )

    proc = _run(
        [
            "bash",
            str(SERVER / "deploy.sh"),
            "deploy",
            "--bundle-dir",
            str(bundle),
            "--name",
            "sg-1",
            "--endpoint-host",
            "203.0.113.77",
        ],
        env=_env_with(bin_dir),
    )

    node = json.loads(proc.stdout)
    assert node["uuid"] == UUID
    assert node["reality"]["public_key"] == PUBLIC_KEY
    assert node["uuid"] != old_uuid
    assert node["reality"]["public_key"] != old_public_key
    assert all("exec -T reality-node cat" not in line for line in docker_calls.read_text(encoding="utf-8").splitlines())


def test_shell_syntax_valid():
    for script in ("gen-keys.sh", "deploy.sh"):
        _run(["bash", "-n", str(SERVER / script)], env=os.environ.copy())
