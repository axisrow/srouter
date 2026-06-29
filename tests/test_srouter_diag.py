import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "srouter-diag.sh"


def test_srouter_diag_bash_syntax():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


def test_srouter_diag_reads_enabled_nodes_without_real_network(tmp_path):
    false_bin = shutil.which("false")
    assert false_bin
    state_path = tmp_path / "srouter.local.json"
    state_path.write_text(
        json.dumps(
            {
                "nodes": [
                    {
                        "name": "sg-1",
                        "endpoint_host": "203.0.113.10",
                        "route_ip": "203.0.113.10",
                        "enabled": True,
                        "probe": {"socks_port": 11080},
                    },
                    {
                        "name": "hk-disabled",
                        "endpoint_host": "203.0.113.20",
                        "route_ip": "203.0.113.20",
                        "enabled": False,
                        "probe": {"socks_port": 11081},
                    },
                ],
                "active_node": {"name": "sg-1", "pending": None},
                "probes": {
                    "reachability_targets": ["https://reach.local/ping"],
                    "connect_timeout_sec": 1,
                    "max_time_sec": 1,
                },
            }
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.update(
        {
            "SROUTER_PYTHON": sys.executable,
            "SROUTER_CURL": false_bin,
            "SROUTER_DIG": false_bin,
            "SROUTER_LSOF": false_bin,
            "SROUTER_ROUTE": false_bin,
        }
    )

    result = subprocess.run(
        [str(SCRIPT), "novpn", "--state", str(state_path)],
        check=True,
        capture_output=True,
        env=env,
        text=True,
        timeout=10,
    )

    assert "sg-1" in result.stdout
    assert "hk-disabled" not in result.stdout
    assert "NODE_SOCKS" in result.stdout
    assert "11080/closed" in result.stdout
    assert "https://reach.local/ping" in result.stdout
    assert "node.probe.socks_port" in result.stdout
