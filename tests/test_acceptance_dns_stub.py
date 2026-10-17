import os
from pathlib import Path
import subprocess


def test_docker_dns_stub_preserves_and_restores_manual_and_automatic_dns(tmp_path):
    stub = Path(__file__).parent.parent / 'docker/stubs/networksetup.sh'
    def command(*args):
        return subprocess.run(['/bin/sh', str(stub), *args], env={**os.environ, 'HOME': str(tmp_path)},
                              capture_output=True, text=True, check=True).stdout.strip()
    automatic = command('-getdnsservers', 'Wi-Fi')
    assert "aren't any" in automatic
    command('-setdnsservers', 'Wi-Fi', '223.5.5.5', '1.1.1.1')
    manual = command('-getdnsservers', 'Wi-Fi')
    assert manual == '223.5.5.5\n1.1.1.1'
    command('-setdnsservers', 'Wi-Fi', '127.0.0.1')
    assert command('-getdnsservers', 'Wi-Fi') == '127.0.0.1'
    command('-setdnsservers', 'Wi-Fi', *manual.splitlines())
    assert command('-getdnsservers', 'Wi-Fi') == manual
    command('-setdnsservers', 'Wi-Fi', 'Empty')
    assert command('-getdnsservers', 'Wi-Fi') == automatic
