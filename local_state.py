"""Defensive stdlib-only helper над unified local state `srouter.local.json`.

Контракт (#2): функции НИКОГДА не бросают; невалидный ввод деградирует в empty/default.
Path по умолчанию — рядом с модулем (не cwd), чтобы работал под launchd.
Каждая public функция принимает path= для тестов (tmp_path fixture).
"""
import json
import re
from pathlib import Path

# Путь к локальному state по умолчанию — рядом с этим модулем, не cwd.
_DEFAULT_PATH = Path(__file__).resolve().parent / "srouter.local.json"

# D2: валидация хоста — только безопасные символы, shell-метасимволы запрещены.
# Переиспользовано из закрытого PR #19; закреплено в #2.
_HOST_RE = re.compile(r"^[A-Za-z0-9.:_-]+$")


def _is_valid_host(host):
    """True если строка содержит только безопасные для shell символы."""
    return bool(isinstance(host, str) and _HOST_RE.match(host))


# Safe-default state: секции v1 (#2). probes — эталонные defaults (G3);
# реальную запись делает #5 setup/check на реальной машине.
_DEFAULT_STATE = {
    "schema_version": 1,
    "nodes": [],
    "active_node": {"name": None, "pending": None},
    "probes": {
        "reachability_targets": ["https://api.ip.sb/ip", "https://www.cloudflare.com/cdn-cgi/trace"],
        "throughput_targets": [{"url": "https://speed.cloudflare.com/__down?bytes=1048576", "bytes": 1048576}],
        "connect_timeout_sec": 4,
        "max_time_sec": 8,
    },
    "network": {"gateway": "", "vpn_server": "", "vpn_exit_ip": "", "channels": {}},
    "traffic_guard": {"mode": "off", "domains": {}},
    "detected_environment": {"last_checked_at": None, "brew": None, "xray": None, "privoxy": None, "dnsmasq": None},
    "runtime": {"last_apply": None, "last_error": None},
}
