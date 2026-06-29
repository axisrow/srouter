"""Общие локальные probes для dashboard/install без Flask-зависимостей."""
from __future__ import annotations

import socket
import subprocess


BREW_COMPONENTS = ("xray", "privoxy", "dnsmasq")


def run(cmd_list, timeout):
    """Всегда список аргументов, без shell=True. Возвращает dict и не бросает."""
    try:
        proc = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout)
        return {"rc": proc.returncode, "out": proc.stdout.strip(), "err": proc.stderr.strip(), "timeout": False}
    except subprocess.TimeoutExpired:
        return {"rc": None, "out": "", "err": "timeout", "timeout": True}
    except Exception as exc:
        return {"rc": None, "out": "", "err": str(exc), "timeout": True}


def port_open(host, port, timeout=0.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def parse_brew_services(text, names=BREW_COMPONENTS):
    """Разобрать `brew services list`; при names вернуть только нужные сервисы."""
    services = {}
    if not isinstance(text, str):
        return services
    allowed = set(names) if names is not None else None
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        name, state = fields[0], fields[1]
        if allowed is None or name in allowed:
            services[name] = state
    return services


def brew_service_state(result, name):
    """Семантика dashboard.py: timeout -> unknown, отсутствующий сервис -> none."""
    if result.get("timeout"):
        return "unknown"
    return parse_brew_services(result.get("out") or "", names=None).get(name, "none")
