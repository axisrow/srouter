"""Общие локальные probes для dashboard/install без Flask-зависимостей."""
from __future__ import annotations

import socket
import subprocess


BREW_COMPONENTS = ("xray", "privoxy", "dnsmasq")


def tunnel_code_up(code):
    """Единый предикат «канал/туннель до сервера жив» по HTTP-коду curl (issue #82, класс #3).

    Назначение probe туннеля/прямого доступа — доказать, что ТРАФИК ДОХОДИТ до сервера через
    канал, а не что конкретный URL отдаёт 200. Реальные endpoint'ы отвечают 4xx на '/'
    (api.anthropic.com → 404, api.openai.com → 421) — это ЖИВОЙ канал: сервер ответил HTTP.
    Мёртвым каналом считаем только:
      - 000 / нет кода — соединение не установлено (curl не достучался);
      - 5xx — сбой самого прокси-/upstream-слоя (мёртвый туннель за прокси).
    Живой = сервер вернул валидный HTTP-статус ниже 500. Держим предикат в sys_probe (базовый
    слой без config), чтобы dashboard_network и health.py делили ОДНУ семантику, а не расходились."""
    return isinstance(code, int) and 100 <= code < 500


def run(cmd_list, timeout, *, env=None):
    """Всегда список аргументов, без shell=True. Возвращает dict и не бросает.

    timeout=True ТОЛЬКО при реальном истечении срока (TimeoutExpired). Прочие сбои запуска
    (нет бинаря — FileNotFoundError, нет прав — PermissionError, иной OSError) — это НЕ таймаут:
    возвращаем timeout=False с типизированной причиной в err, иначе вызывающий код принял бы
    отсутствие /usr/bin/curl за «медленную сеть» (issue #82)."""
    try:
        kwargs = {"capture_output": True, "text": True, "timeout": timeout}
        if env is not None:
            kwargs["env"] = env
        proc = subprocess.run(cmd_list, **kwargs)
        return {"rc": proc.returncode, "out": proc.stdout.strip(), "err": proc.stderr.strip(), "timeout": False}
    except subprocess.TimeoutExpired as exc:
        def _text(value):
            if isinstance(value, bytes):
                return value.decode(errors="replace")
            return value or ""

        out = _text(exc.stdout).strip()
        stderr = _text(exc.stderr).strip()
        err = f"{stderr}\ntimeout".strip()
        return {"rc": None, "out": out, "err": err, "timeout": True}
    except Exception as exc:
        return {"rc": None, "out": "", "err": f"{type(exc).__name__}: {exc}", "timeout": False}


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
