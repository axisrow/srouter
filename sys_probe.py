"""Общие локальные probes для dashboard/install без Flask-зависимостей."""
from __future__ import annotations

import os
import socket
import subprocess


BREW_COMPONENTS = ("xray", "privoxy", "dnsmasq")

# Абсолютный путь: launchd/GUI PATH его не содержит (канон проекта, как health.CURL).
CURL = "/usr/bin/curl"


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


def direct_probe(host, *, connect_timeout=4, max_time=8):
    """Прямой curl к host МИНУЯ прокси (env -u) — достигается ли домен без туннеля?

    Базовый слой без config (как tunnel_code_up) — делят health.py (#206 GFW per-domain: github
    режется избирательно?) и direct_first.py (#197: домен reachable → в NO_PROXY). Перенесено 1:1
    из health._direct_domain_probe (health.py, issue #206) — контракт неизменен, health теперь
    тонкая обёртка над этой функцией (канон verify-dont-guess: один probe, не дублировать).

    env -u всех proxy-vars (оба регистра) — прямой путь минуя privoxy/xray. Список = тот же, что
    _claude_transport_once clean_keys + GH_DIRECT_HINT #199 (единый контракт «снять прокси»).

    Семантика reachable = ЛЮБОЙ HTTP-ответ сервера (включая 5xx): GFW даёт timeout/connection-reset,
    НЕ HTTP-ответ → сам факт HTTP-кода доказывает достижимость (домен не режется). 404/421/5xx =
    сервер ответил = канал работает. timeout/000 = режется/нет ответа. kind разделяет «здоров»
    (HTTP<500, ok) от «ответил, но лежит» (5xx, upstream-error) — та же дискриминация, что
    _tunnel_target_up (#207).

    Возвращает {"reachable": bool, "kind": str}:
      reachable=True,  kind="ok"                  — сервер ответил HTTP < 500 (домен доступен напрямую);
      reachable=True,  kind="upstream-error"      — сервер ответил HTTP 5xx (домен достижим, GFW НЕ
                                                    режет, но сам лежит — vendor down, не "ok");
      reachable=False, kind="timeout"             — curl timeout (GFW режет / нет ответа);
      reachable=False, kind="connection-failed"   — curl 000/no-response/мусор (reset/не установлено).
    Не бросает (probe-канон)."""
    env = os.environ.copy()
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        env.pop(key, None)
    # https:// + путь '/' — GFW режет на TLS-handshake к корню; -I (HEAD) лёгкий.
    r = run([CURL, "-sS", "-o", "/dev/null", "-I",
             "--connect-timeout", str(connect_timeout), "--max-time", str(max_time),
             "-w", "%{http_code}", f"https://{host}/"],
            timeout=max_time + 2, env=env)
    if r.get("timeout"):
        return {"reachable": False, "kind": "timeout"}
    code = (r.get("out") or "").strip()
    if not code or code == "000":
        return {"reachable": False, "kind": "connection-failed"}
    try:
        code_int = int(code)
    except ValueError:
        return {"reachable": False, "kind": "connection-failed"}
    if tunnel_code_up(code_int):
        return {"reachable": True, "kind": "ok"}
    return {"reachable": True, "kind": "upstream-error"}
