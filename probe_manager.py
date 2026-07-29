"""ProbeManager: группировка probe-функций для явного state-менеджмента и тестируемости.

Класс инкапсулирует probe-логику без внешнего состояния (без сайд-эффектов кроме I/O).
Сохраняет обратную совместимость через module-level функции-делегаты.

Создан для issue #160 (refactor: ввести классы ProbeManager/StateManager/PrivilegedOps).
"""
from __future__ import annotations

import os
import socket
import subprocess
from typing import Dict, Any, List, Optional


class ProbeManager:
    """Менеджер probe-операций — группирует функции проверки состояния системы.

    Все методы stateless (кроме I/O) и не бросают исключений — возвращают structured results.
    Это позволяет легко их мокать в тестах и-compose в цепочки.
    """

    def __init__(self, curl_path: str = "/usr/bin/curl", brew_components: Optional[tuple] = None):
        """Инициализировать ProbeManager.

        Args:
            curl_path: Путь к curl бинарнику (абсолютный, для launchd/GUI PATH).
            brew_components: Кортеж имен brew-сервисов для parse_brew_services.
        """
        self.curl_path = curl_path
        self.brew_components = brew_components or ("xray", "privoxy", "dnsmasq")

    def tunnel_code_up(self, code: Any) -> bool:
        """Единый предикат «канал/туннель до сервера жив» по HTTP-коду curl.

        Назначение probe туннеля/прямого доступа — доказать, что ТРАФИК ДОХОДИТ до сервера
        через канал, а не что конкретный URL отдаёт 200. Реальные endpoint'ы отвечают 4xx на '/'
        (api.anthropic.com → 404, api.openai.com → 421) — это ЖИВОЙ канал: сервер ответил HTTP.
        Мёртвым каналом считаем только:
          - 000 / нет кода — соединение не установлено (curl не достучался);
          - 5xx — сбой самого прокси-/upstream-слоя (мёртвый туннель за прокси).
        Живой = сервер вернул валидный HTTP-статус ниже 500.
        """
        return isinstance(code, int) and 100 <= code < 500

    def run(self, cmd_list: List[str], timeout: float, *, env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Всегда список аргументов, без shell=True. Возвращает dict и не бросает.

        timeout=True ТОЛЬКО при реальном истечении срока (TimeoutExpired). Прочие сбои запуска
        (нет бинаря — FileNotFoundError, нет прав — PermissionError, иной OSError) — это НЕ таймаут:
        возвращаем timeout=False с типизированной причиной в err.
        """
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
        except (OSError, ValueError, TypeError) as exc:
            # Process creation failures: OSError (binary not found, permission denied),
            # ValueError/TypeError on invalid input types. Return structured error.
            return {"rc": None, "out": "", "err": f"{type(exc).__name__}: {exc}", "timeout": False}

    def port_open(self, host: str, port: int, timeout: float = 0.5) -> bool:
        """Проверить, что порт открыт на хосте."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def parse_brew_services(self, text: str, names: Optional[tuple] = None) -> Dict[str, str]:
        """Разобрать `brew services list`; при names вернуть только нужные сервисы."""
        services = {}
        if not isinstance(text, str):
            return services
        # Если names не указан, используем brew_components по умолчанию
        allowed = set(names) if names is not None else set(self.brew_components)
        for line in text.splitlines():
            fields = line.split()
            if len(fields) < 2:
                continue
            name, state = fields[0], fields[1]
            if name in allowed:
                services[name] = state
        return services

    def brew_service_state(self, result: Dict[str, Any], name: str) -> str:
        """Семантика dashboard.py: timeout -> unknown, отсутствующий сервис -> none."""
        if result.get("timeout"):
            return "unknown"
        return self.parse_brew_services(result.get("out") or "", names=None).get(name, "none")

    def direct_probe(self, host: str, *, connect_timeout: int = 4, max_time: int = 8) -> Dict[str, Any]:
        """Прямой curl к host МИНУЯ прокси (env -u) — достигается ли домен без туннеля?

        Базовый слой без config — делят health.py (#206 GFW per-domain) и direct_first.py (#197).
        env -u всех proxy-vars (оба регистра) — прямой путь минуя privoxy/xray.

        Семантика reachable = ЛЮБОЙ HTTP-ответ сервера (включая 5xx): GFW даёт timeout/connection-reset,
        НЕ HTTP-ответ → сам факт HTTP-кода доказывает достижимость. 404/421/5xx =
        сервер ответил = канал работает. timeout/000 = режется/нет ответа.

        Возвращает {"reachable": bool, "kind": str}:
          reachable=True,  kind="ok"                  — сервер ответил HTTP < 500 (домен доступен);
          reachable=True,  kind="upstream-error"      — сервер ответил HTTP 5xx (vendor down);
          reachable=False, kind="timeout"             — curl timeout (GFW режет);
          reachable=False, kind="connection-failed"   — curl 000/no-response.
        Не бросает (probe-канон).
        """
        env = os.environ.copy()
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                    "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
            env.pop(key, None)
        # https:// + путь '/' — GFW режет на TLS-handshake к корню; -I (HEAD) лёгкий.
        r = self.run([self.curl_path, "-sS", "-o", "/dev/null", "-I",
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
        if self.tunnel_code_up(code_int):
            return {"reachable": True, "kind": "ok"}
        return {"reachable": True, "kind": "upstream-error"}


# ============================ Обратная совместимость ============================
# Module-level функции делегируют глобальному экземпляру ProbeManager.
# Это сохраняет существующий API в то же время позволяя использовать класс напрямую.

_default_manager = ProbeManager()


def tunnel_code_up(code: Any) -> bool:
    """Единый предикат «канал/туннель до сервера жив» по HTTP-коду curl."""
    return _default_manager.tunnel_code_up(code)


def run(cmd_list: List[str], timeout: float, *, env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Всегда список аргументов, без shell=True. Возвращает dict и не бросает."""
    return _default_manager.run(cmd_list, timeout, env=env)


def port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    """Проверить, что порт открыт на хосте."""
    return _default_manager.port_open(host, port, timeout)


def parse_brew_services(text: str, names: Optional[tuple] = None) -> Dict[str, str]:
    """Разобрать `brew services list`; при names вернуть только нужные сервисы."""
    return _default_manager.parse_brew_services(text, names)


def brew_service_state(result: Dict[str, Any], name: str) -> str:
    """Семантика dashboard.py: timeout -> unknown, отсутствующий сервис -> none."""
    return _default_manager.brew_service_state(result, name)


def direct_probe(host: str, *, connect_timeout: int = 4, max_time: int = 8) -> Dict[str, Any]:
    """Прямой curl к host МИНУЯ прокси (env -u) — достигается ли домен без туннеля?"""
    return _default_manager.direct_probe(host, connect_timeout=connect_timeout, max_time=max_time)


# Константы для обратной совместимости
BREW_COMPONENTS = _default_manager.brew_components
CURL = _default_manager.curl_path