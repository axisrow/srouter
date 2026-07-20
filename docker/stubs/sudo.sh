#!/bin/sh
# srouter acceptance: stub /usr/bin/sudo (тупой passthrough — путь 3).
# srouter зовёт sudo БЕЗ флагов, сразу команда: [SUDO, BREW, "services", "restart", "dnsmasq"]
# (install_lib.py:651/971) и [SUDO, BREW, ...] (srouter._is_privileged_cmd). В Docker контейнер уже
# root → sudo не нужен, просто проксируем команду (exec "$@") без повышения.
# stub обязателен: python:3.12-slim не содержит sudo → без stub был FileNotFoundError → dnsmasq_restart_failed.
# Если srouter когда-то добавит `sudo -n`/`sudo --` — расширить парсинг флагов (пока не нужно).
exec "$@"
