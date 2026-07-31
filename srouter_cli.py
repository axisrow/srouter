"""CLI интерфейс srouter (argparse + команды).

Вынесено из srouter.py для issue #228 (refactor эпик #158).

ВНИМАНИЕ: временная заглушка для завершения экстракции. Полная реализация
будет восстановлена из оригинального srouter.py после завершения рефакторинга.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from importlib.metadata import PackageNotFoundError, version

# Импортируем из оригинальных модулей
from install_lib import InstallEnv


def _env_from_args(args) -> InstallEnv:
    """Собрать InstallEnv из флагов CLI (state/prefix/launchagents-dir)."""
    env = InstallEnv.from_env(state_path=args.state, prefix=args.prefix)
    if getattr(args, "launchagents_dir", None):
        env.launchagent_dir = Path(args.launchagents_dir)
    # Python, из которого запущена команда srouter — в нём гарантированно стоит flask (зависимость
    # пакета srouter). /usr/bin/python3 (default в install_lib) — системный Python Apple, flask'а нет,
    # демон крашнется с ModuleNotFoundError. Приоритет: --python флаг (для sudo) → SROUTER_PYTHON env → sys.executable.
    env.python_bin = getattr(args, "python", None) or os.environ.get("SROUTER_PYTHON") or sys.executable
    return env


def _is_ip_literal(value) -> bool:
    """Строгая проверка IP-литерала."""
    import ipaddress
    if not isinstance(value, str) or not value or "%" in value:
        return False
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return False
    return str(parsed) == value


def _prompt_bool(label: str) -> bool:
    return input(f"{label} [y/N]: ").strip().lower() in {"y", "yes", "д", "да"}


def _prompt_choice(name: str) -> str:
    """adopt | overwrite | skip (install_lib.CHOICES)."""
    from install_lib import CHOICES
    while True:
        answer = input(f"Выбор для {name} [adopt/overwrite/skip]: ").strip().lower()
        if answer in CHOICES:
            return answer
        print("Допустимо: adopt, overwrite, skip.")


def _version_string() -> str:
    """Версия пакета srouter."""
    try:
        return f"srouter {version('srouter')}"
    except PackageNotFoundError:
        return "srouter (dev/unknown version)"


def _read_routing_domains(config_path, outbound):
    """Прочитать routing-домены из xray config."""
    import json
    try:
        with open(config_path, encoding="utf-8") as f:
            cfg = json.load(f)
        return [rule.get("domain", "") for rule in cfg.get(outbound, {}).get("routing", {}).get("rules", []) if rule.get("domain")]
    except Exception:
        return []


def _routing_has_marker(config_path, outbound):
    """Проверить наличие маркера в routing rules."""
    import json
    try:
        with open(config_path, encoding="utf-8") as f:
            cfg = json.load(f)
        for rule in cfg.get(outbound, {}).get("routing", {}).get("rules", []):
            if "# srouter-managed-domain" in rule.get("domain", ""):
                return True
        return False
    except Exception:
        return False


def _delegate_command(name: str, args) -> int:
    """Временно вызвать реализацию команды из legacy-модуля.

    Реализации остаются в srouter.py до завершения экстракции; импорт внутри функции
    сохраняет возможность импортировать этот CLI-модуль без циклического импорта.
    """
    from srouter import __dict__ as legacy
    return legacy[name](args)


def cmd_install(args) -> int:
    return _delegate_command("cmd_install", args)

def cmd_uninstall(args) -> int:
    return _delegate_command("cmd_uninstall", args)

def cmd_start(args) -> int:
    return _delegate_command("cmd_start", args)

def cmd_stop(args) -> int:
    return _delegate_command("cmd_stop", args)

def cmd_restart(args) -> int:
    return _delegate_command("cmd_restart", args)

def cmd_status(args) -> int:
    return _delegate_command("cmd_status", args)

def cmd_doctor(args) -> int:
    return _delegate_command("cmd_doctor", args)

def cmd_sync(args) -> int:
    return _delegate_command("cmd_sync", args)

def cmd_routing(args) -> int:
    return _delegate_command("cmd_routing", args)

def cmd_privoxy(args) -> int:
    return _delegate_command("cmd_privoxy", args)


def build_parser() -> argparse.ArgumentParser:
    """Создать ArgumentParser для CLI srouter."""
    parser = argparse.ArgumentParser(
        prog="srouter",
        description="Управление локальным дашбордом srouter.",
        formatter_class=argparse.HelpFormatter,
    )
    parser.add_argument("--version", action="store_true", help="показать версию и выйти")

    subparsers = parser.add_subparsers(dest="command", help="Доступные команды")
    parser.set_defaults(
        state=None, prefix=None, launchagents_dir=None, python=None,
        yes=False, force_endpoint_overwrite=False,
    )

    # install
    install_parser = subparsers.add_parser("install", help="Полная установка стека (brew-сервисы + конфиги + DNS + LaunchAgent).")
    install_parser.add_argument("-y", "--yes", action="store_true", help="подтвердить без промпта")

    # uninstall
    uninstall_parser = subparsers.add_parser("uninstall", help="Полный откат стека + удаление split-route.")
    uninstall_parser.add_argument("-y", "--yes", action="store_true", help="подтвердить без промпта")

    # start
    start_parser = subparsers.add_parser("start", help="Запустить демон (plist уже установлен).")

    # stop
    stop_parser = subparsers.add_parser("stop", help="Остановить демон (plist сохранён).")

    # restart
    restart_parser = subparsers.add_parser("restart", help="Перезапустить демон (применить правки кода).")

    # status
    status_parser = subparsers.add_parser("status", help="Показать статус демона.")

    # doctor
    doctor_parser = subparsers.add_parser("doctor", help="Проверить здоровье стека (порты + туннель).")

    # sync
    sync_parser = subparsers.add_parser("sync", help="Импорт endpoint из рабочего xray в local.json (рассинхрон placeholder). #200.")

    # routing
    routing_parser = subparsers.add_parser("routing", help="Управление routing-доменами xray (add-domain/remove-domain/list). #136.")
    routing_parser.add_argument("action", choices=["add-domain", "remove-domain", "list"], help="Действие с доменами")
    routing_parser.add_argument("domain", nargs="?", help="Домен (для add-domain/remove-domain)")

    # privoxy
    privoxy_parser = subparsers.add_parser("privoxy", help="Защищённый system-режим Privoxy.")

    return parser


def main(argv=None) -> int:
    """Точка входа CLI srouter."""
    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(_version_string())
        return 0

    if not args.command:
        parser.print_help()
        return 0

    # Диспетчеризация команд
    cmd_func = {
        "install": cmd_install,
        "uninstall": cmd_uninstall,
        "start": cmd_start,
        "stop": cmd_stop,
        "restart": cmd_restart,
        "status": cmd_status,
        "doctor": cmd_doctor,
        "sync": cmd_sync,
        "routing": cmd_routing,
        "privoxy": cmd_privoxy,
    }.get(args.command)

    if cmd_func:
        return cmd_func(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
