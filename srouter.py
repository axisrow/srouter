#!/usr/bin/env python3
"""CLI-точка входа srouter: управление LaunchAgent дашборда (apply/stop),
foreground-запуск (run) и статус демона (status).

CLI строит отдельный интерфейс поверх библиотечных функций install_lib — НЕ дублирует
логику рендеринга plist/загрузки launchd. Полная установка brew-стека (xray/privoxy/dnsmasq,
конфиги, сервисы, DNS) остаётся за ./install.sh apply (см. install_lib.py).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from importlib.metadata import PackageNotFoundError, version

from install_lib import (
    LAUNCHAGENT_LABEL,
    LAUNCHCTL,
    InstallEnv,
    _has_launchagent_marker,
    _install_launchagent,
    apply_uninstall,
)
from sys_probe import run


def _env_from_args(args) -> InstallEnv:
    """Собрать InstallEnv из флагов CLI (state/prefix/launchagents-dir)."""
    env = InstallEnv.from_env(state_path=args.state, prefix=args.prefix)
    if getattr(args, "launchagents_dir", None):
        env.launchagent_dir = Path(args.launchagents_dir)
    # Python, из которого запущена команда srouter — в нём гарантированно стоит flask (зависимость
    # пакета srouter). /usr/bin/python3 (default в install_lib) — системный Python Apple, flask'а нет,
    # демон крашнется с ModuleNotFoundError. SROUTER_PYTHON остаётся ручным override (используется тестами).
    env.python_bin = os.environ.get("SROUTER_PYTHON") or sys.executable
    return env


def cmd_apply(args) -> int:
    """Установить и загрузить LaunchAgent дашборда (loopback)."""
    env = _env_from_args(args)
    ok, error = _install_launchagent(env, runner=run)
    if ok:
        print(f"LaunchAgent {LAUNCHAGENT_LABEL} загружен: {env.launchagent_path()}")
        return 0
    print(f"Не удалось загрузить LaunchAgent: {error}", file=sys.stderr)
    return 2


def cmd_stop(args) -> int:
    """Выгрузить и удалить srouter-managed LaunchAgent."""
    env = _env_from_args(args)
    result = apply_uninstall(env=env, confirmations={"launchagent": True}, runner=run)
    if result.get("ok"):
        print(f"LaunchAgent {LAUNCHAGENT_LABEL} выгружен и удалён.")
        return 0
    blocked = ", ".join(result.get("blocked") or ["unknown"])
    print(f"stop остановлен: {blocked}", file=sys.stderr)
    return 2


def cmd_run(args) -> int:
    """Foreground-запуск дашборда (НЕ демон)."""
    import dashboard  # ленивый: без srouter_config.py поднимет SystemExit на старте
    dashboard.main()  # блокирует до Ctrl-C
    return 0


def cmd_status(args) -> int:
    """Статус LaunchAgent: работает / крашнулся / не загружен.

    Формат `launchctl list`: «PID  ExitCode  Label» (3 колонки). Ищем службу по последней
    колонке (fields[-1] == label) — она устойчива к числу предшествующих полей.
    """
    result = run([LAUNCHCTL, "list"], 5)
    if result.get("timeout"):
        print("Не удалось получить статус: timeout launchctl list.", file=sys.stderr)
        return 2
    fields = None
    for line in (result.get("out") or "").splitlines():
        row = line.split()
        if row and row[-1] == LAUNCHAGENT_LABEL:
            fields = row
            break

    env = InstallEnv.from_env()
    plist_path = env.launchagent_path()
    on_disk = plist_path.exists()
    marker_ok = on_disk and _has_launchagent_marker(plist_path)
    marker = "ok" if marker_ok else ("MISSING" if on_disk else "absent/foreign")

    if not fields:
        state = "plist на диске" if on_disk else "plist отсутствует"
        print(f"LaunchAgent {LAUNCHAGENT_LABEL}: НЕ загружен. ({state}; marker={marker})")
        return 1

    # launchctl list: fields[0]=PID ('-' если не запущен), fields[1]=ExitCode последнего запуска.
    pid = fields[0] if len(fields) > 0 else "-"
    exit_code = fields[1] if len(fields) > 1 else "-"
    if pid != "-":
        print(f"LaunchAgent {LAUNCHAGENT_LABEL}: загружен и работает (PID={pid}). "
              f"plist={plist_path} (marker={marker})")
        return 0
    if exit_code not in ("-", "0"):
        log_err = getattr(env, "log_err", None)
        log_hint = f"\n  лог ошибки: {log_err}" if log_err else ""
        print(f"LaunchAgent {LAUNCHAGENT_LABEL}: загружен, но процесс крашнулся "
              f"(exit code={exit_code}); launchd попытается перезапустить (KeepAlive). "
              f"plist={plist_path} (marker={marker}){log_hint}\n"
              f"  проверь ProgramArguments (Python с flask) и попробуй: srouter stop && srouter apply",
              file=sys.stderr)
        return 1
    print(f"LaunchAgent {LAUNCHAGENT_LABEL}: загружен, но не запущен (exit code=0). "
          f"plist={plist_path} (marker={marker})")
    return 1


def _version_string() -> str:
    """Версия из метаданных пакета (единственный источник — pyproject.toml)."""
    try:
        return version("srouter")
    except PackageNotFoundError:
        return "0.0.0+unknown"  # пакет не установлен (запуск из исходников без install)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="srouter", description="Управление локальным дашбордом srouter.")
    parser.add_argument("--version", action="version", version=f"srouter {_version_string()}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_env_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument("--state", default=None, help="Путь к srouter.local.json")
        p.add_argument("--prefix", default=None, help="Homebrew prefix")
        p.add_argument("--launchagents-dir", default=None, help="Каталог LaunchAgents")

    for name, help_text, fn in [
        ("apply", "Установить и загрузить LaunchAgent дашборда.", cmd_apply),
        ("stop", "Выгрузить и удалить srouter-managed LaunchAgent.", cmd_stop),
        ("status", "Показать статус LaunchAgent дашборда.", cmd_status),
    ]:
        p = sub.add_parser(name, help=help_text)
        add_env_flags(p)
        p.set_defaults(func=fn)

    # `run` и `start` — синонимы: foreground-запуск дашборда (НЕ демон).
    for name in ("run", "start"):
        p_run = sub.add_parser(name, help="Запустить дашборд в foreground (НЕ демон).")
        p_run.set_defaults(func=cmd_run)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
