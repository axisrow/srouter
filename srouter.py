#!/usr/bin/env python3
"""CLI-точка входа srouter: управление LaunchAgent дашборда (apply/uninstall-apply),
foreground-запуск (run) и статус демона (status).

CLI строит отдельный интерфейс поверх библиотечных функций install_lib — НЕ дублирует
логику рендеринга plist/загрузки launchd. Полная установка brew-стека (xray/privoxy/dnsmasq,
конфиги, сервисы, DNS) остаётся за ./install.sh apply (см. install_lib.py).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

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


def cmd_uninstall_apply(args) -> int:
    """Выгрузить и удалить srouter-managed LaunchAgent."""
    env = _env_from_args(args)
    result = apply_uninstall(env=env, confirmations={"launchagent": True}, runner=run)
    if result.get("ok"):
        print(f"LaunchAgent {LAUNCHAGENT_LABEL} выгружен и удалён.")
        return 0
    blocked = ", ".join(result.get("blocked") or ["unknown"])
    print(f"uninstall-apply остановлен: {blocked}", file=sys.stderr)
    return 2


def cmd_run(args) -> int:
    """Foreground-запуск дашборда (НЕ демон)."""
    import dashboard  # ленивый: без srouter_config.py поднимет SystemExit на старте
    dashboard.main()  # блокирует до Ctrl-C
    return 0


def cmd_status(args) -> int:
    """Статус LaunchAgent: загружен/нет, PID если есть."""
    result = run([LAUNCHCTL, "list"], 5)
    if result.get("timeout"):
        print("Не удалось получить статус: timeout launchctl list.", file=sys.stderr)
        return 2
    found = None
    for line in (result.get("out") or "").splitlines():
        fields = line.split()
        if fields and fields[0] == LAUNCHAGENT_LABEL:
            found = fields
            break
    env = InstallEnv.from_env()
    plist_path = env.launchagent_path()
    on_disk = plist_path.exists()
    marker_ok = on_disk and _has_launchagent_marker(plist_path)
    if found:
        pid = found[1] if len(found) > 1 else "-"
        marker = "ok" if marker_ok else "MISSING"
        print(f"LaunchAgent {LAUNCHAGENT_LABEL}: загружен (PID={pid}). plist={plist_path} (marker={marker})")
        return 0
    state = "plist на диске" if on_disk else "plist отсутствует"
    marker = "ok" if marker_ok else "absent/foreign"
    print(f"LaunchAgent {LAUNCHAGENT_LABEL}: НЕ загружен. ({state}; marker={marker})")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="srouter", description="Управление локальным дашбордом srouter.")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_env_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument("--state", default=None, help="Путь к srouter.local.json")
        p.add_argument("--prefix", default=None, help="Homebrew prefix")
        p.add_argument("--launchagents-dir", default=None, help="Каталог LaunchAgents")

    for name, help_text, fn in [
        ("apply", "Установить и загрузить LaunchAgent дашборда.", cmd_apply),
        ("uninstall-apply", "Выгрузить и удалить srouter-managed LaunchAgent.", cmd_uninstall_apply),
        ("status", "Показать статус LaunchAgent дашборда.", cmd_status),
    ]:
        p = sub.add_parser(name, help=help_text)
        add_env_flags(p)
        p.set_defaults(func=fn)

    p_run = sub.add_parser("run", help="Запустить дашборд в foreground (НЕ демон).")
    p_run.set_defaults(func=cmd_run)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
