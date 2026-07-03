#!/usr/bin/env python3
"""CLI-точка входа srouter: управление демоном дашборда (LaunchAgent).

Два уровня команд:
  install/uninstall — постановка/снятие службы (plist-файл), одноразово;
  start/stop/restart — управление запущенным процессом (plist не трогается);
  status — состояние демона.

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


def cmd_install(args) -> int:
    """Установить LaunchAgent (plist) и запустить демон. Одноразовая настройка."""
    env = _env_from_args(args)
    ok, error = _install_launchagent(env, runner=run)
    if ok:
        print(f"LaunchAgent {LAUNCHAGENT_LABEL} установлен и запущен: {env.launchagent_path()}")
        return 0
    print(f"Не удалось установить LaunchAgent: {error}", file=sys.stderr)
    return 2


def cmd_uninstall(args) -> int:
    """Выгрузить демон и удалить srouter-managed LaunchAgent (plist)."""
    env = _env_from_args(args)
    result = apply_uninstall(env=env, confirmations={"launchagent": True}, runner=run)
    if result.get("ok"):
        print(f"LaunchAgent {LAUNCHAGENT_LABEL} выгружен и удалён.")
        return 0
    blocked = ", ".join(result.get("blocked") or ["unknown"])
    print(f"uninstall остановлен: {blocked}", file=sys.stderr)
    return 2


def _launchd_domain() -> str:
    """Домен launchd текущего пользователя: gui/<uid>."""
    return f"gui/{os.getuid()}"


def _is_loaded() -> bool | None:
    """Загружен ли LaunchAgent в launchd (по launchctl list). None — не удалось узнать."""
    r = run([LAUNCHCTL, "list"], 5)
    if r.get("timeout"):
        return None
    return any(row.split() and row.split()[-1] == LAUNCHAGENT_LABEL
               for row in (r.get("out") or "").splitlines())


def cmd_start(args) -> int:
    """Запустить демон (plist уже должен быть установлен через `install`)."""
    env = _env_from_args(args)
    plist = env.launchagent_path()
    if not plist.exists():
        print("Служба не установлена. Сначала выполните: srouter install", file=sys.stderr)
        return 2
    if _is_loaded():
        print(f"Демон уже запущен: {LAUNCHAGENT_LABEL}")
        return 0
    r = run([LAUNCHCTL, "bootstrap", _launchd_domain(), str(plist)], 15)
    if r.get("timeout") or r.get("rc") != 0:
        print(f"Не удалось запустить демон: {r.get('err') or r.get('out') or 'unknown error'}",
              file=sys.stderr)
        return 2
    print(f"Демон запущен: {LAUNCHAGENT_LABEL}")
    return 0


def cmd_stop(args) -> int:
    """Остановить демон, сохранив plist (в отличие от uninstall)."""
    loaded = _is_loaded()
    if loaded is False:
        print(f"Демон не запущен: {LAUNCHAGENT_LABEL}")
        return 0
    r = run([LAUNCHCTL, "bootout", f"{_launchd_domain()}/{LAUNCHAGENT_LABEL}"], 15)
    # bootout возвращает ненулевой rc, если уже выгружен — это не ошибка для нас.
    if r.get("timeout"):
        print("timeout bootout", file=sys.stderr)
        return 2
    print(f"Демон остановлен: {LAUNCHAGENT_LABEL} (plist сохранён)")
    return 0


def cmd_restart(args) -> int:
    """Перезапустить демон (применить правки кода). plist не трогается."""
    env = _env_from_args(args)
    plist = env.launchagent_path()
    # bootout (игнорируем ошибку если не загружен) + bootstrap.
    run([LAUNCHCTL, "bootout", f"{_launchd_domain()}/{LAUNCHAGENT_LABEL}"], 10)
    r = run([LAUNCHCTL, "bootstrap", _launchd_domain(), str(plist)], 15)
    if r.get("timeout") or (r.get("rc") != 0 and not _is_loaded()):
        print(f"Не удалось перезапустить демон: {r.get('err') or r.get('out') or 'unknown error'}",
              file=sys.stderr)
        return 2
    print(f"Демон перезапущен: {LAUNCHAGENT_LABEL}")
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
              f"  проверь ProgramArguments (Python с flask) и попробуй: srouter restart",
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
        ("install", "Установить LaunchAgent и запустить демон (одноразово).", cmd_install),
        ("uninstall", "Остановить демон и удалить LaunchAgent (plist).", cmd_uninstall),
        ("start", "Запустить демон (plist уже установлен).", cmd_start),
        ("stop", "Остановить демон (plist сохранён).", cmd_stop),
        ("restart", "Перезапустить демон (применить правки кода).", cmd_restart),
        ("status", "Показать статус демона.", cmd_status),
    ]:
        p = sub.add_parser(name, help=help_text)
        add_env_flags(p)
        p.set_defaults(func=fn)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
