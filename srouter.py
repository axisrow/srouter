#!/usr/bin/env python3
"""CLI srouter: управление локальным стеком (xray/privoxy/dnsmasq) и демоном дашборда.

Команды:
  install/uninstall — полная установка/откат стека (brew-сервисы, конфиги, DNS, LaunchAgent);
                      uninstall дополнительно удаляет split-route до VPS.
  start/stop/restart — управление демоном дашборда (plist не трогается после install).
  status             — состояние демона.

Привилегии — автодетект: под sudo (os.geteuid()==0) привилегированные шаги идут напрямую;
иначе networksetup/route/sudo-brew-dnsmasq оборачиваются в osascript-мост с GUI-паролем macOS
(канон: dashboard.py _sudo_route_ip).

CLI — тонкий слой над install_lib.apply_install/apply_uninstall; рендеринг plist и логика
конфликтов живут в install_lib.py (покрыты pytest без реальных привилегий).
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import shlex
import sys
from pathlib import Path
from importlib.metadata import PackageNotFoundError, version

import local_state
from install_lib import (
    BREW,
    NETWORKSETUP,
    ROUTE,
    SUDO,
    CHOICES,
    LAUNCHAGENT_LABEL,
    LAUNCHCTL,
    InstallEnv,
    _has_launchagent_marker,
    apply_install,
    apply_uninstall,
    build_plan,
    build_uninstall_plan,
    format_plan,
    format_uninstall_plan,
    _install_generic_launchagent,
)
from sys_probe import run

import claude_proxy  # вкл/откл HTTPS_PROXY для Claude Code (~/.claude/settings.json)
import health  # doctor-проверки стека

# OSASCRIPT отсутствует в install_lib — локальная константа (копия dashboard_common).
OSASCRIPT = "/usr/bin/osascript"


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


def _is_privileged_cmd(cmd) -> bool:
    """Только эти сигнатуры install_lib требуют root. Остальное (brew/launchctl/lsof,
    route -n get, networksetup -listallnetworkservices) работает без повышения."""
    if not cmd:
        return False
    head = cmd[0]
    # networksetup -setdnsservers — мутация DNS (НЕ -listallnetworkservices, это чтение).
    if head == NETWORKSETUP and len(cmd) > 1 and cmd[1] == "-setdnsservers":
        return True
    # sudo brew services ... dnsmasq — dnsmasq на UDP:53. xray/privoxy идут БЕЗ sudo.
    if head == SUDO and len(cmd) > 1 and cmd[1] == BREW:
        return True
    # route -n delete -host <ip> — удаление split-route (новое в uninstall). route get — чтение.
    if head == ROUTE and len(cmd) > 2 and cmd[1] == "-n" and cmd[2] == "delete":
        return True
    return False


def _to_osascript(cmd):
    """Обернуть cmd в osascript-мост 'do shell script ... with administrator privileges'.

    SUDO удаляется из cmd — osascript сам повышает привилегии (канон dashboard.py:122-134).
    Без этого получилось бы sudo внутри уже-privileges-сессии (избыточно, потенциально ломается).
    """
    cleaned = list(cmd[1:] if cmd and cmd[0] == SUDO else cmd)
    shell_cmd = " ".join(shlex.quote(str(a)) for a in cleaned)
    applescript = f'do shell script "{shell_cmd}" with administrator privileges'
    return [OSASCRIPT, "-e", applescript]


def make_privileged_runner(underlying_run=run, *, osascript_timeout: int = 60):
    """runner(cmd, timeout) с автодетектом привилегий.

    Под sudo (os.geteuid()==0) все команды идут напрямую. Иначе привилегированные
    (networksetup -setdnsservers / sudo brew ... dnsmasq / route delete) оборачиваются
    в osascript-мост с GUI-паролем; остальные — напрямую.
    """
    am_root = os.geteuid() == 0

    def runner(cmd, timeout):
        if not _is_privileged_cmd(cmd) or am_root:
            return underlying_run(cmd, timeout)
        return underlying_run(_to_osascript(cmd), osascript_timeout)

    return runner


def _is_ip_literal(value) -> bool:
    """Строгая проверка IP-литерала. Канон dashboard_common._ip_literal, но без импорта
    dashboard_common (он тянет srouter_config через module-level код)."""
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
    while True:
        answer = input(f"Выбор для {name} [adopt/overwrite/skip]: ").strip().lower()
        if answer in CHOICES:
            return answer
        print("Допустимо: adopt, overwrite, skip.")


def _active_route_ip_for_removal(state_path) -> str:
    """route_ip активного узла для route delete. '' если нет валидного IP/узла."""
    try:
        node = local_state.active_node(path=state_path) or {}
        route_ip = local_state.resolve_route_ip(node, path=state_path)
    except Exception:
        return ""
    return route_ip if _is_ip_literal(route_ip) else ""


def _remove_active_split_route(state_path, runner) -> int:
    """route -n delete -host <active_route_ip>. Idempotent: отсутствие маршрута = успех.

    Возвращает 0 (ok/нечего удалять), 2 (отмена GUI/сбой).
    """
    route_ip = _active_route_ip_for_removal(state_path)
    if not route_ip:
        print("split-route: нет активного route_ip — пропуск удаления маршрута.")
        return 0
    print(f"split-route: удаляю маршрут до {route_ip} ...")
    result = runner([ROUTE, "-n", "delete", "-host", route_ip], 60)
    if result.get("timeout"):
        print(f"split-route: timeout при удалении маршрута до {route_ip}.", file=sys.stderr)
        return 2
    rc = result.get("rc")
    if rc == 0:
        return 0
    err = f"{result.get('err') or ''} {result.get('out') or ''}"
    if rc == -128 or "-128" in err:
        print("split-route: удаление маршрута отменено пользователем (диалог пароля).", file=sys.stderr)
        return 2
    if "not in table" in err.lower() or "no such process" in err.lower():
        return 0  # маршрута уже нет — idempotent успех
    print(f"split-route: не удалось удалить маршрут до {route_ip}: {err.strip()}", file=sys.stderr)
    return 2


def cmd_install(args) -> int:
    """Полная установка стека: brew-сервисы + конфиги + DNS + LaunchAgent.

    Показывает план, при конфликтах (чужие конфиги) спрашивает adopt/overwrite/skip,
    подтверждает. Делегирует тяжёлую работу в install_lib.apply_install.
    """
    env = _env_from_args(args)
    runner = make_privileged_runner(run)

    # 1) Discovery (ничего не пишет).
    try:
        plan = build_plan(env=env, runner=runner)
    except Exception as exc:
        print(f"install: сбой discovery: {exc}", file=sys.stderr)
        return 2

    # 2) Показать план.
    print(format_plan(plan))
    print()

    # 3) Конфликты → интерактивный выбор per компонент.
    choices = {}
    conflicts = [(name, item) for name, item in (plan.get("components") or {}).items()
                 if isinstance(item, dict) and item.get("conflict")]
    if conflicts:
        if not sys.stdin.isatty():
            names = ", ".join(n for n, _ in conflicts)
            print(f"install: обнаружены конфликты ({names}); разрешите вручную или удалите чужие "
                  f"конфиги.", file=sys.stderr)
            return 2
        for name, item in conflicts:
            reasons = ", ".join(item.get("conflicts") or [])
            print(f"\nКонфликт по компоненту {name} ({reasons}):")
            print(f"  config_path: {item.get('config_path')}")
            print(f"  port_owner:  {item.get('port_owner') or '-'}")
            choices[name] = _prompt_choice(name)
        print()

    # 4) Подтверждение.
    if not sys.stdin.isatty():
        print("install: подтверждение требует терминал (используйте -y/--yes).", file=sys.stderr)
        return 2
    if not getattr(args, "yes", False) and not _prompt_bool("Применить установку стека?"):
        print("install отменён.")
        return 1

    # 5) apply: confirm=True, choices собраны, launchagent ставится тоже.
    result = apply_install(
        env=env, confirm=True, choices=choices,
        runner=runner, install_launchagent=True,
    )
    if result.get("ok"):
        # Claude Code обязан ходить через прокси (изоляция режет api.anthropic.com напрямую).
        # Best-effort: не критично для install, но удобно «из коробки».
        cp = claude_proxy.enable()
        cp_note = ("Claude Code: HTTPS_PROXY прописан в ~/.claude/settings.json."
                   if cp.get("ok") else
                   f"Claude Code: не удалось прописать HTTPS_PROXY ({cp.get('err', 'unknown')}).")
        # Watchdog-plist: фоновый пинг туннеля раз в 90с + macOS-нотификация при падении.
        # Best-effort (не критично для install), но удобно «из коробки» — защищает от «остался без ИИ».
        wd_ok, wd_err = _install_generic_launchagent(
            env, runner,
            template_name="com.srouter.watchdog.plist",
            label="com.srouter.watchdog",
            marker="srouter-managed-watchdog-v1",
            script_path=env.root / "health.py",
        )
        wd_note = ("Watchdog: установлен (нотификация при падении туннеля)."
                   if wd_ok else
                   f"Watchdog: не установлен ({wd_err}).")
        print("Установка стека завершена: brew-сервисы, конфиги, DNS, LaunchAgent применены.\n"
              f"{cp_note}\n"
              f"{wd_note}\n"
              f"Дашборд: http://127.0.0.1:8787  (srouter status — проверить)")
        return 0
    blocked = ", ".join(result.get("blocked") or ["unknown"])
    print(f"install остановлен: {blocked}", file=sys.stderr)
    if "plan" in result:
        print(format_plan(result["plan"]), file=sys.stderr)
    return 2


def cmd_uninstall(args) -> int:
    """Полный откат к дефолту: brew-сервисы, конфиги (restore из бэкапа), DNS, LaunchAgent.

    apply_uninstall сам выгружает демон и останавливает сервисы. ДОПОЛНИТЕЛЬНО удаляет
    split-route до VPS (install_lib про маршрут не знает).
    """
    env = _env_from_args(args)
    runner = make_privileged_runner(run)
    state_path = getattr(args, "state", None)

    # 1) Discovery + показ плана.
    try:
        plan = build_uninstall_plan(env=env)
    except Exception as exc:
        print(f"uninstall: сбой discovery: {exc}", file=sys.stderr)
        return 2
    print(format_uninstall_plan(plan))
    print()

    # 2) Подтверждение (полный откат — серьёзный шаг).
    if not sys.stdin.isatty():
        print("uninstall: подтверждение требует терминал (используйте -y/--yes).", file=sys.stderr)
        return 2
    if not getattr(args, "yes", False) and not _prompt_bool("Полный откат стека к дефолту?"):
        print("uninstall отменён.")
        return 1

    # 3) apply_uninstall: ВСЕ 4 категории. Сам остановит сервисы и выгрузит демон.
    result = apply_uninstall(
        env=env,
        confirmations={"configs": True, "services": True, "dns": True, "launchagent": True},
        runner=runner,
    )
    if not result.get("ok"):
        blocked = ", ".join(result.get("blocked") or ["unknown"])
        print(f"uninstall остановлен: {blocked}", file=sys.stderr)
        return 2

    # 4) Удалить split-route (новое — install_lib про маршрут не знает).
    route_rc = _remove_active_split_route(state_path, runner)

    # 5) Снять HTTPS_PROXY для Claude Code — privoxy больше не запущен, прокси бессмысленен.
    cp = claude_proxy.disable()
    cp_note = ". Claude Code HTTPS_PROXY снят." if cp.get("ok") else ""

    print("Откат завершён: brew-сервисы остановлены, конфиги восстановлены/оставлены, "
          "DNS сброшен, LaunchAgent удалён"
          + (". split-route удалён." if route_rc == 0 else ", split-route не удалён — см. выше.")
          + cp_note)
    return 0


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


def cmd_doctor(args) -> int:
    """Проверить здоровье стека: порты + реальный туннель. Отчёт ✅/❌ + подсказки."""
    result = health.check_all()
    health._print_report(result)
    return 0 if result["status"] == "ok" else 1


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
        ("install", "Полная установка стека (brew-сервисы + конфиги + DNS + LaunchAgent).", cmd_install),
        ("uninstall", "Полный откат стека + удаление split-route.", cmd_uninstall),
        ("start", "Запустить демон (plist уже установлен).", cmd_start),
        ("stop", "Остановить демон (plist сохранён).", cmd_stop),
        ("restart", "Перезапустить демон (применить правки кода).", cmd_restart),
        ("status", "Показать статус демона.", cmd_status),
        ("doctor", "Проверить здоровье стека (порты + туннель).", cmd_doctor),
    ]:
        p = sub.add_parser(name, help=help_text)
        add_env_flags(p)
        if name in ("install", "uninstall"):
            p.add_argument("-y", "--yes", action="store_true",
                           help="Подтвердить без интерактивного промпта (конфликты всё равно блокируют).")
        p.set_defaults(func=fn)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
