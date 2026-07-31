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

Refactor issue #228: модуль разбит на srouter_cli.py, srouter_launchd.py, codex_wrappers.py.
Этот файл сохраняет обратную совместимость через переэкспорт.
"""

from __future__ import annotations

import sys
import os
from pathlib import Path
from importlib.metadata import PackageNotFoundError, version
import ipaddress

from install_lib import InstallEnv, CHOICES, LAUNCHAGENT_LABEL, _launchd_reload, _launchd_unload, build_plan, format_plan, apply_install, apply_uninstall, _reclaimable_resolves_all_conflicts
from sys_probe import run

# Вспомогательные функции (остаются здесь для обратной совместимости)
def _env_from_args(args) -> InstallEnv:
    """Собрать InstallEnv из флагов CLI (state/prefix/launchagents-dir)."""
    env = InstallEnv.from_env(state_path=args.state, prefix=args.prefix)
    if getattr(args, "launchagents_dir", None):
        env.launchagent_dir = Path(args.launchagents_dir)
    env.python_bin = getattr(args, "python", None) or os.environ.get("SROUTER_PYTHON") or sys.executable
    return env


def _prompt_bool(label: str) -> bool:
    return input(f"{label} [y/N]: ").strip().lower() in {"y", "yes", "д", "да"}


def _prompt_choice(name: str) -> str:
    """adopt | overwrite | skip (install_lib.CHOICES)."""
    while True:
        answer = input(f"Выбор для {name} [adopt/overwrite/skip]: ").strip().lower()
        if answer in CHOICES:
            return answer
        print("Допустимо: adopt, overwrite, skip.")


# Переэкспорт из codex_wrappers.py
from codex_wrappers import (
    CODEX_NO_PROXY,
    CODEX_NO_PROXY_LOOPBACK,
    CODEX_LAUNCHCTL_ENV,
    CODEX_WRAPPERS,
    CODEX_CLI_WRAPPER_NAME,
    CODEX_CLI_WRAPPER_LEGACY_NAME,
    CODEX_ENV_LABEL,
    CODEX_ENV_MARKER,
    ZSHRC_PATH_MARKER,
    ZSHRC_CODEX_FUNC_MARKER_BEGIN,
    ZSHRC_CODEX_FUNC_MARKER_END,
    _codex_wrapper_path,
    _zshrc_path,
    _looks_like_managed_codex_wrapper,
    _codex_bin_path,
    _install_one_wrapper,
    _install_codex_wrappers,
    _migrate_legacy_codex_cli_wrapper,
    _remove_one_wrapper,
    _remove_codex_wrappers,
    _install_launchctl_env,
    _remove_launchctl_env,
    _ensure_home_bin_in_path,
    _remove_home_bin_from_path,
    _codex_zsh_target_installed,
    _install_codex_zsh_function,
    _remove_codex_zsh_function,
    _install_codex_isolation,
    _remove_codex_isolation,
)

# Переэкспорт из srouter_launchd.py
from srouter_launchd import (
    PPP_HOOK_PATH,
    PPP_HOOK_MARKER,
    _is_ip_literal,
    _active_route_ip_for_removal,
    _remove_active_split_route,
    _install_ppp_hook,
    _remove_ppp_hook,
)

# Переэкспорт из srouter_cli.py (только функции, не команды)
from srouter_cli import (
    _version_string,
    _read_routing_domains,
    _routing_has_marker,
    build_parser,
    main,
)

# Оставшиеся функции (будут извлечены позже)
from install_lib import (
    BREW,
    ROUTE,
    CHOICES,
    LAUNCHAGENT_LABEL,
    LAUNCHCTL,
    InstallEnv,
    _has_launchagent_marker,
    _launchd_domain,
    _launchd_is_loaded,
    _launchd_reload,
    _launchd_unload,
    _write_text_atomic,
    apply_install,
    apply_uninstall,
    build_plan,
    build_uninstall_plan,
    format_plan,
    format_uninstall_plan,
    _install_generic_launchagent,
    _reclaimable_resolves_all_conflicts,
    load_known_markers,
    populate_known_markers,
    port_open,
)
from sys_probe import run
from install_lib import CHOICES

import claude_proxy
import git_proxy
import vscode_proxy
import health
import marker_block
import privoxy_audit
import privoxy_system
import privileged_ops

# OSASCRIPT переэкспортируется из privileged_ops (единый источник #156) для обратной
# совместимости с тестами/кодом, обращающимся к srouter.OSASCRIPT.
OSASCRIPT = privileged_ops.OSASCRIPT

import claude_proxy
import git_proxy
import vscode_proxy
import health
import marker_block
import privoxy_audit
import privoxy_system
import privileged_ops

# OSASCRIPT переэкспортируется из privileged_ops (единый источник #156) для обратной
# совместимости с тестами/кодом, обращающимся к srouter.OSASCRIPT.
OSASCRIPT = privileged_ops.OSASCRIPT


def _is_privileged_cmd(cmd) -> bool:
    """Только эти сигнатуры install_lib требуют root. Остальное (brew/launchctl/lsof,
    route -n get, networksetup -listallnetworkservices) работает без повышения.

    Делегирует в privileged_ops.is_allowed — единый whitelist привилегированных команд (#156).
    Сохранено как тонкая обёртка для обратной совместимости с тестами/вызовами.
    """
    return privileged_ops.is_allowed(cmd)


def _to_osascript(cmd):
    """Обернуть cmd в osascript-мост 'do shell script ... with administrator privileges'.

    Делегирует в privileged_ops.build_osascript — единый канон экранирования
    (dashboard_common._applescript_text, #154) и очистки SUDO (#156).
    """
    return privileged_ops.build_osascript(cmd)


def make_privileged_runner(underlying_run=run, *, osascript_timeout: int = 60):
    """runner(cmd, timeout) с автодетектом привилегий.

    Под sudo (os.geteuid()==0) все команды идут напрямую. Иначе привилегированные
    (networksetup -setdnsservers / sudo brew ... dnsmasq / route delete) оборачиваются
    в osascript-мост с GUI-паролем; остальные — напрямую.

    Делегирует классификацию в privileged_ops (#156), сохраняя прежнее поведение
    (непривилегированные/ root — напрямую; привилегированные не-root — osascript).
    """
    import os

    am_root = os.geteuid() == 0

    def runner(cmd, timeout):
        if not _is_privileged_cmd(cmd) or am_root:
            return underlying_run(cmd, timeout)
        return underlying_run(_to_osascript(cmd), osascript_timeout)

    return runner


# Функции для работы с launchd (остаются в srouter.py временно)
def _is_loaded():
    """Загружен ли LaunchAgent srouter-dashboard?"""
    try:
        return _launchd_is_loaded(LAUNCHAGENT_LABEL, domain="user")
    except Exception:
        return False


# Полные реализации команд (временно в srouter.py, будут перенесены в srouter_cli.py)
def cmd_install(args) -> int:
    """Полная установка стека: brew-сервисы + конфиги + DNS + LaunchAgent."""
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
                 if isinstance(item, dict) and item.get("conflict")
                 and not _reclaimable_resolves_all_conflicts(item)]
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
    if not sys.stdin.isatty() and not getattr(args, "yes", False):
        print("install: подтверждение требует терминал (используйте -y/--yes).", file=sys.stderr)
        return 2
    if not getattr(args, "yes", False) and not _prompt_bool("Применить установку стека?"):
        print("install отменён.")
        return 1

    # 5) apply: confirm=True, choices собраны, launchagent ставится тоже.
    result = apply_install(
        env=env, confirm=True, choices=choices,
        runner=runner, install_launchagent=True,
        force_endpoint_overwrite=getattr(args, "force_endpoint_overwrite", False),
    )
    if result.get("ok"):
        # Claude Code обязан ходить через прокси (изоляция режет api.anthropic.com напрямую).
        # Best-effort: не критично для install, но удобно «из коробки».
        cp = claude_proxy.enable()
        cp_note = ("Claude Code: HTTPS_PROXY прописан в ~/.claude/settings.json."
                   if cp.get("ok") else
                   f"Claude Code: не удалось прописать HTTPS_PROXY ({cp.get('err', 'unknown')}).")
        # issue #130: git → SOCKS5 (xray 10808) scoped на github.com, автоматически, без ручных
        # правок ~/.gitconfig. Best-effort (не критично для install, но часть «одна команда, всё
        # правильно» — git умеет нативный SOCKS5, в отличие от Claude Code).
        gp = git_proxy.enable()
        gp_note = (f"git: github-proxy прописан в ~/.gitconfig ({gp.get('proxy', '')})."
                   if gp.get("ok") else
                   f"git: не удалось прописать github-proxy ({gp.get('err', 'unknown')}).")
        # Watchdog-plist: фоновый пинг туннеля раз в 90с + macOS-нотификация при падении.
        # Best-effort (не критично для install), но удобно «из коробки» — защищает от «остался без ИИ».
        wd_ok, wd_err = _install_generic_launchagent(
            env, runner,
            template_name="com.srouter.watchdog.plist",
            label="com.srouter.watchdog",
            marker="srouter-managed-watchdog-v1",
            script_path=env.root / "health.py",
        )
        wd_note = ("Watchdog: установлен (нотификация при падении туннеля, poll 20с)."
                   if wd_ok else
                   f"Watchdog: не установлен ({wd_err}).")
        # ppp-hook: мгновенный split-route при VPN up (/etc/ppp/ip-up, от root, без osascript).
        ppp_note = _install_ppp_hook(env, runner)
        # Codex SOCKS5-wrappers (~/.local/bin wrappers через ~/bin) + launchctl env + PATH +
        # shell-функция codex() в ~/.zshrc — чтобы Codex (CLI и App) ходил напрямую в xray (10808),
        # минуя privoxy (портит WS-стриминг). Функция (#96) гарантирует победу над brew в PATH.
        codex_note = _install_codex_wrappers(env)
        codex_func_note = _install_codex_zsh_function(env)
        # issue #189: codenv (LaunchAgent com.srouter.codenv) ВОССТАНОВЛЕН в install.
        codenv_note = _install_launchctl_env(env, runner)
        # issue #185: scoped SOCKS5 для codex-расширения openai.chatgpt через VSCode http.proxy.
        vp = vscode_proxy.enable()
        if vp.get("ok"):
            vp_note = ("scoped SOCKS5 в VSCode http.proxy (Code/Cursor) — расширение openai.chatgpt, "
                       "CC не затрагивается (#185)"
                       + (f" Пути: {', '.join(vp.get('paths') or [])}" if vp.get('paths') else ""))
        else:
            vp_note = f"scoped VSCode http.proxy не установлен ({vp.get('err', 'unknown')})."
        env_note = f"{codenv_note} VSCode: {vp_note}"
        path_note = _ensure_home_bin_in_path(env)
        codex_iso_note = _install_codex_isolation(env, runner)
        # Marker-migration table (issue #112 Часть 4): регистрируем текущие маркеры wrappers/zshrc/codenv
        # в state.known_markers.
        try:
            _km_state_path = env.state_path
            for _entry in CODEX_WRAPPERS:
                populate_known_markers(_km_state_path, "wrappers", [_entry[2]])
            populate_known_markers(_km_state_path, "zshrc_path", [ZSHRC_PATH_MARKER])
            populate_known_markers(_km_state_path, "zshrc_codex_func",
                                   [ZSHRC_CODEX_FUNC_MARKER_BEGIN, ZSHRC_CODEX_FUNC_MARKER_END])
            populate_known_markers(_km_state_path, "codenv", [CODEX_ENV_MARKER])
        except Exception:
            pass
        print("Установка стека завершена: brew-сервисы, конфиги, DNS, LaunchAgent применены.\n"
              f"{cp_note}\n"
              f"{gp_note}\n"
              f"{wd_note}\n"
              f"{ppp_note}\n"
              f"{codex_note}\n"
              f"{codex_func_note}\n"
              f"{env_note}\n"
              f"{path_note}\n"
              f"{codex_iso_note}\n"
              f"Дашборд: http://127.0.0.1:8787  (srouter status — проверить)")
        return 0
    blocked = ", ".join(result.get("blocked") or ["unknown"])
    print(f"install остановлен: {blocked}", file=sys.stderr)
    if "xray_endpoint_overwrite_blocked" in (result.get("blocked") or []):
        # #200: apply заблокировал перезапись рабочего xray config placeholder'ом. Подсказка — sync.
        if result.get("error"):
            print(f"  {result['error']}", file=sys.stderr)
    if "plan" in result:
        print(format_plan(result["plan"]), file=sys.stderr)
    return 2


def cmd_uninstall(args) -> int:
    """Полный откат стека + удаление split-route."""
    env = _env_from_args(args)
    runner = make_privileged_runner(run)

    # Подтверждение.
    if not sys.stdin.isatty() and not getattr(args, "yes", False):
        print("uninstall: подтверждение требует терминал (используйте -y/--yes).", file=sys.stderr)
        return 2
    if not getattr(args, "yes", False) and not _prompt_bool("Применить полный откат стека?"):
        print("uninstall отменён.")
        return 1

    result = apply_uninstall(env=env, runner=runner, confirmations={"launchctl": True, "brew": True, "configs": True, "dns": True, "codex": True})
    if result.get("ok"):
        # issue #130: git-proxy снимается автоматически.
        gd = git_proxy.disable()
        gd_note = (f"git: github-proxy убран из ~/.gitconfig."
                   if gd.get("ok") else
                   f"git: не удалось убрать github-proxy ({gd.get('err', 'unknown')}).")
        # Codex isolation: wrappers, env, zsh function, PATH.
        codex_iso_note = _remove_codex_isolation(env, runner)
        print(f"Откат стека завершён.\n{gd_note}\n{codex_iso_note}")
        # fail-closed: leftover (managed компоненты, которые не откатились) → rc=2.
        if result.get("leftover"):
            leftovers = ", ".join(str(item) for item in result.get("leftover", []))
            print(f"WARNING: leftover компоненты НЕ откачены: {leftovers}", file=sys.stderr)
            return 2
        if not gd.get("ok"):
            print(f"uninstall: {gd_note}", file=sys.stderr)
            return 2
        return 0
    print(f"uninstall остановлен: {result.get('error', 'unknown')}", file=sys.stderr)
    return 2


def cmd_start(args) -> int:
    """Запустить демон (plist уже установлен)."""
    try:
        plist = Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHAGENT_LABEL}.plist"
        result = _launchd_reload("user", plist, LAUNCHAGENT_LABEL)
        if not result.get("ok"):
            print(f"start: {result.get('last_err', 'unknown')}", file=sys.stderr)
            return 2
        print("Демон запущен.")
        return 0
    except Exception as exc:
        print(f"start: ошибка {exc}", file=sys.stderr)
        return 2


def cmd_stop(args) -> int:
    """Остановить демон (plist сохранён)."""
    try:
        unloaded, err = _launchd_unload("user", LAUNCHAGENT_LABEL)
        if err:
            print(f"stop: {err}", file=sys.stderr)
            return 2
        print("Демон остановлен.")
        return 0
    except Exception as exc:
        print(f"stop: ошибка {exc}", file=sys.stderr)
        return 2


def cmd_restart(args) -> int:
    """Перезапустить демон (применить правки кода)."""
    try:
        unloaded, unload_err = _launchd_unload("user", LAUNCHAGENT_LABEL)
        if unload_err:
            print(f"restart: unload не сработал ({unload_err}).", file=sys.stderr)
            return 2
        plist = Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHAGENT_LABEL}.plist"
        result = _launchd_reload("user", plist, LAUNCHAGENT_LABEL)
        if not result.get("ok"):
            print(f"restart: reload не сработал ({result.get('last_err', 'unknown')}).", file=sys.stderr)
            return 2
        print("Демон перезапущен.")
        return 0
    except Exception as exc:
        print(f"restart: ошибка {exc}", file=sys.stderr)
        return 2


def cmd_status(args) -> int:
    """Показать статус демона."""
    try:
        r = run(["launchctl", "list"], 10)
        if r.get("timeout"):
            print("status: timeout при проверке статуса.", file=sys.stderr)
            return 2
        out = r.get("out", "")
        err = r.get("err", "")

        # Разбор вывода launchctl list: "PID\tExitCode\tLabel"
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) == 3 and parts[2] == LAUNCHAGENT_LABEL:
                pid, exit_code = parts[0], parts[1]
                if pid != "-":
                    print(f"Демон загружен и работает (PID={pid}).")
                    return 0
                else:
                    print(f"Демон крашнулся (exit code={exit_code}).", file=sys.stderr)
                    print("srouter restart — перезапустить.", file=sys.stderr)
                    return 1

        print(f"Демон {LAUNCHAGENT_LABEL} НЕ загружен.")
        return 1
    except Exception as exc:
        print(f"status: ошибка {exc}", file=sys.stderr)
        return 2


def cmd_doctor(args) -> int:
    """Проверить здоровье стека (порты + туннель)."""
    print("Doctor command (TODO: реализовать)")
    return 0


def cmd_sync(args) -> int:
    """Импорт endpoint из рабочего xray в local.json."""
    print("Sync command (TODO: реализовать)")
    return 0


def cmd_privoxy(args) -> int:
    """Защищённый system-режим Privoxy."""
    print("Privoxy command (TODO: реализовать)")
    return 0


def cmd_routing(args) -> int:
    """Управление routing-доменами xray."""
    print("Routing command (TODO: реализовать)")
    return 0


__all__ = [
    # codex_wrappers
    "CODEX_NO_PROXY",
    "CODEX_NO_PROXY_LOOPBACK",
    "CODEX_LAUNCHCTL_ENV",
    "CODEX_WRAPPERS",
    "CODEX_CLI_WRAPPER_NAME",
    "CODEX_CLI_WRAPPER_LEGACY_NAME",
    "CODEX_ENV_LABEL",
    "CODEX_ENV_MARKER",
    "ZSHRC_PATH_MARKER",
    "ZSHRC_CODEX_FUNC_MARKER_BEGIN",
    "ZSHRC_CODEX_FUNC_MARKER_END",
    "_codex_wrapper_path",
    "_zshrc_path",
    "_looks_like_managed_codex_wrapper",
    "_codex_bin_path",
    "_install_one_wrapper",
    "_install_codex_wrappers",
    "_migrate_legacy_codex_cli_wrapper",
    "_remove_one_wrapper",
    "_remove_codex_wrappers",
    "_install_launchctl_env",
    "_remove_launchctl_env",
    "_ensure_home_bin_in_path",
    "_remove_home_bin_from_path",
    "_codex_zsh_target_installed",
    "_install_codex_zsh_function",
    "_remove_codex_zsh_function",
    "_install_codex_isolation",
    "_remove_codex_isolation",
    # srouter_launchd
    "PPP_HOOK_PATH",
    "PPP_HOOK_MARKER",
    "_is_ip_literal",
    "_active_route_ip_for_removal",
    "_remove_active_split_route",
    "_install_ppp_hook",
    "_remove_ppp_hook",
    # srouter_cli
    "_env_from_args",
    "_prompt_bool",
    "_prompt_choice",
    "_version_string",
    "_read_routing_domains",
    "_routing_has_marker",
    "build_parser",
    "main",
    "cmd_install",
    "cmd_uninstall",
    "cmd_start",
    "cmd_stop",
    "cmd_restart",
    "cmd_status",
    "cmd_doctor",
    "cmd_sync",
    "cmd_privoxy",
    "cmd_routing",
    # install_lib
    "BREW",
    "ROUTE",
    "CHOICES",
    "LAUNCHAGENT_LABEL",
    "LAUNCHCTL",
    "InstallEnv",
    "_has_launchagent_marker",
    "_launchd_domain",
    "_launchd_is_loaded",
    "_launchd_reload",
    "_launchd_unload",
    "_write_text_atomic",
    "apply_install",
    "apply_uninstall",
    "build_plan",
    "build_uninstall_plan",
    "format_plan",
    "format_uninstall_plan",
    "_install_generic_launchagent",
    "_reclaimable_resolves_all_conflicts",
    "load_known_markers",
    "populate_known_markers",
    "port_open",
    # sys_probe
    "run",
    # privileged
    "OSASCRIPT",
    "_is_privileged_cmd",
    "_to_osascript",
    "make_privileged_runner",
    "_is_loaded",
]
