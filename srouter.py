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
import json
import os
import sys
from pathlib import Path
from importlib.metadata import PackageNotFoundError, version

import local_state
from install_lib import (
    CHOICES,
    LAUNCHAGENT_LABEL,
    LAUNCHCTL,
    InstallEnv,
    _has_launchagent_marker,
    _launchd_domain,
    _launchd_is_loaded,
    _launchd_reload,
    _write_text_atomic,  # noqa: F401 — публичный контракт srouter (мокается в тестах)
    apply_install,
    apply_uninstall,
    build_plan,
    build_uninstall_plan,
    format_plan,
    format_uninstall_plan,
    _install_generic_launchagent,
    _reclaimable_resolves_all_conflicts,
    populate_known_markers,
    port_open,
)
from sys_probe import run

import claude_proxy  # вкл/откл HTTPS_PROXY для Claude Code (~/.claude/settings.json)
import git_proxy  # issue #130: вкл/откл SOCKS5 github-proxy в ~/.gitconfig (xray 10808)
import vscode_proxy  # issue #185: scoped SOCKS5 для codex-расширения через VSCode http.proxy
import health  # doctor-проверки стека
import privoxy_audit  # пассивный root-owned аудит lifecycle-команд Privoxy (#122)
import privoxy_system  # root-gated system LaunchDaemon для Privoxy (#122)
import privileged_ops  # единая osascript/sudo-обёртка + whitelist (#156)

# OSASCRIPT переэкспортируется из privileged_ops (единый источник #156) для обратной
# совместимости с тестами/кодом, обращающимся к srouter.OSASCRIPT.
OSASCRIPT = privileged_ops.OSASCRIPT


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
    am_root = os.geteuid() == 0

    def runner(cmd, timeout):
        if not _is_privileged_cmd(cmd) or am_root:
            return underlying_run(cmd, timeout)
        return underlying_run(_to_osascript(cmd), osascript_timeout)

    return runner


def _prompt_bool(label: str) -> bool:
    return input(f"{label} [y/N]: ").strip().lower() in {"y", "yes", "д", "да"}


def _prompt_choice(name: str) -> str:
    """adopt | overwrite | skip (install_lib.CHOICES)."""
    while True:
        answer = input(f"Выбор для {name} [adopt/overwrite/skip]: ").strip().lower()
        if answer in CHOICES:
            return answer
        print("Допустимо: adopt, overwrite, skip.")


# launchd/PPP-hook + split-route вынесены в srouter_launchd.py (#228).
# Re-export для обратной совместимости.
from srouter_launchd import (  # noqa: E402,F401 — намеренный re-export публичного контракта
    PPP_HOOK_MARKER,
    PPP_HOOK_PATH,
    _active_route_ip_for_removal,
    _install_ppp_hook,
    _is_ip_literal,
    _remove_active_split_route,
    _remove_ppp_hook,
)



# ============================ Codex SOCKS5-wrappers + launchctl env ============================
# Codex wrappers / launchctl-env / PATH-zsh вынесены в codex_wrappers.py (#228).
# Re-export для обратной совместимости: тесты и потребители продолжают брать их из srouter.
from codex_wrappers import (  # noqa: E402,F401 — намеренный re-export публичного контракта
    CODEX_CLI_WRAPPER_LEGACY_NAME,
    CODEX_CLI_WRAPPER_NAME,
    CODEX_ENV_LABEL,
    CODEX_ENV_MARKER,
    CODEX_LAUNCHCTL_ENV,
    CODEX_NO_PROXY,
    CODEX_NO_PROXY_LOOPBACK,
    CODEX_WRAPPERS,
    ZSHRC_CODEX_FUNC_MARKER_BEGIN,
    ZSHRC_CODEX_FUNC_MARKER_END,
    ZSHRC_PATH_MARKER,
    _CODEX_FUNC_BLOCK,
    _codex_bin_path,
    _codex_wrapper_path,
    _codex_zsh_target_installed,
    _ensure_home_bin_in_path,
    _install_codex_isolation,
    _install_codex_wrappers,
    _install_codex_zsh_function,
    _install_launchctl_env,
    _install_one_wrapper,
    _looks_like_managed_codex_wrapper,
    _migrate_legacy_codex_cli_wrapper,
    _remove_codex_isolation,
    _remove_codex_wrappers,
    _remove_codex_zsh_function,
    _remove_home_bin_from_path,
    _remove_launchctl_env,
    _remove_one_wrapper,
    _zshrc_path,
)



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
    except Exception as exc:  # noqa: BLE001 — CLI entry point, не роняем stack trace в пользователя
        print(f"install: сбой discovery: {exc}", file=sys.stderr)
        return 2

    # 2) Показать план.
    print(format_plan(plan))
    print()

    # 3) Конфликты → интерактивный выбор per компонент.
    # reclaimable («свой старый»: state.managed=True, маркер пропал, issue #110 Дефект 2) НЕ попадает
    # в интерактивный фильтр — он тихо авторазрешается в apply_install (с backup). Иначе non-TTY install
    # падал rc=2 на «своём старом» сразу после uninstall, даже с -y. НО только если reclaimable покрывает
    # ВСЕ конфликты (cycle-review #111 cycle 1 finding 2): non_brew_binary и будущие conflict-типы НЕ
    # поглощаются → остаются в фильтре, требуют adopt/overwrite/skip. Истинно foreign требует выбора.
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
    # Не-TTY запуск допустим ТОЛЬКО с -y/--yes (промпт не нужен). Без TTY и без -y — отказ:
    # _prompt_bool зависнет на EOF. Раньше isatty()-gate стоял ДО проверки yes → -y игнорировался
    # в не-TTY среде (cron/launchd/CI/фоновый процесс). Issue #106.
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
        # Эмпирика (verify, lsof per-process ChatGPT.app): ChatGPT.app = Electron-оболочка над
        # Rust-бинарником — ДВА стека. Chromium-оболочка уважает СИСТЕМНЫЙ SOCKS (scutil) — работает.
        # Rust app-server (/Resources/codex, основной WS к wss://chatgpt.com) НЕ уважает системный SOCKS,
        # берёт ТОЛЬКО env SOCKS5 → без env идёт напрямую → GFW рвёт (error_kind=TimedOut в logs_2.sqlite).
        # config.toml [network] proxy_url МЁРТВ в codex 0.146. Единственный путь для Rust app-server =
        # env SOCKS5 в launchd gui-домене → codenv (RunAtLoad + StartInterval=300, переживает ребут).
        # РАНЬШЕ (PR #187/#185) codenv деактивировали из-за #130 (CC SOCKS5-несовместимость), НО эмпирика
        # #189 опровергает конфликт: CC CLI читает прокси из ~/.claude/settings.json (claude_proxy.py),
        # НЕ из launchd gui-env → месяц коэкзиста CC+Codex это подтверждает (codenv был загружен весь месяц).
        # Корень «error 5» #189: PR #187 деактивировал install-codenv, но plist на диске остался как
        # placeholder-шаблон (не отрендерен) → job перезагрузился с __SROUTER_CODENV_PATH__ → error 5 →
        # env не применялся → сломалось после обеда. Восстановление = правильный рендер plist тут.
        codenv_note = _install_launchctl_env(env, runner)
        # issue #185: scoped SOCKS5 для codex-расширения openai.chatgpt через VSCode http.proxy.
        # Отдельный клиент от ChatGPT.app (расширение в Code/Cursor, не GUI-приложение). Комплементарен
        # codenv: codenv покрывает Rust app-server ChatGPT.app, VSCode http.proxy — расширение. CC
        # (отдельный процесс, свой ~/.claude/settings.json) НЕ затрагивается ни одним из них.
        vp = vscode_proxy.enable()
        if vp.get("ok"):
            vp_note = ("scoped SOCKS5 в VSCode http.proxy (Code/Cursor) — расширение openai.chatgpt, "
                       "CC не затрагивается (#185)"
                       + (f" Пути: {', '.join(vp.get('paths') or [])}" if vp.get("paths") else ""))
        else:
            vp_note = f"scoped VSCode http.proxy не установлен ({vp.get('err', 'unknown')})."
        env_note = f"{codenv_note} VSCode: {vp_note}"
        path_note = _ensure_home_bin_in_path(env)
        codex_iso_note = _install_codex_isolation(env, runner)
        # Marker-migration table (issue #112 Часть 4): регистрируем текущие маркеры wrappers/zshrc/codenv
        # в state.known_markers. При будущей смене версии маркера old останется как legacy → следующий
        # install мигрирует old→current. Без регистрации install использует только current (safe fallback).
        # Best-effort: ошибка/отсутствие state_path не блокируют install (маркеры в коде всё равно валидны).
        try:
            _km_state_path = env.state_path
            for _entry in CODEX_WRAPPERS:
                populate_known_markers(_km_state_path, "wrappers", [_entry[2]])
            populate_known_markers(_km_state_path, "zshrc_path", [ZSHRC_PATH_MARKER])
            populate_known_markers(_km_state_path, "zshrc_codex_func",
                                   [ZSHRC_CODEX_FUNC_MARKER_BEGIN, ZSHRC_CODEX_FUNC_MARKER_END])
            populate_known_markers(_km_state_path, "codenv", [CODEX_ENV_MARKER])
        except Exception:  # noqa: BLE001 — cleanup не должен маскировать основную ошибку
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
    except Exception as exc:  # noqa: BLE001 — CLI entry point, не роняем stack trace в пользователя
        print(f"uninstall: сбой discovery: {exc}", file=sys.stderr)
        return 2
    print(format_uninstall_plan(plan))
    print()

    # 2) Подтверждение (полный откат — серьёзный шаг).
    # Не-TTY запуск допустим ТОЛЬКО с -y/--yes (промпт не нужен). Без TTY и без -y — отказ:
    # _prompt_bool зависнет на EOF. Раньше isatty()-gate стоял ДО проверки yes → -y игнорировался
    # в не-TTY среде (cron/launchd/CI/фоновый процесс). Issue #106.
    if not sys.stdin.isatty() and not getattr(args, "yes", False):
        print("uninstall: подтверждение требует терминал (используйте -y/--yes).", file=sys.stderr)
        return 2
    if not getattr(args, "yes", False) and not _prompt_bool("Полный откат стека к дефолту?"):
        print("uninstall отменён.")
        return 1

    # Защищённый Privoxy нельзя отдавать legacy apply_uninstall: тот управляет пользовательскими
    # brew-services и не имеет права писать /Library. Сначала одной root-транзакцией возвращаем
    # прежний user-service/state, затем обычный uninstall применяет существующую provenance-семантику.
    env_state_path = getattr(env, "state_path", None)
    protected_state = bool(env_state_path) and privoxy_system.state_protected(env_state_path)
    physical_protected = False
    if isinstance(env, InstallEnv) and env_state_path:
        try:
            physical_protected = (
                Path(env_state_path).resolve() == (Path(__file__).resolve().parent / "srouter.local.json").resolve()
                and privoxy_system.protection_present()
            )
        except OSError:
            physical_protected = False
    if physical_protected or protected_state:
        protected = privoxy_system.unprotect(
            state_path=env_state_path or state_path or InstallEnv.from_env().state_path,
            restore=True,
            runner=run,
        )
        if not protected.get("ok"):
            print(f"uninstall остановлен: защищённый privoxy не восстановлен "
                  f"({protected.get('error', 'unknown')})", file=sys.stderr)
            return 2

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
    # leftover (issue #110 Дефект 1): компоненты, которые srouter СТАВИЛ, но не откатил (нет backup /
    # маркер пропал). НЕ ошибка (ok=True — uninstall не крашится), но partial: следующий install увидит
    # эти конфиги как reclaimable (Дефект 2) либо foreign. Сообщаем честно, rc=2 — иначе headline
    # «Откат завершён» маскирует, что по сути ничего не откатили.
    leftover = result.get("leftover") or []
    partial_configs = bool(leftover)

    # 4) Удалить split-route (новое — install_lib про маршрут не знает).
    route_rc = _remove_active_split_route(state_path, runner)

    # 5) Снять HTTPS_PROXY для Claude Code — privoxy больше не запущен, прокси бессмысленен.
    cp = claude_proxy.disable()
    cp_note = ". Claude Code HTTPS_PROXY снят." if cp.get("ok") else ""
    # 5a) issue #130: снять github-proxy из ~/.gitconfig (xray SOCKS5 больше не запущен) —
    # возвращает git к состоянию до srouter.
    gp = git_proxy.disable()
    cp_note += ". git github-proxy снят." if gp.get("ok") else ". git github-proxy не снят."
    # 5b) issue #185: снять scoped SOCKS5 из VSCode http.proxy (симметрично install). Чужой http.proxy
    # не трогаем (fail-closed provenance — vscode_proxy.disable сверяет значение).
    vp = vscode_proxy.disable()
    cp_note += ". VSCode codex http.proxy снят." if vp.get("ok") else ". VSCode codex http.proxy не снят."

    # 6) Удалить ppp-hook (/etc/ppp/ip-up) — мгновенный split-route больше не нужен.
    ppp_note = ". " + _remove_ppp_hook(runner)
    # 7) Удалить Codex SOCKS5-wrappers + shell-функцию codex() + снять launchctl env + убрать ~/bin
    #    из PATH (всё ставил install). marker-gate: чужое не трогаем.
    codex_note = ". " + _remove_codex_wrappers()
    codex_func_note = ". " + _remove_codex_zsh_function()
    env_status = _remove_launchctl_env(runner)
    env_note = ". " + env_status["note"]
    path_note = ". " + _remove_home_bin_from_path()
    codex_iso_note = ". " + _remove_codex_isolation(env, runner)

    # env-cleanup fail-closed (issue #94 DEFECT A): мёртвый прокси остался в gui-домене → НЕ успех,
    # даже если всё остальное прошло. Раньше env_note просто конкатенировался в сообщение → fail-open
    # (rc=0 при живом socks5://127.0.0.1:10808 в GUI). ok=False пробрасываем в ненулевой rc.
    # Тот же инвариант — git-proxy (Codex cycle-review PR #221, issue #130): gp["ok"]=False раньше
    # менял только текст (cp_note), но не rc → «Откат завершён» rc=0 при locked ~/.gitconfig, пока
    # git всё ещё указывает на мёртвый 127.0.0.1:10808 (xray уже остановлен apply_uninstall).
    # Шапка сообщения зависит от итога: «Откат завершён» только при подтверждённо снятом env И
    # git-proxy И без leftover (issue #110 Дефект 1), иначе «Откат выполнен частично» — rc=2.
    full_ok = env_status["ok"] and gp.get("ok", False) and not partial_configs
    headline = "Откат завершён" if full_ok else "Откат выполнен частично"
    print(f"{headline}: brew-сервисы остановлены, конфиги восстановлены/оставлены, "
          "DNS сброшен, LaunchAgent удалён"
          + (". split-route удалён." if route_rc == 0 else ", split-route не удалён — см. выше.")
          + cp_note
          + ppp_note
          + codex_note
          + codex_func_note
          + env_note
          + path_note
          + codex_iso_note)
    # leftover per-имённо (issue #110): «частично» без деталей = новый обман. Оператор должен видеть,
    # КАКИЕ конфиги srouter ставил, но не откатил (следующий install авторазрешит их как reclaimable
    # с backup, либо потребует решения если они foreign).
    if leftover:
        names = ", ".join(item["name"] for item in leftover)
        print(f"uninstall выполнен частично: конфиги оставлены ({names}) — не найден backup/маркер. "
              f"Повторный install авторазрешит их (с backup) либо потребует adopt/overwrite/skip.",
              file=sys.stderr)
    if not env_status["ok"]:
        print(f"uninstall завершён с ошибкой: Codex env не подтверждённо снят — {env_status['note']}",
              file=sys.stderr)
        return 2
    if not gp.get("ok", False):
        print(f"uninstall завершён с ошибкой: git github-proxy не подтверждённо снят — "
              f"{gp.get('err', 'unknown')}", file=sys.stderr)
        return 2
    if partial_configs:
        return 2
    return 0


def _is_loaded():
    """Загружен ли демон в launchd. Делегирует к install_lib._launchd_is_loaded (канон: единый
    источник правды о launchd — CLI не дублирует парсинг launchctl). Домен gui/<uid> явно — тот же
    таргет, что bootout в cmd_stop/_launchd_reload (домен-осознанная проверка, cycle-review #93)."""
    return _launchd_is_loaded(LAUNCHAGENT_LABEL, domain=_launchd_domain(), runner=run)


def cmd_start(args) -> int:
    """Запустить демон (plist уже должен быть установлен через `install`)."""
    env = _env_from_args(args)
    plist = env.launchagent_path()
    if not plist.exists():
        print("Служба не установлена. Сначала выполните: srouter install", file=sys.stderr)
        return 2
    loaded = _is_loaded()
    if loaded is True:
        print(f"Демон уже запущен: {LAUNCHAGENT_LABEL}")
        return 0
    if loaded is None:
        # launchctl list таймаутит — состояние неизвестно. Не делаем bootout (он убил бы работающий
        # демон, если таймаут скрыл, что он загружен). Просим пользователя проверить status.
        print("Не удалось узнать состояние демона (timeout launchctl). Проверьте: srouter status",
              file=sys.stderr)
        return 2
    # loaded is False — демон точно не загружен, _launchd_reload безопасен (bootout = no-op).
    # bootstrap с retry покрывает гонку, если кто-то только что сделал stop → start с малой задержкой.
    res = _launchd_reload(_launchd_domain(), plist, LAUNCHAGENT_LABEL, runner=run)
    if not res["ok"]:
        print(f"Не удалось запустить демон: {res.get('last_err') or 'unknown error'}", file=sys.stderr)
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
    """Перезапустить демон (применить правки кода). plist не трогается.

    Через _launchd_reload: bootout → poll-wait выгрузки → bootstrap(retry). Решает гонку
    «Bootstrap failed: 5: Input/output error», когда launchd не успевает освободить домен.
    """
    env = _env_from_args(args)
    plist = env.launchagent_path()
    res = _launchd_reload(_launchd_domain(), plist, LAUNCHAGENT_LABEL, runner=run)
    if not res["ok"]:
        print(f"Не удалось перезапустить демон: {res.get('last_err') or 'unknown error'}",
              file=sys.stderr)
        return 2
    print(f"Демон перезапущен: {LAUNCHAGENT_LABEL}")
    return 0


def cmd_status(args) -> int:
    """Статус LaunchAgent: работает / крашнулся / не загружен.

    Формат `launchctl list`: «PID  ExitCode  Label» (3 колонки). Ищем службу по последней
    колонке (fields[-1] == label) — она устойчива к числу предшествующих полей.

    best-effort: legacy `list` инспектирует домен ВЫЗЫВАЮЩЕГО (из не-gui контекста — SSH/cron —
    gui-агент может не отобразиться → неточный статус). Осознанно оставлено на `list` (cycle-review
    #93): cmd_status только ЧИТАЕТ/печатает, домен-mismatch тут даёт неверный вывод, НЕ потерю данных
    (в отличие от unlink-границы _launchd_is_loaded, переведённой на домен-осознанный `print`). Перевод
    на `print` требовал бы переписать парсинг трёх состояний под хрупкий недокументированный текст —
    цена/польза не оправдана для read-only статуса.
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
    result = health.check_all(active_claude=True)
    health._print_report(result)
    return 0 if result["status"] == "ok" else 1


def cmd_sync(args) -> int:
    """Синхронизировать endpoint активного узла из РАБОЧЕГО xray config в srouter.local.json (#200).

    Единый источник правды: local.json = canonical state, но рабочий xray config держит РЕАЛЬНЫЙ
    VPS-address (gen_xray_config пишет туда resolve_route_ip). Если local.json — placeholder test-IP
    (203.0.113.x, RFC 5737), а xray — реальный, это рассинхрон: gen_xray генерит из active_node() →
    `srouter apply` заблокирован (#200 защита от перезаписи). sync импортит реальный address из xray
    в local.json, делая canonical state правдивым. НЕ авто-overwrite когда local уже реальный (detect-only).
    """
    state_path = getattr(args, "state", None)
    xray_config = getattr(args, "xray_config", None) or local_state.XRAY_CONFIG_PATH

    # Сначала покажем состояние (compare) — даже если sync неприменим, пользователь видит причину.
    cmp = local_state.compare_endpoint_with_xray(state_path=state_path, xray_config_path=xray_config)
    local, xray, placeholder = cmp["local"], cmp["xray"], cmp["placeholder"]
    if not local:
        print("sync: нет активного узла / endpoint_host в local.json — нечего синхронизировать.",
              file=sys.stderr)
        return 1
    if not xray:
        print(f"sync: рабочий xray config ({xray_config}) не найден / без vless-address — "
              f"нечего импортировать (local.json endpoint={local}).", file=sys.stderr)
        return 1
    if cmp["synced"]:
        print(f"sync: уже синхронизировано — local.json endpoint == xray == {local}.")
        return 0
    if not placeholder:
        # оба реальных, но разные — выбор пользователя, sync не подменяет молча.
        print(f"sync: рассинхрон без placeholder — local.json={local} (реальный), xray={xray} (реальный). "
              f"`srouter sync` НЕ перезаписывает реальный endpoint вручную. Реши, какой правдив, "
              f"и отредактируй local.json (или xray) осознанно.", file=sys.stderr)
        return 1

    # local — placeholder, xray — реальный → импорт.
    r = local_state.sync_endpoint_from_xray(xray_config_path=xray_config, path=state_path)
    if not r["ok"]:
        print(f"sync: не удалось импортировать endpoint из xray в local.json "
              f"(state unreadable / узел не найден). local={local}, xray={xray}.", file=sys.stderr)
        return 1
    print(f"sync: импортирован реальный endpoint из рабочего xray в local.json: "
          f"{local} (placeholder) → {r['endpoint']} (реальный).")
    print("  local.json теперь canonical-правдив; `srouter apply` больше не заблокирован (#200).")
    return 0


def cmd_privoxy(args) -> int:
    """Ручное root-gated управление защищённым Privoxy (#122)."""
    action = getattr(args, "privoxy_action", None)
    if action == "audit":
        audit_action = getattr(args, "privoxy_audit_action", None)
        if audit_action == "status":
            current = privoxy_audit.status(runner=run)
            installed = "установлен" if current["installed"] else "не установлен"
            loaded = "загружен" if current["loaded"] else "не загружен"
            print(
                f"Аудит Privoxy: {installed}; {loaded}; state={current['state']}; "
                f"events={current['events_written']}; parse_errors={current['parse_errors']}."
            )
            if current.get("last_error"):
                print(f"  последняя ошибка: {current['last_error']}", file=sys.stderr)
            if current.get("fda_required"):
                print(
                    "  macOS требует Full Disk Access для /usr/bin/eslogger; после выдачи "
                    "повторите: srouter privoxy audit install",
                    file=sys.stderr,
                )
            return 0 if current["installed"] and current["loaded"] \
                and current["state"] == "running" else 1
        if audit_action == "report":
            outcome = privoxy_audit.report(limit=getattr(args, "limit", 50))
            if not outcome["ok"]:
                print(f"privoxy audit report: {outcome['error']}", file=sys.stderr)
                return 2
            if getattr(args, "json", False):
                print(json.dumps(outcome["records"], ensure_ascii=False, indent=2))
            elif not outcome["records"]:
                print(f"Аудит Privoxy: подходящих команд пока нет. Лог: {outcome['path']}")
            else:
                for record in outcome["records"]:
                    actor = record.get("actor") or {}
                    target = record.get("target") or {}
                    command = " ".join(target.get("args") or [])
                    print(
                        f"{record.get('captured_at') or '-'} actor={actor.get('pid') or '-'} "
                        f"{actor.get('executable') or '-'} -> {command or target.get('executable') or '-'}"
                    )
            if outcome.get("parse_errors"):
                print(f"В журнале повреждённых строк: {outcome['parse_errors']}", file=sys.stderr)
            return 0
        if audit_action == "install":
            outcome = privoxy_audit.install(runner=run)
        elif audit_action == "uninstall":
            outcome = privoxy_audit.uninstall(
                purge_log=getattr(args, "purge_log", False), runner=run,
            )
        else:
            print(f"privoxy audit: неизвестное действие {audit_action!r}", file=sys.stderr)
            return 2
        if not outcome.get("ok"):
            print(f"privoxy audit {audit_action}: {outcome.get('error', 'failed')}", file=sys.stderr)
            return 2
        changed = "изменён" if outcome.get("changed", True) else "уже в нужном состоянии"
        print(f"Аудит Privoxy {audit_action}: {changed}.")
        current = outcome.get("status")
        if isinstance(current, dict) and (current.get("fda_required") or current.get("state") == "error"):
            print(
                "macOS не разрешила чтение Endpoint Security. Добавьте /usr/bin/eslogger в "
                "System Settings → Privacy & Security → Full Disk Access и повторите install.",
                file=sys.stderr,
            )
            return 1
        return 0

    state_path = getattr(args, "state", None) or InstallEnv.from_env().state_path
    prefix = getattr(args, "prefix", None) or "/opt/homebrew"

    if action == "status":
        result = privoxy_system.status(runner=run)
        protection = "защищён" if result["protected"] else "не защищён"
        loaded = "загружен" if result["loaded"] else "не загружен"
        port = "8118 слушает" if result["port_up"] else "8118 закрыт"
        owner = result.get("owner") or "-"
        shadow = "; ВНИМАНИЕ: загружена user-копия" if result.get("user_shadow_loaded") else ""
        writable = ""
        if (result.get("config_writable") is True or result.get("binary_writable") is True
                or result.get("assets_writable") is True):
            writable = "; ВНИМАНИЕ: защищённые файлы доступны для записи"
        print(f"Privoxy: {protection}; {loaded}; {port}; PID={result.get('pid') or '-'}; "
              f"user={owner}{shadow}{writable}")
        healthy = (
            result["protected"]
            and result["loaded"]
            and result["port_up"]
            and result.get("owner") == "nobody"
            and result.get("config_writable") is False
            and result.get("binary_writable") is False
            and result.get("assets_writable") is False
            and not result.get("user_shadow_loaded")
        )
        return 0 if healthy else 1

    if action == "protect":
        if not getattr(args, "strict", False):
            print("protect требует явный флаг --strict (sudo будет спрашивать подтверждение каждый раз).",
                  file=sys.stderr)
            return 2
        result = privoxy_system.protect(state_path=state_path, prefix=prefix, runner=run)
    elif action == "unprotect":
        result = privoxy_system.unprotect(state_path=state_path, restore=True, runner=run)
    elif action in ("start", "stop", "restart"):
        result = privoxy_system.control(action, runner=run)
    else:
        print(f"privoxy: неизвестное действие {action!r}", file=sys.stderr)
        return 2

    if not result.get("ok"):
        print(f"privoxy {action}: {result.get('error', 'failed')}", file=sys.stderr)
        status = result.get("status")
        if status:
            print(f"  protected={status.get('protected')} loaded={status.get('loaded')} "
                  f"port_up={status.get('port_up')} owner={status.get('owner') or '-'}",
                  file=sys.stderr)
        return 2
    changed = "изменён" if result.get("changed", True) else "уже в нужном состоянии"
    print(f"Privoxy {action}: {changed}.")
    return 0


def cmd_routing(args) -> int:
    """Управление routing-доменами production xray-config (#136).

    srouter adopt'ит секцию reality-out (маркер _srouter_managed, НЕ захватывая весь foreign-конфиг),
    домены хранит в srouter.local.json. Two-phase: backup → modify → restart xray → promote.
    `add-domain telegram.org` — добавить домен в проксируемые (первый раз требует --adopt).
    """
    subcmd = getattr(args, "routing_subcommand", None)
    state_path = getattr(args, "state", None)
    outbound = getattr(args, "outbound", None) or local_state.DEFAULT_ROUTING_OUTBOUND

    if subcmd == "list":
        # показать текущие домены reality-out из config (read-only, без state)
        domains = _read_routing_domains(args.xray_config, outbound)
        if domains is None:
            print("routing: не найден rule reality-out в xray-config "
                  f"({args.xray_config}). adopt? или --outbound другой?", file=sys.stderr)
            return 2
        managed = _routing_has_marker(args.xray_config, outbound)
        print(f"routing ({outbound}) {'[managed by srouter]' if managed else '[foreign]'}:")
        for d in domains:
            print(f"  {d}")
        return 0

    if subcmd not in ("add-domain", "remove-domain"):
        print(f"routing: неизвестная подкоманда {subcmd!r}", file=sys.stderr)
        return 2

    host = args.host
    action = "add" if subcmd == "add-domain" else "remove"
    adopt = getattr(args, "adopt", False)
    if not adopt and not sys.stdin.isatty():
        # non-TTY без --adopt: не виснуть на промпте (канон cmd_install TTY-gate)
        pass  # routing_apply сам вернёт err=foreign_config_needs_adopt без adopt
    runner = make_privileged_runner(run)
    r = local_state.routing_apply(
        [host], action=action, adopt=adopt, outbound=outbound,
        config_path=args.xray_config, state_path=state_path,
        runner=runner, port_checker=port_open,
    )
    if not r["ok"]:
        print(f"routing {subcmd} {host}: {r.get('err', 'failed')}", file=sys.stderr)
        if r.get("err") == "foreign_config_needs_adopt":
            print("  (первый раз: добавь --adopt, чтобы srouter принял секцию reality-out "
                  "под управление — домены существующего rule сохранятся)", file=sys.stderr)
        return 2
    verb = "добавлен" if action == "add" else "убран"
    if r.get("changed"):
        print(f"routing: {host} {verb}, xray перезапущен.")
    else:
        print(f"routing: {host} уже в нужном состоянии (no-op).")
    return 0


def _read_routing_domains(config_path, outbound):
    """Текущие domain[] rule с outboundTag=outbound. None если rule не найден/битый."""
    try:
        import json as _json
        from pathlib import Path
        data = _json.loads(Path(config_path).read_text(encoding="utf-8"))
        for r in (data.get("routing") or {}).get("rules") or []:
            if isinstance(r, dict) and r.get("outboundTag") == outbound and isinstance(r.get("domain"), list):
                return r["domain"]
    except (OSError, json.JSONDecodeError, ValueError, TypeError, KeyError):
        # JSON операции + словари → OSError, json.JSONDecodeError, ValueError, TypeError, KeyError
        return None
    return None


def _routing_has_marker(config_path, outbound):
    """Есть ли _srouter_managed на rule с outboundTag=outbound."""
    try:
        import json as _json
        from pathlib import Path
        data = _json.loads(Path(config_path).read_text(encoding="utf-8"))
        for r in (data.get("routing") or {}).get("rules") or []:
            if isinstance(r, dict) and r.get("outboundTag") == outbound:
                return r.get(local_state.ROUTING_MARKER) is True
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        # JSON операции + словари → OSError, json.JSONDecodeError, ValueError, TypeError
        pass
    return False


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
        p.add_argument("--python", default=None,
                       help="Явный путь к Python (для sudo: --python $(which python3))")

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
        if name == "install":
            p.add_argument("--force-endpoint-overwrite", action="store_true",
                           help="Обойти #200 защиту: перезаписать рабочий xray config placeholder'ом "
                                "(осознанно; обычно запусти `srouter sync` вместо этого).")
        p.set_defaults(func=fn)

    # sync (#200): импорт endpoint активного узла из РАБОЧЕГО xray config в srouter.local.json,
    # когда local.json — placeholder test-IP, а xray — реальный VPS. Чинит рассинхрон источника
    # правды и снимает блок apply (#200 защита от перезаписи рабочего xray placeholder'ом).
    p_sync = sub.add_parser(
        "sync", help="Импорт endpoint из рабочего xray в local.json (рассинхрон placeholder). #200.")
    p_sync.add_argument("--state", default=None, help="Путь к srouter.local.json.")
    p_sync.add_argument("--xray-config", default=local_state.XRAY_CONFIG_PATH,
                        help="Путь к production xray-config.json.")
    p_sync.set_defaults(func=cmd_sync)

    # routing (#136): управление routing-доменами production xray-config. Отдельная подкоманда —
    # свои sub-subcommands (add-domain/remove-domain/list). НЕ "route" (конфликт с split-route).
    p_route = sub.add_parser(
        "routing",
        help="Управление routing-доменами xray (add-domain/remove-domain/list). #136.")
    p_route_sub = p_route.add_subparsers(dest="routing_subcommand", required=True)
    for sub_name, sub_help in (
        ("add-domain", "Добавить домен в проксируемые (первый раз — --adopt)."),
        ("remove-domain", "Убрать домен из проксируемых."),
        ("list", "Показать текущие routing-домены (read-only)."),
    ):
        sp = p_route_sub.add_parser(sub_name, help=sub_help)
        sp.add_argument("--outbound", default=None,
                        help=f"outboundTag rule (по умолчанию {local_state.DEFAULT_ROUTING_OUTBOUND}).")
        sp.add_argument("--state", default=None, help="Путь к srouter.local.json.")
        sp.add_argument("--xray-config", default=local_state.XRAY_CONFIG_PATH,
                        help="Путь к production xray-config.json.")
        if sub_name in ("add-domain", "remove-domain"):
            sp.add_argument("host", help="Домен (напр. telegram.org).")
            sp.add_argument("--adopt", action="store_true",
                            help="Принять секцию reality-out под управление (первый раз). "
                                 "Существующие домены сохраняются, добавляется маркер _srouter_managed.")
        sp.set_defaults(func=cmd_routing)

    # privoxy (#122): статус read-only; любые мутации идут через root-owned helper и свежий sudo.
    p_privoxy = sub.add_parser("privoxy", help="Защищённый system-режим Privoxy.")
    p_privoxy_sub = p_privoxy.add_subparsers(dest="privoxy_action", required=True)
    for sub_name, sub_help in (
        ("status", "Показать защищённый статус без sudo."),
        ("protect", "Перенести Privoxy в system LaunchDaemon."),
        ("start", "Запустить защищённый Privoxy."),
        ("stop", "Остановить защищённый Privoxy."),
        ("restart", "Перезапустить защищённый Privoxy."),
        ("unprotect", "Вернуть прежний пользовательский service/config."),
    ):
        sp = p_privoxy_sub.add_parser(sub_name, help=sub_help)
        sp.add_argument("--state", default=None, help="Путь к srouter.local.json.")
        if sub_name == "protect":
            sp.add_argument("--prefix", default=None, help="Homebrew prefix (/opt/homebrew или /usr/local).")
            sp.add_argument("--strict", action="store_true",
                            help="Отключить sudo timestamp cache для текущего пользователя.")
        sp.set_defaults(func=cmd_privoxy)
    p_audit = p_privoxy_sub.add_parser(
        "audit", help="Пассивный журнал команд, способных менять Privoxy.")
    p_audit_sub = p_audit.add_subparsers(dest="privoxy_audit_action", required=True)
    for sub_name, sub_help in (
        ("install", "Установить root-owned eslogger-аудитор (нужен свежий sudo)."),
        ("status", "Показать состояние аудитора без sudo."),
        ("report", "Показать последние подходящие команды без sudo."),
        ("uninstall", "Удалить аудитор, сохранив журнал по умолчанию."),
    ):
        sp = p_audit_sub.add_parser(sub_name, help=sub_help)
        if sub_name == "report":
            sp.add_argument("--limit", type=int, default=50, help="Число последних событий (1–1000).")
            sp.add_argument("--json", action="store_true", help="Вывести записи как JSON.")
        if sub_name == "uninstall":
            sp.add_argument("--purge-log", action="store_true",
                            help="Также удалить накопленный журнал (необратимо).")
        sp.set_defaults(func=cmd_privoxy)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
