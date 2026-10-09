#!/usr/bin/env python3
"""Команды CLI srouter и argparse-парсер (вынесено из srouter.py, #228/#259).

Экстракция без редизайна: тела команд перенесены байт-в-байт, поверхность парсера
(подкоманды, флаги, type/default, set_defaults(func=...)) сохранена целиком.
`srouter.py` переэкспортирует всё отсюда — точки входа (`srouter` console-script,
`python srouter.py`) и потребители/тесты продолжают работать без изменений.

Владелец имён — этот модуль. Привилегированный слой (`_env_from_args`,
`make_privileged_runner`, `_is_privileged_cmd`, `_to_osascript`) живёт в
`srouter_privileged.py`, от которого зависят и `srouter_cli`, и `srouter` — так
цикла `srouter → srouter_cli → srouter` (антипаттерн закрытого PR #232 с
двусторонней делегацией через `srouter.__dict__`) не возникает.

ВАЖНО для тестов: моки команд надо ставить на модуль-ВЛАДЕЛЕЦ. `cmd_install`
резолвит свои глобалы здесь, поэтому `monkeypatch.setattr(srouter, "build_plan", ...)`
после экстракции был бы no-op — патчить надо `srouter_cli`. Гвард
`tests/test_srouter_refactor_228.py::TestReexportIdentity` следит за тем, чтобы
re-export отдавал ТОТ ЖЕ объект и затенения не появилось.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import replace
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path  # noqa: F401 — публичный контракт srouter (мокается в тестах)

import diag_netprobe  # mark: контекст сети на момент ручной отметки (fail-soft контракт)
import local_state
import metrics_store  # mark: append_timing_event + MARKS_LOG (владелец — модуль, тесты мокают его)
from install_lib import (
    CHOICES,
    LAUNCHAGENT_LABEL,
    LAUNCHCTL,
    InstallEnv,
    _has_launchagent_marker,
    _launchd_domain,
    _launchd_is_loaded,
    _launchd_reload,
    _read_head,
    _unload_launchagent,
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
import go_proxy  # 2026-09-30: тумблер Go-модулей в обход GFW (goproxy.cn-зеркало / wrapper-туннель)
import isolate_firewall  # protect: вкл/откл PF-изоляции Anthropic (strict-подсети, 2026-10-09)
import vscode_proxy  # issue #185: scoped SOCKS5 для codex-расширения через VSCode http.proxy
import health  # doctor-проверки стека
import privoxy_audit  # пассивный root-owned аудит lifecycle-команд Privoxy (#122)
import privoxy_system  # root-gated system LaunchDaemon для Privoxy (#122)
import privileged_ops  # noqa: F401 — единая osascript/sudo-обёртка + whitelist (#156)
import system_proxy_control  # explicit repair/restore системного SOCKS (Dock-запуск ChatGPT.app)

# Привилегированный слой — единый владелец srouter_privileged (#259). Импортируем ИМЕНА
# (а не модуль), чтобы `monkeypatch.setattr(srouter_cli, "make_privileged_runner", ...)`
# в тестах команд действовал: cmd_* резолвят их в globals ЭТОГО модуля.
from srouter_privileged import (
    OSASCRIPT,  # noqa: F401 — публичный контракт srouter.OSASCRIPT
    _env_from_args,
    _is_privileged_cmd,  # noqa: F401 — публичный контракт srouter._is_privileged_cmd
    _to_osascript,  # noqa: F401 — публичный контракт srouter._to_osascript
    make_privileged_runner,
)

# launchd/PPP-hook + split-route (#228) и Codex-wrappers/launchctl-env/PATH-zsh (#228) —
# импорт имён, а не модулей: cmd_install/cmd_uninstall зовут их как свои глобалы, и тесты
# мокают их через модуль-владелец команд (этот файл).
from srouter_launchd import (
    PPP_HOOK_MARKER,  # noqa: F401 — публичный контракт srouter
    PPP_HOOK_PATH,  # noqa: F401 — публичный контракт srouter
    _active_route_ip_for_removal,  # noqa: F401 — публичный контракт srouter
    _install_ppp_hook,
    _is_ip_literal,  # noqa: F401 — публичный контракт srouter
    _remove_active_split_route,
    _remove_ppp_hook,
)
from codex_wrappers import (
    CODEX_CLI_WRAPPER_LEGACY_NAME,  # noqa: F401 — публичный контракт srouter
    CODEX_CLI_WRAPPER_NAME,  # noqa: F401 — публичный контракт srouter
    CODEX_ENV_LABEL,  # noqa: F401 — публичный контракт srouter
    CODEX_ENV_MARKER,
    CODEX_LAUNCHCTL_UNSET_KEYS,  # noqa: F401 — публичный контракт srouter
    CODEX_NO_PROXY,  # noqa: F401 — публичный контракт srouter
    CODEX_NO_PROXY_LOOPBACK,  # noqa: F401 — публичный контракт srouter
    CODEX_WRAPPERS,
    ZSHRC_CODEX_FUNC_MARKER_BEGIN,
    ZSHRC_CODEX_FUNC_MARKER_END,
    ZSHRC_PATH_MARKER,
    _CODEX_FUNC_BLOCK,  # noqa: F401 — публичный контракт srouter
    _codex_bin_path,  # noqa: F401 — публичный контракт srouter
    _codex_wrapper_path,  # noqa: F401 — публичный контракт srouter
    _codex_zsh_target_installed,  # noqa: F401 — публичный контракт srouter
    _ensure_home_bin_in_path,
    _install_codex_isolation,
    _install_codex_wrappers,
    _install_codex_zsh_function,
    _install_launchctl_env,
    _install_one_wrapper,  # noqa: F401 — публичный контракт srouter
    _looks_like_managed_codex_wrapper,  # noqa: F401 — публичный контракт srouter
    _migrate_legacy_codex_cli_wrapper,  # noqa: F401 — публичный контракт srouter
    _remove_codex_isolation,
    _remove_codex_wrappers,
    _remove_codex_zsh_function,
    _remove_home_bin_from_path,
    _remove_launchctl_env,
    _remove_one_wrapper,  # noqa: F401 — публичный контракт srouter
    _zshrc_path,  # noqa: F401 — публичный контракт srouter
)

# Claude.app wrapper (инцидент 2026-10-07): env + --proxy-server точечно, канон codex-wrappers.
from claude_wrappers import (
    CLAUDE_APP_MARKER,
    _install_claude_app_wrapper,
    _remove_claude_app_wrapper,
)


def _prompt_bool(label: str) -> bool:
    return input(f"{label} [y/N]: ").strip().lower() in {"y", "yes", "д", "да"}


def _prompt_choice(name: str) -> str:
    """adopt | overwrite | skip (install_lib.CHOICES)."""
    while True:
        answer = input(f"Выбор для {name} [adopt/overwrite/skip]: ").strip().lower()
        if answer in CHOICES:
            return answer
        print("Допустимо: adopt, overwrite, skip.")



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
        # Issue #307 round 2 (Codex cycle-review finding 1): -y НЕ разрешает перезапись ЧУЖИХ
        # значений; force — только явный --force-proxy-overwrite (прецедент force_endpoint_overwrite).
        _proxy_force = bool(getattr(args, "force_proxy_overwrite", False))
        cp = claude_proxy.enable(force=_proxy_force)
        cp_note = ("Claude Code: HTTPS_PROXY прописан в ~/.claude/settings.json."
                   if cp.get("ok") else
                   f"Claude Code: не удалось прописать HTTPS_PROXY ({cp.get('err', 'unknown')}).")
        # issue #130: git → SOCKS5 (xray 10808) scoped на github.com, автоматически, без ручных
        # правок ~/.gitconfig. Best-effort (не критично для install, но часть «одна команда, всё
        # правильно» — git умеет нативный SOCKS5, в отличие от Claude Code).
        gp = git_proxy.enable(force=_proxy_force)
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
        # config.toml [network] proxy_url МЁРТВ в codex 0.146. Исторически (до контракта
        # 2026-10-07) единственный путь для Rust app-server = env SOCKS5 в launchd gui-домене →
        # codenv (RunAtLoad + StartInterval=300, переживает ребут). Сейчас ambient-прокси в
        # gui-домен не сеется (контракт: агент — только residual-чистка), прокси App задаётся
        # точечно — ~/bin/codex-app-proxy (--proxy-server) / per-tool wrappers.
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
        vp = vscode_proxy.enable(force=_proxy_force)
        if vp.get("ok"):
            vp_note = ("scoped SOCKS5 в VSCode http.proxy (Code/Cursor) — расширение openai.chatgpt, "
                       "CC не затрагивается (#185)"
                       + (f" Пути: {', '.join(vp.get('paths') or [])}" if vp.get("paths") else ""))
        else:
            vp_note = f"scoped VSCode http.proxy не установлен ({vp.get('err', 'unknown')})."
        env_note = f"{codenv_note} VSCode: {vp_note}"
        path_note = _ensure_home_bin_in_path(env)
        codex_iso_note = _install_codex_isolation(env, runner)
        # Claude.app wrapper (инцидент 2026-10-07): Chromium-стек Electron игнорирует env —
        # нужен argv --proxy-server; без wrapper'а App из Dock идёт напрямую за GFW.
        claude_note = _install_claude_app_wrapper(env)
        # Marker-migration table (issue #112 Часть 4): регистрируем текущие маркеры wrappers/zshrc/codenv
        # в state.known_markers. При будущей смене версии маркера old останется как legacy → следующий
        # install мигрирует old→current. Без регистрации install использует только current (safe fallback).
        # Best-effort: ошибка/отсутствие state_path не блокируют install (маркеры в коде всё равно валидны).
        try:
            _km_state_path = env.state_path
            for _entry in CODEX_WRAPPERS:
                populate_known_markers(_km_state_path, "wrappers", [_entry[2]])
            populate_known_markers(_km_state_path, "wrappers", [CLAUDE_APP_MARKER])
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
              f"{claude_note}\n"
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
    # Claude.app wrapper — симметрично install (marker-gate: current ИЛИ legacy — наш).
    claude_note = ". " + _remove_claude_app_wrapper()

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
          + codex_iso_note
          + claude_note)
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


# Диагностическая кампания деградации туннеля (2026-09): ping участков сети (gateway/domestica/VPS
# мимо туннеля) раз в 60с → корреляция с блэкаутами туннеля (diag_netprobe.py report).
NETPROBE_LABEL = "com.srouter.netprobe"
NETPROBE_MARKER = "srouter-managed-netprobe-v1"
NETPROBE_TEMPLATE = "com.srouter.netprobe.plist"
NETPROBE_SCRIPT = "diag_netprobe.py"
NETPROBE_JSONL_HINT = "~/Library/Logs/srouter-netprobe.jsonl"  # подпись в сообщениях (путь живёт в diag_netprobe.NETPROBE_LOG)


def _netprobe_env():
    """InstallEnv кампании: те же SROUTER_*-переопределения, но СВОИ логи (не dashboard-файлы)."""
    env = InstallEnv.from_env()
    return replace(env,
                   log_out=env.log_out.with_name("srouter-netprobe.out.log"),
                   log_err=env.log_err.with_name("srouter-netprobe.err.log"))


def _netprobe_subprocess(env, mode, timeout, extra=None):
    """Прогон diag_netprobe.py <mode> [extra] в subprocess: граница таймаута + изоляция
    fail-soft. Печатает stdout/stderr, возвращает rc (0 ок, 2 ошибка/таймаут)."""
    cmd = [sys.executable, str(env.root / NETPROBE_SCRIPT), mode]
    if extra:
        cmd.append(extra)
    res = run(cmd, timeout)
    out = (res.get("out") or "").strip()
    err = (res.get("err") or "").strip()
    if out:
        print(out)
    if err:
        print(err)
    if res.get("timeout") or res.get("rc") != 0:
        print(f"Netprobe: {mode} завершился с ошибкой (rc={res.get('rc')}, "
              f"timeout={res.get('timeout')}).")
        return 2
    return 0


def cmd_netprobe(args) -> int:
    """apply|stop|report|ssid диагностической LaunchAgent-джобы netprobe (кампания 2026-09).

    apply — тонкая обёртка _install_generic_launchagent (канон watchdog/codenv: marker-gate,
    рендер, atomic write, bootout→bootstrap идемпотентно). stop — канон _unload_launchagent:
    marker-gate своим маркером, identity-связка plist↔Label (plistlib), unlink только после
    ПОДТВЕРЖДЁННОЙ выгрузки (tristate через None — fail-safe, plist остаётся). JSONL/логи при
    stop НЕ удаляются — форензика кампании.
    report — коррелятор (блэкауты туннеля × потери по участкам пути).
    ssid — ручной режим из ТЕРМИНАЛА пользователя: показать SSID и записать метку сети
    в JSONL (launchd-джоба SSID получить не может — геоданные, см. diag_netprobe.read_ssid).
    """
    action = args.netprobe_action
    env = _netprobe_env()
    if action == "apply":
        ok, err = _install_generic_launchagent(
            env, run,
            template_name=NETPROBE_TEMPLATE, label=NETPROBE_LABEL, marker=NETPROBE_MARKER,
            script_path=env.root / NETPROBE_SCRIPT)
        if ok:
            print(f"Netprobe: установлен ({NETPROBE_LABEL}, ping участков раз в 60с, "
                  f"JSONL {NETPROBE_JSONL_HINT}). Отчёт: srouter netprobe report")
            return 0
        if "_foreign" in err:
            print(f"Netprobe: чужой plist {NETPROBE_LABEL} (без маркера {NETPROBE_MARKER}) — "
                  f"не трогаю. Если это остаток ручной установки, выгрузи и удали его вручную:\n"
                  f"  launchctl bootout gui/501/{NETPROBE_LABEL}\n"
                  f"  rm ~/Library/LaunchAgents/{NETPROBE_LABEL}.plist")
        else:
            print(f"Netprobe: не установлен ({err}).")
        return 2
    if action == "stop":
        plist = env.launchagent_dir / f"{NETPROBE_LABEL}.plist"
        if not plist.exists():
            print(f"Netprobe: не установлен ({plist} отсутствует).")
            return 2
        # marker-gate своим маркером (не generic LAUNCHAGENT_MARKER), затем канон
        # _unload_launchagent: identity-связка plist↔Label через plistlib (#94 DEFECT B),
        # unlink только при ПОДТВЕРЖДЁННОЙ выгрузке (tristate None — fail-safe, plist остаётся).
        try:
            marker_present = NETPROBE_MARKER in _read_head(plist)
        except OSError as exc:
            print(f"Netprobe: plist нечитаем ({exc}) — не трогаю.")
            return 2
        if not marker_present:
            print(f"Netprobe: чужой plist {NETPROBE_LABEL} (без маркера) — не трогаю.")
            return 2
        res = _unload_launchagent({"plist_path": str(plist), "label": NETPROBE_LABEL,
                                   "removable": True}, run)
        if res.get("ok"):
            print(f"Netprobe: остановлен. JSONL-данные кампании сохранены "
                  f"({NETPROBE_JSONL_HINT}).")
            return 0
        print(f"Netprobe: не выгружен/не удалён ({res.get('blocked', 'unknown')}) — "
              f"plist оставлен (fail-safe). Проверь: launchctl list | grep {NETPROBE_LABEL}")
        return 2
    if action == "netname":
        if not getattr(args, "name", None):
            print("Netprobe: netname требует имя сети.")
            return 2
        return _netprobe_subprocess(env, "netname", 30, extra=args.name)
    if action in ("report", "ssid"):
        return _netprobe_subprocess(env, action, 120 if action == "report" else 30)
    # неизвестный action — argparse не пустит, но fail-closed
    return 2


def cmd_mark(args) -> int:
    """Ручная отметка качества интернета: srouter mark <good|ok|bad> [комментарий].

    Субъективный вердикт пользователя в момент ощущения + контекст сети на момент
    отметки (current_net_status: метка/известность/источник) → append в MARKS_LOG.
    Цель — корреляция «ощущение × автометрики» вместо гадания (2026-10-04).
    Семантика уровней (решение пользователя): глазного критерия «хорошо vs норм» нет —
    good резервируется под будущую автоматическую разметку, вручную ставятся ok/bad.
    append best-effort, но команда честная: неудача записи → stderr + exit 1.
    """
    comment = (args.comment or "").strip() or None
    ts = time.time()
    st = diag_netprobe.current_net_status()  # fail-soft контракт: сам не бросает
    event = {
        "timestamp": datetime.fromtimestamp(ts).astimezone().isoformat(),
        "ts": ts,
        "verdict": args.verdict,
        "comment": comment,
        "net": (st or {}).get("label"),
        "net_known": bool((st or {}).get("known")),
        "net_source": (st or {}).get("source"),
    }
    if not metrics_store.append_timing_event(event, log_path=metrics_store.MARKS_LOG):
        print(f"Отметка НЕ записана: append в {metrics_store.MARKS_LOG} не удался.",
              file=sys.stderr)
        return 1
    net_txt = event["net"] or "нет"
    if st is not None and not st.get("known"):
        net_txt += " (неизвестная сеть)"
    suffix = f" (комментарий: {comment})" if comment else ""
    print(f"Отметка записана: {args.verdict}{suffix} — сеть: {net_txt}")
    return 0


def cmd_doctor(args) -> int:
    """Проверить здоровье стека: порты + реальный туннель. Отчёт ✅/❌ + подсказки."""
    result = health.check_all(active_claude=True)
    health._print_report(result)
    health._print_degradation_legend()
    return 0 if result["status"] == "ok" else 1


def cmd_git_proxy(args) -> int:
    """status|enable|disable git-прокси для github (git_proxy: socks5h xray 10808, ~/.gitconfig).

    status — ЭФФЕКТИВНЫЙ вердикт по всем слоям лестницы git (effective_proxy: local urlmatch >
    global urlmatch > глобальные generic http.proxy/https.proxy > env). Мотивация 2026-09-30:
    doctor называл «напрямую» состояние, где бесхозный глобальный 8118 реально проксировал git.
    enable/disable — managed-ключ (транзакция + backup). disable --full — дополнительно снимает
    бесхозные глобальные ключи (purge_stray; чужие значения — только с --force, контракт #307).
    """
    action = getattr(args, "gitproxy_action", "status")

    if action == "status":
        st = git_proxy.status()
        lo = git_proxy.local_override()
        sg = git_proxy.stray_global()
        print("git-proxy: слои прокси для git → github.com")
        print(f"  1. local urlmatch (.git/config этого репо): "
              + (f"{lo['values']}" if lo["present"] else "нет"))
        print(f"  2. global urlmatch {git_proxy.KEY}: "
              + (f"{st.get('values')} (state={st.get('state')})" if st.get("present") else "нет"))
        for name, rec in (("https.proxy", sg["https"]), ("http.proxy", sg["http"])):
            print(f"  3. глобальный {name}: "
                  + (f"{rec['values']}" if rec["present"] else "нет"))
        eff = git_proxy.effective_proxy()
        if not isinstance(eff, dict) or not eff.get("layer") or eff.get("layer") == "unknown":
            print("Вердикт: конфиг нечитаем (unknown).")
            return 1
        if eff["layer"] == "direct" or (eff["layer"] == "local-urlmatch" and not eff.get("proxy")):
            print(f"Вердикт: git→github идёт НАПРЯМУЮ ({eff.get('detail')}).")
        else:
            print(f"Вердикт: git→github идёт через {eff.get('proxy')} "
                  f"(слой {eff['layer']}: {eff.get('detail')}).")
        print("Управление: srouter git-proxy enable [--force] / disable [--full]")
        return 0

    if action == "enable":
        r = git_proxy.enable(force=args.force)
        if not r.get("ok"):
            if r.get("conflict"):
                cur = git_proxy.status()
                print(f"git-proxy: отказ — {r.get('err')}\n"
                      f"  текущие значения: {cur.get('values')}\n"
                      f"  перезаписать осознанно: srouter git-proxy enable --force")
            else:
                print(f"git-proxy: не включён ({r.get('err')}).")
            return 1
        print(f"git-proxy: включён ({r.get('proxy')}) — ключ {git_proxy.KEY} в ~/.gitconfig.")
        lo = git_proxy.local_override()
        if lo["present"]:
            print(f"  ВНИМАНИЕ: локальный override .git/config ЭТОГО репо ({lo['values']}) "
                  f"побеждает глобальный ключ. Снять: git config --local --unset {git_proxy.KEY}")
        return 0

    if action == "disable":
        r = git_proxy.disable()
        if not r.get("ok"):
            print(f"git-proxy: managed-ключ не снят ({r.get('err')}).")
            return 1
        print(f"git-proxy: managed-ключ снят ({git_proxy.KEY}).")
        ok = True
        if args.full:
            pr = git_proxy.purge_stray(force=args.force)
            for key, vals in pr.get("purged", {}).items():
                adds = " ; ".join(f"git config --global --add {key} '{v}'" for v in vals)
                print(f"  снят бесхозный {key}: {vals} (восстановить: {adds})")
            for key, info in pr.get("refused", {}).items():
                ok = False
                print(f"  ОТКАЗ на {key}: {info.get('err')} значения={info.get('values')} "
                      f"(чужое — осознанно: srouter git-proxy disable --full --force)")
            sg = git_proxy.stray_global()
            left = {k: rec["values"] for k, rec in sg.items() if rec["present"]}
            if left:
                ok = False
                print(f"  остались бесхозные ключи: {left} — git продолжает ходить через них.")
            elif not pr.get("purged"):
                print("  бесхозных глобальных http.proxy/https.proxy нет.")
        else:
            sg = git_proxy.stray_global()
            left = {k: rec["values"] for k, rec in sg.items() if rec["present"]}
            if left:
                print(f"  осталось проксирование через бесхозный слой: {left} "
                      f"(полное отключение: srouter git-proxy disable --full)")
        return 0 if ok else 1
    return 2


def cmd_go_proxy(args) -> int:
    """status|enable|disable go-прокси для модулей (go_proxy).

    proxy.golang.org — GFW-чёрная дыра напрямую (эмпирика 2026-09-30), а транспортного
    конфига у Go нет (`go env -w HTTPS_PROXY` отвергается) — отсюда два режима:
    mirror (GOPROXY=goproxy.cn, VPS-независимо) и tunnel (wrapper ~/bin/go + socks5 xray).
    Чужой GOPROXY/чужой ~/bin/go — только с --force (#307-канон).
    """
    action = getattr(args, "goproxy_action", "status")

    if action == "status":
        st = go_proxy.status()
        g, w = st["goproxy"], st["wrapper"]
        print("go-proxy: слои прокси для Go-модулей (go build / go mod download)")
        print(f"  1. wrapper {go_proxy.WRAPPER_PATH}: "
              + (f"managed → {w['target']}" if w["managed"]
                 else ("присутствует БЕЗ маркера (чужой)" if w["present"] else "нет")))
        print(f"  2. GOPROXY (go env): {g.get('value') or '—'} (state={g.get('state')})")
        print(f"  3. env процесса (HTTPS_PROXY/HTTP_PROXY): {st.get('env_proxy') or 'нет'}")
        verdicts = {
            "tunnel": f"Go-модули идут через туннель ({go_proxy.TUNNEL_PROXY}, wrapper ~/bin/go).",
            "mirror": f"Go-модули идут через зеркало {go_proxy.MIRROR_GOPROXY} (VPS-независимо).",
            "foreign": f"GOPROXY задан вручную ({g.get('value')}) — srouter этим не управляет.",
            "direct": "Go-модули идут НАПРЯМУЮ на proxy.golang.org — GFW-чёрная дыра "
                      "(эмпирика 2026-09-30): go build будет падать по таймауту.",
        }
        print(f"Вердикт: {verdicts.get(st['verdict'], st['verdict'])}")
        print("Управление: srouter go-proxy enable [--mode=mirror|tunnel] [--force] / "
              "disable [--full] [--force]")
        return 0

    if action == "enable":
        r = go_proxy.enable(mode=getattr(args, "mode", "mirror"), force=args.force)
        if not r.get("ok"):
            print(f"go-proxy: не включён — {r.get('error')}")
            return 1
        if r["mode"] == "mirror":
            print(f"go-proxy: включён mirror — GOPROXY={r['goproxy']} "
                  f"(go env -w, VPS-независимо).")
        else:
            print(f"go-proxy: включён tunnel — wrapper {r['wrapper']} → {r['target']} "
                  f"через {go_proxy.TUNNEL_PROXY}.")
        return 0

    if action == "disable":
        r = go_proxy.disable(full=args.full, force=args.force)
        if not r.get("ok"):
            print(f"go-proxy: не выключен — {r.get('error')}")
            return 1
        for item in r.get("removed", []):
            print(f"  снято: {item}")
        print("go-proxy: выключен" + (" (полностью)" if args.full else "") + ".")
        return 0
    return 2


def cmd_protect(args) -> int:
    """on|off|status — человековые вкл/выкл PF-изоляции Anthropic (строгий режим).

    on = enable_strict + lease phase="strict" в runtime.active_isolate: дашборд-карточка
    (/api/isolate) читает ТОТ ЖЕ ключ — без persist она врала бы «выключено» при работающем
    PF (канон «два контура противоречат» #341). Повторный on при живом lease — отказ БЕЗ
    pfctl-вызова: enable_strict не идемпотентна (каждый вызов = новый pfctl -E ref).
    off — disable_strict(token из lease) + clear; без lease disable всё равно зовётся
    (fail-safe: lease мог потеряться, якорь PF — нет). status — probe_isolation (state-only);
    probe красит strict как warn по бут-семантике («промежуточная фаза») — для ручного
    режима strict это норма, рендерим как steady-state. Слово «isolate» отвергнуто
    пользователем как сложное (2026-10-09); aliases enable/disable/вкл/выкл.
    """
    # canonical ставит set_defaults парсера (алиасы add_parser aliases= — те же
    # parser-объекты): истина алиасов в одном месте, dict-нормализация не нужна.
    action = getattr(args, "canonical", None) or getattr(args, "protect_action", "status")
    state = getattr(args, "state", None)

    if action == "on":
        lease = local_state.load_active_isolate(state)
        if lease is not None:
            print(f"protect: защита уже включена (phase={lease.get('phase')}, "
                  f"с {lease.get('applied_at')}). Сначала: srouter protect off")
            return 1
        # Preflight writability (#68): доказать atomic-write путь ДО pf enable-ref —
        # тот же гейт, что у роута /api/isolate/enable (dashboard_routes:625), иначе
        # сожжём GUI-пароль и pf-ref и только потом узнаем про неписабельный state.
        if not local_state.preflight_state_write(state):
            print("protect: отказ — state недоступен на запись, pf-ref не создаю.")
            return 1
        r = isolate_firewall.enable_strict()
        if r.get("cancelled"):
            print("protect: включение отменено — пароль не введён.")
            return 1
        if r.get("timeout"):
            print("protect: не удалось включить: timeout pfctl.", file=sys.stderr)
            return 2
        if not r.get("ok"):
            # enable_strict сам помечает ok=False при отсутствующем token (ref-течь).
            print(f"protect: не включён ({r.get('err')}).")
            return 1
        entry = {"domains": [], "ports": [80, 443], "token": r["token"],
                 "applied_at": int(time.time()), "phase": "strict"}
        if local_state.save_active_isolate(entry, state) is None:
            # Зеркало rollback'а роута /api/isolate/enable (dashboard_routes:646-651):
            # PF включён, но контур состояния не записан — снимать, а не оставлять
            # «включено-невидимо».
            isolate_firewall.disable_strict(r["token"])
            print("protect: PF включён, но lease не записан — откатил "
                  "(state недоступен на запись?).", file=sys.stderr)
            return 2
        print("Защита включена: Anthropic отрезан от прямого доступа "
              "(строгий режим: подсети 160.79.104.0/21, 2607:6bc0::/32; порты 80/443). "
              "Снять: srouter protect off")
        return 0

    if action == "off":
        lease = local_state.load_active_isolate(state)
        r = isolate_firewall.disable_strict(lease.get("token") if lease else None)
        if r.get("cancelled"):
            print("protect: выключение отменено — пароль не введён.")
            return 1
        if r.get("timeout"):
            print("protect: не удалось снять: timeout pfctl.", file=sys.stderr)
            return 2
        if not r.get("ok"):
            print(f"protect: не снята ({r.get('err')}).")
            return 1
        if lease:
            local_state.clear_active_isolate(state)
            print("Защита снята.")
        else:
            print("Защита и так была выключена (lease нет; якорь PF сброшен на всякий случай).")
        return 0

    if action == "status":
        p = isolate_firewall.probe_isolation(state_path=state)
        if p.get("status") == "unknown":
            print(f"protect: статус нечитаем ({p.get('error')}).", file=sys.stderr)
            return 2
        if p.get("phase") == "strict":
            print("Защита: ВКЛ (строгий режим — подсети Anthropic отрезаны напрямую, "
                  f"с {p.get('applied_at')}).")
            print("  Статус — по lease (без pfctl): защита действует, пока не снята. "
                  "Если загружены авто-агенты isolate/escape, strict мог быть снят ими "
                  "уже — проверка ядра: sudo pfctl -s Anchors. Ручное снятие: "
                  "srouter protect off; аварийно: sudo pfctl -a com.apple/srouter_isolate -F all")
            return 0
        if p.get("phase") == "working":
            n = sum(len(v) for v in (p.get("ips") or {}).values())
            print(f"Защита: ВКЛ (режим доменов: {n} IP, порты {p.get('ports')}). "
                  "Управление: карточка дашборда / srouter protect off")
            return 0
        print("Защита: ВЫКЛ — Anthropic может ходить напрямую. Включить: srouter protect on")
        return 1
    return 2


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


def cmd_system_proxy(args) -> int:
    """Явный repair/restore/status системного macOS SOCKS активного network service.

    Отдельная explicit-операция (НЕ часть install/start/watchdog): чинит обычный запуск
    ChatGPT.app/Codex.app из Dock, когда системный SOCKS выключен/настроен неверно — без
    переустановки стека и без перезапуска приложения. См. докстринг health_codenv.py
    _codex_app_chromium_proxy_check и system_proxy_control.py.
    """
    action = getattr(args, "system_proxy_action", None)
    state_path = getattr(args, "state", None)
    runner = make_privileged_runner(run)

    if action == "status":
        st = system_proxy_control.status(runner=runner)
        if st["status"] != "ok":
            print(f"system-proxy: {st.get('detail', 'состояние не определено')}", file=sys.stderr)
            return 1
        socks = st["socks"]
        marker = "✅ (target)" if st["target"] else "⚠️"
        print(f"system-proxy: сервис={st['service']} (interface={st['interface']}) {marker}")
        print(f"  SOCKS: enabled={socks['enabled']} {socks['server']}:{socks['port']} "
              f"authenticated={socks['authenticated']}")
        return 0 if st["target"] else 1

    if action == "repair":
        r = system_proxy_control.repair(path=state_path, runner=runner)
        if r["ok"]:
            print("system-proxy: repair выполнен — системный SOCKS настроен и включён "
                  f"({'изменения применены' if r.get('changed') else 'уже был настроен'}).")
            if r.get("warning"):
                print(f"system-proxy: warning — {r['warning']}", file=sys.stderr)
            return 0
        print(f"system-proxy: repair не выполнен — {r.get('err', 'unknown error')}", file=sys.stderr)
        return 1

    if action == "restore":
        r = system_proxy_control.restore(path=state_path, runner=runner,
                                         service=getattr(args, "system_proxy_service", None))
        for res in r.get("results", []):
            word = "восстановлен" if res["ok"] else "НЕ восстановлен"
            line = f"system-proxy: {res['service']}: {word}"
            if res.get("err"):
                line += f" — {res['err']}"
            print(line, file=sys.stderr if not res["ok"] else sys.stdout)
            if res.get("warning"):
                print(f"system-proxy: {res['service']}: warning — {res['warning']}",
                      file=sys.stderr)
        if r["ok"]:
            print("system-proxy: восстановлен прежний системный SOCKS.")
            if r.get("warning"):
                print(f"system-proxy: warning — {r['warning']}", file=sys.stderr)
            return 0
        print(f"system-proxy: restore не выполнен — {r.get('err', 'unknown error')}", file=sys.stderr)
        return 1

    print(f"system-proxy: неизвестное действие {action!r}", file=sys.stderr)
    return 2


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
    if result.get("persistent") is False:
        # #330: сервис поднят, но launchd-регистрация не подтверждена — молчаливый транзиентный
        # подъём = следующий инцидент после ребута (канон noisy-log-better-than-no-log). rc 0:
        # трафик идёт, это warning, а не failure; doctor-грань persists-across-boot подхватит.
        print(
            f"ВНИМАНИЕ: launchd-регистрация НЕ подтверждена ({result.get('persistence_reason', 'unknown')}): "
            "privoxy поднят ТРАНЗИЕНТНО — после перезагрузки НЕ поднимется (#330). "
            "Верните регистрацию: srouter privoxy protect --strict (пересоздаёт managed-plist).",
            file=sys.stderr,
        )
    elif result.get("persistent") is None:
        # #330 P3: launchctl timeout — регистрация не верифицирована (unknown ≠ not_loaded,
        # канон #204): НЕ клеймим «транзиентно», но и не молчим — подтверждения нет.
        print(
            f"ВНИМАНИЕ: launchd-регистрацию не удалось верифицировать "
            f"({result.get('persistence_reason', 'unknown')}): подтверждения boot-персистентности нет "
            "(#330). Проверьте: srouter privoxy status.",
            file=sys.stderr,
        )
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
        for i in _read_routing_ips(args.xray_config, outbound) or []:
            print(f"  ip {i}")
        return 0

    if subcmd not in ("add-domain", "remove-domain", "add-ip", "remove-ip"):
        print(f"routing: неизвестная подкоманда {subcmd!r}", file=sys.stderr)
        return 2

    is_ip = subcmd in ("add-ip", "remove-ip")
    action = "add" if subcmd in ("add-domain", "add-ip") else "remove"
    adopt = getattr(args, "adopt", False)
    if not adopt and not sys.stdin.isatty():
        # non-TTY без --adopt: не виснуть на промпте (канон cmd_install TTY-gate)
        pass  # routing_apply сам вернёт err=foreign_config_needs_adopt без adopt
    runner = make_privileged_runner(run)
    if is_ip:
        # ip-matchers живут в том же managed-правиле, что и домены; доменный состав не трогается
        label = ", ".join(args.ips)
        r = local_state.routing_apply(
            None, ips=list(args.ips), ip_action=action, adopt=adopt, outbound=outbound,
            config_path=args.xray_config, state_path=state_path,
            runner=runner, port_checker=port_open,
        )
    else:
        label = args.host
        r = local_state.routing_apply(
            [args.host], action=action, adopt=adopt, outbound=outbound,
            config_path=args.xray_config, state_path=state_path,
            runner=runner, port_checker=port_open,
        )
    if not r["ok"]:
        print(f"routing {subcmd} {label}: {r.get('err', 'failed')}", file=sys.stderr)
        if r.get("err") == "foreign_config_needs_adopt":
            print("  (первый раз: добавь --adopt, чтобы srouter принял секцию reality-out "
                  "под управление — домены существующего rule сохранятся)", file=sys.stderr)
        return 2
    verb = "добавлен" if action == "add" else "убран"
    if r.get("changed"):
        print(f"routing: {label} {verb}, xray перезапущен.")
    else:
        print(f"routing: {label} уже в нужном состоянии (no-op).")
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


def _read_routing_ips(config_path, outbound):
    """Текущие ip[] того же rule (domain-состав без ip → пустой список; rule не найден → None)."""
    try:
        import json as _json
        from pathlib import Path
        data = _json.loads(Path(config_path).read_text(encoding="utf-8"))
        for r in (data.get("routing") or {}).get("rules") or []:
            if isinstance(r, dict) and r.get("outboundTag") == outbound and isinstance(r.get("domain"), list):
                ips = r.get("ip")
                return list(ips) if isinstance(ips, list) else []
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
            # Issue #307 (Codex cycle-review PR #328 finding 1): `-y` НЕ означает разрешение
            # перезаписывать ЧУЖИЕ proxy-настройки (корпоративные/ручные). Перезапись — только
            # этот явный флаг (или осознанный force через дашборд-панель).
            p.add_argument("--force-proxy-overwrite", action="store_true",
                           help="Перезаписать ЧУЖИЕ значения прокси в ~/.gitconfig, "
                                "~/.claude/settings.json и settings.json редакторов "
                                "(чужие значения сохраняются в backup; по умолчанию install "
                                "на чужое значение честно отказывает).")
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

    # system-proxy: explicit repair/restore/status системного macOS SOCKS активного network
    # service (Wi-Fi/Ethernet). Отдельная команда, НЕ часть install/start/watchdog — чинит обычный
    # Dock-запуск ChatGPT.app/Codex.app, когда системный SOCKS выключен/настроен неверно, без
    # переустановки и без перезапуска приложения. См. health_codenv._codex_app_chromium_proxy_check.
    p_sysproxy = sub.add_parser(
        "system-proxy",
        help="Явный repair/restore/status системного SOCKS macOS (обычный Dock-запуск ChatGPT.app).")
    p_sysproxy_sub = p_sysproxy.add_subparsers(dest="system_proxy_action", required=True)
    for sub_name, sub_help in (
        ("status", "Показать текущее состояние системного SOCKS активного network service."),
        ("repair", "Настроить и включить наш SOCKS endpoint (бэкапит чужой, если он выключен)."),
        ("restore", "Вернуть endpoint'ы, сохранённые repair'ами (все сервисы или --service)."),
    ):
        sp = p_sysproxy_sub.add_parser(sub_name, help=sub_help)
        sp.add_argument("--state", default=None, help="Путь к srouter.local.json.")
        if sub_name == "restore":
            sp.add_argument("--service", dest="system_proxy_service", default=None,
                            help="Восстановить только указанный network service "
                                 "(по умолчанию — все известные leases).")
        sp.set_defaults(func=cmd_system_proxy)

    # git-proxy (2026-09-30): единый тумблер git-прокси для github — status всех слоёв
    # (effective_proxy), enable/disable managed-ключа; disable --full снимает и бесхозные
    # глобальные http.proxy/https.proxy (force-гейт на чужие значения, #307).
    p_gitproxy = sub.add_parser(
        "git-proxy",
        help="Тумблер git-прокси для github: status/enable/disable (--full — и бесхозные глобальные).")
    p_gp_sub = p_gitproxy.add_subparsers(dest="gitproxy_action", required=True)
    for sub_name, sub_help in (
        ("status", "Эффективный вердикт по всем слоям прокси (local urlmatch/global/generic/env)."),
        ("enable", "Включить managed SOCKS5 xray в ~/.gitconfig (чужое значение — только --force)."),
        ("disable", "Снять managed-ключ (--full — плюс бесхозные http.proxy/https.proxy)."),
    ):
        sp = p_gp_sub.add_parser(sub_name, help=sub_help)
        if sub_name == "enable":
            sp.add_argument("--force", action="store_true",
                            help="Перезаписать ЧУЖОЕ значение (backup сохраняется, #307).")
        if sub_name == "disable":
            sp.add_argument("--full", action="store_true",
                            help="Также снять бесхозные глобальные http.proxy/https.proxy.")
            sp.add_argument("--force", action="store_true",
                            help="Снять и ЧУЖИЕ значения бесхозных ключей (снятое печатается).")
        sp.set_defaults(func=cmd_git_proxy)

    # go-proxy (2026-09-30): тумблер Go-модулей в обход GFW. proxy.golang.org — чёрная дыра
    # напрямую; транспортного конфига у Go нет → режимы mirror (GOPROXY=goproxy.cn) и
    # tunnel (wrapper ~/bin/go + socks5). Чужой GOPROXY/чужой wrapper — только --force (#307).
    p_goproxy = sub.add_parser(
        "go-proxy",
        help="Тумблер Go-модулей: status/enable/disable (--mode=mirror|tunnel, --full).")
    p_gpx_sub = p_goproxy.add_subparsers(dest="goproxy_action", required=True)
    for sub_name, sub_help in (
        ("status", "Слои (wrapper/GOPROXY/env) + вердикт: куда реально идут go-модули."),
        ("enable", "Включить режим: --mode=mirror (дефолт, goproxy.cn) | tunnel (wrapper ~/bin/go)."),
        ("disable", "Выключить: снять wrapper; --full — плюс managed GOPROXY (go env -u)."),
    ):
        sp = p_gpx_sub.add_parser(sub_name, help=sub_help)
        if sub_name == "enable":
            sp.add_argument("--mode", choices=("mirror", "tunnel"), default="mirror",
                            help="mirror = GOPROXY=goproxy.cn (VPS-независимо, дефолт); "
                                 "tunnel = wrapper ~/bin/go через socks5 xray 10808.")
            sp.add_argument("--force", action="store_true",
                            help="Перезаписать ЧУЖОЙ GOPROXY / чужой ~/bin/go (#307).")
        if sub_name == "disable":
            sp.add_argument("--full", action="store_true",
                            help="Также снять managed GOPROXY (go env -u GOPROXY).")
            sp.add_argument("--force", action="store_true",
                            help="Снять и ЧУЖИЕ значения (снятое печатается).")
        sp.set_defaults(func=cmd_go_proxy)

    # protect (2026-10-09): человековые вкл/выкл PF-изоляции Anthropic (strict-подсети).
    # Слово «isolate» отвергнуто пользователем; lease phase="strict" совместим с
    # дашборд-карточкой (один ключ runtime.active_isolate — один контур, канон #341).
    p_protect = sub.add_parser(
        "protect",
        help="Вкл/выкл PF-изоляции Anthropic: protect on | off | status "
             "(алиасы enable/disable/вкл/выкл).")
    p_pr_sub = p_protect.add_subparsers(dest="protect_action", required=True)
    for sub_name, aliases, sub_help in (
        ("on", ("enable", "вкл"),
         "Включить (строгий режим: подсети Anthropic; спросит пароль админа)."),
        ("off", ("disable", "выкл"), "Выключить: снять якорь PF и lease."),
        ("status", (), "Человеческий статус защиты."),
    ):
        sp = p_pr_sub.add_parser(sub_name, aliases=aliases, help=sub_help)
        sp.add_argument("--state", default=None, help="Путь к srouter.local.json.")
        sp.set_defaults(func=cmd_protect, canonical=sub_name)

    # netprobe (кампания деградации туннеля 2026-09): LaunchAgent ping'ует участки сети
    # (gateway/domestica/VPS мимо туннеля) раз в 60с; report — корреляция блэкаутов туннеля
    # (metrics-JSONL watchdog'а) с потерями по участкам → вердикт «транзит vs DPI».
    p_netprobe = sub.add_parser(
        "netprobe",
        help="Диагностика участков сети: launchd-джоба (apply/stop) + отчёт корреляции (report).")
    p_netprobe_sub = p_netprobe.add_subparsers(dest="netprobe_action", required=True)
    for sub_name, sub_help in (
        ("apply", "Установить/обновить LaunchAgent com.srouter.netprobe (ping раз в 60с)."),
        ("stop", "Выгрузить джобу и удалить plist (JSONL-данные кампании сохраняются)."),
        ("report", "Корреляция блэкаутов туннеля с потерями по участкам (diag_netprobe.py)."),
        ("ssid", "Показать SSID и записать метку сети в JSONL (из терминала с Location Services)."),
    ):
        sp = p_netprobe_sub.add_parser(sub_name, help=sub_help)
        sp.set_defaults(func=cmd_netprobe)
    sp_nn = p_netprobe_sub.add_parser(
        "netname",
        help="Запомнить текущую сеть под именем (обучение отпечатка DNS; один прогон на сеть).")
    sp_nn.add_argument("name", help="Имя сети (напр. 103 / 888-5G).")
    sp_nn.set_defaults(func=cmd_netprobe)

    # mark (2026-10-04): ручная отметка качества интернета → JSONL (metrics_store.MARKS_LOG).
    # Цель — корреляция субъективных ok/bad с автометриками; good — резерв под авторазметку.
    p_mark = sub.add_parser(
        "mark", help="Ручная отметка качества интернета (ok/bad + комментарий) в JSONL-лог.")
    p_mark.add_argument(
        "verdict", choices=("good", "ok", "bad"),
        help="good — резерв под будущую авторазметку (глазного критерия «хорошо vs норм» "
             "нет); вручную ставь ok или bad.")
    p_mark.add_argument("comment", nargs="?", default=None,
                        help="Свободный комментарий (напр. «видео лагает»).")
    p_mark.set_defaults(func=cmd_mark)

    # routing (#136): управление routing-доменами production xray-config. Отдельная подкоманда —
    # свои sub-subcommands (add-domain/remove-domain/list). НЕ "route" (конфликт с split-route).
    p_route = sub.add_parser(
        "routing",
        help="Управление routing-доменами/ip xray (add-domain/remove-domain/add-ip/remove-ip/list). #136.")
    p_route_sub = p_route.add_subparsers(dest="routing_subcommand", required=True)
    for sub_name, sub_help in (
        ("add-domain", "Добавить домен в проксируемые (первый раз — --adopt)."),
        ("remove-domain", "Убрать домен из проксируемых."),
        ("add-ip", "Добавить ip/CIDR в то же managed-правило (напр. Hetzner-узел для ssh)."),
        ("remove-ip", "Убрать ip/CIDR из managed-правила."),
        ("list", "Показать текущие routing-домены и ip (read-only)."),
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
        elif sub_name in ("add-ip", "remove-ip"):
            sp.add_argument("ips", nargs="+", metavar="IP", help="IP или CIDR (напр. 78.47.183.125).")
            sp.add_argument("--adopt", action="store_true",
                            help="Принять секцию reality-out под управление (первый раз).")
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

