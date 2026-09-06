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

СТРУКТУРА (#228/#259). Этот файл — точка входа и слой обратной совместимости; реализация
живёт в четырёх модулях, зависимости строго однонаправленны (циклов нет):

    privileged_ops ← srouter_privileged ─┐
    srouter_launchd ─────────────────────┼→ srouter_cli ← srouter (этот файл)
    codex_wrappers ──────────────────────┘

  * srouter_privileged — `_env_from_args`, `make_privileged_runner`, `_is_privileged_cmd`,
    `_to_osascript`. Отдельный модуль ровно потому, что от них зависят ОБЕ стороны: без него
    получался бы цикл `srouter` → `srouter_cli` → `srouter` (в закрытом PR #232 его лечили
    двусторонней делегацией через `srouter.__dict__` — антипаттерн, не повторять).
  * srouter_launchd — launchd/PPP-hook и split-route.
  * codex_wrappers  — Codex SOCKS5-wrappers, launchctl-env, PATH/zsh.
  * srouter_cli     — команды `cmd_*`, `build_parser`, `main`.

ВАЖНО ПРО МОКИ. Владелец имени = модуль, где определена ЧИТАЮЩАЯ его функция. `cmd_install`
резолвит `build_plan`/`apply_install`/`git_proxy`/… в globals `srouter_cli`, поэтому
`monkeypatch.setattr(srouter, "build_plan", ...)` — тихий no-op (имя тут есть, AttributeError
не будет, но реальный `apply_install` всё равно выполнится). Патчить надо `srouter_cli`.
Исключение — патч атрибута НА объекте модуля (`srouter.health.check_all`, `srouter.sys.stdin`):
объект модуля общий, такой патч виден отовсюду. Гвард — `tests/test_srouter_refactor_228.py`.
"""
from __future__ import annotations

# Публичный контракт srouter: всё, что исторически лежало в этом модуле, остаётся доступным
# как srouter.X. Re-export отдаёт ТОТ ЖЕ объект (identity-гвард TestReexportIdentity), своих
# определений тут нет — иначе получилось бы затенение/двусторонняя делегация (#232).
from srouter_privileged import (  # noqa: F401 — намеренный re-export публичного контракта
    OSASCRIPT,
    _env_from_args,
    _is_privileged_cmd,
    _to_osascript,
    make_privileged_runner,
    os,
)
from srouter_launchd import (  # noqa: F401 — намеренный re-export публичного контракта
    PPP_HOOK_MARKER,
    PPP_HOOK_PATH,
    _active_route_ip_for_removal,
    _install_ppp_hook,
    _is_ip_literal,
    _remove_active_split_route,
    _remove_ppp_hook,
)
from codex_wrappers import (  # noqa: F401 — намеренный re-export публичного контракта
    CODEX_CLI_WRAPPER_LEGACY_NAME,
    CODEX_CLI_WRAPPER_NAME,
    CODEX_ENV_LABEL,
    CODEX_ENV_MARKER,
    CODEX_LAUNCHCTL_ENV,
    CODEX_LAUNCHCTL_UNSET_KEYS,
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
from srouter_cli import (  # noqa: F401 — намеренный re-export публичного контракта
    CHOICES,
    LAUNCHAGENT_LABEL,
    LAUNCHCTL,
    InstallEnv,
    PackageNotFoundError,
    Path,
    _has_launchagent_marker,
    _install_generic_launchagent,
    _is_loaded,
    _launchd_domain,
    _launchd_is_loaded,
    _launchd_reload,
    _prompt_bool,
    _prompt_choice,
    _read_routing_domains,
    _reclaimable_resolves_all_conflicts,
    _routing_has_marker,
    _version_string,
    _write_text_atomic,
    apply_install,
    apply_uninstall,
    argparse,
    build_parser,
    build_plan,
    build_uninstall_plan,
    claude_proxy,
    cmd_doctor,
    cmd_install,
    cmd_privoxy,
    cmd_restart,
    cmd_routing,
    cmd_start,
    cmd_status,
    cmd_stop,
    cmd_sync,
    cmd_system_proxy,
    cmd_uninstall,
    format_plan,
    format_uninstall_plan,
    git_proxy,
    health,
    json,
    local_state,
    main,
    populate_known_markers,
    port_open,
    privileged_ops,
    privoxy_audit,
    privoxy_system,
    run,
    sys,
    system_proxy_control,
    version,
    vscode_proxy,
)

if __name__ == "__main__":
    raise SystemExit(main())
