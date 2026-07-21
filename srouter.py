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
import json
import os
import re
import shlex
import shutil
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

import claude_proxy  # вкл/откл HTTPS_PROXY для Claude Code (~/.claude/settings.json)
import health  # doctor-проверки стека
import privoxy_audit  # пассивный root-owned аудит lifecycle-команд Privoxy (#122)
import privoxy_system  # root-gated system LaunchDaemon для Privoxy (#122)

# OSASCRIPT отсутствует в install_lib — локальная константа (копия dashboard_common).
OSASCRIPT = "/usr/bin/osascript"


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


PPP_HOOK_PATH = "/etc/ppp/ip-up"
PPP_HOOK_MARKER = "# srouter: мгновенная реакция"


def _install_ppp_hook(env, runner) -> str:
    """Установить /etc/ppp/ip-up — мгновенный split-route при VPN up (от root, без osascript).

    Шаблон launchagents/srouter-ppp-ip-up.sh рендерится (плейсхолдеры) и копируется в /etc/ppp/ip-up.
    Требует root (osascript admin-мост, как _sudo_route_ip). Возвращает строку-статус для вывода.
    """
    try:
        template = (env.root / "launchagents" / "srouter-ppp-ip-up.sh").read_text(encoding="utf-8")
        rendered = (template
                    .replace("__SROUTER_PYTHON_BIN__", env.python_bin)
                    .replace("__SROUTER_ROOT_DIR__", str(env.root))
                    .replace("__SROUTER_LOG_ERR__", str(env.log_err)))
        # Копирование в /etc/ppp/ip-up через osascript (требует admin, /etc/ = root).
        from traffic_shape import _applescript_text
        # Записать во временный файл, потом cp + chmod + chown (всё под osascript admin).
        tmp = f"/tmp/srouter-ppp-ip-up.{os.getpid()}"
        # Defence: rendered идёт в файл через printf %s (не shell-интерполяция).
        safe = rendered.replace("\\", "\\\\").replace("'", "'\\''")
        full_cmd = (f"printf '%s' '{safe}' > {tmp} && /bin/cp {tmp} {PPP_HOOK_PATH} && "
                    f"/bin/chmod 755 {PPP_HOOK_PATH} && /usr/sbin/chown root:wheel {PPP_HOOK_PATH} && "
                    f"/bin/rm -f {tmp}")
        applescript = f'do shell script "{_applescript_text(full_cmd)}" with administrator privileges'
        r = runner([OSASCRIPT, "-e", applescript], 30)
        if r.get("timeout") or (r.get("rc") not in (0, None) and r.get("rc") != 0 and "-128" not in (r.get("err") or "")):
            return f"PPP-hook: не установлен ({(r.get('err') or 'ошибка')[:80]})."
        if r.get("rc") == -128 or "-128" in (r.get("err") or ""):
            return "PPP-hook: отменено (диалог пароля)."
        return "PPP-hook: установлен (/etc/ppp/ip-up — мгновенный split-route при VPN up)."
    except Exception as exc:
        return f"PPP-hook: не установлен ({str(exc)[:80]})."


def _remove_ppp_hook(runner) -> str:
    """Удалить /etc/ppp/ip-up (если srouter-managed). Возвращает строку-статус."""
    try:
        from traffic_shape import _applescript_text
        # Проверить маркер перед удалением (не трогать чужой скрипт).
        check = runner(["/bin/cat", PPP_HOOK_PATH], 5)
        if check.get("timeout") or check.get("rc") != 0:
            return "PPP-hook: не был установлен (файла нет)."
        if PPP_HOOK_MARKER not in (check.get("out") or ""):
            return "PPP-hook: чужой скрипт в /etc/ppp/ip-up — не трогаем."
        rm_cmd = f"/bin/rm -f {PPP_HOOK_PATH}"
        applescript = f'do shell script "{_applescript_text(rm_cmd)}" with administrator privileges'
        r = runner([OSASCRIPT, "-e", applescript], 15)
        if r.get("rc") == -128 or "-128" in (r.get("err") or ""):
            return "PPP-hook: удаление отменено (диалог пароля)."
        return "PPP-hook: удалён." if r.get("rc") in (0, None) else f"PPP-hook: не удалён ({(r.get('err') or '')[:60]})."
    except Exception as exc:
        return f"PPP-hook: не удалён ({str(exc)[:60]})."


# ============================ Codex SOCKS5-wrappers + launchctl env ============================
# Codex (CLI + App) работает стабильно только через SOCKS5 (xray 10808) минуя privoxy (портит WS).
# srouter install ставит ~/bin/codex + ~/bin/codex-app-proxy + launchctl env (через LaunchAgent
# plist, переживает ребут) + ~/bin в PATH; uninstall убирает. Канон — _install_ppp_hook
# (best-effort, marker-gate, строка-статус).
# URL SOCKS5 — из dashboard_common (SOCKS_PROXY_URL), единый источник правды для xray-порта.
# except BaseException (не Exception): dashboard_common raise SystemExit при отсутствии
# srouter_config.py, а SystemExit не ловится Exception — fallback должен сработать и для него.
try:
    from dashboard_common import SOCKS_PROXY_URL as _CODEX_PROXY_URL
except BaseException:
    _CODEX_PROXY_URL = "socks5h://127.0.0.1:10808"
CODEX_NO_PROXY = "localhost,127.0.0.1,::1"
# (env-key, value) — единый список для install/setenv и uninstall/unsetenv (синхронны всегда).
CODEX_LAUNCHCTL_ENV = tuple((k, _CODEX_PROXY_URL) for k in
                            ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                             "http_proxy", "https_proxy", "all_proxy")) \
                      + (("NO_PROXY", CODEX_NO_PROXY), ("no_proxy", CODEX_NO_PROXY))
# Wrappers: (name, template, marker). Цикл в install/remove — не два явных вызова.
CODEX_WRAPPERS = (
    ("codex", "srouter-codex-cli-wrapper.sh", "# srouter: codex CLI wrapper (managed)"),
    ("codex-app-proxy", "srouter-codex-app-proxy-wrapper.sh", "# srouter: codex-app-proxy wrapper (managed)"),
)
# LaunchAgent для глобального env: launchctl setenv SOCKS5 в GUI-домен (переживает ребут).
# Label = com.srouter.codenv → prefix CODENV для плейсхолдеров __SROUTER_CODENV_*__ в шаблоне plist.
CODEX_ENV_LABEL = "com.srouter.codenv"
CODEX_ENV_MARKER = "srouter-managed-codex-env-v1"
ZSHRC_PATH_MARKER = "# srouter: ~/bin в PATH для codex wrapper"
# Shell-функция codex() в ~/.zshrc (issue #96): вызывает ~/bin/codex по абсолютному пути, чтобы
# порядок brew в PATH был не важен (функция всегда бьёт binary). Без неё wrapper #83 проигрывает
# /opt/homebrew/bin/codex. Парные маркеры для marker-gate install/remove (как ZSHRC_PATH_MARKER).
ZSHRC_CODEX_FUNC_MARKER_BEGIN = "# >>> srouter-managed-codex-function-v1 >>>"
ZSHRC_CODEX_FUNC_MARKER_END = "# <<< srouter-managed-codex-function-v1 <<<"
# function codex { … }, не голый codex() — существующий alias может помешать парсингу определения.
# guard `! $+aliases[codex] && ! $+functions[codex]` — не перекрываем молча чужое определение.
# Без exec внутри (заменит интерактивный шелл). Абсолютный путь "$HOME/bin/codex".
_CODEX_FUNC_BLOCK = (
    f"{ZSHRC_CODEX_FUNC_MARKER_BEGIN}\n"
    'if (( ! ${+aliases[codex]} && ! ${+functions[codex]} )); then\n'
    '  function codex {\n'
    '    "$HOME/bin/codex" "$@"\n'
    '  }\n'
    "fi\n"
    f"{ZSHRC_CODEX_FUNC_MARKER_END}"
)


def _codex_wrapper_path(name: str) -> Path:
    """Путь к wrapper в ~/bin (вычисляется динамически — дружелюбно к мокам Path.home в тестах)."""
    return Path.home() / "bin" / name


def _zshrc_path() -> Path:
    """Путь к ~/.zshrc (динамически, для моков Path.home в тестах)."""
    return Path.home() / ".zshrc"


def _codex_bin_path() -> str:
    """Абсолютный путь к реальному codex binary (не наш wrapper). shutil.which минуя ~/bin/codex,
    fallback на homebrew-пути (Apple Silicon / Intel). None если не найден — wrapper будет WARN."""
    wrapper = _codex_wrapper_path("codex")
    found = shutil.which("codex")
    if found and Path(found).resolve() != wrapper.resolve():
        return found
    for cand in (str(Path(BREW).parent / "codex"), "/opt/homebrew/bin/codex", "/usr/local/bin/codex"):
        if Path(cand).exists():
            return cand
    return ""  # не найден — _install_one_wrapper покажет WARN


def _install_one_wrapper(env, wrapper_path: Path, template_name: str, marker: str) -> str:
    """Поставить один wrapper. Marker-gate + marker-migration + atomic write + chmod +x.

    issue #112 Часть 4 (РЕШЕНИЕ 2): при существующем wrapper'е различаем ТРИ случая:
      - current-маркер есть → переустановить (idempotent, обновить рендер).
      - legacy-маркер из known_markers → МИГРИРОВАТЬ (перезаписать с current-маркером). Смена версии
        маркера: старый «свой» распознаётся через state-таблицу, иначе залипал бы на старой версии.
      - unmarked (нет ни current, ни legacy) → WARN, НЕ adopt молча (канон fail-closed, чужое не трогаем).
    """
    try:
        if wrapper_path.exists():
            content = wrapper_path.read_text(encoding="utf-8")
            if marker in content:
                pass  # наш current — переустановим (idempotent).
            else:
                # Marker-migration: проверить legacy-маркеры из known_markers (state-based, #112 ч.4).
                known = load_known_markers(env.state_path, "wrappers", [marker])
                legacy_hits = [m for m in known if m != marker and m in content]
                if not legacy_hits:
                    # Unmarked wrapper — не наш (нет current, нет legacy). WARN, не adopt.
                    return (f"Codex {wrapper_path.name}: существует без srouter-маркера — не трогаем "
                            f"(удали вручную, если это твой старый wrapper).")
                # legacy-маркер найден → мигрируем (продолжаем к рендеру, atomic write обновит файл).
        codex_bin = _codex_bin_path()
        if not codex_bin:
            return f"Codex {wrapper_path.name}: codex binary не найден — wrapper не установлен (установи codex)."
        template = (env.root / "launchagents" / template_name).read_text(encoding="utf-8")
        # Рендер всех плейсхолдеров из единого источника правды (_CODEX_PROXY_URL/CODEX_NO_PROXY),
        # не хардкод литералов. CLI-wrapper (srouter-codex-cli-wrapper.sh) использует все три;
        # App-wrapper (__SROUTER_CODEX_BIN__) — только бинарь (прочие плейсхолдеры там отсутствуют,
        # .replace на отсутствующую подстроку — no-op). Issue #96.
        rendered = (template
                    .replace("__SROUTER_CODEX_BIN__", codex_bin)
                    .replace("__SROUTER_CODEX_PROXY_URL__", _CODEX_PROXY_URL)
                    .replace("__SROUTER_CODEX_NO_PROXY__", CODEX_NO_PROXY))
        wrapper_path.parent.mkdir(parents=True, exist_ok=True)
        if not _write_text_atomic(wrapper_path, rendered):
            return f"Codex {wrapper_path.name}: не записан (ошибка atomic write)."
        wrapper_path.chmod(0o755)
        return f"Codex {wrapper_path.name}: установлен ({wrapper_path} — SOCKS5 минуя privoxy)."
    except Exception as exc:
        return f"Codex {wrapper_path.name}: не установлен ({str(exc)[:80]})."


def _install_codex_wrappers(env) -> str:
    """Поставить ~/bin/codex + ~/bin/codex-app-proxy. Best-effort, цикл по CODEX_WRAPPERS."""
    return "\n".join(_install_one_wrapper(env, _codex_wrapper_path(name), tmpl, marker)
                     for name, tmpl, marker in CODEX_WRAPPERS)


def _remove_one_wrapper(wrapper_path: Path, marker: str) -> str:
    """Удалить один wrapper (если srouter-managed). Marker-gate обязательный."""
    try:
        if not wrapper_path.exists():
            return f"Codex {wrapper_path.name}: не был установлен."
        if marker not in wrapper_path.read_text(encoding="utf-8"):
            return f"Codex {wrapper_path.name}: чужой {wrapper_path} — не трогаем."
        wrapper_path.unlink()
        return f"Codex {wrapper_path.name}: удалён."
    except Exception as exc:
        return f"Codex {wrapper_path.name}: не удалён ({str(exc)[:60]})."


def _remove_codex_wrappers() -> str:
    """Удалить wrappers (если srouter-managed). Цикл по CODEX_WRAPPERS, единый разделитель с install."""
    return "\n".join(_remove_one_wrapper(_codex_wrapper_path(name), marker)
                     for name, _, marker in CODEX_WRAPPERS)


def _install_launchctl_env(env, runner) -> str:
    """Глобальный SOCKS5 env через LaunchAgent (RunAtLoad + launchctl setenv). Переживает ребут.

    launchctl setenv кладёт переменные в GUI-домен launchd → все GUI-приложения их видят. Но setenv
    сам по себе не переживает ребут — LaunchAgent com.srouter.codenv (RunAtLoad + StartInterval=300)
    вызывает скрипт srouter-codex-env.sh, который делает setenv при загрузке и каждые 5мин.
    Эмпирически: Claude.app/ChatGPT.app на System Settings SOCKS, global env их не ломает.

    Через _install_generic_launchagent (как watchdog): marker-gate + atomic write + _launchd_reload
    (bootout→poll→bootstrap-retry, решает гонку занятого домена — PR #80).
    """
    try:
        # Предупредить, если в GUI-домене уже есть ЧУЖОЙ прокси (корпоративный/ручной) — setenv
        # скрипта его перезапишет без восстановления. Не блокируем, но WARN в статусе.
        # getenv gui/<uid> явно (issue #94 DEFECT A аудит setenv): getenv без домена читает caller-context,
        # а setenv-скрипт кладёт в gui — из SSH/cron caller-context другой, WARN пропустил бы чужой gui-прокси.
        warn = ""
        existing = runner([LAUNCHCTL, "getenv", _launchd_domain(), "HTTP_PROXY"], 5)
        val = (existing.get("out") or "").strip()
        if val and "127.0.0.1:10808" not in val:
            warn = f" ВНИМАНИЕ: существующий GUI HTTP_PROXY={val[:40]} будет перезаписан (backup не делается)."
        ok, err = _install_generic_launchagent(
            env, runner,
            template_name="com.srouter.codenv.plist",
            label=CODEX_ENV_LABEL,
            marker=CODEX_ENV_MARKER,
            script_path=env.root / "launchagents" / "srouter-codex-env.sh",
        )
        if ok:
            return (f"Codex env: LaunchAgent {CODEX_ENV_LABEL} загружен (SOCKS5 в GUI-домен, "
                    f"переживает ребут).{warn}")
        if err.endswith("_foreign"):
            return f"Codex env: чужой LaunchAgent {CODEX_ENV_LABEL} — не трогаем."
        return f"Codex env: не установлен ({err})."
    except Exception as exc:
        return f"Codex env: не установлен ({str(exc)[:80]})."


def _remove_launchctl_env(runner) -> dict:
    """Выгрузить LaunchAgent env + снять переменные из GUI-домена + удалить plist.

    Возвращает {ok: bool, note: str}. ok=False пробрасывается в ненулевой rc cmd_uninstall — это
    и есть fail-closed (раньше возвращалась только строка → конкатенировалась в сообщение → fail-open).

    Порядок важен: bootout ПЕРЕД unlink. Если bootout не сработал, а агент всё ещё загружен
    (_launchd_is_loaded), НЕ удаляем plist — иначе StartInterval-агент останется в памяти и будет
    пере-применять мёртвый socks5 env каждые 5 мин (утечка нерабочего прокси в GUI-домен).

    env-cleanup — ВНУТРИ gui-домена явно (issue #94 DEFECT A). `launchctl setenv/unsetenv/getenv`
    оперируют «caller's context» (man launchctl): setenv делает LaunchAgent-скрипт, запущенный launchd
    В gui-домене → переменные в gui. uninstall бежит из процесса cmd_uninstall (caller-context может
    быть user/<uid> из SSH/cron). unsetenv без домена снял бы НЕ в gui → gui-домен остался бы с мёртвым
    127.0.0.1:10808. Поэтому: `unsetenv gui/<uid> <key>` (доменный таргет принимается launchctl),
    затем верификация `getenv gui/<uid> <key>` → пустой вывод = подтверждено снято (строгий
    первоисточник, НЕ rc unsetenv). Любой ключ, оставшийся в gui-домене → ok=False (fail-closed).
    """
    try:
        plist_path = Path.home() / "Library" / "LaunchAgents" / f"{CODEX_ENV_LABEL}.plist"
        if not plist_path.exists():
            return {"ok": True, "note": "Codex env: не был установлен."}
        if CODEX_ENV_MARKER not in plist_path.read_text(encoding="utf-8"):
            return {"ok": True, "note": f"Codex env: чужой LaunchAgent {CODEX_ENV_LABEL} — не трогаем."}
        # bootout + poll реальной выгрузки — единый контракт _launchd_unload (issue #84). bootout
        # асинхронен: без poll _launchd_is_loaded вернёт True в окне → ложный «ещё загружен» → plist
        # оставлен + StartInterval-агент пере-применяет мёртвый env. tristate проходит насквозь.
        loaded = _launchd_unload(_launchd_domain(), CODEX_ENV_LABEL, runner=runner)["state"]
        # None = unknown (launchctl list timeout) — fail-safe: НЕ удаляем plist (оставить контроль).
        # True = агент реально ещё загружен после settle — тоже не удаляем.
        if loaded is not False:
            note = (f"Codex env: LaunchAgent {CODEX_ENV_LABEL} "
                    f"{'не подтверждена выгрузка' if loaded is None else 'всё ещё загружен'} "
                    f"после bootout — plist оставлен (не удалять контроль). "
                    f"Проверь: launchctl list | grep {CODEX_ENV_LABEL}")
            # Агент потенциально жив в gui-домене → env активен. ok=False: cmd_uninstall не должен
            # рапортовать полный успех, пока env-прокси не подтверждённо снят (fail-closed).
            return {"ok": False, "note": note}
        # Снять переменные ИЗ gui-домена явно и верифицировать. setenv делал LaunchAgent-скрипт
        # (caller-context = gui), uninstall бежит в возможно-другом caller-context → ЯВНЫЙ gui-таргет.
        domain = _launchd_domain()
        leftover = []
        unverifiable = []
        for key, _ in CODEX_LAUNCHCTL_ENV:
            runner([LAUNCHCTL, "unsetenv", domain, key], 5)
            # Строгий первоисточник: getenv gui/<uid> <key>. rc unsetenv игнорируем (loose-валидатор:
            # «отработал» ≠ «снял»). Пустой вывод getenv = переменной нет в gui-домене = подтверждено.
            g = runner([LAUNCHCTL, "getenv", domain, key], 5)
            # fail-closed верификации (канон): сам сбой getenv → переменная НЕверифицируема. Пустой out
            # при timeout/OSError (rc=None) НЕ считать «снято» — иначе fail-open (переменная могла
            # остаться, но верификация не смогла спросить). Только достоверный rc=0 + пустой out = снято.
            if g.get("timeout") or g.get("rc") is None:
                unverifiable.append(key)
            elif (g.get("out") or "").strip():
                leftover.append(key)
        if leftover:
            # Переменная осталась ЖИВОЙ в gui-домене → мёртвый 127.0.0.1:10808 утечёт в GUI-приложения.
            # НЕ удаляем plist (контроль), ok=False → cmd_uninstall вернёт ненулевой rc (fail-closed).
            return {"ok": False,
                    "note": (f"Codex env: НЕ снят — переменные остались в gui-домене ({', '.join(leftover)}). "
                             f"Проверь: launchctl getenv gui/<uid> {leftover[0]} | "
                             f"launchctl unsetenv gui/<uid> {leftover[0]}. Plist оставлен.")}
        if unverifiable:
            # getenv не смог спросить gui-домен (timeout / launchctl-OSError) → состояние НЕверифицируемо.
            # fail-closed (канон): НЕ рапортуем «снято», ok=False — оператор должен проверить вручную.
            # Plist оставлен как контроль. Отличие от leftover: переменные МОГУТ быть сняты, но мы не знаем.
            return {"ok": False,
                    "note": (f"Codex env: НЕ подтверждено снятие — getenv gui-домена не ответил "
                             f"({', '.join(unverifiable)}). Проверь: launchctl getenv gui/<uid> {unverifiable[0]}. "
                             f"Plist оставлен.")}
        plist_path.unlink()
        return {"ok": True,
                "note": f"Codex env: снят (LaunchAgent {CODEX_ENV_LABEL} выгружен, env очищен, plist удалён)."}
    except Exception as exc:
        return {"ok": False, "note": f"Codex env: не снят ({str(exc)[:80]})."}


def _ensure_home_bin_in_path(env) -> str:
    """Добавить ~/bin в PATH через ~/.zshrc (marker-gate + backup через install_lib._backup + atomic write).

    CLI wrapper требует ~/bin раньше системного codex в PATH.
    """
    try:
        from install_lib import _backup
        zshrc = _zshrc_path()
        block = f'\n{ZSHRC_PATH_MARKER}\nexport PATH="$HOME/bin:$PATH"\n'
        if not zshrc.exists():
            # Тот же порядок, что и append (marker → export), чтобы _remove_home_bin_from_path
            # (удаляет marker + следующую строку) корректно убирал блок. Не export→marker (иначе
            # uninstall оставит висячий export).
            _write_text_atomic(zshrc, f'{ZSHRC_PATH_MARKER}\nexport PATH="$HOME/bin:$PATH"\n')
            return "PATH: создан ~/.zshrc с ~/bin (новый терминал подхватит codex wrapper)."
        content = zshrc.read_text(encoding="utf-8")
        if ZSHRC_PATH_MARKER in content or '$HOME/bin' in content or "${HOME}/bin" in content:
            return "PATH: ~/bin уже в ~/.zshrc (idempotent)."
        _backup(zshrc, env)  # timestamped backup через каноничный helper
        _write_text_atomic(zshrc, content + block)
        return "PATH: ~/bin добавлен в ~/.zshrc (backup: .zshrc.srouter-backup-*)."
    except Exception as exc:
        return f"PATH: не изменён ({str(exc)[:80]})."


def _remove_home_bin_from_path() -> str:
    """Убрать srouter-блок ~/bin из ~/.zshrc (симметрично _ensure_home_bin_in_path). Marker-gate.

    Удаляет ТОЛЬКО наш управляемый блок: маркер + следующую за ним строку export. Чужой
    `export PATH="$HOME/bin:$PATH"` в другом месте файла — НЕ трогаем (правило «чужое не трогать»).
    """
    try:
        zshrc = _zshrc_path()
        if not zshrc.exists():
            return "PATH: не был изменён."
        lines = zshrc.read_text(encoding="utf-8").splitlines()
        if ZSHRC_PATH_MARKER not in lines:
            return "PATH: не был изменён."
        # Найти индекс маркера, удалить его + следующую строку (наш export PATH).
        out = []
        i = 0
        while i < len(lines):
            if lines[i] == ZSHRC_PATH_MARKER:
                # Пропустить маркер и следующую строку (управляемый блок). Если следующая не наш
                # export — всё равно пропускаем (мы её сами добавили после маркера при install).
                i += 2
                continue
            out.append(lines[i])
            i += 1
        _write_text_atomic(zshrc, "\n".join(out).rstrip() + "\n")
        return "PATH: ~/bin убран из ~/.zshrc."
    except Exception as exc:
        return f"PATH: не убран ({str(exc)[:80]})."


def _install_codex_zsh_function(env) -> str:
    """Добавить shell-функцию codex() в ~/.zshrc (issue #96).

    Функция вызывает ~/bin/codex по АБСОЛЮТНОМУ пути — порядок brew в PATH не важен (функция всегда
    бьёт binary). Без неё wrapper #83 проигрывает /opt/homebrew/bin/codex → Codex идёт через privoxy
    (наследует HTTP_PROXY от ~/.claude/settings.json env) → режёт WS → "Falling back to HTTPS".

    Marker-gate (парные begin/end) + backup через install_lib._backup + atomic write — тот же
    канон, что _ensure_home_bin_in_path. Fail-closed: чужой alias codex/function codex без нашего
    маркера → НЕ добавляем блок (не перекрываем молча).
    """
    try:
        from install_lib import _backup
        zshrc = _zshrc_path()
        content = zshrc.read_text(encoding="utf-8") if zshrc.exists() else ""
        # Idempotent: блок уже на месте.
        if ZSHRC_CODEX_FUNC_MARKER_BEGIN in content:
            return "Codex функция: уже в ~/.zshrc (idempotent)."
        # Fail-closed: чужое определение codex (alias или function) без нашего маркера — не трогаем.
        # `alias codex=` или `codex()` или `function codex`/`codex ()`. Ищем как определение,
        # не как упоминание в комментарии (требуем синтаксис присваивания/определения).
        has_foreign = bool(re.search(r'(^|\n)\s*(alias\s+codex\s*=|function\s+codex\b|codex\s*\(\s*\)\s*\{)',
                                    content))
        if has_foreign:
            return ("Codex функция: обнаружен чужой alias/function codex в ~/.zshrc — "
                    "не добавляю (конфликт). ~/bin/codex доступен как явная точка входа.")
        if not zshrc.exists():
            _write_text_atomic(zshrc, _CODEX_FUNC_BLOCK + "\n")
            return ("Codex функция: создан ~/.zshrc с codex() → ~/bin/codex (новый терминал подхватит). "
                    "ВНИМАНИЕ: существующие терминалы/codex-процессы не получат новое окружение — "
                    "перезапусти их (exec zsh -l в каждом, затем закрыть/открыть TUI).")
        _backup(zshrc, env)  # timestamped backup, каноничный helper
        _write_text_atomic(zshrc, content.rstrip() + "\n\n" + _CODEX_FUNC_BLOCK + "\n")
        return ("Codex функция: добавлена в ~/.zshrc (codex → ~/bin/codex по абс. пути, "
                "бьёт brew в PATH). Backup: .zshrc.srouter-backup-*. "
                "ВНИМАНИЕ: существующие терминалы/codex-процессы не получат новое окружение — "
                "перезапусти их (exec zsh -l, затем закрыть/открыть TUI); иначе старая TUI пойдёт "
                "через privoxy 8118 и порвёт long-lived WS (#120).")
    except Exception as exc:
        return f"Codex функция: не добавлена ({str(exc)[:80]})."


def _remove_codex_zsh_function() -> str:
    """Убрать managed-блок codex() из ~/.zshrc (симметрично _install_codex_zsh_function).

    Удаляет ТОЛЬКО парный begin…end блок (включая function-определение внутри). Чужой контент
    (export PATH, комментарии, чужой alias/function codex — если появился позже) НЕ трогаем.
    Если маркеры непарные (повреждённое состояние) — fail-closed: отказ, не широкое удаление.
    """
    try:
        zshrc = _zshrc_path()
        if not zshrc.exists():
            return "Codex функция: не была изменена."
        content = zshrc.read_text(encoding="utf-8")
        if ZSHRC_CODEX_FUNC_MARKER_BEGIN not in content and ZSHRC_CODEX_FUNC_MARKER_END not in content:
            return "Codex функция: не была изменена."
        # Fail-closed: ровно один парный блок. Непарный/дублированный → отказ (safe-noop).
        # Достаточно begins==1 and ends==1 (это уже влечёт их равенство) — без третьего условия.
        begins = content.count(ZSHRC_CODEX_FUNC_MARKER_BEGIN)
        ends = content.count(ZSHRC_CODEX_FUNC_MARKER_END)
        if begins != 1 or ends != 1:
            return ("Codex функция: не удалена — повреждённый маркер "
                    f"(begin={begins}, end={ends}), проверь ~/.zshrc вручную.")
        start = content.index(ZSHRC_CODEX_FUNC_MARKER_BEGIN)
        end = content.index(ZSHRC_CODEX_FUNC_MARKER_END) + len(ZSHRC_CODEX_FUNC_MARKER_END)
        # Зачистить окружающие пустые строки (мы добавляли \n\n перед блоком при install).
        before = content[:start].rstrip("\n")
        out = before + ("\n" if before else "") + content[end:]
        _write_text_atomic(zshrc, out.rstrip() + "\n")
        return "Codex функция: убрана из ~/.zshrc."
    except Exception as exc:
        return f"Codex функция: не убрана ({str(exc)[:80]})."


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
        env_note = _install_launchctl_env(env, runner)
        path_note = _ensure_home_bin_in_path(env)
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
        except Exception:
            pass
        print("Установка стека завершена: brew-сервисы, конфиги, DNS, LaunchAgent применены.\n"
              f"{cp_note}\n"
              f"{wd_note}\n"
              f"{ppp_note}\n"
              f"{codex_note}\n"
              f"{codex_func_note}\n"
              f"{env_note}\n"
              f"{path_note}\n"
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

    # 6) Удалить ppp-hook (/etc/ppp/ip-up) — мгновенный split-route больше не нужен.
    ppp_note = ". " + _remove_ppp_hook(runner)
    # 7) Удалить Codex SOCKS5-wrappers + shell-функцию codex() + снять launchctl env + убрать ~/bin
    #    из PATH (всё ставил install). marker-gate: чужое не трогаем.
    codex_note = ". " + _remove_codex_wrappers()
    codex_func_note = ". " + _remove_codex_zsh_function()
    env_status = _remove_launchctl_env(runner)
    env_note = ". " + env_status["note"]
    path_note = ". " + _remove_home_bin_from_path()

    # env-cleanup fail-closed (issue #94 DEFECT A): мёртвый прокси остался в gui-домене → НЕ успех,
    # даже если всё остальное прошло. Раньше env_note просто конкатенировался в сообщение → fail-open
    # (rc=0 при живом socks5://127.0.0.1:10808 в GUI). ok=False пробрасываем в ненулевой rc.
    # Шапка сообщения зависит от итога: «Откат завершён» только при подтверждённо снятом env И без
    # leftover (issue #110 Дефект 1), иначе «Откат выполнен частично» — без противоречия rc=2.
    full_ok = env_status["ok"] and not partial_configs
    headline = "Откат завершён" if full_ok else "Откат выполнен частично"
    print(f"{headline}: brew-сервисы остановлены, конфиги восстановлены/оставлены, "
          "DNS сброшен, LaunchAgent удалён"
          + (". split-route удалён." if route_rc == 0 else ", split-route не удалён — см. выше.")
          + cp_note
          + ppp_note
          + codex_note
          + codex_func_note
          + env_note
          + path_note)
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
    except Exception:
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
    except Exception:
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
        p.set_defaults(func=fn)

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
