"""launchd/LaunchAgent управление для srouter.

Вынесено из srouter.py для issue #228 (refactor эпик #158).

Содержит функции:
- PPP hook (/etc/ppp/ip-up) для мгновенного split-route при VPN up
- launchctl env управление
- PATH helpers для ~/bin
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import local_state
from install_lib import InstallEnv
from sys_probe import run

try:
    from dashboard_common import _applescript_text
except BaseException:
    # dashboard_common может быть недоступен в тестах
    def _applescript_text(cmd):
        return cmd

try:
    import privileged_ops
    OSASCRIPT = privileged_ops.OSASCRIPT
except BaseException:
    # fallback для тестов
    OSASCRIPT = "/usr/bin/osascript"

PPP_HOOK_PATH = "/etc/ppp/ip-up"
PPP_HOOK_MARKER = "# srouter: мгновенная реакция"


def _is_ip_literal(value) -> bool:
    """Строгая проверка IP-литерала. Канон dashboard_common._ip_literal, но без импорта
    dashboard_common (он тянет srouter_config через module-level код)."""
    import ipaddress
    if not isinstance(value, str) or not value or "%" in value:
        return False
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return False
    return str(parsed) == value


def _active_route_ip_for_removal(state_path) -> str:
    """route_ip активного узла для route delete. '' если нет валидного IP/узла."""
    try:
        node = local_state.active_node(path=state_path) or {}
        route_ip = local_state.resolve_route_ip(node, path=state_path)
    except (OSError, ValueError, TypeError, KeyError):
        # local_state operations over JSON/files/dicts
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
    result = runner(["route", "-n", "delete", "-host", route_ip], 60)
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
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError, ValueError) as exc:
        # file reads and subprocess runner failures
        return f"PPP-hook: не установлен ({str(exc)[:80]})."


def _remove_ppp_hook(runner) -> str:
    """Удалить /etc/ppp/ip-up (если srouter-managed). Возвращает строку-статус."""
    try:
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
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError, ValueError) as exc:
        # subprocess runner and file operations
        return f"PPP-hook: не удалён ({str(exc)[:60]})."
