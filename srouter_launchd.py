"""launchd/PPP-hook и split-route helpers (вынесено из srouter.py, #228).

Экстракция без редизайна: тела функций перенесены байт-в-байт, публичные имена
и семантика сохранены. srouter.py переэкспортирует всё отсюда для обратной
совместимости с тестами и потребителями.
"""

from __future__ import annotations

import ipaddress
import os
import shlex
import tempfile
import subprocess
import sys
from pathlib import Path

import local_state
import install_restore
import privileged_ops
from install_lib import ROUTE

# OSASCRIPT — единый источник privileged_ops (#156), как и в srouter.py.
OSASCRIPT = privileged_ops.OSASCRIPT


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


def _active_route_ip_for_removal(state_path) -> str:
    """route_ip активного узла для route delete. '' если нет валидного IP/узла."""
    try:
        node = local_state.active_node(path=state_path) or {}
        route_ip = local_state.resolve_route_ip(node, path=state_path)
    except (OSError, ValueError, TypeError, KeyError):
        # local_state операции с JSON/файлами/словарями → типичные ошибки
        return ""
    return route_ip if _is_ip_literal(route_ip) else ""


def _route_error(message):
    return {"rc": 1, "out": "", "err": message, "timeout": False}


def _host_route(route_ip, runner):
    result = runner([ROUTE, "-n", "get", "-host", route_ip], 5)
    if result.get("timeout") or result.get("rc") != 0:
        message = (result.get("err") or "").lower()
        if not result.get("timeout") and any(text in message for text in ("not in table", "no such process", "not in routing table")):
            return None, ""
        return None, "route_read_failed"
    fields = dict(line.strip().split(":", 1) for line in (result.get("out") or "").splitlines() if ":" in line)
    fields = {key: value.strip() for key, value in fields.items()}
    flags = fields.get("flags", "").strip("<>").split(",")
    if "HOST" not in flags or fields.get("destination") != route_ip:
        return None, ""
    return {"gateway": fields.get("gateway", "")}, ""


def tracked_route_action(action, route_ip, gateway, mutate, *, runner, state_path=None):
    """Record an exact route's ownership before its first mutation on new installations."""
    state, readable = local_state.load_state_checked(path=state_path)
    if not readable:
        return _route_error("state_unreadable")
    runtime = state.get("runtime") or {}
    if "split_routes" not in runtime:
        return mutate()  # Legacy installs have no trustworthy original route history.
    routes = runtime["split_routes"]
    if not isinstance(routes, dict) or not _is_ip_literal(route_ip):
        return _route_error("route_history_invalid")
    if action == "add" and route_ip not in routes:
        original, error = _host_route(route_ip, runner)
        if error:
            return _route_error(error)
        routes[route_ip] = {"preexisting": original is not None, "gateway": gateway, "owned": False}
        if local_state.save_state(state, path=state_path) is None:
            return _route_error("route_original_write_failed")
    result = mutate()
    if result.get("timeout") or result.get("rc") != 0:
        return result
    if action == "add":
        current, error = _host_route(route_ip, runner)
        if error or not current or current.get("gateway") != gateway:
            return _route_error("route_apply_unverified")
        if not routes[route_ip]["preexisting"]:
            routes[route_ip]["owned"] = True
    elif action == "remove":
        routes.pop(route_ip, None)
    if local_state.save_state(state, path=state_path) is None:
        return _route_error("route_result_write_failed")
    return result


def route_owned_for_switch(route_ip, state_path=None):
    state = local_state.load_state(path=state_path)
    runtime = state.get("runtime") or {}
    if "split_routes" not in runtime:
        return True  # Keep the existing legacy manual-switch contract.
    return (runtime["split_routes"].get(route_ip) or {}).get("owned") is True


def _remove_active_split_route(state_path, runner) -> int:
    state, readable = local_state.load_state_checked(path=state_path)
    if not readable:
        print("split-route: state нечитаем.", file=sys.stderr)
        return 2
    runtime = state.get("runtime") or {}
    routes = runtime.get("split_routes")
    if routes is None:
        route_ip = _active_route_ip_for_removal(state_path)
        if not route_ip:
            return 0
        current, error = _host_route(route_ip, runner)
        if error or current:
            print("split-route: происхождение маршрута неизвестно; сохранён для ручного разбора.", file=sys.stderr)
            return 2
        return 0
    if not isinstance(routes, dict):
        return 2
    for route_ip, lease in list(routes.items()):
        if not _is_ip_literal(route_ip) or not isinstance(lease, dict):
            return 2
        if lease.get("preexisting") is not True:
            current, error = _host_route(route_ip, runner)
            if error:
                return 2
            if current:
                if lease.get("owned") is not True or current.get("gateway") != lease.get("gateway"):
                    print("split-route: поздняя чужая правка или незавершённая установка; маршрут сохранён.", file=sys.stderr)
                    return 2
                result = runner([ROUTE, "-n", "delete", "-host", route_ip], 60)
                if result.get("timeout") or result.get("rc") != 0:
                    return 2
                current, error = _host_route(route_ip, runner)
                if error or current:
                    return 2
        routes.pop(route_ip)
        if local_state.save_state(state, path=state_path) is None:
            return 2
    if runtime.get("split_routes_legacy"):
        route_ip = _active_route_ip_for_removal(state_path)
        if route_ip:
            current, error = _host_route(route_ip, runner)
            if error or current:
                print("split-route: legacy-маршрут не имеет истории; сохранён.", file=sys.stderr)
                return 2
    return 0


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
        install_restore.capture_install_files(env, [Path(PPP_HOOK_PATH)])
        # Копирование в /etc/ppp/ip-up через osascript (требует admin, /etc/ = root).
        from dashboard_common import _applescript_text
        # Записать во временный файл, потом cp + chmod + chown (всё под osascript admin).
        stage = f"/etc/ppp/.srouter-ip-up-{os.getpid()}"
        with tempfile.TemporaryDirectory(prefix="srouter-ppp-install-") as directory:
            source = Path(directory) / "ip-up"
            source.write_text(rendered, encoding="utf-8")
            full_cmd = (f"/bin/mkdir -p /etc/ppp && "
                        f"/usr/bin/install -m 755 -o root -g wheel {shlex.quote(str(source))} {stage} && "
                        f"/bin/mv -fh {stage} {PPP_HOOK_PATH}")
            applescript = f'do shell script "{_applescript_text(full_cmd)}" with administrator privileges'
            r = runner([OSASCRIPT, "-e", applescript], 30)
        if r.get("rc") == -128 or "-128" in (r.get("err") or ""):
            return "PPP-hook: отменено (диалог пароля)."
        if r.get("timeout") or r.get("rc") != 0:
            return f"PPP-hook: не установлен ({(r.get('err') or 'ошибка')[:80]})."
        install_restore.record_install_files(env, [Path(PPP_HOOK_PATH)])
        return "PPP-hook: установлен (/etc/ppp/ip-up — мгновенный split-route при VPN up)."
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError, ValueError) as exc:
        # read_text() → OSError; runner() → subprocess исключения; операции со строками → ValueError
        return f"PPP-hook: не установлен ({str(exc)[:80]})."


def _remove_ppp_hook(runner, env=None) -> str:
    """Удалить /etc/ppp/ip-up (если srouter-managed). Возвращает строку-статус."""
    try:
        if env is not None:
            result = install_restore.restore_install_files(env, [Path(PPP_HOOK_PATH)], runner=runner)
            if not result["ok"]:
                return "PPP-hook: не восстановлен (" + "; ".join(result["errors"]) + ")."
            if result["handled"]:
                install_restore.finish_file_restore(env, result["handled"])
                return "PPP-hook: исходный скрипт восстановлен."
        from dashboard_common import _applescript_text
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
        return "PPP-hook: удалён." if not r.get("timeout") and r.get("rc") == 0 else f"PPP-hook: не удалён ({(r.get('err') or '')[:60]})."
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError, ValueError) as exc:
        # runner() → subprocess исключения; osascript/файловые операции → OSError
        return f"PPP-hook: не удалён ({str(exc)[:60]})."
