"""Privileged-слой CLI srouter: InstallEnv из флагов + runner с автодетектом привилегий (#259).

Зачем отдельный модуль (issue #259, вариант 1). `cmd_*` (srouter_cli.py) зовут `_env_from_args`
и `make_privileged_runner`, а `srouter.py` обязан переэкспортировать оба ради обратной
совместимости. Оставь их в `srouter.py` — получишь `srouter` → `srouter_cli` → `srouter`,
ровно тот цикл, который в закрытом PR #232 лечили двусторонней делегацией через
`srouter.__dict__` (антипаттерн). Оставь их в `srouter_cli` — `srouter` переэкспортирует, но
тогда владелец имён — CLI, а `_is_privileged_cmd`/`_to_osascript` к CLI отношения не имеют:
это тонкие обёртки над `privileged_ops`, им место рядом с ним.

Отсюда третий модуль, от которого зависят ОБЕ стороны:

    privileged_ops ← srouter_privileged ← srouter_cli ← srouter

Цикла нет, двусторонней делегации нет, у каждого имени ровно один владелец.

Экстракция, не редизайн: тела перенесены из srouter.py без изменения поведения.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import privileged_ops  # единая osascript/sudo-обёртка + whitelist (#156)
from install_lib import InstallEnv
from sys_probe import run

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
