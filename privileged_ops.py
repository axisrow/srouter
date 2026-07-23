r"""Единая osascript/sudo-обёртка для привилегированных операций (issue #156, эпик #107 задача P0-3).

ДО этого модуля osascript admin-мост (`do shell script "..." with administrator privileges`)
был размазан по кодовой базе: srouter.py (install_lib runner), dashboard.py (_sudo_route_ip),
traffic_shape.py, isolate_firewall.py. Это значит — НЕТ одной точки для валидации разрешённых
команд, и любой новый osascript-вызов легко написать без оглядки на безопасность.

Единый контракт этого модуля:

  - `is_allowed(cmd)` — строгий whitelist разрешённых привилегированных сигнатур.
    Никакого «почти-regex»: точное совпадение head + flag по абсолютным путям из install_lib.
    Чужая/неизвестная команда → False (fail-closed граница, эталон privileged-boundary-fail-closed).

  - `build_osascript(cmd)` — обернуть cmd в osascript-мост. SUDO избыточен под osascript
    (он сам повышает привилегии, канон dashboard.py) и удаляется. shell-команда экранируется
    КАНОНИЧЕСКОЙ dashboard_common._applescript_text (#154) — единый канон экранирования,
    НЕ локальная копия.

  - `run_privileged(cmd, *, timeout, run=sys_probe.run)` — fail-closed: неизвестная команда
    НЕ доходит до osascript (возвращает структурированный fail-результат). Под root
    (os.geteuid()==0) команда идёт напрямую, без osascript-моста. Результат нормализован
    через _normalize_result (rc -128 → cancelled, канон dashboard._route_result).

Эталоны: sys_probe #35 (no-hidden-magic — единый непадающий runner), privileged-boundary-fail-closed
(строгий whitelist), always-tdd (тесты в tests/test_privileged_ops.py).

Это ЭКСТРАКЦИЯ, не редизайн: поведение существующих обёрток сохраняется, они делегируют сюда.
"""

import logging
import os
import shlex

import sys_probe
from dashboard_common import _applescript_text
from install_lib import BREW, NETWORKSETUP, ROUTE, SUDO

# OSASCRIPT — абсолютный путь к macOS-бинарю osascript (GUI admin-мост).
# Системная константа; дублируется из srouter.py/dashboard.py при миграции (см. #162
# про централизацию SROUTER-портов — абсолютные системные пути намеренно НЕ в dashboard_common).
OSASCRIPT = "/usr/bin/osascript"

# Таймаут osascript-моста по умолчанию: GUI-ввод пароля + выполнение команды (как у
# switch_channel/sudo_route/install_lib runner). Перекрыть через timeout= в run_privileged.
DEFAULT_OSCRIPT_TIMEOUT = 60

logger = logging.getLogger("privileged_ops")

# Канонический непадающий runner (no-hidden-magic): sys_probe.run всегда возвращает dict, не бросает.
_DEFAULT_RUN = sys_probe.run


def is_allowed(cmd) -> bool:
    """Строгий whitelist: True ТОЛЬКО для разрешённых привилегированных сигнатур.

    Сигнатуры — мутации, требующие root на пользовательской машине (install_lib runner):
      - networksetup -setdnssensors (мутация DNS; НЕ -listallnetworkservices — чтение)
      - sudo brew services ... dnsmasq (UDP:53; xray/privoxy — user-services, НЕ sudo)
      - route -n delete (удаление split-route; route get — чтение)

    Никакого regex/префикс-матча: точное совпадение head + flag по абсолютным путям.
    Чужая/неизвестная/пустая команда → False (fail-closed).
    """
    if not cmd:
        return False
    head = cmd[0]
    # networksetup -setdnssensors — мутация DNS.
    if head == NETWORKSETUP and len(cmd) > 1 and cmd[1] == "-setdnsservers":
        return True
    # sudo brew ... dnsmasq — dnsmasq на UDP:53.
    if head == SUDO and len(cmd) > 1 and cmd[1] == BREW:
        return True
    # route -n delete — удаление split-route.
    if head == ROUTE and len(cmd) > 2 and cmd[1] == "-n" and cmd[2] == "delete":
        return True
    return False


def build_osascript(cmd):
    """Обернуть cmd в osascript-мост 'do shell script ... with administrator privileges'.

    SUDO удаляется из cmd — osascript сам повышает привилегии (канон dashboard.py:122-134).
    Без этого получилось бы sudo внутри уже-privileges-сессии (избыточно, потенциально ломается).

    Аргументы экранируются КАНОНИЧЕСКОЙ dashboard_common._applescript_text (#154):
    сначала бэкслэши, потом кавычки (порядок security-критичен), затем вставляются в
    applescript-строку. shlex.quote даёт безопасную shell-команду, _applescript_text —
    безопасное вложение её в applescript-литерал. Двойная защита против arbitrary cmd exec.
    """
    cleaned = list(cmd[1:] if cmd and cmd[0] == SUDO else cmd)
    shell_cmd = " ".join(shlex.quote(str(a)) for a in cleaned)
    applescript = f'do shell script "{_applescript_text(shell_cmd)}" with administrator privileges'
    return [OSASCRIPT, "-e", applescript]


def _normalize_result(r):
    """Нормализовать результат underlying-run в dashboard-style dict.

    Канон dashboard._route_result: rc -128 (отмена GUI-пароля) → cancelled=True,
    НЕ ok и НЕ timeout. timeout=True только при реальном истечении срока.
    """
    r = r or {}
    rc = r.get("rc")
    err = r.get("err") or ""
    timeout = bool(r.get("timeout"))
    cancelled = rc == -128 or (rc not in (0, None) and "-128" in err)
    return {
        "ok": rc == 0 and not timeout,
        "cancelled": cancelled,
        "rc": rc,
        "out": r.get("out") or "",
        "err": err,
        "timeout": timeout,
    }


def run_privileged(cmd, *, timeout=DEFAULT_OSCRIPT_TIMEOUT, run=_DEFAULT_RUN):
    """Выполнить cmd привилегированно: под root — напрямую, иначе — osascript admin-мост.

    fail-closed: если cmd НЕ в whitelist (is_allowed=False) И мы НЕ root — команда НЕ
    выполняется вообще, возвращается структурированный fail-результат (rc != 0, ok=False).
    Лучше ничего не выполнить, чем выполнить неизвестную/чужую команду с GUI-правами.

    Под root (os.geteuid()==0) все разрешённые команды идут напрямую — osascript-мост
    избыточен (уже привилегии) и не нужен (как make_privileged_runner в srouter.py).

    `run` по умолчанию — канон sys_probe.run (всегда dict, не бросает, no-hidden-magic).
    Каждый привилегированный/osascript-вызов логируется (audit trail, DEBUG).
    """
    am_root = os.geteuid() == 0

    if not am_root and not is_allowed(cmd):
        # fail-closed граница: неизвестная команда не доходит до underlying run.
        logger.warning("privileged_ops: reject non-whitelisted cmd head=%r", cmd[0] if cmd else None)
        return {
            "ok": False,
            "cancelled": False,
            "rc": 126,  # 126 = "command invoked cannot execute" — явный fail, не таймаут.
            "out": "",
            "err": f"privileged_ops: команда не в whitelist: {cmd[0] if cmd else '<empty>'}",
            "timeout": False,
        }

    if am_root:
        # Уже root: osascript-мост избыточен, идём напрямую.
        logger.debug("privileged_ops: root-direct cmd=%s", cmd)
        return _normalize_result(run(cmd, timeout))

    # Пользователь: оборачиваем разрешённую команду в osascript admin-мост.
    wrapped = build_osascript(cmd)
    logger.debug("privileged_ops: osascript-bridge for cmd=%s", cmd)
    return _normalize_result(run(wrapped, timeout))
