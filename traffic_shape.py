"""Traffic Guard throttle: per-domain замедление через root-only macOS shaping.

Модуль строит правила pf (`pfctl` anchor) + dummynet pipe (`dnctl`) и выполняет
их привилегированно через тот же osascript admin-мост, что и dashboard.sudo_route:
`do shell script "<из констант+validated>" with administrator privileges`, запуск
через `sys_probe.run([OSASCRIPT, "-e", applescript], timeout=)`.

Границы безопасности (privileged root pf — строго!):
- shell-текст собирается ТОЛЬКО из констант (абсолютные пути бинарей + флаги) и
  из ВАЛИДИРОВАННЫХ значений: canonical IP-литерал (round-trip через ipaddress,
  reject scoped `%`), целочисленный rate, whitelist-имя anchor. Ни domain, ни
  сырой пользовательский ввод в shell не попадают никогда.
- Функции НЕ бросают: при любом сбое возвращают структурированный dict.
  Отмена пароля osascript (rc -128) -> cancelled, не ошибка.

Scope: только shaping-логика (функции). Flask-роут `/api/guard/throttle` и UI —
отдельно, после safety-review (issue #13).
"""
import ipaddress
import socket

import local_state
import sys_probe


# ============================ константы (shell-safe) ============================
# Абсолютные пути: launchd/GUI PATH их не содержит (тот же мотив, что в dashboard_common).
PFCTL = "/sbin/pfctl"
DNCTL = "/usr/sbin/dnctl"
OSASCRIPT = "/usr/bin/osascript"

# Whitelist-имя anchor и номер pipe — константы, НЕ пользовательский ввод.
ANCHOR = "srouter_throttle"
PIPE_NUM = 1

# Таймаут osascript-моста: как у sudo_route (пароль + выполнение pf).
_TIMEOUT_SEC = 60


# ============================ валидация входов ============================
def _ip_literal(value):
    """True только для canonical IP-литерала (как dashboard_common._ip_literal).

    Privileged pf-команды интерполируют IP в shell-текст, поэтому принимаем лишь
    canonical написание: scoped IPv6 zone-id (`%en0`) и альтернативные написания
    не должны проскочить границу через ipaddress.ip_address().
    """
    if not isinstance(value, str) or not value:
        return False
    if "%" in value:
        return False
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return False
    return str(parsed) == value


def _valid_rate(rate):
    """Нормализовать rate в '<N>Kbit/s' или вернуть None.

    Принимаем только положительное ЦЕЛОЕ (int или строка из одних цифр). Любой
    нечисловой ввод (спецсимволы, юниты, дробь, bool) -> None: rate попадает в
    shell-текст, поэтому «на всякий случай» строку не пропускаем.
    """
    if isinstance(rate, bool):
        return None
    if isinstance(rate, int):
        n = rate
    elif isinstance(rate, str) and rate.isdigit():
        n = int(rate)
    else:
        return None
    if n <= 0:
        return None
    return f"{n}Kbit/s"


def resolve_domain_ip(domain):
    """domain -> canonical IP-литерал ('' при любом сбое/невалидности).

    Сначала режем shell-небезопасный domain через local_state._is_valid_host (до
    сетевого вызова), затем резолвим и повторно валидируем результат резолвера
    через _ip_literal — резолвер тоже не доверенный источник shell-текста.
    """
    if not local_state._is_valid_host(domain):
        return ""
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return ""
    return ip if _ip_literal(ip) else ""


# ============================ результат privileged-вызова ============================
def _shape_result(r):
    """Свести dict от sys_probe.run к стабильной форме (как dashboard._route_result).

    rc -128 (или '-128' в stderr) — отмена ввода пароля osascript -> cancelled.
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


def _reject(msg):
    """Единый reject без запуска команды: форма как у _shape_result, но run не зван."""
    return {"ok": False, "cancelled": False, "rc": None, "out": "", "err": msg, "timeout": False}


def _admin_run(shell_cmd):
    """Выполнить shell_cmd привилегированно через osascript admin-мост.

    ВАЖНО: shell_cmd обязан быть собран ТОЛЬКО из констант и validated значений
    (см. модульную docstring). Динамический/пользовательский фрагмент здесь —
    ошибка, требующая whitelist + экранирования.
    """
    applescript = f'do shell script "{shell_cmd}" with administrator privileges'
    return _shape_result(sys_probe.run([OSASCRIPT, "-e", applescript], timeout=_TIMEOUT_SEC))


# ============================ публичный API ============================
def apply_throttle(domain, rate):
    """Включить throttle для domain на скорости rate (Kbit/s).

    Резолвит domain->IP, валидирует rate, затем настраивает dummynet pipe (dnctl)
    и загружает pf anchor-правило (pfctl), направляющее трафик к IP в pipe.
    Функция не бросает: любой невалидный вход -> reject без запуска pf.
    """
    ip = resolve_domain_ip(domain)
    if not ip:
        return _reject("не удалось получить canonical IP для домена")
    rate_spec = _valid_rate(rate)
    if not rate_spec:
        return _reject("rate должен быть положительным целым числом (Kbit/s)")

    # Всё ниже — из констант + validated (ip canonical, rate_spec числовой, ANCHOR/PIPE_NUM константы).
    # Правило dummynet заворачивает трафик к целевому IP в pipe с ограниченной полосой.
    pipe_cfg = f"{DNCTL} pipe {PIPE_NUM} config bw {rate_spec}"
    pf_rule = (
        f"dummynet out proto tcp from any to {ip} pipe {PIPE_NUM}\\n"
        f"dummynet in proto tcp from {ip} to any pipe {PIPE_NUM}"
    )
    # Включаем dummynet (`pfctl -E` тихо, если уже включён) и грузим правило в наш anchor.
    load_anchor = f"echo '{pf_rule}' | {PFCTL} -a {ANCHOR} -f -"
    shell_cmd = f"{pipe_cfg}; {PFCTL} -E; {load_anchor}"
    try:
        return _admin_run(shell_cmd)
    except Exception as exc:  # глубокая защита: функция не бросает
        return _reject(f"throttle failed: {exc}")


def clear_throttle():
    """Снять throttle: очистить pf anchor и удалить dummynet pipe.

    Идемпотентно и безопасно к повторному вызову. Всё — из констант.
    """
    flush_anchor = f"{PFCTL} -a {ANCHOR} -F all"
    drop_pipe = f"{DNCTL} pipe {PIPE_NUM} delete"
    shell_cmd = f"{flush_anchor}; {drop_pipe}"
    try:
        return _admin_run(shell_cmd)
    except Exception as exc:  # глубокая защита: функция не бросает
        return _reject(f"clear failed: {exc}")
