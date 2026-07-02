"""Traffic Guard throttle: per-domain замедление через root-only macOS shaping.

Модуль строит правила pf (`pfctl` anchor) + dummynet pipe (`dnctl`) и выполняет
их привилегированно через тот же osascript admin-мост, что и dashboard.sudo_route:
`do shell script "<из констант+validated>" with administrator privileges`, запуск
через `sys_probe.run([OSASCRIPT, "-e", applescript], timeout=)`.

Как throttle реально enforce-ится (важно про pf на macOS):
main pf ruleset НЕ обходит произвольный top-level anchor автоматически — чтобы pf
прогонял пакеты через наш anchor, в main ruleset обязана стоять ссылка
`dummynet-anchor "<name>"` + `anchor "<name>"`. Поэтому модуль владеет собственным
main-ruleset файлом (MAIN_CONF_PATH) с этими ссылками и грузит его через
`pfctl -f <file>`, ЗАТЕМ загружает per-domain правила в sub-anchor через
`pfctl -a <name> -f -`. Без ссылки anchor не вычисляется -> тихий fail-open.
ВНИМАНИЕ: `pfctl -f` заменяет активный main ruleset — модуль осознанно берёт
main pf ruleset под свой контроль (для изолированной throttle-функции это цена
корректного enforce; интеграция включается только осознанно, issue #13 low/future).

Управление pf enable-reference (важно про побочные эффекты):
`pfctl -E` включает pf и инкрементит enable-reference-count, возвращая release-
token (`Token : <N>`). Токен нужно освободить через `pfctl -X <token>`, иначе pf
остаётся включён системно и счётчик течёт при повторных apply. Поэтому apply
парсит токен из вывода -E и ВОЗВРАЩАЕТ его вызывающему; clear_throttle(token)
освобождает ссылку через `-X`. Fail-closed: если -E не дал токен — reject.

Границы безопасности (privileged root pf — строго!):
- shell-текст собирается ТОЛЬКО из констант (абсолютные пути бинарей + флаги) и
  из ВАЛИДИРОВАННЫХ значений: canonical IP-литерал (round-trip через ipaddress,
  reject scoped `%`), целочисленный rate, whitelist-имя anchor, числовой токен.
  Ни domain, ни сырой пользовательский ввод в shell не попадают никогда.
- Функции НЕ бросают: при любом сбое возвращают структурированный dict.
  Отмена пароля osascript (rc -128) -> cancelled, не ошибка.

Scope: только shaping-логика (функции). Flask-роут `/api/guard/throttle` и UI —
отдельно, после safety-review (issue #13).
"""
import ipaddress
import re
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

# Собственный main-ruleset файл модуля: содержит ссылки на наш anchor, чтобы pf
# реально вычислял его. Путь фиксирован (не пользовательский ввод).
MAIN_CONF_PATH = "/tmp/srouter_throttle.pf.conf"

# Таймаут osascript-моста: как у sudo_route (пароль + выполнение pf).
_TIMEOUT_SEC = 60

# 'Token : <N>' из вывода `pfctl -E`. Только цифры — токен идёт в shell (-X).
_TOKEN_RE = re.compile(r"Token\s*:\s*(\d+)")


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


def _valid_token(token):
    """Токен pf enable-ref в shell-безопасной форме или None (только цифры)."""
    if isinstance(token, bool):
        return None
    if isinstance(token, int) and token >= 0:
        return str(token)
    if isinstance(token, str) and token.isdigit():
        return token
    return None


def _parse_token(out):
    """Вытащить числовой токен из вывода `pfctl -E` ('Token : <N>') или None."""
    if not isinstance(out, str):
        return None
    m = _TOKEN_RE.search(out)
    return m.group(1) if m else None


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


def _main_ruleset_text():
    """Статичный main pf ruleset модуля: ссылки на наш anchor (без validated-ввода).

    dummynet-anchor вычисляет dummynet-правила sub-anchor'а, anchor — filter-часть.
    Имя anchor — константа ANCHOR, не пользовательский ввод.
    """
    return (
        f'dummynet-anchor "{ANCHOR}"\n'
        f'anchor "{ANCHOR}"\n'
    )


# ============================ публичный API ============================
def apply_throttle(domain, rate):
    """Включить throttle для domain на скорости rate (Kbit/s).

    Шаги: резолв domain->canonical IP, валидация rate, `pfctl -E` (ловим enable-
    token, fail-closed без него), настройка dummynet pipe, установка main-ruleset
    со ссылкой на anchor и загрузка per-domain правил в sub-anchor.

    Возвращает dict как _shape_result + ключ `token` (release-token pf enable-ref).
    Токен ОБЯЗАН быть передан позже в clear_throttle(token=...) для освобождения.
    Функция не бросает: любой невалидный вход -> reject без запуска pf.
    """
    ip = resolve_domain_ip(domain)
    if not ip:
        return _reject("не удалось получить canonical IP для домена")
    rate_spec = _valid_rate(rate)
    if not rate_spec:
        return _reject("rate должен быть положительным целым числом (Kbit/s)")

    try:
        # 1) Включаем pf с инкрементом enable-ref и ловим release-token.
        #    stderr сливаем в stdout (osascript отдаёт stdout) — там 'Token : <N>'.
        enable = _admin_run(f"{PFCTL} -E 2>&1")
        if not enable["ok"]:
            enable["token"] = None
            return enable  # cancelled/timeout/ошибка -128 и т.п. — прокидываем как есть
        token = _parse_token(enable["out"])
        if not token:
            # fail-closed: без токена мы не сможем освободить enable-ref -> не продолжаем.
            return {**_reject("pfctl -E не вернул release-token; throttle не применён"),
                    "token": None}

        # 2) main ruleset со ссылкой на anchor пишем на диск (статичный контент,
        #    без validated-ввода) и грузим — иначе pf не вычисляет наш anchor.
        with open(MAIN_CONF_PATH, "w", encoding="utf-8") as fh:
            fh.write(_main_ruleset_text())

        # 3) Всё ниже — из констант + validated (ip canonical, rate_spec числовой,
        #    ANCHOR/PIPE_NUM/MAIN_CONF_PATH константы). Правило dummynet заворачивает
        #    трафик к целевому IP в pipe с ограниченной полосой.
        pipe_cfg = f"{DNCTL} pipe {PIPE_NUM} config bw {rate_spec}"
        pf_rule = (
            f"dummynet out proto tcp from any to {ip} pipe {PIPE_NUM}\\n"
            f"dummynet in proto tcp from {ip} to any pipe {PIPE_NUM}"
        )
        load_main = f"{PFCTL} -f {MAIN_CONF_PATH}"
        load_anchor = f"echo '{pf_rule}' | {PFCTL} -a {ANCHOR} -f -"
        shell_cmd = f"{pipe_cfg}; {load_main}; {load_anchor}"
        res = _admin_run(shell_cmd)
        res["token"] = token
        return res
    except Exception as exc:  # глубокая защита: функция не бросает
        return {**_reject(f"throttle failed: {exc}"), "token": None}


def clear_throttle(token=None):
    """Снять throttle: очистить anchor, удалить dummynet pipe, освободить enable-ref.

    Если передан валидный (числовой) token из apply_throttle — вызывает
    `pfctl -X <token>` для декремента pf enable-reference-count. Без токена
    чистит anchor+pipe best-effort (enable-ref не трогает — освобождать нечего/
    неизвестно что). Идемпотентно и безопасно к повторному вызову. Всё — из
    констант + validated токен.
    """
    try:
        parts = [
            f"{PFCTL} -a {ANCHOR} -F all",   # сброс правил нашего sub-anchor
            f"{DNCTL} pipe {PIPE_NUM} delete",  # удаление dummynet pipe
        ]
        tok = _valid_token(token)
        if tok is not None:
            parts.append(f"{PFCTL} -X {tok}")   # освободить enable-reference
        shell_cmd = "; ".join(parts)
        return _admin_run(shell_cmd)
    except Exception as exc:  # глубокая защита: функция не бросает
        return _reject(f"clear failed: {exc}")
