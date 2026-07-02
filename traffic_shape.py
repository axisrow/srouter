"""Traffic Guard throttle: per-domain замедление через root-only macOS shaping.

Модуль строит правила pf + dummynet pipe (`dnctl`) и выполняет их привилегированно
через тот же osascript admin-мост, что и dashboard.switch_channel/sudo_route:
`do shell script "<из констант+validated, экранированный>" with administrator privileges`,
запуск через `sys_probe.run([OSASCRIPT, "-e", applescript], timeout=)`.

Как throttle enforce-ится (важно про pf на macOS):
main pf ruleset НЕ трогаем. /etc/pf.conf (macOS default) уже содержит
`dummynet-anchor "com.apple/*"` и `anchor "com.apple/*"`, поэтому под-anchor с
именем `com.apple/srouter_throttle` УЖЕ вычисляется системой. Правила грузятся в
этот под-anchor через stdin (`pfctl -a "com.apple/srouter_throttle" -f -`) —
никаких временных файлов и никакой замены активного main ruleset пользователя.

Fail-fast (apply): все шаги — ОДНА osascript-инвокация (один пароль-промпт),
команды соединены через `&&` (канон — dashboard_connectivity.switch_channel).
rc отражает ПЕРВЫЙ сбой; частичный успех не может вернуть ok:true.

Управление pf enable-reference и его lifecycle:
`pfctl -E` включает pf и инкрементит enable-reference-count, печатая release-token
(`Token : <N>`). Токен обязателен к освобождению через `pfctl -X <token>`, иначе pf
остаётся включён системно и счётчик течёт при повторных apply. Инварианты:
- Токен парсится из объединённого вывода НЕЗАВИСИМО от rc (`-E` печатает его до
  сбоя последующих команд). Если -E успел — токен ВСЕГДА в возвращаемом dict.
- При сбое ПОСЛЕ -E (rc != 0, токен распарсен) apply делает best-effort rollback
  (clear_throttle(token) — второй промпт только в failure-path), результат кладёт
  в ответ (`rollback`), исходную ошибку не теряет.
- Широкий except (defensive) тоже сохраняет уже распарсенный токен.

Cleanup (clear) — attempt-all: обязан попытаться выполнить ВСЕ шаги, даже если
один упал, но rc отражает любой сбой. Паттерн `... || rc=1; ...; exit $rc`
(`&&` тут НЕ подходит — маскирует остаток cleanup).

Границы безопасности (privileged root pf — строго!):
- shell-текст собирается ТОЛЬКО из констант (абсолютные пути бинарей + флаги) и
  из ВАЛИДИРОВАННЫХ значений: canonical IP-литерал (round-trip через ipaddress,
  reject scoped `%`), целочисленный rate, whitelist-имя anchor, числовой токен.
  Ни domain, ни сырой пользовательский ввод в shell не попадают никогда.
- shell_cmd экранируется для applescript (_applescript_text) перед вставкой в
  `do shell script "..."` — anchor-имя содержит кавычки/слэш.
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

# Под-anchor внутри com.apple/* — этот anchor point УЖЕ объявлен в /etc/pf.conf
# (dummynet-anchor/anchor "com.apple/*"), поэтому pf вычисляет наш под-anchor без
# правки main ruleset. Имя — константа, не пользовательский ввод.
ANCHOR = "com.apple/srouter_throttle"
PIPE_NUM = 1

# Таймаут osascript-моста: как у switch_channel/sudo_route (пароль + выполнение pf).
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


def _applescript_text(text):
    """Экранировать shell-строку для вставки в `do shell script "..."`.

    Канон dashboard_connectivity._applescript_text: сначала бэкслэши, потом кавычки.
    Anchor-имя содержит кавычки (`-a "com.apple/..."`), без экранирования applescript
    оборвёт строку.
    """
    return str(text).replace("\\", "\\\\").replace('"', '\\"')


def _admin_run(shell_cmd):
    """Выполнить shell_cmd привилегированно через osascript admin-мост.

    ВАЖНО: shell_cmd обязан быть собран ТОЛЬКО из констант и validated значений
    (см. модульную docstring). Динамический/пользовательский фрагмент здесь —
    ошибка, требующая whitelist + экранирования.
    """
    applescript = f'do shell script "{_applescript_text(shell_cmd)}" with administrator privileges'
    return _shape_result(sys_probe.run([OSASCRIPT, "-e", applescript], timeout=_TIMEOUT_SEC))


# ============================ публичный API ============================
def apply_throttle(domain, rate):
    """Включить throttle для domain на скорости rate (Kbit/s).

    Одна privileged-инвокация (fail-fast `&&`): `pfctl -E` (включить pf + получить
    enable-token) -> `dnctl pipe config` -> загрузка правил в под-anchor через stdin.
    main pf ruleset НЕ трогается (под-anchor com.apple/* уже вычисляется системой).

    Возвращает dict как _shape_result + ключ `token` (release-token pf enable-ref;
    None если -E не дошёл/не распарсился). Токен ОБЯЗАН быть передан позже в
    clear_throttle(token=...) для освобождения. При сбое ПОСЛЕ -E с распарсенным
    токеном — best-effort rollback (ключ `rollback`). Функция не бросает.
    """
    ip = resolve_domain_ip(domain)
    if not ip:
        return _reject("не удалось получить canonical IP для домена")
    rate_spec = _valid_rate(rate)
    if not rate_spec:
        return _reject("rate должен быть положительным целым числом (Kbit/s)")

    token = None
    try:
        # Всё ниже — из констант + validated (ip canonical, rate_spec числовой,
        # ANCHOR/PIPE_NUM константы). Правило dummynet заворачивает трафик к целевому
        # IP в pipe с ограниченной полосой. `-E 2>&1` сливает stderr в stdout, чтобы
        # osascript отдал строку 'Token : <N>'.
        pf_rule = (
            f"dummynet out proto tcp from any to {ip} pipe {PIPE_NUM}\\n"
            f"dummynet in proto tcp from {ip} to any pipe {PIPE_NUM}"
        )
        enable = f"{PFCTL} -E 2>&1"
        pipe_cfg = f"{DNCTL} pipe {PIPE_NUM} config bw {rate_spec}"
        load_anchor = f"printf '{pf_rule}' | {PFCTL} -a \"{ANCHOR}\" -f -"
        # fail-fast: первый сбой обрывает цепочку, rc его и отражает.
        shell_cmd = f"{enable} && {pipe_cfg} && {load_anchor}"

        res = _admin_run(shell_cmd)
        # Токен печатает -E ДО возможного сбоя последующих команд — парсим независимо от rc.
        token = _parse_token(res.get("out"))
        res["token"] = token

        if not res["ok"] and token:
            # Сбой после включения pf: pf остался с инкрементированным enable-ref.
            # best-effort rollback (второй промпт только здесь), ошибку не теряем.
            res["rollback"] = clear_throttle(token)
        return res
    except Exception as exc:  # глубокая защита: функция не бросает, токен не теряем
        return {**_reject(f"throttle failed: {exc}"), "token": token}


def clear_throttle(token=None):
    """Снять throttle: очистить под-anchor, удалить dummynet pipe, освободить enable-ref.

    attempt-all: пытается выполнить ВСЕ шаги, даже если предыдущий упал (cleanup не
    должен обрываться на первом сбое), но rc отражает любой сбой (`|| rc=1; exit $rc`).
    `pfctl -X <token>` — только при валидном (числовом) токене из apply_throttle.
    Без токена enable-ref не трогает (нечего/неизвестно что освобождать). Идемпотентно.
    Всё — из констант + validated токен. Функция не бросает.
    """
    try:
        steps = [
            f'{PFCTL} -a "{ANCHOR}" -F all',    # сброс правил нашего под-anchor
            f"{DNCTL} pipe {PIPE_NUM} delete",   # удаление dummynet pipe
        ]
        tok = _valid_token(token)
        if tok is not None:
            steps.append(f"{PFCTL} -X {tok}")    # освободить enable-reference
        # attempt-all: каждый шаг помечает rc при сбое, но не обрывает cleanup.
        body = "; ".join(f"{step} || rc=1" for step in steps)
        shell_cmd = f"rc=0; {body}; exit $rc"
        return _admin_run(shell_cmd)
    except Exception as exc:  # глубокая защита: функция не бросает
        return _reject(f"clear failed: {exc}")
