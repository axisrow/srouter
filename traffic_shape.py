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
остаётся включён системно и счётчик течёт при повторных apply.

РЕАЛЬНАЯ семантика osascript (issue #61, доказано экспериментом): при rc != 0
любой команды цепочки `do shell script` ОТБРАСЫВАЕТ stdout, error message (-> err)
аккумулирует только stderr цепочки. Поэтому токен, напечатанный лишь в stdout,
при сбое dnctl/pfctl -a был бы потерян. Инварианты:
- Токен захватывается в переменную (`t=$(pfctl -E 2>&1) || exit $?` — сбой самого
  -E обрывает цепочку, токен не создан, утечки нет) и дублируется в ОБА потока:
  stdout (success-путь) и stderr (переживает сбой цепочки).
- Парсинг: `_parse_token(out) or _parse_token(err)` — независимо от rc.
- rc=0 БЕЗ распарсенного токена — СБОЙ (fail-closed): pf включён, release-token
  неизвестен, enable-ref может течь. Явная ошибка + best-effort cleanup
  (clear_throttle(None) — без -X, токена нет), результат в `rollback`.
- При сбое ПОСЛЕ -E (rc != 0, токен распарсен из err) apply делает best-effort
  rollback (clear_throttle(token) — второй промпт только в failure-path),
  результат кладёт в ответ (`rollback`), исходную ошибку не теряет.
- Timeout osascript: out/err пусты, токен потерян, состояние pf неизвестно —
  явная ошибка про возможную утечку enable-ref (rollback невозможен).
- Широкий except (defensive) тоже сохраняет уже распарсенный токен.

Владение dummynet pipe (issue #61): id pipe глобален и НЕ скоупится pf-anchor'ом.
Наш id нестандартно высокий (PIPE_NUM), apply начинает privileged-цепочку с
fail-closed busy-проверки: pipe уже существует -> отказ (exit 71 + маркер) ДО
pfctl -E и до config — чужой шейпинг не перезаписывается и не удаляется.

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

# Id dummynet pipe ГЛОБАЛЕН (не скоупится pf-anchor'ом): низкие id (1-10) типичны
# для чужого шейпинга (Network Link Conditioner конфигурирует pipe 1-2 и т.п.) —
# `dnctl pipe N config` молча перезаписал бы чужой pipe, а clear его удалил бы.
# Нестандартно высокий id + fail-closed busy-проверка в apply (см. PIPE_BUSY_MARKER).
PIPE_NUM = 4127

# Маркер отказа busy-проверки: pipe PIPE_NUM уже существует (чужой шейпинг).
# Печатается в stderr цепочки ДО pfctl -E (токен не создаётся) и детектится
# Python-стороной в err (rc при этом exit 71). Только [a-z_] — идёт в shell.
PIPE_BUSY_MARKER = "srouter_pipe_busy"

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

    Одна privileged-инвокация: busy-проверка pipe (fail-closed владение: id
    глобален — существующий pipe чужой, отказ exit 71 + PIPE_BUSY_MARKER до -E) ->
    `pfctl -E` (включить pf + получить enable-token, сбой самого -E обрывает
    цепочку через `|| exit $?`) -> дубль токена в stdout И stderr (stderr
    переживает сбой цепочки — реальная семантика osascript, см. модульную
    docstring) -> `dnctl pipe config` -> загрузка правил в под-anchor через stdin
    (fail-fast `&&`). main pf ruleset НЕ трогается (под-anchor com.apple/* уже
    вычисляется системой).

    Возвращает dict как _shape_result + ключ `token` (release-token pf enable-ref;
    None если -E не дошёл/не распарсился). Токен ОБЯЗАН быть передан позже в
    clear_throttle(token=...) для освобождения. Fail-closed: rc=0 без распарсенного
    токена — сбой с best-effort cleanup (`rollback`, clear без -X). При сбое ПОСЛЕ
    -E с распарсенным токеном — best-effort rollback (ключ `rollback`).
    Функция не бросает.
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
        # IP в pipe с ограниченной полосой.
        pf_rule = (
            f"dummynet out proto tcp from any to {ip} pipe {PIPE_NUM}\\n"
            f"dummynet in proto tcp from {ip} to any pipe {PIPE_NUM}"
        )
        # Fail-closed владение pipe: id глобален, существующий pipe = чужой шейпинг.
        # dnctl-чтение требует root => проверка ПЕРВОЙ командой privileged-цепочки:
        # до -E (токен не создаётся) и до config (чужой pipe не перезаписывается).
        busy_check = (
            f"if {DNCTL} pipe show {PIPE_NUM} >/dev/null 2>&1; "
            f"then echo {PIPE_BUSY_MARKER} 1>&2; exit 71; fi"
        )
        # `-E 2>&1` сливает stderr -E в захват: строка 'Token : <N>' целиком в $t.
        # `|| exit $?` — fail-fast: -E упал => токена нет => утечки нет.
        enable = f"t=$({PFCTL} -E 2>&1) || exit $?"
        # Дубль токена в оба потока СРАЗУ после -E: stdout — success-путь; stderr —
        # переживает сбой dnctl/pfctl -a (osascript при rc!=0 отбрасывает stdout).
        emit_token = "printf '%s\\n' \"$t\"; printf '%s\\n' \"$t\" 1>&2"
        pipe_cfg = f"{DNCTL} pipe {PIPE_NUM} config bw {rate_spec}"
        load_anchor = f"printf '{pf_rule}' | {PFCTL} -a \"{ANCHOR}\" -f -"
        # fail-fast: busy-check/-E обрывают через exit, сбой config не даёт грузить anchor.
        shell_cmd = f"{busy_check}; {enable}; {emit_token}; {pipe_cfg} && {load_anchor}"

        res = _admin_run(shell_cmd)
        # Токен напечатан в оба потока — парсим из out (успех) ИЛИ err (сбой цепочки).
        token = _parse_token(res.get("out")) or _parse_token(res.get("err"))
        res["token"] = token

        if PIPE_BUSY_MARKER in (res.get("err") or ""):
            # Чужой pipe: отказ ДО -E и до config — ничего не создано и не изменено.
            # Fail-closed: маркер = отказ безусловно, независимо от rc.
            res["ok"] = False
            res["err"] = (
                f"dummynet pipe {PIPE_NUM} уже существует (чужой шейпинг?) — "
                "отказ, конфигурация не изменена"
            )
            return res

        if res["timeout"] and not token:
            # osascript не завершился: состояние pf неизвестно, токен потерян.
            res["err"] = (
                "osascript timeout: состояние pf неизвестно, release-token потерян — "
                "enable-ref может течь; " + (res["err"] or "")
            ).rstrip("; ")
            return res

        if res["ok"] and not token:
            # Fail-closed: rc=0, но release-token не распарсен. Считаем сбоем —
            # pf включён, освободить enable-ref нечем. Cleanup без -X (токена нет).
            res["ok"] = False
            res["err"] = (
                "pf включён, но release-token не получен — enable-ref может течь; "
                + (res["err"] or "")
            ).rstrip("; ")
            res["rollback"] = clear_throttle(None)
            return res

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

    Инвариант владения pipe: удаляется ТОЛЬКО pipe нашего id (PIPE_NUM) — apply
    создаёт его лишь после fail-closed busy-проверки, поэтому pipe PIPE_NUM
    принадлежит нам; чужие id не перечисляются и не трогаются никогда.

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
