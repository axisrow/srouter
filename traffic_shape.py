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
fail-closed busy-probe: вывод `dnctl pipe show N` захватывается (exit-код у него
НЕ предикат существования — см. комментарий у PIPE_BUSY_MARKER); сбой probe ->
отказ «владение неизвестно» (exit 72 + маркер), строка `^0*N:` в выводе -> отказ
«pipe занят» (exit 71 + маркер) — оба ДО pfctl -E и до config, чужой шейпинг не
перезаписывается и не удаляется.

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
GREP = "/usr/bin/grep"

# Под-anchor внутри com.apple/* — этот anchor point УЖЕ объявлен в /etc/pf.conf
# (dummynet-anchor/anchor "com.apple/*"), поэтому pf вычисляет наш под-anchor без
# правки main ruleset. Имя — константа, не пользовательский ввод.
ANCHOR = "com.apple/srouter_throttle"

# Id dummynet pipe ГЛОБАЛЕН (не скоупится pf-anchor'ом): низкие id (1-10) типичны
# для чужого шейпинга (Network Link Conditioner конфигурирует pipe 1-2 и т.п.) —
# `dnctl pipe N config` молча перезаписал бы чужой pipe, а clear его удалил бы.
# Нестандартно высокий id + fail-closed busy-проверка в apply (см. PIPE_BUSY_MARKER).
PIPE_NUM = 4127

# Маркеры отказа busy-probe (оба печатаются в stderr цепочки ДО pfctl -E — токен
# не создаётся — и детектятся Python-стороной ТОЛЬКО по подстроке в err: реальный
# osascript возвращает rc=1, числа exit-кодов остаются лишь в тексте ошибки).
# Только [a-z_] — идут в shell.
# ВАЖНО (Apple dnctl.c, list_pipes): `dnctl pipe show N` — ФИЛЬТР листинга, его
# exit-код НЕ предикат существования pipe: отсутствующий pipe => пустой вывод и
# rc=0, а rc!=0 значит лишь сбой самого dnctl (socket/getsockopt). Секция queues
# печатается БЕЗ фильтра по номеру, поэтому существование проверяется якорным
# матчем строки pipe (`%05d:` => `^0*N:`), не exit-кодом и не «вывод непуст».
PIPE_BUSY_MARKER = "srouter_pipe_busy"            # pipe существует (чужой шейпинг), exit 71
PIPE_PROBE_FAILED_MARKER = "srouter_pipe_probe_failed"  # probe упал — владение неизвестно, exit 72

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

    Одна privileged-инвокация: busy-probe pipe (fail-closed владение: id глобален —
    существующий pipe чужой; probe по захваченному выводу, сбой probe => отказ
    exit 72 + PIPE_PROBE_FAILED_MARKER, строка pipe в выводе => отказ exit 71 +
    PIPE_BUSY_MARKER — всё до -E) ->
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
        # Exit-код `pipe show` — НЕ предикат существования (см. PIPE_BUSY_MARKER):
        # захватываем вывод; сбой probe => fail-closed отказ (владение неизвестно);
        # существование => якорная строка `^0*N:` (формат %05d:, queues не матчатся).
        # Разбор rc grep через case: 0 -> busy, 1 -> свободен, >=2 (сбой самого
        # grep) -> fail-closed probe-failed — симметрично сбою dnctl-половины.
        busy_check = (
            f"p=$({DNCTL} pipe show {PIPE_NUM} 2>&1) || "
            f"{{ printf '%s\\n' \"$p\" 1>&2; echo {PIPE_PROBE_FAILED_MARKER} 1>&2; exit 72; }}; "
            f"printf '%s\\n' \"$p\" | {GREP} -q '^0*{PIPE_NUM}:'; "
            f"case $? in 0) echo {PIPE_BUSY_MARKER} 1>&2; exit 71;; 1) ;; "
            f"*) echo {PIPE_PROBE_FAILED_MARKER} 1>&2; exit 72;; esac"
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

        if PIPE_PROBE_FAILED_MARKER in (res.get("err") or ""):
            # Probe упал (socket/getsockopt/grep): владение pipe проверить нельзя =>
            # fail-closed отказ ДО -E — ничего не создано и не изменено. Исходную
            # диагностику ($p форварднут в stderr цепочки) не выбрасываем.
            res["ok"] = False
            res["err"] = (
                f"не удалось проверить владение dummynet pipe {PIPE_NUM} "
                "(dnctl pipe show упал) — отказ, конфигурация не изменена; "
                + (res["err"] or "")
            ).rstrip("; ")
            return res

        if PIPE_BUSY_MARKER in (res.get("err") or ""):
            # Занятый pipe (чужой шейпинг ИЛИ наш незавершённый throttle): отказ
            # ДО -E и до config — ничего не создано и не изменено.
            # Fail-closed: маркер = отказ безусловно, независимо от rc.
            res["ok"] = False
            res["err"] = (
                f"dummynet pipe {PIPE_NUM} уже существует (чужой шейпинг или наш "
                "незавершённый throttle — сначала clear_throttle) — "
                "отказ, конфигурация не изменена"
            )
            return res

        if res["timeout"] and not token:
            # osascript не завершился: состояние pf неизвестно, токен потерян.
            # Формулировка «timeout или сбой запуска»: sys_probe.run помечает
            # timeout=True и для generic-исключений запуска, не только TimeoutExpired.
            res["err"] = (
                "osascript не завершился (timeout или сбой запуска): состояние pf "
                "неизвестно, release-token потерян — enable-ref может течь; "
                + (res["err"] or "")
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
    создаёт его лишь после fail-closed busy-probe, поэтому pipe PIPE_NUM
    принадлежит нам; чужие id не перечисляются и не трогаются никогда.
    Ограничение (осознанное, ревью PR #63): dummynet не хранит владельца pipe,
    доказать владение в момент clear невозможно в принципе — коллизия с чужим
    шейпингом минимизирована нестандартным id + busy-probe в apply; гарантия
    «clear зовётся только для своего активного throttle» (session-lease) —
    ответственность роут-слоя (issue #13).

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
