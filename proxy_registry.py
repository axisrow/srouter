"""Единый реестр потребителей прокси: кто куда настроен и работает ли это физически.

Проблема, которую решает модуль. Прокси настраивается независимо в пяти местах, и ни одно
из них не знает про остальные:

    системный macOS  -> Network settings (scutil/networksetup)
    git -> github    -> ~/.gitconfig
    Claude Code      -> ~/.claude/settings.json (env)
    VSCode/codex     -> <editor>/User/settings.json (http.proxy)
    Codex App        -> launchctl setenv (gui-домен)

Пользователь не мог ответить на вопрос «какой прокси включён и работает ли вообще»: нужно
было руками обойти пять конфигов, и даже это не сказало бы, доходит ли трафик.

ДВЕ НЕЗАВИСИМЫЕ ОСИ — суть модуля:
  configured — что записано в родном конфиге потребителя (намерение);
  runtime    — идёт ли трафик на самом деле (доказательство).
Ни одна по отдельности на вопрос не отвечает. Эмпирически наблюдались оба расхождения:
«настроен, но узел мёртв» (порт открыт, curl таймаутит) и «дашборд думает, что выключено»
(мутация не доехала, а badge держался в JS-переменной).

ТРЁХУРОВНЕВАЯ ОСЬ (issue #302, design-анализ подтверждён axisrow): поле runtime честно
только там, где существует физический сигнал. Класс evidence задаётся декларативно:
  physical     — runtime-замер есть (claude/codex: lsof ESTABLISHED по PID);
  active-probe — физика только активной пробой, секунды, probe=True и только при
                 configured=True (git: процесс живёт <2с, пассивный lsof промахивается —
                 эмпирика design-анализа #302; замер = git ls-remote стеком самого git);
  config-only  — физического сигнала нет (vscode/desktop: health_fn читает settings.json/
                 launchctl — тот же класс артефакта, что configured). Их конфиг-проба НЕ
                 попадает в runtime: там честное 'n/a', иначе панель показывает ложный ok
                 именно там, ради которого её строили (noisy-log-better-than-no-log).
Плюс отдельная ось running (process-alive): живой процесс потребителя по ps, гейтится
наличием процесса по образцу #337; измеряется только при probe=True (~десятки ms).

Почему отдельный модуль, а не расширение health.py: health уже 2895 строк и 13 issue-секций;
это плоский список процедур с семантикой doctor-вердикта (driver/info), а не lifecycle
потребителей. Реестр живёт ВЫШЕ health и переиспользует его пробы как есть. Бонус: health
не может импортировать codex_wrappers (цикл) — у реестра этого ограничения нет.

Что реестр даёт сверх health.check_all():
  1) единый write-путь (apply) — его сейчас нет вообще, оркестрация размазана по srouter_cli;
  2) машиночитаемую пару configured/runtime на потребителя вместо строк-detail;
  3) декларативный список — новый потребитель добавляется одной записью, а не правкой процедур.

Нормализация обязательна: формы status() у трёх модулей реально разные —
  git_proxy    ключ "status" присутствует ТОЛЬКО в unknown-ветке;
  vscode_proxy "paths" — dict в status() и list в enable();
  claude_proxy ни present, ни status, ни paths.
Общее ядро всех трёх — {enabled, proxy}.

Fail-soft: ни один упавший потребитель не имеет права уронить всю панель.
"""
import logging

import claude_proxy
import git_proxy
import health
import proxy_effective
import sys_probe
import system_proxy
import vscode_proxy

try:
    from dashboard_common import PRIVOXY_ADDR, XRAY_SOCKS_ADDR
except SystemExit:  # pragma: no cover
    # Тот же fallback, что в git_proxy/claude_proxy/vscode_proxy: без srouter_config.py
    # модуль обязан импортироваться (install-путь), а не падать.
    PRIVOXY_ADDR = ("127.0.0.1", 8118)
    XRAY_SOCKS_ADDR = ("127.0.0.1", 10808)

_log = logging.getLogger(__name__)

_ACTIONS = ("enable", "disable")

# Статусы health-проб, которые означают «трафик реально идёт мимо прокси» либо «не идёт».
_RUNTIME_ALLOWED = ("ok", "down", "warn", "unknown", "mixed", "n/a")


class ConsumerSpec:
    """Декларативное описание одного потребителя прокси.

    status_fn  — сырое состояние конфига (свой формат у каждого модуля);
    health_fn  — проба из health.py ({status, detail}); её СМЫСЛ задаёт evidence (#302):
                 physical -> runtime, config-only -> не runtime (см. докстринг модуля);
    evidence   — класс физического сигнала: physical | active-probe | config-only;
    enable_fn/disable_fn — write-путь; None -> manageable=False (только наблюдаем).
    """

    __slots__ = ("id", "title", "kind", "status_fn", "health_fn", "evidence",
                 "enable_fn", "disable_fn", "note")

    def __init__(self, id, title, kind, status_fn, health_fn=None,
                 enable_fn=None, disable_fn=None, note="", evidence="config-only"):
        self.id = id
        self.title = title
        self.kind = kind
        self.status_fn = status_fn
        self.health_fn = health_fn
        self.evidence = evidence
        self.enable_fn = enable_fn
        self.disable_fn = disable_fn
        self.note = note

    @property
    def manageable(self):
        return self.enable_fn is not None and self.disable_fn is not None


def _system_status():
    """Системный прокси -> общая форма {enabled, proxy}. any_enabled=None -> unknown."""
    st = system_proxy.status()
    any_on = st.get("any_enabled")
    if any_on is None:
        return {"enabled": False, "proxy": "", "status": "unknown"}
    parts = []
    for name in ("http", "https", "socks"):
        ch = st.get(name) or {}
        if ch.get("enabled") and ch.get("server"):
            parts.append(f"{name}://{ch['server']}:{ch.get('port') or '?'}")
    pac = st.get("pac") or {}
    if pac.get("enabled") and pac.get("url"):
        parts.append(f"PAC {pac['url']}")
    return {"enabled": bool(any_on), "proxy": ", ".join(parts)}


CONSUMERS = (
    ConsumerSpec(
        id="git", title="git → github", kind="git-config",
        status_fn=lambda: git_proxy.status(),
        # #302: физика git — ТОЛЬКО активная проба (_git_verified), не _github_direct_check:
        # та читает git-config (класс configured) и вдобавок зовёт ok «идёт напрямую».
        health_fn=lambda: _git_verified(),
        evidence="active-probe",
        enable_fn=lambda force=False: git_proxy.enable(force=force),
        disable_fn=lambda: git_proxy.disable(),
        note="~/.gitconfig · http.https://github.com.proxy",
    ),
    ConsumerSpec(
        id="claude", title="Claude Code", kind="env-json",
        status_fn=lambda: claude_proxy.status(),
        health_fn=lambda: health._claude_proxy_probe(),
        evidence="physical",
        enable_fn=lambda force=False: claude_proxy.enable(force=force),
        disable_fn=lambda: claude_proxy.disable(),
        note="~/.claude/settings.json · env.HTTPS_PROXY",
    ),
    ConsumerSpec(
        id="vscode", title="VSCode / codex", kind="json-settings",
        status_fn=lambda: vscode_proxy.status(),
        # #302: _vscode_proxy_check читает settings.json — класс configured; в runtime
        # не попадает (был ложный ok «физически» из того же файла, что и ось «настроен»).
        health_fn=lambda: health._vscode_proxy_check(),
        evidence="config-only",
        enable_fn=lambda force=False: vscode_proxy.enable(force=force),
        disable_fn=lambda: vscode_proxy.disable(),
        note="settings.json · http.proxy",
    ),
    # Ниже — наблюдаемые, но не управляемые отсюда потребители: их write-путь живёт в
    # CLI (codex-wrappers/launchctl) либо намеренно отсутствует (системный прокси).
    ConsumerSpec(
        id="codex", title="Codex CLI", kind="wrapper",
        status_fn=None,
        health_fn=lambda: health._codex_proxy_probe(),
        evidence="physical",
        note="~/bin/codex-srouter · zsh-функция (управляется через srouter install)",
    ),
    ConsumerSpec(
        id="desktop", title="Desktop / ChatGPT.app", kind="launchctl",
        status_fn=None,
        # #302: _desktop_proxy_check читает launchctl getenv — класс configured, не физика.
        health_fn=lambda: health._desktop_proxy_check(),
        evidence="config-only",
        note="launchctl setenv (gui-домен)",
    ),
    ConsumerSpec(
        id="system", title="Система (macOS)", kind="system",
        status_fn=_system_status,
        health_fn=None,
        evidence="config-only",
        note="Network settings · только чтение",
    ),
)

_BY_ID = {c.id: c for c in CONSUMERS}


def _health_call(fn):
    """Вызов health-пробы с fail-soft. Отдельная функция — точка подмены в тестах."""
    return fn()


def _effective():
    """Физический замер. Отдельная функция — чтобы тесты могли его отключить/подменить."""
    return proxy_effective.proxy_effective_probe()


# ==================== #302: process-alive ось + активный git-замер ====================

PS = "/bin/ps"
# Замер идёт СТЕКОМ САМОГО git (ls-remote через его scoped-прокси из git-config) — это и
# есть per-потребительский физический сигнал, в отличие от proxy_effective_probe (curl).
GITHUB_PROBE_URL = "https://github.com/axisrow/srouter.git"
# Process-alive гейт (#302, по образцу #337): ps один раз, substring по comm. git не имеет
# долгоживущего процесса (эмпирика: операция <2с, lsof-сэмплирование промахивается) — None.
_PROCESS_PATTERNS = {
    "claude": ("claude",),
    "vscode": ("Code Helper", "Cursor Helper"),
    "desktop": ("ChatGPT",),
}


def _process_running(consumer_id):
    """Живой процесс потребителя: True/False, None = нет процесса либо ps не ответил.

    Дешёво (один ps), но зовётся только при probe=True (см. _row) — открытие страницы
    лёгкое, watchdog не получает лишнего машинно-зависимого скана (канон #251/#263).
    """
    patterns = _PROCESS_PATTERNS.get(consumer_id)
    if not patterns:
        return None
    r = sys_probe.run([PS, "-axo", "pid=,comm="], timeout=3)
    if r.get("timeout") or not r.get("out"):
        return None
    return any(p in line for line in r["out"].splitlines() for p in patterns)


def _git_verified():
    """Активный физический замер git (#302): ls-remote через СОБСТВЕННЫЙ стек git —
    его scoped git-config proxy, его LibreSSL-стек. Секунды через GFW, поэтому зовётся
    только при probe=True и только при configured=True (не настроен — путь не задействован).

    ok   — rc=0: стек git доставил ответ github (с его прокси или без — как настроено);
    down — иной rc: транспорт не доставил ответ (мёртвый прокси/сеть);
    unknown — таймаут замера (не гадаем, что именно не ответило).
    """
    r = sys_probe.run(["git", "ls-remote", "--exit-code", GITHUB_PROBE_URL, "HEAD"], timeout=15)
    if r.get("timeout"):
        return {"status": "unknown",
                "detail": f"git ls-remote timeout — физический замер {GITHUB_PROBE_URL} не ответил"}
    if r.get("rc") == 0:
        return {"status": "ok",
                "detail": "git ls-remote ok — стек git (со своим scoped-прокси) доставляет ответ github"}
    return {"status": "down",
            "detail": f"git ls-remote не удался (rc={r.get('rc')}): {(r.get('err') or '')[:200]}"}


def _configured_from(raw):
    """{enabled, proxy, state?, status?} -> (configured: bool|None, proxy: str, state: str|None).

    status == 'unknown' -> configured=None: конфиг не прочитан, и это НЕ «выключено»
    (канон verify-dont-guess — неизвестность не равна отрицанию).
    state (issue #307) — absent/managed-on/foreign/mixed/unknown: foreign обязан дойти до
    панели как ОТДЕЛЬНОЕ состояние, иначе «Включить» выглядит безопасным кликом, а
    уничтожил бы чужую настройку.
    """
    if not isinstance(raw, dict):
        return None, "", None
    if raw.get("status") == "unknown":
        return None, str(raw.get("proxy") or ""), _UNKNOWN_STATE
    return bool(raw.get("enabled")), str(raw.get("proxy") or ""), raw.get("state")


_UNKNOWN_STATE = "unknown"


def _row(spec, want_runtime):
    """Одна строка панели. Никогда не бросает — упавший потребитель деградирует в unknown."""
    configured, proxy, state = None, "", None
    if spec.status_fn is not None:
        try:
            configured, proxy, state = _configured_from(spec.status_fn())
        except Exception as e:  # noqa: BLE001 — fail-soft boundary: один потребитель не роняет панель
            _log.warning("proxy_registry: status %s failed: %s", spec.id, e)

    runtime, detail = "n/a", spec.note
    running = None
    if want_runtime:
        # running (process-alive) — дешёвая ось (~десятки ms ps), но только по явному
        # запросу (#302, гейт по образцу #337): открытие страницы остаётся лёгким.
        try:
            running = _process_running(spec.id)
        except Exception as e:  # noqa: BLE001 — fail-soft boundary: ось не роняет панель
            _log.warning("proxy_registry: process %s failed: %s", spec.id, e)
            running = None

    if spec.evidence == "config-only":
        # #302: физического сигнала нет — конфиг-проба (settings.json/launchctl) НЕ может
        # стать runtime (ложный ok из того же класса артефакта, что ось configured).
        # Честное n/a; результат конфиг-пробы живёт в detail, не в вердикте.
        if spec.health_fn is not None and want_runtime:
            try:
                h = _health_call(spec.health_fn) or {}
                if h.get("detail"):
                    detail = f"config-only ({spec.note}); конфиг-проба: {h['detail']}"
            except Exception as e:  # noqa: BLE001 — fail-soft boundary
                _log.warning("proxy_registry: health %s failed: %s", spec.id, e)
    elif spec.evidence == "active-probe":
        # #302: активная проба (секунды через GFW) — только по probe=True и только при
        # configured=True: не настроен/неизвестно — прокси-путь git не задействован
        # (runtime остаётся исходным "n/a"; configured=None дозаглушается guard'ом ниже —
        # канон cycle-review PR #299 claim C: не знаем, задействован ли путь, -> unknown).
        if want_runtime and configured is True:
            try:
                h = _health_call(spec.health_fn) or {}
                runtime = h.get("status") or "unknown"
                detail = h.get("detail") or spec.note
            except Exception as e:  # noqa: BLE001 — fail-soft boundary
                _log.warning("proxy_registry: health %s failed: %s", spec.id, e)
                runtime = "unknown"
                # honest unknown: без объяснения «unknown из ниоткуда» нечитаем
                detail = f"активная проба не удалась: {e.__class__.__name__}: {e}"
    elif spec.health_fn is not None:
        # physical: настоящий runtime-замер (lsof ESTABLISHED по PID).
        if want_runtime:
            try:
                h = _health_call(spec.health_fn) or {}
                runtime = h.get("status") or "unknown"
                detail = h.get("detail") or spec.note
            except Exception as e:  # noqa: BLE001 — fail-soft boundary (см. выше)
                _log.warning("proxy_registry: health %s failed: %s", spec.id, e)
                runtime = "unknown"
        else:
            runtime = "unknown"
    if runtime not in _RUNTIME_ALLOWED:
        runtime = "unknown"
    # Потребитель не настроен на прокси -> прокси-путь не задействован, и "ok" от health-пробы
    # означает не «прокси работает», а «потребитель здоров сам по себе». Наблюдалось вживую:
    # health._github_direct_check() рапортует ok со смыслом «git корректно идёт НАПРЯМУЮ»; в
    # панели «настроен=нет / физически=ok» читалось бы как работающий прокси. Честное n/a.
    # Обратное НЕ маскируем: down/warn — доказанная утечка или поломка, её показываем всегда.
    if configured is False and runtime in ("ok", "unknown"):
        runtime = "n/a"
    # Упавший status_fn -> configured=None; для таких строк runtime тоже честно unknown —
    # НЕЗАВИСИМО от того, что вернул health_fn (cycle-review PR #299, claim C: раньше guard
    # ловил только runtime=='n/a', пропуская случай «status_fn упал, health_fn всё равно
    # отработал и вернул ok/down» — панель показала бы «не проверяли, настроен ли» +
    # утверждение о физической работе, которого мы не проверяли).
    if spec.status_fn is not None and configured is None:
        runtime = "unknown"

    return {
        "id": spec.id,
        "title": spec.title,
        "kind": spec.kind,
        "configured": configured,
        "state": state,
        "runtime": runtime,
        "running": running,
        "evidence": spec.evidence,
        "proxy": proxy,
        "detail": detail,
        "manageable": spec.manageable,
        "note": spec.note,
    }


def _stack():
    """Живы ли локальные прокси-порты. Быстро (TCP-connect), без brew/launchctl."""
    return {
        "privoxy": sys_probe.port_open(*PRIVOXY_ADDR),
        "xray": sys_probe.port_open(*XRAY_SOCKS_ADDR),
    }


def _short(text, limit=200):
    """Выжимка многострочного detail: health-пробы возвращают инструкции в сотни символов
    с переносами строк (напр. _github_direct_check ~700), а warning должен читаться одной
    строкой. Полный текст остаётся в поле detail соответствующего потребителя."""
    flat = " ".join(str(text or "").split())
    return flat if len(flat) <= limit else flat[:limit] + "…"


def _warnings(rows, stack, effective):
    """Расхождения, ради которых панель и существует — человеческим языком, по-русски."""
    out = []
    for r in rows:
        # Главное расхождение, ради которого панель и существует: намерение есть,
        # доказательства нет. Именно эта строка отвечает на «работает ли вообще».
        if r["configured"] is True and r["runtime"] == "down":
            out.append(f"{r['title']}: настроен, но трафик не идёт — {_short(r['detail'])}")
    if not stack.get("privoxy"):
        out.append("privoxy не слушает 8118 — HTTP-потребители (Claude Code) пойдут напрямую")
    if not stack.get("xray"):
        out.append("xray не слушает 10808 — SOCKS-потребители (git, codex) пойдут напрямую")
    if effective and effective.get("verdict") == "proxy-broken":
        out.append(f"физический замер: {_short(effective.get('detail', 'прокси не работает'))}")
    return out


def overview(*, probe=False):
    """Полная картина прокси. Не бросает.

    probe=False — только чтение конфигов (лёгкое, для открытия страницы);
    probe=True  — плюс runtime-пробы и парный замер (секунды, по явному запросу).

    {consumers: [...], stack: {privoxy, xray}, effective: {...}|None, warnings: [...]}
    """
    rows = [_row(spec, probe) for spec in CONSUMERS]
    stack = _stack()
    effective = None
    if probe:
        try:
            effective = _effective()
        except Exception as e:  # noqa: BLE001 — probe-канон: замер не роняет панель
            _log.warning("proxy_registry: effective probe failed: %s", e)
            effective = {"status": "unknown", "verdict": "unknown", "works": None}
    return {
        "consumers": rows,
        "stack": stack,
        "effective": effective,
        "warnings": _warnings(rows, stack, effective),
    }


def apply(ids=None, *, action, force=False):
    """Включить/выключить потребителей по реестру. {ok, partial, results, applied,
    rolled_back, rollback_errors, failed, unattempted}.

    Вайтлист id и action ДО любой мутации (канон: мутирующий путь валидирует по вайтлисту).
    Неуправляемый потребитель -> честный отказ, а не молчаливый успех.

    АТОМАРНОСТЬ (issue #303): валидация ДО мутаций (action, id, manageability), затем
    stop-on-first-error + компенсирующий rollback. Первая неудавшаяся мутация (включая
    conflict) останавливает применение — не расширяем частично изменённое состояние
    (fail-closed). Откат восстанавливает ИСХОДНОЕ состояние (review #347): pre-state
    снимается через status_fn до мутации; откатывается только реально изменённое
    (enable -> disable_fn для был-выключен; disable -> enable(force=True) для был-включён-НАШ);
    уже-включённый потребитель не выключается откатом, foreign/mixed pre-state не
    перезаписывается force-восстановлением (#307), нечитаемый pre-state — честный skip.
    Отчитываемся явно: applied / rolled_back / rollback_errors / rollback_skipped / failed /
    unattempted / partial — partial-состояние не может быть тихим. Ошибки и skips rollback
    НЕ глотаются: они видны в ответе и в warning-логе; rollback_errors -> ok=False.

    force (issue #307) — осознанная перезапись чужого значения: реестр доносит его до
    enable_fn каждого потребителя; без force enable на foreign/mixed возвращает per-consumer
    {ok: False, conflict: True} (панель показывает confirm вместо silent-перезаписи).
    """
    if action not in _ACTIONS:
        return {"ok": False, "err": f"unknown action: {action!r}", "results": [],
                "partial": False, "applied": [], "rolled_back": [], "rollback_errors": [],
                "rollback_skipped": [], "failed": None, "unattempted": []}

    if ids is None:
        targets = [c for c in CONSUMERS if c.manageable]
    else:
        targets = []
        for cid in ids:
            spec = _BY_ID.get(cid)
            if spec is None:
                return {"ok": False, "err": f"unknown consumer: {cid!r}", "results": [],
                        "partial": False, "applied": [], "rolled_back": [],
                        "rollback_errors": [], "rollback_skipped": [], "failed": None,
                        "unattempted": []}
            targets.append(spec)

    results = []
    applied = []          # [(spec, pre_state_dict)] — pre-state снимается ДО мутации
    failed = None

    # Review #347: manageability-проверка — В фазе валидации, до любых мутаций (канон
    # «мутирующий путь валидирует по вайтлисту»). Иначе отказ unmanageable посреди цикла
    # оставляет применённую половину без rollback при ok=False — тихий partial в обход #303.
    for spec in targets:
        if not spec.manageable:
            return {"ok": False, "err": f"{spec.title}: управление отсюда не поддерживается ({spec.note})",
                    "results": [{"id": spec.id, "ok": False,
                                 "err": f"{spec.title}: управление отсюда не поддерживается ({spec.note})"}],
                    "partial": False, "applied": [], "rolled_back": [], "rollback_errors": [],
                    "rollback_skipped": [], "failed": None, "unattempted": []}

    for spec in targets:
        # Review #347: pre-state снимается ДО мутации — rollback обязан восстанавливать
        # исходное состояние, а не слепо применять противоположное действие.
        try:
            pre = spec.status_fn() if spec.status_fn is not None else None
        except Exception:  # noqa: BLE001 — нечитаемый pre-state честно попадёт в skip
            pre = None
        fn = spec.enable_fn if action == "enable" else spec.disable_fn
        try:
            r = (fn(force=force) if action == "enable" else fn()) or {}
            entry = {"id": spec.id, "ok": bool(r.get("ok")), "err": str(r.get("err") or "")}
            if r.get("conflict"):
                entry["conflict"] = True
                entry["state"] = r.get("state")
            results.append(entry)
        except Exception as e:  # noqa: BLE001 — сбой мутации = стоп + rollback (см. докстринг)
            _log.warning("proxy_registry: %s %s failed: %s", action, spec.id, e)
            entry = {"id": spec.id, "ok": False, "err": str(e) or e.__class__.__name__}
            results.append(entry)
        if not entry["ok"]:
            failed = {"id": spec.id, "err": entry["err"]}
            break
        applied.append((spec, pre))

    # #303: компенсирующий rollback применённого — в обратном порядке. Review #347:
    # откатывается только РЕАЛЬНО изменённое (pre-state выключен при enable / включён и
    # наш при disable); уже-включённый потребитель не выключается откатом, чужой pre-state
    # (foreign/mixed) не перезаписывается force-восстановлением (#307).
    rolled_back, rollback_errors, rollback_skipped = [], [], []
    if failed is not None:
        for spec, pre in reversed(applied):
            skip = _rollback_skip_reason(action, pre, force)
            if skip:
                _log.warning("proxy_registry: rollback %s skipped: %s", spec.id, skip)
                rollback_skipped.append({"id": spec.id, "reason": skip})
                continue
            try:
                if action == "enable":
                    ir = spec.disable_fn() or {}
                else:
                    ir = spec.enable_fn(force=True) or {}
                if ir.get("ok") is False:
                    rollback_errors.append({"id": spec.id, "err": str(ir.get("err") or "rollback refused")})
                else:
                    rolled_back.append(spec.id)
            except Exception as e:  # noqa: BLE001 — ошибка отката не может быть тихой
                _log.warning("proxy_registry: rollback %s failed: %s", spec.id, e)
                rollback_errors.append({"id": spec.id, "err": str(e) or e.__class__.__name__})

    failed_index = next((i for i, s in enumerate(targets) if s.id == (failed or {}).get("id")), len(targets))
    unattempted = [s.id for s in targets[failed_index + 1:]]

    return {
        "ok": failed is None and not rollback_errors,
        "partial": failed is not None and bool(applied),
        "results": results,
        "applied": [s.id for s, _ in applied],
        "rolled_back": rolled_back,
        "rollback_errors": rollback_errors,
        "rollback_skipped": rollback_skipped,
        "failed": failed,
        "unattempted": unattempted,
    }


def _rollback_skip_reason(action, pre, force=False):
    """Review #347: причина, по которой consumer НЕ откатывается (None = откатывать можно).

    Слепая инверсия опасна в обе стороны: disable уже-включённого = новое разрушение
    рабочего состояния; enable(force=True) поверх foreign = перезапись без consent (#307).
    Нечитаемый pre-state — тоже skip: неизвестность не равна «изменилось» (verify-dont-guess).
    """
    if not isinstance(pre, dict) or pre.get("status") == "unknown" or "enabled" not in pre:
        return "pre-state неизвестен — слепой откат опасен (review #347)"
    enabled_pre = bool(pre.get("enabled"))
    if action == "enable" and enabled_pre:
        # Code-review 2-й pass: force перезаписал ЧУЖОЕ включённое значение — restore
        # значением невозможен (enable_fn не принимает значение); выключать тоже нельзя
        # (до apply прокси работал). Честно называем перезапись и прежнее значение.
        if force and pre.get("state") in ("foreign", "mixed"):
            return (f"pre-state {pre.get('state')} ({pre.get('proxy') or 'значение не читается'}) "
                    f"перезаписан force-включением — auto-restore значением невозможен, "
                    f"требуется ручной шаг (#307)")
        return "уже был включён до apply — откат выключил бы рабочее состояние"
    if action == "disable":
        if not enabled_pre:
            return "уже был выключен до apply — восстанавливать нечего"
        if pre.get("state") in ("foreign", "mixed"):
            return f"pre-state {pre.get('state')} — force-перезапись чужого значения без consent (#307)"
    return None
