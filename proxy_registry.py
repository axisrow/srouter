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
    health_fn  — runtime-проба из health.py ({status, detail}); None -> runtime "n/a";
    enable_fn/disable_fn — write-путь; None -> manageable=False (только наблюдаем).
    """

    __slots__ = ("id", "title", "kind", "status_fn", "health_fn", "enable_fn", "disable_fn", "note")

    def __init__(self, id, title, kind, status_fn, health_fn=None,
                 enable_fn=None, disable_fn=None, note=""):
        self.id = id
        self.title = title
        self.kind = kind
        self.status_fn = status_fn
        self.health_fn = health_fn
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
        health_fn=lambda: health._github_direct_check(),
        enable_fn=lambda: git_proxy.enable(),
        disable_fn=lambda: git_proxy.disable(),
        note="~/.gitconfig · http.https://github.com.proxy",
    ),
    ConsumerSpec(
        id="claude", title="Claude Code", kind="env-json",
        status_fn=lambda: claude_proxy.status(),
        health_fn=lambda: health._claude_proxy_probe(),
        enable_fn=lambda: claude_proxy.enable(),
        disable_fn=lambda: claude_proxy.disable(),
        note="~/.claude/settings.json · env.HTTPS_PROXY",
    ),
    ConsumerSpec(
        id="vscode", title="VSCode / codex", kind="json-settings",
        status_fn=lambda: vscode_proxy.status(),
        health_fn=lambda: health._vscode_proxy_check(),
        enable_fn=lambda: vscode_proxy.enable(),
        disable_fn=lambda: vscode_proxy.disable(),
        note="settings.json · http.proxy",
    ),
    # Ниже — наблюдаемые, но не управляемые отсюда потребители: их write-путь живёт в
    # CLI (codex-wrappers/launchctl) либо намеренно отсутствует (системный прокси).
    ConsumerSpec(
        id="codex", title="Codex CLI", kind="wrapper",
        status_fn=None,
        health_fn=lambda: health._codex_proxy_probe(),
        note="~/bin/codex-srouter · zsh-функция (управляется через srouter install)",
    ),
    ConsumerSpec(
        id="desktop", title="Desktop / ChatGPT.app", kind="launchctl",
        status_fn=None,
        health_fn=lambda: health._desktop_proxy_check(),
        note="launchctl setenv (gui-домен)",
    ),
    ConsumerSpec(
        id="system", title="Система (macOS)", kind="system",
        status_fn=_system_status,
        health_fn=None,
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


def _configured_from(raw):
    """{enabled, proxy, status?} -> (configured: bool|None, proxy: str).

    status == 'unknown' -> configured=None: конфиг не прочитан, и это НЕ «выключено»
    (канон verify-dont-guess — неизвестность не равна отрицанию).
    """
    if not isinstance(raw, dict):
        return None, ""
    if raw.get("status") == "unknown":
        return None, str(raw.get("proxy") or "")
    return bool(raw.get("enabled")), str(raw.get("proxy") or "")


def _row(spec, want_runtime):
    """Одна строка панели. Никогда не бросает — упавший потребитель деградирует в unknown."""
    configured, proxy = None, ""
    if spec.status_fn is not None:
        try:
            configured, proxy = _configured_from(spec.status_fn())
        except Exception as e:  # noqa: BLE001 — fail-soft boundary: один потребитель не роняет панель
            _log.warning("proxy_registry: status %s failed: %s", spec.id, e)

    runtime, detail = "n/a", spec.note
    if spec.health_fn is not None:
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
    # Упавший status_fn -> configured=None; для таких строк runtime тоже честно unknown,
    # иначе панель показала бы «не настроен, но работает», чего мы не проверяли.
    if spec.status_fn is not None and configured is None and runtime == "n/a":
        runtime = "unknown"

    return {
        "id": spec.id,
        "title": spec.title,
        "kind": spec.kind,
        "configured": configured,
        "runtime": runtime,
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


def _warnings(rows, stack, effective):
    """Расхождения, ради которых панель и существует — человеческим языком, по-русски."""
    out = []
    for r in rows:
        # Главное расхождение, ради которого панель и существует: намерение есть,
        # доказательства нет. Именно эта строка отвечает на «работает ли вообще».
        if r["configured"] is True and r["runtime"] == "down":
            out.append(f"{r['title']} ({r['id']}): настроен, но трафик не идёт — {r['detail']}")
    if not stack.get("privoxy"):
        out.append("privoxy не слушает 8118 — HTTP-потребители (Claude Code) пойдут напрямую")
    if not stack.get("xray"):
        out.append("xray не слушает 10808 — SOCKS-потребители (git, codex) пойдут напрямую")
    if effective and effective.get("verdict") == "proxy-broken":
        out.append(f"физический замер: {effective.get('detail', 'прокси не работает')}")
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


def apply(ids=None, *, action):
    """Включить/выключить потребителей по реестру. {ok, results: [{id, ok, err}]}.

    Вайтлист id и action ДО любой мутации (канон: мутирующий путь валидирует по вайтлисту).
    Неуправляемый потребитель -> честный отказ, а не молчаливый успех.
    """
    if action not in _ACTIONS:
        return {"ok": False, "err": f"unknown action: {action!r}", "results": []}

    if ids is None:
        targets = [c for c in CONSUMERS if c.manageable]
    else:
        targets = []
        for cid in ids:
            spec = _BY_ID.get(cid)
            if spec is None:
                return {"ok": False, "err": f"unknown consumer: {cid!r}", "results": []}
            targets.append(spec)

    results = []
    for spec in targets:
        if not spec.manageable:
            results.append({"id": spec.id, "ok": False,
                            "err": f"{spec.title}: управление отсюда не поддерживается ({spec.note})"})
            continue
        fn = spec.enable_fn if action == "enable" else spec.disable_fn
        try:
            r = fn() or {}
            results.append({"id": spec.id, "ok": bool(r.get("ok")), "err": str(r.get("err") or "")})
        except Exception as e:  # noqa: BLE001 — fail-soft: один сбой не прерывает остальные
            _log.warning("proxy_registry: %s %s failed: %s", action, spec.id, e)
            results.append({"id": spec.id, "ok": False, "err": str(e) or e.__class__.__name__})

    return {"ok": bool(results) and all(r["ok"] for r in results), "results": results}
