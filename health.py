"""Health-проверки стека srouter: общий движок для `srouter doctor`, `/health` и watchdog.

Переиспользует логику probe_tunnel (dashboard_network): curl через прокси к api.anthropic.com.
Прокси-трафик идёт через loopback (127.0.0.1:8118 → privoxy → xray → VPS IP), а PF-изоляция
режет только en*/ppp* — значит проверка НЕ блокируется даже при включённой изоляции.

Три потребителя:
  - `srouter doctor` (CLI) — разовый прогон, человекочитаемый отчёт.
  - `GET /health` (эндпоинт) — лёгкий, 200 ok / 503 degraded/down.
  - watchdog (launchd, раз в 90с) — фоновый пинг; нотификация при переходе ok→down.

Не бросает, всегда dict со status (probe-канон).
"""
from pathlib import Path
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlparse

import local_state
import privoxy_system
import sys_probe
from install_lib import _LAUNCHCTL_SERVICE_NOT_FOUND, _launchd_domain, _launchd_is_loaded

_log = logging.getLogger("srouter.health")

# Абсолютные пути: launchd/GUI PATH их не содержит (канон проекта).
CURL = "/usr/bin/curl"
LSOF = "/usr/sbin/lsof"
PS = "/bin/ps"
OSASCRIPT = "/usr/bin/osascript"
LAUNCHCTL = "/bin/launchctl"
ROUTE = "/sbin/route"      # route -n get default — есть ли default route (issue #203)
IFCONFIG = "/sbin/ifconfig"  # активный iface с inet — второй эшелон (issue #203)

# Прокси = privoxy (8118). Берём из dashboard_common если доступен; fallback на хардкод,
# чтобы модуль не падал в среде без srouter_config (как git_proxy/claude_proxy).
try:
    from dashboard_common import HTTP_PROXY_URL as _PROXY  # http://127.0.0.1:8118
    # Порты компонентов стека — единый источник dashboard_common (issue #155).
    from dashboard_common import PRIVOXY_PORT, XRAY_SOCKS_PORT as XRAY_PORT
except (ImportError, SystemExit) as exc:  # noqa: BLE001 — намеренно широкий top-level import-guard.
    # dashboard_common без srouter_config.py бросает SystemExit (не ImportError) — ветка унаследована
    # от канона (git_proxy/claude_proxy). Оба случая (модуль недоступен / конфиг не создан) равнозначны
    # для health: используем fallback-константы, не роняем модуль на import time (probe-канон — health
    # не бросает). Маркер canonical-fallback-port
    _log.info("dashboard_common недоступен (%s: %s) — health использует fallback-константы порта",
              type(exc).__name__, exc)
    _PROXY = "http://127.0.0.1:8118"
    # Fallback на то же каноническое значение. Значения здесь держат единый литерал, а не
    # расходящийся хардкод, даже когда srouter_config недоступен — tests/test_proxy_constants.py
    # пропускает как осознанный fallback, не свежий дубликат.
    PRIVOXY_PORT = 8118  # canonical-fallback-port
    XRAY_PORT = 10808  # canonical-fallback-port

DASHBOARD_PORT = 8787

# Эндпоинты туннеля для проверки — ДВА таргета, как probe_tunnel (dashboard_network): origin-5xx
# одного вендора (Anthropic лежит, но канал жив) не должен читаться как «туннель упал».
TUNNEL_TARGETS = ("https://api.anthropic.com/", "https://api.openai.com/")

# #207: маркер vendor outage в detail _tunnel_up — единый источник правды для человекочитаемого
# префикса (канон issue #155: константа, не разбросанные подстроки). Программный дискриминатор
# едёт структурно (check["category"]=="vendor-outage" в check_all, см. _tunnel_up return 3-tuple),
# а НЕ парсом этой строки — канон loose-validator-recurring-leak. Маркер — только display-текст.
VENDOR_OUTAGE_MARKER = "vendor outage"

# State watchdog'а (переход ok→down, чтобы не спамить). /tmp не переживает ребут — приемлемо:
# после ребута fresh state, первый прогон без нотификации если уже down.
WATCHDOG_STATE = Path("/tmp/srouter-watchdog.last")
WATCHDOG_NOTIFY_LOG = Path.home() / "Library" / "Logs" / "srouter-watchdog.notify.log"
WATCHDOG_LIFECYCLE_STATE = Path("/tmp/srouter-watchdog.launchd.json")
WATCHDOG_LIFECYCLE_LOG = Path.home() / "Library" / "Logs" / "srouter-watchdog.lifecycle.jsonl"

# Real Claude Code transport probe is doctor-only: failed proxy negotiation may spend several
# seconds in retries. Dashboard /health and watchdog keep using lightweight passive checks.
CLAUDE_TRANSPORT_TIMEOUT = 8
CLAUDE_API_BASE_URL = "https://api.anthropic.com"
CLAUDE_DUMMY_API_KEY = "sk-ant-srouter-transport-probe-invalid"


def _port_up(port):
    """Слушает ли кто-то TCP порт (быстро, без сети). True/False."""
    if port == PRIVOXY_PORT and privoxy_system.protection_present():
        # macOS скрывает fd system-daemon пользователя `nobody` от обычного `lsof`, поэтому после
        # #122 lsof даёт ложный down. Loopback connect проверяет именно доступность 8118 без sudo.
        return sys_probe.port_open("127.0.0.1", port, timeout=0.5)
    r = sys_probe.run([LSOF, "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"], timeout=3)
    if r.get("timeout"):
        return False
    return bool((r.get("out") or "").strip())


# ============================ #204: локальный прокси service-status ============================
# Ситуация #3 эпика #201: различать «локальный прокси упал» (privoxy/xray краш/зомби) от «VPS мёртв»
# (#194 — есть) и «туннель сломан». _port_up (TCP-listen) сам по себе не различает «демон слушает»
# от «порт занят orphan'ом» → зомби даёт ложный ok. Service-status (launchd state=running) = ЯВНЫЙ
# сигнал. НЕ используем `brew services info` (issue #201 предлагает): protected-mode privoxy = system
# daemon com.srouter.privoxy, brew его НЕ видит → ложный зомби на нормальной protected-установке.
# Единый источник launchctl print для protected (system) И brew-mode (gui), как _collect_launchd_lifecycle.

# Re-export privoxy system label — тесты (test_health #204) и единый источник для _local_proxy_up.
PRIVOXY_SYSTEM_LABEL = privoxy_system.SYSTEM_LABEL  # com.srouter.privoxy
PRIVOXY_BREW_LABEL = privoxy_system.USER_LABEL      # homebrew.mxcl.privoxy
XRAY_BREW_LABEL = "homebrew.mxcl.xray"


def _privoxy_service_target():
    """(label, domain) для launchctl print privoxy в ТЕКУЩЕМ режиме. protected → system-daemon,
    brew-mode → user-agent. Тот же выбор, что _collect_launchd_lifecycle (health.py:1658)."""
    if privoxy_system.protection_present():
        return PRIVOXY_SYSTEM_LABEL, "system"
    return PRIVOXY_BREW_LABEL, f"gui/{os.getuid()}"


def _service_running(label, domain=None):
    """Состояние launchd-сервена по `launchctl print <domain>/<label>` — tri-state (#204 cycle-review P1).

    Возвращает ОДНО из:
      "running"     — job загружен (rc=0) AND state="running";
      "not_running" — launchctl ОТВЕТИЛ, но сервис не Running: rc!=0 (job не загружен) ИЛИ state!=running
                      (waiting/exiting/etc). Подтверждённый сигнал — doctor может диагностировать зомби/крах.
      "unknown"     — НЕ ответил: launchctl timeout. Не различимо «не работает» от «не спросили» →
                      fail-closed: НЕ трактуем как not_running (cycle-review P1: иначе port-open+timeout
                      давало ложный зомби с советом restart на живом прокси).

    Единый источник правды: работает и для system-daemon (protected privoxy), и для user-agent (brew).
    НЕ brew services info — он слеп к protected privoxy (#204). Канон verify-don't-guess: state-поле,
    не pid (KeepAlive-restart может держать pid при state=exiting).
    """
    domain = domain or f"gui/{os.getuid()}"
    r = sys_probe.run([LAUNCHCTL, "print", f"{domain}/{label}"], timeout=3)
    if r.get("timeout"):
        return "unknown"  # fail-closed: не утверждаем not_running без ответа launchctl
    if r.get("rc") != 0:
        # launchctl ответил ошибкой (job не загружен) — это подтверждённый not_running (сервис снят).
        return "not_running"
    state = _launchd_field(r.get("out") or "", "state")
    return "running" if state == "running" else "not_running"


def _local_proxy_up():
    """Локальный прокси жив? privoxy + xray port-open AND service-running (#204).

    Различение #201/#204 ситуаций (verify-don't-guess — service-status, не догадка по порту):
      - port closed → КРАХ (демон не слушает — упал/не стартовал);
      - port open + service not_running → ЗОМБИ (orphan держит порт, launchd-сервис не Running);
      - port open + service unknown → НЕ зомби (fail-closed: launchctl не ответил — вердикт по port-open,
        с пометкой «service-status не верифицирован»). cycle-review P1: иначе timeout давал ложный зомби;
      - оба компонента port-up + running → ok.
    Возвращает {status, detail}: ok / down (с причиной крах vs зомби + какой компонент). Не бросает.
    unknown по service-status НЕ роняет ok (port-open = прокси принимает соединения), но помечается
    в detail (observability — noisy-log-better-than-no-log).
    """
    privoxy_label, privoxy_domain = _privoxy_service_target()
    components = [
        ("privoxy", PRIVOXY_PORT, privoxy_label, privoxy_domain),
        ("xray", XRAY_PORT, XRAY_BREW_LABEL, f"gui/{os.getuid()}"),
    ]
    problems = []
    unverified = []
    for name, port, label, domain in components:
        port_open = _port_up(port)
        svc = _service_running(label, domain)
        if not port_open:
            # порт не слушается → КРАХ независимо от service-status (трафик не идёт).
            if svc == "running":
                # launchd считает Running, но порт не слушается → bind упал под живым job'ом (крах процесса).
                problems.append(f"{name} крах (port {port} closed, но сервис Running — bind упал)")
            else:
                hint = "сервис не Running" if svc == "not_running" else "service-status unknown"
                problems.append(f"{name} крах (port {port} closed, {hint} — restart)")
        elif svc == "not_running":
            # port open + ПОДТВЕРЖДЁННО не Running → зомби (orphan/launchd рассинхрон).
            problems.append(f"{name} зомби (port {port} слушается, но сервис не Running — orphan/launchd)")
        elif svc == "unknown":
            # port open, но launchctl не ответил → НЕ зомби (fail-closed), помечаем для observability.
            unverified.append(name)
    if problems:
        restart_hint = "brew services restart privoxy xray" if not privoxy_system.protection_present() \
            else "srouter privoxy restart (protected-mode)"
        return {"status": "down",
                "detail": f"локальный прокси упал: {'; '.join(problems)}. Restart: {restart_hint}"}
    detail = "локальный прокси жив: privoxy 8118 + xray 10808 port-up + service-running"
    if unverified:
        detail += f" (⚠ service-status не верифицирован для {', '.join(unverified)} — launchctl timeout)"
    return {"status": "ok", "detail": detail}


# ============================ #206: GFW per-domain (github режется vs нет сети/VPS) ============================
# Эпик #201 ситуация 5: GFW избирателен — режет конкретные домены (github) по TLS-fingerprint, а
# другие (z.ai) пропускает. Doctor сваливал это в «туннель fail» / «VPS мёртв». _gfw_domain_check =
# ПРЯМОЙ curl к доменам БЕЗ прокси (env -u): timeout/reset/connection-failed = режется; HTTP < 500 =
# не режется (даже 404 = живой ответ, канал работает — та же семантика, что sys_probe.tunnel_code_up).
# Канон: verify-dont-guess (прямая причина — прямой curl минуя прокси), zai-direct-no-proxy (z.ai —
# канонически НЕ GFW-target, moonbridge ходит напрямую → эталон «домен не режется»), noisy-log.

# Домены для per-domain GFW-теста. github — типичный GFW-target (issue #199: TLS-блокировка системного
# curl/LibreSSL). api.z.ai — контрольный: канонически НЕ режется (zai-direct-no-proxy, memory). Если
# github режется, а z.ai нет → GFW избирателен; если ОБА режутся → не GFW (нет сети/VPS, первичная
# причина выше в каскаде #203/#196). Список — упорядоченный ([target..., control]): первый режущийся
# при живом контроле = диагноз. НЕ endpoint_host узла: GFW-блокировка доменная, не по IP-маршруту VPS.
GFW_PROBE_DOMAINS = ("github.com",)
GFW_CONTROL_DOMAIN = "api.z.ai"  # канонически не GFW-target (zai-direct-no-proxy)


def _direct_domain_probe(host):
    """Прямой curl к host МИНУЯ прокси (env -u) — достигается ли домен без туннеля?

    #206 per-domain GFW-тест. Тонкая обёртка над sys_probe.direct_probe: #197 cycle-review вынес
    тело в базовый слой sys_probe (как tunnel_code_up) — делят health.py (GFW per-domain) и
    direct_first.py (NO_PROXY reachability). Канон verify-dont-guess: один probe, не дублировать.
    Контракт неизменен: {"reachable": bool, "kind": "ok"|"upstream-error"|"timeout"|"connection-failed"}.
    Не бросает (probe-канон).
    """
    return sys_probe.direct_probe(host)


def _gfw_domain_check(domains=GFW_PROBE_DOMAINS, control=GFW_CONTROL_DOMAIN):
    """Per-domain GFW-тест: режется ли конкретный домен избирательно (github vs z.ai)?

    #206. Прямой curl к каждому домену из `domains` + контрольному `control`. Вердикт:
      gfw  — SOME домен из `domains` НЕ reachable И контрольный reachable → GFW режет избирательно;
      ok   — все домены reachable (ничто не режется);
      info — контрольный тоже НЕ reachable → НЕ GFW (нет сети/VPS — первичная причина выше в каскаде
             #203 сеть/#196 VPS; GFW избирателен, «всё режется» = не GFW-блокировка), или нет доменов.
    Каскад #201: ...→сеть(#203)→DNS(#205)→VPS(#196)→прокси(#204)→GFW per-domain(этот). GFW-чек
    info-only ВСЕГДА (картина для конкретного домена, не сбой стека — как endpoint-override/
    _github_direct_check): режется → подсказка «нужен прокси/VPS для домена», не роняет вердикт.
    Канон: verify-dont-guess (прямая причина — прямой curl), zai-direct-no-proxy (control = z.ai).

    Возвращает {status, detail}: status = gfw | ok | info. Не бросает (probe-канон).
    """
    if not domains:
        return {"status": "info", "detail": "нет доменов для GFW-теста (check пропущен)"}
    ctrl = _direct_domain_probe(control)
    if not ctrl["reachable"]:
        # контрольный домен (z.ai, канонически не GFW-target) тоже режется → НЕ GFW: более общая
        # причина (нет сети/VPS/нет маршрута), которая уже ловится выше в каскаде. Не обвиняем GFW.
        return {"status": "info",
                "detail": f"контрольный домен {control} тоже не отвечает напрямую ({ctrl['kind']}) — "
                          f"это НЕ GFW (нет сети/VPS, первичная причина выше в каскаде)"}
    cut = []
    for host in domains:
        r = _direct_domain_probe(host)
        if not r["reachable"]:
            cut.append((host, r["kind"]))
    if not cut:
        targets = ", ".join(domains)
        return {"status": "ok",
                "detail": f"домены напрямую reachable: {targets} + контрольный {control} "
                          f"(GFW не режет избирательно)"}
    names = ", ".join(h for h, _ in cut)
    return {"status": "gfw",
            "detail": f"домен(ы) {names} режется GFW ({'; '.join(f'{h}: {k}' for h, k in cut)}) — "
                      f"контрольный {control} отвечает напрямую (zai-direct-no-proxy). Нужен "
                      f"прокси/VPS для {names}: github/gh через прокси (env -u снимает scoped git-proxy)"}


def _direct_first_check():
    """#197: какие candidate-домены (z.ai BUILTIN + user direct_domains) идут напрямую (NO_PROXY),
    какие через прокси. info-only ВСЕГДА (как _gfw_domain_check) — картина для диагностики
    (какие домены переживут смерть VPS), НЕ driver: доступность прокси-стека не зависит от
    direct-first детекции. Doctor-only (active_claude gate, как GFW-чек) — direct_first.detect()
    делает прямой curl per-domain = сетевой overhead, не для лёгкого /health/watchdog.

    Возвращает {status, detail}: status = ok (все candidate reachable) | info (часть/все через
    прокси, картина) | unknown (direct_first недоступен — import упал). Не бросает.
    Канон: verify-dont-guess (честный TLS-test, переиспользует sys_probe.direct_probe — не
    дублирует #206), srouter-critical-infra-24-7 (direct-домены переживают смерть VPS),
    more-options-better (user direct_domains конфигурируем), zai-direct-no-proxy (z.ai всегда candidate).
    """
    try:
        import direct_first
        det = direct_first.detect()
    except (ImportError, RuntimeError, OSError, ValueError) as exc:
        # ImportError — модуль недоступен; RuntimeError/OSError — сбой detect() (fail-soft).
        _log.info("direct_first недоступен/сбой: %s — check пропущен", exc)
        return {"status": "unknown", "detail": "direct-first detect недоступен — check пропущен"}
    reach = det.get("reachable", [])
    blocked = det.get("blocked", [])
    if reach and not blocked:
        return {"status": "ok", "detail": f"direct-first: {', '.join(reach)} → напрямую (NO_PROXY)"}
    if reach:
        return {"status": "info",
                "detail": f"direct: {', '.join(reach)}; через прокси: {', '.join(blocked)}"}
    if blocked:
        return {"status": "info", "detail": f"direct-first: все candidate через прокси ({', '.join(blocked)})"}
    return {"status": "info", "detail": "direct-first: нет candidate-доменов"}


def _tunnel_target_up(url):
    """Один таргет через прокси: (ok, detail, kind). Живой = сервер ответил HTTP < 500
    (sys_probe.tunnel_code_up). 000/timeout/5xx — не жив. Не бросает.

    kind — структурный дискриминатор провала (канон loose-validator-recurring-leak: не парсим
    его из detail-строки). Один из: ok | timeout | no-response | connection-failed | bad-code |
    upstream-error. #207: upstream-error = HTTP 5xx (сервер ответил через туннель → канал жив,
    но сам вендор лежит); прочие = curl не достучался (сеть/VPS)."""
    r = sys_probe.run([CURL, "-sS", "-o", "/dev/null", "-x", _PROXY,
                       "--connect-timeout", "4", "--max-time", "8",
                       "-w", "%{http_code}", url], timeout=10)
    if r.get("timeout"):
        return False, "timeout", "timeout"
    code = (r.get("out") or "").strip()
    if not code:
        return False, "no-response", "no-response"
    if code == "000":
        return False, "connection-failed", "connection-failed"
    try:
        code_int = int(code)
    except ValueError:
        return False, f"bad-code {code}", "bad-code"
    if not sys_probe.tunnel_code_up(code_int):
        return False, f"upstream-error HTTP {code}", "upstream-error"
    return True, f"HTTP {code}", "ok"


def _tunnel_up():
    """Реальный туннель жив? curl через прокси к TUNNEL_TARGETS (ровно как probe_tunnel).

    Бьём ДВА таргета (Anthropic + OpenAI), up = первый OR второй — та же избыточность, что у
    probe_tunnel: origin-5xx одного вендора (сам вендор лежит, но канал жив) НЕ читается как
    «туннель упал», иначе watchdog поднимет ложную тревогу (issue #82). Единая семантика 5xx=down
    сохраняется, но применяется per-target, а решение — по обоим.
    НЕ блокируется PF — прокси-трафик через loopback, PF режет только en*/ppp*.
    #207: если ВСЕ таргеты дали HTTP 5xx (kind=="upstream-error" — сервер ответил через туннель,
    значит канал жив, но сами вендоры лежат) → detail = «vendor outage», is_vendor_outage=True.
    Это различает HTTP-level vendor-down от network/VPS-death (timeout/connection-failed/...).
    Возвращает (ok, detail, is_vendor_outage). is_vendor_outage — структурный сигнал (не parse
    detail-строки), consumer'ы (check_all → _print_report) читают его, а не подстроку.
    """
    if not TUNNEL_TARGETS:
        return False, "no tunnel targets", False
    details, kinds = [], []
    for url in TUNNEL_TARGETS:
        ok, detail, kind = _tunnel_target_up(url)
        if ok:
            return True, detail, False  # любой живой таргет = туннель жив (как up = a OR o)
        details.append(detail)
        kinds.append(kind)
    # ни один таргет не ответил живым HTTP < 500 → туннель/прокси down.
    # #207: vendor outage = ВСЕ kind'и upstream-error (HTTP 5xx, канал жив). Структурный
    # дискриминатор по kind, не parse detail-строки (канон loose-validator-recurring-leak).
    is_vendor_outage = all(k == "upstream-error" for k in kinds)
    if is_vendor_outage:
        return False, f"{VENDOR_OUTAGE_MARKER} — оба вендора лежат, канал жив ({'; '.join(details)})", True
    return False, "; ".join(details), False


# ============================ #203: активный сетевой интерфейс/маршрут (нет сети vs VPS мёртв) ============================
# Эпик #201 ситуация 1: doctor не различал «нет сети вообще» (Wi-Fi/eth выкл, нет default route)
# от «VPS мёртв». _upstream_vps_reachable (#196) делает TCP-probe до VPS → при отсутствии сети
# TCP тоже timeout → ложно «VPS мёртв». Этот чек — ПЕРВЫЙ в каскаде (нет сети → VPS → локальный
# прокси → ...), перехватывает «нет сети» ДО VPS-probe, чтобы doctor сказал точную причину.
# Канон: verify-dont-guess (прямая причина — маршрут/интерфейс), probe-semantics-from-primary-source
# (man route + эмпирика: rc!=0 + "not in table" = нет default route), sys_probe #35 (no-hidden-magic).

# IPv4 loopback-префикс — inet 127.x.x.x отбрасываем (это не внешний путь). Не urlsplit/ipaddress:
# ifconfig отдаёт CIDR-суффиксом ('inet 127.0.0.1'), host-часть сравниваем как строку (как
# node_selector._route_iface_from_output — раздел ':', первый токен). Маркер primary-source-loopback.
_LOOPBACK_INET_PREFIX = "127."


def _route_default_interface():
    """Имя интерфейса default route из `route -n get default`, или '' если default route'а нет.

    Переиспользует парсинг 'interface:' канона node_selector._route_iface_from_output (один формат
    macOS `route get`, один источник). Эмпирика (verify): default route есть → rc=0 + 'interface: en0';
    нет → rc!=0 (man route: 'not in table'). timeout/сбой запуска route — не таймаут сети (как
    sys_probe.run контракт), трактуется как «default route неприменим» → ''. Не бросает.
    """
    try:
        raw = sys_probe.run([ROUTE, "-n", "get", "default"], timeout=3) or {}
    except (OSError, subprocess.SubprocessError) as exc:
        _log.debug("route -n get default: сбой запуска (%s) — default route неприменим", exc)
        return ""
    if raw.get("timeout") or raw.get("rc") != 0:
        return ""
    out = raw.get("out") or ""
    for line in out.splitlines():
        key, sep, value = line.strip().partition(":")
        if sep and key.strip().lower() == "interface":
            return (value.strip().split() or [""])[0]
    return ""


def _inet_interface():
    """Имя первого интерфейса с inet (не loopback) из `ifconfig`, или '' если такого нет.

    Второй эшелон детекта: route сброшен/кэш протух, но физический iface ещё держит inet → сеть
    активна. Парсим ifconfig построчно: блок интерфейса = 'name: flags=...', затем '\tinet <ip>'.
    Отбрасываем loopback (127.x — _LOOPBACK_INET_PREFIX) — он есть всегда, не доказывает внешний
    путь. Эмпирика (verify, ifconfig на macOS): en0 + 'inet 192.168.1.17' → внешний; lo0 + inet
    127.0.0.1 → loopback (отбрасываем); awdl0 active без inet → не считает (нет IPv4). Не бросает.
    """
    try:
        raw = sys_probe.run([IFCONFIG], timeout=3) or {}
    except (OSError, subprocess.SubprocessError) as exc:
        _log.debug("ifconfig: сбой запуска (%s) — inet-интерфейс неприменим", exc)
        return ""
    if raw.get("timeout"):
        return ""
    cur_iface = ""
    for line in (raw.get("out") or "").splitlines():
        stripped = line.strip()
        # Заголовок блока интерфейса: 'en0: flags=...' — имя до ':' в начале непустой строки без \t.
        if stripped and not line.startswith("\t") and ":" in stripped:
            cur_iface = stripped.split(":", 1)[0].strip()
            continue
        # '\tinet <ip> netmask ...' — IPv4-адрес текущего iface.
        if stripped.startswith("inet ") and cur_iface:
            ip = stripped.split()[1] if len(stripped.split()) > 1 else ""
            if ip and not ip.startswith(_LOOPBACK_INET_PREFIX):
                return cur_iface
    return ""


def _network_interface_up():
    """Есть ли активный сетевой путь наружу (default route ИЛИ iface с inet не-loopback).

    Каскад эпика #201, ситуация 1: «нет сети» vs «VPS мёртв». Проверяется ПЕРВЫМ (до
    _upstream_vps_reachable #196), чтобы отсутствие интернета не читалось как «VPS мёртв»
    (TCP-probe до VPS при мёртвой сети тоже timeout → ложный диагноз).

    Два эшелона (канон verify-dont-guess — прямая причина):
      1. route -n get default → interface: есть default route (как node_selector._route_iface_from_output);
      2. ifconfig → iface с inet (не loopback) — маршрут сброшен, но iface ещё держит адрес.
    up = ЭШЕЛОН 1 ИЛИ ЭШЕЛОН 2. Оба пусты → нет сети.

    Возвращает {up: bool, detail}:
      up=True   — сеть активна (detail: через какой iface/route);
      up=False  — нет сети (detail: «нет активного интерфейса/маршрута — подключи интернет»).
    Не бросает (probe-канон, как _upstream_vps_reachable/_port_up).
    """
    iface = _route_default_interface()
    if iface:
        return {"up": True, "detail": f"сеть активна: default route через {iface}"}
    inet_iface = _inet_interface()
    if inet_iface:
        return {"up": True, "detail": f"сеть активна: интерфейс {inet_iface} с IP (default route отсутствует)"}
    return {"up": False,
            "detail": "нет активного сетевого интерфейса/маршрута — подключи интернет (Wi-Fi/eth)"}


# #205: тестовый домен для DNS-резолва. Стабильный, widely-resolved, не GFW-target (как
# TUNNEL_TARGETS). НЕ endpoint_host узла: endpoint может быть IP (Reality), и резолв IP не
# проверит DNS-стек — нужен именно домен. Канон: verify-dont-guess (прямая причина — resolve).
DNS_PROBE_HOST = "github.com"


def _resolve_host(host):
    """socket.getaddrinfo обёртка для тестируемости (mock по имени на модуле health).

    Возвращает True если резолв дал хотя бы один адрес, False при gaierror/OSError. Не бросает.
    getaddrinfo не принимает timeout kwarg — резолв bounded системным resolver timeout (на macOS
    через mDNSResponder обычно <1с). Обёртка (а не socket напрямую) даёт детерминированный mock в
    тестах, как _mock_vps_tcp подменяет sys_probe.port_open (канон no-hidden-magic).
    """
    try:
        socket.getaddrinfo(host, 443)
        return True
    except OSError as exc:
        # socket.gaierror (NXDOMAIN/резолвер недоступен) — подкласс OSError (verify).
        _log.debug("resolve %s: %s — DNS не резолвит", host, exc)
        return False


def _dns_up():
    """DNS-стек резолвит домены? Каскад эпика #201 ситуация #4, МЕЖДУ #203 (нет сети) и #196 (VPS).

    _upstream_vps_reachable (#196) зовёт sys_probe.port_open → socket.create_connection, которая
    САМА резолвит hostname endpoint'а. При сломанном DNS (упал dnsmasq/resolver) resolve падает с
    gaierror → port_open=False → ложно «VPS мёртв». Этот чек = socket.getaddrinfo тестового домена
    (НЕ endpoint: Reality-IP резолв не проверит DNS). Проверяется ПОСЛЕ #203 (сеть есть) и ДО #196
    (VPS), чтобы сломанный резолв не маскировался в «VPS мёртв»: gaierror ≠ VPS-смерть. Канон:
    verify-dont-guess (прямая причина — resolve-ошибка), probe-semantics-from-primary-source
    (getaddrinfo NXDOMAIN → socket.gaierror, подкласс OSError — подтверждено эмпирически).

    Возвращает {up: bool, detail}:
      up=True   — домен отрезолвился (DNS работает);
      up=False  — getaddrinfo gaierror/timeout — DNS не резолвит (проверь dnsmasq/resolver).
    Не бросает (probe-канон, как _network_interface_up/_upstream_vps_reachable).
    """
    if _resolve_host(DNS_PROBE_HOST):
        return {"up": True, "detail": f"DNS резолвит: {DNS_PROBE_HOST} (резолвер работает)"}
    return {"up": False,
            "detail": f"DNS не резолвит {DNS_PROBE_HOST} — проверь dnsmasq/resolver "
                      f"(домены не разрешаются)"}



# #194: прямой TCP-probe до upstream VPS endpoint (минуя прокси). socket.create_connection
# НЕ знает про HTTP_PROXY/HTTPS_PROXY env — это голый TCP до host:port, в обход privoxy/xray.
# timeout подобран > connect-timeout curl-туннеля (4с) — probe должен ответить быстрее, чем
# _tunnel_up сдаться, чтобы различение «VPS мёртв» vs «локальный прокси упал» было осмысленным.
VPS_TCP_PROBE_TIMEOUT = 3.0

# TEST-NET 203.0.113.0/24 (RFC 5737) placeholder-детектор = canonical local_state._is_testnet_placeholder
# (единый источник правды, #200). PR #196 ввёл здесь собственный inline-предикат без octet-валидации
# → drift с canonical на 203.0.113.300/abc/-1 (post-review #198, cycle-review high-confirmed, канон
# loose-validator-recurring-leak). Делегируем canonical: doctor и apply/compare судят об endpoint-плейсхолдере
# одинаково. Прямой TCP-probe до 203.0.113.x ничего не доказывает (пакеты уходят в никуда) — детект ДО пробы.


def _vps_endpoint(node):
    """(host, port) VPS-endpoint из узла. port из node['port'], default 443 (Reality на TLS).

    Источник порта = тот же, что gen_xray_config._safe_port(node.get('port'), default=443): единый
    контракт порта узла (канон — единый источник). host = endpoint_host (не route_ip: route_ip —
    рабочий IP из xray/resolve, может расходиться; endpoint_host = то, что пользователь настроил).
    Возвращает (host, port) или (None, None) если узла/хоста нет / хост невалиден. Не бросает.
    """
    if not isinstance(node, dict):
        return None, None
    host = node.get("endpoint_host")
    if not isinstance(host, str) or not host or not local_state._is_valid_host(host):
        return None, None
    try:
        port = int(node.get("port"))
    except (TypeError, ValueError):
        port = 443  # как gen_xray_config._safe_port default — Reality на TLS 443
    if not (1 <= port <= 65535):
        port = 443
    return host, port


def _upstream_vps_reachable(node=None):
    """Прямой TCP-probe до upstream VPS endpoint (БЕЗ прокси) — различение #194.

    _tunnel_up() бьёт через прокси к API-таргетам → connection-failed без различения «VPS мёртв»
    vs «локальный прокси (privoxy/xray) упал». Этот чек = socket.create_connection (TCP) до
    active_node().endpoint_host:port напрямую, минуя прокси (sys_probe.port_open). Канон:
    verify-don't-guess — прямая причина, не догадка (эталон sys_probe #35).

    Возвращает {status, detail}:
      ok   — TCP-connect успешен (VPS жив);
      down — TCP timeout/refused (VPS мёртв);
      warn — placeholder TEST-NET 203.0.113.x (нельзя реально зондировать test-IP);
      info — нет активного узла / нет endpoint_host.
    Не бросает (probe-канон).
    """
    if node is None:
        try:
            node = local_state.active_node() or {}
        except (OSError, ValueError, TypeError, KeyError) as exc:
            _log.debug("active_node() недоступен (%s) — VPS-probe неприменим", exc)
            node = {}
    host, port = _vps_endpoint(node)
    if host is None:
        return {"status": "info",
                "detail": "нет активного узла / endpoint_host (VPS-probe неприменим)"}
    # Placeholder TEST-NET — детект ДО пробы: TCP до 203.0.113.x ничего не доказывает.
    # #198: делегируем canonical local_state._is_testnet_placeholder (валидация octet 0..255),
    # не собственный «prefix + count==3» (drift на 203.0.113.300/abc/-1).
    if local_state._is_testnet_placeholder(host):
        return {"status": "warn",
                "detail": f"endpoint {host}:{port} — placeholder TEST-NET 203.0.113.x (RFC 5737), "
                          f"не маршрутизируется; замени на реальный VPS-адрес"}
    try:
        reachable = sys_probe.port_open(host, port, timeout=VPS_TCP_PROBE_TIMEOUT)
    except OSError as exc:
        _log.debug("TCP-probe %s:%s: %s — считаем VPS недоступным", host, port, exc)
        reachable = False
    if reachable:
        return {"status": "ok",
                "detail": f"VPS reachable: TCP-коннект до {host}:{port} (VPS жив)"}
    return {"status": "down",
            "detail": f"VPS недоступен: TCP timeout/refused до {host}:{port} "
                      f"(VPS мёртв? заплачен/запущен?)"}


def _is_claude_code_comm(comm):
    """Является ли comm (из `ps comm=`) процессом Claude Code?

    `ps comm=` на macOS отдаёт полный путь. Реальные CC-варианты:
      - basename "claude": CLI (~/.local/bin/claude), GUI pty-host (ClaudeCode.app/.../claude), bare "claude";
      - version-runner: путь содержит "/claude/versions/" (basename = номер версии, не "claude") — это
        основной движок CC, который реально держит коннект к privoxy.
    Отбрасывает desktop Claude.app helpers, codex, сторонние claude*-wrappers.
    """
    if not comm:
        return False
    if os.path.basename(comm) == "claude":
        return True
    return "/claude/versions/" in comm


def _claude_code_pids():
    """CC PID'ы через `ps -axo pid=,comm=` (#143 — общий источник для runtime env-чека).

    Переиспользует _is_claude_code_comm (один критерий CC-процесса). Возвращает список PID-строк,
    [] если CC не запущен ИЛИ ps-timeout. Fail-soft: любой сбой ps → []. (Тот же парсинг, что в
    _claude_proxy_probe:145-155 — line.split(None,1) сохраняет пробелы в comm-пути.)
    НЕ трогает _claude_proxy_probe — там своя проверка timeout для двух разных detail-сообщений
    («timeout ps» vs «CC не запущен»), которые здесь схлопываются в один пустой результат.
    """
    r = sys_probe.run([PS, "-axo", "pid=,comm="], timeout=3)
    if r.get("timeout"):
        return []
    pids = []
    for line in (r.get("out") or "").splitlines():
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        pid_s, comm = parts[0].strip(), parts[1].strip()
        if pid_s.isdigit() and _is_claude_code_comm(comm):
            pids.append(pid_s)
    return pids


def _claude_proxy_probe():
    """Какой локальный маршрут виден у запущенного Claude Code? Passive lsof evidence.

    Важно (#127): ESTABLISHED к 10808 доказывает только TCP до SOCKS listener, но не SOCKS
    handshake и не доставку запроса к API. Поэтому 10808 без active real-CLI probe никогда не
    получает ok. External socket остаётся доказательством direct leak.
    """
    r = sys_probe.run([PS, "-axo", "pid=,comm="], timeout=3)
    if r.get("timeout"):
        return {"status": "unknown", "source": "n/a", "detail": "timeout ps"}
    pids = []
    for line in (r.get("out") or "").splitlines():
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        pid_s, comm = parts[0].strip(), parts[1].strip()
        if pid_s.isdigit() and _is_claude_code_comm(comm):
            pids.append(pid_s)
    if not pids:
        return {"status": "unknown", "source": "n/a", "detail": "Claude Code не запущен"}

    # Один lsof на все PID'ы. Любой local proxy + external = mixed/direct leak.
    lr = sys_probe.run([LSOF, "-nP", "-p", ",".join(pids)], timeout=3)
    if lr.get("timeout"):
        return {"status": "unknown", "source": "n/a", "detail": "timeout lsof"}
    proxy_pids, socks_pids, external_pids = set(), set(), set()
    for line in (lr.get("out") or "").splitlines():
        if "TCP" not in line or "ESTABLISHED" not in line:
            continue
        fields = line.split()
        pid = fields[1] if len(fields) > 1 else ""
        if f"->127.0.0.1:{PRIVOXY_PORT}" in line:
            proxy_pids.add(pid)
        elif f"->127.0.0.1:{XRAY_PORT}" in line:
            socks_pids.add(pid)
        elif "->127.0.0.1:" not in line:
            # external ESTABLISHED (не localhost) — CC идёт напрямую, мимо прокси.
            external_pids.add(pid)
    local_pids = proxy_pids | socks_pids
    if local_pids and external_pids:
        return {"status": "down", "source": "runtime",
                "detail": (f"runtime: Claude Code MIXED — local proxy (PID {','.join(sorted(local_pids))}) "
                           f"+ direct-leak (PID {','.join(sorted(external_pids))}). "
                           f"Один из PID идёт напрямую — нарушение fail-closed. "
                           f"Проверь HTTPS_PROXY в ~/.claude/settings.json env.")}
    if proxy_pids and not socks_pids:
        return {"status": "ok", "source": "runtime",
                "detail": f"runtime: Claude Code через HTTP bridge 8118 (PID {','.join(sorted(proxy_pids))})"}
    if socks_pids:
        routes = f"; HTTP 8118 PID {','.join(sorted(proxy_pids))}" if proxy_pids else ""
        return {"status": "unknown", "source": "runtime",
                "detail": (f"runtime: TCP к SOCKS5 10808 (PID {','.join(sorted(socks_pids))}){routes} "
                           f"не доказывает API transport; нужен активный real-CLI probe")}
    if external_pids:
        return {"status": "down", "source": "runtime",
                "detail": (f"runtime: Claude Code идёт НАПРЯМУЮ (мимо прокси) — нарушение fail-closed. "
                           f"PID {','.join(sorted(external_pids))}. "
                           f"Проверь HTTPS_PROXY в ~/.claude/settings.json env "
                           f"(ожидается http://127.0.0.1:8118)")}
    return {"status": "unknown", "source": "runtime",
            "detail": "runtime: Claude Code запущен, но нет активных сокетов (idle)"}


def _find_claude_binary():
    """Найти настоящий Claude Code без зависимости от урезанного launchd PATH."""
    candidates = [
        Path.home() / ".local" / "bin" / "claude",
        Path("/opt/homebrew/bin/claude"),
        Path("/usr/local/bin/claude"),
    ]
    discovered = shutil.which("claude")
    if discovered:
        candidates.append(Path(discovered))
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return ""


def _has_expected_api_401(output):
    """Только structured api_error_status=401 считается положительным transport proof."""
    for line in output.splitlines():
        try:
            payload = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(payload, dict) and payload.get("api_error_status") == 401:
            return True
    return False


def _has_api_retry(output):
    """Есть ли structured retry без ответа API (формат stream-json может содержать пробелы)."""
    for line in output.splitlines():
        try:
            payload = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(payload, dict) and payload.get("subtype") == "api_retry":
            return True
    return False


def _claude_transport_once(proxy, timeout=CLAUDE_TRANSPORT_TIMEOUT):
    """Запустить настоящий Claude Code изолированно через один proxy.

    Dummy key гарантирует нулевой model-call: успешный транспорт заканчивается ожидаемым API 401.
    User settings, NO_PROXY, alternative base URL и реальные credentials не участвуют (#127).
    """
    claude = _find_claude_binary()
    if not claude:
        return {"status": "unknown", "proxy": proxy, "api_status": None,
                "error": "Claude Code binary not found", "detail": "Claude Code binary not found"}

    clean_keys = (
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "all_proxy", "no_proxy",
        "ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
    )
    with tempfile.TemporaryDirectory(prefix="srouter-claude-probe-") as temp_home:
        config_dir = Path(temp_home) / ".claude"
        config_dir.mkdir()
        env = os.environ.copy()
        for key in clean_keys:
            env.pop(key, None)
        env.update({
            "HOME": temp_home,
            "CLAUDE_CONFIG_DIR": str(config_dir),
            "ANTHROPIC_BASE_URL": CLAUDE_API_BASE_URL,
            "ANTHROPIC_API_KEY": CLAUDE_DUMMY_API_KEY,
            "HTTP_PROXY": proxy,
            "HTTPS_PROXY": proxy,
            "http_proxy": proxy,
            "https_proxy": proxy,
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "DISABLE_TELEMETRY": "1",
            "DISABLE_ERROR_REPORTING": "1",
        })
        cmd = [
            claude,
            "--bare",
            "--setting-sources", "",
            "--no-session-persistence",
            "--tools", "",
            "--max-budget-usd", "0.01",
            "--verbose",
            "--output-format", "stream-json",
            "-p", "srouter transport probe",
        ]
        run_result = sys_probe.run(cmd, timeout=timeout, env=env)

    output = "\n".join(
        part for part in (run_result.get("out", ""), run_result.get("err", "")) if part
    )
    if _has_expected_api_401(output):
        return {"status": "ok", "proxy": proxy, "api_status": 401, "error": "",
                "detail": "API returned expected 401 (transport works)"}
    if "UnsupportedProxyProtocol" in output:
        error = "UnsupportedProxyProtocol"
    elif run_result.get("timeout") or "Connection error" in output or _has_api_retry(output):
        error = "Connection error / timeout"
    elif run_result.get("rc") is None:
        error = (run_result.get("err") or "Claude Code launch failed").splitlines()[0][:160]
    else:
        error = f"Claude Code exited rc={run_result.get('rc')} before any API response"
    detail = error
    if run_result.get("timeout"):
        detail += " before any API response"
    return {"status": "down", "proxy": proxy, "api_status": None,
            "error": error, "detail": detail}


def _configured_claude_proxy():
    """Proxy из settings.json; local import сохраняет fail-soft границу health."""
    try:
        import claude_proxy
        return claude_proxy.status().get("proxy", "")
    except ImportError as exc:
        _log.debug("claude_proxy недоступен: %s — proxy считается не настроенным", exc)
        return ""


def _claude_transport_probe(proxy=None):
    """Doctor-only active proof. Для failed SOCKS запускает известный HTTP control."""
    configured = proxy if proxy is not None else _configured_claude_proxy()
    if not configured:
        return {"status": "unknown", "proxy": "", "api_status": None,
                "error": "proxy is not configured", "detail": "Claude Code proxy не настроен"}

    result = _claude_transport_once(configured)
    scheme = urlparse(configured).scheme.lower()
    if result["status"] != "down" or scheme not in {"socks", "socks5", "socks5h"}:
        return result

    control = _claude_transport_once(_PROXY)
    detail = f"configured proxy {configured}: {result['detail']}; HTTP control {_PROXY}: {control['detail']}"
    if control["status"] == "ok":
        detail += "; configured SOCKS path is unusable — configure Claude Code to use the HTTP bridge"
    result = dict(result)
    result["detail"] = detail
    result["control"] = control
    return result


# codex-binary comm-паттерн. Матчит ОСНОВНОЙ codex-binary по BASENAME (независимо от способа установки):
#   basename "codex"                       — npm-vendor (.../bin/codex), standalone (~/.local/bin/codex)
#   basename "codex-<arch>-apple-darwin"   — Homebrew cask / release-binary
# НЕ матчит (исключает по basename):
#   moonbridge, browser_crashpad_handler, ChatGPT for Chrome, node (Codex.app helpers / .codex/plugins),
#   codex-code-mode-host (вспомогательный binary, не основной движок).
# cycle-review #121 C1: npm-only regex пропускал brew-cask/standalone → doctor ложно «codex не запущен».
# cycle 2 cleanup: общий substring 'codex' over-matched helpers → matcher по basename (точно).
_CODEX_BIN_RE = re.compile(r"(^|/)codex(?:-(?:aarch64|x86_64)-apple-darwin)?$")

# Issue #189: ChatGPT.app (com.openai.codex) бандлит свой Rust-binary по пути
# /Applications/ChatGPT.app/Contents/Resources/codex — basename 'codex' → МАТЧИТСЯ _CODEX_BIN_RE.
# Этот Rust app-server — основной WS-трафик к chatgpt.com, берёт прокси ТОЛЬКО из launchd gui-env
# (codenv), НЕ из CLI-shell-env → другой контекст, чем CLI codex (TUI/terminal). _codex_proxy_probe
# (TUI-чек) его НЕ учитывает; App-PID уходит в отдельный _codex_app_proxy_check (driver для gui-env).
# Разделение по path-сегменту .app/ (comm = полный путь): /ChatGPT.app/ или /Codex.app/ → App-context.
_CODEX_APP_PATH_RE = re.compile(r"/(?:ChatGPT|Codex)\.app/", re.IGNORECASE)


def _is_codex_app_comm(comm):
    """Codex.app/ChatGPT.app-bundled codex (Rust app-server, launchd-env контекст)?

    По path-сегменту .app/ в полном comm (ps -axo comm= отдаёт путь). App-PID — другой контекст
    прокси, чем CLI-codex: наследует launchd gui-env (codenv), а не shell-env. Детект нужен, чтобы
    _codex_proxy_probe (TUI/CLI-чек) исключил App-PID (иначе ложный mixed/down на нерелевантном PID —
    баг «❌ на VSCode PID 56748» #189). path-сегмент стабильнее bundle-id: comm не отдаёт signing_id,
    а /ChatGPT.app/ (com.openai.codex ребрендинг) и /Codex.app/ оба покрыты одним regex.
    """
    return bool(comm and _CODEX_APP_PATH_RE.search(comm))


def _is_codex_binary_comm(comm):
    """Является ли comm основным codex-binary? По basename: 'codex' или 'codex-<arch>-apple-darwin'.

    Любой способ установки (npm/cask/standalone). Отбрасывает helpers (moonbridge, crashpad, node,
    ChatGPT-for-Chrome) и codex-code-mode-host (вспомогательный binary).
    """
    if not comm:
        return False
    return bool(_CODEX_BIN_RE.search(comm))


def _codex_proxy_probe():
    """Какой маршрут используют ЖИВЫЕ codex-процессы? Поведенческий proof (lsof), не файл/which.

    Решает #120: codex TUI рвёт long-lived WS через privoxy 8118, но стабилен через SOCKS5 10808.
    `which codex` НЕ доказательство — wrapper использует exec, процесс выглядит как brew-codex в ps.
    Единственный критерий — runtime-сокет конкретного PID к 10808 (ok) vs 8118 (warn, #120) vs напрямую
    (down). ps eww env ЧУЖОГО/системного codex-процесса на macOS не читается (права) → классификация по
    lsof-сокетам, как у claude-proxy. (Для same-UID CC env читается — см. #143 _read_runtime_endpoint_config;
    здесь lsof остаётся источником, т.к. codex-binary часто запущен под другим контекстом/правами.)

    Возвращает {status, source, detail}:
      status="ok"      — codex-binary-PID держит коннект к 10808 (SOCKS5/xray, стабильно);
      status="warn"    — codex на 8118 (privoxy) — long-lived WS порвётся (#120);
      status="down"    — codex идёт напрямую (external IP, без localhost-прокси);
      status="mixed"   — несколько codex-PID на разных маршрутах;
      status="unknown" — codex не запущен ИЛИ lsof timeout (info-only, не роняет вердикт).
    """
    # 1. PID'ы codex-binary. ps -axo comm= отдаёт полный путь — матчим по vendor-binary-path.
    # Issue #189: делим на CLI-PID (TUI/terminal-контекст) и App-PID (ChatGPT.app launchd-контекст).
    # App-PID (Rust app-server, /ChatGPT.app/.../codex) — другой контекст прокси (codenv gui-env, не
    # shell-env) → уходит в отдельный _codex_app_proxy_check. Иначе App-PID direct (без codenv) +
    # CLI на SOCKS5 → ложный mixed; только-App direct → ложный down в TUI-чеке (баг «❌ на VSCode PID»).
    r = sys_probe.run([PS, "-axo", "pid=,comm="], timeout=3)
    if r.get("timeout"):
        return {"status": "unknown", "source": "n/a", "detail": "timeout ps"}
    cli_pids, app_pids = [], []
    for line in (r.get("out") or "").splitlines():
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        pid_s, comm = parts[0].strip(), parts[1].strip()
        if not (pid_s.isdigit() and _is_codex_binary_comm(comm)):
            continue
        (app_pids if _is_codex_app_comm(comm) else cli_pids).append(pid_s)
    if not cli_pids:
        # App-PID есть, но CLI/TUI-codex не запущен — это не TUI-сцена. App уходит в свой чек;
        # TUI-чек = unknown (info-only), не роняет вердикт (как claude-proxy когда CC не запущен).
        app_hint = (f" (App-codex PID {','.join(app_pids)} → см. codex-app-proxy check)"
                    if app_pids else "")
        return {"status": "unknown", "source": "n/a",
                "detail": f"codex CLI/TUI не запущен{app_hint}"}
    pids = cli_pids

    # 2. Один lsof на ВСЕ PID'ы (батч). Классифицируем по ->127.0.0.1:PORT (как claude-proxy).
    lr = sys_probe.run([LSOF, "-nP", "-p", ",".join(pids)], timeout=3)
    if lr.get("timeout"):
        return {"status": "unknown", "source": "n/a", "detail": "timeout lsof"}

    # 3. Классификация per-PID по множествам маршрутов. external_pids (per-PID, не bool) — критично для
    # C2: SOCKS-PID + direct-PID → mixed (не ok), иначе direct-сессия маскируется (#121 cycle 1 C2).
    socks_pids, privoxy_pids, external_pids = set(), set(), set()
    for line in (lr.get("out") or "").splitlines():
        if "TCP" not in line or "ESTABLISHED" not in line:
            continue
        # localhost-прокси: ->127.0.0.1:PORT. PID — fields[1] (COMMAND=0, PID=1 в lsof-выводе).
        fields = line.split()
        pid = fields[1] if len(fields) > 1 else ""
        if f"->127.0.0.1:{XRAY_PORT}" in line:
            socks_pids.add(pid)
        elif f"->127.0.0.1:{PRIVOXY_PORT}" in line:
            privoxy_pids.add(pid)
        elif "->127.0.0.1:" not in line:
            # external ESTABLISHED (не localhost) — codex идёт напрямую. Track per-PID.
            external_pids.add(pid)

    # 4. Классификация по комбинации множеств. Любая direct-сессия при SOCKS-сессии → mixed
    # (multi-session-утечка, которую probe должен ловить — #120/#121 C2).
    def _fmt(status, **kw):
        parts = []
        if kw.get("socks"):
            parts.append(f"10808 (PID {','.join(sorted(kw['socks']))})")
        if kw.get("privoxy"):
            parts.append(f"8118 (PID {','.join(sorted(kw['privoxy']))})")
        if kw.get("external"):
            parts.append(f"direct (PID {','.join(sorted(kw['external']))})")
        return ", ".join(parts)

    has_good = bool(socks_pids)
    has_bad = bool(privoxy_pids or external_pids)
    if has_good and has_bad:
        return {"status": "mixed", "source": "runtime",
                "detail": (f"runtime: смешанные сессии — {_fmt('mixed', socks=socks_pids, privoxy=privoxy_pids, external=external_pids)}; "
                           f"перезапусти ломаную TUI (exec zsh -l)")}
    if socks_pids:
        return {"status": "ok", "source": "runtime",
                "detail": f"runtime: codex через SOCKS5 10808 (PID {','.join(sorted(socks_pids))})"}
    if privoxy_pids and not external_pids:
        return {"status": "warn", "source": "runtime",
                "detail": (f"runtime: codex через privoxy 8118 — long-lived WS порвётся (#120); "
                           f"перезапусти TUI в новом терминале (exec zsh -l). PID {','.join(sorted(privoxy_pids))}")}
    if external_pids and not privoxy_pids:
        return {"status": "down", "source": "runtime",
                "detail": f"runtime: codex идёт напрямую (external IP, без прокси) — PF/провайдер режет. PID {','.join(sorted(external_pids))}"}
    if privoxy_pids and external_pids:
        # оба плохих, но без SOCKS — классифицируем как down (хуже warn).
        return {"status": "down", "source": "runtime",
                "detail": f"runtime: codex через privoxy 8118 + direct — нет SOCKS-маршрута. PID {_fmt('down', privoxy=privoxy_pids, external=external_pids)}"}
    return {"status": "unknown", "source": "runtime",
            "detail": f"runtime: codex запущен (PID {','.join(sorted(pids))}), но нет активных сокетов (idle)"}


# ============================ #145: установленные codex/claude-code binary на диске ============================
# Дополняет runtime-probes (lsof по ЖИВЫМ proc) инвентаризацией ДИСКА. Несколько версий — ранний
# сигнал конфликта (#135 desktop-proxy-vs-managed-codex-socks5-conflict), но НЕ сбой стека → info-only
# (как claude-proxy когда CC не запущен). Doctor показывает картину, не угадывает за пользователя.

# Маркер srouter-wrapper в ~/bin/codex-srouter (первая строка шаблона srouter-codex-cli-wrapper.sh).
# Совпадает с CODEX_WRAPPERS[0] marker в srouter.py (канон: один источник правды для маркера).
# Issue #169: wrapper файл переименован codex → codex-srouter, но МАРКЕР не менялся (идентифицирует
# «srouter-managed wrapper», не имя файла) → один и тот же маркер в health.py и srouter.py.
_CODEX_WRAPPER_MARKER = "# srouter: codex CLI wrapper (managed)"

# Which(1) с -a печатает ВСЕ совпадения в PATH; абсолютные пути — только строки, начинающиеся с /
# (на zsh `which -a codex` печатает shell-функцию `codex () {...}` ПЕРЕД binary — её отбрасываем).
WHICH = "/usr/bin/which"
NPM = "/opt/homebrew/bin/npm"  # абсолютный путь: launchd/GUI PATH его не содержит (канон)


def _codex_wrapper_path():
    """Путь к codex-wrapper в ~/bin/codex-srouter (динамически, для моков Path.home — канон srouter.py).
    Issue #169 rename: wrapper файл codex → codex-srouter (real binary по-прежнему зовётся codex)."""
    return Path.home() / "bin" / "codex-srouter"


def _which_all(name):
    """`which -a <name>` → список абсолютных путей. Отбрасывает shell-функции/aliases (не начинаются с /).
    Не бросает (fail-soft: timeout/нет which → пустой список)."""
    r = sys_probe.run([WHICH, "-a", name], timeout=3)
    if r.get("timeout"):
        return []
    paths = []
    for line in (r.get("out") or "").splitlines():
        line = line.strip()
        # абсолютный путь = кандидат (zsh-функция/alias/описание — пропускаем).
        if line.startswith("/"):
            paths.append(line)
    return paths


def _binary_version(path):
    """`<path> --version` → первая непустая строка (версия). Пусто если не запустился. Не бросает."""
    r = sys_probe.run([path, "--version"], timeout=4)
    if r.get("timeout"):
        return ""
    out = (r.get("out") or "").strip()
    if not out:
        out = (r.get("err") or "").strip()
    return out.splitlines()[0].strip()[:120] if out else ""


def _is_srouter_codex_wrapper(path):
    """Файл path — наш srouter-wrapper? Путь == ~/bin/codex-srouter И маркер в содержимом (первая строка шаблона).
    Не полагается только на путь: чужой wrapper в ~/bin/codex-srouter без маркера — НЕ наш (regression-гвард).
    Issue #169: путь к wrapper'у = ~/bin/codex-srouter (rename из codex).
    """
    try:
        if path == str(_codex_wrapper_path()):
            return _CODEX_WRAPPER_MARKER in Path(path).read_text(encoding="utf-8")
        return False
    except OSError:
        return False


def _codex_provenance(path):
    """Provenance codex-binary по его расположению: npm / homebrew / usr-local / bin / path.
    НЕ утверждает «обёрнут srouter» — это решает _is_srouter_codex_wrapper (по маркеру, не по пути),
    поэтому ~/bin/codex-srouter без маркера = provenance 'bin' (чужой/устаревший wrapper), не 'srouter-wrapper'."""
    p = str(path)
    if "/lib/node_modules/" in p or p.endswith(".js"):
        return "npm"
    if "/opt/homebrew/" in p:
        return "homebrew"
    if "/usr/local/bin/" in p:
        return "usr-local"
    if p == str(_codex_wrapper_path()):
        return "bin"
    return "path"


def _claude_provenance(path):
    """Provenance claude-code по расположению: CLI / GUI app / version-runner."""
    p = str(path)
    if "/versions/" in p:
        return "version-runner"
    if "/ClaudeCode.app" in p:
        return "gui-app"
    return "cli"


def _scan_codex_binaries():
    """Найти ВСЕ codex-binary на диске. Источники: which -a, homebrew-paths, ~/bin wrapper,
    npm global root (@openai/codex/bin/codex.js), brew-cask. Дедуп по нормализованному пути.
    Каждый: {path, provenance, version, wrapped}. Не бросает (fail-soft).

    Issue #169: real binary зовётся codex (имя освобождено от wrapper'а при rename). srouter-wrapper
    живёт в ~/bin/codex-srouter и НЕ находится через `which -a codex` (другое имя) — добавляем его явно
    (шаг 3), чтобы doctor показывал wrapped-статус."""
    candidates = []
    # 1. which -a codex (real binary в PATH; старый устаревший ~/bin/codex тоже, если остался после rename).
    candidates.extend(_which_all("codex"))
    # 2. well-known homebrew/standalone (Apple Silicon / Intel).
    for cand in ("/opt/homebrew/bin/codex", "/usr/local/bin/codex"):
        if Path(cand).is_file():
            candidates.append(cand)
    # 3. srouter-wrapper ~/bin/codex-srouter (явно — который() codex его не вернёт: имя codex-srouter,
    # и ~/bin может не быть в PATH пробы). Переименован в #169 из ~/bin/codex.
    wrapper = str(_codex_wrapper_path())
    if Path(wrapper).is_file():
        candidates.append(wrapper)
    # 4. npm global root (@openai/codex) — отдельный источник (which может не показать .js).
    npm_r = sys_probe.run([NPM, "root", "-g"], timeout=4)
    if not npm_r.get("timeout"):
        npm_root = (npm_r.get("out") or "").strip()
        if npm_root:
            npm_codex = str(Path(npm_root) / "@openai" / "codex" / "bin" / "codex.js")
            if Path(npm_codex).is_file():
                candidates.append(npm_codex)
    # 5. brew-cask codex (отдельный binary, не npm).
    brew_r = sys_probe.run(["/opt/homebrew/bin/brew", "list", "--cask"], timeout=5)
    if not brew_r.get("timeout") and "codex" in (brew_r.get("out") or ""):
        for cand in ("/opt/homebrew/Caskroom/codex",):
            if Path(cand).is_dir():
                candidates.append(cand)

    # Дедуп по нормализованному пути (один файл через два имени — один).
    seen = set()
    results = []
    for cand in candidates:
        try:
            norm = str(Path(cand).resolve())
        except OSError:
            norm = cand
        if norm in seen or not Path(cand).is_file():
            continue
        seen.add(norm)
        results.append({
            "path": cand,
            "provenance": _codex_provenance(cand),
            "version": _binary_version(cand),
            "wrapped": _is_srouter_codex_wrapper(cand),
        })
    return results


def _scan_claude_code_binaries():
    """Найти claude-code на диске: CLI (~/.local/bin/claude), GUI app, version-runners (versions/*).
    Переиспользует path-семантику _is_claude_code_comm (basename/versions), но на диске, не на proc.
    Каждый: {path, provenance, version, wrapped}. wrapped всегда False (CC не оборачиваем srouter).
    Не бросает."""
    home = Path.home()
    candidates = []
    # CLI (в PATH + well-known) — which может найти иGUI-pty-host, но CLI — основной.
    candidates.extend(_which_all("claude"))
    cli = str(home / ".local" / "bin" / "claude")
    if Path(cli).is_file():
        candidates.append(cli)
    # GUI app (bundle).
    app = home / ".local" / "share" / "claude" / "ClaudeCode.app"
    if app.is_dir():
        candidates.append(str(app))
    # version-runners (основной движок CC) — каждый каталог-версия = отдельный binary.
    versions_dir = home / ".local" / "share" / "claude" / "versions"
    if versions_dir.is_dir():
        try:
            for child in sorted(versions_dir.iterdir()):
                if child.is_file():
                    candidates.append(str(child))
        except OSError:
            pass

    seen = set()
    results = []
    for cand in candidates:
        try:
            norm = str(Path(cand).resolve())
        except OSError:
            norm = cand
        if norm in seen:
            continue
        seen.add(norm)
        # version: только для исполняемых файлов (не .app bundle).
        version = _binary_version(cand) if Path(cand).is_file() else ""
        results.append({
            "path": cand,
            "provenance": _claude_provenance(cand),
            "version": version,
            "wrapped": False,
        })
    return results


def _format_versions_detail(codex_bins, claude_bins):
    """Человекочитаемый detail для doctor: буллеты provenance + версия + бейдж обёрнут/нет (issue #145)."""
    lines = []
    if codex_bins:
        lines.append(f"codex: {len(codex_bins)} установлено")
        for b in codex_bins:
            badge = "обёрнут srouter" if b["wrapped"] else "НЕ обёрнут"
            ver = b["version"] or "версия неизвестна"
            lines.append(f"  • {b['provenance']} {ver} → {b['path']} ({badge})")
    else:
        lines.append("codex: не установлен")
    if claude_bins:
        lines.append(f"claude-code: {len(claude_bins)} установлено")
        for b in claude_bins:
            ver = b["version"] or ("версия в имени" if b["provenance"] == "version-runner" else "версия неизвестна")
            lines.append(f"  • {b['provenance']} {ver} → {b['path']}")
    else:
        lines.append("claude-code: не установлен")
    return "; ".join(lines)


def _privoxy_log_observability_check(layout=privoxy_system.DEFAULT_LAYOUT):
    """Observability privoxy-лога под protected-mode (#152): молчалив ли privoxy? logfile жив?

    privoxy #141 ставится БЕЗ директивы debug → logfile всегда пустой → не поймать флап к github
    через 8118. Чек показывает картину (как claude-proxy/versions): не роняет вердикт, WARN живёт
    в detail. Возвращает {status, detail}:
      status="ok"   — debug выкл (осознанно тихий, дефолт #141) ИЛИ включён и logfile пишет;
      status="warn" — debug включён, но logfile пустой (privoxy не пишет? rights/logrotate/level?);
      status="info" — config/logfile не читаются без sudo (права/отсутствие) — fail-soft, не гадаем.

    Канон: privacy-no-content-hash-on-disk (debug 1=URLs — помечаем как чувствительный), noisy-log-
    better-than-no-log (молчаливый privoxy = observability-дыра, подсвечиваем подсказку SROUTER_PRIVOXY_DEBUG=2).
    """
    try:
        text = layout.config_path.read_text(encoding="utf-8", errors="ignore")[:16384]
    except OSError:
        return {"status": "info",
                "detail": "privoxy config не читается без sudo (protected-mode) — observability недоступна"}
    # debug-уровень из live-конфига. _config_directives из privoxy_system: ключ→значение, skip comments.
    try:
        directives = privoxy_system._config_directives(text)
    except ValueError:
        directives = {}
    debug_raw = directives.get("debug", "0").strip()
    try:
        debug = int(debug_raw)
    except ValueError:
        debug = 0

    # logfile = logdir + "logfile logfile" (ProtectedLayout.log_dir / "logfile").
    logfile = layout.log_dir / "logfile"
    logfile_size = -1
    try:
        logfile_size = logfile.stat().st_size
    except OSError:
        pass  # не существует / не читается — учтём ниже

    if debug == 0:
        # Молчаливый (дефолт #141) — это осознанно, но observability-дыра при флапе. Подсказка уровня.
        return {"status": "ok",
                "detail": ("privoxy: debug выкл (молчаливый); для диагностики флапа/таймаутов — "
                           "SROUTER_PRIVOXY_DEBUG=2 (connections, приватно: без URL/body)")}

    sensitive = " (⚠ URLs — чувствительно: токены/query пишутся на диск)" if debug == 1 else ""
    if logfile_size == 0:
        return {"status": "warn",
                "detail": (f"privoxy: debug {debug} включён{sensitive}, но logfile пуст — "
                           f"privoxy не пишет? (rights/logrotate/level/sudo при rotate)")}
    if logfile_size > 0:
        return {"status": "ok",
                "detail": f"privoxy: debug {debug} включён{sensitive}; logfile {logfile_size} байт"}
    # logfile не существует/не читается, но debug включён — странно, но не driver.
    return {"status": "info",
            "detail": f"privoxy: debug {debug} включён{sensitive}, но logfile не читается (права/отсутствие)"}


def _installed_versions_check():
    """Инвентаризация codex/claude-code binary на ДИСКЕ + их версии + обёрнут ли srouter (#145).

    Дополняет runtime-probes (живые proc): показывает, СКОЛЬКО версий установлено и какая обёрнута.
    Info-only: несколько версий — ранний сигнал конфликта (#135), но НЕ сбой стека → не роняет status.
    Возвращает {status, detail, codex:[...], claude_code:[...]}:
      status="ok"      — что-то установлено (картина показана);
      status="unknown" — ничего не найдено (info-only «не установлено»).
    Не бросает (fail-soft: каждый источник изолирован try/except в sys_probe.run)."""
    try:
        codex_bins = _scan_codex_binaries()
    except OSError as exc:
        _log.debug("_scan_codex_binaries: %s — codex-инвентаризация пропущена", exc)
        codex_bins = []
    try:
        claude_bins = _scan_claude_code_binaries()
    except OSError as exc:
        _log.debug("_scan_claude_code_binaries: %s — claude-code-инвентаризация пропущена", exc)
        claude_bins = []
    detail = _format_versions_detail(codex_bins, claude_bins)
    if not codex_bins and not claude_bins:
        return {"status": "unknown", "detail": detail, "codex": [], "claude_code": []}
    return {"status": "ok", "detail": detail, "codex": codex_bins, "claude_code": claude_bins}


# ============================ #186: PF codex kill-switch (provisioning uid 503) ============================
def _codex_isolation_check():
    """Статус PF codex kill-switch — настоящая fail-closed граница (epic #166, #186).

    info-only для ВСЕХ «незамкнутых» состояний (НЕ driver — иначе doctor всегда degraded на
    нормальных установках, где codex идёт под user-UID 501, паттерн шума PR #135). ok — только
    при реальном процессе под UID 503. Возвращает {status, detail}, status: info|ok. НЕ бросает.

    Состояния:
      - нет lease (probe_codex_isolation.status != 'ok') → info «не установлен (по выбору)».
      - lease ok, НО probe_codex_user не provisioned → info «инфра загружена, UID не создан».
      - lease ok + user provisioned, НО нет процесса под UID 503 → info «PF standby, sudo -u = follow-up»
        (wrapper в проде НЕ запускает codex под uid 503 — осознанный scope #186).
      - lease ok + user provisioned + процесс под UID 503 → ok «real fail-closed активна».

    ps -u <uid> для без-процесса UID → rc=1 + пустой out (verify-dont-guess); has_proc требует
    rc=0 И непустой out (консервативно: сбой ps → info, не ложный ok).
    """
    try:
        import isolate_firewall
        lease = isolate_firewall.probe_codex_isolation()
        if lease.get("status") != "ok":
            return {"status": "info",
                    "detail": "PF codex kill-switch не установлен (lease отсутствует) — по выбору."}
        user = isolate_firewall.probe_codex_user()
        if not user.get("provisioned"):
            return {"status": "info",
                    "detail": "PF codex-изоляция: sub-anchor загружен, НО _srouter_codex (uid 503) "
                              "не создан → правила не матчат. Переустановите (install) для provisioning."}
        # ps -u <uid>: rc=0 + непустой вывод → процесс под этим UID есть.
        r = sys_probe.run([PS, "-u", isolate_firewall.CODEX_USER, "-o", "pid=,comm="], timeout=3)
        has_proc = (not r.get("timeout")) and r.get("rc") == 0 and bool((r.get("out") or "").strip())
        if has_proc:
            return {"status": "ok",
                    "detail": f"PF codex kill-switch активен: lease ok + uid "
                              f"{isolate_firewall.CODEX_USER} provisioned + процесс под этим UID "
                              f"работает (real fail-closed)."}
        return {"status": "info",
                "detail": f"PF codex kill-switch готов, но codex не запущен под uid "
                          f"{isolate_firewall.CODEX_USER} (sudo -u) — продакшн-запуск = follow-up."}
    except (ImportError, AttributeError, KeyError, OSError, subprocess.SubprocessError) as exc:
        # ImportError — isolate_firewall недоступен; AttributeError/KeyError — probe_* вернул
        # неожиданную форму (defensive); OSError/SubprocessError — сбой sys_probe.run/ps.
        _log.info("codex-isolation check: сбой (%s: %s)", type(exc).__name__, exc)
        return {"status": "info", "detail": f"codex-isolation check: сбой ({str(exc)[:80]})."}


# ============================ #129: endpoint-override detection ============================

_DEFAULT_ANTHROPIC_HOST = "api.anthropic.com"


def _read_endpoint_config():
    """Читает ANTHROPIC_BASE_URL + NO_PROXY из всех источников (#129).

    Источники (по приоритету): shell env → ~/.claude/settings.json env → launchctl getenv.
    Managed/local/project settings scopes (Claude Code docs) — НЕ покрыты: srouter не имеет доступа
    к этим scope'ам из Doctor. Если ни один источник не задан → source="default" (предполагаем
    стандартный api.anthropic.com).
    Возвращает {base_url, no_proxy, source}. Не бросает.
    """
    import claude_proxy
    # settings.json env
    data = claude_proxy._load()
    env = data.get("env", {}) if isinstance(data, dict) else {}
    # launchctl getenv (gui-домен) — фолбэк если shell/settings пусты.
    lc_base = sys_probe.run(["/bin/launchctl", "getenv", "ANTHROPIC_BASE_URL"], timeout=3)
    lc_base_val = (lc_base.get("out") or "").strip() if not lc_base.get("timeout") else ""
    lc_noproxy = sys_probe.run(["/bin/launchctl", "getenv", "NO_PROXY"], timeout=3)
    lc_noproxy_val = (lc_noproxy.get("out") or "").strip() if not lc_noproxy.get("timeout") else ""
    base = os.environ.get("ANTHROPIC_BASE_URL", "") or env.get("ANTHROPIC_BASE_URL", "") or lc_base_val
    no_proxy = os.environ.get("NO_PROXY", "") or env.get("NO_PROXY", "") or lc_noproxy_val
    no_proxy += "," + (os.environ.get("no_proxy", "") or env.get("no_proxy", ""))
    source = ("shell" if os.environ.get("ANTHROPIC_BASE_URL")
              else "settings.json" if env.get("ANTHROPIC_BASE_URL")
              else "launchctl" if lc_base_val
              else "default")
    return {"base_url": base, "no_proxy": no_proxy, "source": source}


def _endpoint_override_check():
    """Детектит ANTHROPIC_BASE_URL override + NO_PROXY masking (#129).

    Если hostname BASE_URL = api.anthropic.com (exact match) → ok (стандартный).
    Иначе → info (WARN). Если домен в NO_PROXY → info «CC ходит напрямую».
    Урок #127: doctor был слеп к endpoint-override → ложный SOCKS5-тест.
    cycle-review #131 C2: exact hostname match (не substring — lookalike-атака).
    """
    cfg = _read_endpoint_config()
    base = cfg["base_url"]
    if not base:
        return {"status": "ok", "detail": f"стандартный endpoint ({_DEFAULT_ANTHROPIC_HOST})"}
    host = (urlparse(base).hostname or "").lower().rstrip(".")
    if host == _DEFAULT_ANTHROPIC_HOST:
        return {"status": "ok", "detail": f"стандартный endpoint ({_DEFAULT_ANTHROPIC_HOST})"}
    no_proxy = cfg["no_proxy"]
    in_no_proxy = any(
        h.strip() and (host == h.strip() or host.endswith("." + h.strip()))
        for h in no_proxy.split(",")
    )
    if in_no_proxy:
        return {"status": "info",
                "detail": f"endpoint override: {base} (в NO_PROXY → CC ходит напрямую, "
                          f"прокси/туннель-проверки нерелевантны)"}
    return {"status": "info", "detail": f"endpoint override: {base} (нестандартный endpoint)"}


# ============================ #200: рассинхрон endpoint local.json ↔ xray config ============================
# Doctor видит РЕАЛЬНЫЙ endpoint (из рабочего xray config), не placeholder из local.json. Когда
# active_node.endpoint_host — test-IP 203.0.113.x (RFC 5737), а рабочий xray config держит реальный
# VPS-address — это рассинхрон источника правды: local.json (canonical) врёт, xray — правда. Канон
# verify-dont-guess (показываем реальный, не placeholder), srouter-is-configurator (local.json=canonical).
# Чек info-only (как endpoint-override): картина для диагностики + подсказка `srouter sync`, не сбой стека.
# Path-константы module-level — чтобы тесты могли перенаправить в tmp через monkeypatch (канон #155/#165).
_ENDPOINT_SYNC_STATE_PATH = None  # None → local_state default (рядом с модулем)
_ENDPOINT_SYNC_XRAY_PATH = local_state.XRAY_CONFIG_PATH


def _endpoint_xray_sync_check(state_path=None, xray_config_path=None):
    """Детектит рассинхрон endpoint_host (local.json) ↔ address (рабочий xray config) — #200.

    Возвращает {status, detail}:
      ok   — endpoint активного узла (canonical state) == address из xray (синхрон);
      warn — рассинхрон: local.json — placeholder test-IP, а xray держит реальный address. detail
             показывает РЕАЛЬНЫЙ endpoint (из xray) и подсказку `srouter sync` (импорт в local.json);
      info — нет xray config (fresh install) / нет активного узла (apply не настроен).
    Канон: local.json = canonical источник, но рабочий xray — runtime-истина. apply-защита (#200
    в install_lib) блокирует перезапись рабочего config placeholder'ом; doctor показывает картину.
    Не бросает (probe-канон: compare_endpoint_with_xray сам fail-soft).
    """
    sp = state_path or _ENDPOINT_SYNC_STATE_PATH
    xp = xray_config_path or _ENDPOINT_SYNC_XRAY_PATH
    cmp = local_state.compare_endpoint_with_xray(state_path=sp, xray_config_path=xp)
    local, xray, placeholder = cmp["local"], cmp["xray"], cmp["placeholder"]
    # нет активного узла в local.json → endpoint не настроен через srouter; sync-чек неприменим
    # (даже если рабочий xray есть — apply не использует local.json без узла). info, не warn.
    if not local:
        return {"status": "info",
                "detail": "нет активного узла / endpoint_host в local.json (sync-чек неприменим)"}
    # нет рабочего xray config → local.json единственный источник (fresh install), дрейфа нет.
    if not xray:
        return {"status": "info",
                "detail": f"endpoint {local}: рабочий xray config отсутствует (fresh install) — "
                          f"sync-чек неприменим, local.json — единственный источник"}
    if cmp["synced"]:
        return {"status": "ok",
                "detail": f"endpoint синхронизирован: local.json == xray == {local}"}
    # рассинхрон: показываем РЕАЛЬНЫЙ endpoint из xray (не placeholder), warn + подсказка sync
    if placeholder:
        return {"status": "warn",
                "detail": (f"рассинхрон: local.json endpoint_host={local} (placeholder TEST-NET), "
                           f"рабочий xray config держит РЕАЛЬНЫЙ address={xray}. "
                           f"Doctor/apply видят реальный ({xray}). Запусти `srouter sync` "
                           f"(импорт address из xray в local.json) или проверь active_node.")}
    # оба реальных, но разные — detect-only, без авто-sync (выбор пользователя)
    return {"status": "warn",
            "detail": (f"рассинхрон: local.json endpoint_host={local}, рабочий xray={xray} "
                       f"(оба реальные). `srouter sync` НЕ применит — реши вручную, какой правдив.")}


# ============================ #143: runtime env живого CC-процесса (ps eww) ============================
# Сценарий #143: CC запустился с ANTHROPIC_BASE_URL / ANTHROPIC_DEFAULT_*_MODEL override; затем
# пользователь сбросил settings.json/shell/launchctl на стандартные, а ЖИВОЙ процесс сохранил env.
# Doctor читает файлы (_read_endpoint_config, #129) → видит «стандартный endpoint», а CC реально
# ходит на подменённый сервер. Файлы слепы к runtime-override — нужно env ЖИВОГО процесса.
# На macOS `ps eww -p <pid>` читает env процесса ТОГО ЖЕ UID (эмпирически подтверждено: живой CC
# отдаёт ANTHROPIC_BASE_URL=api.z.ai + ANTHROPIC_DEFAULT_*_MODEL=glm-*). Чужой/системный UID →
# пустой вывод (fail-soft). НЕ противоречит докстрингу _codex_proxy_probe (:369 уточнён): там env
# чужого codex-процесса не читается → lsof-классификация; здесь — same-UID CC.

# Regex извлекает ANTHROPIC_* vars из вывода `ps eww`. Env разделяется ПРОБЕЛОМ (не \012); [^ ]*
# обрезает значение до следующего пробела. Ключи — только ANTHROPIC_* (наш trust boundary).
_RUNTIME_ENV_RE = re.compile(r"(ANTHROPIC_[A-Z_]+)=([^ ]*)")
# Каждая строка процесса в `ps eww` начинается с PID-цифр (`^[0-9]+ `); заголовок отбрасывается.
# Per-PID секционирование (см. _read_runtime_endpoint_config) — не слить env разных процессов.
_PID_LINE_RE = re.compile(r"^\s*(\d+)\s")


def _read_runtime_endpoint_config():
    """Читает env ЖИВОГО CC-процесса через `ps eww` (#143), per-PID.

    Возвращает {per_pid, pids, readable}:
      - readable=False, pids=[]   — CC не запущен (ps -axo пуст) ИЛИ ps-timeout;
      - readable=False, pids=[..] — CC запущен, но ps eww пуст/timeout/нет ANTHROPIC_* (чужой
        UID/sandbox — PID сохранены для forensics в detail чека);
      - readable=True, per_pid={pid: {KEY: value}} — env прочитан ПО PID'ам.
    per_pid: {pid: {ANTHROPIC_*: value}} для каждого CC PID (включая секреты — doctor доверяет
    тому же UID; фильтрацию секретов делает чек, НЕ эта функция). Per-PID, не merged — иначе
    dict(findall) перезаписал бы дубликаты ключей и ОДИН override-процесс маскировался бы
    standard-процессом (cycle-review Codex: false-negative ровно в сценарии #143 — несколько
    живых CC-сессий штатны). Один ps eww батчем; вывод секционируется по строкам `^[0-9]+ `.
    """
    pids = _claude_code_pids()
    if not pids:
        return {"per_pid": {}, "pids": [], "readable": False}
    # Один ps eww на ВСЕ PID батчем (запятая, как lsof в _claude_proxy_probe). ps eww отдаёт
    # каждую строку процесса с PID в начале — секционируем per-PID, не одним dict().
    r = sys_probe.run([PS, "eww", "-p", ",".join(pids)], timeout=3)
    if r.get("timeout") or not (r.get("out") or "").strip():
        return {"per_pid": {}, "pids": pids, "readable": False}
    per_pid = {}
    cur_pid, cur_lines = "", []
    for line in (r["out"] or "").splitlines():
        m = _PID_LINE_RE.match(line)
        if m:  # новая строка процесса — фиксируем предыдущую
            if cur_pid:
                per_pid[cur_pid] = dict(_RUNTIME_ENV_RE.findall("\n".join(cur_lines)))
            cur_pid, cur_lines = m.group(1), [line]
        elif cur_pid:
            cur_lines.append(line)  # продолжение env того же PID (маловероятно, но устойчиво)
    if cur_pid:
        per_pid[cur_pid] = dict(_RUNTIME_ENV_RE.findall("\n".join(cur_lines)))
    # НИ у одного PID нет ANTHROPIC_* (мусор/неполный env/чужой контекст) — evidence нет → НЕ
    # readable. Иначе чек дал бы ложный ok «стандартный endpoint» без proof (verify-dont-guess).
    if not any(per_pid.values()):
        return {"per_pid": {}, "pids": pids, "readable": False}
    return {"per_pid": per_pid, "pids": pids, "readable": True}


def _runtime_model_override_check():
    """Детектит env-override ЖИВОГО CC и расхождение runtime vs файлов doctor (#143).

    Возвращает {status, detail}. status:
      - "unknown" — CC не запущен / env не читается (fail-soft; info-only, как _claude_proxy_probe idle);
      - "ok"      — ВСЕ CC PID'ы на api.anthropic.com, без model-substitution, без расхождения с файлами;
      - "info"    — ХОТЯ БЫ ОДИН CC PID с override/substitution/расхождением.
    Per-PID агрегация: ЛЮБОЙ override-PID = unsafe runtime (стандартный процесс его НЕ маскирует —
    cycle-review Codex false-negative fix). Сигналы per-PID (накапливаются в detail):
      (a) runtime base_url override на нестандартный хост;
      (b) ANTHROPIC_DEFAULT_* присутствуют → slot-mapping модели подменён (даже при чистом base_url);
      (c) stale-process: runtime override есть, а файлы doctor ЧИСТЫ → ровно сценарий #143
          (живой CC держит override после сброса настроек);
      (d) runtime != files (PID и файлы на разных нестандартных endpoint'ах).
    Канон info-only: НЕ driver (как _endpoint_override_check) — картина для диагностики (#143 п.1+4).
    Security: detail выводит ТОЛЬКО base_url и ANTHROPIC_DEFAULT_* — никогда ANTHROPIC_API_KEY /
    ANTHROPIC_AUTH_TOKEN (doctor доверяет тому же UID, но логи/terminal не должны содержать секреты).
    """
    rt = _read_runtime_endpoint_config()
    if not rt["readable"]:
        detail = ("Claude Code не запущен" if not rt["pids"]
                  else f"env живого CC не читается (PID {','.join(rt['pids'])}) — возможно чужой UID/sandbox")
        return {"status": "unknown", "detail": detail}

    cfg = _read_endpoint_config()  # что видит doctor по файлам/сессии
    files_base = cfg["base_url"]
    files_host = (urlparse(files_base).hostname or "").lower().rstrip(".")
    files_clean = (not files_base) or files_host == _DEFAULT_ANTHROPIC_HOST

    signals = []
    ok_pids = []
    unreadable_pids = []  # PID без распарсенного env (per-process sandbox/permission/partial ps).
    for pid in rt["pids"]:
        env = rt["per_pid"].get(pid, {})
        if not env:
            # этого PID env не прочитан. Override-сигналов по нему нет, но и evidence «standard» тоже
            # нет — override-PID мог быть им (Codex c2: standard-PID не должен маскировать). Не ok.
            unreadable_pids.append(pid)
            continue
        runtime_base = env.get("ANTHROPIC_BASE_URL", "")
        runtime_host = (urlparse(runtime_base).hostname or "").lower().rstrip(".")
        model_keys = {k: v for k, v in env.items() if k.startswith("ANTHROPIC_DEFAULT_")}
        runtime_overridden = bool(runtime_base and runtime_host != _DEFAULT_ANTHROPIC_HOST)
        pid_signals = []
        if runtime_overridden:
            pid_signals.append(f"runtime endpoint: {runtime_base}")
        if model_keys:
            pairs = ", ".join(f"{k}={v}" for k, v in sorted(model_keys.items()))
            pid_signals.append(f"model substitution: {pairs}")
        if runtime_overridden and files_clean:
            pid_signals.append("stale process (override после сброса настроек, runtime != files)")
        if runtime_base and files_base and runtime_base != files_base:
            pid_signals.append(f"runtime != files ({runtime_base} vs {files_base})")
        if pid_signals:
            signals.append(f"PID {pid}: " + "; ".join(pid_signals))
        else:
            ok_pids.append(pid)

    pid_list = ",".join(rt["pids"])
    # Override приоритетнее (info). Но если override не найден и ХОТЯ БЫ ОДИН PID без evidence →
    # unknown: override-PID мог быть непрочитанным, а standard-PID его бы маскировал ложным ok
    # (verify-dont-guess: нет evidence для PID = не ok, Codex c2 false-negative fix). ok — только
    # когда ВСЕ PID прочитаны и standard.
    if not signals:
        if unreadable_pids:
            return {"status": "unknown",
                    "detail": (f"env не прочитан для PID {','.join(unreadable_pids)} "
                               f"(sandbox/права/partial ps) — override-PID мог быть непрочитанным; "
                               f"остальные standard: PID {','.join(ok_pids)}")}
        return {"status": "ok",
                "detail": f"runtime: стандартный endpoint, без model-substitution (PID {pid_list})"}
    detail = f"runtime override (PID {pid_list}): " + " | ".join(signals)
    extras = []
    if ok_pids:
        extras.append(f"остальные standard: PID {','.join(ok_pids)}")
    if unreadable_pids:
        extras.append(f"env не прочитан: PID {','.join(unreadable_pids)}")
    if extras:
        detail += " (" + "; ".join(extras) + ")"
    return {"status": "info", "detail": detail}




# ============================ #134: Desktop App proxy (launchctl getenv) ============================

# launchctl держит ТРИ прокси-ключа; Desktop App наследует все. Инцидент #127: SOCKS5 сидел в
# HTTP_PROXY (не HTTPS_PROXY) → doctor (читая только HTTPS_PROXY) сказал ✅. Обходим все три,
# НЕ угадывая selector приложения (он у Claude/Node/Electron разный) — показываем «как есть».
# NOTE: не то же что CODEX_LAUNCHCTL_ENV в srouter.py — там (key, SOCKS5-value)-пары для Codex
# install; здесь — диагностика Claude Desktop, другая семантика.
LAUNCHCTL_PROXY_KEYS = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY")

def _read_proxy_sources():
    """Читает Desktop App прокси (launchctl gui-домен) + CLI прокси (settings.json) — #134.

    Desktop App видит launchd gui-домен, в отличие от CLI (settings.json). launchctl держит ТРИ
    ключа (LAUNCHCTL_PROXY_KEYS); инцидент #127 — SOCKS5 в HTTP_PROXY. Не угадываем приоритет
    приложения — собираем все найденные «как есть», классификацию делает _desktop_proxy_check.
    cli_proxy (settings.json HTTPS_PROXY) нужен для детекта расхождения CLI vs Desktop (issue #134 п.2) —
    один клиент может работать, другой быть сломан, а без сравнения doctor молчит (#127-класс инцидент).

    cycle-review PR #219 round 2 (Codex, confidence 0.96): голый `launchctl getenv KEY` читает
    caller-context домен, НЕ gui/<uid> (issue #191 — тот же класс). Из SSH/cron/AO-shell это может
    быть НЕ gui-домен → _desktop_proxy_check сверял бы SOCKS5-значение с _CODENV_SOCKS_URL по
    значению из НЕПРАВИЛЬНОГО домена. Делегируем в _read_gui_proxy_env() (`launchctl print gui/<uid>`,
    тот же domain-aware источник, что уже использует _codenv_managed) — единый домен для всей
    codenv-trust цепочки. verifiable=False (timeout/unknown domain) → desktop_keys пуст (fail-closed:
    не выдумываем значения из caller-context, лучше unknown, чем ложный ok/info).

    Возвращает {desktop_keys: {KEY: value}, cli_proxy: str}. Не бросает (fail-soft: import claude_proxy
    — local, сохраняет fail-soft границу health).
    """
    gui = _read_gui_proxy_env(keys_filter=LAUNCHCTL_PROXY_KEYS)
    desktop_keys = gui.get("keys") or {} if gui.get("verifiable") else {}
    try:
        import claude_proxy
        data = claude_proxy._load()
        env = data.get("env", {}) if isinstance(data, dict) else {}
        cli_proxy = env.get("HTTPS_PROXY", "") or os.environ.get("HTTPS_PROXY", "")
    except ImportError as exc:
        _log.debug("claude_proxy недоступен: %s — cli_proxy пуст", exc)
        cli_proxy = ""
    return {"desktop_keys": desktop_keys, "cli_proxy": cli_proxy}


def _codenv_managed(runner=None):
    """codenv LaunchAgent srouter-managed? Маркер в plist (provenance) И реально loaded в launchd.

    Архитектурный конфликт #189/#127: codenv ставит SOCKS5 в gui-домен (нужно ChatGPT.app Rust
    app-server), но тот же SOCKS5 ломает Claude Desktop App (#127). _desktop_proxy_check отличает
    «наш codenv» (намеренный tradeoff → info, не driver-шум) от «чужой корпоративный SOCKS5» (→ down).

    issue #192: маркер на диске один — НЕДОСТАТОЧЕН. Stale-plist сценарий: codenv когда-то стоял,
    потом bootout БЕЗ удаления plist (маркер остаётся навсегда), пользователь ставит ЧУЖОЙ SOCKS5
    вручную — маркер-only читал бы это как managed=True → info, молча маскируя инцидент #127.
    managed = маркер В plist (provenance) AND job РЕАЛЬНО загружен в launchd (install_lib.
    _launchd_is_loaded — домен-осознанный `launchctl print`, rc=0 loaded/113 not-found/иначе
    unknown fail-safe). Только оба условия дают True; unknown (None) НЕ трактуется как loaded —
    не выдумываем managed без доказательства (та же fail-safe семантика, что и сам _launchd_is_loaded).

    runner: опциональный (cmd, timeout) -> {rc, out, err, timeout} для _launchd_is_loaded — по
    умолчанию sys_probe.run (as-is для health.py doctor-чеков), инъекция для тестов.
    Ошибка чтения plist/отсутствие → False (fail-safe: трактуем как чужой → down, не глушим #127).
    """
    try:
        plist = Path.home() / "Library" / "LaunchAgents" / f"{_CODENV_LABEL}.plist"
        has_marker = plist.exists() and _CODENV_MARKER in plist.read_text(encoding="utf-8")
    except (OSError, ValueError):
        # OSError — нет файла/прав; ValueError — UnicodeDecodeError на бинарном/повреждённом plist
        # (codenv plist обычно XML, но может быть binary plutil-convert или битым). НЕ Exception —
        # иначе маскирует баги (канон systemexit-breaks-except-exception-fallback). Fail-safe False.
        return False
    if not has_marker:
        return False
    run = runner if runner is not None else sys_probe.run
    loaded = _launchd_is_loaded(_CODENV_LABEL, domain=_launchd_domain(), runner=run)
    return loaded is True


def _desktop_proxy_check():
    """Прокси Desktop App (launchctl getenv) — SOCKS5 в любом ключе → down (#127/#134).

    Не угадываем selector приложения (у Claude/Node/Electron разные). Для Claude SOCKS5 ломается
    везде (#127 fiasco), HTTP работает. SOCKS5 в любом launchctl-ключе — либо уже ломает, либо
    мина (вспыхнет при смене конфига) → down. Scheme-классификация через urlparse (эталон #127,
    не подстрока — иначе http://socks.example.com даст ложный down). detail перечисляет все
    найденные ключи «как есть».

    issue #189 codenv-aware: SOCKS5 от srouter-managed codenv (для ChatGPT.app Rust app-server) —
    намеренный tradeoff (лечит ChatGPT.app #189, ломает Claude Desktop App #127). doctor показывает
    факт в detail, но НЕ роняет вердикт (status="info") — иначе нормальная установка с codenv вечно
    degraded (шум, как PR #135 для PF). Чужой SOCKS5 (не codenv) → по-прежнему down (#127-инцидент).

    Расхождение settings.json (CLI) vs launchctl HTTPS_PROXY (Desktop) → warn (issue #134 п.2):
    один клиент может работать, другой сломан, а без этого сравнения doctor молчит (#127-класс).
    down (уже сломанный SOCKS5) важнее warn (потенциальное расхождение) — проверяется первым.
    """
    src = _read_proxy_sources()
    keys = src["desktop_keys"]
    cli_proxy = src.get("cli_proxy", "")
    if not keys:
        return {"status": "unknown",
                "detail": "launchctl proxy не задан — Desktop App идёт напрямую (ok для NO_PROXY-доменов, не защищён PF для остальных)"}
    # SOCKS-scheme в ЛЮБОМ ключе → down (Claude Code/Desktop App через SOCKS не умеют, #127).
    # urlparse по scheme, не подстрока — канон loose-validator (health.py:313).
    socks_keys = {k: v for k, v in keys.items()
                  if urlparse(v).scheme.lower() in {"socks", "socks5", "socks5h"}}
    if socks_keys:
        bad = ", ".join(f"{k}={v}" for k, v in socks_keys.items())
        # issue #189: srouter-managed codenv SOCKS5 — намеренный (лечит ChatGPT.app). info, не driver-шум.
        # cycle-review PR #219 (Codex, confidence 0.93): _codenv_managed()=True доказывает только,
        # что job com.srouter.codenv ЗАГРУЖЕН — НЕ то, что именно он записал ЭТИ SOCKS5-значения.
        # Кто-то другой может параллельно прописать чужой SOCKS5 в тот же launchctl gui-домен ключ,
        # пока codenv тоже загружен — тот же класс инцидента #127. Сверяем КАЖДОЕ найденное SOCKS5-
        # значение с каноническим codenv endpoint (_CODENV_SOCKS_URL) — только полное совпадение
        # всех ключей даёт info; любое расхождение — down (не глушим потенциально чужой SOCKS5).
        if _codenv_managed() and all(v == _CODENV_SOCKS_URL for v in socks_keys.values()):
            return {"status": "info",
                    "detail": (f"SOCKS5 в launchctl ({bad}) = srouter codenv (#189 для ChatGPT.app Rust "
                               f"app-server). Claude Desktop App ломается на SOCKS5 (#127), но CC CLI "
                               f"через ~/.claude/settings.json не затронут. Намеренный tradeoff.")}
        return {"status": "down",
                "detail": f"SOCKS5 в launchctl ({bad}) — Desktop App UnsupportedProxyProtocol (#127)"}
    # Расхождение CLI (settings.json) vs Desktop (launchctl HTTPS_PROXY) — оба заданы и различны.
    desktop_https = keys.get("HTTPS_PROXY", "")
    if cli_proxy and desktop_https and cli_proxy != desktop_https:
        return {"status": "warn",
                "detail": f"CLI={cli_proxy}, Desktop={desktop_https} — расхождение прокси "
                          f"(один клиент может работать, другой — нет)"}
    # Только HTTP-прокси, без расхождения → ok, перечисляем все найденные ключи.
    found = ", ".join(f"{k}={v}" for k, v in keys.items())
    return {"status": "ok", "detail": f"Desktop App proxy (launchctl): {found}"}


# ============================ #189: ChatGPT.app Rust app-server proxy (launchctl gui-env) =========

# codenv LaunchAgent label/marker — ДУБЛИРОВАНЫ из codex_wrappers.py (CODEX_ENV_LABEL/MARKER :74-75).
# health.py НЕ импортирует codex_wrappers (тот сам импортирует health — вышел бы цикл; плюс CLI-слой
# тащит argparse/apply_install). Парity-гвард: при смене маркера в codex_wrappers.py — обновить тут.
# Указатель на srouter.py устарел: PR #258 (a177c6f) перенёс определения в codex_wrappers.py,
# srouter.py их только реэкспортирует (cycle-review PR #262).
_CODENV_LABEL = "com.srouter.codenv"
_CODENV_MARKER = "srouter-managed-codex-env-v1"

# Канонический codenv SOCKS5-endpoint — тот же литерал, что dashboard_common.SOCKS_PROXY_URL /
# srouter.py._CODEX_PROXY_URL. cycle-review PR #219 (Codex, confidence 0.93): _codenv_managed()=True
# доказывает только «job зарегистрирован», НЕ что именно он записал ЭТО SOCKS5-значение — сверка
# со значением обязательна, иначе чужой SOCKS5 в том же launchctl-ключе маскируется под codenv (#127).
_CODENV_SOCKS_URL = f"socks5h://127.0.0.1:{XRAY_PORT}"


def _read_gui_proxy_env(runner=None, *, keys_filter=LAUNCHCTL_PROXY_KEYS):
    """Прокси в launchd GUI-домене (где codenv ставит SOCKS5) — через `launchctl print gui/<uid>`.

    launchctl getenv читает ТОЛЬКО caller-context (`Usage: getenv <key>` — НЕ принимает домен), молча
    игнорируя домен-аргумент → из SSH/cron/AO-shell даёт НЕ gui, а из GUI-терминала совпадает случайно.
    codenv-факт = факт о GUI-домене (видит ChatGPT.app launchd-process), не о терминале doctor'а →
    единственный домен-осознанный источник = `launchctl print gui/<uid>` блок `environment = {...}`.
    Эмпирически подтверждено (issue #191): unsetenv gui/<uid> KEY тоже игнорирует домен — arg1
    трактуется как имя переменной, arg2 (реальный ключ) молча отбрасывается.

    runner: опциональный (cmd, timeout) -> {rc, out, err, timeout} — для переиспользования вызывающим
    кодом с собственным инъектируемым runner (srouter._remove_launchctl_env, issue #191). По умолчанию
    sys_probe.run (as-is для health.py doctor-чеков).

    Возвращает {keys: {KEY: value}, verifiable: bool}. timeout → verifiable=False (fail-closed: не
    различимо «пусто» vs «не смогли спросить», не выдумываем false-down). keys_filter ограничивает
    парсинг нужными env-ключами (по умолчанию LAUNCHCTL_PROXY_KEYS — HTTPS_PROXY/HTTP_PROXY/ALL_PROXY).
    """
    run = runner if runner is not None else sys_probe.run
    domain = f"gui/{os.getuid()}"
    lc = run([LAUNCHCTL, "print", domain], 3)
    if lc.get("timeout"):
        return {"keys": {}, "verifiable": False}  # fail-closed
    keys = {}
    in_env = False
    found_block = False  # блок environment найден? Иначе out без блока (несуществующий домен/иной
                        # формат) → НЕ верим, не выдумываем false-down «codenv снят» (fail-closed).
    for line in (lc.get("out") or "").splitlines():
        stripped = line.strip()
        if stripped == "environment = {":
            in_env = True
            found_block = True
            continue
        if in_env:
            # конец блока — строка из одного '}' (отступ launchctl print).
            if stripped == "}":
                break
            # формат: '\t\tKEY => value' (как отдаёт launchctl print).
            if " => " in stripped:
                k, _, v = stripped.partition(" => ")
                k = k.strip()
                if k in keys_filter and v.strip():
                    keys[k] = v.strip()
    if not found_block:
        # out без блока environment (несуществующий домен: launchctl print gui/<bad> отдаёт rc=0 +
        # 'Bad request. Could not find domain'). Не различимо «домен недоступен» от «codenv снят»
        # → unknown (fail-closed), НЕ false-down.
        return {"keys": {}, "verifiable": False}
    return {"keys": keys, "verifiable": True}


# ============================ #250: состояние codenv launchd-job (первоисточник) =================
#
# Инцидент 2026-07-30: job загружен, plist с диска удалён, ProgramArguments указывает в стёртый
# AO-worktree → exit 127 при КАЖДОМ из 1419 запусков (RunAtLoad + StartInterval=300), Codex молча
# без SOCKS5. doctor молчал: _codenv_managed читал АРТЕФАКТ (plist-файл + маркер), а не СОСТОЯНИЕ
# job'а. Первоисточник — `launchctl print gui/<uid>/<label>`: path / state / runs / last exit code /
# arguments. Канон verify-dont-guess (probe-semantics-from-primary-source).

# Эфемерный каталог AO-worktree. Постоянный LaunchAgent, указывающий туда, — всегда мина: worktree
# удаляется, job остаётся и падает. Тот же литерал — в guard установки (codex_wrappers).
_AO_WORKTREE_MARK = "/.ao/data/worktrees/"


def _in_ao_worktree(path):
    """Путь ведёт внутрь эфемерного AO-worktree? Единая точка для guard установки и детектора.

    cycle-review round 2 (Codex, critical): сравнение было регистрозависимым. Эмпирически на APFS
    по умолчанию `.AO/data/worktrees` и `.ao/data/worktrees` — ОДИН каталог (`Path.samefile` →
    True), но `resolve()` сохраняет исходное написание, поэтому подстрочная сверка промахивалась:
    install через альтернативное написание молча зашивал эфемерный путь в постоянный LaunchAgent
    (та самая мина issue #250), а детектор его не подсвечивал. Сверяем casefold'ом — решение по
    свойствам ФС, а не по написанию строки (канон loose-validator-recurring-leak).

    resolve(strict=False) нормализует '..' и делает путь абсолютным ДАЖЕ для несуществующего файла,
    поэтому вердикт не зависит ни от факта существования, ни от регистра, ни от '..'-сегментов.

    НЕ бросает ни на каком входе — контракт, а не почти-контракт (cycle-review round 2, /review):
    `Path(path)` кидает TypeError на None/int/bytes РАНЬШЕ, чем отработает except вокруг resolve().
    Оба текущих вызывающих защищены, но это ОБЩИЙ предикат двух подсистем, и исключение отсюда
    ушло бы в check_all — fail-open по всему стеку. Нераспознанный вход → False: «не доказано, что
    worktree». Для guard'а это fail-open-сторона, поэтому оба вызывающих обязаны давать реальный
    путь (Path/str), а не полагаться на этот fallback.
    """
    try:
        resolved = Path(path).resolve(strict=False)
    except (OSError, ValueError, RuntimeError):
        # Путь есть, но ОС/парсер его не осилили — решаем по сырой строке (ниже, регистронезависимо).
        return _AO_WORKTREE_MARK in str(path).casefold()
    except TypeError:
        _log.debug("_in_ao_worktree: не путь (%s) — не worktree", type(path).__name__)
        return False
    # Точное совпадение написания — worktree без вопросов (быстрый путь, большинство случаев).
    if _AO_WORKTREE_MARK in str(resolved):
        return True
    # Иначе написание отличается регистром. Регистр решает НЕ строка, а сама ФС (cycle-review
    # round 3, Codex): macOS поддерживает case-sensitive APFS, где '.AO' и '.ao' — РАЗНЫЕ каталоги,
    # и безусловный casefold объявил бы канонический '/.AO/...'-чекаут эфемерным worktree →
    # guard отказал бы в установке, doctor нарисовал бы ложный down на здоровой машине (канон #135).
    # Спрашиваем первоисточник: тот же ли это физически каталог, что канонический AO-worktrees-корень.
    if _AO_WORKTREE_MARK not in str(resolved).casefold():
        return False
    # Ищем предка, чьё написание заканчивается worktrees-маркером, и спрашиваем ФС: он ли это.
    canonical = Path.home() / ".ao" / "data" / "worktrees"
    for ancestor in resolved.parents:
        if not f"{ancestor}/".casefold().endswith(_AO_WORKTREE_MARK):
            continue
        try:
            # Оба существуют и это ОДИН каталог → просто иначе записан (case-insensitive том).
            return ancestor.samefile(canonical)
        except OSError:
            # Одного из каталогов нет / нет прав → ФС не опровергла совпадение. Fail-closed:
            # для guard'а «не доказано, что другой» безопаснее трактовать как worktree — цена
            # ошибки здесь отказ в установке, а не молча зашитая мина (issue #250).
            return True
    return False


# Хвост stderr codenv-скрипта: там причина падения прописана буквально ('No such file or directory'
# с полным путём). Канон noisy-log-better-than-no-log — detail без причины бесполезен оператору.
_CODENV_STDERR_TAIL_BYTES = 2048


def _codenv_default_stderr_path():
    """Дефолтный StandardErrorPath codenv — из того же генератора, что рендерит шаблон.

    cycle-review round 2 (/review): дефолт был захардкожен как '/tmp/codenv.err' (взят из текста
    инцидента), тогда как шаблон подставляет `__SROUTER_LOG_ERR__` → InstallEnv.log_err
    (~/Library/Logs/...). Мёртвый дефолт: когда `launchctl print` не отдал 'stderr path', читался
    несуществующий файл и причина падения молча терялась из detail — канон
    config-contract-is-the-generator (путь берём у генератора, не переписываем его руками).
    """
    try:
        import install_config
        # from_env(), НЕ InstallEnv(): реальный CLI строит env именно так, и именно его log_err
        # рендерится в plist. InstallEnv() дал бы дефолты класса, игнорируя SROUTER_LOG_DIR —
        # при кастомном log-dir doctor читал бы ЧУЖОЙ лог и молча терял причину падения
        # (cycle-review round 3, Codex; каноны more-options-better + config-contract-is-the-generator).
        return str(install_config.InstallEnv.from_env().log_err)
    except (ImportError, OSError, ValueError, TypeError, AttributeError) as exc:
        _log.debug("install_config недоступен (%s) — дефолт stderr codenv неизвестен", exc)
        return ""


def _codenv_stderr_tail(path=None, *, limit=_CODENV_STDERR_TAIL_BYTES):
    """Хвост stderr-лога codenv (по умолчанию StandardErrorPath из шаблона). Не бросает → ''."""
    try:
        target = path or _codenv_default_stderr_path()
        if not target:
            return ""
        data = Path(target).read_bytes()[-limit:]
        return data.decode("utf-8", errors="replace").strip()
    except (OSError, ValueError):
        # Нет файла / нет прав / битый путь — отсутствие лога не должно ронять чек (fail-soft).
        return ""


def _codenv_plist_is_managed():
    """srouter-managed codenv plist лежит на диске? (только provenance, БЕЗ launchd-состояния.)

    Доказательство «установка была»: маркер в plist. Отличает «codenv не ставили» (опционален —
    молчим) от «ставили, а job мёртв» (авария #250). Провенанс-часть _codenv_managed, вынесенная
    отдельно: тому нужны И маркер, И loaded — здесь как раз случай «маркер есть, loaded нет».
    Ошибка чтения/битый plist → False (fail-safe: не выдумываем установку без доказательства).
    """
    try:
        plist = Path.home() / "Library" / "LaunchAgents" / f"{_CODENV_LABEL}.plist"
        return plist.exists() and _CODENV_MARKER in plist.read_text(encoding="utf-8")
    except (OSError, ValueError):
        # OSError — нет файла/прав; ValueError — UnicodeDecodeError на бинарном/битом plist
        # (та же граница, что в _codenv_managed: один файл не должен ронять doctor).
        return False


def _codenv_job_state(runner=None):
    """Состояние launchd-job com.srouter.codenv по `launchctl print gui/<uid>/<label>`.

    Первоисточник, не артефакт: plist-файл на диске может быть удалён, пока job живёт в памяти
    launchd (осиротевший job) — и наоборот. Разбираем реальный формат launchctl print (проверен на
    живой машине, `com.srouter.dashboard`): табулированные `key = value` + блок `arguments = { ... }`
    со строками-аргументами по одной на строку.

    Возвращает dict, НЕ бросает:
      loaded: True (rc=0, вывод распознан) / False (rc=113 service-not-found) / None (unknown)
      path: str — plist-путь, как его помнит launchd ('' если поля нет)
      state: str — 'running' / 'not running' / 'spawn scheduled' / ''
      runs: int|None, last_exit_code: int|None — None = поля НЕТ (нет данных), НЕ 0
      arguments: list[str] — ProgramArguments как их видит launchd
      stderr_path: str — StandardErrorPath (для хвоста причины)

    last_exit_code=None НАМЕРЕННО не подменяется нулём: 0 = «доказанно завершился успешно»,
    None = «нет данных». Подмена вернула бы fail-open (молчание при неизвестном состоянии).
    """
    empty = {"loaded": None, "path": "", "state": "", "runs": None, "last_exit_code": None,
             "arguments": [], "stderr_path": ""}
    run = runner if runner is not None else sys_probe.run
    try:
        r = run([LAUNCHCTL, "print", f"{_launchd_domain()}/{_CODENV_LABEL}"], 5)
    except (OSError, ValueError, TypeError) as exc:
        # runner — инъекция; сбой запуска launchctl не должен ронять doctor (fail-soft граница).
        _log.debug("launchctl print codenv не выполнен: %s", exc)
        return empty
    # cycle-review PR #262 (Codex): try охватывал только ВЫЗОВ, а разбор результата был снаружи —
    # runner, вернувший не-словарь (None/строка), ронял `.get` → AttributeError сквозь весь
    # check_all (общий doctor/watchdog путь → fail-open по всему стеку). Валидируем форму ответа.
    if not isinstance(r, dict):
        _log.debug("launchctl print codenv: runner вернул %s, не словарь", type(r).__name__)
        return empty
    # rc-семантика ОБЯЗАНА совпадать с install_plist._launchd_is_loaded (rc=0 загружен / rc=113
    # not-found — единственный достоверный False / иначе unknown fail-safe). Мы не вызываем его
    # напрямую: он отдаёт голый tristate, а нам нужен САМ вывод того же `launchctl print` для
    # разбора state/runs/last exit code/arguments — вызов _launchd_is_loaded означал бы ВТОРОЙ
    # идентичный subprocess за прогон doctor'а. Парity-гвард (как _CODENV_LABEL ниже): при смене
    # tristate-контракта в install_plist — обновить здесь; тест-гвард на совпадение семантики —
    # tests/test_health_codenv_job.py::test_codenv_job_state_rc_semantics_match_launchd_is_loaded.
    if r.get("timeout"):
        return empty  # unknown, НЕ false-down (probe-канон)
    rc = r.get("rc")
    if rc == _LAUNCHCTL_SERVICE_NOT_FOUND:
        return {**empty, "loaded": False}  # 113 — единственный достоверный «не загружен»
    if rc != 0:
        return empty
    out = r.get("out") or ""
    st = {**empty, "loaded": None}
    in_args = False
    args = []
    # Глубина вложенности. cycle-review PR #262: парсер строил `key = value` ПЛОСКО, срезая отступы,
    # а реальный `launchctl print` содержит вложенные блоки (`resource coalition = {`,
    # `jetsam coalition = {`, `event triggers = {`) со СВОИМИ `state`/`runs`/`last exit code`. Они
    # идут ПОСЛЕ top-level полей и затирали их: на живом `com.srouter.dashboard` истинное
    # `state = spawn scheduled` читалось как `active` (state коалиции, к job'у отношения не имеет).
    # Критично вдвойне — `state` служит гейтом loaded=True: обрывок, заканчивающийся внутри
    # coalition-блока, выдал бы себя за полноценно загруженный job (fail-open).
    # Берём ТОЛЬКО поля первого уровня (depth == 1: внутри `gui/<uid>/<label> = {`).
    depth = 0
    for line in out.splitlines():
        stripped = line.strip()
        if in_args:
            if stripped == "}":
                in_args = False
                depth -= 1
                continue
            if stripped:
                args.append(stripped)
            continue
        if stripped == "}":
            depth -= 1
            # cycle-review round 2 (/review): на закрывающей скобке top-level блока depth падал в 0,
            # и СЛЕДУЮЩИЙ блок-сосед снова входил на depth==1 → его `state`/`last exit code`
            # читались как поля нашего job'а (утечка 99 вместо 0). Живой `launchctl print` отдаёт
            # один top-level блок, так что случай недостижим из настоящего вывода — но парсер
            # первоисточника обязан быть строг: после закрытия своего блока читать больше нечего.
            if depth <= 0:
                break
            continue
        if stripped.endswith("= {"):
            depth += 1
            # `arguments = {` парсим как список строк-аргументов; прочие блоки просто пропускаем.
            if stripped == "arguments = {" and depth == 2:
                in_args = True
            continue
        if depth != 1:
            continue  # вложенный блок (coalition/triggers) — его поля НЕ про наш job
        key, sep, value = stripped.partition(" = ")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if key == "path":
            st["path"] = value
        elif key == "state":
            st["state"] = value
        elif key == "stderr path":
            st["stderr_path"] = value
        elif key in ("runs", "last exit code"):
            field = "runs" if key == "runs" else "last_exit_code"
            try:
                st[field] = int(value)
            except ValueError:
                # launchctl печатает 'last exit code = (never exited)' и подобное — не число,
                # значит данных нет. None, не выдуманный 0 (fail-closed).
                st[field] = None
    st["arguments"] = args
    # rc=0 сам по себе НЕ доказывает загруженный job: `launchctl print gui/<bad>/<label>` отдаёт
    # rc=0 + 'Bad request.' Требуем узнаваемый вывод — иначе unknown (не выдумываем ни down, ни ok
    # из мусора; тот же fail-closed, что found_block в _read_gui_proxy_env).
    #
    # cycle-review PR #262 (Codex): прежнее условие принимало ЛЮБОЕ одно поле, включая одинокий
    # `path`. Усечённый вывод (только path) давал loaded=True → все проверки падений пропускались
    # → «здоров». Неполный первоисточник — это «не смогли спросить», а не «спросили, всё хорошо».
    # `state` обязателен: это поле launchd печатает для КАЖДОГО реально загруженного job'а, и
    # именно оно отличает живую запись от обрывка вывода.
    if st["state"]:
        st["loaded"] = True
    return st


# Пауза перед перепроверкой «job выгружен». Окно reload в install_plist — до ~3.5с
# (_BOOTOUT_SETTLE_MAX_WAIT 2.0 + 3 x _BOOTSTRAP_RETRY_DELAY 0.5). Ждём с запасом, но не настолько,
# чтобы затормозить doctor: перепроверка происходит ТОЛЬКО в редкой ветке «managed plist + rc=113».
_CODENV_RELOAD_SETTLE_WAIT = 4.0


def _codenv_unloaded_is_persistent(runner=None, *, wait=_CODENV_RELOAD_SETTLE_WAIT):
    """«Выгружен» — устойчивое состояние, а не окно reload? Перепроверка после паузы.

    cycle-review round 3 (Codex): единичный снимок rc=113 не отличает мёртвый codenv от штатной
    переустановки — install_plist._launchd_reload делает bootout → poll → bootstrap, и в этом окне
    plist уже на диске, а job'а ещё нет. Ложный down там шумел бы на ЗДОРОВОЙ машине (канон #135)
    и мог бы дёрнуть watchdog ложным recovery.

    True только если job ПОВТОРНО не найден (rc=113) после паузы, перекрывающей окно reload.
    Любой другой исход (job появился / launchctl недоступен / таймаут) → False: не эскалируем
    в down без подтверждения (fail-safe, та же семантика, что и у остального детектора).
    """
    time.sleep(wait)
    st = _codenv_job_state(runner=runner)
    return st["loaded"] is False


def _codenv_job_check(runner=None):
    """codenv LaunchAgent реально ЖИВ? По состоянию job'а, не по наличию plist-файла (issue #250).

    Исходы (ТДД issue #250):
      down    — job загружен, но: last exit code != 0 (падает; runs подсвечивает флап) ИЛИ plist
                на диске отсутствует (осиротевший job переживает удаление своего plist) ИЛИ
                ProgramArguments указывает на несуществующий файл ИЛИ путь внутри AO-worktree
                (эфемерный каталог как цель постоянного LaunchAgent — всегда мина установки).
      ok      — job загружен, exit ДОКАЗАННО 0, скрипт на месте: канон #135 — здоровый codenv
                НЕ шумит. Именно ok, а не info: _print_report рендерит КАЖДЫЙ info-чек жёлтым ⚠️
                (`mark = "⚠️" if c.get("info")`), т.е. info для здорового вернуло бы ровно тот шум,
                который #135 запрещает — просто в другом цвете (cycle-review PR #262, Codex).
      unknown — job не загружен (codenv опционален — не авария), launchctl недоступен/таймаут,
                вывод не распознан ИЛИ exit-код неизвестен. Никогда не бросает (probe-канон).

    down обязан быть DRIVER: 1419 падений в тишине — ровно то, что этот чек закрывает
    (noisy-log-better-than-no-log). Без codenv Codex после ребута идёт напрямую за GFW —
    утечка реального IP (fail-closed-proxy-down).
    """
    st = _codenv_job_state(runner=runner)
    if st["loaded"] is not True:
        if st["loaded"] is False:
            # cycle-review round 2 (Codex, critical): rc=113 БЕЗУСЛОВНО давал «опционален» → info.
            # Но srouter-managed plist на диске ДОКАЗЫВАЕТ, что установка была: значит это не «не
            # ставили», а «поставили, и job выгружен/не забутстрапился». Зеркало осиротевшего job'а
            # (там job без plist, тут plist без job'а) — и ровно тот класс, что ловит issue #250:
            # codenv сконфигурирован, но мёртв → после ребута Codex молча без SOCKS5.
            # Provenance-граница (#112): ЧУЖОЙ plist без маркера — не наша установка, молчим.
            # Окно reload — НЕ авария (cycle-review round 3, Codex): install пишет plist, затем
            # bootout → poll → bootstrap (install_plist._launchd_reload), и МЕЖДУ ними состояние
            # ровно «managed plist есть, rc=113». Окно до ~3.5с, а watchdog бежит раз в ~20с и
            # /health дёргается в любой момент → штатная переустановка давала бы degraded/503 и
            # ложное recovery-уведомление. Uninstall имеет такое же окно (bootout→unlink).
            # Down — только для УСТОЙЧИВОГО состояния: перепроверяем после короткой паузы.
            if _codenv_plist_is_managed() and _codenv_unloaded_is_persistent(runner=runner):
                return {"status": "down",
                        "detail": (f"codenv установлен, но НЕ загружен: srouter-managed plist на диске "
                                   f"({Path.home() / 'Library' / 'LaunchAgents' / f'{_CODENV_LABEL}.plist'}), "
                                   f"а job в launchd отсутствует — bootstrap не прошёл или job выгружен. "
                                   f"Codex останется без SOCKS5 после ребута → прямой трафик за GFW. "
                                   f"Лечение: srouter install (codenv) — перезагрузит LaunchAgent")}
            return {"status": "unknown",
                    "detail": f"codenv LaunchAgent {_CODENV_LABEL} не загружен в launchd "
                              f"(опционален — нужен только для ChatGPT.app Rust app-server, #189)"}
        return {"status": "unknown",
                "detail": f"состояние {_CODENV_LABEL} не определено (launchctl print недоступен/таймаут)"}
    facts = f"state={st['state'] or '?'}, runs={st['runs'] if st['runs'] is not None else '?'}"
    # 1. Падает. Хвост stderr — причина буквально ('No such file or directory' + полный путь).
    exit_code = st["last_exit_code"]
    if exit_code is not None and exit_code != 0:
        tail = _codenv_stderr_tail(st["stderr_path"] or None)
        cause = f" Причина (stderr): {tail[-300:]}" if tail else ""
        flap = " ФЛАП (падает при каждом запуске)" if (st["runs"] or 0) > 5 else ""
        return {"status": "down",
                "detail": (f"codenv падает: last exit code = {exit_code} ({facts}).{flap} "
                           f"Codex останется без SOCKS5 после ребута → прямой трафик за GFW."
                           f"{cause} Лечение: srouter install (codenv)")}
    # 2. Осиротевший job: живёт в launchd, plist с диска удалён (bootout его не снял).
    plist = Path.home() / "Library" / "LaunchAgents" / f"{_CODENV_LABEL}.plist"
    if not plist.exists():
        return {"status": "down",
                "detail": (f"осиротевший codenv job: загружен в launchd ({facts}), но plist на диске "
                           f"отсутствует ({plist}) — переустановка его не заменит. "
                           f"Лечение: launchctl bootout {_launchd_domain()}/{_CODENV_LABEL}, "
                           f"затем srouter install")}
    # 3. ProgramArguments → эфемерный worktree / несуществующий файл (корень exit 127).
    script = st["arguments"][-1] if st["arguments"] else ""
    if script:
        # _in_ao_worktree — та же единая точка, что и в guard установки (codex_wrappers):
        # resolve('..'/относительных) + casefold. Guard и детектор ОБЯЗАНЫ видеть worktree
        # одинаково, иначе одна сторона молчит там, где другая бьёт тревогу.
        if _in_ao_worktree(script):
            return {"status": "down",
                    "detail": (f"codenv указывает в эфемерный AO-worktree: {script} ({facts}). "
                               f"Worktree удаляется — job останется и начнёт падать с exit 127 "
                               f"(мина установки, issue #250). Лечение: srouter install из "
                               f"канонического репозитория")}
        if not Path(script).exists():
            return {"status": "down",
                    "detail": (f"codenv ProgramArguments указывает на несуществующий файл: {script} "
                               f"({facts}) — следующий запуск даст exit 127, Codex без SOCKS5. "
                               f"Лечение: srouter install (codenv)")}
    # 4. Здоров — но только если exit-код ДОКАЗАННО 0. cycle-review PR #262 (Codex): `None` («нет
    # данных»: launchctl не напечатал поле или напечатал '(never exited)') раньше проваливался сюда,
    # и detail ЛГАЛ «last exit code = 0» — «не смогли проверить» выдавалось за «проверили, здоров».
    # Ровно тот fail-open, который докстринг _codenv_job_state обещал исключить.
    if exit_code is None:
        return {"status": "unknown",
                "detail": (f"codenv загружен ({facts}), но launchctl не сообщил last exit code — "
                           f"здоровье не подтверждено (job мог ни разу не завершиться). "
                           f"Проверить вручную: launchctl print {_launchd_domain()}/{_CODENV_LABEL}")}
    return {"status": "ok",
            "detail": f"codenv LaunchAgent загружен и здоров ({facts}, last exit code = 0): {script or plist}"}


def _codex_app_proxy_check():
    """ChatGPT.app Rust app-server без прокси (codenv снят/битый) → down DRIVER (issue #189).

    Эмпирика (verify, lsof per-process): ChatGPT.app = Electron-оболочка над Rust-бинарником. Rust
    app-server (/Applications/ChatGPT.app/.../codex, основной WS к wss://chatgpt.com) НЕ уважает
    системный SOCKS (Rust reqwest без SystemConfiguration), берёт ТОЛЬКО env SOCKS5 из launchd gui-домена
    (codenv LaunchAgent). codenv снят/битый (plist-шаблон с placeholder'ами после #185 деактивации
    install) → gui-env пуст → Rust app-server напрямую → GFW рвёт ('failed to connect... TimedOut').

    Чек: (1) App-codex активен (ps по _is_codex_app_comm); (2) gui-env через _read_gui_proxy_env.
      status="down"    — App активен, gui-env пуст (codenv не загружен) — DRIVER;
      status="warn"    — App активен, gui-env только HTTP (privoxy рвёт WS #120) — DRIVER;
      status="ok"      — App активен, gui-env SOCKS5 (codenv работает) — DRIVER;
      status="unknown" — App не запущен ИЛИ gui-env не верифицируем — info-only (fail-closed).
    App-PID здесь, НЕ в _codex_proxy_probe (TUI-чек исключил App-PID, чтобы не давать ложный mixed/down
    на нерелевантном PID — баг «❌ на VSCode PID 56748»).
    """
    # 1. App-codex процессы активны?
    r = sys_probe.run([PS, "-axo", "pid=,comm="], timeout=3)
    if r.get("timeout"):
        return {"status": "unknown", "source": "n/a", "detail": "timeout ps"}
    app_pids = []
    for line in (r.get("out") or "").splitlines():
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        pid_s, comm = parts[0].strip(), parts[1].strip()
        if pid_s.isdigit() and _is_codex_binary_comm(comm) and _is_codex_app_comm(comm):
            app_pids.append(pid_s)
    if not app_pids:
        return {"status": "unknown", "source": "n/a",
                "detail": "ChatGPT.app/Codex.app не запущен — Rust app-server не активен"}

    # 2. gui-env (codenv).
    gui = _read_gui_proxy_env()
    if not gui.get("verifiable"):
        return {"status": "unknown", "source": "n/a",
                "detail": f"launchctl gui-env не отвечает — ручная проверка: "
                          f"launchctl getenv gui/$(id -u) HTTPS_PROXY (App PID {','.join(app_pids)})"}
    keys = gui.get("keys") or {}
    pid_hint = f"PID {','.join(app_pids)}"

    if not keys:
        return {"status": "down", "source": "gui-env",
                "detail": (f"ChatGPT.app Rust app-server без прокси: launchctl gui-env пуст — codenv "
                           f"не загружен/битый ({pid_hint}). WS к chatgpt.com рвётся (GFW). "
                           f"Восстановить: srouter install (codenv)")}
    socks_keys = {k: v for k, v in keys.items()
                  if urlparse(v).scheme.lower() in {"socks", "socks5", "socks5h"}}
    if socks_keys:
        found = ", ".join(f"{k}={v}" for k, v in socks_keys.items())
        # cycle-review #190 round 2: ok требует POSITIVE SOCKS5 evidence (route['socks']). gui-env SOCKS5
        # ≠ live-маршрут App-PID: setenv не ретроактивен (stale App direct), либо App выбрал privoxy 8118,
        # либо idle/нет ESTABLISHED, либо lsof сбой (rc≠0) — всё это НЕ ok (false-ok, round-1/2 finding).
        route = _app_pids_route(app_pids)
        if route.get("external"):
            ext = ",".join(sorted(route["external"]))
            return {"status": "down", "source": "runtime",
                    "detail": (f"ChatGPT.app Rust app-server НАПРЯМУЮ (gui-env SOCKS5 есть, но App PID {ext} "
                               f"держит external-сокеты) — STALE App: запущен ДО codenv, setenv не ретроактивен. "
                               f"Полностью перезапусти ChatGPT.app (Cmd+Q из Dock, не закрыть окно). "
                               f"codenv gui-env: {found}")}
        if route.get("privoxy"):
            pv = ",".join(sorted(route["privoxy"]))
            return {"status": "warn", "source": "runtime",
                    "detail": (f"ChatGPT.app Rust app-server через privoxy 8118 (PID {pv}), не SOCKS5 — "
                               f"long-lived WS порвётся (#120). STALE App: перезапусти ChatGPT.app (Cmd+Q). "
                               f"codenv gui-env: {found}")}
        if not route.get("verifiable") or not route.get("socks"):
            # lsof timeout/rc≠0 ИЛИ нет positive SOCKS5-сокета (idle/нет ESTABLISHED к 10808) —
            # не можем доказать ok → unknown (fail-closed). gui-env SOCKS5 недостаточен.
            return {"status": "unknown", "source": "runtime",
                    "detail": (f"App-PID runtime-маршрут не подтверждён SOCKS5 (gui-env SOCKS5: {found}, "
                               f"{pid_hint}, lsof socks={','.join(sorted(route.get('socks', set()))) or 'нет'}). "
                               f"Ручная проверка: lsof -nP -p {','.join(app_pids)}")}
        return {"status": "ok", "source": "runtime",
                "detail": (f"ChatGPT.app Rust app-server через SOCKS5 (lsof PID {','.join(sorted(route['socks']))} "
                           f"-> 10808, codenv gui-env: {found})")}
    # gui-env задан, но без SOCKS5 (только HTTP/privoxy) → warn (long-lived WS порвётся #120).
    found = ", ".join(f"{k}={v}" for k, v in keys.items())
    return {"status": "warn", "source": "gui-env",
            "detail": (f"ChatGPT.app Rust app-server через HTTP прокси без SOCKS5 ({found}, {pid_hint}) — "
                       f"privoxy рвёт long-lived WS (#120). codenv должен ставить SOCKS5")}


def _app_pids_route(app_pids):
    """Runtime-маршрут App-PID по lsof-сокетам (как _codex_proxy_probe, но для App-PID).

    cycle-review #190 round 1/2: _codex_app_proxy_check не может полагаться только на gui-env (setenv
    не ретроактивен → stale App). lsof по App-PID классифицирует РЕАЛЬНЫЙ маршрут: external-ESTABLISHED
    (direct) / SOCKS5 10808 / privoxy 8118 (рвёт WS #120). ok требует positive SOCKS5 (round 2).
    Возвращает {external, socks, privoxy: set(pids), verifiable: bool}. timeout ИЛИ rc≠0 → verifiable=False
    (сбой lsof ≠ доказательство маршрута → fail-closed unknown, не ok).
    """
    lr = sys_probe.run([LSOF, "-nP", "-p", ",".join(app_pids)], timeout=3)
    if lr.get("timeout") or lr.get("rc") not in (0, None):
        return {"external": set(), "socks": set(), "privoxy": set(), "verifiable": False}
    external, socks, privoxy = set(), set(), set()
    for line in (lr.get("out") or "").splitlines():
        if "TCP" not in line or "ESTABLISHED" not in line:
            continue
        fields = line.split()
        pid = fields[1] if len(fields) > 1 else ""
        if f"->127.0.0.1:{XRAY_PORT}" in line:
            socks.add(pid)
        elif f"->127.0.0.1:{PRIVOXY_PORT}" in line:
            privoxy.add(pid)  # HTTP-прокси рвёт long-lived WS (#120)
        elif "->127.0.0.1:" not in line:
            external.add(pid)  # external ESTABLISHED — direct, без localhost-прокси
    return {"external": external, "socks": socks, "privoxy": privoxy, "verifiable": True}


# ============================ #185: scoped SOCKS5 для codex через VSCode http.proxy ============================

def _vscode_proxy_check():
    """Scoped SOCKS5 для codex-расширения openai.chatgpt через VSCode `http.proxy` (#185).

    Расширение openai.chatgpt запускает свой codex-binary (мимо wrapper), наследует HTTP_PROXY=privoxy
    из ~/.claude/settings.json → privoxy рвёт WS (#96/#120). Scoped-фикс: VSCode http.proxy=socks5h://10808
    → расширение строит HTTP_PROXY/HTTPS_PROXY В ENV codex-процессА (verify из extension.js), CC не трогает.
    Чек читает user-settings.json (Code+Cursor) и сверяет http.proxy.

    Возвращает {status, detail}:
      ok      — хотя бы один существующий settings.json содержит http.proxy == socks5h://10808;
      unknown — ни одного settings.json нет (редактор не установлен) — info-only (как desktop-proxy);
      down    — http.proxy есть, но НЕ socks5 (privoxy/HTTP рвёт WS #120, или чужой корпоративный) — driver.
    Чек ВСЕГДА info-only (как endpoint-override): VSCode может быть не установлен, srouter-stack от этого
    не падает. ok/down — картина scoped-маршрута codex для диагностики, не driver агрегированного вердикта.
    """
    try:
        import vscode_proxy
    except ImportError as exc:
        _log.debug("vscode_proxy недоступен: %s — check пропущен", exc)
        return {"status": "unknown", "detail": "vscode_proxy недоступен — check пропущен"}
    st = vscode_proxy.status()
    paths = st.get("paths") or {}
    present = {p: info for p, info in paths.items() if info.get("present")}
    if not present:
        return {"status": "unknown",
                "detail": "VSCode/Cursor user-settings не найдены — редактор не установлен (scoped http.proxy неприменим)"}
    # Хотя бы один с правильным SOCKS5 → ok (пользователь может пользоваться любым редактором).
    socks_ok = [p for p, info in present.items()
                if urlparse(info.get("proxy", "")).scheme.lower() in {"socks", "socks5", "socks5h"}]
    if socks_ok:
        names = ", ".join(Path(p).parent.parent.name for p in socks_ok)  # 'Code' / 'Cursor'
        return {"status": "ok", "detail": f"VSCode http.proxy=SOCKS5 10808 ({names}) — codex расширения гонит через xray (#185)"}
    # http.proxy задан, но НЕ socks5 → down (privoxy/HTTP рвёт WS, или чужой прокси мимо xray).
    bad = ", ".join(f"{Path(p).parent.parent.name}={info['proxy']}" for p, info in present.items() if info.get("proxy"))
    if bad:
        return {"status": "down",
                "detail": f"VSCode http.proxy НЕ SOCKS5 ({bad}) — codex рвёт WS через privoxy/чужой (#120)"}
    # Файлы есть, http.proxy не задан совсем → unknown (scoped не настроен, но не сломан — info-only).
    return {"status": "unknown",
            "detail": "VSCode http.proxy не задан — codex расширения наследует privoxy из env (рвёт WS #120), scoped не активирован"}


# ============================ #199: gh/git VPS-независимый dev-workflow ============================

# Подсказка-текст для VPS-независимого gh/git — единый литерал, чтобы doctor и README говорили
# одно (канон — единый источник правды). РАЗДЕЛЯЕТ стеки: gh (Go, env-прокси) и git (git-config
# scoped proxy) — это РАЗНЫЕ источники прокси, им нужны РАЗНЫЕ команды (cycle-1 FIX Codex critical).
#
# Эмпирика (verify 2026-07-27): github TCP напрямую открыт (GFW не режет TCP); gh Go-стек обходит
# GFW TLS. НО прокси-источников два:
#   1. env: srouter ставит И uppercase (HTTP_PROXY), И lowercase (http_proxy) — Go httpproxy
#      fallback читает оба регистра. Снимать надо ВСЕ: HTTP_PROXY/http_proxy, HTTPS_PROXY/https_proxy,
#      ALL_PROXY/all_proxy, NO_PROXY/no_proxy.
#   2. git-config: `http.https://github.com.proxy` (git_proxy.enable, SOCKS5 xray 10808 — #130) —
#      env -u его НЕ трогает (verify: `git config --get-urlmatch` после env -u всё ещё показывает
#      прокси активным). Снимается `git -c http.https://github.com.proxy= <cmd>` (переопределение
#      на лету, пустое).
# gh repo clone делегирует внутреннему git → scoped git-config применяется к clone (не чистый gh-путь).
GH_DIRECT_HINT = (
    "gh (Go-стек) и git-over-https — РАЗНЫЕ стеки прокси, разные команды (verify 2026-07-27):\n"
    "  • gh: `env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY -u http_proxy -u https_proxy "
    "-u all_proxy -u no_proxy gh ...` — снять env-прокси ОБА регистра (Go fallback на lowercase).\n"
    "  • git over https: env -u НЕ трогает scoped git-config `http.https://github.com.proxy` → "
    "`git -c http.https://github.com.proxy= fetch|pull|push` (пустое значение перекрывает config).\n"
    "  • gh repo clone делегирует git → scoped config применяется; clone VPS-независим ТОЛЬКО через "
    "`git -c http.https://github.com.proxy=` (или `gh api`, или ssh:22 — github SSH открыт напрямую).\n"
    "github TCP напрямую открыт; gh Go-стек обходит GFW TLS (curl/git LibreSSL — нет). VPS-независимо (#199)."
)


def _github_direct_check():
    """Подсказка VPS-независимого dev-workflow для gh/git (issue #199). info-only ВСЕГДА.

    Диагноз #199 (verify, эмпирически): github доступен напрямую через gh — Go HTTP/TLS-стек gh
    обходит GFW TLS-блокировку (в отличие от curl/git на LibreSSL + системном resolver). Но если в
    ~/.gitconfig включён scoped git-прокси `http.https://github.com.proxy → privoxy 8118` (git_proxy),
    то git pull/push идёт ЧЕРЕЗ прокси → зависит от VPS: мёртвый VPS = git timeout (выглядело как
    «флап gh»). Подсказка РАЗДЕЛЯЕТ стеки (cycle-1 FIX): gh → снять env-прокси (оба регистра) через
    `env -u`; git-over-https → env -u НЕ трогает git-config, нужен `git -c http.https://github.com.proxy=`.

    Предикт = статичный git-config (verify-don't-guess — не догадки о таймаутах, а проверяемый
    факт конфигурации). Чек info-only ВСЕГДА (как endpoint-override): git-proxy-настройка — это
    scoped-конфиг, не сбой стека; warn/ok/unknown НЕ роняют агрегированный вердикт — это картина
    для диагностики dev-workflow, не driver. Канон: verify-don't-guess, srouter-critical-infra-24-7
    (dev-workflow не должен зависеть от VPS — github-операции переживают смерть VPS).

    Возвращает {status, detail}:
      ok      — git-config github-proxy выключен (github уже идёт напрямую);
      warn    — git-config ВКЛЮЧЁН (scoped github → privoxy) → git зависит от VPS, подсказка env -u;
      unknown — git_proxy.status unknown/ошибка (git config timeout/недоступен).
    Не бросает (probe-канон).
    """
    try:
        import git_proxy
        st = git_proxy.status()
    except (ImportError, RuntimeError, OSError, ValueError) as exc:
        # ImportError — модуль недоступен; RuntimeError/OSError/ValueError — сбой status() (fail-soft).
        _log.debug("git_proxy недоступен/сбой: %s — check пропущен", exc)
        return {"status": "unknown", "detail": "git_proxy недоступен — check пропущен"}
    # isinstance ДО .get: git_proxy.status может вернуть None/не-dict (мусор) — .get упал бы
    # (probe-канон: чек не бросает). git_proxy.status при timeout отдаёт {status:"unknown"} — это
    # НЕ «git-proxy выключен» (enabled=False без status — другое; ниже разделяем).
    if not isinstance(st, dict) or st.get("status") == "unknown":
        return {"status": "unknown",
                "detail": "git config недоступен (timeout) — github-direct check пропущен"}
    enabled = bool(st.get("enabled"))
    if not enabled:
        return {"status": "ok",
                "detail": "git github-proxy выключен — github идёт напрямую (VPS-независимо). "
                          "Если gh/git timeout через прокси: " + GH_DIRECT_HINT}
    return {"status": "warn",
            "detail": f"git github-proxy ВКЛЮЧЁН ({st.get('proxy') or 'xray SOCKS5 10808'}) → "
                      f"git pull/push зависит от VPS. " + GH_DIRECT_HINT}


def check_all(*, active_claude=False):
    """Все проверки стека. {status: ok|degraded|down, checks: [{name, ok, detail?, info?}]}.

    status: ok (всё живо) / degraded (часть жива) / down (всё мертво). Не бросает.
    claude-proxy check имеет смысл только когда CC запущен: если unknown (CC не работает) — он
    добавляется в checks как info (не driver), чтобы не ронять вердикт без причины.
    """
    checks = []
    checks.append({"name": f"privoxy ({PRIVOXY_PORT})", "ok": _port_up(PRIVOXY_PORT)})
    checks.append({"name": f"xray ({XRAY_PORT})", "ok": _port_up(XRAY_PORT)})
    checks.append({"name": f"dashboard ({DASHBOARD_PORT})", "ok": _port_up(DASHBOARD_PORT)})
    tun_ok, tun_detail, tun_vendor_outage = _tunnel_up()
    # #207: vendor outage (оба вендора HTTP 5xx = канал жив, вендоры лежат) структурно помечаем
    # в check["category"] (как vps_check["info"] / lp_check["info"] ниже) — _print_report читает
    # поле, а не парсит detail-строку. Каскад #201: ...→сеть→VPS→туннель→vendor outage. При vendor
    # outage туннель driver-down, но VPS/local-proxy чеки ниже остаются info (они живы).
    tun_check = {"name": "туннель (api.anthropic.com через прокси)", "ok": tun_ok, "detail": tun_detail}
    if tun_vendor_outage:
        tun_check["category"] = "vendor-outage"
    checks.append(tun_check)
    # #203: активный сетевой интерфейс/маршрут — ПЕРВЫЙ чек каскада (нет сети → VPS → локальный
    # прокси → ...). Эпик #201 ситуация 1: doctor не различал «нет сети» (Wi-Fi/eth выкл, нет
    # default route) от «VPS мёртв» — TCP-probe VPS при мёртвой сети тоже timeout → ложный диагноз.
    # _network_interface_up ПЕРЕД VPS-probe перехватывает «нет сети» и даёт точную причину. DRIVER
    # только когда сети НЕТ (up=False): это совсем другая причина, чем «VPS мёртв» — подключи интернет.
    # up=True → info-only (картина, не роняет вердикт, как endpoint-override/versions). Каскад:
    # нет сети подавляет VPS-чек (info, не нагромождает «VPS мёртв» поверх «нет сети»). Канон:
    # verify-dont-guess (прямая причина), srouter-critical-infra-24-7 (точный диагноз = быстрая починка).
    net = _network_interface_up()
    net_check = {"name": "сеть (default route / активный интерфейс)",
                 "ok": net["up"], "detail": net["detail"]}
    if net["up"]:
        net_check["info"] = True  # сеть есть — не driver (как endpoint-override)
    checks.append(net_check)
    # #205: DNS-резолв — ВТОРОЙ чек каскада (после «нет сети» #203, ПЕРЕД VPS-probe #196). Эпик #201
    # ситуация 4: сломанный DNS (упал dnsmasq/resolver) → _upstream_vps_reachable ложно «VPS мёртв»
    # (port_open сам резолвит hostname → gaierror → unreachable). _dns_up ПЕРЕД VPS-probe перехватывает:
    # DNS не резолвит → точная причина «проверь резолвер», VPS-чек подавляется (info, не нагромождает
    # «VPS мёртв» поверх «DNS сломан»). DRIVER только когда DNS НЕ резолвит (up=False). up=True →
    # info-only (картина, не роняет вердикт, как net-up/endpoint-override). Каскад: нет сети
    # подавляет DNS (бессмысленно резолвить без сети), DNS подавляет VPS (gaierror ≠ VPS-смерть).
    # Канон: verify-dont-guess (прямая причина — resolve-ошибка), probe-semantics-from-primary-source.
    dns = _dns_up()
    dns_check = {"name": "DNS (резолв тестового домена)",
                 "ok": dns["up"], "detail": dns["detail"]}
    if dns["up"] or not net["up"]:
        # DNS работает → info-only (картина). НЕТ СЕТИ → тоже info (подавлен): резолв без сети
        # бессмысленен, первичная причина уже «нет сети» (net_check driver) — не нагромождаем
        # «DNS сломан» поверх «нет сети» (канон каскада #203→#205, как VPS-чек подавляется нет-сети).
        dns_check["info"] = True
    checks.append(dns_check)
    # #194: прямой TCP-probe до upstream VPS endpoint (минуя прокси). Различение «VPS мёртв» vs
    # «локальный прокси упал» — оба дают connection-failed через прокси, но прямой TCP доказывает
    # состояние VPS. DRIVER только когда СЕТЬ ЕСТЬ И DNS РЕЗОЛВИТ И туннель fail И VPS down
    # (гарантирует DOWN — VPS-смерть = critical-infra #194, не DEGRADED). VPS ok при туннель-fail → info «проблема в локальном
    # прокси, VPS жив» (туннель-чек уже driver). Туннель ok → info (VPS-доступность не релевантна).
    # placeholder TEST-NET / нет узла → info (картина, не сбой). Канон: verify-don't-guess.
    vps = _upstream_vps_reachable()
    vps_check = {"name": "upstream VPS (TCP-коннект до endpoint, минуя прокси)",
                 "ok": True, "info": True, "detail": vps["detail"]}
    if net["up"] and dns["up"] and not tun_ok and vps["status"] == "down":
        # VPS мёртв + туннель fail + сеть есть + DNS работает → driver: усиливаем до DOWN.
        vps_check["ok"] = False
        vps_check["info"] = False
    checks.append(vps_check)
    # #204: локальный прокси (privoxy/xray) service-status — различение «локальный прокси упал»
    # (#201 ситуация 3) от «VPS мёртв» (#194) / «туннель сломан». _port_up чеки выше (privoxy/xray)
    # уже driver по TCP-listen; этот чек добавляет ЯВНЫЙ signal (зомби: port-open + service
    # not-running — orphan держит порт, launchd-сервис упал). DRIVER когда туннель fail (проблема
    # актуальна); туннель ok → info-only (порты живы, сервис-статус не роняет вердикт когда канал и
    # так работает). Канон: verify-don't-guess — service-status launchctl print, не brew services info
    # (последний слеп к protected privoxy system-daemon → ложный зомби на нормальной установке).
    lp = _local_proxy_up()
    lp_check = {"name": "локальный прокси (privoxy/xray service-status)",
                "ok": lp["status"] == "ok", "detail": lp["detail"]}
    if tun_ok:
        # туннель жив → сервис-статус не driver (порт-чеки выше уже валидны). Зомби при живом канале
        # — картина (например orphan на старом порту), не сбой: показываем в detail, не роняем.
        lp_check["info"] = True
    elif lp["status"] == "down" and vps["status"] == "ok":
        # туннель fail + VPS жив + локальный прокси down → ТОЧНАЯ причина: прокси упал, не VPS.
        # Усиливаем до driver-down (ситуация #3 #201). VPS жив (#194) исключает upstream-смерть.
        lp_check["ok"] = False
    elif lp["status"] == "down":
        # туннель fail + прокси down, но VPS статус не ok (info/down/placeholder) — прокси-down
        # всё равно driver (туннель fail уже driver выше; этот чек объясняет причину локально).
        lp_check["ok"] = False
    checks.append(lp_check)
    # Claude Code РЕАЛЬНО использует прокси? runtime (lsof), не файл. unknown (CC не запущен) →
    # info-only, не driver: проверять «CC юзает прокси» бессмысленно, если CC не работает.
    cp = _claude_proxy_probe()
    cp_check = {"name": "claude-proxy (HTTPS_PROXY для CLI)",
                "ok": cp["status"] == "ok", "detail": cp["detail"]}
    if cp["status"] == "unknown":
        cp_check["info"] = True  # не участвует в агрегации (drivers ниже фильтруют info)
    checks.append(cp_check)
    if active_claude:
        active = _claude_transport_probe()
        active_check = {"name": "Claude Code transport (real CLI)",
                        "ok": active["status"] == "ok", "detail": active["detail"]}
        if active["status"] == "unknown":
            active_check["info"] = True
        checks.append(active_check)
    # endpoint-override (#129): info-only ВСЕГДА (как endpoint-xray-sync/vscode-proxy/gh-direct
    # ниже) — «стандартный endpoint» это картина, не сигнал живости прокси/сети. #225: eo_check
    # раньше был driver с ok захардкоженным в True (никогда не False) — единственный вечно-живой
    # driver держал вердикт на degraded, даже когда все реальные driver-чеки (порты/туннель/прокси)
    # мертвы. status у _endpoint_override_check() — только ok/info (никогда down/warn), значит он
    # органически не может сигналить о сбое стека — driver-роль была ошибкой агрегации.
    eo = _endpoint_override_check()
    eo_check = {"name": "endpoint (ANTHROPIC_BASE_URL)", "ok": True, "info": True, "detail": eo["detail"]}
    checks.append(eo_check)
    # endpoint-xray sync (#200): рассинхрон active_node (local.json) ↔ рабочий xray config.
    # info-only ВСЕГДА (как endpoint-override) — картина для диагностики + подсказка `srouter sync`,
    # не сбой стека (прокси может работать через реальный xray, пока local.json — placeholder).
    # warn (рассинхрон) показываем в detail, но НЕ driver: apply-защита (#200 в install_lib) —
    # настоящая fail-closed граница от перезаписи; doctor лишь подсвечивает расхождение.
    exs = _endpoint_xray_sync_check()
    exs_check = {"name": "endpoint (local.json ↔ xray sync)", "ok": exs["status"] != "warn",
                 "info": True, "detail": exs["detail"]}
    checks.append(exs_check)
    # Desktop App proxy (#134): SOCKS5 в launchctl = broken Desktop App; warn = CLI/Desktop
    # расхождение (driver degraded — реальный сигнал несоответствия, не info-only).
    dp = _desktop_proxy_check()
    dp_check = {"name": "desktop proxy (launchctl)", "ok": dp["status"] == "ok", "detail": dp["detail"]}
    # unknown (launchctl пуст) ИЛИ info (codenv SOCKS5 — намеренный tradeoff #189, не инцидент #127)
    # → info-only, не driver (не роняет вердикт на нормальной установке с codenv).
    if dp["status"] in ("unknown", "info"):
        dp_check["info"] = True
    checks.append(dp_check)
    # Codex-маршрут (#120): warn (privoxy 8118) — driver degraded (WS порвётся); down — driver;
    # mixed — driver (часть сессий ломаные); unknown (codex не запущен / lsof-timeout / idle) — info-only,
    # не роняет вердикт (как claude-proxy). ok — driver (всё ок).
    cx = _codex_proxy_probe()
    cx_check = {"name": "codex-proxy (маршрут TUI)",
                "ok": cx["status"] == "ok", "detail": cx["detail"]}
    if cx["status"] == "unknown":
        cx_check["info"] = True
    elif cx["status"] == "warn":
        cx_check["ok"] = False  # privoxy-сессия — degraded, но не «всё мертво»
    checks.append(cx_check)
    # ChatGPT.app Rust app-server proxy (#189): App-codex без прокси (codenv снят/битый) → down DRIVER.
    # App-PID исключён из cx_check выше (TUI-чек) — здесь отдельный driver для gui-env/codenv-состояния.
    # unknown (App не запущен / gui-env не верифицируем) — info-only (fail-closed, как claude-proxy).
    # НЕ под active_claude gate — чек лёгкий (ps + launchctl getenv), нужен в /health и watchdog.
    ap = _codex_app_proxy_check()
    ap_check = {"name": "codex-app-proxy (ChatGPT.app gui-env SOCKS5)",
                "ok": ap["status"] == "ok", "detail": ap["detail"]}
    if ap["status"] == "unknown":
        ap_check["info"] = True
    elif ap["status"] == "warn":
        ap_check["ok"] = False  # App на privoxy — degraded (WS порвётся #120)
    checks.append(ap_check)
    # codenv launchd-job (#250): job загружен, но падает (exit != 0) / осиротел (plist удалён) /
    # указывает на несуществующий путь → down DRIVER. Реальный инцидент: 1419 падений подряд в
    # тишине — doctor читал plist-артефакт, а не состояние job'а. Без codenv Codex после ребута
    # идёт напрямую за GFW (fail-closed-proxy-down) → это настоящий сбой стека, не info-шёпот.
    # ok (здоровый job) — обычный ✅ БЕЗ info-флага: _print_report рендерит любой info-чек жёлтым
    # ⚠️, что для здоровой установки и есть запрещённый каноном #135 шум (cycle-review PR #262).
    # unknown (job не загружен — codenv опционален / launchctl недоступен / exit-код неизвестен) —
    # info-only: не роняет вердикт, но и не притворяется подтверждённо здоровым.
    cj = _codenv_job_check()
    cj_check = {"name": "codenv LaunchAgent (job launchd)",
                "ok": cj["status"] != "down", "detail": cj["detail"]}
    if cj["status"] == "unknown":
        cj_check["info"] = True
    checks.append(cj_check)
    # VSCode scoped SOCKS5 (#185): codex-расширение openai.chatgpt через http.proxy. info-only ВСЕГДА
    # (как endpoint-override) — VSCode может быть не установлен, srouter-stack от этого не падает.
    # down (http.proxy=privoxy/чужой — рвёт WS) показываем в detail, но НЕ driver: это scoped-диагностика
    # одного клиента (codex-расширение), не общий вердикт стека. Runtime-маршрут codex ловит cx_check выше.
    vp = _vscode_proxy_check()
    vp_check = {"name": "codex vscode-proxy (http.proxy)",
                "ok": vp["status"] != "down", "info": True, "detail": vp["detail"]}
    checks.append(vp_check)
    # gh/git VPS-независимый dev-workflow (#199): github доступен напрямую через gh (Go-стек обходит
    # GFW TLS); scoped git-proxy → privoxy делает git pull/push VPS-зависимым. info-only ВСЕГДА (как
    # endpoint-override) — это образовательная подсказка для dev-workflow, не сбой стека: warn
    # (git-proxy ВКЛ) подсказывает env -u, не роняя вердикт. Лёгкий чек (git config --get, как git_proxy).
    gh = _github_direct_check()
    gh_check = {"name": "gh/git direct (github env -u)",
                "ok": gh["status"] != "warn", "info": True, "detail": gh["detail"]}
    checks.append(gh_check)
    # Установленные codex/claude-code binary на диске (#145): инвентаризация, info-only ВСЕГДА
    # (несколько версий — ранний сигнал конфликта #135, не сбой стека). unknown (ничего не установлено)
    # тоже info — не роняет вердикт. Doctor показывает картину, не угадывает.
    # cycle-review round 1: disk inventory запускает npm/brew/which/<binary> --version — НЕ лёгкий,
    # выполняет arbitrary PATH-discovered binaries. check_all шарится между doctor (active_claude=True),
    # /health (dashboard.py:990 «Мгновенный, лёгкий») и watchdog (раз в ~20с). Инвентаризация —
    # ТОЛЬКО doctor-путь, иначе лёгкий healthcheck получит DoS-поверхность + overhead.
    if active_claude:
        # #143 runtime env живого CC: детект ANTHROPIC_BASE_URL/DEFAULT_*_MODEL override + stale-process
        # (живой CC держит override после сброса настроек — файлы doctor слепы). info-only (как
        # endpoint-override) — картина для диагностики (#143 п.1+4), НЕ driver. Под active_claude gate:
        # ps eww по живым PID + чтение env = overhead/поверхность, не для лёгкого /health/watchdog.
        rmo = _runtime_model_override_check()
        # info-only БЕЗУСЛОВНО (как _installed_versions_check/_privoxy_log_observability_check ниже):
        # диагностика подмены модели — картина, не сбой стека; ни ok, ни info, ни unknown не driver.
        rmo_check = {"name": "runtime env (ANTHROPIC_* живого CC)",
                     "ok": rmo["status"] == "ok", "info": True, "detail": rmo["detail"]}
        checks.append(rmo_check)
        iv = _installed_versions_check()
        iv_check = {"name": "версии (codex/claude-code на диске)",
                    "ok": True, "info": True, "detail": iv["detail"]}
        checks.append(iv_check)
        # Privoxy-log observability (#152): молчалив ли privoxy? debug включён? logfile пишет?
        # info-only (не driver) — картина для диагностики флапа к github через 8118; WARN в detail.
        plo = _privoxy_log_observability_check()
        plo_check = {"name": "privoxy-log (observability)",
                     "ok": plo["status"] != "warn", "info": True, "detail": plo["detail"]}
        checks.append(plo_check)
        # PF codex kill-switch (#186): info-only ВСЕГДА (не driver) — незамкнутая граница на
        # нормальных установках (codex под user-UID 501, sudo -u = follow-up) — НЕ роняет вердикт
        # (избегаем шума как PR #135). ok только при реальном процессе под UID 503.
        # gate под active_claude (doctor-only): dscl + ps = overhead/поверхность, не для лёгкого
        # /health/watchdog (как _installed_versions_check / _runtime_model_override_check).
        ci = _codex_isolation_check()
        ci_check = {"name": "codex-isolation (PF kill-switch)",
                    "ok": ci["status"] == "ok", "detail": ci["detail"]}
        if ci["status"] == "info":
            ci_check["info"] = True
        checks.append(ci_check)
        # #206 GFW per-domain: github режется GFW избирательно (z.ai проходит напрямую) — различение
        # от «VPS мёртв»/«туннель fail». info-only ВСЕГДА (как _github_direct_check) — картина для
        # конкретного домена, не сбой стека: режется → подсказка «нужен прокси/VPS для домена», не
        # роняет вердикт. gate под active_claude (doctor-only): _direct_domain_probe делает прямой
        # curl к github/z.ai = сетевой overhead/поверхность, не для лёгкого /health/watchdog (как
        # _installed_versions_check/_codex_isolation_check). Каскад #201: ...→VPS→прокси→GFW per-domain.
        gfw = _gfw_domain_check()
        gfw_check = {"name": "GFW per-domain (github vs z.ai прямой curl)",
                     "ok": gfw["status"] != "gfw", "info": True, "detail": gfw["detail"]}
        checks.append(gfw_check)
        # #197 direct-first: какие candidate-домены (z.ai BUILTIN + user direct_domains) идут
        # напрямую (NO_PROXY) — переживают смерть VPS. info-only ВСЕГДА (как GFW-чек выше) — картина,
        # не сбой стека. gate под active_claude (doctor-only): direct_first.detect() делает прямой
        # curl per-domain = сетевой overhead, не для лёгкого /health/watchdog (тот же паттерн, что GFW).
        df = _direct_first_check()
        df_check = {"name": "direct-first (NO_PROXY reachable)",
                    "ok": df["status"] == "ok", "info": True, "detail": df["detail"]}
        checks.append(df_check)
    drivers = [c for c in checks if not c.get("info")]
    all_ok = all(c["ok"] for c in drivers)
    any_ok = any(c["ok"] for c in drivers)
    status = "ok" if all_ok else ("degraded" if any_ok else "down")
    # #194: VPS-смерть — абсолютный триггер DOWN (минуя degraded). Даже при живых локальных
    # портах мёртвый upstream VPS = весь стек бесполезен (нет куда гонять трафик). Таблица issue:
    # privoxy/xray open + VPS unreachable + туннель fail = upstream VPS мёртв (DOWN, не DEGRADED).
    # Канон: srouter-critical-infra-24-7 + fail-closed. Без этого — живые порты маскируют
    # VPS-смерть в degraded (регрессия #194). vps-driver ok=False = VPS точно мёртв (не placeholder/нет-узла — те info).
    # #203: net["up"] гвард — при мёртвой сети VPS-down НЕ абсолютный DOWN-override (TCP-timeout =
    # следствие «нет сети», не «VPS мёртв»). «Нет сети» уже driver через net_check выше.
    if net["up"] and dns["up"] and not tun_ok and vps["status"] == "down":
        status = "down"
    return {"status": status, "checks": checks}


def _notify(msg, sound="Glass"):
    """macOS-нотификация через osascript + audit trail в лог (#109).

    Логируем ВСЕГДА (даже если osascript не сработал) — audit trail «что пушалось и когда».
    osascript — best-effort (не роняет watchdog при сбое).
    """
    from datetime import datetime
    try:
        WATCHDOG_NOTIFY_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(WATCHDOG_NOTIFY_LOG, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} [{sound}] {msg}\n")
    except OSError as exc:
        _log.warning("watchdog notify-log write failed: %s — audit trail неполон", exc)
    try:
        sys_probe.run([OSASCRIPT, "-e",
                       f'display notification "{msg}" with title "srouter" sound name "{sound}"'],
                      timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:  # noqa: BLE001 — best-effort нотификация,
        # не роняет watchdog при сбое osascript (top-level defensive fallback #109).
        _log.debug("osascript notify failed: %s — нотификация пропущена, watchdog продолжает", exc)


def _launchd_field(output, key):
    """Первое scalar-поле из `launchctl print`; nested endpoint state не перетирает root state."""
    match = re.search(rf"^\s*{re.escape(key)}\s*=\s*(.*?)\s*;?\s*$", output or "", re.MULTILINE)
    return match.group(1) if match else None


def _launchd_int(output, key):
    value = _launchd_field(output, key)
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _launchd_job_snapshot(label, *, plist_path=None, domain=None):
    """Компактный forensic snapshot launchd job без домыслов о причине отсутствия.

    KeepAlive-restart сохраняет загруженный label и plist, но меняет pid/runs/last-exit. Внешний
    `bootout` даёт loaded=false; последующий `brew services start` обычно меняет plist mtime/inode и
    сбрасывает runs. Эта разница нужна для #132: строка startup banner сама по себе её не показывает.
    """
    domain = domain or f"gui/{os.getuid()}"
    if plist_path is None:
        if domain == "system":
            plist_path = Path("/Library/LaunchDaemons") / f"{label}.plist"
        else:
            plist_path = Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"
    else:
        plist_path = Path(plist_path)

    result = sys_probe.run(
        [LAUNCHCTL, "print", f"{domain}/{label}"],
        timeout=3,
    )
    output = result.get("out") or ""
    loaded = result.get("rc") == 0 and bool(output.strip())

    plist = {"exists": False, "mtime_ns": None, "inode": None}
    try:
        stat = plist_path.stat()
        plist = {"exists": True, "mtime_ns": stat.st_mtime_ns, "inode": stat.st_ino}
    except OSError:
        pass

    error = ""
    if not loaded:
        error = (result.get("err") or ("timeout" if result.get("timeout") else "not loaded"))[:240]

    return {
        "label": label,
        "domain": domain,
        "loaded": loaded,
        "state": _launchd_field(output, "state") if loaded else None,
        "pid": _launchd_int(output, "pid") if loaded else None,
        "runs": _launchd_int(output, "runs") if loaded else None,
        "last_exit_code": _launchd_field(output, "last exit code") if loaded else None,
        "last_terminating_signal": (
            _launchd_field(output, "last terminating signal") if loaded else None
        ),
        "plist": plist,
        "error": error,
    }


def _collect_launchd_lifecycle():
    """Privoxy снимается в фактическом domain; xray остаётся стабильным user-контролем."""
    protected = privoxy_system.protection_present()
    return {
        "privoxy": _launchd_job_snapshot(
            privoxy_system.SYSTEM_LABEL if protected else "homebrew.mxcl.privoxy",
            plist_path=(privoxy_system.DEFAULT_LAYOUT.launchdaemon_path if protected else None),
            domain=("system" if protected else None),
        ),
        "xray": _launchd_job_snapshot("homebrew.mxcl.xray"),
    }


def _record_watchdog_lifecycle():
    """Записать JSONL только при изменении launchd lifecycle; первый снимок — тихий baseline.

    Best-effort: forensic logging не меняет health status и никогда не роняет watchdog. Даже если
    stop/start целиком попал между watchdog ticks, изменение plist mtime/inode или pid/runs остаётся
    видимым в следующем снимке.
    """
    try:
        current = _collect_launchd_lifecycle()
    except (OSError, subprocess.SubprocessError, AttributeError, KeyError) as exc:
        _log.debug("_collect_launchd_lifecycle failed: %s — lifecycle-снимок пропущен", exc)
        return

    previous = None
    try:
        if WATCHDOG_LIFECYCLE_STATE.exists():
            previous = json.loads(WATCHDOG_LIFECYCLE_STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _log.debug("watchdog lifecycle state read failed: %s — baseline считается пустым", exc)
        previous = None

    if previous is not None and previous != current:
        try:
            from datetime import datetime

            WATCHDOG_LIFECYCLE_LOG.parent.mkdir(parents=True, exist_ok=True)
            event = {
                "timestamp": datetime.now().astimezone().isoformat(),
                "previous": previous,
                "current": current,
            }
            with open(WATCHDOG_LIFECYCLE_LOG, "a", encoding="utf-8") as log_file:
                log_file.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
        except OSError as exc:
            _log.warning("watchdog lifecycle-log write failed: %s — событие не записано", exc)

    try:
        WATCHDOG_LIFECYCLE_STATE.parent.mkdir(parents=True, exist_ok=True)
        WATCHDOG_LIFECYCLE_STATE.write_text(
            json.dumps(current, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )
    except OSError as exc:
        _log.warning("watchdog lifecycle-state write failed: %s — следующий прогон может ложно "
                     "считать это baseline", exc)


def _print_report(result):
    """Человекочитаемый отчёт check_all (для doctor). Вывод в stdout."""
    print(f"srouter health: {result['status'].upper()}\n")
    for c in result["checks"]:
        # info-only check: endpoint-override (WARN), claude-proxy idle (нейтрально).
        # ⚠️ — жёлтый треугольник (привлекает внимание, но не ❌): override/idle, а не «всё мертво».
        mark = "⚠️" if c.get("info") else ("✅" if c["ok"] else "❌")
        detail = f" ({c['detail']})" if c.get("detail") else ""
        print(f"  {mark} {c['name']}{detail}")
    if result["status"] != "ok":
        print("\nЧто проверить:")
        failed_names = " ".join(c["name"] for c in result["checks"] if not c["ok"] and not c.get("info"))
        if "сеть" in failed_names:
            # #203: нет активного интерфейса/маршрута — самая первичная причина (до VPS/прокси).
            # Не «VPS мёртв» и не «локальный прокси» — подключи интернет. Чинить первым.
            print("  • сеть: нет активного сетевого интерфейса/маршрута — подключи интернет (Wi-Fi/eth).")
            print("    Это НЕ «VPS мёртв» и НЕ «локальный прокси упал» — сначала восстановь сеть.")
        if "privoxy" in failed_names:
            if privoxy_system.protection_present():
                print("  • Privoxy защищён: выполни `srouter privoxy status`, затем вручную "
                      "`srouter privoxy restart` (потребуется подтверждение)")
            else:
                print("  • privoxy: brew services restart privoxy  (или srouter install)")
        if "xray" in failed_names:
            print("  • xray: brew services restart xray  (или srouter install)")
        if "туннель" in failed_names:
            # #207: vendor outage (оба вендора 5xx, канал/узел/VPS живы) → совет ждать вендора,
            # не чинить узел. Канон: verify-dont-guess (5xx доказывает ответ через туннель, не
            # источник; но при живых VPS/local-proxy вероятен вендор), noisy-log-better-than-no-log.
            tun_check = next((c for c in result["checks"] if "туннель" in c["name"]), None)
            if tun_check and tun_check.get("category") == "vendor-outage":
                print("  • туннель: vendor outage — оба вендора (Anthropic + OpenAI) отвечают 5xx, "
                      "при живых узле/VPS/локальном прокси. Вероятно, лежит сам вендор (не ваша "
                      "инфраструктура).")
                print("    Проверь статусные страницы (status.anthropic.com / status.openai.com), "
                      "подожди восстановления. Узел и локальный прокси трогать не нужно.")
            else:
                print("  • туннель: проверь узел (srouter status / дашборд nodes), возможно узел недоступен")
        if "DNS" in failed_names:
            # #205: DNS точно сломан (getaddrinfo не резолвил) — НЕ чинить VPS/локальный прокси,
            # проблема в резолвере. Домены не разрешаются = всё выглядит connection-failed.
            print("  • DNS: домены не резолвятся — проверь dnsmasq/resolver (это НЕ «VPS мёртв»).")
            print("    Проверь: запущен ли dnsmasq (brew services restart dnsmasq), /etc/resolv.conf, системный DNS")
        if "upstream VPS" in failed_names:
            # #194: VPS точно мёртв (прямой TCP-probe не прошёл) — НЕ чинить локальный прокси,
            # проблема не в нём. VPS-смерть = critical-infra DOWN.
            print("  • upstream VPS: прямой TCP-зонд до endpoint не прошёл — VPS мёртв (не локальный прокси!).")
            print("    Проверь: заплачен/запущен ли VPS, не упал ли хостинг, верный ли endpoint_host:port в узле")
        # #206: GFW режет домен избирательно. Чек info-only (не driver) → не в failed_names; сканируем
        # checks напрямую по имени + ok=False (status=="gfw"). GFW — scoped-диагностика домена:
        # VPS/прокси НЕ виноваты, режущийся домен блокируется по TLS-fingerprint. Подсказка — прокси/VPS
        # для домена. Конкретные имена доменов НЕ хардкодим тут (как раньше «github»): detail чека уже
        # generic по GFW_PROBE_DOMAINS — если список расширится (anthropic и др.), совет останется верным.
        # Канон: verify-dont-guess (точная причина — прямой curl: target режется, контрольный z.ai ок).
        gfw_check = next((c for c in result["checks"] if "GFW per-domain" in c["name"]), None)
        if gfw_check and not gfw_check["ok"]:
            print(f"  • GFW режет домен: {gfw_check.get('detail', 'домен')} — это НЕ «VPS мёртв» и НЕ "
                  f"«локальный прокси» (GFW избирательно блокирует по TLS, контрольный домен отвечает).")
            print("    Решение: гони режущийся домен через прокси/VPS (gh: env -u снимает scoped git-proxy; "
                  "git: git -c http.https://github.com.proxy=).")
        if "локальный прокси" in failed_names:
            # #204: privoxy/xray service-status down (крах/зомби). VPS жив → проблема локальная.
            print("  • локальный прокси упал (privoxy/xray): brew services restart privoxy xray")
            if privoxy_system.protection_present():
                print("    (protected-mode: srouter privoxy restart вместо brew)")
        if "dashboard" in failed_names:
            print("  • дашборд: srouter restart")
        if "claude-proxy" in failed_names:
            print("  • Claude Code proxy: включи в дашборде (карточка Claude Code proxy) и ПЕРЕЗАПУСТИ Claude Code")
        if "Claude Code transport" in failed_names:
            print("  • Claude Code transport: используй HTTP bridge http://127.0.0.1:8118; "
                  "SOCKS TCP-соединение само по себе не доказывает работу API")
        if "codex-proxy" in failed_names:
            print("  • Codex TUI: перезапусти в НОВОМ терминале (exec zsh -l) — старая сессия не подхватила SOCKS5;")
            print("    через privoxy 8118 long-lived WS рвётся (#120); нужен SOCKS5 10808 (~/bin/codex-srouter)")


def cmd_watchdog():
    """Один прогон watchdog'а (запускается launchd раз в ~20с).

    Нотификация только при ПЕРЕХОДЕ состояния (ok→down — громко, down→ok — тихо), не при каждом
    прогоне — чтобы не спамить. State в WATCHDOG_STATE (/tmp).

    Split-route НЕ делается тут — это ответственность ppp-hook (/etc/ppp/ip-up, мгновенно при VPN
    up, от root без osascript). Watchdog только детектит падение туннеля и нотифицирует. Если
    ppp-hook не сработал (utun-VPN) — пользователь видит нотификацию и手动но ensure-split-route-root.
    """
    result = check_all(active_claude=False)
    _record_watchdog_lifecycle()
    cur = result["status"]
    try:
        prev = WATCHDOG_STATE.read_text().strip() if WATCHDOG_STATE.exists() else ""
    except OSError as exc:
        _log.debug("watchdog state read failed: %s — считаем fresh (пустой prev)", exc)
        prev = ""

    # Exact-state transitions (#109 + cycle-review #133 C1):
    # Пуш при переходе ok/degraded → down (новое падение). Не пушить degraded→degraded (спам!).
    # Восстановление при down/degraded → ok.
    if cur == "down" and prev in ("ok", "degraded", ""):
        # Новое падение (ok→down, degraded→down, fresh→down).
        failed = ", ".join(c["name"] for c in result["checks"] if not c["ok"] and not c.get("info"))
        _notify(f"туннель/стек упал ({failed})", "Basso")
    elif cur == "ok" and prev in ("down", "degraded", ""):
        # Восстановление (down→ok, degraded→ok, fresh→ok не пушим — fresh = первый прогон).
        if prev in ("down", "degraded"):
            _notify("стек восстановлен", "Glass")
    # down→down, degraded→degraded, ok→degraded — молча (не спамим).
    # ok→degraded НЕ пушим (degraded — не «упал», просто «часть жива»).

    try:
        WATCHDOG_STATE.write_text(result["status"])
    except OSError as exc:
        _log.warning("watchdog state write failed: %s — следующий прогон может ложно "
                     "считать переход fresh", exc)
    return 0 if cur == "ok" else 1


def main(argv=None):
    """CLI: check (отчёт) | watchdog (нотификация при переходе)."""
    import argparse
    p = argparse.ArgumentParser(prog="health", description="Health-проверки стека srouter.")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("check", help="Разовый прогон проверок, отчёт ✅/❌.")
    sub.add_parser("watchdog", help="Один прогон watchdog'а (для launchd): нотификация при переходе.")
    sub.add_parser("ensure-split-route-root", help="Split-route при VPN up (ppp-hook, от root).")
    args = p.parse_args(argv)

    if args.cmd == "watchdog":
        return cmd_watchdog()
    if args.cmd == "ensure-split-route-root":
        # ppp-hook (/etc/ppp/ip-up) — от root, route add напрямую (без osascript).
        import node_selector
        r = node_selector.ensure_split_route()
        return 0 if r.get("enabled") else 1
    # default / "check"
    result = check_all(active_claude=True)
    _print_report(result)
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
