"""Health-проверки стека srouter: общий движок для `srouter doctor`, `/health` и watchdog.

Переиспользует логику probe_tunnel (dashboard_network): curl через прокси к api.anthropic.com.
Прокси-трафик идёт через loopback (127.0.0.1:8118 → privoxy → xray → VPS IP), а PF-изоляция
режет только en*/ppp* — значит проверка НЕ блокируется даже при включённой изоляции.

Три потребителя:
  - `srouter doctor` (CLI) — разовый прогон, человекочитаемый отчёт.
  - `GET /health` (эндпоинт) — лёгкий, 200 ok / 503 degraded/down.
  - watchdog (launchd, раз в 90с) — фоновый пинг; нотификация при переходе ok→down.

Не бросает, всегда dict со status (probe-канон).

issue #158: файл вырос до 2895 строк — разбит на модули по обязанностям (probes/claude/codex/
codenv/devworkflow/endpoint), health.py остаётся тонким фасадом. `check_all` (оркестратор) и watchdog/report/
main остаются здесь: тесты monkeypatch'ат отдельные чеки через `monkeypatch.setattr(health, "_x", ...)`,
и check_all резолвит имена через модуль health в момент вызова — значит вызовы внутри check_all
обязаны оставаться module-level bare names в ЭТОМ модуле (не health_probes._port_up(...) и т.п.),
иначе monkeypatch на health перестанет перехватывать. Каждый под-модуль ре-экспортирует свои публичные
имена через `from <module> import *` (канон star-import-reexport-contract) — существующие
`from health import X` в коде/тестах продолжают работать без изменений (grep-consumer verified).
"""
from pathlib import Path
import fcntl  # macOS-only проект (PF/osascript/launchd) — flock для watchdog-лока
import json
import logging
import os
import socket  # noqa: F401 — re-export для monkeypatch health.socket.getaddrinfo (health_probes._resolve_host)
import subprocess
import sys as _sys
import time  # noqa: F401 — re-export для monkeypatch health.time.sleep (health_codenv._codenv_unloaded_is_persistent)

import local_state  # noqa: F401 — re-export для monkeypatch health.local_state.* (health_probes/health_endpoint)
import metrics_store
import privoxy_system
import sys_probe

# Watchdog-launchagent запускает этот файл напрямую (`<python> health.py watchdog`, см.
# launchagents/com.srouter.watchdog.plist) — тогда исполняющийся модуль регистрируется в
# sys.modules как '__main__', НЕ 'health' (тот же эффект и у `python -m health`: runpy тоже
# исполняет модуль под именем '__main__'). health_probes.py ниже делает `import health as
# _health_facade` (циклический self-import для monkeypatch-совместимости, канон #158) — при
# запуске как __main__ Python не находит 'health' в sys.modules и заново импортирует/исполняет
# ЭТОТ ЖЕ файл под ключом 'health' — создаётся ВТОРОЙ, независимый объект модуля, у которого
# звёздный ре-экспорт (from health_probes import * ниже) ещё не связал имена (TUNNEL_TARGETS и
# т.п.) на момент обращения из health_probes._tunnel_up() → AttributeError. Регистрируем себя под
# именем 'health' ДО импорта health_probes — тогда его циклический `import health` находит ЭТОТ
# ЖЕ, уже строящийся модуль (как при обычном `import health`), а не запускает повторную
# инициализацию с нуля.
_sys.modules.setdefault("health", _sys.modules[__name__])

from health_constants import _PROXY, DASHBOARD_PORT, PRIVOXY_PORT, XRAY_PORT  # noqa: F401 re-export
from health_probes import *  # noqa: F401,F403 re-export — probes/сеть/туннель/VPS (канон #158)
from health_claude import *  # noqa: F401,F403 re-export — Claude Code detection (канон #158)
from health_codex import *  # noqa: F401,F403 re-export — Codex detection/binaries/isolation (канон #158)
from health_codenv import *  # noqa: F401,F403 re-export — codenv/desktop/app-proxy (канон #158)
from health_devworkflow import *  # noqa: F401,F403 re-export — VSCode/gh/git dev-workflow (канон #158)
from health_endpoint import *  # noqa: F401,F403 re-export — ANTHROPIC_BASE_URL endpoint (канон #158)

_log = logging.getLogger("srouter.health")

# Абсолютные пути: launchd/GUI PATH их не содержит (канон проекта).
OSASCRIPT = "/usr/bin/osascript"
LAUNCHCTL = "/bin/launchctl"

# State watchdog'а (переход ok→down, чтобы не спамить). /tmp не переживает ребут — приемлемо:
# после ребута fresh state, первый прогон без нотификации если уже down.
WATCHDOG_STATE = Path("/tmp/srouter-watchdog.last")
WATCHDOG_NOTIFY_LOG = Path.home() / "Library" / "Logs" / "srouter-watchdog.notify.log"
WATCHDOG_LIFECYCLE_STATE = Path("/tmp/srouter-watchdog.launchd.json")
WATCHDOG_LIFECYCLE_LOG = Path.home() / "Library" / "Logs" / "srouter-watchdog.lifecycle.jsonl"
# Heartbeat-метрики туннеля (observe-only): {last_write, last_rotate} в /tmp — как
# WATCHDOG_STATE, не переживает ребут и не должен (interval-троттлинг внутренний).
WATCHDOG_METRICS_STATE = Path("/tmp/srouter-watchdog.metrics.last.json")
# Audit-JSONL истории статуса (#315 п.2): событие при каждом изменении {status, failed} —
# ретроспективный анализ осцилляций ok↔degraded (диагностика #315 была слепа без него).
WATCHDOG_STATUS_LOG = Path.home() / "Library" / "Logs" / "srouter-watchdog.status.jsonl"
# Cooldown (сек) degraded-класса нотификаций — «деградировал»/«состав изменился» (#315 п.1/п.3):
# против спама от ok↔degraded-осцилляции PID-зависимых MIXED-чеков (каждые 1–7 мин по
# форензике #315). «упал»/«восстановлен» НЕ троттлятся (переходы статуса — редкие события).
# Env-параметризуемо (канон more-options-better): 0 — выключить троттлинг.
_DEGRADED_NOTIFY_COOLDOWN_DEFAULT_SEC = 900
_DEGRADED_NOTIFY_COOLDOWN_ENV = "SROUTER_WATCHDOG_DEGRADED_COOLDOWN"


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
    tun_ok, tun_detail, tun_vendor_outage, tun_timing = _tunnel_up()
    # #207: vendor outage (оба вендора HTTP 5xx = канал жив, вендоры лежат) структурно помечаем
    # в check["category"] (как vps_check["info"] / lp_check["info"] ниже) — _print_report читает
    # поле, а не парсит detail-строку. Каскад #201: ...→сеть→VPS→туннель→vendor outage. При vendor
    # outage туннель driver-down, но VPS/local-proxy чеки ниже остаются info (они живы).
    # tun_timing — разложение времени того же curl-запроса (connect/tls/ttfb/total):
    # consumer (heartbeat-метрики) читает его, не делая доп. сетевых запросов.
    # id — структурный ключ чека (как category ниже): consumer'ы находят туннель по нему,
    # а не по префиксу человекочитаемого name (канон loose-validator-recurring-leak:
    # переименование строки не должно тихо гасить потребителя).
    tun_check = {"id": "tunnel", "name": "туннель (api.anthropic.com через прокси)", "ok": tun_ok,
                 "detail": tun_detail, "timing": tun_timing}
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
                 "ok": vps["status"] == "ok", "info": True, "detail": vps["detail"]}
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
    # #341: грань режима регистрации privoxy (protected vs brew). Прокси жив через вторую
    # легитимную регистрацию — это НЕ «зомби» и не сбой стека: отдельный info-only чек
    # (канон #329 — probe распознаёт легитимную альтернативную конфигурацию; warn-текст
    # объясняет, почему рестарт выбранного режима поверх живой альтернативы опасен).
    if lp.get("facets"):
        # ok=False (грань по построению — warn: выбранный режим не Running / crash-loop), но
        # info-only: не driver (канал в моменте работает). Захардкоженный ok=True рендерил бы
        # ✅ поверх предупреждающего текста — тот же класс, что #225.
        checks.append({"name": "локальный прокси (режим регистрации)",
                       "ok": False, "info": True, "detail": "; ".join(lp["facets"])})
    # #330: persists-across-boot — грань launchd-регистрации локального прокси. Орфан с живым
    # портом, но без регистрации (plist отсутствует / job не загружен), выглядел healthy до
    # ближайшего ребута (инцидент 2026-09-03: после ребута privoxy не поднялся, туннель лёг).
    # Info-only ВСЕГДА (паттерн codex-isolation probe «PF kill-switch не установлен — по
    # выбору»): warn «порт жив, но после перезагрузки не поднимется» требует внимания, но
    # не роняет вердикт — канал в моменте работает.
    bp = _local_proxy_boot_persistence()
    checks.append({"name": "локальный прокси (persists-across-boot)",
                   "ok": bp["status"] == "ok", "info": True, "detail": bp["detail"]})
    # Claude Code РЕАЛЬНО использует прокси? runtime (lsof), не файл. unknown (CC не запущен) →
    # info-only, не driver: проверять «CC юзает прокси» бессмысленно, если CC не работает.
    cp = _claude_proxy_probe()
    cp_check = {"name": "claude-proxy (HTTPS_PROXY для CLI)",
                "ok": cp["status"] == "ok", "detail": cp["detail"]}
    if cp["status"] == "unknown":
        cp_check["info"] = True  # не участвует в агрегации (drivers ниже фильтруют info)
    checks.append(cp_check)
    # Issue #331: консистентность прокси-env — SOCKS-плечо (ALL_PROXY/all_proxy из launchctl
    # gui-домена) не нейтрализовано при managed CC-прокси → warn DRIVER degraded: pip/requests
    # в сессиях CC падают (TypeError PoolKey). unknown (битый settings.json / чужой прокси /
    # claude_proxy недоступен) — info-only, как claude-proxy (fail-closed, не роняет вердикт).
    pe = _proxy_env_consistency()
    pe_check = {"name": "proxy-env (консистентность ALL_PROXY)",
                "ok": pe["status"] == "ok", "detail": pe["detail"]}
    if pe["status"] == "unknown":
        pe_check["info"] = True
    checks.append(pe_check)
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
    # ok отражает СТАТУС чека, а не «не роняй вердикт» (роль info): status=info у этого чека
    # означает WARN (override уводит CC мимо туннеля, #129) — захардкоженный ok=True выдавал его
    # за подтверждённое здоровье. Раньше это скрывала info-ветка рендера; ok-first её убрал.
    eo = _endpoint_override_check()
    eo_check = {"name": "endpoint (ANTHROPIC_BASE_URL)", "ok": eo["status"] == "ok",
                "info": True, "detail": eo["detail"]}
    checks.append(eo_check)
    # endpoint-xray sync (#200): рассинхрон active_node (local.json) ↔ рабочий xray config.
    # info-only ВСЕГДА (как endpoint-override) — картина для диагностики + подсказка `srouter sync`,
    # не сбой стека (прокси может работать через реальный xray, пока local.json — placeholder).
    # warn (рассинхрон) показываем в detail, но НЕ driver: apply-защита (#200 в install_lib) —
    # настоящая fail-closed граница от перезаписи; doctor лишь подсвечивает расхождение.
    exs = _endpoint_xray_sync_check()
    exs_check = {"name": "endpoint (local.json ↔ xray sync)", "ok": exs["status"] == "ok",
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
    # ChatGPT.app Chromium network-service system-proxy (живая регрессия 2026-08-28): обычный
    # запуск из Dock идёт через СИСТЕМНЫЙ macOS SOCKS активного network service, не через
    # launchd gui-env (тот покрывает только Rust app-server, см. ap_check выше). Down здесь
    # означает конкретную и чинимую причину — выключенный/неверный системный SOCKS, лечится
    # `srouter system-proxy repair`, БЕЗ переустановки/перезапуска App. unknown (NetworkService
    # не активен/idle) — info-only, как остальные App-пробы (fail-closed). НЕ под active_claude
    # gate — чек лёгкий (ps + lsof, тот же бюджет, что ap_check).
    acp = _codex_app_chromium_proxy_check()
    acp_check = {"name": "codex-app-proxy (ChatGPT.app Chromium system-proxy)",
                 "ok": acp["status"] == "ok", "detail": acp["detail"]}
    if acp["status"] == "unknown":
        acp_check["info"] = True
    checks.append(acp_check)
    # codenv launchd-job (#250): job загружен, но падает (exit != 0) / осиротел (plist удалён) /
    # указывает на несуществующий путь → down DRIVER. Реальный инцидент: 1419 падений подряд в
    # тишине — doctor читал plist-артефакт, а не состояние job'а. Без codenv Codex после ребута
    # идёт напрямую за GFW (fail-closed-proxy-down) → это настоящий сбой стека, не info-шёпот.
    # ok (здоровый job) — обычный ✅ БЕЗ info-флага: подтверждённо здоров ≠ «не смогли проверить».
    # (Исторически PR #262 выбрал ok ещё и потому, что _print_report красил ЛЮБОЙ info-чек жёлтым;
    # тот баг рендера исправлен — ok читается первым — но выбор верен по существу, а не как обход.)
    # unknown (job не загружен — codenv опционален / launchctl недоступен / exit-код неизвестен) —
    # info-only: не роняет вердикт, но и не притворяется подтверждённо здоровым.
    cj = _codenv_job_check()
    # ok == «проверено и прошло» (только status ok), НЕ «не down»: unknown — это «не смогли
    # проверить», и ok=True выдавал его за здоровье (✅ «состояние не определено» — fail-open).
    # info=True держит его вне агрегации вердикта — обе оси остаются независимыми.
    cj_check = {"name": "codenv LaunchAgent (job launchd)",
                "ok": cj["status"] == "ok", "detail": cj["detail"]}
    if cj["status"] == "unknown":
        cj_check["info"] = True
    checks.append(cj_check)
    # VSCode scoped SOCKS5 (#185): codex-расширение openai.chatgpt через http.proxy. info-only ВСЕГДА
    # (как endpoint-override) — VSCode может быть не установлен, srouter-stack от этого не падает.
    # down (http.proxy=privoxy/чужой — рвёт WS) показываем в detail, но НЕ driver: это scoped-диагностика
    # одного клиента (codex-расширение), не общий вердикт стека. Runtime-маршрут codex ловит cx_check выше.
    vp = _vscode_proxy_check()
    vp_check = {"name": "codex vscode-proxy (http.proxy)",
                "ok": vp["status"] == "ok", "info": True, "detail": vp["detail"]}
    checks.append(vp_check)
    # gh/git VPS-независимый dev-workflow (#199): github доступен напрямую через gh (Go-стек обходит
    # GFW TLS); scoped git-proxy → privoxy делает git pull/push VPS-зависимым. info-only ВСЕГДА (как
    # endpoint-override) — это образовательная подсказка для dev-workflow, не сбой стека: warn
    # (git-proxy ВКЛ) подсказывает env -u, не роняя вердикт. Лёгкий чек (git config --get, как git_proxy).
    gh = _github_direct_check()
    gh_check = {"name": "gh/git direct (github env -u)",
                "ok": gh["status"] == "ok", "info": True, "detail": gh["detail"]}
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
                    "ok": iv["status"] == "ok", "info": True, "detail": iv["detail"]}
        checks.append(iv_check)
        # Privoxy-log observability (#152): молчалив ли privoxy? debug включён? logfile пишет?
        # info-only (не driver) — картина для диагностики флапа к github через 8118; WARN в detail.
        plo = _privoxy_log_observability_check()
        plo_check = {"name": "privoxy-log (observability)",
                     "ok": plo["status"] == "ok", "info": True, "detail": plo["detail"]}
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
        # category несёт НАСТОЯЩИЙ статус пробы (канон vendor-outage у туннеля, #207): ok=False
        # означает лишь «не подтверждено здоровым» и покрывает И gfw, И info («контрольный домен
        # недоступен — тест неприменим»). Совет «GFW режет домен» верен ТОЛЬКО для gfw, поэтому
        # _print_report гейтится на category, а не восстанавливает статус из перегруженного ok.
        gfw_check = {"name": "GFW per-domain (github vs z.ai прямой curl)",
                     "ok": gfw["status"] == "ok", "info": True, "detail": gfw["detail"]}
        if gfw["status"] == "gfw":
            gfw_check["category"] = "gfw"
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


# Нижняя граница metrics_interval_sec (кламп): чаще прогона watchdog писать бессмысленно.
# Вынесена в константу — pre-check троттлинга в _record_watchdog_metrics обязан использовать
# ту же грань, иначе дешёвая проверка отбросила бы запись, разрешённую конфигом.
_METRICS_INTERVAL_MIN_SEC = 20


def _metrics_probe_options(state_path=None):
    """probes.metrics_* из srouter.local.json, defensive (битое -> дефолты).

    metrics_enabled по умолчанию True: доп. сетевого трафика нет вообще — пишется
    timing curl-пробы, которую watchdog и так выполняет каждые ~20с. Клампы:
    interval ≥ 20с (чаще прогона watchdog бессмысленно), retention 1..90 дней.
    """
    # Дефолты — из local_state._DEFAULT_STATE (единый источник схемы probes, как
    # dashboard_common._probe_defaults), а не четвёртая копия чисел здесь.
    try:
        defaults = local_state._DEFAULT_STATE.get("probes", {})
    except AttributeError:
        defaults = {}
    try:
        state = local_state.load_state(path=state_path)
        raw = state.get("probes") if isinstance(state.get("probes"), dict) else {}
    except (OSError, ValueError, TypeError) as exc:
        _log.debug("metrics options: local state недоступен (%s) — дефолты", exc)
        raw = {}

    def _int_or(key, fallback, lo, hi):
        default = defaults.get(key, fallback)
        try:
            value = int(raw.get(key))
        except (TypeError, ValueError):
            try:
                return max(lo, min(hi, int(default)))
            except (TypeError, ValueError):
                return fallback
        return max(lo, min(hi, value))

    return {
        "enabled": raw.get("metrics_enabled", defaults.get("metrics_enabled")) is not False,
        "interval_sec": _int_or("metrics_interval_sec", metrics_store.DEFAULT_INTERVAL_SEC,
                                _METRICS_INTERVAL_MIN_SEC, 86400),
        "retention_days": _int_or("metrics_retention_days", metrics_store.DEFAULT_RETENTION_DAYS, 1, 90),
    }


def _read_watchdog_state(path):
    """Прочитать sidecar-state watchdog'а (JSON-dict). Missing/битый -> {}. Не бросает."""
    try:
        if not Path(path).exists():
            return {}
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _log.debug("watchdog state read failed (%s): %s — считаем fresh", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def _write_watchdog_state(path, state):
    """Атомарно записать sidecar-state (канон local_state._atomic_write_text: tmp+fsync+rename —
    оборванная запись не оставляет пустой/битый файл). Возвращает True/False, не бросает."""
    return local_state._atomic_write_text(
        path, json.dumps(state, ensure_ascii=False, sort_keys=True))


def _state_float(state, key):
    """Числовое поле sidecar-state; отсутствующее/битое -> 0.0 (=== «никогда не делали»)."""
    try:
        return float(state.get(key) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _record_watchdog_metrics(result):
    """Дописать heartbeat-метрики туннеля в metrics_store JSONL (observe-only).

    Ноль дополнительного сетевого трафика: timing берётся из curl-пробы, которую
    check_all() и так выполнил в этом прогоне. Пишем не чаще probes.metrics_interval_sec
    (default 60с при watchdog-тике ~20с); ретеншн-ротация — не чаще раза в час.
    Best-effort, как _record_watchdog_lifecycle: сбой записи не роняет watchdog.
    """
    try:
        tun_check = next(
            (c for c in result.get("checks", []) if c.get("id") == "tunnel"), None)
        if tun_check is None:
            return
        now = time.time()
        state = _read_watchdog_state(WATCHDOG_METRICS_STATE)
        # Троттлинг проверяем ДО чтения local state: на 2 тиках из 3 (тик 20с, интервал
        # 60с) запись не состоится — незачем открывать и парсить srouter.local.json.
        interval_floor = min(metrics_store.DEFAULT_INTERVAL_SEC, _METRICS_INTERVAL_MIN_SEC)
        if now - _state_float(state, "last_write") < interval_floor:
            return
        opts = _metrics_probe_options()
        if not opts["enabled"] or now - _state_float(state, "last_write") < opts["interval_sec"]:
            return

        timing = tun_check.get("timing")
        if isinstance(timing, dict):
            event = metrics_store.build_event(timing, now=now)
        else:
            # curl не успел вывести -w (sys_probe timeout) — фиксируем сам факт
            # провала как замер: failure_rate окна обязан видеть и падения тоже.
            event = metrics_store.build_event(
                {"status": "down" if not tun_check.get("ok") else "unknown"}, now=now)
        metrics_store.append_timing_event(event)

        if now - _state_float(state, "last_rotate") >= metrics_store.RETENTION_CHECK_INTERVAL_SEC:
            metrics_store.rotate_metrics_log(retention_days=opts["retention_days"])
            state["last_rotate"] = now

        state["last_write"] = now
        _write_watchdog_state(WATCHDOG_METRICS_STATE, state)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        _log.debug("watchdog metrics recording failed: %s — метрики пропущены", exc)


def _print_report(result):
    """Человекочитаемый отчёт check_all (для doctor). Вывод в stdout."""
    print(f"srouter health: {result['status'].upper()}\n")
    for c in result["checks"]:
        # info — ось «не участвует в агрегации вердикта» (drivers ниже), ОРТОГОНАЛЬНАЯ оси
        # «прошло/не прошло». ok читается ПЕРВЫМ: иначе info перекрывает его и успешные проверки
        # («DNS резолвит», «сеть активна») рисуются жёлтым — шум, в котором тонут реальные ❌.
        # ⚠️ = не-driver требует внимания (намеренный tradeoff #189, PF-lease «по выбору»), не «сломано».
        if c["ok"]:
            mark = "✅"
        else:
            mark = "⚠️" if c.get("info") else "❌"
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
        # checks напрямую по имени + category=="gfw". Гейт именно на category, НЕ на ok=False: ok
        # у info-чеков означает «подтверждено здоровым», и «контрольный домен недоступен» (info —
        # проба явно говорит «не GFW») тоже даёт ok=False. Совет по нему был бы ложью («контрольный
        # домен отвечает» при мёртвой сети) и уводил бы от настоящей причины. GFW — scoped-диагностика домена:
        # VPS/прокси НЕ виноваты, режущийся домен блокируется по TLS-fingerprint. Подсказка — прокси/VPS
        # для домена. Конкретные имена доменов НЕ хардкодим тут (как раньше «github»): detail чека уже
        # generic по GFW_PROBE_DOMAINS — если список расширится (anthropic и др.), совет останется верным.
        # Канон: verify-dont-guess (точная причина — прямой curl: target режется, контрольный z.ai ок).
        gfw_check = next((c for c in result["checks"] if "GFW per-domain" in c["name"]), None)
        if gfw_check and gfw_check.get("category") == "gfw":
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


def _degraded_notify_cooldown_sec():
    """Cooldown degraded-класса нотификаций из env (#315): 0..86400с, мусор → дефолт."""
    raw = os.environ.get(_DEGRADED_NOTIFY_COOLDOWN_ENV)
    if raw is None:
        return _DEGRADED_NOTIFY_COOLDOWN_DEFAULT_SEC
    try:
        return max(0, min(86400, int(raw)))
    except ValueError:
        return _DEGRADED_NOTIFY_COOLDOWN_DEFAULT_SEC


def _read_watchdog_prev_state():
    """Prev-state watchdog'а: JSON-dict | legacy-строка | None. Не бросает.

    #315: state мигрировал с голой строки («ok») на JSON {status, failed, last_degraded_push}
    ради детекта смены СОСТАВА упавших драйверов (п.3) и cooldown-троттлинга (п.1).
    Legacy-строка → failed=None («набор неизвестен»): смену состава не детектим, но
    статус-переходы работают — старый state-файл после апгрейда не ломает watchdog.
    None = файла нет/пустой (fresh: первый прогон).
    """
    try:
        raw = WATCHDOG_STATE.read_text().strip() if WATCHDOG_STATE.exists() else ""
    except OSError as exc:
        _log.debug("watchdog state read failed: %s — считаем fresh (пустой prev)", exc)
        return None
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        status = parsed.get("status")
        try:
            last_push = float(parsed.get("last_degraded_push") or 0.0)
        except (TypeError, ValueError):
            last_push = 0.0
        # Кламп [0, now] (PR #326 review P3): nan/inf/отрицательный из битого state
        # навсегда глушат degraded-класс (сравнение с nan всегда False) — сбрасываем в 0.
        if not (0.0 <= last_push <= time.time()):
            last_push = 0.0

        def _canon_names(value):
            # sorted-канонизация набора имён (round 4 P2: перестановка — не смена
            # состава). Не-строки из битого state отбрасываем, а не роняем парсер:
            # sorted([3, 'x']) — TypeError ДО записи state = crash-loop каждого тика
            # (/tmp world-writable), нотификации мертвы до ручной чистки (review P3).
            if not isinstance(value, list):
                return None
            return sorted(x for x in value if isinstance(x, str))

        return {
            "status": status if isinstance(status, str) else "",
            "failed": _canon_names(parsed.get("failed")),
            # notified_failed — последний УВЕДОМЛЁННЫЙ состав (Codex P1-1 round 2): при
            # подавлении cooldown'ом НЕ продвигается, чтобы событие не терялось навсегда.
            "notified_failed": _canon_names(parsed.get("notified_failed")),
            "last_degraded_push": last_push,
        }
    # Legacy: голая строка статуса (в т.ч. закавыченная валидным JSON — тоже строка).
    legacy = parsed if isinstance(parsed, str) else raw
    return {"status": legacy.strip(), "failed": None, "notified_failed": None,
            "last_degraded_push": 0.0}


def _append_watchdog_status_event(previous, current):
    """Audit-JSONL статуса (#315 п.2): событие при изменении {status, failed}.

    Канон _record_watchdog_lifecycle: best-effort (сбой записи не роняет watchdog),
    без изменения — не пишем (не раздуваем лог на каждом тике).
    """
    if previous == current:
        return
    try:
        from datetime import datetime

        WATCHDOG_STATUS_LOG.parent.mkdir(parents=True, exist_ok=True)
        event = {
            "timestamp": datetime.now().astimezone().isoformat(),
            "previous": previous,
            "current": current,
        }
        with open(WATCHDOG_STATUS_LOG, "a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
    except OSError as exc:
        _log.warning("watchdog status-log write failed: %s — событие не записано", exc)


def cmd_watchdog():
    """Один прогон watchdog'а (запускается launchd раз в ~20с).

    Нотификация при ПЕРЕХОДЕ состояния, не при каждом прогоне (не спамим). #315-симметрия:
    «упал» = →down (Basso); «восстановлен» = down→ok (Glass; degraded→ok молчит — не падение);
    «деградировал» = ok/fresh→degraded и «состав изменился» = смена набора упавших драйверов при
    том же не-ok статусе (Ping) — с cooldown SROUTER_WATCHDOG_DEGRADED_COOLDOWN (дефолт 900с).
    История статусов пишется в WATCHDOG_STATUS_LOG (#315 п.2). State — JSON в WATCHDOG_STATE (/tmp).

    Split-route НЕ делается тут — это ответственность ppp-hook (/etc/ppp/ip-up, мгновенно при VPN
    up, от root без osascript). Watchdog только детектит падение туннеля и нотифицирует. Если
    ppp-hook не сработал (utun-VPN) — пользователь видит нотификацию и手动но ensure-split-route-root.
    """
    result = check_all(active_claude=False)
    cur = result["status"]

    # Межпроцессный lock (Codex P1-2/P1-3, round 2): launchd-тик + ручной прогон могут
    # идти параллельно — без lock оба читают один prev (дубли пушей/аудита, потеря state,
    # double-write metrics). Занят → тик пропускаем: следующий через ~20с, потеря недопустима.
    # LOCK_NB: watchdog не должен висеть на чужом прогоне. Сам lock — best-effort: не
    # открылся (нет каталога и т.п.) → гоним без лока, watchdog не падает из-за форензики.
    lock_file = None
    try:
        lock_path = Path(str(WATCHDOG_STATE) + ".lock")
        lock_file = open(lock_path, "w")
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _log.debug("watchdog: параллельный прогон держит lock — тик пропущен")
            lock_file.close()
            lock_file = None
            return 0 if cur == "ok" else 1
    except OSError as exc:
        if lock_file is not None:
            lock_file.close()
            lock_file = None
        _log.warning("watchdog: lock-файл недоступен (%s) — прогон без лока", exc)
    try:
        return _cmd_watchdog_locked(result)
    finally:
        if lock_file is not None:
            lock_file.close()  # освобождает flock


def _cmd_watchdog_locked(result):
    """Критическая секция watchdog'а — вызывается только под flock (см. cmd_watchdog)."""
    _record_watchdog_lifecycle()
    _record_watchdog_metrics(result)
    cur = result["status"]
    # Канонический вид набора (round 4 P2): sorted — порядок перечисления драйверов не
    # событие, иначе перестановка [a,b]→[b,a] давала ложный Ping и ложный audit-diff.
    failed = sorted({c["name"] for c in result["checks"] if not c["ok"] and not c.get("info")})
    prev = _read_watchdog_prev_state()
    prev_status = prev["status"] if prev else ""
    prev_failed = prev["failed"] if prev else None
    # notified_failed — последний УВЕДОМЛЁННЫЙ состав (Codex P1-1): не продвигается при
    # подавленном cooldown'ом событии, иначе подавленная смена состава терялась бы навсегда.
    notified_failed = prev["notified_failed"] if prev else None

    # Audit-JSONL статуса (#315 п.2): ДО нотификаций и без cooldown — форензика полная,
    # даже когда звук затроттлен. Fresh-прогон (prev=None) — тихий baseline, как lifecycle.
    if prev is not None:
        _append_watchdog_status_event(
            {"status": prev_status, "failed": prev_failed},
            {"status": cur, "failed": failed})

    # Exact-state transitions (#109 + #133 C1 + #315 симметрия):
    # - «упал»: переход ok/degraded/fresh → down (громко, без троттлинга).
    # - «восстановлен»: ТОЛЬКО down → ok (#315 п.1: degraded→ok — не восстановление,
    #   иначе осцилляция ok↔degraded порождает «восстановлен» без единого «упал» —
    #   воспринимается как флап прокси, хотя down-переходов не было).
    # - «деградировал» (#315 п.1): ok/fresh → degraded — событие с cooldown (п.1),
    #   против спама MIXED-осцилляции.
    # - «состав изменился» (#315 п.3): не-ok статус, а уведомлённый состав отличается
    #   от фактического — включая подавленный cooldown'ом (P1-1) — событие с cooldown.
    last_push = prev["last_degraded_push"] if prev else 0.0
    if cur == "down" and prev_status in ("ok", "degraded", ""):
        _notify(f"туннель/стек упал ({', '.join(failed)})", "Basso")
        notified_failed = failed
    elif cur == "ok" and prev_status == "down":
        _notify("стек восстановлен", "Glass")
        notified_failed = []
    elif cur in ("degraded", "down"):
        # Гейт cur in (degraded, down) обязателен (Codex F1 round 3): без него ok-прогон с
        # «не уведомлённым» составом прошлого degraded пушит ложное «стек деградировал ()».
        new_degradation = cur == "degraded" and prev_status in ("ok", "")
        # Состав не уведомлён: либо сменился, либо был подавлен cooldown'ом (P1-1).
        unnotified = notified_failed is not None and list(notified_failed) != failed
        if (new_degradation or unnotified) and \
                time.time() - last_push >= _degraded_notify_cooldown_sec():
            # Лейбл по prev_status (PR #326 review P3): «деградировал» — только вход из
            # ok/fresh; не-ok→не-ok (в т.ч. down→degraded с СОКРАТИВШИМСЯ набором) —
            # «состав изменился», не ложное ухудшение в момент улучшения.
            if prev_status in ("", "ok"):
                label = "стек деградировал"
            else:
                label = "состав отказа изменился" if cur == "down" else "состав деградации изменился"
            _notify(f"{label} ({', '.join(failed)})", "Ping")
            notified_failed = failed
            last_push = time.time()

    try:
        # _write_watchdog_state сам делает json.dumps + atomic-write (tmp+fsync+rename,
        # канон local_state): передаём dict, не строку. notified_failed=None (legacy-строка
        # или битый JSON) → baseline текущим составом (Codex F3 round 3): тихая миграция
        # один раз, все ПОСЛЕДУЮЩИЕ смены состава детектятся (не null навсегда).
        _write_watchdog_state(WATCHDOG_STATE, {
            "status": cur,
            "failed": failed,
            "notified_failed": (notified_failed if notified_failed is not None else failed)
            if cur != "ok" else [],
            "last_degraded_push": last_push,
        })
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
