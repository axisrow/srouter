"""Health-пробы низкого уровня: порты, локальный прокси, туннель, сеть/DNS, upstream VPS, GFW.

Извлечено из health.py (issue #158 — разбиение крупного файла на модули по обязанностям).
health.py остаётся тонким фасадом: `from health_probes import *` ре-экспортирует все публичные
имена (канон star-import-reexport-contract) — существующие `health.<name>` и monkeypatch на
`health` module продолжают работать без изменений (check_all/_print_report остаются в health.py
и резолвят имена через модуль health в момент вызова).

Не бросает: все чеки здесь возвращают dict/tuple со status, probe-канон (см. health.py docstring).
"""
import logging
import os
from pathlib import Path
import socket
import subprocess
import time

import local_state
import privoxy_system
import sys_probe

import health as _health_facade  # noqa: E402 — резолвит intra-module вызовы через health для monkeypatch (канон #158)

_log = logging.getLogger("srouter.health")

# star-import re-export (канон star-import-reexport-contract): `from health_probes import *` в
# health.py по умолчанию НЕ подхватывает имена с ведущим '_' — тесты monkeypatch'ают их напрямую
# на модуле health (`monkeypatch.setattr(health, "_port_up", ...)`), поэтому __all__ обязан
# перечислить ВСЕ публичные для health.py имена, включая приватные (health.py — единственный
# consumer этого __all__; внешний код импортирует health, не health_probes напрямую).
__all__ = [
    "_launchd_field", "_port_up", "PRIVOXY_SYSTEM_LABEL", "PRIVOXY_BREW_LABEL", "XRAY_BREW_LABEL",
    "_privoxy_service_target", "_privoxy_alternate_registration", "_service_running",
    "_local_proxy_up",
    "_zombie_recheck_delay", "_ZOMBIE_RECHECK_DELAY_SEC", "_launchd_loaded_status",
    "_user_launchagent_plist", "_local_proxy_boot_persistence",
    "GFW_PROBE_DOMAINS", "GFW_CONTROL_DOMAIN", "_direct_domain_probe", "_gfw_domain_check",
    "_direct_first_check", "TUNNEL_TARGETS", "VENDOR_OUTAGE_MARKER",
    "_tunnel_target_up", "_tunnel_up",
    "_route_default_interface", "_inet_interface", "_network_interface_up",
    "DNS_PROBE_HOST", "_resolve_host", "_dns_up",
    "VPS_TCP_PROBE_TIMEOUT", "_vps_endpoint", "_upstream_vps_reachable",
]

# Абсолютные пути: launchd/GUI PATH их не содержит (канон проекта).
LSOF = "/usr/sbin/lsof"
LAUNCHCTL = "/bin/launchctl"
CURL = "/usr/bin/curl"
ROUTE = "/sbin/route"      # route -n get default — есть ли default route (issue #203)
IFCONFIG = "/sbin/ifconfig"  # активный iface с inet — второй эшелон (issue #203)

# Порты компонентов стека — единый источник dashboard_common (issue #155). health.py уже сделал
# import-guard fallback (canonical-fallback-port) — health_probes читает готовые константы оттуда,
# чтобы не дублировать fallback-логику (единый источник правды в одном месте).
from health_constants import _PROXY, PRIVOXY_PORT, XRAY_PORT

# Эндпоинты туннеля для проверки — ДВА таргета, как probe_tunnel (dashboard_network): origin-5xx
# одного вендора (Anthropic лежит, но канал жив) не должен читаться как «туннель упал».
TUNNEL_TARGETS = ("https://api.anthropic.com/", "https://api.openai.com/")

# #207: маркер vendor outage в detail _tunnel_up — единый источник правды для человекочитаемого
# префикса (канон issue #155: константа, не разбросанные подстроки). Программный дискриминатор
# едёт структурно (check["category"]=="vendor-outage" в check_all, см. _tunnel_up return-кортеж),
# а НЕ парсом этой строки — канон loose-validator-recurring-leak. Маркер — только display-текст.
VENDOR_OUTAGE_MARKER = "vendor outage"


def _launchd_field(output, key):
    """Первое scalar-поле из `launchctl print`; nested endpoint state не перетирает root state."""
    import re
    match = re.search(rf"^\s*{re.escape(key)}\s*=\s*(.*?)\s*;?\s*$", output or "", re.MULTILINE)
    return match.group(1) if match else None


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
    brew-mode → user-agent. Тот же выбор, что _collect_launchd_lifecycle (health.py)."""
    if privoxy_system.protection_present():
        return PRIVOXY_SYSTEM_LABEL, "system"
    return PRIVOXY_BREW_LABEL, f"gui/{os.getuid()}"


def _privoxy_alternate_registration(label, domain):
    """Вторая легитимная регистрация privoxy (#341): protected system-daemon ИЛИ brew
    user-LaunchAgent — обе каноничны (канон #329: детектор обязан знать легитимные
    альтернативные конфигурации). Возвращает (label, domain), не совпадающий с выбранным
    по protection_present таргетом. Используется ТОЛЬКО когда выбранный таргет не Running,
    а порт жив: прежде чем клеймить «зомби», спросить launchd про альтернативу —
    port может держать легитимная вторая регистрация, и protected-restart поверх неё
    создал бы конфликт двух сервисов за 8118."""
    if (label, domain) == (PRIVOXY_SYSTEM_LABEL, "system"):
        return PRIVOXY_BREW_LABEL, f"gui/{os.getuid()}"
    return PRIVOXY_SYSTEM_LABEL, "system"


# #330: короткий backoff перед re-check'ом вердиктов, чувствительных к mid-start (зомби,
# «plist не загружен»): первый срез launchctl print ловил bootstrap в полёте и клеймил зомби
# на running-сервисе (стенограмма инцидента #330: второй прогон после `brew services start`
# показал ⚠ зомби на running-сервисе).
_ZOMBIE_RECHECK_DELAY_SEC = 1.5


def _zombie_recheck_delay():
    """Backoff перед повторным срезом launchctl (anti-mid-start, #330). Отдельная функция —
    тесты гасят sleep (monkeypatch health._zombie_recheck_delay), не теряя логики re-check'а."""
    time.sleep(max(0.0, _ZOMBIE_RECHECK_DELAY_SEC))


def _launchd_loaded_status(label, domain=None):
    """Загружен ли job в launchd — tri-state #204-канон (#330 persists-across-boot).
      "loaded"     — launchctl print ответил rc=0 (job в launchd);
      "not_loaded" — launchctl ОТВЕТИЛ ошибкой (job не загружен) — подтверждённый сигнал;
      "unknown"    — timeout: fail-closed, НЕ утверждаем «не загружен» (как _service_running).
    Отличие от _service_running: это ЗАГРУЖЕННОСТЬ (регистрация), не Running-состояние —
    job бывает загружен и waiting/exiting, регистрация при этом валидна (свойство персистентности).
    """
    domain = domain or f"gui/{os.getuid()}"
    r = sys_probe.run([LAUNCHCTL, "print", f"{domain}/{label}"], timeout=3)
    if r.get("timeout"):
        return "unknown"
    return "loaded" if r.get("rc") == 0 else "not_loaded"


def _user_launchagent_plist(label):
    """Путь brew-plist'а в пользовательских LaunchAgents (тот же конвеншн, что
    _launchd_job_snapshot в health.py: plist_path=None → ~/Library/LaunchAgents/<label>.plist)."""
    return Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"


def _launchd_disabled_status(label, domain):
    """Персистентно ли выключен сервис (launchctl print-disabled) — tri-state (#330 P2).

    bootout — RUNTIME-операция: после ребута launchd заново сканирует LaunchDaemons/
    LaunchAgents и поднимет job (RunAtLoad — man launchd.plist). Персистентный «не поднимется»
    даёт только disabled-статус (launchctl disable / Disabled=true). Формат вывода print-disabled
    (эмпирика launchctl, macOS 25): 'disabled services = {' и строки '"<label>" => enabled|disabled'.
      "disabled" — launchctl ответил, label помечен disabled;
      "enabled"  — label в списке enabled ИЛИ отсутствует в выводе (не выключен);
      "unknown"  — timeout/rc!=0: fail-closed, НЕ утверждаем disabled (канон #204).
    """
    import re
    r = sys_probe.run([LAUNCHCTL, "print-disabled", domain], timeout=3)
    if r.get("timeout") or r.get("rc") != 0:
        return "unknown"
    match = re.search(rf'^\s*"{re.escape(label)}"\s*=>\s*(disabled|enabled)\s*$',
                      r.get("out") or "", re.MULTILINE)
    if not match:
        return "enabled"  # label нет в выводе — не выключен
    return match.group(1)


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
    #341: для privoxy «зомби» требует не-Running ОБЕИХ легитимных регистраций (protected system
    И brew user-agent): порт может держать вторая легитимная регистрация — это НЕ зомби, а грань
    режима (facets, info-only). Возвращает {status, detail, facets}: ok / down (с причиной
    крах vs зомби + какой компонент). Не бросает.
    unknown по service-status НЕ роняет ok (port-open = прокси принимает соединения), но помечается
    в detail (observability — noisy-log-better-than-no-log).
    """
    privoxy_label, privoxy_domain = _privoxy_service_target()
    components = [
        ("privoxy", PRIVOXY_PORT, privoxy_label, privoxy_domain),
        ("xray", XRAY_PORT, XRAY_BREW_LABEL, f"gui/{os.getuid()}"),
    ]
    problems = []
    facets = []  # #341: грани режима (info/warn), НЕ роняющие вердикт — отдельная от «зомби»
    unverified = []
    for name, port, label, domain in components:
        port_open = _health_facade._port_up(port)
        svc = _health_facade._service_running(label, domain)
        if not port_open:
            # порт не слушается → КРАХ независимо от service-status (трафик не идёт).
            if svc == "running":
                # launchd считает Running, но порт не слушается → bind упал под живым job'ом (крах процесса).
                problems.append(f"{name} крах (port {port} closed, но сервис Running — bind упал)")
            else:
                hint = "сервис не Running" if svc == "not_running" else "service-status unknown"
                problems.append(f"{name} крах (port {port} closed, {hint} — restart)")
        elif svc == "not_running":
            # #330: re-check с коротким backoff перед вердиктом — одиночный срез ловил mid-start
            # (bootstrap в полёте: job ещё не загружен / state ещё не running) и клеймил зомби
            # на running-сервисе (стенограмма инцидента #330). Зомби = подтверждённый ДВАЖДЫ:
            # порт жив на обоих срезах + not_running на обоих; любой другой исход re-check'а
            # читается по его собственному значению (крах / mid-start ok / timeout fail-closed).
            _health_facade._zombie_recheck_delay()
            svc_recheck = _health_facade._service_running(label, domain)
            port_open_recheck = _health_facade._port_up(port)
            if not port_open_recheck:
                # Порт закрылся между срезами: зомби-формулировка «порт слушается» была бы ложью
                # о повторной пробе — это крах.
                problems.append(f"{name} крах (port {port} закрылся при повторной пробе)")
            elif svc_recheck == "running":
                # mid-start рассосался: сервис уже Running — НЕ зомби (verify-dont-guess).
                continue
            elif svc_recheck == "unknown":
                # timeout даже на re-check'е — fail-closed, НЕ зомби (тот же канон, что первый срез).
                unverified.append(name)
            else:
                # #341: прежде чем клеймить «зомби», спросить launchd про ВТОРУЮ легитимную
                # регистрацию privoxy (канон #329 — детектор знает легитимные альтернативы).
                # Эмпирика #341: protected job loaded, но crash-loop (state=spawn scheduled,
                # EX_CONFIG), порт 8118 держит живой brew homebrew.mxcl.privoxy — зомби был
                # false positive, а совет protected-restart создал бы вторую регистрацию за порт.
                alt_label, alt_domain = (None, None)
                if name == "privoxy":
                    alt_label, alt_domain = _privoxy_alternate_registration(label, domain)
                if alt_label is not None and \
                        _health_facade._service_running(alt_label, alt_domain) == "running":
                    facets.append(
                        f"{name} жив через альтернативную регистрацию {alt_label} "
                        f"(домен {alt_domain}), а выбранная по режиму {label} — не Running. "
                        f"Порт {port} обслуживается; рестарт выбранного режима поверх живой "
                        f"альтернативы создал бы конфликт за порт")
                    continue
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
    # #341: facets — отдельные грани (режим регистрации), НЕ зомби; check_all показывает их
    # отдельным info-only чеком. "facets" в down-ветке не нужен: down означает, что ни одна
    # легитимная регистрация не Running (фасету там взяться неоткуда).
    return {"status": "ok", "detail": detail, "facets": facets}


# ============================ #330: persists-across-boot (launchd-регистрация) ==================
# Дыра #330 (инцидент 2026-09-03): probe локального прокси видел только «порт слушается + сервис
# Running» в момент пробы — orphan (порт жив, launchd-регистрации нет: plist отсутствует, job не
# загружен) выглядел healthy до ближайшего ребута. После ребута privoxy не поднялся, туннель лёг
# (fail-closed), а doctor перед ребутом был зелёный. Опорный паттерн семантики — codex-isolation
# probe («PF kill-switch не установлен (lease отсутствует) — по выбору»): грань персистентности —
# это warn (⚠, info-only), не error.

def _local_proxy_boot_persistence():
    """Переживёт ли локальный прокси перезагрузку? (#330 — грань persists-across-boot)

    На компонент (канон probe-semantics-from-primary-source — man launchd.plist):
      - plist ОТСУТСТВУЕТ (protected privoxy — по managed-маркеру; brew/xray — по факту файла)
        → job при буте не загрузится НИКАК → warn «после перезагрузки не поднимется» (это класс
        инцидента #330: orphan с живым портом, doctor зелёный до ребута);
      - plist на диске + job не загружен (после anti-mid-start re-check) → bootout — RUNTIME-
        операция, при буте launchd поднимет сервис (RunAtLoad; KeepAlive=true implicitly implies
        RunAtLoad) → «не поднимется» говорить НЕЛЬЗЯ (P2 cycle-review). Warn только когда это
        anomaly ЗДЕСЬ И СЕЙЧАС: персистентный disabled (print-disabled) → честное «не поднимется»;
        порт жив без launchd-job → orphan-конфликт (посторонний процесс держит порт); порт
        закрыт + plist цел → осознанный stop → НЕ warn (факт — в detail, noisy-log).
      - launchctl timeout → fail-closed (unknown ≠ not_loaded), пометка в detail, не warn.

    Info-only ВСЕГДА: warn не роняет вердикт (канал в моменте работает). Все machine-dependent
    вызовы — через _health_facade (канон #158, гвард test_boot_persistence_plist_path_resolved_
    through_facade). Возвращает {status, detail}: "ok" | "warn". Не бросает.
    """
    privoxy_label, privoxy_domain = _privoxy_service_target()
    protected = privoxy_system.protection_present()
    components = [
        ("privoxy", PRIVOXY_PORT, privoxy_label, privoxy_domain,
         privoxy_system.DEFAULT_LAYOUT.launchdaemon_path if protected
         else _health_facade._user_launchagent_plist(PRIVOXY_BREW_LABEL),
         privoxy_system.PROTECTED_MARKER if protected else None),
        ("xray", XRAY_PORT, XRAY_BREW_LABEL, f"gui/{os.getuid()}",
         _health_facade._user_launchagent_plist(XRAY_BREW_LABEL), None),
    ]
    problems = []
    notes = []
    unverified = []
    for name, port, label, domain, plist_path, managed_marker in components:
        port_open = _health_facade._port_up(port)
        if managed_marker is not None:
            plist_ok = privoxy_system._managed_file(plist_path, managed_marker)
        else:
            plist_ok = plist_path.is_file()
        if not plist_ok:
            # Плоскость инцидента #330: без plist'а launchd при буте ничего не загрузит.
            why = f"plist отсутствует ({plist_path})"
            remedy = ("srouter privoxy protect --strict (пересоздаёт managed-plist)"
                      if name == "privoxy" and protected
                      else f"brew services start {name} (создаёт plist)")
            if port_open:
                problems.append(f"{name}: порт {port} жив, но launchd-регистрации нет ({why}) — "
                                f"после перезагрузки не поднимется; регистрация: {remedy}")
            else:
                problems.append(f"{name}: не запущен и не зарегистрирован ({why}) — после "
                                f"перезагрузки сам не поднимется; регистрация: {remedy}")
            continue
        loaded = _health_facade._launchd_loaded_status(label, domain)
        if loaded == "unknown":
            # fail-closed: не утверждаем «не зарегистрирован» без ответа launchctl.
            unverified.append(name)
            continue
        if loaded == "loaded":
            continue
        # anti-mid-start: bootstrap в полёте даёт not_loaded на первом срезе.
        _health_facade._zombie_recheck_delay()
        if _health_facade._launchd_loaded_status(label, domain) == "loaded":
            continue
        # plist на диске + job не загружен: bootout не персистентен — при буте launchd поднимет
        # сервис (RunAtLoad). «Не поднимется» персистентен только disabled (print-disabled).
        if _launchd_disabled_status(label, domain) == "disabled":
            problems.append(f"{name}: {'порт ' + str(port) + ' жив, но ' if port_open else ''}"
                            f"сервис выключен в launchd (print-disabled: disabled, job не загружен) — "
                            f"после перезагрузки не поднимется")
            continue
        if port_open:
            problems.append(f"{name}: порт {port} жив, но launchd-job не запущен (plist на диске, "
                            f"disabled нет) — порт держит посторонний процесс; после перезагрузки "
                            f"launchd поднимет сервис, но он не займёт порт, пока orphan держит его")
            continue
        # порт закрыт + plist цел = осознанный stop (protected: control_as_root stop = bootout,
        # plist остаётся): после ребута поднимется — персистентность ок, факт остаём в detail.
        notes.append(f"{name}: остановлен (job не загружен), plist на диске — "
                     f"после перезагрузки launchd поднимет")
    if problems:
        detail = "; ".join(problems)
        if notes:
            detail += f" (прочее: {'; '.join(notes)})"
        return {"status": "warn", "detail": detail}
    detail = "регистрация launchd подтверждена: privoxy + xray (plist на месте + job загружен)"
    if notes:
        detail += f" ({'; '.join(notes)})"
    if unverified:
        detail += f" (⚠ launchctl не верифицирован для {', '.join(unverified)} — timeout)"
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
    ctrl = _health_facade._direct_domain_probe(control)
    if not ctrl["reachable"]:
        # контрольный домен (z.ai, канонически не GFW-target) тоже режется → НЕ GFW: более общая
        # причина (нет сети/VPS/нет маршрута), которая уже ловится выше в каскаде. Не обвиняем GFW.
        return {"status": "info",
                "detail": f"контрольный домен {control} тоже не отвечает напрямую ({ctrl['kind']}) — "
                          f"это НЕ GFW (нет сети/VPS, первичная причина выше в каскаде)"}
    cut = []
    for host in domains:
        r = _health_facade._direct_domain_probe(host)
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


# Разложение времени того же curl-запроса (observe-only, ноль доп. трафика): код +
# time_connect (TCP до локального прокси) + time_appconnect (TLS через туннель — весь
# путь до таргета) + time_starttransfer (первый байт ответа) + time_total. Watchdog
# пишет это в metrics_store; рост connect_ms = затор локального прокси, рост
# tls_ms = потери/DPI на канале, рост total_ms при стабильном handshake = троттлинг полосы.
_TIMING_WRITE_FORMAT = (
    "%{http_code} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total}"
)


def _timing_from_tokens(tokens, url, kind, rc=None, err=None):
    """timing-dict из токенов curl -w (код уже исключён из tokens[1:]). None-мс за мусор.

    tls_ms = appconnect − connect, ttfb_ms = starttransfer − appconnect; всё в мс,
    кламп ≥ 0. Каждое поле None, если curl его не выдал (частичный провал).
    rc/err (#315 п.5) — exit-код и stderr ЭТОЙ же пробы (ProbeManager.run их уже
    возвращал, но до #315 отбрасывались): сигнатуры отказов #301 (exit 56/35/28 ↔
    xray-мёртв/узел-отказал/узел-висит) протекают в metrics_store без нового запроса.
    """
    def _ms(index):
        try:
            return round(float(tokens[index]) * 1000)
        except (IndexError, TypeError, ValueError):
            return None

    connect_ms, appconnect_ms, starttransfer_ms, total_ms = (
        _ms(1), _ms(2), _ms(3), _ms(4))
    tls_ms = ttfb_ms = None
    if connect_ms is not None and appconnect_ms is not None:
        tls_ms = max(0, appconnect_ms - connect_ms)
    if appconnect_ms is not None and starttransfer_ms is not None:
        ttfb_ms = max(0, starttransfer_ms - appconnect_ms)
    host = None
    try:
        from urllib.parse import urlsplit
        host = urlsplit(url).hostname
    except ValueError:
        host = None
    return {
        "target": host,
        "code": tokens[0] if tokens else None,
        "status": kind,
        "connect_ms": connect_ms,
        "tls_ms": tls_ms,
        "ttfb_ms": ttfb_ms,
        "total_ms": total_ms,
        "rc": rc,
        "err": err,
    }


def _tunnel_target_up(url):
    """Один таргет через прокси: (ok, detail, kind, timing). Живой = сервер ответил
    HTTP < 500 (sys_probe.tunnel_code_up). 000/timeout/5xx — не жив. Не бросает.

    kind — структурный дискриминатор провала (канон loose-validator-recurring-leak: не парсим
    его из detail-строки). Один из: ok | timeout | no-response | connection-failed | bad-code |
    upstream-error. #207: upstream-error = HTTP 5xx (сервер ответил через туннель → канал жив,
    но сам вендор лежит); прочие = curl не достучался (сеть/VPS).

    timing — dict разложения времени ЭТОГО ЖЕ curl-запроса (connect_ms/tls_ms/ttfb_ms/
    total_ms + target/code/status=kind): watcher пишет его в metrics_store, не делая
    ни одного дополнительного сетевого запроса. None только при sys_probe timeout
    (процесс убит до вывода -w)."""
    r = sys_probe.run([CURL, "-sS", "-o", "/dev/null", "-x", _PROXY,
                       "--connect-timeout", "4", "--max-time", "8",
                       "-w", _TIMING_WRITE_FORMAT, url], timeout=10)
    if r.get("timeout"):
        # timing-минимум, не None (#315 round 2 / Codex P2-4): rc/err причины доступны
        # даже когда процесс убит до вывода -w — timeout-класс не терял бы err в metrics.
        # target — hostname по контракту metrics (urlsplit), не полный URL (Codex F2 r3).
        try:
            from urllib.parse import urlsplit
            host = urlsplit(url).hostname
        except ValueError:
            host = None
        return False, "timeout", "timeout", {
            "target": host, "code": "000", "status": "timeout",
            "connect_ms": None, "tls_ms": None, "ttfb_ms": None, "total_ms": None,
            "rc": r.get("rc"), "err": r.get("err"),
        }
    tokens = (r.get("out") or "").strip().split()
    code = tokens[0] if tokens else ""
    # Сначала классифицируем (ok, detail, kind), timing собираем ОДИН раз в конце:
    # иначе kind дублировался бы литералом на каждом выходе и мог разъехаться с
    # timing["status"] незамеченным (metrics_store молча перепишет его в "down").
    if not code:
        ok, detail, kind = False, "no-response", "no-response"
    elif code == "000":
        ok, detail, kind = False, "connection-failed", "connection-failed"
    else:
        try:
            code_int = int(code)
        except ValueError:
            ok, detail, kind = False, f"bad-code {code}", "bad-code"
        else:
            if sys_probe.tunnel_code_up(code_int):
                ok, detail, kind = True, f"HTTP {code}", "ok"
            else:
                ok, detail, kind = False, f"upstream-error HTTP {code}", "upstream-error"
    return ok, detail, kind, _timing_from_tokens(
        tokens, url, kind, rc=r.get("rc"), err=r.get("err"))


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
    Возвращает (ok, detail, is_vendor_outage, first_timing). is_vendor_outage — структурный
    сигнал (не parse detail-строки), consumer'ы (check_all → _print_report) читают его, а не
    подстроку. first_timing — timing-замер ПЕРВОГО таргета (стабильная серия для тренда
    metrics_store: замер всегда по одному и тому же таргету, даже когда up по второму).
    """
    if not _health_facade.TUNNEL_TARGETS:
        return False, "no tunnel targets", False, None
    details, kinds = [], []
    first_timing = None
    for url in _health_facade.TUNNEL_TARGETS:
        ok, detail, kind, timing = _tunnel_target_up(url)
        if first_timing is None:
            first_timing = timing
        if ok:
            return True, detail, False, first_timing  # любой живой таргет = туннель жив
        details.append(detail)
        kinds.append(kind)
    # ни один таргет не ответил живым HTTP < 500 → туннель/прокси down.
    # #207: vendor outage = ВСЕ kind'и upstream-error (HTTP 5xx, канал жив). Структурный
    # дискриминатор по kind, не parse detail-строки (канон loose-validator-recurring-leak).
    is_vendor_outage = all(k == "upstream-error" for k in kinds)
    if is_vendor_outage:
        return False, f"{VENDOR_OUTAGE_MARKER} — оба вендора лежат, канал жив ({'; '.join(details)})", True, first_timing
    return False, "; ".join(details), False, first_timing


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
    iface = _health_facade._route_default_interface()
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
    if _health_facade._resolve_host(DNS_PROBE_HOST):
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
