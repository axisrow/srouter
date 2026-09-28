#!/usr/bin/env python3
"""Диагностика участков сети — стационарная кампания измерений деградации туннеля (2026-09-27).

Контекст: туннель Mac↔VPS деградирует (фейлы проб 1%→29% за 7 дней, см. план в
~/.claude/plans/wtf-proud-umbrella.md). Развилка, которую закрывает этот логгер:
  (а) транзит линии теряет пакеты — ICMP до VPS умирает В ОКНА БЛЭКАУТОВ туннеля;
  (б) линия/GFW режет только TLS-паттерны — ICMP чист даже в блэкаут (DPI-душение Reality).

Режимы:
  без аргументов      — один раунд проб (launchd StartInterval=60): ping -c 3 до трёх участков,
                        JSONL-допись в ~/Library/Logs/srouter-netprobe.jsonl (~1 МБ/сутки).
  report              — корреляционный отчёт: окна блэкаутов туннеля (metrics-JSONL watchdog'а)
                        × потери/RTT по участкам (наш JSONL) → вердикт (а)/(б).

Не root-helper — ограничение stdlib-only на него не распространяется: переиспользует repo-модули,
sys_probe.run (единый примитив запуска), metrics_store (METRICS_LOG, rotate_journal,
read_timing_events) и local_state_nodes (активный узел — первоисточник VPS-цели: ping следует
за сменой узла, канон #200/#8). History-источник туннеля — существующий watchdog
(metrics_store.append_timing_event), не дублируем его.
"""
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

import metrics_store
from sys_probe import run

NETPROBE_LOG = Path.home() / "Library" / "Logs" / "srouter-netprobe.jsonl"
NETS_MAP = Path.home() / "Library" / "Logs" / "srouter-netprobe-networks.json"
RESOLV_CONF = Path("/etc/resolv.conf")
PING = "/sbin/ping"
ROUTE = "/sbin/route"
IPCONFIG = "/usr/sbin/ipconfig"
NETWORKSETUP = "/usr/sbin/networksetup"
ARP = "/usr/sbin/arp"
WIFI_IFACE = "en0"  # ponytail: Wi-Fi-интерфейс этой машины; перебор en0–en9 не нужен
DOMESTIC_TARGET = "223.5.5.5"  # AliDNS — domestica без GFW-нюансов ICMP
# ponytail: DEFAULT_VPS_TARGET — fallback кампании; первоисточник VPS-цели — активный узел из
# local.json (_vps_target), env SROUTER_NETPROBE_VPS — override для тестов/форензики.
DEFAULT_VPS_TARGET = "85.136.181.198"
LEGS = ("gateway", "domestic", "vps")  # один источник правды: порядок = порядок отчёта
WINDOW_PAD_SEC = 120          # запас вокруг блэкаут-окна (хвост пробы до ~70с)
CLUSTER_GAP_SEC = 300         # фейлы реже чем через 5м — разные блэкауты

# Пороги атрибуции деградации (diagnose_degradation/вердикт report) — один источник
# правды. Без env-ручек: это текст диагностики, не гейт действий; ручка появится
# при первой реальной мисатрибуции (канон more-options-better по потребности).
RATIO_MIN = metrics_store.DEGRADE_RATIO  # 1.5 — тот же порог, что тренд-детектор фаз
LOSS_BAD = 0.10                # потери ≥10% — канал «умирает»
LOSS_MULT = 2.0                # ... или ≥2× собственного фона
LOSS_CALM = 0.03               # <3% по обе стороны — ICMP чист (вердикт DPI)
CONNECT_FLAT = 1.2             # connect-фаза «норма» — ниже этого ratio


def _default_route():
    """(gateway|None, iface|None) из одного route -n get default.

    iface — конфаундер кампании: при поднятом VPN (ipsec0) ВСЕ raw-ноги и дозвон xray
    идут через него, поэтому интерфейс пишется в каждый раунд — данные делятся на
    VPN-периоды при анализе.
    """
    proc = run([ROUTE, "-n", "get", "default"], 5)
    out = proc.get("out") or ""
    gateway = re.search(r"^\s*gateway:\s*(\S+)", out, re.MULTILINE)
    iface = re.search(r"^\s*interface:\s*(\S+)", out, re.MULTILINE)
    return (gateway.group(1) if gateway else None,
            iface.group(1) if iface else None)


def _default_gateway():
    """Gateway текущего default route. None при сбое/VPN-интерфейсе (ipsec0 без gateway)."""
    return _default_route()[0]


def _vps_target():
    """VPS-цель: env SROUTER_NETPROBE_VPS → активный узел local.json → константа кампании.

    Активный узел — канонический первоисточник (#200/#8): смена узла (рекомендованный фикс
    вердикта (а)) автоматически переносит пинг на новый endpoint, кампания не инвалидируется.
    Fail-soft: нет читаемого local.json/узла → fallback константы.
    """
    override = os.environ.get("SROUTER_NETPROBE_VPS")
    if override:
        return override
    try:
        from local_state_nodes import active_node, resolve_route_ip
        ip = resolve_route_ip(active_node())
    except Exception:  # noqa: BLE001 — probe не зависит от state-слоя (канон fail-soft)
        return DEFAULT_VPS_TARGET
    return ip or DEFAULT_VPS_TARGET


def _ping(target):
    """(recv, avg_ms|None) по ping -c 3. run() не бросает; пустой вывод → (0, None)."""
    proc = run([PING, "-c", "3", "-W", "2000", target], 15)
    out = proc.get("out") or ""
    recv = len(re.findall(r"bytes from", out))
    times = [float(x) for x in re.findall(r"time[=<]([\d.]+)\s*ms", out)]
    avg = round(sum(times) / len(times), 1) if times else None
    return recv, avg


def probe():
    """Один раунд: 3 участка, одна ts-отметка на раунд, 3 JSONL-строки. Не бросает."""
    # Ретеншн по канону metrics_store.rotate_journal (early-exit на свежей голове,
    # atomic rewrite): 7 дней/8МиБ — с запасом покрывает кампанию.
    metrics_store.rotate_journal(NETPROBE_LOG, ts_of_line=metrics_store._event_ts,
                                 log_name="netprobe")
    gateway, iface = _default_route()
    # net — распознавание по ФИЗИЧЕСКОМУ шлюзу (при VPN ipsec0 route-default ведёт в
    # туннель и MAC недоступен); поля iface/target в JSONL не трогаем — конфаундер
    # VPN-периодов, на них опирается анализ кампании.
    net_gateway = _physical_gateway()[0]
    gateway_mac = _gateway_mac(net_gateway)
    targets = {
        "gateway": gateway,
        "domestic": DOMESTIC_TARGET,
        "vps": _vps_target(),
    }
    now = time.time()
    timestamp = datetime.now().astimezone().isoformat()
    lines = []
    for leg in LEGS:
        target = targets[leg]
        if not target:
            continue
        recv, avg = _ping(target)
        lines.append(json.dumps(
            {"ts": round(now, 3), "timestamp": timestamp, "leg": leg, "target": target,
             "net": _net_name(gateway=net_gateway, gateway_mac=gateway_mac),
             "iface": iface, "sent": 3, "recv": recv, "avg_ms": avg},
            ensure_ascii=False, sort_keys=True))
    if not lines:
        return
    try:
        NETPROBE_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(NETPROBE_LOG, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except OSError:
        pass  # forensic-лог не роняет джобу (канон append_timing_event)


def read_ssid():
    """SSID текущей Wi-Fi сети, None если macOS его не отдаёт.

    macOS 15.4+/26 считает SSID геоданными: без Location Services у ВЫЗЫВАЮЩЕГО приложения
    ipconfig/networksetup отвечают «<redacted>»/ошибкой (launchd-джобе разрешение выдать
    нечем — поэтому ssid() только ручной режим из терминала пользователя).
    """
    proc = run([IPCONFIG, "getsummary", WIFI_IFACE], 5)
    match = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", proc.get("out") or "", re.MULTILINE)
    ssid = match.group(1).strip() if match else ""
    if ssid and ssid != "<redacted>":
        return ssid
    proc = run([NETWORKSETUP, "-getairportnetwork", WIFI_IFACE], 5)
    match = re.search(r"Current Wi-Fi Network:\s*(.+)", proc.get("out") or "")
    if match:
        ssid = match.group(1).strip()
        # выключенный Wi-Fi/нет интерфейса: '** Error **', '<generic error>' — мусор, не SSID
        if ssid and "<" not in ssid and "**" not in ssid:
            return ssid
    return None


def ssid():
    """Ручной режим: показать SSID и записать метку сети в JSONL кампании.

    Метка {"leg": "ssid"} без sent/recv — report игнорирует её по построению (LEGS);
    target = шлюз, чтобы связка сеть↔шлюз была видна прямо в строке. Без полученного
    SSID JSONL не загрязняется.
    """
    name = read_ssid()
    if not name:
        print("SSID недоступен: macOS отдаёт <redacted> без Location Services у терминала.\n"
              "Выдай терминалу доступ (Системные настройки → Конфиденциальность и безопасность "
              "→ Location Services) и повтори.")
        return
    gateway = _default_gateway()
    try:
        NETPROBE_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(NETPROBE_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(
                {"ts": round(time.time(), 3),
                 "timestamp": datetime.now().astimezone().isoformat(),
                 "leg": "ssid", "target": gateway, "ssid": name},
                ensure_ascii=False, sort_keys=True) + "\n")
    except OSError as exc:
        print(f"SSID: {name} (метка в JSONL не записана: {exc})")
        return
    print(f"SSID: {name} — метка записана в {NETPROBE_LOG}")


def _gateway_mac(ip):
    """MAC шлюза из ARP-таблицы — BSSID-прокси, железный дискриминатор сетей
    (hotspot мобилки ≠ домашний Wi-Fi даже при одинаковых DNS оператора, кейс
    2026-09-28). «no entry»/rc≠0/timeout → None. Fail-soft, не бросает."""
    if not ip:
        return None
    out = run([ARP, "-n", ip], 5).get("out") or ""
    mac = re.search(r"\bat ([0-9a-fA-F:]{17})\b", out)
    return mac.group(1).lower() if mac else None


def _dns_servers(path=None):
    """Отсортированный кортеж DNS-резолверов из resolv.conf — слабый отпечаток сети
    (operator-DNS совпадает между роутером и hotspot'ом; ночные DHCP-коктейли).
    Дискриминатор — MAC шлюза (_gateway_mac); DNS — legacy-fallback для записей без
    gateway/MAC. Fail-soft: нет файла → ().
    """
    try:
        text = (Path(path) if path else RESOLV_CONF).read_text(encoding="utf-8")
    except OSError:
        return ()
    return tuple(sorted(line.split()[1] for line in text.splitlines()
                        if line.startswith("nameserver") and len(line.split()) > 1))


def _load_nets():
    """Мапа обученных сетей {имя: {dns, gateway, iface}}. Нет/битый файл → {}."""
    try:
        data = json.loads(NETS_MAP.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _net_name(dns=None, gateway=None, gateway_mac=None):
    """Имя сети по отпечатку; None — не матчился. Приоритет специфичности, для
    каждой записи: MAC шлюза (совпал = кандидат, другой = блок записи — DNS не
    спасает, кейс «hotspot как 888-5G»), затем gateway (старые записи без MAC),
    затем legacy DNS-пересечение (записи без gateway). Не бросает."""
    current_dns = set(dns if dns is not None else _dns_servers())
    for name, info in _load_nets().items():
        info = info or {}
        rec_mac = info.get("gateway_mac")
        rec_gw = info.get("gateway")
        if rec_mac:
            if gateway_mac and rec_mac.lower() == gateway_mac.lower():
                return name
            continue
        if rec_gw:
            if gateway and rec_gw == gateway:
                return name
            continue
        if current_dns and current_dns & set(info.get("dns") or []):
            return name
    return None


def _physical_gateway():
    """(gateway|None, iface|None) физического линка: route default; при туннельном
    default (VPN: ipsec/utun/ppp) — DHCP-router en0, иначе «сеть» = туннель и
    распознавание/обучение пишут мусор (кейс 2026-09-28). ponytail: en0 захардкожен
    (Wi-Fi этой машины), перебор линковых en* — когда физика переедет с en0."""
    gateway, iface = _default_route()
    if iface and re.match(r"^(ipsec|utun|ppp)", iface):
        tokens = (run([IPCONFIG, "getoption", "en0", "router"], 5).get("out") or "").split()
        if tokens:
            return tokens[-1], "en0"
    return gateway, iface


def learn_net(name):
    """Запомнить текущую сеть под именем (обучение: один прогон на сеть, без прав)."""
    dns = list(_dns_servers())
    gateway, iface = _physical_gateway()
    nets = _load_nets()
    nets[name] = {"dns": dns, "gateway": gateway, "iface": iface,
                  "gateway_mac": _gateway_mac(gateway)}
    try:
        from local_state import _atomic_write_text  # канон atomic-save (tmp+fsync+rename) #139
        if not _atomic_write_text(NETS_MAP, json.dumps(
                nets, ensure_ascii=False, sort_keys=True, indent=1) + "\n"):
            raise OSError("atomic write вернул False")
    except OSError as exc:
        print(f"netname: не удалось сохранить мапу ({exc})")
        return
    print(f"netname: сеть {name!r} запомнена (dns={dns}, gateway={gateway}, iface={iface})")


def _blackout_windows(events, since_ts=None):
    """[start, end] кластеров подряд идущих фейлов туннеля (gap ≤ CLUSTER_GAP_SEC).

    since_ts отсекает события до начала кампании (netprobe-данных за них всё равно нет).
    """
    fails = sorted(float(e["ts"]) for e in events
                   if isinstance(e.get("ts"), (int, float)) and e.get("status") != "ok"
                   and (since_ts is None or float(e["ts"]) >= since_ts))
    windows = []
    for ts in fails:
        if windows and ts - windows[-1][1] <= CLUSTER_GAP_SEC:
            windows[-1][1] = ts
        else:
            windows.append([ts, ts])
    return windows


def _leg_stats(events, windows):
    """По участку: {inside: {rounds, lost, avgs}, outside: {...}}; окно = ±WINDOW_PAD_SEC."""
    stats = {key: {"rounds": 0, "lost": 0, "avgs": []} for key in ("inside", "outside")}
    for e in events:
        ts = e.get("ts")
        if not isinstance(ts, (int, float)):
            continue
        key = "inside" if any(start - WINDOW_PAD_SEC <= ts <= end + WINDOW_PAD_SEC
                              for start, end in windows) else "outside"
        bucket = stats[key]
        bucket["rounds"] += 1
        sent, recv = e.get("sent"), e.get("recv")
        if isinstance(sent, int) and isinstance(recv, int) and sent > 0:
            bucket["lost"] += sent - recv
        avg = e.get("avg_ms")
        if isinstance(avg, (int, float)):
            bucket["avgs"].append(avg)
    return stats


def _packet_loss(bucket):
    """Доля потерянных пакетов bucket (rounds × 3 пакета). 0.0 при пустом bucket."""
    packets = bucket["rounds"] * 3
    return bucket["lost"] / packets if packets else 0.0


def _snap_loss(rows):
    """Доля потерь по строкам (1 − Σrecv/Σsent); None — нет валидных строк (sent≤0/мусор)."""
    sent = recv = 0
    for e in rows:
        s, r = e.get("sent"), e.get("recv")
        if isinstance(s, int) and not isinstance(s, bool) and s > 0 \
                and isinstance(r, int) and not isinstance(r, bool):
            sent += s
            recv += r
    return round(1.0 - recv / sent, 3) if sent else None


def _snap_median(rows):
    """Медиана avg_ms по числовым строкам; None — числовых нет."""
    vals = [e.get("avg_ms") for e in rows if isinstance(e.get("avg_ms"), (int, float))
            and not isinstance(e.get("avg_ms"), bool)]
    return metrics_store._median(vals) if vals else None


def leg_snapshots(window_sec=900, hours=168, now=None, log_path=None):
    """Снимок «сейчас vs норма» по каждой ноге — ОДНО чтение хвоста netprobe-JSONL.

    Окно [now−window_sec, now] — текущее состояние; база — весь hours-хвост (7д
    retention) — норма. Формат: {leg: {avg_ms, avg_ms_base, loss, loss_base,
    samples}}; avg_* — медианы, loss — доля потерь валидных раундов. Нет лога или
    данных → None-поля (fail-open, не бросает).
    # ponytail: хвост ~20k строк ≈ 4-5 суток кампании — для фона достаточно;
    >7д истории всё равно нет (ротация).
    """
    try:
        events = metrics_store.read_timing_events(
            hours=hours, log_path=log_path or NETPROBE_LOG, now=now)
    except (OSError, ValueError):
        events = []
    now_ts = metrics_store._now(now)
    win = {leg: [] for leg in LEGS}
    base = {leg: [] for leg in LEGS}
    for e in events:
        if not isinstance(e, dict):
            continue
        leg = e.get("leg")
        if leg not in win:
            continue  # ssid-метки и мусор
        ts = e.get("ts")
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            continue
        base[leg].append(e)
        if now_ts - window_sec <= ts <= now_ts:
            win[leg].append(e)
    return {leg: {"avg_ms": _snap_median(win[leg]),
                  "avg_ms_base": _snap_median(base[leg]),
                  "loss": _snap_loss(win[leg]),
                  "loss_base": _snap_loss(base[leg]),
                  "samples": len(win[leg])}
            for leg in LEGS}


def _fmt_ratio(cur, base):
    """ratio cur/base по числовым (base>0); None — не сравнимо (fail-open)."""
    if isinstance(cur, (int, float)) and not isinstance(cur, bool) \
            and isinstance(base, (int, float)) and not isinstance(base, bool) and base > 0:
        return cur / float(base)
    return None


def _fmt_pair(cur, base):
    """« (норма→сейчас)» по числовым; пустая строка — не сравнимо."""
    if isinstance(cur, (int, float)) and not isinstance(cur, bool) \
            and isinstance(base, (int, float)) and not isinstance(base, bool):
        return f" ({base:.0f}→{cur:.0f}мс)"
    return ""


def _leg_bad(snap):
    """Потери ноги плохие: ≥LOSS_BAD или ≥LOSS_MULT×фона. Нет данных → False."""
    loss, base = snap.get("loss"), snap.get("loss_base")
    if isinstance(loss, bool) or not isinstance(loss, (int, float)):
        return False
    if loss >= LOSS_BAD:
        return True
    return isinstance(base, (int, float)) and not isinstance(base, bool) \
        and base > 0 and loss >= LOSS_MULT * base


def _leg_calm(snap):
    """Потери ноги чистые: <LOSS_BAD и <LOSS_MULT×фона (данные есть). Нет данных → False."""
    loss, base = snap.get("loss"), snap.get("loss_base")
    if isinstance(loss, bool) or not isinstance(loss, (int, float)) or loss >= LOSS_BAD:
        return False
    if isinstance(base, (int, float)) and not isinstance(base, bool):
        return loss < max(LOSS_BAD, LOSS_MULT * base)
    return True


def diagnose_degradation(summary, legs):
    """Атрибуция деградации туннеля: {suspect, evidence} | None. Чистая, fail-open.

    summary — вывод metrics_store.summarize (фазные ratios: connect=сеть/локал,
    tls=DPI/потери пути, ttfb=сервер/выход), legs — вывод leg_snapshots (ICMP-ноги).
    Правила по порядку, первое совпадение выигрывает; None — данных не хватает,
    подозреваемого назвать нельзя (пуш/отчёт печатаются без заметки).
    """
    summary = summary if isinstance(summary, dict) else {}
    raw = summary.get("ratios")
    ratios = raw if isinstance(raw, dict) else {}
    raw = summary.get("latest")
    latest = raw if isinstance(raw, dict) else {}
    raw = summary.get("baseline")
    baseline = raw if isinstance(raw, dict) else {}
    raw = baseline.get("phases")
    phases = raw if isinstance(raw, dict) else {}
    legs = legs if isinstance(legs, dict) else {}
    r_connect = ratios.get("connect")
    r_tls = ratios.get("tls")
    r_ttfb = ratios.get("ttfb")

    def snap(leg):
        s = legs.get(leg)
        return s if isinstance(s, dict) else {}

    gw, dom, vps = snap("gateway"), snap("domestic"), snap("vps")

    rt = _fmt_ratio(gw.get("avg_ms"), gw.get("avg_ms_base"))
    if rt is not None and rt >= RATIO_MIN:
        return {"suspect": "Wi-Fi/роутер",
                "evidence": "RTT до шлюза ×%.1f%s" % (rt, _fmt_pair(gw.get("avg_ms"),
                                                                    gw.get("avg_ms_base")))}
    rt = _fmt_ratio(dom.get("avg_ms"), dom.get("avg_ms_base"))
    if rt is not None and rt >= RATIO_MIN:
        return {"suspect": "провайдер (дом→интернет)",
                "evidence": "RTT до domestica ×%.1f%s" % (rt, _fmt_pair(dom.get("avg_ms"),
                                                                        dom.get("avg_ms_base")))}
    connect_flat = r_connect is None or r_connect < CONNECT_FLAT
    if _leg_bad(vps) and isinstance(r_tls, (int, float)) and r_tls >= RATIO_MIN \
            and connect_flat:
        parts = []
        vps_rt = _fmt_ratio(vps.get("avg_ms"), vps.get("avg_ms_base"))
        if vps_rt is not None:
            parts.append("RTT до VPS ×%.1f%s" % (vps_rt, _fmt_pair(vps.get("avg_ms"),
                                                                   vps.get("avg_ms_base"))))
        parts.append("потери %.0f%%" % (vps["loss"] * 100))
        return {"suspect": "транзит до VPS", "evidence": ", ".join(parts)}
    if _leg_calm(vps) and isinstance(r_ttfb, (int, float)) and r_ttfb >= RATIO_MIN:
        return {"suspect": "сам VPS",
                "evidence": "TTFB ×%.1f%s — нагрузка/канал сервера"
                            % (r_ttfb, _fmt_pair(latest.get("ttfb_ms"),
                                                 phases.get("ttfb_ms")))}
    if isinstance(r_tls, (int, float)) and r_tls >= RATIO_MIN and connect_flat:
        ev = "TLS-фаза ×%.1f%s" % (r_tls, _fmt_pair(latest.get("tls_ms"),
                                                    phases.get("tls_ms")))
        if _leg_calm(vps):
            ev += ", ICMP до VPS чист"
        return {"suspect": "DPI/потери на пути (Reality-паттерн)", "evidence": ev}
    return None


def _fmt_bucket(bucket):
    loss = _packet_loss(bucket) * 100
    packets = bucket["rounds"] * 3
    avg = (f"{sum(bucket['avgs']) / len(bucket['avgs']):.0f}мс"
           if bucket["avgs"] else "—")
    return f"{bucket['rounds']:4d} раундов, потери {bucket['lost']}/{packets} ({loss:4.1f}%), RTT {avg}"


def report():
    """Корреляция блэкаутов туннеля с потерями по участкам пути → вердикт (а)/(б). Не бросает."""
    tunnel = metrics_store.read_timing_events(log_path=metrics_store.METRICS_LOG)
    legs = metrics_store.read_timing_events(log_path=NETPROBE_LOG)
    if not tunnel:
        print("metrics-JSONL watchdog'а пуст/отсутствует — корреляция невозможна")
        return
    if not legs:
        print("netprobe-JSONL пуст/отсутствует — кампания ещё не копила данные (ждём 24–48ч)")
        return
    first_leg_ts = min(float(e["ts"]) for e in legs if isinstance(e.get("ts"), (int, float)))
    windows = _blackout_windows(tunnel, since_ts=first_leg_ts)
    span_h = (time.time() - first_leg_ts) / 3600
    print(f"netprobe-данные: {span_h:.1f}ч, блэкаут-окон туннеля за это время: {len(windows)}")
    # Атрибуция по текущему окну (фазы туннеля × ICMP-ноги) — тот же движок, что
    # в деградационном пуше watchdog'а. Печатается ДО loss-корреляции: DPI-кейс
    # блэкаутов не даёт, а ранний return ниже её не отменяет.
    diag = diagnose_degradation(metrics_store.summarize(tunnel), leg_snapshots())
    if diag:
        print(f"Сегмент (текущее окно): {diag['suspect']} — {diag['evidence']}")
    else:
        print("Сегмент (текущее окно): неопределим (мало данных)")
    if not windows:
        print("За время кампании блэкаутов не было — вердикта нет, копим данные дальше.")
        return
    by_leg = {}
    for e in legs:
        by_leg.setdefault(e.get("leg"), []).append(e)
    stats_by_leg = {leg: _leg_stats(by_leg.get(leg, []), windows) for leg in LEGS}
    print(f"\n{'участок':<10} внутри окон (±2м)                      | вне окон")
    for leg in LEGS:
        s = stats_by_leg[leg]
        print(f"{leg:<10} {_fmt_bucket(s['inside']):<43} | {_fmt_bucket(s['outside'])}")
    inside_loss = _packet_loss(stats_by_leg["vps"]["inside"])
    outside_loss = _packet_loss(stats_by_leg["vps"]["outside"])
    print("\nВердикт по VPS-участку:")
    if inside_loss >= LOSS_BAD and inside_loss >= outside_loss * LOSS_MULT:
        print("  (а) ТРАНЗИТ: ICMP до VPS умирает в блэкауты — линия теряет пакеты до VPS.")
        print("      Фикс: смена узла/региона (APAC), VPS-сторону трогать бессмысленно.")
    elif inside_loss < LOSS_CALM and outside_loss < LOSS_CALM:
        print("  (б) DPI: ICMP до VPS чист даже в блэкауты — режутся только TLS/Reality-потоки.")
        print("      Фикс: смена порта/протокола/узла (серверная часть, вне репо).")
    else:
        print(f"  неоднозначно (inside {inside_loss:.1%} / outside {outside_loss:.1%}) — копим данные.")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "netname":
        try:
            if len(sys.argv) > 2:
                learn_net(sys.argv[2])
            else:
                print("usage: diag_netprobe.py netname <имя сети>")
        except Exception as exc:  # noqa: BLE001 — ручные режимы не должны падать (канон fail-soft)
            print(f"netname failed: {exc}")
    elif mode in ("report", "ssid"):
        try:
            (report if mode == "report" else ssid)()
        except Exception as exc:  # noqa: BLE001 — ручные режимы не должны падать (канон fail-soft)
            print(f"{mode} failed: {exc}")
    else:
        try:
            probe()
        except Exception:  # noqa: BLE001 — launchd-джоба молчит и выходит 0 (канон watchdog'а)
            pass
