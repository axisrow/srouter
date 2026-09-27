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
PING = "/sbin/ping"
ROUTE = "/sbin/route"
DOMESTIC_TARGET = "223.5.5.5"  # AliDNS — domestica без GFW-нюансов ICMP
# ponytail: DEFAULT_VPS_TARGET — fallback кампании; первоисточник VPS-цели — активный узел из
# local.json (_vps_target), env SROUTER_NETPROBE_VPS — override для тестов/форензики.
DEFAULT_VPS_TARGET = "85.136.181.198"
LEGS = ("gateway", "domestic", "vps")  # один источник правды: порядок = порядок отчёта
WINDOW_PAD_SEC = 120          # запас вокруг блэкаут-окна (хвост пробы до ~70с)
CLUSTER_GAP_SEC = 300         # фейлы реже чем через 5м — разные блэкауты


def _default_gateway():
    """Gateway текущего default route ('gateway: X' из route -n get default). None при сбое."""
    proc = run([ROUTE, "-n", "get", "default"], 5)
    match = re.search(r"^\s*gateway:\s*(\S+)", proc.get("out") or "", re.MULTILINE)
    return match.group(1) if match else None


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
    targets = {
        "gateway": _default_gateway(),
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
             "sent": 3, "recv": recv, "avg_ms": avg},
            ensure_ascii=False, sort_keys=True))
    if not lines:
        return
    try:
        NETPROBE_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(NETPROBE_LOG, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except OSError:
        pass  # forensic-лог не роняет джобу (канон append_timing_event)


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
    if inside_loss >= 0.10 and inside_loss >= outside_loss * 2:
        print("  (а) ТРАНЗИТ: ICMP до VPS умирает в блэкауты — линия теряет пакеты до VPS.")
        print("      Фикс: смена узла/региона (APAC), VPS-сторону трогать бессмысленно.")
    elif inside_loss < 0.03 and outside_loss < 0.03:
        print("  (б) DPI: ICMP до VPS чист даже в блэкауты — режутся только TLS/Reality-потоки.")
        print("      Фикс: смена порта/протокола/узла (серверная часть, вне репо).")
    else:
        print(f"  неоднозначно (inside {inside_loss:.1%} / outside {outside_loss:.1%}) — копим данные.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "report":
        try:
            report()
        except Exception as exc:  # noqa: BLE001 — отчёт не должен падать (канон fail-soft)
            print(f"report failed: {exc}")
    else:
        try:
            probe()
        except Exception:  # noqa: BLE001 — launchd-джоба молчит и выходит 0 (канон watchdog'а)
            pass
