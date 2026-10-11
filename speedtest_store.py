"""Append-only JSONL-журнал ручных замеров скорости (srouter speedtest, 2026-10-12).

Контракт тот же, что metrics_store (writer CLI / reader dashboard — разные процессы):
- SPEEDTEST_LOG — module-level константа (мокается в тестах), рядом с остальными
  журналами замеров в ~/Library/Logs (metrics/marks/netprobe).
- append_result best-effort (True/False, не бросает), read_results — bounded-хвост
  через hot_routes._read_tail, newest-first, битые строки пропускаются.
- build_record — defensive: мусорная выдача speedtest → None-поля, никогда не бросает.

Метки записи — два честных источника: сеть (net/net_known) из
diag_netprobe.current_net_status() (SSID → netname по MAC шлюза, канон #375/#385),
VPN (iface/vpn/isp/exit_ip) — из собственной выдачи speedtest: это то, ЧЕРЕЗ ЧТО
реально шёл замер. Ротации нет: замеры ручные и редкие (ponytail-потолок —
добавить rotate_journal по образцу metrics_store, если станет тысячами строк).
"""
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path

import hot_routes  # _read_tail: единый bounded-tail примитив

_log = logging.getLogger("srouter.speedtest_store")

SPEEDTEST_LOG = Path.home() / "Library" / "Logs" / "srouter-speedtest.jsonl"

# Ookla CLI из Homebrew (brew install speedtest): абсолютный путь — launchd/GUI PATH
# его не содержит (канон бинарников по абсолютным путям). SROUTER_SPEEDTEST —
# подмена в тестах (канон SROUTER_CURL), читается на вызове.
SPEEDTEST_BIN = "/opt/homebrew/bin/speedtest"

_READ_MAX_LINES = 1000
_READ_MAX_BYTES = 1024 * 1024


def speedtest_bin():
    """Бинарник замера: env-подмена для тестов, иначе brew-путь."""
    return os.environ.get("SROUTER_SPEEDTEST") or SPEEDTEST_BIN


def _num(value, digits=1, minimum=None):
    """float с округлением; мусор/bool → None (defensive как _safe_kibs)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        out = round(float(value), digits)
    except (OverflowError, ValueError):
        return None
    if minimum is not None and out < minimum:
        return None
    return out


def _bandwidth_mbps(section):
    """bandwidth из выдачи Ookla — БАЙТЫ/с → Мбит/с (82121 Б/с ≈ 0.66, замер 10-11)."""
    if not isinstance(section, dict):
        return None
    bw = section.get("bandwidth")
    if isinstance(bw, bool) or not isinstance(bw, (int, float)):
        return None
    return _num(bw * 8 / 1_000_000, digits=2, minimum=0)


def build_record(speed, net_status=None, now=None):
    """Нормализовать выдачу `speedtest -f json` в запись журнала. Не бросает.

    speed — распарсенный JSON (dict) или мусор; net_status — результат
    current_net_status() ({label, known, source}) или None.
    """
    ts = now if isinstance(now, (int, float)) and not isinstance(now, bool) else time.time()
    raw = speed if isinstance(speed, dict) else {}
    # одноразовый get + isinstance-сужение: повторный raw.get(...) в тернарнике
    # не сужается типизатором (и читается хуже)
    iface = raw.get("interface")
    iface = iface if isinstance(iface, dict) else {}
    ping = raw.get("ping")
    ping = ping if isinstance(ping, dict) else {}
    server = raw.get("server")
    server = server if isinstance(server, dict) else {}
    result = raw.get("result")
    result = result if isinstance(result, dict) else {}
    net = net_status if isinstance(net_status, dict) else {}
    label = net.get("label")
    location = server.get("location")
    country = server.get("country")
    parts = [p for p in (server.get("name"), location, country) if isinstance(p, str) and p]
    return {
        "timestamp": datetime.fromtimestamp(ts).astimezone().isoformat(),
        "ts": ts,
        "net": label if isinstance(label, str) and label else None,
        "net_known": bool(net.get("known")),
        "iface": iface.get("name") if isinstance(iface.get("name"), str) else None,
        "vpn": iface.get("isVpn") is True,
        "isp": raw.get("isp") if isinstance(raw.get("isp"), str) else None,
        "exit_ip": iface.get("externalIp") if isinstance(iface.get("externalIp"), str) else None,
        "download_mbps": _bandwidth_mbps(raw.get("download")),
        "upload_mbps": _bandwidth_mbps(raw.get("upload")),
        "ping_ms": _num(ping.get("latency"), digits=1, minimum=0),
        "jitter_ms": _num(ping.get("jitter"), digits=1, minimum=0),
        "packet_loss": _num(raw.get("packetLoss"), digits=1, minimum=0),
        "server": " — ".join([" / ".join(parts[:1])] + parts[1:]) if parts else None,
        "result_url": result.get("url") if isinstance(result.get("url"), str) else None,
    }


def append_result(record, log_path=None):
    """Дописать одну запись в JSONL. Best-effort: True/False, не бросает."""
    path = Path(log_path) if log_path else SPEEDTEST_LOG
    if not isinstance(record, dict):
        return False
    try:
        line = json.dumps(record, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
    except (TypeError, ValueError) as exc:
        _log.debug("speedtest record serialize failed: %s — запись не сохранена", exc)
        return False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError as exc:
        _log.warning("speedtest append failed: %s — запись не сохранена", exc)
        return False
    return True


def read_results(limit=10, log_path=None):
    """Прочитать последние limit записей (newest-first). Fail-soft: отсутствующий
    файл/битые строки → пропускаются, никогда не бросает."""
    path = Path(log_path) if log_path else SPEEDTEST_LOG
    try:
        limit = max(1, int(limit))
    except (TypeError, ValueError):
        limit = 10
    events = []
    for line in hot_routes._read_tail(path, _READ_MAX_LINES, _READ_MAX_BYTES):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events[-limit:][::-1]
