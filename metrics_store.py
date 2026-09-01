"""Append-only JSONL-хранилище heartbeat-метрик туннеля + observe-only анализ тренда.

Контракт (automation ladder — observe first):
- Writer (health.cmd_watchdog) дописывает события не чаще probes.metrics_interval_sec
  (default 60с). Источник таймингов — curl-проба туннеля, которую watchdog и так
  выполняет каждые ~20с: ДОПОЛНИТЕЛЬНОГО сетевого трафика ноль — пишется только
  измерение уже идущего запроса.
- Reader (GET /api/metrics/tunnel) читает хвост JSONL и сводит тренд: медиана окна
  15 минут против baseline «тот же час суток прошлых дней» (fallback — окно 2–24ч
  назад). degraded = ratio ≥ threshold при достатке замеров, либо флап ≥ 50%.
  Никаких действий на основе тренда — только индикация (политика roadmap).
- Timing-разложение (диагностика причины деградации):
    connect_ms — TCP до локального прокси (затор в privoxy);
    tls_ms     — весь путь до таргета через VPS + TLS handshake (потери/DPI/канал);
    ttfb_ms    — ответ сервера после handshake (троттлинг полосы / перегрузка VPS);
    total_ms   — весь запрос.
- Defensive (канон #2, как local_state/hot_routes): функции НИКОГДА не бросают;
  отсутствующий/битый файл и кривые строки -> пусто/None, не исключение.
- Формат события (одна строка JSONL, ключи стабильны):
    {"timestamp": iso, "ts": epoch, "target": host|None, "code": str|None,
     "status": ok|timeout|connection-failed|upstream-error|bad-code|no-response|down,
     "connect_ms": int|None, "tls_ms": int|None, "ttfb_ms": int|None, "total_ms": int|None,
     "rc": int|None, "err": str|None}
    rc/err (#315 п.5) — exit-код и stderr той же curl-пробы: сигнатуры отказов #301
    (exit 56≈8ms — xray мёртв; 35≈2s — узел отказал; 28≈4s — узел висит) видны в JSONL
    ретроспективно. err — одна строка, ≤200 символов.
"""
import json
import logging
import statistics
from datetime import datetime
from pathlib import Path

import hot_routes  # _read_tail: единый bounded-tail примитив (ротация/обрезанная первая строка)
import local_state  # _atomic_write_text: канон atomic-save (tmp+fsync+rename), #139

_log = logging.getLogger("srouter.metrics_store")

# Writer и reader живут в разных процессах (launchd-watchdog vs Flask), поэтому
# путь — module-level константа (мокается в тестах, как health.WATCHDOG_LIFECYCLE_LOG).
METRICS_LOG = Path.home() / "Library" / "Logs" / "srouter-watchdog.metrics.jsonl"

# Дефолты интервалов/хранения — публичный контракт (дублируются в local_state probes).
DEFAULT_INTERVAL_SEC = 60
DEFAULT_RETENTION_DAYS = 7

# Ретеншн: при записи не чаще раза в час файл переписывается, если в нём есть
# события старше retention или он дорос до max_bytes (atomic rewrite).
RETENTION_MAX_BYTES = 8 * 1024 * 1024
RETENTION_CHECK_INTERVAL_SEC = 3600

# Читаем только хвост (bounded) через hot_routes._read_tail: файл после ротации ≤ 8 МиБ,
# но defensive-лимит на случай внешне раздутого файла. Границы — те же, что у hot_routes.
_READ_MAX_BYTES = hot_routes._DEFAULT_MAX_BYTES
_READ_MAX_LINES = hot_routes._DEFAULT_MAX_LINES

# Окно/пороги детектора деградации.
WINDOW_SEC = 15 * 60            # медиана «сейчас» — последние 15 минут
DEGRADE_RATIO = 1.5             # окно в 1.5× медленнее baseline = деградация
MIN_WINDOW_SAMPLES = 5          # меньше 5 ok-замеров в окне — тренд не утверждаем
MIN_BASELINE_SAMPLES = 30       # baseline с меньшим числом замеров не используетс
DEGRADE_FAILURE_RATE = 0.5      # флап: ≥50% замеров окна упали — тоже деградация
_SAME_HOUR_HALF_WIDTH_SEC = 30 * 60  # «тот же час» ± 30 минут
_RETENTION_MAX_DAYS = 90

_EVENT_STATUSES = (
    "ok", "timeout", "connection-failed", "upstream-error",
    "bad-code", "no-response", "down",
)


def _now(now=None):
    """Единая точка времени (как hot_routes._now): тесты передают now=, прод — системное."""
    if now is not None:
        try:
            return float(now)
        except (TypeError, ValueError):
            pass
    import time

    return time.time()


def _safe_ms(value):
    """int мс ≥ 0 уже-миллисекундное значение события (round-trip чтения).

    Отрицательные клампятся в 0, а не отбрасываются: curl не выдаёт отрицательных
    времен, значит это артефакт записи — сохраняем нижнюю грань, не теряя замер.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        ms = int(round(float(value)))
    except (OverflowError, ValueError):
        return None
    return ms if ms >= 0 else 0


def build_event(timing, now=None):
    """Нормализовать timing-словарь пробы (health_probes) в событие JSONL.

    timing может быть None/битым — тогда событие-минимум (ts + status). Не бросает.
    """
    ts = _now(now)
    raw = timing if isinstance(timing, dict) else {}
    status = raw.get("status")
    if status not in _EVENT_STATUSES:
        status = "unknown" if not raw else "down"
    code = raw.get("code")
    if not isinstance(code, (str, int)):
        code = None
    target = raw.get("target")
    if not isinstance(target, str) or not target:
        target = None
    rc = raw.get("rc")
    if isinstance(rc, bool) or not isinstance(rc, int):
        rc = None
    err = raw.get("err")
    if not isinstance(err, str) or not err.strip():
        err = None
    else:
        # Многострочный stderr curl → одна строка (join), bounded (канон hot_routes: лог
        # bounded, иначе деградация сама раздувает файл метрик).
        err = " | ".join(line.strip() for line in err.splitlines() if line.strip())[:200]
    return {
        "timestamp": datetime.fromtimestamp(ts).astimezone().isoformat(),
        "ts": ts,
        "target": target,
        "code": str(code) if code is not None else None,
        "status": status,
        "connect_ms": _safe_ms(raw.get("connect_ms")),
        "tls_ms": _safe_ms(raw.get("tls_ms")),
        "ttfb_ms": _safe_ms(raw.get("ttfb_ms")),
        "total_ms": _safe_ms(raw.get("total_ms")),
        "rc": rc,
        "err": err,
    }


def append_timing_event(event, log_path=None):
    """Дописать одно событие в JSONL. Best-effort: True/False, не бросает (как
    _record_watchdog_lifecycle — forensic logging не роняет watchdog)."""
    path = Path(log_path) if log_path else METRICS_LOG
    if not isinstance(event, dict):
        return False
    try:
        line = json.dumps(event, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
    except (TypeError, ValueError) as exc:
        _log.debug("metrics event serialize failed: %s — событие не записано", exc)
        return False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError as exc:
        _log.warning("metrics append failed: %s — событие не записано", exc)
        return False
    return True


def read_timing_events(hours=None, max_lines=None, log_path=None, now=None):
    """Прочитать хвост JSONL: события за последние `hours` часов (default — retention).

    Bounded-чтение (max_bytes с конца + max_lines), битые строки пропускаются.
    Никогда не бросает; отсутствующий файл -> [].
    """
    path = Path(log_path) if log_path else METRICS_LOG
    try:
        hours = max(1, int(hours)) if hours is not None else DEFAULT_RETENTION_DAYS * 24
    except (TypeError, ValueError):
        hours = DEFAULT_RETENTION_DAYS * 24
    try:
        max_lines = max(1, int(max_lines)) if max_lines is not None else _READ_MAX_LINES
    except (TypeError, ValueError):
        max_lines = _READ_MAX_LINES
    cutoff = _now(now) - hours * 3600.0

    events = []
    for line in hot_routes._read_tail(path, max_lines, _READ_MAX_BYTES):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        ts = event.get("ts")
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            continue
        try:
            ts = float(ts)
        except (TypeError, ValueError):
            continue
        if ts < cutoff:
            continue
        event["ts"] = ts
        for key in ("connect_ms", "tls_ms", "ttfb_ms", "total_ms"):
            event[key] = _safe_ms(event.get(key))
        events.append(event)
    return events


def thin_series(events, max_points=60):
    """Равномерно проредить события до ≤ max_points точек {ts, total_ms, status}.

    Первая и последняя точки сохраняются всегда (край окна виден на графике).
    Чистая функция, не бросает.
    """
    try:
        max_points = max(1, int(max_points))
    except (TypeError, ValueError):
        max_points = 60
    pts = [
        {"ts": e.get("ts"), "total_ms": e.get("total_ms"), "status": e.get("status")}
        for e in events
        if isinstance(e, dict) and isinstance(e.get("ts"), (int, float))
    ]
    if len(pts) <= max_points:
        return pts
    step = (len(pts) - 1) / float(max_points - 1)
    out = []
    seen = set()
    for i in range(max_points):
        idx = min(len(pts) - 1, int(round(i * step)))
        if idx not in seen:
            seen.add(idx)
            out.append(pts[idx])
    return out


def _event_ts(line):
    """ts события из строки JSONL; битая строка/нечисловой ts -> None. Не бросает."""
    try:
        event = json.loads(line)
    except ValueError:
        return None
    if not isinstance(event, dict):
        return None
    ts = event.get("ts")
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        return None
    return float(ts)


def _median(values):
    vals = [v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]
    if not vals:
        return None
    try:
        return round(float(statistics.median(vals)), 1)
    except (statistics.StatisticsError, TypeError, ValueError):
        return None


def _seconds_of_day(ts):
    try:
        dt = datetime.fromtimestamp(float(ts))
    except (OverflowError, OSError, TypeError, ValueError):
        return None
    return dt.hour * 3600 + dt.minute * 60 + dt.second


def _same_hour(ts, sod_now):
    """True если локальное время суток события в ±30 мин от sod_now (секунды суток
    «сейчас»; переход полночи через 86400 — тоже соседний час).

    sod_now передаётся готовым, а не пересчитывается из now_ts: вызывается на каждом
    событии retention-окна (~10k) — datetime.fromtimestamp для константы там лишний.
    """
    sod_a = _seconds_of_day(ts)
    if sod_a is None or sod_now is None:
        return False
    diff = abs(sod_a - sod_now)
    diff = min(diff, 86400 - diff)
    return diff <= _SAME_HOUR_HALF_WIDTH_SEC


def summarize(events, now=None, window_sec=WINDOW_SEC, ratio_threshold=DEGRADE_RATIO,
              min_window_samples=MIN_WINDOW_SAMPLES):
    """Свести тренд деградации по событиям (чистая функция, не бросает).

    Окно = последние window_sec; baseline = ok-замеры total_ms «того же часа ±30 мин»
    из возраста 1–7 дней (circadian-профиль: вечерний пик легитимно хуже утреннего,
    фиксированный порог дал бы ложные срабатывания каждый вечер). Данных того же
    часа < MIN_BASELINE_SAMPLES → fallback: окно 2–24ч назад.

    Возвращает {latest, baseline, ratio, trend}:
      latest    — медианы connect/tls/ttfb/total окна + failure_rate + samples (None без замеров);
      baseline  — {total_ms, source: same-hour|trailing|none, samples};
      ratio     — latest.total_ms / baseline.total_ms (None без baseline);
      trend     — stable | degraded | insufficient.
    degraded: ratio ≥ threshold (при ok-замерах окна ≥ min_window_samples) ИЛИ
    failure_rate ≥ DEGRADE_FAILURE_RATE (туннель флапает — медиана выживших не видит этого).
    """
    now_ts = _now(now)
    try:
        window_sec = max(1.0, float(window_sec))
    except (TypeError, ValueError):
        window_sec = WINDOW_SEC
    try:
        ratio_threshold = float(ratio_threshold) if ratio_threshold else DEGRADE_RATIO
    except (TypeError, ValueError):
        ratio_threshold = DEGRADE_RATIO
    try:
        min_window_samples = max(1, int(min_window_samples))
    except (TypeError, ValueError):
        min_window_samples = MIN_WINDOW_SAMPLES

    # Один проход по событиям: окно, ok-окно и оба baseline-накопителя. Retention-хвост
    # ~10k событий — отдельные проходы на каждую выборку здесь не бесплатны.
    sod_now = _seconds_of_day(now_ts)
    window, ok_window = [], []
    same_hour_vals, trailing_vals = [], []  # только числовые total_ms (len == samples)
    for e in events:
        if not isinstance(e, dict):
            continue
        try:
            age = now_ts - float(e.get("ts") or 0)
        except (TypeError, ValueError):
            continue
        is_ok = e.get("status") == "ok"
        if age <= window_sec:
            window.append(e)
            if is_ok:
                ok_window.append(e)
            continue
        if not is_ok:
            continue
        total = e.get("total_ms")
        if isinstance(total, bool) or not isinstance(total, (int, float)):
            continue
        if 24 * 3600 <= age <= DEFAULT_RETENTION_DAYS * 24 * 3600 and _same_hour(e.get("ts"), sod_now):
            same_hour_vals.append(total)
        elif 2 * 3600 <= age <= 24 * 3600:
            trailing_vals.append(total)

    latest = None
    if window:
        fails = len(window) - len(ok_window)
        latest = {
            "connect_ms": _median([e.get("connect_ms") for e in ok_window]),
            "tls_ms": _median([e.get("tls_ms") for e in ok_window]),
            "ttfb_ms": _median([e.get("ttfb_ms") for e in ok_window]),
            "total_ms": _median([e.get("total_ms") for e in ok_window]),
            "failure_rate": round(fails / float(len(window)), 3),
            "samples": len(window),
        }

    # Baseline: сначала circadian (тот же час прошлых дней), затем trailing-окно.
    # samples — размер выборки, реально прошедшей порог (накопители уже только числовые).
    baseline = {"total_ms": None, "source": "none", "samples": 0}
    for source, vals in (("same-hour", same_hour_vals), ("trailing", trailing_vals)):
        if len(vals) >= MIN_BASELINE_SAMPLES:
            baseline = {"total_ms": _median(vals), "source": source, "samples": len(vals)}
            break

    ratio = None
    if latest and latest.get("total_ms") and baseline.get("total_ms"):
        try:
            ratio = round(latest["total_ms"] / float(baseline["total_ms"]), 2)
        except (TypeError, ValueError, ZeroDivisionError):
            ratio = None

    # Тренд утверждаем только при достатке ok-замеров окна И наличии baseline; иначе
    # insufficient (в т.ч. первые сутки наблюдения — окно есть, baseline ещё нет).
    trend = "insufficient"
    if latest is not None and len(ok_window) >= min_window_samples and baseline["total_ms"] is not None:
        slow = ratio is not None and ratio >= ratio_threshold
        flapping = latest.get("failure_rate", 0.0) >= DEGRADE_FAILURE_RATE
        trend = "degraded" if (slow or flapping) else "stable"

    return {"latest": latest, "baseline": baseline, "ratio": ratio, "trend": trend}


def rotate_metrics_log(log_path=None, retention_days=None, max_bytes=None, now=None):
    """Переписать JSONL без событий старше retention / сверх max_bytes (atomic).

    Вызывается writer'ом не чаще раза в час (RETENTION_CHECK_INTERVAL_SEC), чтобы
    не гонять rewrite на каждом watchdog-тике. True если файл переписан/чист, False
    при сбое (существующий файл остаётся нетронутым — temp + os.replace). Не бросает.
    """
    path = Path(log_path) if log_path else METRICS_LOG
    try:
        retention_days = max(1, int(retention_days)) if retention_days is not None else DEFAULT_RETENTION_DAYS
    except (TypeError, ValueError):
        retention_days = DEFAULT_RETENTION_DAYS
    retention_days = min(retention_days, _RETENTION_MAX_DAYS)
    try:
        max_bytes = int(max_bytes) if max_bytes is not None else RETENTION_MAX_BYTES
    except (TypeError, ValueError):
        max_bytes = RETENTION_MAX_BYTES

    try:
        if not path.exists():
            return True
        size = path.stat().st_size
        if size == 0:
            return True
        cutoff = _now(now) - retention_days * 24 * 3600.0
        # Early-exit: файл append-only и монотонен по ts, поэтому самое старое событие —
        # первая строка. Свежая голова + размер в пределах лимита = переписывать нечего,
        # и полный парс всех ~10k строк (сотни мс на watchdog-тике) не нужен.
        if size <= max_bytes:
            with open(path, "r", encoding="utf-8") as f:
                head = f.readline().strip()
            head_ts = _event_ts(head) if head else None
            if head_ts is not None and head_ts >= cutoff:
                return True
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
        kept = []
        dropped = 0
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            ts = _event_ts(stripped)
            if ts is not None and ts >= cutoff:
                kept.append(stripped)
            else:
                dropped += 1  # битая строка или протухшее событие
        if dropped == 0 and size <= max_bytes:
            return True
        return local_state._atomic_write_text(
            path, "".join(line + "\n" for line in kept[-_READ_MAX_LINES:]))
    except OSError as exc:
        _log.warning("metrics retention rotate failed: %s — файл не тронут", exc)
        return False
