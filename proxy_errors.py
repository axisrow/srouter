"""Observe-only error-rate реального клиентского трафика из privoxy access-лога.

Дополняет hot_routes (частоты доменов) второй, ортогональной осью качества: КАК
отвечает туннель на живой клиентский трафик. Ноль дополнительного сетевого трафика —
парсится хвост уже существующего лога (access-строки пишет privoxy при `debug 1`,
как для hot_routes).

Контракт:
- Privacy-first (схема #76, как hot_routes): в памяти и на диске — ТОЛЬКО числовые
  агрегаты {bucket: {total, errors, by_code}}. Домены, пути, IP — не извлекаются
  и не сохраняются никогда.
- Свой НЕЗАВИСИМЫЙ cursor (offset/inode/dev) по тому же файлу лога, что hot_routes:
  reader'ы не мешают друг другу (каждый держит свой offset). Content-free детект
  ротации/усечения/copytruncate — переиспользуется из hot_routes._read_new_lines.
- Ошибка = HTTP-код 5xx (прокси/upstream сломал запрос). 4xx — валидные ответы
  origin (404 и т.п.), не деградация туннеля; считаются в by_code, но не в errors.
- Opt-in по наличию файла: access-лог выключен по умолчанию → status "disabled",
  лог/кэш не трогаются (включается пользователем через privoxy debug 1).
- Defensive (канон #2): не бросает никогда; битые строки/файлы → пусто/нули.
- Throttle: инкрементальное чтение лога не чаще UPDATE_THROTTLE_SEC (60с), как
  probe_hot_routes — открытие страницы не гоняет парсер на каждый poll. Throttle/
  error-state держит _lock (LEVEL_CACHE в графе #159, bounded_acquire); парсинг лога
  и запись кэша — ВНЕ лока (лист графа).
- Ошибка липкая до следующего успеха (как probe_hot_routes), не до конца процесса:
  один транзиентный сбой не красит панель warn'ом навсегда.
"""
import json
import re
import threading
import time
from pathlib import Path

import hot_routes
import local_state  # _atomic_write_text: канон atomic-save (tmp+fsync+rename), #139
import lock_hierarchy  # #159: кэш-лок регистрируется в графе и берётся bounded

# Кэш — ignored-файл рядом с модулем (как srouter.hot_routes.json), не коммитится.
_DEFAULT_CACHE_PATH = Path(__file__).resolve().parent / "srouter.proxy_errors.json"
# Тот же privoxy access-лог, что у hot_routes (единый первоисточник).
_DEFAULT_LOG_PATH = hot_routes._DEFAULT_LOG_PATH

DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60
DEFAULT_BUCKET_SECONDS = 3600
UPDATE_THROTTLE_SEC = 60.0

# Строка privoxy CLF: '"<method> <target> HTTP/x.x" <code> <size>'. Метод/таргет
# НЕ захватываем (privacy: домены не нужны) — только код после закрывающей кавычки.
_LINE_RE = re.compile(r'"[A-Z]+\s+\S+\s+HTTP/[0-9.]+"\s+([0-9]{3})\b')

_SCHEMA = 1

_lock = threading.Lock()
_state = {"last_update": 0.0, "error": ""}


def _now(now=None):
    if now is not None:
        try:
            return float(now)
        except (TypeError, ValueError):
            pass
    return time.time()


def parse_new_status_log(path=None, offset=None, inode=None, dev=None,
                         max_lines=None, max_bytes=None):
    """Посчитать {total, errors, by_code} по НОВЫМ строкам лога + cursor.

    Переиспользует hot_routes._read_new_lines (bounded tail, ротация/усечение/
    copytruncate). Чистая относительно файловой системы функция: не трогает кэш.
    """
    lines, new_offset, new_inode, new_dev, new_size = hot_routes._read_new_lines(
        path if path is not None else _DEFAULT_LOG_PATH,
        offset, inode, dev,
        max_bytes if max_bytes is not None else hot_routes._DEFAULT_MAX_BYTES,
        max_lines if max_lines is not None else hot_routes._DEFAULT_MAX_LINES,
    )
    stats = {"total": 0, "errors": 0, "by_code": {}}
    for line in lines:
        m = _LINE_RE.search(line)
        if not m:
            continue
        code = m.group(1)
        stats["total"] += 1
        stats["by_code"][code] = stats["by_code"].get(code, 0) + 1
        if code.startswith("5"):
            stats["errors"] += 1
    cursor = {"log_offset": new_offset, "log_inode": new_inode,
              "log_dev": new_dev, "log_size": new_size}
    return stats, cursor


def _load_cache(path):
    """-> (buckets, meta). Missing/битый -> ({}, {}). Cursor — только числа (#76)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}, {}
    if not isinstance(data, dict):
        return {}, {}
    meta = hot_routes._cursor_meta(data.get("meta"))
    if isinstance(data.get("meta"), dict):
        bs = hot_routes._safe_positive_int(data["meta"].get("bucket_size"))
        if bs is not None:
            meta["bucket_size"] = bs
    raw = data.get("buckets")
    buckets = {}
    if isinstance(raw, dict):
        for bucket_ts, entry in raw.items():
            bucket_ts = hot_routes._safe_non_negative_int(bucket_ts)
            if bucket_ts is None or not isinstance(entry, dict):
                continue
            total = hot_routes._safe_non_negative_int(entry.get("total"))
            errors = hot_routes._safe_non_negative_int(entry.get("errors"))
            by_code_raw = entry.get("by_code")
            by_code = {}
            if isinstance(by_code_raw, dict):
                for code, n in by_code_raw.items():
                    if isinstance(code, str) and re.fullmatch(r"[0-9]{3}", code):
                        cnt = hot_routes._safe_non_negative_int(n)
                        if cnt:
                            by_code[code] = cnt
            if total:
                buckets[bucket_ts] = {"total": total,
                                      "errors": errors or 0,
                                      "by_code": by_code}
    return buckets, meta


def _prune(buckets, ttl, now):
    cutoff = float(now) - float(ttl)
    out = {}
    for bucket_ts, entry in buckets.items():
        if bucket_ts >= cutoff and entry.get("total"):
            out[bucket_ts] = entry
    return out


def _atomic_write(path, buckets, meta):
    """Atomic rewrite через канон-примитив local_state._atomic_write_text (tmp+fsync+
    rename): оборванная запись не оставляет пустой/битый кэш. Не бросает."""
    try:
        text = json.dumps({"meta": meta, "buckets": {str(k): buckets[k] for k in sorted(buckets)}},
                          ensure_ascii=False, indent=2, allow_nan=False)
    except (TypeError, ValueError):
        return False
    return local_state._atomic_write_text(path, text)


def update_error_cache(stats, path=None, ttl=None, bucket_size=None, cursor=None, now=None,
                       cached=None):
    """Влить свежие stats в windowed-кэш (bucket по часу) и обновить cursor.

    cached — уже прочитанная пара (buckets, meta): caller, который читал кэш ради
    cursor, не платит за второй open+json.load+ревалидацию того же файла.
    Defensive: несериализуемый ввод/ошибка записи -> None, не бросает.
    """
    if path is None:
        path = _DEFAULT_CACHE_PATH
    if ttl is None:
        ttl = DEFAULT_TTL_SECONDS
    ts = _now(now)
    buckets, meta = cached if isinstance(cached, tuple) and len(cached) == 2 else _load_cache(path)
    buckets = _prune(buckets, ttl, ts)
    bs = hot_routes._safe_positive_int(bucket_size) or meta.get("bucket_size") or DEFAULT_BUCKET_SECONDS
    bucket_ts = hot_routes._bucket_of(ts, bs)
    if isinstance(stats, dict):
        inc_total = hot_routes._safe_non_negative_int(stats.get("total")) or 0
        inc_errors = hot_routes._safe_non_negative_int(stats.get("errors")) or 0
        entry = buckets.get(bucket_ts) or {"total": 0, "errors": 0, "by_code": {}}
        entry["total"] += inc_total
        entry["errors"] += inc_errors
        by_code_raw = stats.get("by_code")
        if isinstance(by_code_raw, dict):
            for code, n in by_code_raw.items():
                cnt = hot_routes._safe_non_negative_int(n)
                if isinstance(code, str) and re.fullmatch(r"[0-9]{3}", code) and cnt:
                    entry["by_code"][code] = entry["by_code"].get(code, 0) + cnt
        if entry["total"]:
            buckets[bucket_ts] = entry
    out_meta = dict(meta)
    out_meta["bucket_size"] = bs
    out_meta["schema"] = _SCHEMA
    if isinstance(cursor, dict):
        for key, value in hot_routes._cursor_meta(cursor).items():
            out_meta[key] = value
    if not _atomic_write(path, buckets, out_meta):
        return None
    return buckets


def _window_totals(buckets, window_hours, now):
    cutoff = float(now) - max(1, int(window_hours)) * 3600.0
    total = errors = 0
    by_code = {}
    for bucket_ts, entry in buckets.items():
        if bucket_ts < cutoff:
            continue
        total += int(entry.get("total") or 0)
        errors += int(entry.get("errors") or 0)
        for code, n in (entry.get("by_code") or {}).items():
            by_code[code] = by_code.get(code, 0) + int(n)
    return {"total": total, "errors": errors, "by_code": dict(sorted(by_code.items(), key=lambda kv: -kv[1]))}


def _empty_payload(status, window_hours):
    return {"status": status, "window_hours": window_hours,
            "total": 0, "errors": 0, "error_rate": None, "by_code": {}}


def probe_error_rate(window_hours=1, cache_path=None, log_path=None, now=None):
    """5xx-rate реального трафика за окно window_hours (observe-only, не бросает).

    status: ok (лог есть, кэш посчитан) | disabled (access-лога нет — opt-in через
    privoxy debug 1) | warn (сбой инкремента — отдаём последний кэш с ошибкой).
    Инкрементальное чтение лога — не чаще UPDATE_THROTTLE_SEC.
    """
    try:
        window_hours = max(1, int(window_hours))
    except (TypeError, ValueError):
        window_hours = 1
    cache_path = cache_path if cache_path is not None else _DEFAULT_CACHE_PATH
    log_path = log_path if log_path is not None else _DEFAULT_LOG_PATH
    ts = _now(now)
    try:
        if not Path(log_path).exists():
            # Access-лог выключен (privoxy debug 0) — не трогаем лог/кэш вообще.
            return _empty_payload("disabled", window_hours)

        # Кэш-лок в графе #159 (LEVEL_CACHE, лист: внутри только dict-доступ, парсинг
        # лога вынесен наружу). bounded_acquire — hang не вешает 24/7-дашборд; таймаут
        # трактуем как «не наша очередь обновлять» и отдаём прежний кэш.
        try:
            with lock_hierarchy.bounded_acquire(
                _lock, name="proxy-errors", level=lock_hierarchy.LEVEL_CACHE
            ):
                due = ts - _state["last_update"] >= UPDATE_THROTTLE_SEC
                if due:
                    _state["last_update"] = ts
                err = _state["error"]
        except lock_hierarchy.LockAcquireTimeout:
            due, err = False, _state["error"]

        cached = None
        if due:
            try:
                cached = _load_cache(cache_path)
                stats, cursor = parse_new_status_log(
                    path=log_path,
                    offset=cached[1].get("log_offset"), inode=cached[1].get("log_inode"),
                    dev=cached[1].get("log_dev"),
                )
                buckets = update_error_cache(stats, path=cache_path, cursor=cursor, now=ts,
                                             cached=cached)
                # sticky-until-success (как probe_hot_routes): успешный проход снимает
                # прежний warn, иначе один транзиентный сбой красил бы панель навсегда.
                err = "" if buckets is not None else (err or "cache_update_failed")
                cached = (buckets, cached[1]) if buckets is not None else None
            except (OSError, ValueError, TypeError, KeyError) as exc:
                err = str(exc) or exc.__class__.__name__
                cached = None
            try:
                with lock_hierarchy.bounded_acquire(
                    _lock, name="proxy-errors", level=lock_hierarchy.LEVEL_CACHE
                ):
                    _state["error"] = err
            except lock_hierarchy.LockAcquireTimeout:
                pass

        buckets = cached[0] if cached is not None else _load_cache(cache_path)[0]
        out = _window_totals(buckets, window_hours, ts)
        error_rate = None
        if out["total"] > 0:
            error_rate = round(out["errors"] / float(out["total"]), 4)
        return {"status": "warn" if err else "ok", "window_hours": window_hours,
                "total": out["total"], "errors": out["errors"],
                "error_rate": error_rate, "by_code": out["by_code"],
                **({"error": err} if err else {})}
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return {**_empty_payload("warn", window_hours),
                "error": str(exc) or exc.__class__.__name__}
