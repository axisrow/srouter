"""Observe-only hot routes probe для dashboard.

Интеграция issue #9: читаем локальный opt-in из srouter.local.json, обновляем
ignored cache hot_routes только при enabled=true и отдаём top-N в /api/status.
Роутинг и генератор xray здесь не трогаются.
"""
import threading
import time

import hot_routes
import local_state


HOT_ROUTES_UPDATE_THROTTLE_SEC = 60.0
# In-flight guard отвечает за correctness; минимум здесь только режет ручной
# subsecond busy-poll для observe-only probe.
HOT_ROUTES_MIN_UPDATE_INTERVAL_SEC = 1.0

__all__ = [
    "probe_hot_routes",
]

_lock = threading.Lock()
_probe_cache = {
    "key": None,
    "updated_at": 0.0,
    "entries": {},
    "error": "",
}
_in_progress_updates = set()


def _safe_positive_int(value, default):
    if isinstance(value, bool):
        return default
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return n if n > 0 else default


def _safe_positive_float(value, default):
    if isinstance(value, bool):
        return default
    try:
        n = float(value)
    except (TypeError, ValueError):
        return default
    return n if n > 0 else default


def _now(value=None):
    if value is not None:
        try:
            return float(value)
        except (TypeError, ValueError):
            pass
    return time.time()


def _options(state):
    raw = state.get("hot_routes") if isinstance(state, dict) else {}
    if not isinstance(raw, dict):
        raw = {}
    update_interval = _safe_positive_float(
        raw.get("update_interval_sec"), HOT_ROUTES_UPDATE_THROTTLE_SEC
    )
    return {
        "enabled": raw.get("enabled") is True,
        "top_n": _safe_positive_int(raw.get("top_n"), hot_routes.DEFAULT_TOP_N),
        "ttl": _safe_positive_float(raw.get("ttl_seconds"), hot_routes.DEFAULT_TTL_SECONDS),
        "bucket_size": _safe_positive_int(
            raw.get("bucket_seconds"), hot_routes.DEFAULT_BUCKET_SECONDS
        ),
        "update_interval": max(
            update_interval, HOT_ROUTES_MIN_UPDATE_INTERVAL_SEC
        ),
    }


def _payload(enabled, status, domains, top_n, ttl, updated=False, error=""):
    out = {
        "enabled": bool(enabled),
        "status": status,
        "domains": domains,
        "top_n": top_n,
        "ttl_seconds": ttl,
        "updated": bool(updated),
    }
    if error:
        out["error"] = error
    return out


def _public_entry(entry):
    if not isinstance(entry, dict):
        return None
    domain = entry.get("domain")
    if not isinstance(domain, str) or not domain:
        return None
    try:
        count = int(entry.get("count", 0))
    except (TypeError, ValueError):
        count = 0
    return {"domain": domain, "count": count}


def _ranked_entries(names, cache_entries):
    entries = cache_entries if isinstance(cache_entries, dict) else {}
    out = []
    for name in names if isinstance(names, list) else []:
        entry = _public_entry(entries.get(name))
        if entry is None and isinstance(name, str) and name:
            entry = {"domain": name, "count": 0}
        if entry is not None:
            out.append(entry)
    return out


def _cache_key(cache_path, log_path, top_n, ttl, bucket_size):
    return (str(cache_path), str(log_path), int(top_n), float(ttl), int(bucket_size))


def _last_entries(key):
    with _lock:
        if _probe_cache.get("key") != key:
            return {}
        return dict(_probe_cache.get("entries") or {})


def _last_error(key):
    with _lock:
        if _probe_cache.get("key") != key:
            return ""
        return _probe_cache.get("error") or ""


def _store_entries(key, updated_at, entries, error=""):
    with _lock:
        _probe_cache.update(
            key=key,
            updated_at=updated_at,
            entries=dict(entries or {}),
            error=error or "",
        )


def _update_due(key, now_ts, update_interval):
    with _lock:
        if key in _in_progress_updates:
            return False
        due = _probe_cache.get("key") != key or (
            now_ts - float(_probe_cache.get("updated_at") or 0.0) >= update_interval
        )
        if due:
            _in_progress_updates.add(key)
        return due


def _release_update(key):
    with _lock:
        _in_progress_updates.discard(key)


def probe_hot_routes(state_path=None, cache_path=None, log_path=None, now=None):
    """Status probe: локальный top-N популярных доменов, строго observe-only.

    Disabled/missing config не трогает log/cache вообще. Enabled-ветка парсит privoxy
    log не чаще HOT_ROUTES_UPDATE_THROTTLE_SEC (или local override), затем читает
    публичный top-N через hot_routes.hot_domains().
    """
    top_n = hot_routes.DEFAULT_TOP_N
    ttl = hot_routes.DEFAULT_TTL_SECONDS
    try:
        state = local_state.load_state(path=state_path)
        opts = _options(state)
        top_n = opts["top_n"]
        ttl = opts["ttl"]
        if not opts["enabled"]:
            return _payload(False, "disabled", [], top_n, ttl)

        cache_path = cache_path if cache_path is not None else hot_routes._DEFAULT_CACHE_PATH
        log_path = log_path if log_path is not None else hot_routes._DEFAULT_LOG_PATH
        now_ts = _now(now)
        key = _cache_key(cache_path, log_path, top_n, ttl, opts["bucket_size"])
        updated = False
        error = _last_error(key)

        if _update_due(key, now_ts, opts["update_interval"]):
            try:
                try:
                    cursor = hot_routes.load_cursor(cache_path)
                    counts, cursor = hot_routes.parse_new_access_log(
                        path=log_path,
                        offset=cursor.get("log_offset"),
                        inode=cursor.get("log_inode"),
                        dev=cursor.get("log_dev"),
                    )
                    cache = hot_routes.update_cache(
                        counts,
                        path=cache_path,
                        ttl=ttl,
                        top_n=top_n,
                        now=now_ts,
                        bucket_size=opts["bucket_size"],
                        cursor=cursor,
                    )
                except Exception as e:
                    cache = None
                    error = str(e) or e.__class__.__name__
                if isinstance(cache, dict):
                    _store_entries(key, now_ts, cache)
                    updated = True
                    error = ""
                else:
                    _store_entries(
                        key,
                        now_ts,
                        _last_entries(key),
                        error=error or "cache_update_failed",
                    )
                    error = error or "cache_update_failed"
            finally:
                _release_update(key)

        try:
            names = hot_routes.hot_domains(path=cache_path, top_n=top_n, ttl=ttl, now=now_ts)
        except Exception as e:
            names = []
            error = error or str(e) or e.__class__.__name__
        domains = _ranked_entries(names, _last_entries(key))
        status = "warn" if error else "ok"
        return _payload(True, status, domains, top_n, ttl, updated=updated, error=error)
    except Exception as e:
        # Privacy-first fallback: при любой неожиданной ошибке не пробуем читать
        # лог повторно.
        return _payload(
            False,
            "warn",
            [],
            top_n,
            ttl,
            error=str(e) or e.__class__.__name__,
        )
