"""Тесты proxy_errors: пассивный 5xx-rate из privoxy access-лога (observe-only).

Переиспользует образцы строк test_hot_routes (тот же privoxy CLF). Проверяем:
парсинг кодов, счёт 5xx vs 4xx, cursor-инкрементальность, кэш+TTL, privacy
(только числа, без доменов), opt-in по наличию файла, throttle 60с.
"""
import json

import pytest

import proxy_errors


def _line(code=200, host="api.anthropic.com", method="CONNECT"):
    target = f"{host}:443" if method == "CONNECT" else f"https://{host}/x"
    return f'127.0.0.1 - - [Jul 02 14:00:00.123] "{method} {target} HTTP/1.1" {code} 0'


@pytest.fixture(autouse=True)
def _reset_throttle_state():
    """Модульный throttle-state глобален — сбрасываем перед каждым тестом,
    чтобы шаффлинг порядка (pytest-randomly) не влиял на ожидания."""
    with proxy_errors._lock:
        proxy_errors._state["last_update"] = 0.0
        proxy_errors._state["error"] = ""
    yield


# ============================ parse_new_status_log ============================

def test_parse_missing_log_returns_empty_stats():
    stats, cursor = proxy_errors.parse_new_status_log(path="/nonexistent")
    assert stats == {"total": 0, "errors": 0, "by_code": {}}
    # hot_routes._read_new_lines при os.stat-ошибке возвращает cursor как есть (None).
    assert cursor["log_offset"] is None


def test_parse_counts_from_real_lines(tmp_path):
    log = tmp_path / "privoxy.log"
    log.write_text("\n".join([
        _line(200), _line(200), _line(502), _line(503), _line(429), _line(404),
        "garbage without request", "",
    ]) + "\n", encoding="utf-8")
    stats, cursor = proxy_errors.parse_new_status_log(path=log)
    assert stats["total"] == 6
    assert stats["errors"] == 2  # 502 + 503; 4xx — не ошибка туннеля
    assert stats["by_code"] == {"200": 2, "502": 1, "503": 1, "429": 1, "404": 1}
    assert cursor["log_size"] == log.stat().st_size


def test_parse_incremental_cursor_reads_only_new_lines(tmp_path):
    log = tmp_path / "privoxy.log"
    log.write_text(_line(200) + "\n", encoding="utf-8")
    _, cursor = proxy_errors.parse_new_status_log(path=log)
    with open(log, "a", encoding="utf-8") as f:
        f.write(_line(502) + "\n")
    stats, cursor2 = proxy_errors.parse_new_status_log(
        path=log, offset=cursor["log_offset"], inode=cursor["log_inode"], dev=cursor["log_dev"])
    assert stats["total"] == 1
    assert stats["errors"] == 1
    assert cursor2["log_offset"] > cursor["log_offset"]


def test_parse_rotation_resyncs_from_zero(tmp_path):
    log = tmp_path / "privoxy.log"
    log.write_text(_line(200) + "\n", encoding="utf-8")
    _, cursor = proxy_errors.parse_new_status_log(path=log)
    # Ротация: новый файл, другой inode (copy → replace)
    rotated = tmp_path / "privoxy.log.1"
    log.replace(rotated)
    log.write_text(_line(502) + "\n" + _line(502) + "\n", encoding="utf-8")
    stats, _ = proxy_errors.parse_new_status_log(
        path=log, offset=cursor["log_offset"], inode=cursor["log_inode"], dev=cursor["log_dev"])
    assert stats["total"] == 2  # resync с нуля — весь новый файл посчитан
    assert stats["errors"] == 2


# ============================ кэш: update + privacy ============================

def test_update_error_cache_and_window(tmp_path):
    cache = tmp_path / "cache.json"
    stats = {"total": 10, "errors": 3, "by_code": {"200": 7, "502": 3}}
    proxy_errors.update_error_cache(stats, path=cache, now=1000.0)
    # Privacy: в кэше ТОЛЬКО числа и cursor — никаких доменов/таргетов из лога.
    text = cache.read_text(encoding="utf-8")
    assert "anthropic" not in text and "CONNECT" not in text
    # Окно 1ч от now=1500 всё ещё накрывает бакет 1000
    totals = proxy_errors._window_totals(proxy_errors._load_cache(cache)[0], 1, 1500.0)
    assert totals["total"] == 10
    assert totals["errors"] == 3


def test_update_error_cache_prunes_by_ttl(tmp_path):
    cache = tmp_path / "cache.json"
    proxy_errors.update_error_cache({"total": 5, "errors": 1, "by_code": {"502": 1}},
                                    path=cache, now=1000.0)
    # Через 8 дней (TTL 7d) старый бакет выселен
    proxy_errors.update_error_cache({"total": 1, "errors": 0, "by_code": {"200": 1}},
                                    path=cache, now=1000.0 + 8 * 24 * 3600)
    buckets, _ = proxy_errors._load_cache(cache)
    assert len(buckets) == 1


def test_load_cache_broken_returns_empty(tmp_path):
    cache = tmp_path / "cache.json"
    cache.write_text("{not json", encoding="utf-8")
    assert proxy_errors._load_cache(cache) == ({}, {})


# ============================ probe_error_rate ============================

def test_probe_error_rate_disabled_when_no_log(tmp_path):
    out = proxy_errors.probe_error_rate(
        cache_path=tmp_path / "cache.json", log_path=tmp_path / "nope.log", now=1000.0)
    assert out["status"] == "disabled"
    assert out["error_rate"] is None
    # Кэш не создаётся: disabled не трогает файлы вообще (как hot_routes).
    assert not (tmp_path / "cache.json").exists()


def test_probe_error_rate_ok_counts_window(tmp_path):
    log = tmp_path / "privoxy.log"
    log.write_text(_line(200) + "\n" + _line(502) + "\n" + _line(200) + "\n", encoding="utf-8")
    cache = tmp_path / "cache.json"
    out = proxy_errors.probe_error_rate(cache_path=cache, log_path=log, now=1000.0)
    assert out["status"] == "ok"
    assert out["total"] == 3
    assert out["errors"] == 1
    assert out["error_rate"] == round(1 / 3.0, 4)
    assert out["by_code"] == {"200": 2, "502": 1}


def test_probe_error_rate_throttles_log_reread(tmp_path):
    """Внутри throttle-окна (60с) новые строки лога НЕ подхватываются — только кэш."""
    log = tmp_path / "privoxy.log"
    log.write_text(_line(200) + "\n", encoding="utf-8")
    cache = tmp_path / "cache.json"
    first = proxy_errors.probe_error_rate(cache_path=cache, log_path=log, now=1000.0)
    assert first["total"] == 1
    with open(log, "a", encoding="utf-8") as f:
        f.write(_line(502) + "\n")
    soon = proxy_errors.probe_error_rate(cache_path=cache, log_path=log, now=1010.0)
    assert soon["total"] == 1  # throttle: перечитывания не было
    later = proxy_errors.probe_error_rate(cache_path=cache, log_path=log, now=1061.0)
    assert later["total"] == 2
    assert later["errors"] == 1


def test_probe_error_rate_persists_cursor_across_calls(tmp_path):
    """Cursor сохраняется в кэше — после «рестарта» (state только в кэше) строки не пересчитываются."""
    log = tmp_path / "privoxy.log"
    log.write_text(_line(200) + "\n", encoding="utf-8")
    cache = tmp_path / "cache.json"
    proxy_errors.probe_error_rate(cache_path=cache, log_path=log, now=1000.0)
    with open(log, "a", encoding="utf-8") as f:
        f.write(_line(200) + "\n")
    out = proxy_errors.probe_error_rate(cache_path=cache, log_path=log, now=2000.0)
    assert out["total"] == 2  # только новая строка посчитана в НОВЫЙ бакет + старый в окне... нет:
    # бакет 1000 (1 запрос) истёк для окна от now=2000? Окно 1ч = 3600с — бакет 1000 ещё в окне.
    # total = 1 (старый бакет) + 1 (новый) = 2, и ни одна строка не посчитана дважды.
    assert out["by_code"] == {"200": 2}


def test_probe_error_rate_clears_error_on_next_success(tmp_path, monkeypatch):
    """Ошибка липкая до следующего УСПЕХА, не до конца процесса: один транзиентный
    сбой парсинга не обязан красить панель warn'ом навсегда (как probe_hot_routes)."""
    log = tmp_path / "privoxy.log"
    log.write_text(_line(502) + "\n", encoding="utf-8")
    cache = tmp_path / "cache.json"

    def boom(**kw):
        raise OSError("log vanished")

    monkeypatch.setattr(proxy_errors, "parse_new_status_log", boom)
    out = proxy_errors.probe_error_rate(cache_path=cache, log_path=log, now=1000.0)
    assert out["status"] == "warn" and "error" in out

    monkeypatch.undo()
    # now сдвинут за UPDATE_THROTTLE_SEC — следующий проход реально обновляет кэш.
    out = proxy_errors.probe_error_rate(cache_path=cache, log_path=log, now=2000.0)
    assert out["status"] == "ok", "успешный проход обязан снять прежний warn"
    assert "error" not in out
