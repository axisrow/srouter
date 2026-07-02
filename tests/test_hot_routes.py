"""Тесты hot_routes: синтетические privoxy-строки, tmp-файлы, БЕЗ реальных логов.

Проверяем:
- parse_access_log: privoxy Common Log Format -> per-domain счётчики; порт снимается,
  битые/пустые строки/отсутствующий файл -> defensive (пусто, не бросает); tail-лимит.
- update_cache: атомарная запись (tmp+rename), TTL-eviction, top-N обрезка,
  round-trip, существующий кэш не портится при сбое сериализации.
- hot_domains: текущий top-N из кэша (для будущего status-поля/генератора).
- Privacy: в кэше только hostname + счётчик + timestamp, никаких полных URL/путей.
"""
import json
from pathlib import Path

import hot_routes


# ============================ helpers ============================
def _privoxy_line(host, port=443, method="CONNECT", ts="Jul 02 14:00:00.123"):
    """Синтетическая строка privoxy access-лога (Common Log Format).

    Реальный формат privoxy (debug 1):
    <ip> - - [<ts>] "<method> <host>:<port> HTTP/1.1" <code> <size>
    Для CONNECT host идёт как host:port; для обычных запросов — абсолютный URL.
    """
    return f'127.0.0.1 - - [{ts}] "{method} {host}:{port} HTTP/1.1" 200 0'


def _privoxy_url_line(url, method="GET"):
    """Строка privoxy для не-CONNECT запроса: во втором поле — абсолютный URL."""
    return f'127.0.0.1 - - [Jul 02 14:00:00.000] "{method} {url} HTTP/1.1" 200 1234'


# ============================ parse_access_log ============================
def test_parse_counts_connect_hosts(tmp_path):
    log = tmp_path / "privoxy.log"
    log.write_text(
        "\n".join(
            [
                _privoxy_line("example.com"),
                _privoxy_line("example.com"),
                _privoxy_line("api.github.com"),
            ]
        ),
        encoding="utf-8",
    )
    counts = hot_routes.parse_access_log(str(log))
    assert counts == {"example.com": 2, "api.github.com": 1}


def test_parse_strips_port(tmp_path):
    """Порт не должен попадать в ключ домена (host:443 -> host)."""
    log = tmp_path / "privoxy.log"
    log.write_text(_privoxy_line("example.com", port=8443), encoding="utf-8")
    counts = hot_routes.parse_access_log(str(log))
    assert counts == {"example.com": 1}


def test_parse_extracts_host_from_absolute_url(tmp_path):
    """Для GET с абсолютным URL берём только hostname, без пути/схемы (privacy)."""
    log = tmp_path / "privoxy.log"
    log.write_text(
        _privoxy_url_line("http://example.com/secret/path?token=abc"),
        encoding="utf-8",
    )
    counts = hot_routes.parse_access_log(str(log))
    assert counts == {"example.com": 1}


def test_parse_non_connect_token_is_skipped(tmp_path):
    """Privacy: scheme-less target при не-CONNECT методе НЕ считается доменом.

    'GET SECRET123 HTTP/1.1' — безопасный токен фильтра/origin-form без hostname.
    Раньше принималось по _HOST_RE и попадало в counts (attacker-influenced мусор
    в кэше). Теперь authority-form допустима только для CONNECT."""
    log = tmp_path / "privoxy.log"
    log.write_text(
        "\n".join(
            [
                '127.0.0.1 - - [ts] "GET SECRET123 HTTP/1.1" 200 0',
                '127.0.0.1 - - [ts] "GET /relative/path HTTP/1.1" 200 0',
                _privoxy_url_line("http://good.example/x"),
            ]
        ),
        encoding="utf-8",
    )
    counts = hot_routes.parse_access_log(str(log))
    assert counts == {"good.example": 1}
    assert "secret123" not in counts


def test_parse_connect_authority_still_works(tmp_path):
    """CONNECT host:port (authority-form) по-прежнему считается — regression guard."""
    log = tmp_path / "privoxy.log"
    log.write_text(_privoxy_line("tunnel.example"), encoding="utf-8")
    assert hot_routes.parse_access_log(str(log)) == {"tunnel.example": 1}


def test_parse_malformed_url_does_not_raise(tmp_path):
    """Битый URL (urlsplit ValueError: невалидный IPv6 / не-ASCII netloc под NFKC)
    трактуется как пропуск строки, не роняет весь parse_access_log. Валидная
    строка в том же логе при этом считается."""
    log = tmp_path / "privoxy.log"
    log.write_text(
        "\n".join(
            [
                _privoxy_url_line("http://[::1"),  # Invalid IPv6 URL
                _privoxy_url_line("http://a℀b/"),  # ℀ — invalid netloc под NFKC
                _privoxy_url_line("http://good.example/x"),
            ]
        ),
        encoding="utf-8",
    )
    counts = hot_routes.parse_access_log(str(log))
    assert counts == {"good.example": 1}


def test_parse_userinfo_token_never_leaks(tmp_path):
    """Privacy: мусорный CONNECT-target с userinfo не должен отдать username-токен.

    `user:pass@host` без порта -> rsplit(':') отрезал бы `user`; отвергаем целиком.
    """
    log = tmp_path / "privoxy.log"
    log.write_text(
        '127.0.0.1 - - [ts] "CONNECT user:pass@evil.example HTTP/1.1" 200 0',
        encoding="utf-8",
    )
    counts = hot_routes.parse_access_log(str(log))
    assert counts == {}
    assert "user" not in counts


def test_parse_userinfo_in_url_strips_credentials(tmp_path):
    """URL с userinfo: сохраняется только hostname, креды не утекают."""
    log = tmp_path / "privoxy.log"
    log.write_text(
        _privoxy_url_line("http://user:pass@example.com/x"),
        encoding="utf-8",
    )
    counts = hot_routes.parse_access_log(str(log))
    assert counts == {"example.com": 1}
    assert "pass" not in str(counts)


def test_parse_missing_file_is_empty(tmp_path):
    """Отсутствующий файл -> пустой результат, не бросает."""
    counts = hot_routes.parse_access_log(str(tmp_path / "nope.log"))
    assert counts == {}


def test_parse_empty_file_is_empty(tmp_path):
    log = tmp_path / "privoxy.log"
    log.write_text("", encoding="utf-8")
    assert hot_routes.parse_access_log(str(log)) == {}


def test_parse_broken_lines_are_skipped(tmp_path):
    """Битые строки не роняют парсер и не дают мусорных ключей."""
    log = tmp_path / "privoxy.log"
    log.write_text(
        "\n".join(
            [
                "garbage without any structure",
                "",
                '127.0.0.1 - - [ts] "GET" 200 0',  # нет URL-поля
                _privoxy_line("good.example"),
                '- - - [ts] "CONNECT :443 HTTP/1.1" 200 0',  # пустой host
            ]
        ),
        encoding="utf-8",
    )
    counts = hot_routes.parse_access_log(str(log))
    assert counts == {"good.example": 1}


def test_parse_none_path_does_not_raise(tmp_path, monkeypatch):
    """path=None -> дефолтный путь; если его нет, просто пусто, без исключения."""
    monkeypatch.setattr(hot_routes, "_DEFAULT_LOG_PATH", tmp_path / "absent.log")
    assert hot_routes.parse_access_log() == {}


def test_parse_tail_limits_lines(tmp_path):
    """max_lines читает только хвост: старые строки за пределами лимита игнорируются."""
    lines = [_privoxy_line("old.example") for _ in range(50)]
    lines += [_privoxy_line("recent.example") for _ in range(5)]
    log = tmp_path / "privoxy.log"
    log.write_text("\n".join(lines), encoding="utf-8")
    counts = hot_routes.parse_access_log(str(log), max_lines=5)
    assert counts == {"recent.example": 5}
    assert "old.example" not in counts


def test_parse_tail_limits_bytes(tmp_path):
    """max_bytes ограничивает объём чтения (не читаем весь гигабайтный лог)."""
    log = tmp_path / "privoxy.log"
    big = "\n".join(_privoxy_line("x.example") for _ in range(1000))
    log.write_text(big, encoding="utf-8")
    counts = hot_routes.parse_access_log(str(log), max_bytes=200)
    # прочитан только хвост — счётчик заметно меньше 1000
    assert 0 < counts.get("x.example", 0) < 1000


# ============================ update_cache ============================
def test_update_cache_roundtrip(tmp_path):
    cache = tmp_path / "hot.json"
    hot_routes.update_cache({"a.example": 3, "b.example": 1}, path=str(cache), now=1000.0)
    data = json.loads(cache.read_text(encoding="utf-8"))
    domains = {e["domain"]: e for e in data["domains"]}
    assert domains["a.example"]["count"] == 3
    assert domains["b.example"]["count"] == 1
    assert domains["a.example"]["last_seen"] == 1000.0


def test_update_cache_accumulates_counts(tmp_path):
    cache = tmp_path / "hot.json"
    hot_routes.update_cache({"a.example": 2}, path=str(cache), now=1000.0)
    hot_routes.update_cache({"a.example": 3}, path=str(cache), now=2000.0)
    data = json.loads(cache.read_text(encoding="utf-8"))
    domains = {e["domain"]: e for e in data["domains"]}
    assert domains["a.example"]["count"] == 5
    assert domains["a.example"]["last_seen"] == 2000.0


def test_update_cache_ttl_eviction(tmp_path):
    cache = tmp_path / "hot.json"
    hot_routes.update_cache({"stale.example": 5}, path=str(cache), now=1000.0)
    # спустя время > ttl без обновления домена -> запись выселяется
    hot_routes.update_cache(
        {"fresh.example": 1}, path=str(cache), ttl=100.0, now=2000.0
    )
    data = json.loads(cache.read_text(encoding="utf-8"))
    names = {e["domain"] for e in data["domains"]}
    assert "stale.example" not in names
    assert "fresh.example" in names


def test_update_cache_top_n_truncation(tmp_path):
    cache = tmp_path / "hot.json"
    counts = {f"d{i}.example": i for i in range(1, 11)}
    hot_routes.update_cache(counts, path=str(cache), top_n=3, now=1000.0)
    data = json.loads(cache.read_text(encoding="utf-8"))
    names = {e["domain"] for e in data["domains"]}
    # оставлены только 3 самых частых (d10, d9, d8)
    assert names == {"d10.example", "d9.example", "d8.example"}


def test_update_cache_atomic_no_tmp_left(tmp_path):
    cache = tmp_path / "hot.json"
    hot_routes.update_cache({"a.example": 1}, path=str(cache), now=1000.0)
    leftovers = list(tmp_path.glob("*.tmp"))
    assert leftovers == []


def test_update_cache_ignores_non_numeric_count(tmp_path):
    """Несериализуемый/нечисловой count отбрасывается на входе (как в _load_cache):
    существующий домен цел, мусорный домен не появляется, вызов не бросает."""
    cache = tmp_path / "hot.json"
    hot_routes.update_cache({"a.example": 1}, path=str(cache), now=1000.0)
    result = hot_routes.update_cache({"b.example": object()}, path=str(cache), now=2000.0)
    assert result is not None
    data = json.loads(cache.read_text(encoding="utf-8"))
    names = {e["domain"] for e in data["domains"]}
    assert names == {"a.example"}


def test_update_cache_broken_existing_is_replaced(tmp_path):
    """Битый существующий кэш не роняет update — стартуем с чистого листа."""
    cache = tmp_path / "hot.json"
    cache.write_text("{not json", encoding="utf-8")
    result = hot_routes.update_cache({"a.example": 1}, path=str(cache), now=1000.0)
    assert result is not None
    data = json.loads(cache.read_text(encoding="utf-8"))
    assert data["domains"][0]["domain"] == "a.example"


def test_update_cache_bool_count_is_ignored(tmp_path):
    """bool как inc отбрасывается (иначе записался бы, но при чтении пропал бы)."""
    cache = tmp_path / "hot.json"
    hot_routes.update_cache({"a.example": True, "b.example": 2}, path=str(cache), now=1000.0)
    data = json.loads(cache.read_text(encoding="utf-8"))
    names = {e["domain"] for e in data["domains"]}
    assert names == {"b.example"}


def test_update_cache_non_numeric_now_does_not_raise(tmp_path):
    """Контракт «не бросает»: нечисловой now деградирует, не роняет вызов."""
    cache = tmp_path / "hot.json"
    result = hot_routes.update_cache({"a.example": 1}, path=str(cache), now="oops")
    # запись состоялась (now деградировал в системное время), не исключение
    assert result is not None


def test_update_cache_non_numeric_ttl_top_n_does_not_raise(tmp_path):
    cache = tmp_path / "hot.json"
    hot_routes.update_cache({"a.example": 1}, path=str(cache), now=1000.0)
    # существующий кэш есть -> путь ts-ttl / срез реально исполняется
    assert hot_routes.update_cache({"b.example": 1}, path=str(cache), ttl="week", now=2000.0) is None
    assert hot_routes.update_cache({"b.example": 1}, path=str(cache), top_n="ten", now=2000.0) is None


# ============================ hot_domains ============================
def test_hot_domains_returns_sorted_top_n(tmp_path):
    cache = tmp_path / "hot.json"
    hot_routes.update_cache(
        {"a.example": 1, "b.example": 9, "c.example": 5}, path=str(cache), now=1000.0
    )
    top = hot_routes.hot_domains(path=str(cache), top_n=2, now=1000.0)
    assert top == ["b.example", "c.example"]


def test_hot_domains_missing_cache_is_empty(tmp_path):
    assert hot_routes.hot_domains(path=str(tmp_path / "nope.json")) == []


def test_hot_domains_broken_cache_is_empty(tmp_path):
    cache = tmp_path / "hot.json"
    cache.write_text("garbage", encoding="utf-8")
    assert hot_routes.hot_domains(path=str(cache)) == []


def test_hot_domains_non_numeric_args_do_not_raise(tmp_path):
    """Контракт «не бросает»: нечисловые now/ttl/top_n при наличии данных -> []."""
    cache = tmp_path / "hot.json"
    hot_routes.update_cache({"a.example": 5}, path=str(cache), now=1000.0)
    assert hot_routes.hot_domains(path=str(cache), now="x", ttl=100.0) == []
    assert hot_routes.hot_domains(path=str(cache), ttl="week", now=1000.0) == []
    assert hot_routes.hot_domains(path=str(cache), top_n="ten", now=1000.0) == []


def test_hot_domains_excludes_expired(tmp_path):
    """hot_domains не отдаёт протухшие по TTL записи (чтение тоже фильтрует)."""
    cache = tmp_path / "hot.json"
    hot_routes.update_cache({"old.example": 5}, path=str(cache), now=1000.0)
    top = hot_routes.hot_domains(path=str(cache), ttl=100.0, now=5000.0)
    assert top == []


# ============================ privacy ============================
def test_cache_contains_only_hostnames(tmp_path):
    """В кэше нет полных URL/путей/query — только hostname, count, timestamp."""
    log = tmp_path / "privoxy.log"
    log.write_text(
        _privoxy_url_line("http://example.com/secret/path?token=SECRET123"),
        encoding="utf-8",
    )
    counts = hot_routes.parse_access_log(str(log))
    cache = tmp_path / "hot.json"
    hot_routes.update_cache(counts, path=str(cache), now=1000.0)
    raw = cache.read_text(encoding="utf-8")
    assert "SECRET123" not in raw
    assert "/secret/path" not in raw
    assert "example.com" in raw
    # ключи записей строго ограничены privacy-схемой
    data = json.loads(raw)
    for entry in data["domains"]:
        assert set(entry.keys()) == {"domain", "count", "last_seen"}


def test_default_constants_present():
    """Публичные дефолты существуют (TTL/top-N/пути) — контракт для интеграции."""
    assert isinstance(hot_routes.DEFAULT_TTL_SECONDS, (int, float))
    assert isinstance(hot_routes.DEFAULT_TOP_N, int)
    assert hot_routes.DEFAULT_TOP_N > 0
    assert isinstance(hot_routes._DEFAULT_CACHE_PATH, Path)
    assert isinstance(hot_routes._DEFAULT_LOG_PATH, Path)
