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

import pytest

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


# --- RFC-7230 target-парсер: полная matrix (issue #69) ---
# Каждый кейс — реальная строка лога "<method> <target> HTTP/1.1", гоняется через
# parse_access_log (end-to-end, не только _extract_host). Граница «только hostname»:
# absolute-form и CONNECT authority-form host:port с ЧИСЛОВЫМ портом принимаются;
# origin/asterisk/голый-токен/без-порта/нечисловой-порт/userinfo — REJECT.
_MATRIX_REJECT = [
    ("GET", "http://[::1"),                 # битый IPv6 URL (urlsplit ValueError)
    ("GET", "http://a℀b/"),                 # не-ASCII netloc под NFKC (ValueError)
    ("GET", "SECRET123"),                   # голый токен, не URL
    ("GET", "/relative"),                   # origin-form, hostname не несёт
    ("GET", "*"),                           # asterisk-form (OPTIONS *)
    ("CONNECT", "SECRET123"),               # authority без порта
    ("CONNECT", "SECRET123:abc"),           # нечисловой порт
    ("CONNECT", "user:pass"),               # userinfo-токен (не host:port)
    ("CONNECT", "host"),                    # без порта
    ("CONNECT", "http://host"),             # absolute URL в CONNECT — malformed
    ("CONNECT", "user:pass@host:443"),      # userinfo в authority
    ("CONNECT", "[dead:beef]:443"),         # мусорный IPv6 (loose-regex пропускал)
    ("CONNECT", "[abc:def]:443"),           # не-hex вне диапазона -> невалиден
    ("CONNECT", "[::::]:443"),              # лишние ':' -> невалидный IPv6
    ("CONNECT", "[deadbeef]:443"),          # без ':' -> не IPv6-литерал
]
_MATRIX_ACCEPT = [
    ("GET", "http://good.example/x", "good.example"),
    ("GET", "http://good.example:8080/p?q=1", "good.example"),
    ("CONNECT", "host:443", "host"),
    ("CONNECT", "192.0.2.1:443", "192.0.2.1"),
    ("CONNECT", "[::1]:443", "::1"),
    ("CONNECT", "[2001:db8::1]:443", "2001:db8::1"),
]


@pytest.mark.parametrize("method,target", _MATRIX_REJECT)
def test_parse_target_matrix_reject(tmp_path, method, target):
    """REJECT-кейсы: ни один не должен дать домен (privacy-граница)."""
    log = tmp_path / "privoxy.log"
    log.write_text(
        f'127.0.0.1 - - [ts] "{method} {target} HTTP/1.1" 200 0', encoding="utf-8"
    )
    assert hot_routes.parse_access_log(str(log)) == {}


@pytest.mark.parametrize("method,target,host", _MATRIX_ACCEPT)
def test_parse_target_matrix_accept(tmp_path, method, target, host):
    """ACCEPT-кейсы: считается ровно hostname (без порта/пути/query)."""
    log = tmp_path / "privoxy.log"
    log.write_text(
        f'127.0.0.1 - - [ts] "{method} {target} HTTP/1.1" 200 0', encoding="utf-8"
    )
    assert hot_routes.parse_access_log(str(log)) == {host: 1}


def test_parse_matrix_reject_does_not_poison_valid(tmp_path):
    """REJECT-строки в одном логе с валидной: считается только валидная (одна битая
    строка не роняет parse_access_log и не подмешивает мусор)."""
    lines = [f'127.0.0.1 - - [ts] "{m} {t} HTTP/1.1" 200 0' for m, t in _MATRIX_REJECT]
    lines.append(_privoxy_url_line("http://good.example/x"))
    log = tmp_path / "privoxy.log"
    log.write_text("\n".join(lines), encoding="utf-8")
    assert hot_routes.parse_access_log(str(log)) == {"good.example": 1}


def test_ipv6_garbage_never_reaches_cache(tmp_path):
    """End-to-end через ПУБЛИЧНЫЕ parse_access_log + update_cache: мусорный
    IPv6-литерал не попадает в кэш (loose-regex его пропускал бы как host).
    Валидный canonical IPv6 при этом сохраняется."""
    garbage = ["[dead:beef]:443", "[abc:def]:443", "[::::]:443", "[deadbeef]:443"]
    lines = [f'127.0.0.1 - - [ts] "CONNECT {t} HTTP/1.1" 200 0' for t in garbage]
    lines.append('127.0.0.1 - - [ts] "CONNECT [2001:db8::1]:443 HTTP/1.1" 200 0')
    log = tmp_path / "privoxy.log"
    log.write_text("\n".join(lines), encoding="utf-8")

    counts = hot_routes.parse_access_log(str(log))
    assert counts == {"2001:db8::1": 1}

    cache = tmp_path / "hot.json"
    hot_routes.update_cache(counts, path=str(cache), now=1000.0)
    raw = cache.read_text(encoding="utf-8")
    for bad in ("dead:beef", "::::", "deadbeef", "abc:def"):
        assert bad not in raw
    assert hot_routes.hot_domains(path=str(cache), now=1000.0) == ["2001:db8::1"]


def test_ipv6_garbage_key_rejected_on_read(tmp_path):
    """Write/read симметрия на СТРОГОЙ проверке: битый IPv6-ключ, даже если он уже
    в файле кэша, отвергается при чтении (_is_hostname через ipaddress)."""
    cache = tmp_path / "hot.json"
    cache.write_text(
        json.dumps(
            {
                "domains": [
                    {"domain": "::::", "count": 9, "last_seen": 1000.0},
                    {"domain": "good.example", "count": 1, "last_seen": 1000.0},
                ]
            }
        ),
        encoding="utf-8",
    )
    assert hot_routes.hot_domains(path=str(cache), now=1000.0) == ["good.example"]


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
