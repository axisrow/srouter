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
import random
import string
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


def _request_line(method, target):
    """Строка с произвольным request-target для privacy/security matrix."""
    return f'127.0.0.1 - - [Jul 02 14:00:00.000] "{method} {target} HTTP/1.1" 200 0'


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


def test_target_parser_accept_only_good_matrix_via_cache(tmp_path):
    """Полная matrix из issue #69: reject не появляется ни в counts, ни в кэше."""
    rejects = [
        ("GET", "http://[::1"),
        ("GET", "http://a℀b/"),
        ("GET", "SECRET123"),
        ("GET", "/relative"),
        ("GET", "*"),
        ("CONNECT", "SECRET123"),
        ("CONNECT", "SECRET123:abc"),
        ("CONNECT", "user:pass"),
        ("CONNECT", "host"),
        ("CONNECT", "http://host"),
        ("CONNECT", "user:pass@host:443"),
        ("CONNECT", "[dead:beef]:443"),
        ("CONNECT", "[::::]:443"),
        ("CONNECT", "[deadbeef]:443"),
        ("GET", "http://user:pass/path"),
        ("GET", "http://SECRET123:abc/path"),
        ("CONNECT", "[fe80::1%X]:443"),
        ("GET", "http://[fe80::1%25X]/x"),
        ("GET", "http://[v1.SECRET123]/x"),
        ("CONNECT", "[v1.SECRET123]:443"),
    ]
    accepts = [
        ("GET", "http://good.example/x"),
        ("GET", "http://good.example:8080/p?q=1"),
        ("CONNECT", "host:443"),
        ("CONNECT", "192.0.2.1:443"),
        ("CONNECT", "[::1]:443"),
        ("CONNECT", "[2001:db8::1]:443"),
    ]
    log = tmp_path / "privoxy.log"
    log.write_text(
        "\n".join(_request_line(method, target) for method, target in rejects + accepts),
        encoding="utf-8",
    )

    counts = hot_routes.parse_access_log(str(log))
    assert counts == {
        "good.example": 2,
        "host": 1,
        "192.0.2.1": 1,
        "::1": 1,
        "2001:db8::1": 1,
    }

    cache = tmp_path / "hot.json"
    result = hot_routes.update_cache(counts, path=str(cache), now=1000.0)
    assert result is not None
    raw = cache.read_text(encoding="utf-8").lower()
    names = {entry["domain"] for entry in json.loads(raw)["domains"]}
    assert names == set(counts)
    for leaked in [
        "secret123",
        "user",
        "pass",
        "dead:beef",
        "deadbeef",
        "fe80",
        "v1.secret123",
        "relative",
    ]:
        assert leaked not in raw


def test_target_parser_rejects_overlong_dns_names_via_cache(tmp_path):
    """DNS hostname limits: label <=63, full name <=253, через public API."""
    max_label_host = f"{'a' * 63}.example"
    overlong_label_host = f"{'a' * 64}.example"
    overlong_name_host = ".".join(["a" * 63] * 4)  # 255 chars with dots.
    log = tmp_path / "privoxy.log"
    log.write_text(
        "\n".join(
            [
                _request_line("GET", "http://good.example/x"),
                _request_line("GET", f"http://{max_label_host}/x"),
                _request_line("GET", f"http://{overlong_label_host}/x"),
                _request_line("GET", f"http://{overlong_name_host}/x"),
            ]
        ),
        encoding="utf-8",
    )

    counts = hot_routes.parse_access_log(str(log))
    assert counts == {"good.example": 1, max_label_host: 1}
    assert overlong_label_host not in counts
    assert overlong_name_host not in counts

    cache = tmp_path / "hot.json"
    result = hot_routes.update_cache(counts, path=str(cache), now=1000.0)
    assert result is not None
    raw = cache.read_text(encoding="utf-8")
    names = {entry["domain"] for entry in json.loads(raw)["domains"]}
    assert names == {"good.example", max_label_host}
    assert overlong_label_host not in raw
    assert overlong_name_host not in raw


def test_target_parser_fuzz_never_raises_and_outputs_whitelisted(tmp_path):
    """50k deterministic fuzz: public parse/update не бросают, выход whitelist-only."""
    rng = random.Random(69)
    alphabet = string.ascii_letters + string.digits + "-._:@[]/%?#*" + "℀"
    lines = []
    for _ in range(50000):
        method = rng.choice(["GET", "POST", "CONNECT"])
        token = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 40)))
        shape = rng.randrange(5)
        if shape == 0:
            target = f"http://{token}/x"
        elif shape == 1:
            target = f"http://{token}:443/p?q=1"
        elif shape == 2 and method == "CONNECT":
            target = f"{token}:443"
        elif shape == 3 and method == "CONNECT":
            target = f"[{token}]:443"
        else:
            target = token
        lines.append(_request_line(method, target))

    log = tmp_path / "privoxy.log"
    log.write_text("\n".join(lines), encoding="utf-8")
    counts = hot_routes.parse_access_log(
        str(log), max_lines=60000, max_bytes=16 * 1024 * 1024
    )
    assert all(hot_routes._is_hostname(domain) for domain in counts)

    cache = tmp_path / "hot.json"
    result = hot_routes.update_cache(counts, path=str(cache), now=1000.0)
    assert result is not None
    assert all(hot_routes._is_hostname(entry["domain"]) for entry in result.values())


# ============================ parse_new_access_log ============================
def test_parse_new_access_log_reads_only_new_lines(tmp_path):
    log = tmp_path / "privoxy.log"
    log.write_text(_privoxy_line("old.example") + "\n", encoding="utf-8")

    counts, cursor = hot_routes.parse_new_access_log(str(log), None, None, None)
    assert counts == {"old.example": 1}

    with open(log, "a", encoding="utf-8") as f:
        f.write(_privoxy_line("new.example") + "\n")

    counts, cursor = hot_routes.parse_new_access_log(
        str(log),
        cursor["log_offset"],
        cursor["log_inode"],
        cursor["log_dev"],
    )
    assert counts == {"new.example": 1}
    assert cursor["log_offset"] == log.stat().st_size


def test_parse_new_access_log_size_equal_offset_noop(tmp_path):
    log = tmp_path / "privoxy.log"
    log.write_text(_privoxy_line("a.example") + "\n", encoding="utf-8")
    st = log.stat()

    counts, cursor = hot_routes.parse_new_access_log(
        str(log), st.st_size, st.st_ino, st.st_dev
    )

    assert counts == {}
    assert cursor == {
        "log_offset": st.st_size,
        "log_inode": st.st_ino,
        "log_dev": st.st_dev,
        "log_size": st.st_size,
    }


def test_parse_new_access_log_rotation_inode_reset(tmp_path):
    log = tmp_path / "privoxy.log"
    log.write_text(_privoxy_line("after-rotate.example") + "\n", encoding="utf-8")
    st = log.stat()

    counts, cursor = hot_routes.parse_new_access_log(
        str(log), st.st_size, st.st_ino + 1000, st.st_dev
    )

    assert counts == {"after-rotate.example": 1}
    assert cursor["log_offset"] == st.st_size
    assert cursor["log_inode"] == st.st_ino


def test_parse_new_access_log_truncate_reset(tmp_path):
    log = tmp_path / "privoxy.log"
    log.write_text(
        _privoxy_line("old.example") + "\n" + _privoxy_line("old.example") + "\n",
        encoding="utf-8",
    )
    old = log.stat()
    log.write_text(_privoxy_line("after-truncate.example") + "\n", encoding="utf-8")
    new = log.stat()

    counts, cursor = hot_routes.parse_new_access_log(
        str(log), old.st_size, new.st_ino, new.st_dev
    )

    assert counts == {"after-truncate.example": 1}
    assert cursor["log_offset"] == new.st_size


def test_parse_new_access_log_partial_line_no_double_count(tmp_path):
    log = tmp_path / "privoxy.log"
    complete = _privoxy_line("complete.example") + "\n"
    partial = _privoxy_line("partial.example")
    log.write_text(complete + partial, encoding="utf-8")

    counts, cursor = hot_routes.parse_new_access_log(str(log), None, None, None)
    assert counts == {"complete.example": 1}
    assert cursor["log_offset"] == len(complete.encode("utf-8"))

    with open(log, "a", encoding="utf-8") as f:
        f.write("\n")
    counts, cursor = hot_routes.parse_new_access_log(
        str(log),
        cursor["log_offset"],
        cursor["log_inode"],
        cursor["log_dev"],
    )
    assert counts == {"partial.example": 1}

    counts, _cursor = hot_routes.parse_new_access_log(
        str(log),
        cursor["log_offset"],
        cursor["log_inode"],
        cursor["log_dev"],
    )
    assert counts == {}


def test_parse_new_access_log_first_run_bounded_tail(tmp_path):
    log = tmp_path / "privoxy.log"
    old = [_privoxy_line(f"old{i}.example") for i in range(5)]
    recent = [_privoxy_line("recent1.example"), _privoxy_line("recent2.example")]
    log.write_text("\n".join(old + recent) + "\n", encoding="utf-8")
    tail_bytes = len(("\n".join(recent) + "\n").encode("utf-8")) + 1

    counts, cursor = hot_routes.parse_new_access_log(
        str(log), None, None, None, max_bytes=tail_bytes
    )

    assert counts == {"recent1.example": 1, "recent2.example": 1}
    assert cursor["log_offset"] == log.stat().st_size
    assert all(not name.startswith("old") for name in counts)


# ============================ update_cache ============================
def test_ttl_refresh_loop_regression_static_log_evicts(tmp_path):
    """Статичный лог не должен освежать last_seen и раздувать count на каждом poll."""
    log = tmp_path / "privoxy.log"
    cache = tmp_path / "hot.json"
    log.write_text(_privoxy_line("stale.example") + "\n", encoding="utf-8")

    counts, cursor = hot_routes.parse_new_access_log(str(log), None, None, None)
    assert counts == {"stale.example": 1}
    hot_routes.update_cache(
        counts, path=str(cache), ttl=100.0, now=1000.0, cursor=cursor
    )

    counts, cursor = hot_routes.parse_new_access_log(
        str(log),
        cursor["log_offset"],
        cursor["log_inode"],
        cursor["log_dev"],
    )
    assert counts == {}
    hot_routes.update_cache(
        counts, path=str(cache), ttl=100.0, now=1201.0, cursor=cursor
    )

    data = json.loads(cache.read_text(encoding="utf-8"))
    assert data["domains"] == []
    assert hot_routes.hot_domains(path=str(cache), ttl=100.0, now=1201.0) == []


def test_update_cache_roundtrip(tmp_path):
    cache = tmp_path / "hot.json"
    hot_routes.update_cache({"a.example": 3, "b.example": 1}, path=str(cache), now=1000.0)
    data = json.loads(cache.read_text(encoding="utf-8"))
    domains = {e["domain"]: e for e in data["domains"]}
    assert domains["a.example"]["count"] == 3
    assert domains["b.example"]["count"] == 1
    assert domains["a.example"]["last_seen"] == 1000.0
    assert data["meta"]["schema"] == 2
    assert data["meta"]["bucket_size"] == hot_routes.DEFAULT_BUCKET_SECONDS
    assert data["buckets"]["a.example"] == {"0": 3}


def test_update_cache_windowed_accumulation(tmp_path):
    cache = tmp_path / "hot.json"
    hot_routes.update_cache(
        {"a.example": 2}, path=str(cache), ttl=100.0, now=1000.0, bucket_size=10
    )
    hot_routes.update_cache(
        {"a.example": 3}, path=str(cache), ttl=100.0, now=1040.0, bucket_size=10
    )
    data = json.loads(cache.read_text(encoding="utf-8"))
    domains = {e["domain"]: e for e in data["domains"]}
    assert domains["a.example"]["count"] == 5
    assert domains["a.example"]["last_seen"] == 1040.0

    hot_routes.update_cache(
        {"a.example": 4}, path=str(cache), ttl=100.0, now=1120.0, bucket_size=10
    )
    data = json.loads(cache.read_text(encoding="utf-8"))
    domains = {e["domain"]: e for e in data["domains"]}
    assert domains["a.example"]["count"] == 7
    assert data["buckets"]["a.example"] == {"1040": 3, "1120": 4}


def test_update_cache_sliding_window_forgets_old(tmp_path):
    cache = tmp_path / "hot.json"
    hot_routes.update_cache(
        {"old.example": 2}, path=str(cache), ttl=50.0, now=1000.0, bucket_size=10
    )
    hot_routes.update_cache({}, path=str(cache), ttl=50.0, now=1061.0, bucket_size=10)

    data = json.loads(cache.read_text(encoding="utf-8"))
    assert data["domains"] == []
    assert data["buckets"] == {}


def test_update_cache_sliding_window_keeps_fresh_bucket(tmp_path):
    cache = tmp_path / "hot.json"
    hot_routes.update_cache(
        {"a.example": 2}, path=str(cache), ttl=50.0, now=1000.0, bucket_size=10
    )
    hot_routes.update_cache(
        {"a.example": 3}, path=str(cache), ttl=50.0, now=1040.0, bucket_size=10
    )
    hot_routes.update_cache({}, path=str(cache), ttl=50.0, now=1051.0, bucket_size=10)

    data = json.loads(cache.read_text(encoding="utf-8"))
    domains = {e["domain"]: e for e in data["domains"]}
    assert domains["a.example"]["count"] == 3
    assert data["buckets"]["a.example"] == {"1040": 3}


def test_update_cache_migrates_legacy_flat_cache(tmp_path):
    cache = tmp_path / "hot.json"
    cache.write_text(
        json.dumps(
            {
                "domains": [
                    {"domain": "legacy.example", "count": 5, "last_seen": 1000.0}
                ]
            }
        ),
        encoding="utf-8",
    )

    result = hot_routes.update_cache(
        {}, path=str(cache), ttl=100.0, now=1050.0, bucket_size=10
    )

    assert result is not None
    data = json.loads(cache.read_text(encoding="utf-8"))
    assert data["meta"]["schema"] == 2
    assert data["domains"] == [
        {"domain": "legacy.example", "count": 5, "last_seen": 1000.0}
    ]
    assert data["buckets"] == {"legacy.example": {"1000": 5}}


def test_update_cache_meta_roundtrip_from_cursor(tmp_path):
    log = tmp_path / "privoxy.log"
    cache = tmp_path / "hot.json"
    log.write_text(_privoxy_line("meta.example") + "\n", encoding="utf-8")
    counts, cursor = hot_routes.parse_new_access_log(str(log), None, None, None)

    hot_routes.update_cache(
        counts,
        path=str(cache),
        now=1000.0,
        bucket_size=60,
        cursor=cursor,
    )

    data = json.loads(cache.read_text(encoding="utf-8"))
    assert data["meta"] == {
        "log_offset": cursor["log_offset"],
        "log_inode": cursor["log_inode"],
        "log_dev": cursor["log_dev"],
        "log_size": cursor["log_size"],
        "bucket_size": 60,
        "schema": 2,
    }
    assert hot_routes.load_cursor(str(cache)) == {
        "log_offset": cursor["log_offset"],
        "log_inode": cursor["log_inode"],
        "log_dev": cursor["log_dev"],
        "log_size": cursor["log_size"],
    }


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


def test_update_cache_ignores_non_finite_input_counts(tmp_path):
    """NaN/Infinity на write-boundary отбрасываются до json.dumps."""
    cache = tmp_path / "hot.json"
    result = hot_routes.update_cache(
        {
            "nan.example": float("nan"),
            "inf.example": float("inf"),
            "neg-inf.example": float("-inf"),
            "good.example": 2,
        },
        path=str(cache),
        now=1000.0,
    )
    assert result is not None
    assert set(result) == {"good.example"}
    raw = cache.read_text(encoding="utf-8")
    assert "NaN" not in raw
    assert "Infinity" not in raw


def test_update_cache_ignores_non_finite_crafted_cache_counts(tmp_path):
    """json.load принимает NaN/Infinity; _load_cache обязан молча отфильтровать."""
    cache = tmp_path / "hot.json"
    cache.write_text(
        """{
  "domains": [
    {"domain": "nan.example", "count": NaN, "last_seen": 1000.0},
    {"domain": "inf.example", "count": Infinity, "last_seen": 1000.0},
    {"domain": "neg-inf.example", "count": -Infinity, "last_seen": 1000.0},
    {"domain": "bad_key", "count": 5, "last_seen": 1000.0},
    {"domain": "good.example", "count": 2, "last_seen": 1000.0}
  ]
}""",
        encoding="utf-8",
    )
    result = hot_routes.update_cache({"fresh.example": 1}, path=str(cache), now=2000.0)
    assert result is not None
    assert set(result) == {"good.example", "fresh.example"}
    raw = cache.read_text(encoding="utf-8")
    assert "NaN" not in raw
    assert "Infinity" not in raw


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
    assert (
        hot_routes.update_cache(
            {"b.example": 1}, path=str(cache), ttl="week", now=2000.0
        )
        is None
    )
    assert (
        hot_routes.update_cache(
            {"b.example": 1}, path=str(cache), top_n="ten", now=2000.0
        )
        is None
    )


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
    assert set(data["buckets"]) == {"example.com"}
    assert "SECRET123" not in json.dumps(data["buckets"])
    assert "/secret/path" not in json.dumps(data["buckets"])


def test_default_constants_present():
    """Публичные дефолты существуют (TTL/top-N/пути) — контракт для интеграции."""
    assert isinstance(hot_routes.DEFAULT_TTL_SECONDS, (int, float))
    assert isinstance(hot_routes.DEFAULT_TOP_N, int)
    assert isinstance(hot_routes.DEFAULT_BUCKET_SECONDS, int)
    assert hot_routes.DEFAULT_TOP_N > 0
    assert hot_routes.DEFAULT_BUCKET_SECONDS > 0
    assert isinstance(hot_routes._DEFAULT_CACHE_PATH, Path)
    assert isinstance(hot_routes._DEFAULT_LOG_PATH, Path)
