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
    # Курсор — только числа (offset/inode/dev/size). Никакого производного контента
    # на диске: content-free механизм не добавляет полей в курсор (privacy-схема #76).
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


def test_parse_new_access_log_copytruncate_regrowth_counts_all(tmp_path):
    """copytruncate (усечение in-place: тот же inode/dev) + дорост ЗА старый offset
    до следующего poll не должен пропускать начальные строки нового файла.

    Баг #79: inode/dev совпадают и cur_size >= saved_offset, поэтому старая
    (inode,dev)/size-эвристика не детектила ротацию и reader seek'ал в середину
    нового контента, теряя NEW1/NEW2. Content-free boundary-newline check ловит
    подмену границы (байт [offset-1] нового контента почти никогда не '\\n') и
    делает resync (offset=0), считая все три новые строки ровно один раз.
    """
    log = tmp_path / "privoxy.log"
    # Реальные privoxy-строки переменной длины (хосты разной длины) -> новый контент
    # не выравнен по старому offset, байт на границе offset-1 не '\\n' -> сигнал ловит.
    log.write_text(
        _privoxy_line("o1.example") + "\n" + _privoxy_line("o2.example") + "\n",
        encoding="utf-8",
    )

    counts, cursor = hot_routes.parse_new_access_log(str(log), None, None, None)
    assert counts == {"o1.example": 1, "o2.example": 1}
    saved_offset = cursor["log_offset"]

    # copytruncate: open('w') усекает тот же inode/dev, затем пишет 3 НОВЫЕ строки.
    inode_before = log.stat().st_ino
    with open(log, "w", encoding="utf-8") as f:
        f.write(_privoxy_line("new-long-host-1.example") + "\n")
        f.write(_privoxy_line("new-long-host-2.example") + "\n")
        f.write(_privoxy_line("new-long-host-3.example") + "\n")
    # Sanity: репро валиден только если inode тот же, файл дорос за старый offset,
    # и байт на старой границе больше НЕ '\\n' (иначе content-free сигнал не сработал бы —
    # это тот самый патологический undercount-случай, тут его не проверяем).
    assert log.stat().st_ino == inode_before
    assert log.stat().st_size > saved_offset
    assert log.read_bytes()[saved_offset - 1 : saved_offset] != b"\n"

    counts, cursor2 = hot_routes.parse_new_access_log(
        str(log),
        cursor["log_offset"],
        cursor["log_inode"],
        cursor["log_dev"],
    )
    assert counts == {
        "new-long-host-1.example": 1,
        "new-long-host-2.example": 1,
        "new-long-host-3.example": 1,
    }
    assert cursor2["log_offset"] == log.stat().st_size

    # Идемпотентность: повторный poll без новых строк ничего не досчитывает.
    counts, _cursor3 = hot_routes.parse_new_access_log(
        str(log),
        cursor2["log_offset"],
        cursor2["log_inode"],
        cursor2["log_dev"],
    )
    assert counts == {}


def test_parse_new_access_log_copytruncate_regrowth_stays_bounded(tmp_path):
    """Resync по newline-mismatch на большом файле читает bounded tail, не весь файл.

    copytruncate может подменить содержимое под тем же inode и дорастить его далеко
    за max_bytes ещё до следующего poll. resync (offset=0) не должен превращаться в
    чтение гигабайта: newline-mismatch попадает в тот же tail-режим, что и ротация.
    Проверяем, что первая (обрезанная) строка окна не считается.
    """
    log = tmp_path / "privoxy.log"
    log.write_text(_privoxy_line("old.example") + "\n", encoding="utf-8")
    counts, cursor = hot_routes.parse_new_access_log(str(log), None, None, None)
    assert counts == {"old.example": 1}
    saved_offset = cursor["log_offset"]

    # copytruncate + дорост за пределы окна max_bytes.
    lines = [_privoxy_line(f"win{i}.example") for i in range(6)]
    with open(log, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    # Граница подменена -> сработает newline-mismatch resync.
    assert log.read_bytes()[saved_offset - 1 : saved_offset] != b"\n"
    # Окно вмещает только 2 последние строки + байт (первая обрезается и не считается).
    tail_bytes = len(("\n".join(lines[-2:]) + "\n").encode("utf-8")) + 1

    counts, _cursor = hot_routes.parse_new_access_log(
        str(log),
        cursor["log_offset"],
        cursor["log_inode"],
        cursor["log_dev"],
        max_bytes=tail_bytes,
    )
    # resync -> tail_mode: считаны только 2 последние строки, начало окна отброшено.
    assert counts == {"win4.example": 1, "win5.example": 1}


def test_parse_new_access_log_legit_offset_zero_reads_all_lines(tmp_path):
    """Легитимный persisted-курсор offset=0 с ВАЛИДНЫМ inode/dev на большом файле
    читает ВСЕ строки, а не только tail-хвост.

    Регресс на находку code-review: `read_offset == 0` в предикате tail_mode смешивал
    два разных нуля — resync-к-нулю (нужен tail-bound) и честный курсор на 0 (poll
    пустого лога отдаёт {log_offset:0, log_inode:<valid>, log_dev:<valid>}). Второй
    случай ошибочно уходил в tail-режим и терял ранние строки. tail-bound должен
    применяться только к НАСТОЯЩЕМУ resync (флаг resynced), не к saved_offset==0.
    """
    log = tmp_path / "privoxy.log"
    # Пустой лог -> курсор честно стоит на offset=0 с валидным inode/dev.
    log.write_text("", encoding="utf-8")
    counts, cursor = hot_routes.parse_new_access_log(str(log), None, None, None)
    assert counts == {}
    assert cursor["log_offset"] == 0

    # Лог наполняется многими строками сразу, файл перерастает max_bytes.
    hosts = [f"h{i:02d}.example" for i in range(30)]
    log.write_text("\n".join(_privoxy_line(h) for h in hosts) + "\n", encoding="utf-8")
    max_bytes = 400
    assert log.stat().st_size > max_bytes

    # Курсор честно стоял на 0 (не resync) -> читаем С НАЧАЛА (bounded по max_bytes),
    # а НЕ хвост. Первый poll обязан вернуть ранние строки (h00...), не поздние (h29).
    counts, cursor = hot_routes.parse_new_access_log(
        str(log),
        cursor["log_offset"],
        cursor["log_inode"],
        cursor["log_dev"],
        max_bytes=max_bytes,
    )
    assert "h00.example" in counts  # читаем с начала
    assert "h29.example" not in counts  # не tail-режим (хвост НЕ пропущен вперёд)

    # Инкрементальные poll'ы дочитывают ОСТАТОК без потерь: курсор двигается вперёд,
    # каждая строка посчитана ровно раз. На баге (tail-режим) h00..h27 были бы утеряны.
    seen = dict(counts)
    for _ in range(30):
        counts, cursor = hot_routes.parse_new_access_log(
            str(log),
            cursor["log_offset"],
            cursor["log_inode"],
            cursor["log_dev"],
            max_bytes=max_bytes,
        )
        if not counts:
            break
        for h, c in counts.items():
            seen[h] = seen.get(h, 0) + c
    assert seen == {h: 1 for h in hosts}


def test_parse_new_access_log_append_does_not_false_resync(tmp_path):
    """Обычный append не триггерит newline-resync: байт на границе offset — '\\n',
    поэтому старые строки не пересчитываются (happy-path курсора цел)."""
    log = tmp_path / "privoxy.log"
    log.write_text(_privoxy_line("a.example") + "\n", encoding="utf-8")
    counts, cursor = hot_routes.parse_new_access_log(str(log), None, None, None)
    assert counts == {"a.example": 1}

    with open(log, "a", encoding="utf-8") as f:
        f.write(_privoxy_line("b.example") + "\n")
    counts, cursor2 = hot_routes.parse_new_access_log(
        str(log), cursor["log_offset"], cursor["log_inode"], cursor["log_dev"]
    )
    # Граница цела -> считаем только новую строку, a.example НЕ пересчитан.
    assert counts == {"b.example": 1}
    assert cursor2["log_offset"] == log.stat().st_size


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


def test_copytruncate_regrowth_survives_cache_roundtrip(tmp_path):
    """Content-free детект #79 работает через реальный кэш-round-trip (после рестарта).

    Прод-путь (dashboard_hotroutes) на каждом poll читает курсор из кэша через
    load_cursor, а не держит его в памяти. Курсор — только числа (offset/inode/dev/
    size), поэтому детект copytruncate НЕ зависит от персиста контента: newline на
    границе проверяется в текущем файле. Здесь: poll1 -> update_cache; затем
    copytruncate+regrowth; poll2 читает курсор ИЗ КЭША (эмулируем рестарт) и обязан
    посчитать все новые строки, не seek'нув в середину нового контента.
    """
    log = tmp_path / "privoxy.log"
    cache = tmp_path / "hot.json"
    log.write_text(
        _privoxy_line("o1.example") + "\n" + _privoxy_line("o2.example") + "\n",
        encoding="utf-8",
    )

    cursor0 = hot_routes.load_cursor(str(cache))  # пустой кэш -> {}
    counts, cursor = hot_routes.parse_new_access_log(
        str(log),
        cursor0.get("log_offset"),
        cursor0.get("log_inode"),
        cursor0.get("log_dev"),
    )
    assert counts == {"o1.example": 1, "o2.example": 1}
    hot_routes.update_cache(counts, path=str(cache), now=1000.0, cursor=cursor)

    # copytruncate + regrowth за старый offset (строки переменной длины -> граница
    # offset-1 попадает в середину нового контента, не '\\n').
    with open(log, "w", encoding="utf-8") as f:
        f.write(_privoxy_line("new-long-host-1.example") + "\n")
        f.write(_privoxy_line("new-long-host-2.example") + "\n")
        f.write(_privoxy_line("new-long-host-3.example") + "\n")

    # Курсор берём ИЗ КЭША (как прод после рестарта), не из памяти.
    persisted = hot_routes.load_cursor(str(cache))
    counts, _cursor = hot_routes.parse_new_access_log(
        str(log),
        persisted.get("log_offset"),
        persisted.get("log_inode"),
        persisted.get("log_dev"),
    )
    assert counts == {
        "new-long-host-1.example": 1,
        "new-long-host-2.example": 1,
        "new-long-host-3.example": 1,
    }


def test_cache_meta_never_persists_content_derivative(tmp_path):
    """Privacy-инвариант #76: на диск в meta идут ТОЛЬКО числа — никакого хеша/байт
    контента лога. Регресс на находку privacy code-review (sha1 границы на диске).
    """
    log = tmp_path / "privoxy.log"
    cache = tmp_path / "hot.json"
    log.write_text(_privoxy_line("secret-host.example") + "\n", encoding="utf-8")

    counts, cursor = hot_routes.parse_new_access_log(str(log), None, None, None)
    hot_routes.update_cache(counts, path=str(cache), now=1000.0, cursor=cursor)

    # Курсор из parse не несёт производных контента.
    assert set(cursor) == {"log_offset", "log_inode", "log_dev", "log_size"}

    # На диске meta — только числовые cursor-поля + служебные bucket_size/schema.
    data = json.loads(cache.read_text(encoding="utf-8"))
    assert set(data["meta"]) == {
        "log_offset",
        "log_inode",
        "log_dev",
        "log_size",
        "bucket_size",
        "schema",
    }
    for value in data["meta"].values():
        assert isinstance(value, int)

    # Даже неизвестное производное контента в meta не переживает валидацию курсора.
    assert "log_fingerprint" not in hot_routes.load_cursor(str(cache))


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
