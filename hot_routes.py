"""Observe-only детект популярных маршрутов: подсчёт частоты запросов per-domain
из локального privoxy access-лога + opt-in локальный кэш top-N с TTL.

Контракт (issue #9, automation ladder — observe first):
- Модуль ТОЛЬКО считает и отдаёт top-N. Он НЕ влияет на роутинг в этом виде —
  влияние (dashboard status-поле, gen_xray_config hot-list) добавляется отдельными
  шагами после валидации.
- Privacy-first: в памяти и на диске хранятся ТОЛЬКО hostname + счётчик + timestamp.
  Полные URL, пути, query-строки, тела запросов, IP-клиентов НЕ извлекаются и НЕ
  сохраняются никогда. Из абсолютного URL берётся исключительно hostname.
- Opt-in: кэш живёт в ignored-файле `srouter.hot_routes.json` рядом с модулем и
  НИКОГДА не коммитится/не аплоадится. Никакой сети/телеметрии — чистый файловый
  stdlib-only модуль.
- Defensive (канон #2, как local_state): функции НИКОГДА не бросают; отсутствующий/
  битый файл, кривые строки, несериализуемый ввод -> пусто/None, не исключение.

Формат лога (первоисточник — privoxy Common Log Format при `debug 1`):
    <ip> - - [<ts>] "<method> <target> HTTP/x.x" <code> <size>
где <target> для CONNECT — `host:port`, для остальных методов — абсолютный URL.
Из <target> извлекается ТОЛЬКО hostname (порт, путь, query отбрасываются).
xray в проекте по умолчанию access-лог не пишет (loglevel warning), поэтому
первоисточник здесь — privoxy; парсер устойчив к чужим/битым строкам.

Атомарность записи кэша — тот же паттерн, что local_state.save_state:
temp-файл рядом + `os.replace` (atomic rename); при сбое tmp подчищается, а уже
существующий валидный кэш остаётся нетронутым.
"""
import json
import os
import ipaddress
import math
import re
from pathlib import Path
from urllib.parse import urlsplit

# Пути по умолчанию — рядом с модулем (не cwd), чтобы работало под launchd.
# Кэш — ignored-файл (см. .gitignore), никогда не коммитится и не аплоадится.
_DEFAULT_CACHE_PATH = Path(__file__).resolve().parent / "srouter.hot_routes.json"
# Дефолтный путь privoxy access-лога (Homebrew). Отсутствие файла -> пусто (opt-in:
# лог включается пользователем через `debug 1` в privoxy config, по умолчанию нет).
_DEFAULT_LOG_PATH = Path("/opt/homebrew/var/log/privoxy/logfile")

# Дефолты top-N / TTL — публичный контракт для будущей интеграции.
DEFAULT_TOP_N = 20
DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60  # неделя
DEFAULT_BUCKET_SECONDS = 3600

# Лимиты чтения: не тянем весь (потенциально гигабайтный) лог — только хвост.
_DEFAULT_MAX_LINES = 20000
_DEFAULT_MAX_BYTES = 4 * 1024 * 1024  # 4 MiB хвоста

# Content-free детект copytruncate (issue #79). При copytruncate лог усекается
# in-place (тот же inode/dev) и дорастает ЗА старый offset до следующего poll —
# (inode,dev)/size-эвристика ротацию не видит и reader seek'ает в середину нового
# контента, теряя начальные строки. Курсор ВСЕГДА ставится сразу после '\n'
# (new_offset = start+last_newline+1), поэтому байт на позиции offset-1 в целом
# файле обязан быть '\n'. Перед seek проверяем это: если новый контент разной длины
# со старым, байт на старой границе — середина строки, не '\n' -> mismatch -> resync.
#
# Best-effort limit (НЕ строгая гарантия): если новые строки РОВНО той же длины, что
# старые (напр. повторяющиеся CONNECT к одному хосту — частый случай), граница снова
# совпадает с '\n', детект НЕ срабатывает -> начальные строки пропускаются (undercount).
# Это сознательный трейд-офф в пользу privacy #76: строгая гарантия требовала бы
# писать производное контента лога на диск. Fail-направление безопасное: undercount
# (observe-only, наблюдаемость занижена), НЕ inflation, НЕ privacy-leak — direction
# из issue #79. Ключевое: на диск НЕ идёт ничего производного от контента лога (ни
# хеша, ни байт) — privacy-схема #76 нетронута (санкция оркестратора, PR #92).
_NEWLINE = 0x0A

# Строгий RFC 3986 reg-name: LDH labels, без '_' / ':' / '@' / '[' / ']' / '%'.
# IPv4/IPv6 проходят отдельными canonical-ветками в _is_hostname.
_REG_NAME_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\Z"
)
_NUMERIC_DOTTED_RE = re.compile(r"^[0-9.]+\Z")
_PORT_RE = re.compile(r"^[0-9]+\Z")
_MAX_DNS_NAME_LENGTH = 253
_MAX_DNS_LABEL_LENGTH = 63

# Запрос в кавычках privoxy-лога: "<method> <target> HTTP/x.x".
# Захватываем method — от него зависит, как трактовать scheme-less target
# (authority-form допустим ТОЛЬКО для CONNECT, см. _extract_host).
_REQUEST_RE = re.compile(r'"([A-Z]+)\s+(\S+)\s+HTTP/[0-9.]+"')


def _is_canonical_ipv4(host):
    try:
        ip = ipaddress.IPv4Address(host)
    except ValueError:
        return False
    return str(ip) == host


def _is_canonical_ipv6(host):
    # ipaddress принимает scoped IPv6 (`%zone`), но в кэше нужен только адрес.
    if "%" in host:
        return False
    try:
        ip = ipaddress.IPv6Address(host)
    except ValueError:
        return False
    return str(ip) == host


def _is_hostname(host):
    """Whitelist hostname для парсера и кэша: canonical IP или строгий reg-name."""
    if not isinstance(host, str) or not host:
        return False
    host = host.lower()
    if _is_canonical_ipv4(host) or _is_canonical_ipv6(host):
        return True
    # Голый числовой токен и dotted-numeric без canonical IPv4 не пишем в кэш:
    # это чаще артефакт target-парсинга, а не доменное имя из privoxy.
    if host.isdigit() or _NUMERIC_DOTTED_RE.match(host):
        return False
    if _REG_NAME_RE.match(host) is None:
        return False
    # RFC 3986 reg-name задаёт символы/форму, но не DNS size limits. Для cache-key
    # нам нужен именно hostname: имя до 253 octets, каждая label до 63.
    name = host[:-1] if host.endswith(".") else host
    if len(name) > _MAX_DNS_NAME_LENGTH:
        return False
    return all(0 < len(label) <= _MAX_DNS_LABEL_LENGTH for label in name.split("."))


def _clean_hostname(host):
    if not isinstance(host, str):
        return None
    host = host.lower()
    if not _is_hostname(host):
        return None
    return host


def _is_valid_port(port):
    if not isinstance(port, str) or not _PORT_RE.match(port):
        return False
    try:
        value = int(port)
    except ValueError:
        return False
    return 0 <= value <= 65535


def _is_finite_number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except (OverflowError, TypeError, ValueError):
        return False


def _is_bracketed_ipv6_authority(netloc, host):
    """`[...]` в authority разрешён только как bracketed canonical IPv6 literal."""
    authority = netloc.rsplit("@", 1)[-1]
    if "[" not in authority and "]" not in authority:
        return True
    if not authority.startswith("["):
        return False
    closing = authority.find("]")
    if closing <= 0:
        return False
    rest = authority[closing + 1 :]
    if rest and not rest.startswith(":"):
        return False
    return _is_canonical_ipv6(host.lower())


def _now(now):
    """Единая точка времени: тесты передают now=, прод берёт системное время.

    Defensive: нечисловой now (контракт «не бросает») деградирует в системное
    время, а не в исключение. time.time() импортируется лениво — чистый
    парсинг/чтение не зависят от часов.
    """
    if now is not None:
        try:
            return float(now)
        except (TypeError, ValueError):
            pass
    import time

    return time.time()


def _extract_host(target, method=None):
    """Из request-target privoxy-лога вернуть чистый hostname или None.

    По RFC 7230 request-target бывает четырёх форм; нас интересуют только те, что
    несут hostname (privacy-граница «только hostnames»):
    - absolute-form `scheme://host[:port]/path?query` — обычные методы (GET/…),
      берём ТОЛЬКО hostname (urlsplit снимает и userinfo/query/path).
    - authority-form `host:port` — допустимо ТОЛЬКО для CONNECT; для прочих методов
      scheme-less target это либо origin-form `/path` (без hostname), либо мусорный
      токен (напр. безопасное слово фильтра) — такой target НЕ принимаем, иначе
      attacker-influenced мусор попадает в counts/кэш.
    Возврат None для мусора/отсутствия hostname — вызывающий пропускает строку.
    """
    if not target:
        return None
    method = (method or "").upper()
    if method == "CONNECT":
        # CONNECT по RFC 7230 несёт authority-form host:port. Absolute-form,
        # userinfo, path/query и голый IPv6 без скобок не принимаем.
        if (
            "://" in target
            or "@" in target
            or "/" in target
            or "?" in target
            or "#" in target
        ):
            return None
        if target.startswith("["):
            closing = target.find("]")
            if (
                closing <= 0
                or closing == len(target) - 1
                or target[closing + 1] != ":"
            ):
                return None
            host = target[1:closing]
            port = target[closing + 2 :]
            if not _is_valid_port(port):
                return None
            host = host.lower()
            if not _is_canonical_ipv6(host):
                return None
            return host
        if "[" in target or "]" in target:
            return None
        if target.count(":") != 1:
            return None
        host, port = target.rsplit(":", 1)
        if not _is_valid_port(port):
            return None
        return _clean_hostname(host)
    if "://" in target:
        # Абсолютный URL: hostname без порта/пути/query (urlsplit снимает userinfo).
        # .port читаем обязательно: urlsplit иначе отдаёт hostname даже при
        # невалидном порте (`http://secret:abc/path`).
        try:
            parsed = urlsplit(target)
            host = parsed.hostname
            parsed.port
        except ValueError:
            return None
        if host is None:
            return None
        if not _is_bracketed_ipv6_authority(parsed.netloc, host):
            return None
        return _clean_hostname(host)
    else:
        # Scheme-less target при не-CONNECT методе: origin-form (/path) или токен —
        # hostname не несёт. Не принимаем (privacy: «только hostnames»).
        return None


def _read_tail(path, max_lines, max_bytes):
    """Прочитать ХВОСТ файла: не более max_bytes с конца и не более max_lines строк.

    Возвращает список строк (может быть пустым). Никогда не бросает: отсутствующий
    файл/ошибка чтения -> []. Не загружает весь файл в память (seek с конца).
    """
    p = Path(path)
    try:
        size = p.stat().st_size
        with open(p, "rb") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
                # Первая (вероятно обрезанная) строка неполная — отбрасываем её.
                f.readline()
            data = f.read()
    except (OSError, ValueError):
        return []
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if len(lines) > max_lines:
        lines = lines[-max_lines:]
    return lines


def parse_access_log(path=None, max_lines=None, max_bytes=None):
    """Подсчитать частоту запросов per-domain из privoxy access-лога.

    Читает только ХВОСТ (max_lines / max_bytes), извлекает hostname из каждой
    валидной строки. Возвращает dict {domain: count}. Defensive: отсутствующий/
    пустой/битый файл или кривые строки -> {} (или частичный результат), не бросает.
    """
    if path is None:
        path = _DEFAULT_LOG_PATH
    if max_lines is None:
        max_lines = _DEFAULT_MAX_LINES
    if max_bytes is None:
        max_bytes = _DEFAULT_MAX_BYTES

    counts = {}
    for line in _read_tail(path, max_lines, max_bytes):
        m = _REQUEST_RE.search(line)
        if not m:
            continue
        method, target = m.group(1), m.group(2)
        host = _extract_host(target, method)
        if host is None:
            continue
        counts[host] = counts.get(host, 0) + 1
    return counts


def _safe_non_negative_int(value):
    if isinstance(value, bool):
        return None
    try:
        n = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return n if n >= 0 else None


def _safe_positive_int(value, default=None):
    if isinstance(value, bool):
        return default
    try:
        n = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return n if n > 0 else default


def _boundary_intact(path, boundary_offset):
    """Content-free проверка границы курсора (issue #79). Best-effort, НЕ гарантия.

    Курсор всегда стоит сразу после '\\n', поэтому байт на позиции boundary_offset-1
    в целом файле обязан быть '\\n'. Возвращает True, если это так. copytruncate +
    regrowth подменяет контент под тем же inode: при контенте РАЗНОЙ длины со старым
    байт на старой границе — середина строки, не '\\n' -> False -> resync. Предел: при
    equal-length контенте (напр. повторяющиеся CONNECT к одному хосту) граница снова
    '\\n' -> True -> подмена НЕ детектится -> undercount (сознательный трейд-офф в
    пользу privacy #76, см. константу _NEWLINE). boundary_offset<=0 (курсор честно на
    0) границы не имеет — считаем её intact (нет свидетельства подмены; НЕ ложный
    resync, см. находку про offset==0). Ошибка чтения -> считаем intact: консервативно,
    чтобы не сломать happy-path на транзиентном I/O-сбое (fail безопасен — направление
    модуля undercount, а не потеря на ровном месте).
    """
    if boundary_offset <= 0:
        return True
    try:
        with open(path, "rb") as f:
            f.seek(boundary_offset - 1)
            b = f.read(1)
    except (OSError, ValueError):
        return True
    if not b:
        # Файл короче offset — это уже поймано size<offset выше; сюда обычно не
        # доходим. Нет байта на границе -> подтвердить целостность нечем -> resync.
        return False
    return b[0] == _NEWLINE


def _read_new_lines(path, offset, inode, dev, max_bytes, max_lines):
    """Прочитать только новые полные строки с сохранённого cursor.

    Cursor защищён от rotation/truncate через `(inode, dev)` и размер. От
    copytruncate+regrowth (issue #79, same-inode усечение с доростом за старый
    offset) — best-effort content-free boundary-newline check: курсор всегда стоит
    сразу после '\\n', поэтому байт на позиции offset-1 обязан быть '\\n'; если нет
    (контент подменён и разной длины) — resync (offset=0). Это НЕ строгая гарантия:
    equal-length подмена (напр. повторяющиеся CONNECT к одному хосту) даёт '\\n' на
    границе и НЕ детектится -> undercount (принятый трейд-офф в пользу privacy #76,
    см. _boundary_intact). На диск НЕ идёт ничего производного от контента лога
    (privacy-схема #76). Первый запуск без meta читает bounded tail, а не весь лог:
    старый гигабайтный файл не превращается в долгую bootstrap-операцию. Функция
    никогда не бросает.
    """
    saved_offset = _safe_non_negative_int(offset)
    saved_inode = _safe_non_negative_int(inode)
    saved_dev = _safe_non_negative_int(dev)
    max_bytes = _safe_positive_int(max_bytes, _DEFAULT_MAX_BYTES)
    max_lines = _safe_positive_int(max_lines, _DEFAULT_MAX_LINES)
    try:
        st = os.stat(path)
        cur_size = int(st.st_size)
        cur_inode = int(st.st_ino)
        cur_dev = int(st.st_dev)
    except (OSError, TypeError, ValueError):
        return [], offset, inode, dev, offset

    first_run = saved_offset is None or saved_inode is None or saved_dev is None
    read_offset = 0 if saved_offset is None else saved_offset
    rotated = (
        not first_run
        and (cur_inode != saved_inode or cur_dev != saved_dev)
    )
    # resynced отделяет НАСТОЯЩИЙ сброс курсора в 0 (ротация / усечение / подмена
    # границы — тут tail-bound реально нужен, чтобы не читать гигабайт) от честного
    # курсора, стоящего на offset=0 (poll пустого лога). Только настоящий resync
    # уходит в tail_mode; легитимный 0 читает с начала все строки (находка про
    # offset==0). Флаг ставится ровно там, где read_offset обнуляется.
    resynced = False
    if rotated or cur_size < read_offset:
        read_offset = 0
        resynced = True

    # Content-free детект copytruncate: курсор указывает внутрь файла, ротации нет,
    # но байт на границе offset-1 больше не '\n' -> контент подменён под тем же inode
    # -> resync к 0, чтобы не seek'нуть в середину нового контента. Курсор честно на
    # 0 границы не имеет и сюда не попадает (read_offset > 0).
    if read_offset > 0 and not first_run and not rotated:
        if not _boundary_intact(path, read_offset):
            read_offset = 0
            resynced = True

    if cur_size == read_offset:
        return [], read_offset, cur_inode, cur_dev, cur_size

    tail_mode = (first_run or resynced) and cur_size > max_bytes
    try:
        with open(path, "rb") as f:
            if tail_mode:
                f.seek(cur_size - max_bytes)
                # Первая строка, скорее всего, начата до окна чтения.
                # Не считаем её.
                f.readline()
                start = f.tell()
                read_limit = cur_size - start
            else:
                start = read_offset
                f.seek(start)
                read_limit = min(cur_size - start, max_bytes)
            data = f.read(read_limit)
    except (OSError, ValueError):
        return [], offset, inode, dev, offset

    if not data:
        return [], read_offset, cur_inode, cur_dev, cur_size
    last_newline = data.rfind(b"\n")
    if last_newline < 0:
        return [], start, cur_inode, cur_dev, cur_size

    complete = data[:last_newline]
    new_offset = start + last_newline + 1
    text = complete.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if len(lines) > max_lines:
        lines = lines[-max_lines:]
    return lines, new_offset, cur_inode, cur_dev, cur_size


def parse_new_access_log(
    path=None,
    offset=None,
    inode=None,
    dev=None,
    max_lines=None,
    max_bytes=None,
):
    """Подсчитать только новые privoxy-строки и вернуть обновлённый cursor."""
    if path is None:
        path = _DEFAULT_LOG_PATH
    if max_lines is None:
        max_lines = _DEFAULT_MAX_LINES
    if max_bytes is None:
        max_bytes = _DEFAULT_MAX_BYTES

    lines, new_offset, new_inode, new_dev, new_size = _read_new_lines(
        path, offset, inode, dev, max_bytes, max_lines
    )
    counts = {}
    for line in lines:
        m = _REQUEST_RE.search(line)
        if not m:
            continue
        method, target = m.group(1), m.group(2)
        host = _extract_host(target, method)
        if host is None:
            continue
        counts[host] = counts.get(host, 0) + 1
    cursor = {
        "log_offset": new_offset,
        "log_inode": new_inode,
        "log_dev": new_dev,
        "log_size": new_size,
    }
    return counts, cursor


def _bucket_of(ts, bucket_size):
    size = _safe_positive_int(bucket_size, DEFAULT_BUCKET_SECONDS)
    return int(float(ts) // size * size)


def _live_count(buckets, ttl, now):
    cutoff = float(now) - float(ttl)
    total = 0
    if not isinstance(buckets, dict):
        return 0
    for bucket_ts, hits in buckets.items():
        bucket_ts = _safe_non_negative_int(bucket_ts)
        if bucket_ts is None:
            continue
        if bucket_ts < cutoff:
            continue
        if not _is_finite_number(hits):
            continue
        hits = int(hits)
        if hits > 0:
            total += hits
    return total


def _prune_buckets(buckets, ttl, now):
    cutoff = float(now) - float(ttl)
    out = {}
    if not isinstance(buckets, dict):
        return out
    for bucket_ts, hits in buckets.items():
        bucket_ts = _safe_non_negative_int(bucket_ts)
        if bucket_ts is None or bucket_ts < cutoff:
            continue
        if not _is_finite_number(hits):
            continue
        hits = int(hits)
        if hits > 0:
            out[bucket_ts] = hits
    return out


def _cursor_meta(meta):
    # Курсор на диске — ТОЛЬКО эти числа. Никакого производного от контента лога
    # (privacy-схема #76): детект copytruncate content-free, см. _boundary_intact.
    out = {}
    if not isinstance(meta, dict):
        return out
    for key in ("log_offset", "log_inode", "log_dev", "log_size"):
        value = _safe_non_negative_int(meta.get(key))
        if value is not None:
            out[key] = value
    return out


def _select_bucket_size(*values):
    for value in values:
        n = _safe_positive_int(value)
        if n is not None:
            return n
    return DEFAULT_BUCKET_SECONDS


def _effective_bucket_size(bucket_size, meta_bucket_size, ttl):
    selected = _select_bucket_size(bucket_size, meta_bucket_size)
    ttl_size = _safe_positive_int(ttl)
    if ttl_size is None:
        return selected
    return min(selected, ttl_size)


def _load_cache(path):
    """Загрузить кэш -> (dict {domain: entry}, meta). Missing/битый -> ({}, {}).

    entry внутри процесса содержит ещё `buckets`; на диск это поле не попадает в
    `domains[]`, чтобы privacy-схема #76 оставалась неизменной.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}, {}
    if not isinstance(data, dict):
        return {}, {}

    raw_meta = data.get("meta")
    meta = _cursor_meta(raw_meta)
    bucket_size = _select_bucket_size(
        raw_meta.get("bucket_size") if isinstance(raw_meta, dict) else None
    )
    meta["bucket_size"] = bucket_size
    schema = (
        _safe_non_negative_int(raw_meta.get("schema"))
        if isinstance(raw_meta, dict)
        else None
    )
    if schema is not None:
        meta["schema"] = schema

    entries = data.get("domains")
    if not isinstance(entries, list):
        return {}, meta

    raw_buckets = data.get("buckets")
    if not isinstance(raw_buckets, dict):
        raw_buckets = {}

    out = {}
    for e in entries:
        if not isinstance(e, dict):
            continue
        domain = e.get("domain")
        count = e.get("count")
        last_seen = e.get("last_seen")
        domain = _clean_hostname(domain)
        if domain is None:
            continue
        if not _is_finite_number(count):
            continue
        if not _is_finite_number(last_seen):
            continue
        out[domain] = {
            "domain": domain,
            "count": int(count),
            "last_seen": float(last_seen),
            "buckets": {},
        }
        domain_buckets = raw_buckets.get(domain)
        if isinstance(domain_buckets, dict):
            for bucket_ts, hits in domain_buckets.items():
                bucket_ts = _safe_non_negative_int(bucket_ts)
                if bucket_ts is None:
                    continue
                if not _is_finite_number(hits):
                    continue
                hits = int(hits)
                if hits > 0:
                    out[domain]["buckets"][bucket_ts] = hits
        if not out[domain]["buckets"] and int(count) > 0:
            # Legacy schema 1: last_seen мог быть re-stamp'нут старым багом, но
            # синтетический бакет самоочищается по TTL после миграции.
            out[domain]["buckets"] = {
                _bucket_of(float(last_seen), bucket_size): int(count)
            }
            out[domain]["_legacy_bucket"] = True
    return out, meta


def load_cursor(path=None):
    """Вернуть cursor лога из meta-секции кэша. Missing/битый кэш -> {}."""
    if path is None:
        path = _DEFAULT_CACHE_PATH
    _cache, meta = _load_cache(path)
    return _cursor_meta(meta)


def _atomic_write(path, cache, meta):
    """Атомарно записать кэш (temp + os.replace), как local_state.save_state.

    cache = dict {domain: entry}. Возвращает True при успехе, False при сбое.
    При сбое сериализации/записи tmp подчищается, а существующий файл не тронут.
    """
    p = Path(path)
    tmp = p.with_suffix(p.suffix + ".tmp")
    # Сериализуем в память ДО открытия tmp: TypeError на несериализуемом count
    # не оставит пустой/битый tmp и не тронет существующий кэш. Сортировка тоже
    # внутри try — несериализуемый count роняет unary-minus в key ещё до json.dumps.
    try:
        ranked = sorted(cache.values(), key=lambda e: (-e["count"], e["domain"]))
        domains = [
            {
                "domain": e["domain"],
                "count": int(e["count"]),
                "last_seen": float(e["last_seen"]),
            }
            for e in ranked
        ]
        buckets = {}
        for e in ranked:
            domain_buckets = {}
            for bucket_ts, hits in sorted((e.get("buckets") or {}).items()):
                bucket_ts = _safe_non_negative_int(bucket_ts)
                if bucket_ts is None:
                    continue
                if not _is_finite_number(hits):
                    continue
                hits = int(hits)
                if hits > 0:
                    domain_buckets[str(bucket_ts)] = hits
            if domain_buckets:
                buckets[e["domain"]] = domain_buckets
        out_meta = _cursor_meta(meta)
        out_meta["bucket_size"] = _select_bucket_size(
            meta.get("bucket_size") if isinstance(meta, dict) else None
        )
        out_meta["schema"] = 2
        text = json.dumps(
            {"meta": out_meta, "domains": domains, "buckets": buckets},
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        return False
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        tmp.replace(p)  # atomic rename
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False
    return True


def _evict(cache, ttl, now, top_n):
    """Выселить домены без живых бакетов и обрезать до top_n самых частых."""
    fresh = {}
    for domain, entry in cache.items():
        entry["buckets"] = _prune_buckets(entry.get("buckets"), ttl, now)
        live_count = _live_count(entry["buckets"], ttl, now)
        if live_count <= 0:
            continue
        entry["count"] = live_count
        fresh[domain] = entry
    if len(fresh) <= top_n:
        return fresh
    ranked = sorted(fresh.values(), key=lambda e: (-e["count"], e["domain"]))
    return {e["domain"]: e for e in ranked[:top_n]}


def update_cache(
    counts,
    path=None,
    ttl=None,
    top_n=None,
    now=None,
    *,
    bucket_size=None,
    cursor=None,
):
    """Влить свежие counts в windowed-кэш и обновить cursor лога.

    Defensive: несериализуемый ввод / ошибка записи -> None (существующий кэш цел),
    не бросает. Возвращает актуальный dict {domain: entry} при успехе.
    """
    if path is None:
        path = _DEFAULT_CACHE_PATH
    if ttl is None:
        ttl = DEFAULT_TTL_SECONDS
    if top_n is None:
        top_n = DEFAULT_TOP_N
    ts = _now(now)

    cache, meta = _load_cache(path)
    bucket_size = _effective_bucket_size(bucket_size, meta.get("bucket_size"), ttl)
    bucket_ts = _bucket_of(ts, bucket_size)
    for entry in cache.values():
        if entry.pop("_legacy_bucket", False):
            entry["buckets"] = {
                _bucket_of(entry.get("last_seen", ts), bucket_size): int(entry["count"])
            }
    if isinstance(counts, dict):
        for domain, inc in counts.items():
            domain = _clean_hostname(domain)
            if domain is None:
                continue
            # inc валидируем ТЕМ ЖЕ предикатом, что _load_cache — иначе, например,
            # bool записался бы на диск, но при следующем чтении был бы отброшен
            # (write/read-асимметрия -> тихая потеря домена). bool исключаем явно.
            if not _is_finite_number(inc):
                continue
            inc = int(inc)
            if inc <= 0:
                continue
            entry = cache.get(domain)
            if entry is None:
                cache[domain] = {
                    "domain": domain,
                    "count": inc,
                    "last_seen": ts,
                    "buckets": {bucket_ts: inc},
                }
            else:
                buckets = entry.get("buckets")
                if not isinstance(buckets, dict):
                    buckets = {}
                buckets[bucket_ts] = int(buckets.get(bucket_ts, 0)) + inc
                entry["buckets"] = buckets
                entry["last_seen"] = max(float(entry.get("last_seen", ts)), ts)

    # _evict сортирует по count — несериализуемый count уронил бы unary-minus.
    # Ловим здесь, чтобы контракт «не бросает» держался: существующий кэш цел.
    try:
        cache = _evict(cache, ttl, ts, top_n)
    except (TypeError, ValueError, OverflowError):
        return None

    out_meta = dict(meta)
    out_meta["bucket_size"] = bucket_size
    out_meta["schema"] = 2
    if isinstance(cursor, dict):
        for key, value in _cursor_meta(cursor).items():
            out_meta[key] = value
    if not _atomic_write(path, cache, out_meta):
        return None
    return cache


def hot_domains(path=None, top_n=None, ttl=None, now=None):
    """Текущий top-N доменов из кэша, отсортированный по убыванию частоты.

    Для будущего status-поля dashboard и генератора xray. Фильтрует протухшие по
    TTL (чтение тоже уважает TTL). Defensive: missing/битый кэш -> []. Не бросает.
    """
    if path is None:
        path = _DEFAULT_CACHE_PATH
    if top_n is None:
        top_n = DEFAULT_TOP_N
    if ttl is None:
        ttl = DEFAULT_TTL_SECONDS
    ts = _now(now)

    cache, _meta = _load_cache(path)
    # Симметрично update_cache: нечисловой ttl/top_n (ts-ttl, срез [:top_n]) не
    # должен бросать — контракт «не бросает». Деградируем в [].
    try:
        fresh = []
        for e in cache.values():
            live_count = _live_count(e.get("buckets"), ttl, ts)
            if live_count <= 0:
                continue
            e = dict(e)
            e["count"] = live_count
            fresh.append(e)
        ranked = sorted(fresh, key=lambda e: (-e["count"], e["domain"]))
        return [e["domain"] for e in ranked[:top_n]]
    except (TypeError, ValueError, OverflowError):
        return []
