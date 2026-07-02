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

# Лимиты чтения: не тянем весь (потенциально гигабайтный) лог — только хвост.
_DEFAULT_MAX_LINES = 20000
_DEFAULT_MAX_BYTES = 4 * 1024 * 1024  # 4 MiB хвоста

# Строгий RFC 3986 reg-name: LDH labels, без '_' / ':' / '@' / '[' / ']' / '%'.
# IPv4/IPv6 проходят отдельными canonical-ветками в _is_hostname.
_REG_NAME_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\Z"
)
_NUMERIC_DOTTED_RE = re.compile(r"^[0-9.]+\Z")
_PORT_RE = re.compile(r"^[0-9]+\Z")

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
    return _REG_NAME_RE.match(host) is not None


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


def _load_cache(path):
    """Загрузить кэш -> dict {domain: entry}. Missing/битый/невалидный -> {}.

    entry = {"domain","count","last_seen"}. Никогда не бросает.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    entries = data.get("domains")
    if not isinstance(entries, list):
        return {}
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
        }
    return out


def _atomic_write(path, cache):
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
        text = json.dumps(
            {"domains": ranked}, ensure_ascii=False, indent=2, allow_nan=False
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
    """Выселить протухшие (last_seen старше ttl) и обрезать до top_n самых частых."""
    fresh = {
        d: e for d, e in cache.items() if e["last_seen"] >= now - ttl
    }
    if len(fresh) <= top_n:
        return fresh
    ranked = sorted(fresh.values(), key=lambda e: (-e["count"], e["domain"]))
    return {e["domain"]: e for e in ranked[:top_n]}


def update_cache(counts, path=None, ttl=None, top_n=None, now=None):
    """Влить свежие counts в кэш: аккумулировать счётчики, обновить last_seen,
    выселить протухшие по TTL, обрезать до top_n. Атомарная запись.

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

    cache = _load_cache(path)
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
            entry = cache.get(domain)
            if entry is None:
                cache[domain] = {"domain": domain, "count": int(inc), "last_seen": ts}
            else:
                entry["count"] = entry["count"] + int(inc)
                entry["last_seen"] = ts

    # _evict сортирует по count — несериализуемый count уронил бы unary-minus.
    # Ловим здесь, чтобы контракт «не бросает» держался: существующий кэш цел.
    try:
        cache = _evict(cache, ttl, ts, top_n)
    except TypeError:
        return None
    if not _atomic_write(path, cache):
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

    cache = _load_cache(path)
    # Симметрично update_cache: нечисловой ttl/top_n (ts-ttl, срез [:top_n]) не
    # должен бросать — контракт «не бросает». Деградируем в [].
    try:
        fresh = [e for e in cache.values() if e["last_seen"] >= ts - ttl]
        ranked = sorted(fresh, key=lambda e: (-e["count"], e["domain"]))
        return [e["domain"] for e in ranked[:top_n]]
    except (TypeError, ValueError):
        return []
