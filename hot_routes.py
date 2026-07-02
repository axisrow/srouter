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
import ipaddress
import json
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

# reg-name hostname (RFC 3986): буквы/цифры/`.`/`-`/`_`, БЕЗ двоеточия. Двоеточие
# в authority значит только разделитель порта или IPv6 — их разбираем явно, а не
# пропускаем в host. Так `SECRET123`/`user`/`a:b` не могут притвориться доменом.
_REGNAME_RE = re.compile(r"^[A-Za-z0-9._-]+\Z")
# Порт authority-form: непустой, строго числовой (RFC 3986 port = *DIGIT, но для
# CONNECT-цели пустой порт бессмысленен — требуем ≥1 цифру).
_PORT_RE = re.compile(r"^[0-9]+\Z")


def _is_ipv6_literal(value):
    """РЕАЛЬНАЯ проверка IPv6-литерала через ipaddress, не loose-regex.

    hex+`:`-regex принимал бы мусор (`dead:beef`, `::::`, `deadbeef` — невалидны
    по стандарту, но попадали бы в counts/кэш). Единственный IPv6-гейт в модуле —
    ipaddress.IPv6Address под try/except, чтобы битый литерал не притворялся host.
    """
    if not isinstance(value, str):
        return False
    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


def _is_hostname(value):
    """Единый предикат «это hostname»: reg-name ИЛИ ВАЛИДНЫЙ IPv6-литерал (`::1`).

    Одна граница на весь модуль — и парсер (_extract_host), и валидация ключей
    кэша (_load_cache/update_cache) используют ЭТОТ предикат, чтобы IPv6-домены
    не выпадали при чтении (иначе write/read-асимметрия -> тихая потеря домена).
    IPv6 валидируется строго (ipaddress), а не regex — write/read симметрия держится
    на СТРОГОЙ проверке: битый IPv6-ключ отвергается и на write, и на read.
    """
    return isinstance(value, str) and (
        bool(_REGNAME_RE.match(value)) or _is_ipv6_literal(value)
    )

# Запрос в кавычках privoxy-лога: "<method> <target> HTTP/x.x".
# Захватываем method — от него зависит, как трактовать target (authority-form
# host:port допустим ТОЛЬКО для CONNECT, см. _extract_host).
_REQUEST_RE = re.compile(r'"([A-Z]+)\s+(\S+)\s+HTTP/[0-9.]+"')


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


def _connect_authority_host(target):
    """Строгий разбор CONNECT authority-form `host:port` -> hostname или None.

    По RFC 7230 §5.3.3 CONNECT-цель — ТОЛЬКО authority-form с ОБЯЗАТЕЛЬНЫМ портом.
    Reject всего, что не является строгим host:port с числовым портом:
    - reg-name host:port  -> host, порт обязателен и числовой;
    - IPv6 `[addr]:port`  -> addr (скобки сняты), порт числовой;
    - reject: без порта / нечисловой порт / userinfo `@` / path `/` / query `?` /
      absolute URL (`://`) / голый токен / лишние `:` вне IPv6-скобок.
    Это privacy-граница: attacker-controlled мусор (`SECRET123`, `SECRET123:abc`,
    `user:pass`) НЕ должен пройти как hostname.
    """
    # userinfo / path / query / fragment / scheme в authority недопустимы —
    # любой из этих символов значит, что это не чистый host:port.
    if any(c in target for c in "@/?#") or "://" in target:
        return None

    if target.startswith("["):
        # IPv6-литерал: строго `[addr]:port`.
        end = target.find("]")
        if end == -1:
            return None
        inner = target[1:end]
        rest = target[end + 1:]
        # СТРОГАЯ IPv6-валидация (ipaddress), не loose-regex: `[dead:beef]`,
        # `[::::]`, `[deadbeef]` — невалидны по стандарту и должны быть reject.
        if not _is_ipv6_literal(inner):
            return None
        if not rest.startswith(":"):
            return None  # порт обязателен
        port = rest[1:]
        host = inner
    else:
        # reg-name: РОВНО один ':' разделяет host и port (лишние ':' -> reject).
        if target.count(":") != 1:
            return None
        host, port = target.split(":", 1)
        if not host or not _REGNAME_RE.match(host):
            return None

    if not _PORT_RE.match(port):
        return None  # порт обязателен и строго числовой
    return host.lower()


def _extract_host(target, method=None):
    """Из request-target privoxy-лога вернуть чистый hostname или None.

    ОДИН код-путь, строгий RFC 7230. Privacy-граница «только hostname» — здесь:
    - CONNECT: ТОЛЬКО authority-form host:port с числовым портом (см.
      _connect_authority_host). Absolute URL в CONNECT — malformed, reject.
    - не-CONNECT: ТОЛЬКО absolute-form `scheme://authority/...` -> hostname
      (urlsplit под try/except ValueError). origin-form (`/path`), asterisk-form
      (`*`), голый токен и authority-form hostname не несут -> skip.

    Возврат None для всего, что не несёт валидный hostname — вызывающий пропускает
    строку. urlsplit может бросить ValueError (битый IPv6, не-ASCII netloc под
    NFKC) — ловим, чтобы одна кривая строка не роняла parse_access_log.
    """
    if not target:
        return None
    if (method or "").upper() == "CONNECT":
        return _connect_authority_host(target)
    # Не-CONNECT: hostname несёт только absolute-form (scheme://...).
    if "://" not in target:
        return None
    try:
        host = urlsplit(target).hostname
    except ValueError:
        return None
    if not host or not _is_hostname(host):
        return None
    return host.lower()


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
        if not _is_hostname(domain):
            continue
        if not isinstance(count, (int, float)) or isinstance(count, bool):
            continue
        if not isinstance(last_seen, (int, float)) or isinstance(last_seen, bool):
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
        text = json.dumps({"domains": ranked}, ensure_ascii=False, indent=2)
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
            if not _is_hostname(domain):
                continue
            # inc валидируем ТЕМ ЖЕ предикатом, что _load_cache — иначе, например,
            # bool записался бы на диск, но при следующем чтении был бы отброшен
            # (write/read-асимметрия -> тихая потеря домена). bool исключаем явно.
            if not isinstance(inc, (int, float)) or isinstance(inc, bool):
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
