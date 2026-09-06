"""Физический замер прокси: идёт ли трафик НА САМОМ ДЕЛЕ, а не «включён ли флаг».

Зачем (эмпирика с живой машины, канон verify-dont-guess): privoxy слушал 8118, xray
слушал 10808, `brew services`/порт-пробы были зелёные, дашборд показывал ON — а
`curl https://github.com` через SOCKS давал таймаут, потому что VLESS-узел был мёртв.
**Открытый порт не доказывает, что трафик доходит.** Единственное честное доказательство —
сравнить прямой путь и путь через прокси по одному и тому же домену.

Почему пара, а не один замер через прокси: одиночный fail неразличим между «прокси
сломан» и «весь интернет лежит / домен блокирует». Прямой замер — контрольная группа.

Матрица вердиктов:

    direct   via proxy   verdict             works  status
    ok       ok          ok                  True   ok
    ok       timeout     proxy-broken        False  down     <- мёртвый узел
    timeout  ok          ok-blocked-direct   True   ok       <- прокси спасает от блокировки
    timeout  timeout     both-down           False  down     <- сеть/DNS/узел
    ok       5xx         vendor-outage       True   warn     <- канал жив, лежит вендор
    ok       5xx синт.   proxy-broken        False  down     <- 5xx синтезировал сам посредник (#323)

Семантика 5xx взята из health._tunnel_up (#207) и sys_probe.direct_probe: сервер ОТВЕТИЛ
через прокси, значит канал доказан живым, даже если вендор лежит. Не поднимаем ложную
тревогу «прокси упал» (issue #82 класс).

Уточнение #323 (research #301): на plain-HTTP-плече посредник (privoxy) сам синтезирует
5xx о мёртвом upstream — такой код НЕ доказывает канал. Отличаем по magic-датам privoxy
в заголовках ответа (захват стенда, живые дампы — issue #301). На HTTPS-плече синтетика
в принципе не доходит до кода (провал CONNECT даёт code=000), поэтому там семантика #207
не меняется.

Третье плечо #325 (вердикт автора: ДА): plain-HTTP-замер http://{host}/ — дополнительный
СИГНАЛ, не замена пары. Цель — читать собственную подпись посредника о его upstream
(синтетика видна только на plain-HTTP), а не менять измеряемую семантику потребительского
плеча. Плечо всегда бьёт в privoxy-запись реестра (_CHANNEL_PROXY["http"]) независимо от
channel замера: xray HTTP-5xx синтезировать не может (research #301), а прод-вызов панели
— channel="socks" — иначе не достигал бы guard'а #323 вовсе. Асимметричная сила сигнала:
  - подписанная синтетика (magic-даты — их ambient-шум не подделывает) при works=True
    эскалирует вердикт в proxy-broken: посредник доказанно не смог форвардить — туннель
    умер между плечами (гонка/флап #315); fail-closed без ложной тревоги (#82);
  - неподписанный сбой plain-HTTP (000/таймаут/настоящий 5xx домена) вердикт НЕ меняет:
    plain-HTTP сам по себе шумнее (GFW-класс сетей), http-флап не красит канал сильнее,
    чем TLS-пара.

Probe-канон: НИКОГДА не бросает; при внутреннем сбое works=None (не False — неизвестность
не равна поломке).
"""
from dashboard_network import _curl_through

# Единый источник правды по портам прокси — dashboard_common (issue #155).
# except SystemExit (НЕ BaseException): dashboard_common без srouter_config.py поднимает
# SystemExit, и except Exception его пропустит — fallback не сработал бы в install-пути.
# Fallback пишем в ПРИВАТНЫЕ имена: гвард test_proxy_constants ловит переопределение
# публичных констант вне dashboard_common (канон vscode_proxy.py:35-39).
try:
    from dashboard_common import HTTP_PROXY_URL as _HTTP_PROXY_URL
    from dashboard_common import SOCKS_PROXY_URL as _SOCKS_PROXY_URL
except SystemExit:  # pragma: no cover
    _HTTP_PROXY_URL = "http://127.0.0.1:8118"
    _SOCKS_PROXY_URL = "socks5h://127.0.0.1:10808"

# Канал -> URL прокси. Потребители ходят разными путями, и замер обязан повторить путь
# потребителя: Claude Code = HTTP(privoxy), git/codex/VSCode = SOCKS5(xray).
_CHANNEL_PROXY = {"http": _HTTP_PROXY_URL, "socks": _SOCKS_PROXY_URL}

# Домен по умолчанию: github.com входит в proxy-список xray routing (reality-out), то есть
# ДОЛЖЕН идти через туннель. Домен из direct-ветки роутинга дал бы одинаковый ответ на обоих
# путях и ничего не доказал бы (наблюдалось вживую с api.ip.sb).
DEFAULT_HOST = "github.com"

_SERVER_ERROR = 500

# Magic-даты privoxy-синтетики (issue #323; живой захват изолированного стенда
# privoxy 4.2.0 brew + мёртвый upstream, research #301). Константы privoxy кладёт во ВСЕ
# собственные страницы ошибок; у настоящего ответа домена такие даты практически
# невозможны (1955 — до появления HTTP). Expires есть во всех вариантах синтетики
# (503/502/500), Last-Modified 1955 — только в шаблонных (503/502; у 500-без-шаблона
# там текущая дата), поэтому проверяем обе, OR.
_SYNTHETIC_EXPIRES = "Sat, 17 Jun 2000 12:00:00 GMT"
_SYNTHETIC_LAST_MODIFIED = "Wed, 08 Jun 1955 12:00:00 GMT"


def _code_int(res):
    try:
        return int(str(res.get("code", "")).strip())
    except (TypeError, ValueError):
        return None


def _is_synthetic_middleware_5xx(via):
    """5xx синтезировал сам посредник (privoxy о мёртвом upstream), не вендор.

    Только plain-HTTP-плечо (research #301): на HTTPS синтетика не проходит CONNECT и
    зонд видит code=000. Заголовков нет (HTTPS-зонд, старые данные) -> False: семантика
    канона #207 не меняется.
    """
    code = _code_int(via)
    if code is None or code < _SERVER_ERROR:
        return False
    headers = via.get("headers")
    if not isinstance(headers, dict):
        return False
    expires = str(headers.get("expires", "")).strip()
    last_modified = str(headers.get("last-modified", "")).strip()
    return expires == _SYNTHETIC_EXPIRES or last_modified == _SYNTHETIC_LAST_MODIFIED


def _classify(direct, via):
    """(verdict, works, status) по паре замеров. Чистая функция — вся логика тестируема."""
    via_code = _code_int(via)
    via_5xx = via_code is not None and via_code >= _SERVER_ERROR
    direct_ok = bool(direct.get("up"))
    via_ok = bool(via.get("up"))

    if via_5xx and not _is_synthetic_middleware_5xx(via):
        # Ответ сервера через прокси = канал доказан живым, лежит вендор (не прокси).
        # Синтетика посредника сюда НЕ попадает: она о мёртвом upstream, канал не доказан (#323).
        return "vendor-outage", True, "warn"
    if direct_ok and via_ok:
        return "ok", True, "ok"
    if direct_ok and not via_ok:
        return "proxy-broken", False, "down"
    if not direct_ok and via_ok:
        return "ok-blocked-direct", True, "ok"
    return "both-down", False, "down"


def _escalate(verdict, works, status, arm):
    """Эскалация вердикта подписью посредника с plain-HTTP-плеча (#325). Чистая.

    works=True-вердикт («канал доказан» ответом https-плеча) опровергается подписанной
    синтетикой privoxy: в тот же момент посредник не смог форвардить plain-GET — туннель
    умер между плечами (гонка/флап #315). fail-closed: magic-даты подписи ambient-шум
    не подделывает, поэтому обычный http-шум (#82) эскалации не порождает.
    works=False не меняется (вердикт уже down); works=None сюда не доходит (unknown
    выходит раньше), проверка на всякий случай та же.
    """
    if works and arm is not None and _is_synthetic_middleware_5xx(arm):
        return "proxy-broken", False, "down"
    return verdict, works, status


def proxy_effective_probe(*, host=None, channel="socks", http_arm=True):
    """Прямой vs через-прокси замер одного домена (+ plain-HTTP-плечо, #325). Не бросает.

    {status: ok|warn|down|unknown, verdict, works: bool|None, host, channel,
     direct: {code, ms, up}, proxy: {code, ms, up, synthetic_5xx},
     http_arm: {code, ms, up, synthetic_5xx}|None, detail}

    Вердиктным источником остаётся ПАРА https-замеров (канон #207 нетронут — контрольный
    тест vendor-outage зелёный без правок). http_arm — диагностическое плечо #325:
    plain-HTTP-замер через privoxy, где синтетика посредника доходит до кода и guard #323
    операционно достижим (на https-плече она застревает в CONNECT = code=000). Его
    подпись эскалирует works=True-вердикт в proxy-broken (_escalate), неподписанный сбой
    не меняет ничего. http_arm=False отключает плечо (контракт прежних потребителей).
    """
    host = host or DEFAULT_HOST
    proxy_url = _CHANNEL_PROXY.get(channel, _SOCKS_PROXY_URL)
    url = f"https://{host}/"
    try:
        direct = _curl_through(url, proxy=False)
        # via-плечо просит заголовки: единственный способ отличить синтетический 5xx
        # посредника от настоящего ответа домена (issue #323). direct-плечу они не нужны.
        via = _curl_through(url, proxy=True, proxy_url=proxy_url, capture_headers=True)
        verdict, works, status = _classify(direct, via)
        # Наружу — булев флаг, НЕ сырые заголовки: они не должны утекать в метрики/логи.
        via_public = {k: v for k, v in via.items() if k != "headers"}
        via_public["synthetic_5xx"] = _is_synthetic_middleware_5xx(via)
        arm_public, arm_synthetic = None, False
        if http_arm:
            # Диагностическое плечо #325 — всегда через privoxy-запись реестра: только она
            # plain-HTTP-посредник (research #301), а прод-вызов панели channel="socks"
            # иначе guard'а не достигает. Это НЕ путь потребителя — не путать с via-плечем.
            arm = _curl_through(f"http://{host}/", proxy=True,
                                proxy_url=_CHANNEL_PROXY["http"], capture_headers=True)
            arm_public = {k: v for k, v in arm.items() if k != "headers"}
            arm_synthetic = _is_synthetic_middleware_5xx(arm)
            arm_public["synthetic_5xx"] = arm_synthetic
            verdict, works, status = _escalate(verdict, works, status, arm)
        if arm_synthetic and arm_public is not None:
            # Подпись посредника объясняет ЛЮБОИЙ итоговый down-вердикт — и эскалированный
            # (works=True -> proxy-broken), и уже-broken пару: виновник назван по факту.
            # (arm_public здесь всегда dict — синтетика без словаря плеча невозможна.)
            detail = (f"{host}: через прокси пришёл синтетический "
                      f"{arm_public.get('code', '?')} от самого прокси (мёртвый upstream, "
                      f"plain-HTTP-замер) — туннель не работает")
        else:
            detail = _detail(verdict, host, direct, via_public)
        return {
            "status": status,
            "verdict": verdict,
            "works": works,
            "host": host,
            "channel": channel,
            "proxy_url": proxy_url,
            "direct": direct,
            "proxy": via_public,
            "http_arm": arm_public,
            "detail": detail,
        }
    except Exception as e:  # noqa: BLE001 — probe-канон: boundary catch-all, честный unknown
        return {
            "status": "unknown",
            "verdict": "unknown",
            "works": None,
            "host": host,
            "channel": channel,
            "proxy_url": proxy_url,
            "direct": {}, "proxy": {},
            "detail": f"замер не выполнен: {e or e.__class__.__name__}",
        }


def _detail(verdict, host, direct, via):
    """Человекочитаемая причина — на русском, как весь UI/логи проекта."""
    d, v = direct.get("code", "?"), via.get("code", "?")
    if verdict == "ok":
        return f"{host}: прокси работает (прямо {d}, через прокси {v})"
    if verdict == "proxy-broken":
        if via.get("synthetic_5xx"):
            return (f"{host}: прямой путь работает ({d}), а через прокси пришёл "
                    f"синтетический {v} от самого прокси (мёртвый upstream) — "
                    f"туннель не работает")
        return (f"{host}: прямой путь работает ({d}), а через прокси нет ({v}) — "
                f"узел мёртв или туннель не поднят")
    if verdict == "ok-blocked-direct":
        return f"{host}: напрямую недоступен ({d}), прокси спасает ({v})"
    if verdict == "vendor-outage":
        return f"{host}: канал жив, но сервер вернул {v} — лежит сам вендор, не прокси"
    return f"{host}: недоступен обоими путями (прямо {d}, через прокси {v}) — проверь сеть/DNS/узел"
