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

Семантика 5xx взята из health._tunnel_up (#207) и sys_probe.direct_probe: сервер ОТВЕТИЛ
через прокси, значит канал доказан живым, даже если вендор лежит. Не поднимаем ложную
тревогу «прокси упал» (issue #82 класс).

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


def _code_int(res):
    try:
        return int(str(res.get("code", "")).strip())
    except (TypeError, ValueError):
        return None


def _classify(direct, via):
    """(verdict, works, status) по паре замеров. Чистая функция — вся логика тестируема."""
    via_code = _code_int(via)
    via_5xx = via_code is not None and via_code >= _SERVER_ERROR
    direct_ok = bool(direct.get("up"))
    via_ok = bool(via.get("up"))

    if via_5xx:
        # Ответ сервера через прокси = канал доказан живым, лежит вендор (не прокси).
        return "vendor-outage", True, "warn"
    if direct_ok and via_ok:
        return "ok", True, "ok"
    if direct_ok and not via_ok:
        return "proxy-broken", False, "down"
    if not direct_ok and via_ok:
        return "ok-blocked-direct", True, "ok"
    return "both-down", False, "down"


def proxy_effective_probe(*, host=None, channel="socks"):
    """Прямой vs через-прокси замер одного домена. Не бросает.

    {status: ok|warn|down|unknown, verdict, works: bool|None, host, channel,
     direct: {code, ms, up}, proxy: {code, ms, up}, detail}
    """
    host = host or DEFAULT_HOST
    proxy_url = _CHANNEL_PROXY.get(channel, _SOCKS_PROXY_URL)
    url = f"https://{host}/"
    try:
        direct = _curl_through(url, proxy=False)
        via = _curl_through(url, proxy=True, proxy_url=proxy_url)
        verdict, works, status = _classify(direct, via)
        return {
            "status": status,
            "verdict": verdict,
            "works": works,
            "host": host,
            "channel": channel,
            "proxy_url": proxy_url,
            "direct": direct,
            "proxy": via,
            "detail": _detail(verdict, host, direct, via),
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
        return (f"{host}: прямой путь работает ({d}), а через прокси нет ({v}) — "
                f"узел мёртв или туннель не поднят")
    if verdict == "ok-blocked-direct":
        return f"{host}: напрямую недоступен ({d}), прокси спасает ({v})"
    if verdict == "vendor-outage":
        return f"{host}: канал жив, но сервер вернул {v} — лежит сам вендор, не прокси"
    return f"{host}: недоступен обоими путями (прямо {d}, через прокси {v}) — проверь сеть/DNS/узел"
