"""Физический замер прокси: идёт ли трафик НА САМОМ ДЕЛЕ (не «включён ли флаг»).

Мотивация (эмпирика, снятая на живой машине): privoxy слушал 8118, xray слушал 10808,
дашборд горел зелёным ON — а `curl https://github.com` через SOCKS давал таймаут, потому
что узел был мёртв. Порт открыт != трафик идёт. Отсюда парный замер direct-vs-proxy.

Все пробы замоканы: немоканная проба медленная И machine-dependent (канон
unmocked-probe-is-both-slow-and-machine-dependent).
"""
import proxy_effective


# Живой захват (canon mock-format-must-come-from-live-capture), НЕ сочинённые моки:
# изолированный стенд privoxy 4.2.0 (brew, confdir с prod-шаблонами) + заведомо мёртвый
# upstream, 2026-09-01. Полные дампы и методика — research issue #301
# (issuecomment-5487849612), задача — issue #323. Формат — как его отдаёт
# _curl_through(capture_headers=True): lower-case имя -> значение, статус-лайн выброшен.
PRIVOXY_SYNTHETIC_503_HEADERS = {  # 503 «Forwarding failure»: upstream-SOCKS refused
    "content-type": "text/html",
    "cache-control": "no-cache",
    "date": "Tue, 01 Sep 2026 03:32:59 GMT",
    "last-modified": "Wed, 08 Jun 1955 12:00:00 GMT",
    "expires": "Sat, 17 Jun 2000 12:00:00 GMT",
    "pragma": "no-cache",
}
PRIVOXY_SYNTHETIC_502_HEADERS = {  # 502 «No data received»: upstream оборвал после CONNECT
    "content-type": "text/html",
    "cache-control": "no-cache",
    "date": "Tue, 01 Sep 2026 03:33:01 GMT",
    "last-modified": "Wed, 08 Jun 1955 12:00:00 GMT",
    "expires": "Sat, 17 Jun 2000 12:00:00 GMT",
    "pragma": "no-cache",
}
PRIVOXY_SYNTHETIC_500_HEADERS = {  # 500 без templates-директории: last-modified = текущая
    "content-type": "text/html",
    "cache-control": "no-cache",
    "date": "Tue, 01 Sep 2026 03:32:59 GMT",
    "last-modified": "Tue, 01 Sep 2026 03:32:59 GMT",
    "expires": "Sat, 17 Jun 2000 12:00:00 GMT",
    "pragma": "no-cache",
}
REAL_ORIGIN_503_HEADERS = {  # контроль: настоящий 503 вендора через тот же стек
    "server": "origin-test/1.0",
    "x-origin-test": "real-5xx",
    "content-type": "text/html; charset=utf-8",
    "content-length": "60",
}


def _curl(code, *, ms=120):
    """Форма ответа dashboard_network._curl_through: {code, ms, up}."""
    up = str(code).isdigit() and 100 <= int(code) < 500
    return {"code": str(code), "ms": ms, "up": up}


def _patch(monkeypatch, *, direct, via):
    """Подменяем ровно ту функцию, которую зовёт proxy_effective (не аналог).

    **kwargs: реальный _curl_through получил capture_headers (issue #323) — мок обязан
    зеркалить сигнатуру источника, иначе TypeError на каждом вызове зонда.
    """
    def fake(url, proxy=True, proxy_url=None, **kwargs):
        return via if proxy else direct
    monkeypatch.setattr(proxy_effective, "_curl_through", fake)


def test_both_ok_means_proxy_works(monkeypatch):
    _patch(monkeypatch, direct=_curl(200), via=_curl(200))
    r = proxy_effective.proxy_effective_probe(host="github.com")
    assert r["verdict"] == "ok"
    assert r["status"] == "ok"
    assert r["works"] is True


def test_direct_ok_but_proxy_timeout_is_proxy_broken(monkeypatch):
    """ГЛАВНЫЙ случай: ровно то, что происходило на машине при мёртвом узле."""
    _patch(monkeypatch, direct=_curl(200), via=_curl("000"))
    r = proxy_effective.proxy_effective_probe(host="github.com")
    assert r["verdict"] == "proxy-broken"
    assert r["works"] is False
    assert r["status"] == "down"


def test_direct_blocked_but_proxy_ok_is_the_happy_bypass(monkeypatch):
    """Прокси реально спасает от блокировки — это успех, не деградация."""
    _patch(monkeypatch, direct=_curl("000"), via=_curl(200))
    r = proxy_effective.proxy_effective_probe(host="github.com")
    assert r["verdict"] == "ok-blocked-direct"
    assert r["works"] is True
    assert r["status"] == "ok"


def test_both_down_blames_network_not_proxy(monkeypatch):
    _patch(monkeypatch, direct=_curl("000"), via=_curl("000"))
    r = proxy_effective.proxy_effective_probe(host="github.com")
    assert r["verdict"] == "both-down"
    assert r["works"] is False


def test_5xx_through_proxy_is_vendor_outage_not_broken_proxy(monkeypatch):
    """Канал жив, лежит сам вендор — не поднимать ложную тревогу (семантика health._tunnel_up)."""
    _patch(monkeypatch, direct=_curl(200), via=_curl(503))
    r = proxy_effective.proxy_effective_probe(host="github.com")
    assert r["verdict"] == "vendor-outage"
    assert r["works"] is True          # канал доказан живым
    assert r["status"] == "warn"       # но не «всё хорошо»


def test_probe_never_raises_on_internal_error(monkeypatch):
    """Probe-канон: любой сбой -> unknown, НЕ исключение."""
    def boom(url, proxy=True, proxy_url=None):
        raise RuntimeError("сломалось")
    monkeypatch.setattr(proxy_effective, "_curl_through", boom)
    r = proxy_effective.proxy_effective_probe(host="github.com")
    assert r["status"] == "unknown"
    assert r["works"] is None          # НЕ False: неизвестность != поломка


def test_socks_path_is_measured_through_xray_not_privoxy(monkeypatch):
    """git/codex ходят через SOCKS(xray), Claude Code — через HTTP(privoxy).

    Замер обязан бить в ТОТ путь, который просили, иначе вердикт не про того потребителя.
    """
    seen = []

    def fake(url, proxy=True, proxy_url=None, **kwargs):  # **kwargs: capture_headers (#323)
        seen.append(proxy_url if proxy else "DIRECT")
        return _curl(200)

    monkeypatch.setattr(proxy_effective, "_curl_through", fake)
    proxy_effective.proxy_effective_probe(host="github.com", channel="socks")
    assert "DIRECT" in seen
    assert any(p and p.startswith("socks5") for p in seen if p != "DIRECT")


def test_http_channel_uses_privoxy(monkeypatch):
    seen = []

    def fake(url, proxy=True, proxy_url=None, **kwargs):
        seen.append(proxy_url if proxy else "DIRECT")
        return _curl(200)

    monkeypatch.setattr(proxy_effective, "_curl_through", fake)
    proxy_effective.proxy_effective_probe(host="api.anthropic.com", channel="http")
    assert any(p and p.startswith("http://") for p in seen if p != "DIRECT")


# ===================== issue #323: синтетический 5xx посредника на http://-плече =====================
# Research #301: privoxy сам синтезирует 5xx ТОЛЬКО на plain-HTTP-плече (мёртвый upstream).
# Без guard'а одиночный код >= 500 неотличим от ответа вендора — мёртвый туннель
# показывался бы как «канал жив, вендор лежит» (works=True). Сигнатура синтетики —
# magic-даты privoxy в заголовках (захват стенда, см. константы выше).


def test_synthetic_503_is_proxy_broken_not_vendor_outage(monkeypatch):
    """503 с magic-датами privoxy = посредник сам ответил о мёртвом upstream — канал НЕ доказан."""
    _patch(monkeypatch, direct=_curl(200),
           via={**_curl(503), "headers": PRIVOXY_SYNTHETIC_503_HEADERS})
    r = proxy_effective.proxy_effective_probe(host="example.com")
    assert r["verdict"] == "proxy-broken"
    assert r["works"] is False
    assert r["status"] == "down"


def test_synthetic_502_no_data_is_proxy_broken(monkeypatch):
    """502 «No data received» (xray оборвал после CONNECT) — тот же класс: туннель мёртв."""
    _patch(monkeypatch, direct=_curl(200),
           via={**_curl(502), "headers": PRIVOXY_SYNTHETIC_502_HEADERS})
    r = proxy_effective.proxy_effective_probe(host="example.com")
    assert r["verdict"] == "proxy-broken"
    assert r["works"] is False


def test_synthetic_500_without_template_detected_by_expires(monkeypatch):
    """500 без шаблона не несёт last-modified 1955 — но magic-Expires есть во ВСЕХ
    синтетиках privoxy (универсальный маркер, живой захват стенда)."""
    _patch(monkeypatch, direct=_curl(200),
           via={**_curl(500), "headers": PRIVOXY_SYNTHETIC_500_HEADERS})
    r = proxy_effective.proxy_effective_probe(host="example.com")
    assert r["verdict"] == "proxy-broken"
    assert r["works"] is False


def test_real_503_with_vendor_headers_is_still_vendor_outage(monkeypatch):
    """Контроль: настоящий 503 вендора (заголовки без magic-дат) НЕ съедается guard'ом."""
    _patch(monkeypatch, direct=_curl(200),
           via={**_curl(503), "headers": REAL_ORIGIN_503_HEADERS})
    r = proxy_effective.proxy_effective_probe(host="example.com")
    assert r["verdict"] == "vendor-outage"
    assert r["works"] is True
    assert r["status"] == "warn"


def test_probe_requests_headers_for_via_arm(monkeypatch):
    """Контракт: probe ОБЯЗАН просить заголовки у via-замера, иначе guard мёртв на практике."""
    via_kwargs = []

    def fake(url, proxy=True, proxy_url=None, **kwargs):
        if proxy:
            via_kwargs.append(kwargs)
        return _curl(200)

    monkeypatch.setattr(proxy_effective, "_curl_through", fake)
    proxy_effective.proxy_effective_probe(host="github.com")
    assert any(kw.get("capture_headers") is True for kw in via_kwargs)


def test_probe_result_exposes_flag_not_raw_headers(monkeypatch):
    """Наружу — булев флаг, не сырые заголовки: диагностика без шума/утечки в метрики."""
    _patch(monkeypatch, direct=_curl(200),
           via={**_curl(503), "headers": PRIVOXY_SYNTHETIC_503_HEADERS})
    r = proxy_effective.proxy_effective_probe(host="example.com")
    assert "headers" not in r["proxy"]
    assert r["proxy"].get("synthetic_5xx") is True
