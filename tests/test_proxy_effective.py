"""Физический замер прокси: идёт ли трафик НА САМОМ ДЕЛЕ (не «включён ли флаг»).

Мотивация (эмпирика, снятая на живой машине): privoxy слушал 8118, xray слушал 10808,
дашборд горел зелёным ON — а `curl https://github.com` через SOCKS давал таймаут, потому
что узел был мёртв. Порт открыт != трафик идёт. Отсюда парный замер direct-vs-proxy.

Все пробы замоканы: немоканная проба медленная И machine-dependent (канон
unmocked-probe-is-both-slow-and-machine-dependent).
"""
import proxy_effective


def _curl(code, *, ms=120):
    """Форма ответа dashboard_network._curl_through: {code, ms, up}."""
    up = str(code).isdigit() and 100 <= int(code) < 500
    return {"code": str(code), "ms": ms, "up": up}


def _patch(monkeypatch, *, direct, via):
    """Подменяем ровно ту функцию, которую зовёт proxy_effective (не аналог)."""
    def fake(url, proxy=True, proxy_url=None):
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

    def fake(url, proxy=True, proxy_url=None):
        seen.append(proxy_url if proxy else "DIRECT")
        return _curl(200)

    monkeypatch.setattr(proxy_effective, "_curl_through", fake)
    proxy_effective.proxy_effective_probe(host="github.com", channel="socks")
    assert "DIRECT" in seen
    assert any(p and p.startswith("socks5") for p in seen if p != "DIRECT")


def test_http_channel_uses_privoxy(monkeypatch):
    seen = []

    def fake(url, proxy=True, proxy_url=None):
        seen.append(proxy_url if proxy else "DIRECT")
        return _curl(200)

    monkeypatch.setattr(proxy_effective, "_curl_through", fake)
    proxy_effective.proxy_effective_probe(host="api.anthropic.com", channel="http")
    assert any(p and p.startswith("http://") for p in seen if p != "DIRECT")
