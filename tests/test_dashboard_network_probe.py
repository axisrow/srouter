"""ТДД-тесты probe-семантики dashboard_network (issue #82, находки #3 и #7).

#3: _curl_through не должен считать 5xx/4xx живым туннелем — «жив» строго по семантике
    HTTP-кода (первоисточник — канон проекта _http_code_ok: 200<=code<400).
#7: probe_ping должен деградировать по packet loss, а не только по RTT.
"""
import dashboard_network


def _run_returning(out, *, timed_out=False, rc=0):
    """Фабрика fake sys_probe.run с фиксированным stdout. `timeout` в сигнатуре — это
    аргумент ВЫЗОВА (секунды), не флаг результата; флаг результата фиксируем через timed_out."""
    return lambda cmd, timeout=None: {"rc": rc, "out": out, "err": "", "timeout": timed_out}


# ============================ #3: _curl_through / probe_tunnel HTTP semantics ============================


def test_curl_through_5xx_is_not_up(monkeypatch):
    """503 от мёртвого upstream — туннель НЕ жив. ДЫРА: сейчас up=(code!='000') зеленит 5xx."""
    monkeypatch.setattr(dashboard_network.sys_probe, "run", _run_returning("503 0.100000"))
    r = dashboard_network._curl_through("https://api.anthropic.com/")
    assert r["code"] == "503"
    assert r["up"] is False, f"5xx = мёртвый upstream, не живой туннель, получили {r}"


def test_curl_through_4xx_is_up(monkeypatch):
    """404/421 от реального сервера (api.anthropic.com/ → 404) = канал ЖИВ: пакеты дошли,
    сервер ответил HTTP. Цель probe — достижимость через туннель, не что URL отдаёт 200."""
    monkeypatch.setattr(dashboard_network.sys_probe, "run", _run_returning("404 0.050000"))
    r = dashboard_network._curl_through("https://api.anthropic.com/")
    assert r["code"] == "404"
    assert r["up"] is True, f"4xx от живого сервера = канал жив, получили {r}"


def test_curl_through_421_is_up(monkeypatch):
    """421 Misdirected (реальный ответ api.openai.com/ на '/') — сервер ответил → канал жив."""
    monkeypatch.setattr(dashboard_network.sys_probe, "run", _run_returning("421 0.070000"))
    r = dashboard_network._curl_through("https://api.openai.com/")
    assert r["up"] is True


def test_curl_through_2xx_is_up(monkeypatch):
    """200 — канал жив (существующее корректное поведение, не ломаем)."""
    monkeypatch.setattr(dashboard_network.sys_probe, "run", _run_returning("200 0.120000"))
    r = dashboard_network._curl_through("https://api.anthropic.com/")
    assert r["code"] == "200"
    assert r["ms"] == 120
    assert r["up"] is True


def test_curl_through_3xx_is_up(monkeypatch):
    """3xx (redirect) — канал до сервера жив."""
    monkeypatch.setattr(dashboard_network.sys_probe, "run", _run_returning("301 0.080000"))
    r = dashboard_network._curl_through("https://api.anthropic.com/")
    assert r["up"] is True


def test_curl_through_000_is_not_up(monkeypatch):
    """000 — соединение не установлено (существующее поведение)."""
    monkeypatch.setattr(dashboard_network.sys_probe, "run", _run_returning("000 0.000000"))
    r = dashboard_network._curl_through("https://api.anthropic.com/")
    assert r["code"] == "000"
    assert r["up"] is False


def test_curl_through_empty_output_is_not_up(monkeypatch):
    """Пустой вывод — не жив, ms=None (не бросает)."""
    monkeypatch.setattr(dashboard_network.sys_probe, "run", _run_returning(""))
    r = dashboard_network._curl_through("https://api.anthropic.com/")
    assert r["up"] is False
    assert r["ms"] is None


def test_curl_through_malformed_output_is_not_up(monkeypatch):
    """Битый вывод (нет разделителя/мусор) — не жив, без исключения."""
    monkeypatch.setattr(dashboard_network.sys_probe, "run", _run_returning("garbage-no-space"))
    r = dashboard_network._curl_through("https://api.anthropic.com/")
    assert r["up"] is False


def test_curl_through_nonnumeric_code_is_not_up(monkeypatch):
    """Нечисловой код (теоретический мусор с пробелом) — не жив."""
    monkeypatch.setattr(dashboard_network.sys_probe, "run", _run_returning("abc 0.100000"))
    r = dashboard_network._curl_through("https://api.anthropic.com/")
    assert r["up"] is False


def test_curl_through_timeout_is_not_up(monkeypatch):
    """timeout=True — не жив (существующее поведение)."""
    monkeypatch.setattr(dashboard_network.sys_probe, "run",
                        lambda cmd, timeout=None: {"rc": None, "out": "", "err": "timeout", "timeout": True})
    r = dashboard_network._curl_through("https://api.anthropic.com/")
    assert r["up"] is False


def test_probe_tunnel_down_when_only_5xx(monkeypatch):
    """probe_tunnel: оба таргета отвечают 503 → status='down' (мёртвый upstream ≠ живой туннель)."""
    monkeypatch.setattr(dashboard_network.sys_probe, "run", _run_returning("503 0.100000"))
    r = dashboard_network.probe_tunnel()
    assert r["anthropic"]["up"] is False
    assert r["openai"]["up"] is False
    assert r["status"] == "down", f"5xx на обоих таргетах = туннель down, получили {r}"


def test_probe_tunnel_ok_when_any_2xx(monkeypatch):
    """probe_tunnel: любой таргет 2xx → status='ok' (существующее корректное поведение)."""
    def fake_run(cmd, timeout=None):
        url = cmd[-1]
        code = "200" if "anthropic" in url else "503"
        return {"rc": 0, "out": f"{code} 0.100000", "err": "", "timeout": False}

    monkeypatch.setattr(dashboard_network.sys_probe, "run", fake_run)
    r = dashboard_network.probe_tunnel()
    assert r["anthropic"]["up"] is True
    assert r["status"] == "ok"


def test_probe_direct_down_on_5xx(monkeypatch):
    """probe_direct использует _curl_through(proxy=False): 5xx → down (не «прямой доступ ok»)."""
    monkeypatch.setattr(dashboard_network.sys_probe, "run", _run_returning("502 0.200000"))
    r = dashboard_network.probe_direct()
    assert r["status"] == "down", f"5xx на прямом probe = down, получили {r}"


# ============================ #7: probe_ping packet loss ============================


def test_parse_ping_stats_extracts_loss():
    """_parse_ping_stats возвращает (avg, loss). Первоисточник — macOS ping summary."""
    out = (
        "3 packets transmitted, 1 packets received, 66.7% packet loss\n"
        "round-trip min/avg/max/stddev = 10.0/30.0/50.0/1.0 ms"
    )
    avg, loss = dashboard_network._parse_ping_stats(out)
    assert avg == 30
    assert loss == 66.7


def test_parse_ping_stats_full_loss_no_rtt():
    """100% потерь: RTT-строки нет, avg=None, loss=100.0 (не бросает)."""
    out = "3 packets transmitted, 0 packets received, 100.0% packet loss"
    avg, loss = dashboard_network._parse_ping_stats(out)
    assert avg is None
    assert loss == 100.0


def test_probe_ping_high_loss_degrades_status(monkeypatch):
    """vps_ms=30 (низкий RTT), но vps_loss=66.7% → status warn/down. ДЫРА: сейчас status зависит
    только от vps_ms и показывает 'ok'."""
    monkeypatch.setattr(dashboard_network, "_ping_avg",
                        lambda host: (30, 66.7) if host else (None, None))
    r = dashboard_network.probe_ping(route_ip="1.2.3.4")
    assert r["vps_ms"] == 30
    assert r["vps_loss"] == 66.7
    assert r["status"] in ("warn", "down"), f"высокая потеря пакетов должна деградировать, получили {r}"


def test_probe_ping_full_loss_is_down(monkeypatch):
    """100% потерь → down (канал по сути мёртв, даже если какой-то avg просочился)."""
    monkeypatch.setattr(dashboard_network, "_ping_avg",
                        lambda host: (30, 100.0) if host else (None, None))
    r = dashboard_network.probe_ping(route_ip="1.2.3.4")
    assert r["status"] == "down", f"100% loss = down, получили {r}"


def test_probe_ping_no_data_is_down(monkeypatch):
    """Нет данных (vps_ms=None) → down (существующее поведение)."""
    monkeypatch.setattr(dashboard_network, "_ping_avg", lambda host: (None, None))
    r = dashboard_network.probe_ping(route_ip="1.2.3.4")
    assert r["status"] == "down"


def test_probe_ping_low_loss_stays_ok(monkeypatch):
    """Низкий RTT + низкая потеря → ok (не деградируем на шумовые 0-єдиницы %)."""
    monkeypatch.setattr(dashboard_network, "_ping_avg",
                        lambda host: (30, 0.0) if host else (None, None))
    r = dashboard_network.probe_ping(route_ip="1.2.3.4")
    assert r["status"] == "ok"


def test_probe_ping_partial_loss_warns(monkeypatch):
    """Умеренная потеря (например 33%) при хорошем RTT → warn (деградация, но не полный down)."""
    monkeypatch.setattr(dashboard_network, "_ping_avg",
                        lambda host: (30, 33.3) if host else (None, None))
    r = dashboard_network.probe_ping(route_ip="1.2.3.4")
    assert r["status"] == "warn", f"частичная потеря = warn, получили {r}"


def test_probe_ping_high_rtt_still_warns(monkeypatch):
    """Высокий RTT без потерь по-прежнему warn (существующее поведение не ломаем)."""
    monkeypatch.setattr(dashboard_network, "_ping_avg",
                        lambda host: (200, 0.0) if host else (None, None))
    r = dashboard_network.probe_ping(route_ip="1.2.3.4")
    assert r["status"] == "warn"
