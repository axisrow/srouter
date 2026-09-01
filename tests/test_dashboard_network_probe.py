"""ТДД-тесты probe-семантики dashboard_network (issue #82, находки #3 и #7).

#3: _curl_through не должен считать 5xx/4xx живым туннелем — «жив» строго по семантике
    HTTP-кода (первоисточник — канон проекта _http_code_ok: 200<=code<400).
#7: probe_ping должен деградировать по packet loss, а не только по RTT.
"""
import dashboard_network


def _run_returning(out, *, timed_out=False, rc=0):
    """Фабрика fake sys_probe.run с фиксированным stdout. `timeout` в сигнатуре — это
    аргумент ВЫЗОВА (секунды), не флаг результата; флаг результата фиксируем через timed_out.
    `env` принимается и игнорируется — proxy=False теперь зовёт sys_probe.run(..., env=...)."""
    return lambda cmd, timeout=None, env=None: {"rc": rc, "out": out, "err": "", "timeout": timed_out}


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


# ===================== issue #323: capture_headers — заголовки ответа для guard'а синтетики =====================
# Живой захват (canon mock-format-must-come-from-live-capture): изолированный стенд
# privoxy 4.2.0 (brew), forward-socks5t на мёртвый upstream, 2026-09-01, research #301.
# Это ровно то, что curl -D кладёт в файл при синтетическом 503 «Forwarding failure».
PRIVOXY_SYNTHETIC_503_DUMP = (
    "HTTP/1.1 503 Forwarding failure\r\n"
    "Content-Length: 6925\r\n"
    "Content-Type: text/html\r\n"
    "Cache-Control: no-cache\r\n"
    "Date: Tue, 01 Sep 2026 03:32:59 GMT\r\n"
    "Last-Modified: Wed, 08 Jun 1955 12:00:00 GMT\r\n"
    "Expires: Sat, 17 Jun 2000 12:00:00 GMT\r\n"
    "Pragma: no-cache\r\n"
)


def _run_writing_header_dump(dump, *, timed_out=False):
    """fake sys_probe.run, который ведёт себя как реальный curl -D: пишет дамп по пути
    из аргумента после -D (cmd строится как [curl, ..., -D, path, url])."""
    def fake_run(cmd, timeout=None, env=None):
        path = cmd[cmd.index("-D") + 1]
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(dump)
        return {"rc": 0, "out": "503 0.007139", "err": "", "timeout": timed_out}
    return fake_run


def test_curl_through_capture_headers_parses_live_dump(monkeypatch):
    """capture_headers=True: дамп парсится в lower-case dict, magic-даты доступны guard'у."""
    monkeypatch.setattr(dashboard_network.sys_probe, "run",
                        _run_writing_header_dump(PRIVOXY_SYNTHETIC_503_DUMP))
    r = dashboard_network._curl_through("http://example.com/", capture_headers=True)
    assert r["code"] == "503"
    assert r["headers"]["expires"] == "Sat, 17 Jun 2000 12:00:00 GMT"
    assert r["headers"]["last-modified"] == "Wed, 08 Jun 1955 12:00:00 GMT"
    assert "HTTP/1.1" not in str(r["headers"])  # статус-лайн не попадает в заголовки


def test_curl_through_without_capture_headers_keeps_old_contract(monkeypatch):
    """Без capture_headers ключа headers НЕТ: старые потребители и моки не меняются."""
    monkeypatch.setattr(dashboard_network.sys_probe, "run", _run_returning("200 0.050000"))
    r = dashboard_network._curl_through("https://api.anthropic.com/")
    assert r == {"code": "200", "ms": 50, "up": True}


def test_curl_through_capture_headers_empty_dump_yields_empty(monkeypatch):
    """curl не записал заголовки (таймаут до ответа) — mkstemp-файл пуст, headers = {}.

    Точность нейминга (review PR #324): файл здесь существует всегда (mkstemp создаёт
    его до вызова curl) — «отсутствует» именно дамп заголовков, не файл. Ветку
    отсутствующего файла покрывает отдельный прямой тест парсера ниже.
    """
    monkeypatch.setattr(dashboard_network.sys_probe, "run",
                        lambda cmd, timeout=None, env=None: {"rc": 0, "out": "", "err": "", "timeout": True})
    r = dashboard_network._curl_through("http://example.com/", capture_headers=True)
    assert r["code"] == "000"
    assert r["headers"] == {}


def test_parse_header_dump_missing_file_returns_empty(tmp_path):
    """OSError-ветка парсера: несуществующий путь -> {}, не исключение.

    В проде практически недостижимо (файл живёт от mkstemp до unlink в try/finally),
    но парсер defensive — закрепляем контракт напрямую.
    """
    assert dashboard_network._parse_header_dump(tmp_path / "no-such-dump.txt") == {}


def test_curl_through_direct_strips_proxy_env(monkeypatch):
    """ДЫРА (cycle-review PR #298): proxy=False обязан МИНУТЬ прокси через env -u, иначе
    unвыведенный HTTP_PROXY/ALL_PROXY в окружении процесса тихо перенаправит «прямой» замер
    через посторонний прокси — контрольная группа перестаёт быть контрольной (canon
    probe_manager.direct_probe уже делает это очищение для того же класса замера)."""
    monkeypatch.setenv("HTTP_PROXY", "http://evil-proxy.example:9999")
    monkeypatch.setenv("ALL_PROXY", "socks5://evil-proxy.example:9999")

    seen_env = {}

    def fake_run(cmd, timeout=None, env=None):
        seen_env["env"] = env
        return {"rc": 0, "out": "200 0.050000", "err": "", "timeout": False}

    monkeypatch.setattr(dashboard_network.sys_probe, "run", fake_run)
    dashboard_network._curl_through("https://api.anthropic.com/", proxy=False)

    assert seen_env["env"] is not None, "proxy=False обязан передавать очищенный env, а не наследовать процесс"
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        assert key not in seen_env["env"], f"{key} просочился в direct-замер"


def test_curl_through_via_proxy_does_not_strip_env(monkeypatch):
    """proxy=True — обычный вызов через явный -x proxy_url, очищать env не нужно (не тот
    контракт: сюда никто не передаёт env=, отсутствие ключа в kwargs — ожидаемое поведение)."""
    seen = {}

    def fake_run(cmd, timeout=None, env=None):
        seen["env"] = env
        return {"rc": 0, "out": "200 0.050000", "err": "", "timeout": False}

    monkeypatch.setattr(dashboard_network.sys_probe, "run", fake_run)
    dashboard_network._curl_through("https://api.anthropic.com/", proxy=True)

    assert seen["env"] is None


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
