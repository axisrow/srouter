"""Doctor видит «туннель жив, но exit/маршрут не годен» (инцидент 2026-10-08).

`_anthropic_exit_check` — годность выхода для Anthropic: 401 authentication_error =
exit обслуживает; 403 без cf-challenge = регион/бан; `cf-mitigated: challenge` =
проба недостоверна (бот-челлендж Cloudflare, не регион). `tunnel_code_up` при этом
НЕ меняется (403-как-живой — осознанный дизайн канарейки).

`_xray_config_freshness_check` — config.json новее процесса xray = рестарт не применён:
боевой процесс живёт по старым маршрутам (реальный случай: whitelist на диске,
процесс гонит всё direct).

Моки — по живому захвату форензики 2026-10-08 (заголовки/тела реальных ответов).
"""
import time

import health
import health_probes
import local_state_xray


# ---------- _etime_to_seconds ----------

def test_etime_seconds_formats():
    assert health_probes._etime_to_seconds("01:23") == 83
    assert health_probes._etime_to_seconds("20:33:09") == 20 * 3600 + 33 * 60 + 9
    assert health_probes._etime_to_seconds("1-02:03:04") == 86400 + 2 * 3600 + 3 * 60 + 4


def test_etime_seconds_garbage_is_none():
    assert health_probes._etime_to_seconds("") is None
    assert health_probes._etime_to_seconds(None) is None
    assert health_probes._etime_to_seconds("abc") is None
    assert health_probes._etime_to_seconds("1:2") == 62, "непаддингованный mm:ss валиден"
    assert health_probes._etime_to_seconds("1:2:3:4") is None


# ---------- _anthropic_exit_check ----------

def _mock_run(monkeypatch, out="", err="", timed_out=False, rc=0):
    calls = []

    def fake(cmd, timeout, **kw):
        calls.append((cmd, timeout))
        return {"rc": rc, "out": out, "err": err, "timeout": timed_out}

    monkeypatch.setattr(health_probes.sys_probe, "run", fake)
    return calls


def test_anthropic_exit_401_is_ok(monkeypatch):
    live = ("HTTP/2 401\r\n"
            "content-type: application/json\r\n"
            "\r\n"
            '{"type":"error","error":{"type":"authentication_error",'
            '"message":"x-api-key header is required"}}')
    _mock_run(monkeypatch, out=live)
    chk = health_probes._anthropic_exit_check()
    assert chk["status"] == "ok"
    assert "401" in chk["detail"]


def test_anthropic_exit_parses_past_connect_preamble(monkeypatch):
    """Живой захват 2026-10-08: curl -i через http-прокси выдаёт сначала ответ CONNECT
    прокси («HTTP/1.1 200 Connection established») — целевой ответ последним блоком.
    Парсер обязан взять ПОСЛЕДНИЙ HTTP-блок, иначе код читается из CONNECT-ответа."""
    live = ("HTTP/1.1 200 Connection established\r\n"
            "\r\n"
            "HTTP/2 403\r\n"
            "server: cloudflare\r\n"
            "cf-ray: a4736653ec29d13f-HKG\r\n"
            "\r\n"
            '{\n  "error": {\n    "type": "forbidden",\n'
            '    "message": "Request not allowed"\n  }\n}')
    _mock_run(monkeypatch, out=live)
    chk = health_probes._anthropic_exit_check()
    assert chk["status"] == "warn"
    assert "не обслуживает" in chk["detail"]
    assert "established" not in chk["detail"], "код не должен читаться из CONNECT-ответа"


def test_anthropic_exit_401_after_connect_preamble_is_ok(monkeypatch):
    live = ("HTTP/1.1 200 Connection established\r\n"
            "\r\n"
            "HTTP/2 401\r\n"
            "content-type: application/json\r\n"
            "\r\n"
            '{"type":"error","error":{"type":"authentication_error"}}')
    _mock_run(monkeypatch, out=live)
    chk = health_probes._anthropic_exit_check()
    assert chk["status"] == "ok"
    assert "401" in chk["detail"]


def test_anthropic_exit_403_without_challenge_is_region(monkeypatch):
    live = ("HTTP/2 403\r\n"
            "content-type: application/json\r\n"
            "\r\n"
            '{"type":"error","error":{"type":"not_allowed_error",'
            '"message":"Request not allowed"}}')
    _mock_run(monkeypatch, out=live)
    chk = health_probes._anthropic_exit_check()
    assert chk["status"] == "warn"
    assert "регион" in chk["detail"] or "не обслуживает" in chk["detail"]


def test_anthropic_exit_cf_challenge_is_not_region(monkeypatch):
    live = ("HTTP/2 403\r\n"
            "server: cloudflare\r\n"
            "cf-mitigated: challenge\r\n"
            "\r\n"
            "<html>Just a moment...</html>")
    _mock_run(monkeypatch, out=live)
    chk = health_probes._anthropic_exit_check()
    assert chk["status"] == "warn"
    assert "challenge" in chk["detail"], "бот-челлендж не должен читаться как регион"


def test_anthropic_exit_timeout_is_unknown(monkeypatch):
    _mock_run(monkeypatch, timed_out=True, err="timed out")
    assert health_probes._anthropic_exit_check()["status"] == "unknown"


def test_anthropic_exit_no_response_is_unknown(monkeypatch):
    _mock_run(monkeypatch, out="", err="connection refused")
    assert health_probes._anthropic_exit_check()["status"] == "unknown"


def test_anthropic_exit_5xx_is_warn_upstream(monkeypatch):
    live = "HTTP/2 502\r\ncontent-type: text/html\r\n\r\nbad gateway"
    _mock_run(monkeypatch, out=live)
    chk = health_probes._anthropic_exit_check()
    assert chk["status"] == "warn"
    assert "5xx" in chk["detail"]


# ---------- _xray_config_freshness_check ----------

def _mock_xray_procs(monkeypatch, etime, pids="92758\n"):
    def fake(cmd, timeout, **kw):
        if cmd[0] == health_probes.PGREP:
            return {"rc": 0, "out": pids, "err": "", "timeout": False}
        if cmd[0] == health_probes.PS:
            return {"rc": 0, "out": etime, "err": "", "timeout": False}
        raise AssertionError(f"неожиданная команда {cmd}")
    monkeypatch.setattr(health_probes.sys_probe, "run", fake)


def test_freshness_config_newer_than_process_warns(monkeypatch, tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(local_state_xray, "XRAY_CONFIG_PATH", str(cfg))
    _mock_xray_procs(monkeypatch, etime="00:01:00")  # процесс минуту назад
    # mtime «сейчас» > старта процесса (минуту назад)
    chk = health_probes._xray_config_freshness_check()
    assert chk["status"] == "warn"
    assert "рестарт" in chk["detail"]


def test_freshness_process_newer_is_ok(monkeypatch, tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text("{}", encoding="utf-8")
    old = time.time() - 3600
    import os
    os.utime(cfg, (old, old))
    monkeypatch.setattr(local_state_xray, "XRAY_CONFIG_PATH", str(cfg))
    _mock_xray_procs(monkeypatch, etime="00:01:00")
    assert health_probes._xray_config_freshness_check()["status"] == "ok"


def test_freshness_no_process_is_unknown(monkeypatch, tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(local_state_xray, "XRAY_CONFIG_PATH", str(cfg))
    _mock_xray_procs(monkeypatch, etime="", pids="")
    assert health_probes._xray_config_freshness_check()["status"] == "unknown"


def test_freshness_unparseable_etime_is_unknown(monkeypatch, tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(local_state_xray, "XRAY_CONFIG_PATH", str(cfg))
    _mock_xray_procs(monkeypatch, etime="garbage")
    assert health_probes._xray_config_freshness_check()["status"] == "unknown"


# ---------- интеграция check_all ----------

def test_check_all_includes_both_exit_checks_as_info(monkeypatch):
    from test_health import _all_up_monkey
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_anthropic_exit_check",
                        lambda: {"status": "warn", "detail": "mock: регион"})
    monkeypatch.setattr(health, "_xray_config_freshness_check",
                        lambda: {"status": "warn", "detail": "mock: рестарт не применён"})
    result = health.check_all(active_claude=True)
    names = {c["name"]: c for c in result["checks"]}
    ax = names["anthropic-exit (годность выхода для API)"]
    fr = names["xray-config-freshness (конфиг vs процесс)"]
    assert ax["ok"] is False and ax["info"] is True, "warn-чек не роняет driver-вердикт"
    assert fr["ok"] is False and fr["info"] is True
    assert result["status"] == "ok", "info-чеки не должны ронять общий вердикт"


def test_check_all_omits_unknown_exit_check(monkeypatch):
    from test_health import _all_up_monkey
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_anthropic_exit_check",
                        lambda: {"status": "unknown", "detail": "mock"})
    monkeypatch.setattr(health, "_xray_config_freshness_check",
                        lambda: {"status": "unknown", "detail": "mock"})
    result = health.check_all(active_claude=True)
    names = {c["name"] for c in result["checks"]}
    assert "anthropic-exit (годность выхода для API)" not in names
    assert "xray-config-freshness (конфиг vs процесс)" not in names
