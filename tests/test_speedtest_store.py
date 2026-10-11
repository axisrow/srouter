"""Тесты speedtest_store: append-only JSONL-журнал ручных замеров скорости (srouter speedtest).

Канон metrics_store: build_record defensive (мусор → None-поля, никогда не бросает),
append_result best-effort True/False, read_results — хвост newest-first, битые строки
пропускаются. bandwidth у Ookla JSON — БАЙТЫ/с (82121 Б/с ≈ 0.66 Мбит/с — реальный
замер 10-11 через VPN ipsec0).
"""
import speedtest_store


SPEEDTEST_JSON = {
    "type": "result",
    "timestamp": "2026-10-11T15:29:29Z",
    "ping": {"jitter": 281.065, "latency": 231.949},
    "download": {"bandwidth": 82121},
    "upload": {"bandwidth": 4902928},
    "packetLoss": 0,
    "isp": "M247 Europe",
    "interface": {"internalIp": "10.1.0.73", "name": "ipsec0",
                  "isVpn": True, "externalIp": "2.58.44.46"},
    "server": {"id": 73054, "name": "0DayHost (SMC-Private) Limited",
               "location": "Amsterdam", "country": "Netherlands"},
    "result": {"url": "https://www.speedtest.net/result/c/abc"},
}

NET = {"label": "home-5G", "known": True, "source": "map"}


def test_build_record_maps_fields():
    rec = speedtest_store.build_record(SPEEDTEST_JSON, NET, now=1760000000.0)
    assert rec["ts"] == 1760000000.0
    assert rec["timestamp"]
    assert rec["net"] == "home-5G" and rec["net_known"] is True
    assert rec["iface"] == "ipsec0" and rec["vpn"] is True
    assert rec["isp"] == "M247 Europe" and rec["exit_ip"] == "2.58.44.46"
    # bandwidth — байты/с: 82121 Б/с → 0.66 Мбит/с вниз, 4902928 Б/с → 39.22 вверх
    assert rec["download_mbps"] == 0.66
    assert rec["upload_mbps"] == 39.22
    assert rec["ping_ms"] == 231.9 and rec["jitter_ms"] == 281.1
    assert rec["packet_loss"] == 0
    assert "0DayHost" in rec["server"] and "Amsterdam" in rec["server"]
    assert rec["result_url"].endswith("/abc")


def test_build_record_garbage_never_raises():
    rec = speedtest_store.build_record("мусор", None, now=1760000000.0)
    assert rec["ts"] == 1760000000.0
    assert rec["download_mbps"] is None and rec["iface"] is None
    assert rec["net"] is None and rec["net_known"] is False
    speedtest_store.build_record(None, {"label": None, "known": False, "source": "gw"})


def test_append_and_read_roundtrip(tmp_path):
    log = tmp_path / "speedtest.jsonl"
    assert speedtest_store.append_result({"ts": 1, "net": "a"}, log_path=log)
    assert speedtest_store.append_result({"ts": 2, "net": "b"}, log_path=log)
    out = speedtest_store.read_results(limit=10, log_path=log)
    assert [r["net"] for r in out] == ["b", "a"]  # newest-first


def test_read_results_skips_broken_lines(tmp_path):
    log = tmp_path / "speedtest.jsonl"
    log.write_text('{"ts": 1, "net": "a"}\nбитая строка\n{"ts": 2, "net": "b"}\n',
                   encoding="utf-8")
    out = speedtest_store.read_results(limit=10, log_path=log)
    assert [r["net"] for r in out] == ["b", "a"]


def test_read_results_missing_file_is_empty(tmp_path):
    assert speedtest_store.read_results(log_path=tmp_path / "nope.jsonl") == []


def test_append_result_rejects_non_dict(tmp_path):
    assert speedtest_store.append_result("мусор", log_path=tmp_path / "x.jsonl") is False
