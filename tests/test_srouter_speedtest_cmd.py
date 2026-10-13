"""Тесты `srouter speedtest` — fake-бинарник через SROUTER_SPEEDTEST (канон подмены
SROUTER_CURL), net-контекст мокается на владельце (diag_netprobe), журнал — в tmp
(monkeypatch speedtest_store.SPEEDTEST_LOG: module-level константа, читается на вызове).
"""
import json
import unicodedata
from types import SimpleNamespace

import diag_netprobe
import speedtest_store
import srouter_cli


SPEEDTEST_OUT = json.dumps({
    "type": "result",
    "timestamp": "2026-10-11T15:29:29Z",
    "ping": {"jitter": 281.065, "latency": 231.949},
    "download": {"bandwidth": 82121},
    "upload": {"bandwidth": 4902928},
    "packetLoss": 0,
    "isp": "M247 Europe",
    "interface": {"name": "ipsec0", "isVpn": True, "externalIp": "2.58.44.46"},
    "server": {"name": "0DayHost (SMC-Private) Limited",
               "location": "Amsterdam", "country": "Netherlands"},
    "result": {"url": "https://www.speedtest.net/result/c/abc"},
})

NET = {"label": "home-5G", "known": True, "source": "map"}


def _args(list_=None, iface=None):
    return SimpleNamespace(list=list_, iface=iface)


def _write_bin(tmp_path, body, rc=0, capture=None):
    """Fake speedtest: успех — body в stdout (как -f json), фейл — body в stderr
    (как настоящий CLI); exit rc; capture — файл для $@."""
    lines = ["#!/usr/bin/env bash"]
    if capture:
        lines.append(f"printf '%s\\n' \"$@\" >> \"{capture}\"")
    if rc == 0:
        lines.append("cat <<'SJSON'")
        lines.append(body)
        lines.append("SJSON")
    else:
        lines.append("cat <<'SJSON' >&2")
        lines.append(body)
        lines.append("SJSON")
    lines.append(f"exit {rc}")
    bin_path = tmp_path / "fake_speedtest.sh"
    bin_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    bin_path.chmod(0o755)
    return bin_path


def _setup(monkeypatch, tmp_path, body, rc=0, capture=None):
    bin_path = _write_bin(tmp_path, body, rc=rc, capture=capture)
    monkeypatch.setenv("SROUTER_SPEEDTEST", str(bin_path))
    log = tmp_path / "speedtest.jsonl"
    monkeypatch.setattr(speedtest_store, "SPEEDTEST_LOG", log)
    monkeypatch.setattr(diag_netprobe, "current_net_status", lambda: dict(NET))
    return log


def test_run_appends_record_and_prints_summary(tmp_path, monkeypatch, capsys):
    log = _setup(monkeypatch, tmp_path, SPEEDTEST_OUT)
    rc = srouter_cli.cmd_speedtest(_args())
    assert rc == 0
    out = capsys.readouterr().out
    assert "0.66" in out and "39.22" in out and "home-5G" in out
    recs = speedtest_store.read_results(log_path=log)
    assert len(recs) == 1
    rec = recs[0]
    assert rec["net"] == "home-5G" and rec["net_known"] is True
    assert rec["iface"] == "ipsec0" and rec["vpn"] is True
    assert rec["isp"] == "M247 Europe"
    assert rec["download_mbps"] == 0.66


def test_speedtest_failure_writes_no_record(tmp_path, monkeypatch, capsys):
    log = _setup(monkeypatch, tmp_path, "boom", rc=7)
    rc = srouter_cli.cmd_speedtest(_args())
    assert rc == 7
    assert speedtest_store.read_results(log_path=log) == []
    assert "boom" in capsys.readouterr().err


def test_bad_json_writes_no_record(tmp_path, monkeypatch, capsys):
    log = _setup(monkeypatch, tmp_path, "не json")
    rc = srouter_cli.cmd_speedtest(_args())
    assert rc == 2
    assert speedtest_store.read_results(log_path=log) == []


def test_iface_flag_reaches_binary(tmp_path, monkeypatch, capsys):
    capture = tmp_path / "argv.txt"
    _setup(monkeypatch, tmp_path, SPEEDTEST_OUT, capture=capture)
    rc = srouter_cli.cmd_speedtest(_args(iface="ppp0"))
    assert rc == 0
    argv = capture.read_text(encoding="utf-8").splitlines()
    assert "-I" in argv and "ppp0" in argv


def _rec(ts, net, dl):
    return {"ts": ts, "timestamp": "t", "net": net, "net_known": True, "vpn": False,
            "iface": "en0", "isp": "ISP", "download_mbps": dl,
            "upload_mbps": 10.0, "ping_ms": 20.0}


def test_list_prints_recent_records(tmp_path, monkeypatch, capsys):
    log = tmp_path / "speedtest.jsonl"
    monkeypatch.setattr(speedtest_store, "SPEEDTEST_LOG", log)
    speedtest_store.append_result(_rec(1.0, "office", 5.0), log_path=log)
    speedtest_store.append_result(_rec(2.0, "home-5G", 0.66), log_path=log)
    rc = srouter_cli.cmd_speedtest(_args(list_=10))
    assert rc == 0
    out = capsys.readouterr().out
    assert "home-5G" in out and "office" in out
    assert "0.66" in out and "5.0" in out


def test_list_columns_aligned_for_wide_net_names(tmp_path, monkeypatch, capsys):
    # CJK-имя сети (云栖壁8-3) рендерится в терминале двойной шириной: колонки
    # обязаны выравниваться по display-width, а не по len() — иначе числовые
    # колонки плывут построчно и не образуют вертикали (найдено глазами 2026-10-14).
    log = tmp_path / "speedtest.jsonl"
    monkeypatch.setattr(speedtest_store, "SPEEDTEST_LOG", log)
    speedtest_store.append_result(_rec(1.0, "office", 5.0), log_path=log)
    speedtest_store.append_result(_rec(2.0, "云栖壁8-3", 0.66), log_path=log)
    rc = srouter_cli.cmd_speedtest(_args(list_=10))
    assert rc == 0
    lines = capsys.readouterr().out.splitlines()
    data = [ln for ln in lines if ("5.0" in ln) or ("0.66" in ln)]
    assert len(data) == 2
    ascii_line = next(ln for ln in data if "5.0" in ln)
    cjk_line = next(ln for ln in data if "0.66" in ln)

    def dw(s):
        return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)

    def col_end(line, token):
        return dw(line[:line.index(token) + len(token)])

    # download-колонка правая: правый край чисел совпадает в обеих строках данных
    # (колонка right-aligned) и с правым краем заголовка «↓ Мбит/с»
    assert col_end(ascii_line, "5.0") == col_end(cjk_line, "0.66")
    header = lines[1]
    assert col_end(ascii_line, "5.0") == col_end(header, "↓ Мбит/с")


def test_list_zero_is_value_not_absent_flag(tmp_path, monkeypatch, capsys):
    # --list 0: 0 — заданное значение (nargs="?"), не «флага нет»: таблица,
    # а не молчаливый полный замер на 240с (review #424).
    log = _setup(monkeypatch, tmp_path, SPEEDTEST_OUT)
    speedtest_store.append_result(_rec(1.0, "office", 5.0), log_path=log)
    rc = srouter_cli.cmd_speedtest(_args(list_=0))
    assert rc == 0
    out = capsys.readouterr().out
    assert "Последние замеры" in out
    assert len(speedtest_store.read_results(log_path=log)) == 1  # замер не запускался


def test_list_empty_log_says_no_records(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(speedtest_store, "SPEEDTEST_LOG", tmp_path / "nope.jsonl")
    rc = srouter_cli.cmd_speedtest(_args(list_=10))
    assert rc == 0
    assert "нет" in capsys.readouterr().out
