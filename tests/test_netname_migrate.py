"""#395: learn_net при обучении видит историю под старой gw-меткой (observe — счётчик
событий + подсказка ручного шага), `netname-migrate` — ручная разовая миграция net-метки
в журналах: byte-exact бэкап до записи (канон rollback-byte-exact), чужие метки и битые
строки не трогаются, отсутствие совпадений — файл не переписывается вовсе.
"""
import json
import time

import diag_netprobe
import health
import metrics_store

_LEGACY = "gw:192.168.3.1:a4:2b:8c:11:22:33"


def _learn_mocks(monkeypatch, tmp_path):
    monkeypatch.setattr(diag_netprobe, "NETS_MAP", tmp_path / "nets.json")
    monkeypatch.setattr(diag_netprobe, "_default_route", lambda: ("192.168.3.1", "en0"))
    monkeypatch.setattr(diag_netprobe, "_dns_servers", lambda path=None: ("192.168.3.1",))
    monkeypatch.setattr(diag_netprobe, "run",
                        lambda cmd, timeout, **kw: {"rc": 0, "err": "", "timeout": False,
                                                    "out": "   router 192.168.3.1\n"})
    monkeypatch.setattr(diag_netprobe, "_gateway_mac", lambda ip: "a4:2b:8c:11:22:33")


def test_learn_net_warns_counting_legacy_events(monkeypatch, tmp_path, capsys):
    _learn_mocks(monkeypatch, tmp_path)
    mlog = tmp_path / "metrics.jsonl"
    slog = tmp_path / "status.jsonl"
    mlog.write_text(
        json.dumps({"ts": time.time(), "net": _LEGACY, "status": "ok"}) + "\n"
        + json.dumps({"ts": time.time(), "net": "Другая", "status": "ok"}) + "\n",
        encoding="utf-8")
    slog.write_text(json.dumps({"timestamp": "x", "net": _LEGACY}) + "\n", encoding="utf-8")
    monkeypatch.setattr(metrics_store, "METRICS_LOG", mlog)
    monkeypatch.setattr(health, "WATCHDOG_STATUS_LOG", slog)

    diag_netprobe.learn_net("Дома")

    out = capsys.readouterr().out
    assert "2 событий" in out and _LEGACY in out, out
    assert "netname-migrate Дома" in out, "подсказка ручного шага миграции"


def test_learn_net_silent_without_legacy_events(monkeypatch, tmp_path, capsys):
    _learn_mocks(monkeypatch, tmp_path)
    mlog = tmp_path / "metrics.jsonl"
    mlog.write_text(json.dumps({"ts": time.time(), "net": "Дома"}) + "\n", encoding="utf-8")
    monkeypatch.setattr(metrics_store, "METRICS_LOG", mlog)
    monkeypatch.setattr(health, "WATCHDOG_STATUS_LOG", tmp_path / "absent.jsonl")

    diag_netprobe.learn_net("Дома")

    assert "событий" not in capsys.readouterr().out


def test_migrate_renames_and_backs_up(monkeypatch, tmp_path):
    _learn_mocks(monkeypatch, tmp_path)
    (tmp_path / "nets.json").write_text(json.dumps(
        {"Дома": {"gateway": "192.168.3.1", "gateway_mac": "a4:2b:8c:11:22:33"}}),
        encoding="utf-8")
    mlog = tmp_path / "metrics.jsonl"
    slog = tmp_path / "status.jsonl"
    before_m = (json.dumps({"ts": 1.0, "net": _LEGACY, "status": "ok"}) + "\n"
                + json.dumps({"ts": 2.0, "net": "Другая"}) + "\n"
                + "битая строка без json\n")
    mlog.write_text(before_m, encoding="utf-8")
    slog.write_text(json.dumps({"net": _LEGACY, "previous": {}}) + "\n", encoding="utf-8")
    monkeypatch.setattr(metrics_store, "METRICS_LOG", mlog)
    monkeypatch.setattr(health, "WATCHDOG_STATUS_LOG", slog)

    diag_netprobe.migrate_net_labels("Дома")

    events = [json.loads(line) for line in mlog.read_text(encoding="utf-8").splitlines()
              if line.strip() and not line.startswith("битая")]
    assert events[0]["net"] == "Дома"
    assert events[1]["net"] == "Другая", "чужая метка не тронута"
    assert "битая строка без json" in mlog.read_text(encoding="utf-8"), \
        "битые строки сохраняются как есть"
    backups = list(tmp_path.glob("metrics.jsonl.pre-netname-migrate-*"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == before_m, "бэкап byte-exact"
    sevents = [json.loads(line) for line in slog.read_text(encoding="utf-8").splitlines()
               if line.strip()]
    assert sevents[0]["net"] == "Дома"


def test_migrate_unknown_net_is_noop(monkeypatch, tmp_path, capsys):
    _learn_mocks(monkeypatch, tmp_path)  # NETS_MAP не существует
    mlog = tmp_path / "metrics.jsonl"
    mlog.write_text("", encoding="utf-8")
    monkeypatch.setattr(metrics_store, "METRICS_LOG", mlog)
    monkeypatch.setattr(health, "WATCHDOG_STATUS_LOG", tmp_path / "absent.jsonl")

    diag_netprobe.migrate_net_labels("Нет такой")

    assert "не найдена" in capsys.readouterr().out


def test_migrate_noop_without_matches_keeps_file_untouched(monkeypatch, tmp_path):
    _learn_mocks(monkeypatch, tmp_path)
    (tmp_path / "nets.json").write_text(json.dumps(
        {"Дома": {"gateway": "192.168.3.1", "gateway_mac": "a4:2b:8c:11:22:33"}}),
        encoding="utf-8")
    mlog = tmp_path / "metrics.jsonl"
    before = json.dumps({"ts": 1.0, "net": "Другая"}) + "\n"
    mlog.write_text(before, encoding="utf-8")
    monkeypatch.setattr(metrics_store, "METRICS_LOG", mlog)
    monkeypatch.setattr(health, "WATCHDOG_STATUS_LOG", tmp_path / "absent.jsonl")

    diag_netprobe.migrate_net_labels("Дома")

    assert mlog.read_text(encoding="utf-8") == before, "без совпадений файл не переписывается"
    assert not list(tmp_path.glob("*.pre-netname-migrate-*")), "бэкап без изменений не создаётся"
