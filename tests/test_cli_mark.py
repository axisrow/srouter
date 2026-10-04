"""Тесты srouter mark — ручная отметка качества интернета в JSONL (2026-10-04).

Контракт: одна JSONL-строка на отметку {ts, timestamp, verdict, comment, net,
net_known, net_source}; контекст сети от diag_netprobe.current_net_status (мокается
на владельце-модуле); append через metrics_store.append_timing_event (best-effort)
→ честный exit 0/1; невалидный verdict отсекает argparse (exit 2, ничего не пишет).
"""
import json

import pytest

import diag_netprobe
import metrics_store
import srouter_cli


def _read_rows(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def test_mark_writes_row_with_net_context(monkeypatch, tmp_path, capsys):
    log = tmp_path / "marks.jsonl"
    monkeypatch.setattr(metrics_store, "MARKS_LOG", log)
    monkeypatch.setattr(diag_netprobe, "current_net_status",
                        lambda: {"label": "103", "known": True, "source": "map"})

    assert srouter_cli.main(["mark", "ok", "видео лагает"]) == 0

    rows = _read_rows(log)
    assert len(rows) == 1
    row = rows[0]
    assert row["verdict"] == "ok"
    assert row["comment"] == "видео лагает"
    assert row["net"] == "103"
    assert row["net_known"] is True
    assert row["net_source"] == "map"
    assert isinstance(row["ts"], float)
    assert isinstance(row["timestamp"], str) and "T" in row["timestamp"]
    out = capsys.readouterr().out
    assert "ok" in out and "103" in out


def test_mark_without_comment_and_without_network(monkeypatch, tmp_path):
    log = tmp_path / "marks.jsonl"
    monkeypatch.setattr(metrics_store, "MARKS_LOG", log)
    monkeypatch.setattr(diag_netprobe, "current_net_status", lambda: None)

    assert srouter_cli.main(["mark", "bad"]) == 0

    row = _read_rows(log)[0]
    assert row["verdict"] == "bad"
    assert row["comment"] is None
    assert row["net"] is None
    assert row["net_known"] is False
    assert row["net_source"] is None


def test_mark_unknown_net_not_false_ok(monkeypatch, tmp_path, capsys):
    """known=False (чужая необученная сеть): метка пишется, но с known=false — не ложный ok."""
    log = tmp_path / "marks.jsonl"
    monkeypatch.setattr(metrics_store, "MARKS_LOG", log)
    monkeypatch.setattr(diag_netprobe, "current_net_status",
                        lambda: {"label": "NewCafe", "known": False, "source": "ssid"})

    assert srouter_cli.main(["mark", "ok"]) == 0

    row = _read_rows(log)[0]
    assert row["net"] == "NewCafe"
    assert row["net_known"] is False
    assert row["net_source"] == "ssid"
    assert "неизвестная сеть" in capsys.readouterr().out


def test_mark_append_failure_exit_1(monkeypatch, tmp_path, capsys):
    """append best-effort вернул False → exit 1 + stderr (шумный лог > молчаливый успех)."""
    logdir = tmp_path / "logdir"
    logdir.mkdir()
    monkeypatch.setattr(metrics_store, "MARKS_LOG", logdir)  # директория: open("a") → OSError
    monkeypatch.setattr(diag_netprobe, "current_net_status", lambda: None)

    assert srouter_cli.main(["mark", "ok"]) == 1
    captured = capsys.readouterr()
    assert "НЕ записана" in captured.err


def test_mark_invalid_verdict_rejected_by_argparse(monkeypatch, tmp_path):
    """argparse choices: невалидный verdict → SystemExit 2, файл не создаётся."""
    log = tmp_path / "marks.jsonl"
    monkeypatch.setattr(metrics_store, "MARKS_LOG", log)
    monkeypatch.setattr(diag_netprobe, "current_net_status",
                        lambda: {"label": "103", "known": True, "source": "map"})

    with pytest.raises(SystemExit) as ei:
        srouter_cli.main(["mark", "отлично"])
    assert ei.value.code == 2
    assert not log.exists()
