"""#395: learn_net при обучении видит историю под старой gw-меткой (observe — счётчик
событий + подсказка ручного шага), `netname-migrate` — ручная разовая миграция net-метки
в журналах: byte-exact бэкап до записи (канон rollback-byte-exact), чужие метки и битые
строки не трогаются, отсутствие совпадений — файл не переписывается вовсе.
"""
import json
import time
from pathlib import Path

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
    assert "netname-migrate 'Дома'" in out, "подсказка ручного шага миграции"


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


_QUESTION = "gw:192.168.3.1:?"


def test_migrate_covers_both_mac_and_question_labels(monkeypatch, tmp_path):
    """Тики с холодным ARP писали gw:ip:? (_gateway_mac fail-soft → None), обучение с
    тёплым ARP видит только gw:ip:mac — миграция обязана накрыть ОБЕ метки, иначе часть
    истории главной сети молча остаётся под старой меткой (#395 заново, только тихо)."""
    _learn_mocks(monkeypatch, tmp_path)
    (tmp_path / "nets.json").write_text(json.dumps(
        {"Дома": {"gateway": "192.168.3.1", "gateway_mac": "a4:2b:8c:11:22:33"}}),
        encoding="utf-8")
    mlog = tmp_path / "metrics.jsonl"
    mlog.write_text(
        json.dumps({"ts": 1.0, "net": _LEGACY}) + "\n"
        + json.dumps({"ts": 2.0, "net": _QUESTION}) + "\n", encoding="utf-8")
    monkeypatch.setattr(metrics_store, "METRICS_LOG", mlog)
    monkeypatch.setattr(health, "WATCHDOG_STATUS_LOG", tmp_path / "absent.jsonl")

    diag_netprobe.migrate_net_labels("Дома")

    nets = [json.loads(line)["net"] for line
            in mlog.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert nets == ["Дома", "Дома"], f"обе legacy-метки обязаны мигрировать: {nets}"


def test_learn_net_warns_counting_both_labels(monkeypatch, tmp_path, capsys):
    """observe-счёт learn_net тоже обязан считать обе метки (?-вариант не невидимка)."""
    _learn_mocks(monkeypatch, tmp_path)
    mlog = tmp_path / "metrics.jsonl"
    mlog.write_text(
        json.dumps({"ts": time.time(), "net": _LEGACY}) + "\n"
        + json.dumps({"ts": time.time(), "net": _QUESTION}) + "\n", encoding="utf-8")
    monkeypatch.setattr(metrics_store, "METRICS_LOG", mlog)
    monkeypatch.setattr(health, "WATCHDOG_STATUS_LOG", tmp_path / "absent.jsonl")

    diag_netprobe.learn_net("Дома")

    out = capsys.readouterr().out
    assert "2 событий" in out and _LEGACY in out and _QUESTION in out, out


def test_migrate_explicit_from_label_renames_history_under_old_name(monkeypatch, tmp_path):
    """Переобучение под новым именем оставляет историю под старым ИМЕНЕМ — её derived-метки
    уже не достают: CLI `netname-migrate <новое> <старое>` мигрирует явный источник
    (канон more-options-better)."""
    _learn_mocks(monkeypatch, tmp_path)
    (tmp_path / "nets.json").write_text(json.dumps(
        {"Home5G": {"gateway": "192.168.3.1", "gateway_mac": "a4:2b:8c:11:22:33"}}),
        encoding="utf-8")
    mlog = tmp_path / "metrics.jsonl"
    mlog.write_text(json.dumps({"ts": 1.0, "net": "Дома"}) + "\n", encoding="utf-8")
    monkeypatch.setattr(metrics_store, "METRICS_LOG", mlog)
    monkeypatch.setattr(health, "WATCHDOG_STATUS_LOG", tmp_path / "absent.jsonl")

    diag_netprobe.migrate_net_labels("Home5G", from_label="Дома")

    first = json.loads(mlog.read_text(encoding="utf-8").splitlines()[0])
    assert first["net"] == "Home5G", "история под старым именем обязана мигрировать"


def test_migrate_and_count_cover_marks_and_netprobe_logs(monkeypatch, tmp_path):
    """net-метку пишут ЧЕТЫРЕ журнала (metrics, status, marks `srouter mark`,
    netprobe probe()) — счёт и миграция обязаны покрывать все, иначе ручные отметки
    и кампания остаются под gw-меткой."""
    _learn_mocks(monkeypatch, tmp_path)
    (tmp_path / "nets.json").write_text(json.dumps(
        {"Дома": {"gateway": "192.168.3.1", "gateway_mac": "a4:2b:8c:11:22:33"}}),
        encoding="utf-8")
    mlog = tmp_path / "metrics.jsonl"
    klog = tmp_path / "marks.jsonl"
    plog = tmp_path / "netprobe.jsonl"
    line = json.dumps({"ts": time.time(), "net": _LEGACY}) + "\n"
    for path in (mlog, klog, plog):
        path.write_text(line, encoding="utf-8")
    monkeypatch.setattr(metrics_store, "METRICS_LOG", mlog)
    monkeypatch.setattr(metrics_store, "MARKS_LOG", klog)
    monkeypatch.setattr(diag_netprobe, "NETPROBE_LOG", plog)
    monkeypatch.setattr(health, "WATCHDOG_STATUS_LOG", tmp_path / "absent.jsonl")

    assert diag_netprobe.count_events_under_label(_LEGACY) == 3, "счёт по всем журналам"

    diag_netprobe.migrate_net_labels("Дома")
    for path in (mlog, klog, plog):
        got = json.loads(path.read_text(encoding="utf-8").splitlines()[0])["net"]
        assert got == "Дома", f"{path.name}: метка обязана мигрировать, есть {got!r}"


def test_rewrite_tolerates_undecodable_bytes(tmp_path):
    """Оборванная мультибайт-запись → UnicodeDecodeError (ValueError, НЕ OSError):
    без ловли миграция падает целиком вопреки контракту «Не бросает»."""
    mlog = tmp_path / "metrics.jsonl"
    mlog.write_bytes(b"\xff\xfe broken utf-8 \xff\n")
    changed, backup, err = diag_netprobe._rewrite_net_labels(
        mlog, _LEGACY, "Дома", "stamp")
    assert changed == 0 and backup is None
    assert err, "файл не тронут, ошибка сообщена"


def test_rewrite_missing_file_is_quiet_noop(tmp_path):
    """Отсутствующий журнал — норма (свежая машина/ротация), а не ошибка:
    тихий no-op, как у count-пути."""
    changed, backup, err = diag_netprobe._rewrite_net_labels(
        tmp_path / "absent.jsonl", _LEGACY, "Дома", "stamp")
    assert (changed, backup, err) == (0, None, None)


def test_learn_net_hint_quotes_name_with_space(monkeypatch, tmp_path, capsys):
    """Имя с пробелом в подсказке обязано быть в кавычках — иначе напечатанная
    команда нерабочая (migrate получит «Home»)."""
    _learn_mocks(monkeypatch, tmp_path)
    mlog = tmp_path / "metrics.jsonl"
    mlog.write_text(json.dumps({"ts": time.time(), "net": _LEGACY}) + "\n", encoding="utf-8")
    monkeypatch.setattr(metrics_store, "METRICS_LOG", mlog)
    monkeypatch.setattr(health, "WATCHDOG_STATUS_LOG", tmp_path / "absent.jsonl")

    diag_netprobe.learn_net("Home 5G")

    out = capsys.readouterr().out
    assert "netname-migrate 'Home 5G'" in out, out


def test_cli_migrate_accepts_from_label(tmp_path):
    """CLI `netname-migrate <имя> [from]`: второй аргумент доходит до migrate
    (переобученная сеть: история под старым именем). Запуск в изолированном HOME."""
    import os
    import subprocess
    import sys
    logs = tmp_path / "Library" / "Logs"
    logs.mkdir(parents=True)
    (logs / "srouter-netprobe-networks.json").write_text(json.dumps(
        {"Home5G": {"gateway": "192.168.3.1", "gateway_mac": "a4:2b:8c:11:22:33"}}),
        encoding="utf-8")
    (logs / "srouter-netprobe.jsonl").write_text(
        json.dumps({"ts": 1.0, "net": "Дома"}) + "\n", encoding="utf-8")
    repo = Path(__file__).resolve().parent.parent
    env = dict(os.environ, HOME=str(tmp_path), SROUTER_LOG_DIR=str(logs))
    r = subprocess.run([sys.executable, str(repo / "diag_netprobe.py"),
                        "netname-migrate", "Home5G", "Дома"],
                       capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "1 событий" in r.stdout, r.stdout
    got = json.loads((logs / "srouter-netprobe.jsonl").read_text(encoding="utf-8")
                     .splitlines()[0])["net"]
    assert got == "Home5G"
