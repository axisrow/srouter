"""#445: keeper watchdog'а — пуш при потере heartbeat + liveness-чеки в check_all.

Инцидент 02.11: «watchdog умер тихо» — по факту misdiagnosis (метрики писались весь день),
но дыра реальна: при ПОСТОЯННОЙ смерти watchdog'а (битый деплой в главный чекаут — он и
есть live-путь, апгрейд python, unload) никто не узнает. Keeper = второй launchd-cron
(300с), читает heartbeat (mtime WATCHDOG_STATE) и launchd-снапшот, пушит «Упало: watchdog»
по канону пар «Упало/Восстановлено» (#315/#380): recovery только после прозвучавшего down,
cooldown против флапа, sleep-guard (машина спала — keeper тоже не тикал → не доказано).

Каноны: detector-must-be-function (верdict — чистая функция с инъекцией now/параметров,
wall-clock-assert-is-not-the-invariant — ни одного sleep), mock-format-from-live-capture
(snapshot-словарь той же формы, что _launchd_job_snapshot), unmocked-probe-... (в тестах
нет ни launchctl, ни osascript — все IO мокаются).
"""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import health


def _snap(loaded=True, runs=100):
    """Snapshot той же формы, что _launchd_job_snapshot (живой формат)."""
    return {"label": health.WATCHDOG_LABEL, "domain": "gui/501", "loaded": loaded,
            "state": "running" if loaded else None, "pid": 4242 if loaded else None,
            "runs": runs if loaded else None,
            "last_exit_code": "1" if loaded else None,
            "last_terminating_signal": None,
            "plist": {"exists": True, "mtime_ns": 1, "inode": 2}, "error": ""}


def _prev(**kw):
    base = {"prev_run_ts": 1000.0, "prev_runs": 100, "down_notified": False,
            "last_down_push": 0.0}
    base.update(kw)
    return base


V = dict(stale_sec=300, grace_sec=120, cooldown_sec=900)


# ============================ _watchdog_keeper_verdict ============================

def test_verdict_alive_fresh_heartbeat_silent():
    v = health._watchdog_keeper_verdict(
        now=1100.0, heartbeat_mtime=1095.0, snapshot=_snap(), prev=_prev(), **V)
    assert v["action"] == "alive"
    assert v["msg"] is None
    assert v["down_notified"] is False


def test_verdict_recovery_after_notified_down():
    v = health._watchdog_keeper_verdict(
        now=1100.0, heartbeat_mtime=1098.0, snapshot=_snap(),
        prev=_prev(down_notified=True, last_down_push=1000.0), **V)
    assert v["action"] == "alive"
    assert v["msg"] == "Восстановлено: watchdog"
    assert v["sound"] == "Glass"
    assert v["down_notified"] is False


def test_verdict_baseline_first_run_silent():
    """Первый прогон keeper'а (prev пуст — /tmp после ребута) — тихий baseline."""
    v = health._watchdog_keeper_verdict(
        now=1100.0, heartbeat_mtime=700.0, snapshot=_snap(), prev={}, **V)
    assert v["action"] == "baseline"
    assert v["msg"] is None


def test_verdict_wait_sleep_catchup():
    """Машина спала: keeper не тикал час, heartbeat той же давности — смерть не доказана."""
    v = health._watchdog_keeper_verdict(
        now=4600.0, heartbeat_mtime=1100.0, snapshot=_snap(),
        prev=_prev(prev_run_ts=1000.0), **V)
    assert v["action"] == "wait"
    assert v["msg"] is None


def test_verdict_down_unloaded():
    v = health._watchdog_keeper_verdict(
        now=5000.0, heartbeat_mtime=1000.0, snapshot=_snap(loaded=False),
        prev=_prev(prev_run_ts=4500.0), **V)
    assert v["action"] == "down"
    assert "не загружена" in v["msg"]
    assert v["down_notified"] is True
    assert v["last_down_push"] == 5000.0


def test_verdict_down_crash_loop():
    """Тики идут (runs вырос), heartbeat не пишется — crash-loop импорта (инцидент 14:01,
    если бы окно merge не закрылось)."""
    v = health._watchdog_keeper_verdict(
        now=5000.0, heartbeat_mtime=1000.0, snapshot=_snap(runs=130),
        prev=_prev(prev_run_ts=4500.0, prev_runs=125), **V)
    assert v["action"] == "down"
    assert "crash-loop" in v["msg"]


def test_verdict_down_no_ticks():
    """Джоба загружена, тиков нет (runs заморожен) — launchd не респавнит / прогон завис."""
    v = health._watchdog_keeper_verdict(
        now=5000.0, heartbeat_mtime=1000.0, snapshot=_snap(runs=125),
        prev=_prev(prev_run_ts=4500.0, prev_runs=125), **V)
    assert v["action"] == "down"
    assert "тиков нет" in v["msg"]


def test_verdict_down_cooldown_suppresses_repeat():
    """Повторное «Упало» в окне cooldown молчит, down_notified сохраняется (канон #380 P2:
    подавленный пуш не сбрасывает флаг эпизода — recovery донесёт)."""
    v = health._watchdog_keeper_verdict(
        now=5000.0, heartbeat_mtime=1000.0, snapshot=_snap(runs=125),
        prev=_prev(prev_run_ts=4500.0, down_notified=True, last_down_push=4900.0), **V)
    assert v["action"] == "down-suppressed"
    assert v["msg"] is None
    assert v["down_notified"] is True


def test_verdict_down_push_after_cooldown():
    v = health._watchdog_keeper_verdict(
        now=6000.0, heartbeat_mtime=1000.0, snapshot=_snap(runs=125),
        prev=_prev(prev_run_ts=5500.0, down_notified=True, last_down_push=4900.0), **V)
    assert v["action"] == "down"
    assert "Упало: watchdog" in v["msg"]
    assert v["down_notified"] is True
    assert v["last_down_push"] == 6000.0


# ============================ cmd_watchdog_keeper ============================

def _mock_keeper_world(monkeypatch, tmp_path, *, snapshot, notify_log):
    monkeypatch.setattr(health, "WATCHDOG_STATE", tmp_path / "hb.json")
    monkeypatch.setattr(health, "WATCHDOG_KEEPER_STATE", tmp_path / "keeper.json")
    monkeypatch.setattr(health, "WATCHDOG_PLIST", tmp_path / "wd.plist")
    monkeypatch.setattr(health, "WATCHDOG_KEEPER_PLIST", tmp_path / "keeper.plist")
    monkeypatch.setattr(health, "_launchd_job_snapshot", lambda *a, **k: snapshot)
    pushes = []
    monkeypatch.setattr(health, "_notify", lambda msg, sound="Glass": pushes.append((msg, sound)))
    return pushes


def test_cmd_keeper_noop_without_watchdog_plist(monkeypatch, tmp_path):
    """Keeper без установленного watchdog'а — no-op (машина без watchdog'а не объект
    мониторинга, иначе вечный пуш каждые 15 мин)."""
    pushes = _mock_keeper_world(monkeypatch, tmp_path, snapshot=_snap(loaded=False),
                                notify_log=None)
    rc = health.cmd_watchdog_keeper()
    assert rc == 0
    assert pushes == []
    assert not (tmp_path / "keeper.json").exists()


def test_cmd_keeper_down_flow_writes_state(monkeypatch, tmp_path):
    hb = tmp_path / "hb.json"
    hb.write_text("{}", encoding="utf-8")
    os.utime(hb, (1000.0, 1000.0))
    # prev свежий (keeper тикал 100с назад): baseline-гвард пройден, gap=100 < grace.
    keeper_state = {"prev_run_ts": 4900.0, "prev_runs": 125, "down_notified": False,
                    "last_down_push": 0.0}
    (tmp_path / "keeper.json").write_text(json.dumps(keeper_state), encoding="utf-8")
    monkeypatch.setattr(health, "WATCHDOG_PLIST", tmp_path / "wd.plist")
    (tmp_path / "wd.plist").write_text("x", encoding="utf-8")  # watchdog установлен
    monkeypatch.setattr(health, "WATCHDOG_KEEPER_PLIST", tmp_path / "keeper.plist")
    (tmp_path / "keeper.plist").write_text("x", encoding="utf-8")
    monkeypatch.setattr(health, "WATCHDOG_STATE", hb)
    monkeypatch.setattr(health, "WATCHDOG_KEEPER_STATE", tmp_path / "keeper.json")
    monkeypatch.setattr(health, "_launchd_job_snapshot", lambda *a, **k: _snap(runs=125))
    monkeypatch.setattr(health.time, "time", lambda: 5000.0)
    pushes = []
    monkeypatch.setattr(health, "_notify", lambda msg, sound="Glass": pushes.append((msg, sound)))
    rc = health.cmd_watchdog_keeper()
    assert rc == 1
    assert len(pushes) == 1
    assert "Упало: watchdog" in pushes[0][0]
    assert pushes[0][1] == "Basso"
    state = json.loads((tmp_path / "keeper.json").read_text(encoding="utf-8"))
    assert state["down_notified"] is True
    assert state["prev_runs"] == 125


def test_cmd_keeper_recovery_push(monkeypatch, tmp_path):
    hb = tmp_path / "hb.json"
    hb.write_text("{}", encoding="utf-8")
    os.utime(hb, (4998.0, 4998.0))
    keeper_state = {"prev_run_ts": 4500.0, "prev_runs": 125, "down_notified": True,
                    "last_down_push": 4500.0}
    (tmp_path / "keeper.json").write_text(json.dumps(keeper_state), encoding="utf-8")
    monkeypatch.setattr(health, "WATCHDOG_PLIST", tmp_path / "wd.plist")
    (tmp_path / "wd.plist").write_text("x", encoding="utf-8")
    monkeypatch.setattr(health, "WATCHDOG_KEEPER_PLIST", tmp_path / "keeper.plist")
    (tmp_path / "keeper.plist").write_text("x", encoding="utf-8")
    monkeypatch.setattr(health, "WATCHDOG_STATE", hb)
    monkeypatch.setattr(health, "WATCHDOG_KEEPER_STATE", tmp_path / "keeper.json")
    monkeypatch.setattr(health, "_launchd_job_snapshot", lambda *a, **k: _snap(runs=130))
    monkeypatch.setattr(health.time, "time", lambda: 5000.0)
    pushes = []
    monkeypatch.setattr(health, "_notify", lambda msg, sound="Glass": pushes.append((msg, sound)))
    rc = health.cmd_watchdog_keeper()
    assert rc == 0
    assert pushes == [("Восстановлено: watchdog", "Glass")]
    state = json.loads((tmp_path / "keeper.json").read_text(encoding="utf-8"))
    assert state["down_notified"] is False


# ============================ liveness-чеки в check_all ============================

def test_liveness_info_when_plist_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(health, "WATCHDOG_STATE", tmp_path / "hb.json")
    monkeypatch.setattr(health, "WATCHDOG_PLIST", tmp_path / "absent.plist")
    chk = health._watchdog_liveness_check()
    assert chk["ok"] is True and chk.get("info") is True
    assert "не установлен" in chk["detail"]


def test_liveness_ok_fresh_heartbeat(monkeypatch, tmp_path):
    hb = tmp_path / "hb.json"
    hb.write_text("{}", encoding="utf-8")
    os.utime(hb, (9995.0, 9995.0))
    monkeypatch.setattr(health, "WATCHDOG_STATE", hb)
    monkeypatch.setattr(health, "WATCHDOG_PLIST", tmp_path / "wd.plist")
    (tmp_path / "wd.plist").write_text("x", encoding="utf-8")
    monkeypatch.setattr(health.time, "time", lambda: 10000.0)
    chk = health._watchdog_liveness_check()
    assert chk["ok"] is True and chk.get("info") is True
    assert chk["id"] == "watchdog"


def test_liveness_driver_down_stale_heartbeat(monkeypatch, tmp_path):
    hb = tmp_path / "hb.json"
    hb.write_text("{}", encoding="utf-8")
    os.utime(hb, (1000.0, 1000.0))
    monkeypatch.setattr(health, "WATCHDOG_STATE", hb)
    monkeypatch.setattr(health, "WATCHDOG_PLIST", tmp_path / "wd.plist")
    (tmp_path / "wd.plist").write_text("x", encoding="utf-8")
    monkeypatch.setattr(health.time, "time", lambda: 10000.0)
    chk = health._watchdog_liveness_check()
    assert chk["ok"] is False
    assert "info" not in chk  # driver — роняет вердикт (критичная 24/7 инфраструктура)
    assert "не тикает" in chk["detail"]


def test_liveness_down_when_unloaded(monkeypatch, tmp_path):
    """Heartbeat-файла нет + джоба не загружена = доказанная слепота (driver)."""
    monkeypatch.setattr(health, "WATCHDOG_STATE", tmp_path / "absent-hb.json")
    monkeypatch.setattr(health, "WATCHDOG_PLIST", tmp_path / "wd.plist")
    (tmp_path / "wd.plist").write_text("x", encoding="utf-8")
    monkeypatch.setattr(health, "_launchd_job_snapshot",
                        lambda *a, **k: _snap(loaded=False))
    chk = health._watchdog_liveness_check()
    assert chk["ok"] is False and "info" not in chk
    assert "не загружена" in chk["detail"]


def test_liveness_info_when_missing_but_loaded(monkeypatch, tmp_path):
    """/tmp очищен, но джоба тикает — ложной тревоги нет (тик перепишет heartbeat ≤20с)."""
    monkeypatch.setattr(health, "WATCHDOG_STATE", tmp_path / "absent-hb.json")
    monkeypatch.setattr(health, "WATCHDOG_PLIST", tmp_path / "wd.plist")
    (tmp_path / "wd.plist").write_text("x", encoding="utf-8")
    monkeypatch.setattr(health, "_launchd_job_snapshot",
                        lambda *a, **k: _snap(runs=125))
    chk = health._watchdog_liveness_check()
    assert chk["ok"] is True and chk.get("info") is True


def test_keeper_liveness_info_absent_plist(monkeypatch, tmp_path):
    monkeypatch.setattr(health, "WATCHDOG_STATE", tmp_path / "absent-hb.json")
    monkeypatch.setattr(health, "WATCHDOG_KEEPER_PLIST", tmp_path / "absent.plist")
    chk = health._watchdog_keeper_liveness_check()
    assert chk["ok"] is True and chk.get("info") is True


def test_keeper_liveness_down_when_silent_while_machine_awake(monkeypatch, tmp_path):
    """Keeper молчит, а watchdog-heartbeat свежий → машина заведомо бодрая → keeper мёртв."""
    hb = tmp_path / "hb.json"
    hb.write_text("{}", encoding="utf-8")
    os.utime(hb, (9998.0, 9998.0))
    ks = tmp_path / "keeper.json"
    ks.write_text("{}", encoding="utf-8")
    os.utime(ks, (7000.0, 7000.0))
    monkeypatch.setattr(health, "WATCHDOG_STATE", hb)
    monkeypatch.setattr(health, "WATCHDOG_KEEPER_STATE", ks)
    monkeypatch.setattr(health, "WATCHDOG_KEEPER_PLIST", tmp_path / "keeper.plist")
    (tmp_path / "keeper.plist").write_text("x", encoding="utf-8")
    monkeypatch.setattr(health.time, "time", lambda: 10000.0)
    chk = health._watchdog_keeper_liveness_check()
    assert chk["ok"] is False and "info" not in chk
    assert chk["id"] == "watchdog-keeper"


def test_keeper_liveness_info_when_machine_slept(monkeypatch, tmp_path):
    """Оба heartbeat старые → машина спала, keeper не доказанно мёртв (info)."""
    hb = tmp_path / "hb.json"
    hb.write_text("{}", encoding="utf-8")
    os.utime(hb, (1000.0, 1000.0))
    ks = tmp_path / "keeper.json"
    ks.write_text("{}", encoding="utf-8")
    os.utime(ks, (1000.0, 1000.0))
    monkeypatch.setattr(health, "WATCHDOG_STATE", hb)
    monkeypatch.setattr(health, "WATCHDOG_KEEPER_STATE", ks)
    monkeypatch.setattr(health, "WATCHDOG_KEEPER_PLIST", tmp_path / "keeper.plist")
    (tmp_path / "keeper.plist").write_text("x", encoding="utf-8")
    monkeypatch.setattr(health.time, "time", lambda: 10000.0)
    chk = health._watchdog_keeper_liveness_check()
    assert chk["ok"] is True and chk.get("info") is True


def test_check_all_contains_watchdog_liveness(monkeypatch, tmp_path):
    """Чеки watchdog живы в check_all (doctor/health видят молчание журнала как симптом)."""
    monkeypatch.setattr(health, "WATCHDOG_STATE", tmp_path / "absent-hb.json")
    monkeypatch.setattr(health, "WATCHDOG_PLIST", tmp_path / "absent.plist")
    monkeypatch.setattr(health, "WATCHDOG_KEEPER_PLIST", tmp_path / "absent.plist")
    result = health.check_all()
    ids = {c.get("id") for c in result["checks"]}
    assert "watchdog" in ids
    assert "watchdog-keeper" in ids


def test_main_dispatches_watchdog_keeper(monkeypatch):
    called = []
    monkeypatch.setattr(health, "cmd_watchdog_keeper", lambda: called.append(1) or 0)
    assert health.main(["watchdog-keeper"]) == 0
    assert called == [1]


# ============================ plist-шаблон ============================

def test_keeper_plist_template_renders():
    """Рендер keeper-плиста: маркер/лейбл/путь на месте, cron-канон (StartInterval 300,
    RunAtLoad, БЕЗ KeepAlive — exit 1 на degraded дал бы tight-loop)."""
    import install_plist
    root = Path(__file__).resolve().parents[1]
    env = SimpleNamespace(root=root, python_bin="/usr/bin/python3",
                          log_out=root / "o.log", log_err=root / "e.log")
    out = install_plist._render_generic_launchagent(
        env, template_name="com.srouter.watchdog-keeper.plist",
        label="com.srouter.watchdog-keeper",
        marker="srouter-managed-watchdog-keeper-v1", script_path=root / "health.py")
    assert "__SROUTER_" not in out
    assert "com.srouter.watchdog-keeper" in out
    assert "srouter-managed-watchdog-keeper-v1" in out
    assert "<integer>300</integer>" in out
    assert "RunAtLoad" in out
    assert "<key>KeepAlive</key>" not in out
