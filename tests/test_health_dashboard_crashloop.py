"""Doctor видит crash-loop демона (инцидент 2026-10-08): порт 8787 мёртв + err.log
с ModuleNotFoundError → диагноз с ремонтом (SROUTER_PYTHON), а не немой ❌.

Канон: шумный лог лучше отсутствия лога; детект по сигнатуре err.log — при другой
причине чек остаётся прежним (без detail), поведение не расходится с текущим.
"""
import health


def test_dashboard_check_down_flask_crashloop_gives_repair(monkeypatch, tmp_path):
    err_log = tmp_path / "err.log"
    err_log.write_text(
        "Traceback (most recent call last):\n"
        '  File "dashboard.py", line 19, in <module>\n'
        "ModuleNotFoundError: No module named 'flask'\n",
        encoding="utf-8")
    monkeypatch.setattr(health, "DASHBOARD_ERR_LOG", err_log)
    monkeypatch.setattr(health, "_port_up", lambda port: False)
    chk = health._dashboard_check()
    assert chk["ok"] is False
    assert "flask" in chk["detail"]
    assert "SROUTER_PYTHON" in chk["detail"]


def test_dashboard_check_ok_has_no_detail(monkeypatch):
    monkeypatch.setattr(health, "_port_up", lambda port: True)
    chk = health._dashboard_check()
    assert chk["ok"] is True
    assert "detail" not in chk


def test_dashboard_check_down_other_cause_stays_muted(monkeypatch, tmp_path):
    err_log = tmp_path / "err.log"
    err_log.write_text("случайный шум без сигнатуры\n", encoding="utf-8")
    monkeypatch.setattr(health, "DASHBOARD_ERR_LOG", err_log)
    monkeypatch.setattr(health, "_port_up", lambda port: False)
    chk = health._dashboard_check()
    assert chk["ok"] is False
    assert "detail" not in chk


def test_dashboard_check_down_missing_log_stays_muted(monkeypatch, tmp_path):
    monkeypatch.setattr(health, "DASHBOARD_ERR_LOG",
                        tmp_path / "absent.err.log")
    monkeypatch.setattr(health, "_port_up", lambda port: False)
    chk = health._dashboard_check()
    assert chk["ok"] is False
    assert "detail" not in chk
