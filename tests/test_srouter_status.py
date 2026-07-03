"""Тесты srouter.cmd_status: разбор `launchctl list` и три состояния демона.

Формат вывода launchctl list: «PID  ExitCode  Label» (3 колонки). Служба опознаётся по
последней колонке. Состояния: работает (PID=число) / крашнулся (PID='-', exit≠0) /
не загружен (метки нет в выводе).
"""
import srouter

LAUNCHCTL_LIST_RUNNING = "12345\t0\tcom.srouter.dashboard\n"
LAUNCHCTL_LIST_CRASHED = "-\t1\tcom.srouter.dashboard\n"
LAUNCHCTL_LIST_OTHER = "999\t0\tcom.other.service\n-  \t0\tcom.apple.something\n"


def _run_returning(out: str):
    """Фейк sys_probe.run, возвращающий заданный stdout launchctl list."""
    return lambda cmd, timeout: {"rc": 0, "out": out, "err": "", "timeout": False}


def test_status_running(monkeypatch, capsys):
    monkeypatch.setattr(srouter, "run", _run_returning(LAUNCHCTL_LIST_RUNNING))
    rc = srouter.cmd_status(argparse_ns())
    out = capsys.readouterr().out
    assert rc == 0
    assert "загружен и работает" in out
    assert "PID=12345" in out


def test_status_crashed(monkeypatch, capsys):
    monkeypatch.setattr(srouter, "run", _run_returning(LAUNCHCTL_LIST_CRASHED))
    rc = srouter.cmd_status(argparse_ns())
    err = capsys.readouterr().err
    assert rc == 1
    assert "крашнулся" in err
    assert "exit code=1" in err
    assert "srouter restart" in err


def test_status_not_loaded(monkeypatch, capsys):
    # launchctl list не содержит нашу метку вообще.
    monkeypatch.setattr(srouter, "run", _run_returning(LAUNCHCTL_LIST_OTHER))
    rc = srouter.cmd_status(argparse_ns())
    out = capsys.readouterr().out
    assert rc == 1
    assert "НЕ загружен" in out


def argparse_ns():
    """Пустой args-объект, как у argparse для подкоманды status (флагов нет)."""
    class _NS:
        pass
    return _NS()
