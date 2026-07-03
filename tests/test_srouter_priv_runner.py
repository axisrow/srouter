"""Тесты привилегированного runner в srouter: классификация команд и osascript-мост.

install_lib вызывает runner(cmd, timeout) универсально — он не знает про osascript. Поэтому
обёртка make_privileged_runner детектит привилегированные команды по сигнатуре cmd и решает:
под root / непривилегированная → напрямую; иначе → osascript-мост с GUI-паролем.
"""
import os
import sys

import srouter
from install_lib import BREW, NETWORKSETUP, ROUTE, SUDO


def _cases():
    return [
        # (cmd, is_privileged, описание)
        ([NETWORKSETUP, "-setdnsservers", "Wi-Fi", "127.0.0.1"], True, "DNS mutation"),
        ([NETWORKSETUP, "-listallnetworkservices"], False, "list services (read)"),
        ([SUDO, BREW, "services", "restart", "dnsmasq"], True, "sudo brew dnsmasq (port 53)"),
        ([BREW, "services", "restart", "xray"], False, "brew xray (user service)"),
        ([BREW, "services", "restart", "privoxy"], False, "brew privoxy (user service)"),
        ([BREW, "install", "privoxy"], False, "brew install"),
        ([BREW, "list", "--versions", "xray"], False, "brew list (read)"),
        ([ROUTE, "-n", "delete", "-host", "1.2.3.4"], True, "route delete"),
        ([ROUTE, "-n", "get", "default"], False, "route get (read)"),
        ([], False, "empty cmd"),
    ]


def test_is_privileged_cmd_classification():
    for cmd, expected, desc in _cases():
        got = srouter._is_privileged_cmd(cmd)
        assert got == expected, f"{desc}: {cmd} → {got}, expected {expected}"


def test_to_osascript_strips_sudo():
    """SUDO избыточен под osascript (он сам повышает) — должен быть очищен (канон dashboard:122)."""
    out = srouter._to_osascript([SUDO, BREW, "services", "restart", "dnsmasq"])
    assert out[0] == srouter.OSASCRIPT
    assert out[1] == "-e"
    script = out[2]
    assert "with administrator privileges" in script
    assert "/opt/homebrew/bin/brew services restart dnsmasq" in script
    # Ключевое: НЕТ ведущего sudo внутри shell-команды.
    assert 'do shell script "/usr/bin/sudo' not in script


def test_to_osascript_preserves_non_sudo_cmd():
    """Команда без SUDO не теряет первый аргумент."""
    out = srouter._to_osascript([NETWORKSETUP, "-setdnsservers", "Wi-Fi", "127.0.0.1"])
    script = out[2]
    assert "/usr/sbin/networksetup -setdnsservers" in script
    assert "with administrator privileges" in script


def test_runner_as_root_passes_all_directly(monkeypatch):
    """Под root (geteuid==0) даже привилегированные команды идут напрямую, без osascript."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    seen = []

    def fake_run(cmd, timeout):
        seen.append(cmd)
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    runner = srouter.make_privileged_runner(fake_run)
    priv = [SUDO, BREW, "services", "restart", "dnsmasq"]
    runner(priv, 10)
    assert seen == [priv], "под root osascript-мост не должен применяться"


def test_runner_non_root_wraps_privileged(monkeypatch):
    """Не-root: привилегированная команда оборачивается в osascript."""
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    seen = []

    def fake_run(cmd, timeout):
        seen.append(cmd)
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    runner = srouter.make_privileged_runner(fake_run)
    runner([SUDO, BREW, "services", "restart", "dnsmasq"], 10)
    assert len(seen) == 1
    assert seen[0][0] == srouter.OSASCRIPT, "не-root привилегированная → osascript"


def test_runner_non_root_passes_unprivileged_directly(monkeypatch):
    """Не-root: непривилегированная команда (brew xray) идёт напрямую, без моста."""
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    seen = []

    def fake_run(cmd, timeout):
        seen.append(cmd)
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    runner = srouter.make_privileged_runner(fake_run)
    cmd = [BREW, "services", "restart", "xray"]
    runner(cmd, 10)
    assert seen == [cmd], "непривилегированная → напрямую даже не-root"


def test_runner_uses_osascript_timeout(monkeypatch):
    """osascript-вызовы используют увеличенный timeout (ввод пароля в GUI)."""
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    seen_timeouts = []

    def fake_run(cmd, timeout):
        seen_timeouts.append(timeout)
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    runner = srouter.make_privileged_runner(fake_run, osascript_timeout=99)
    runner([SUDO, BREW, "services", "restart", "dnsmasq"], 5)
    assert seen_timeouts == [99]


# ============================ --python flag (sudo path) ============================
class _Args:
    """Минимальный args-объект для _env_from_args (как argparse отдаёт)."""
    def __init__(self, **kwargs):
        self.state = None
        self.prefix = None
        self.launchagents_dir = None
        self.python = None
        for k, v in kwargs.items():
            setattr(self, k, v)


def test_env_from_args_python_flag_overrides(monkeypatch):
    """--python /custom/python3 → env.python_bin == /custom/python3 (для sudo-пути).

    sudo srouter install --python $(which python3) — правильный Python в plist'ах.
    """
    import srouter
    monkeypatch.delenv("SROUTER_PYTHON", raising=False)
    args = _Args(python="/custom/python3")
    env = srouter._env_from_args(args)
    assert env.python_bin == "/custom/python3"


def test_env_from_args_srouter_python_env_fallback(monkeypatch):
    """Без --python, но SROUTER_PYTHON env задан → env.python_bin из env."""
    import srouter
    monkeypatch.setenv("SROUTER_PYTHON", "/env/python3")
    args = _Args(python=None)
    env = srouter._env_from_args(args)
    assert env.python_bin == "/env/python3"


def test_env_from_args_sys_executable_default(monkeypatch):
    """Без --python и SROUTER_PYTHON → sys.executable (текущий Python)."""
    import srouter
    monkeypatch.delenv("SROUTER_PYTHON", raising=False)
    args = _Args(python=None)
    env = srouter._env_from_args(args)
    assert env.python_bin == sys.executable
