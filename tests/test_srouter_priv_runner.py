"""Тесты привилегированного runner в srouter: классификация команд и osascript-мост.

install_lib вызывает runner(cmd, timeout) универсально — он не знает про osascript. Поэтому
обёртка make_privileged_runner детектит привилегированные команды по сигнатуре cmd и решает:
под root / непривилегированная → напрямую; иначе → osascript-мост с GUI-паролем.
"""
import os

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
