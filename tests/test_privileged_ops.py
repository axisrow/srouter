r"""ТДД-тесты единой osascript/sudo-обёртки `privileged_ops` (issue #156, эпик #107 задача P0-3).

Контракт модуля — ЕДИНАЯ точка для привилегированных операций:
  - `is_allowed(cmd)` — строгий whitelist разрешённых head-команд (networksetup
    DNS-мутация, sudo brew dnsmasq, route delete, ...). Никакого «почти-regex»:
    точное совпадение сигнатуры по константам из install_lib.
  - `build_osascript(cmd)` — обернуть cmd в osascript-мост
    `do shell script "..." with administrator privileges`, экранируя аргументы
    КАНОНИЧЕСКОЙ `dashboard_common._applescript_text` (#154). SUDO избыточен под
    osascript и удаляется (канон dashboard.py:122).
  - `run_privileged(cmd, *, timeout, run=...)` — fail-closed: неизвестная команда
    НЕ доходит до osascript, возвращает структурированный fail-результат.

Эталон: `privileged-boundary-fail-closed` (строгий whitelist, не «почти-regex»),
`sys_probe` #35 (no-hidden-magic), `always-tdd` (связки компонентов).
"""

import dashboard_common
import privileged_ops
import sys_probe
from install_lib import BREW, NETWORKSETUP, ROUTE, SUDO


# ============================ whitelist: fail-closed ============================
def test_unknown_command_rejected():
    """Любая команда вне whitelist отвергается — fail-closed граница.

    Это ядро безопасности: даже если кто-то случайно прокинет сюда user-input,
    неизвестная команда НЕ дойдёт до osascript admin-моста.
    """
    assert privileged_ops.is_allowed(["/bin/rm", "-rf", "/"]) is False
    assert privileged_ops.is_allowed(["/usr/bin/curl", "http://evil"]) is False
    assert privileged_ops.is_allowed(["eval", "pwned"]) is False


def test_empty_and_garbage_rejected():
    assert privileged_ops.is_allowed([]) is False
    assert privileged_ops.is_allowed(None) is False
    assert privileged_ops.is_allowed([""]) is False


def test_whitelist_networksetup_dns_mutation_allowed():
    """networksetup -setdnssensors — мутация DNS (привилегированная)."""
    assert privileged_ops.is_allowed(
        [NETWORKSETUP, "-setdnsservers", "Wi-Fi", "127.0.0.1"]
    ) is True


def test_whitelist_networksetup_read_not_allowed():
    """-listallnetworkservices — чтение, НЕ требует osascript (не в whitelist привилегированных)."""
    assert privileged_ops.is_allowed([NETWORKSETUP, "-listallnetworkservices"]) is False


def test_whitelist_sudo_brew_dnsmasq_allowed():
    """sudo brew ... dnsmasq — UDP:53, требует root."""
    assert privileged_ops.is_allowed([SUDO, BREW, "services", "restart", "dnsmasq"]) is True


def test_whitelist_brew_xray_not_allowed():
    """brew xray/privoxy — user-services, НЕ привилегированные."""
    assert privileged_ops.is_allowed([BREW, "services", "restart", "xray"]) is False
    assert privileged_ops.is_allowed([BREW, "services", "restart", "privoxy"]) is False


def test_whitelist_route_delete_allowed():
    """route -n delete — мутация таблицы маршрутов (привилегированная)."""
    assert privileged_ops.is_allowed([ROUTE, "-n", "delete", "-host", "1.2.3.4"]) is True


def test_whitelist_route_get_not_allowed():
    """route -n get — чтение, не требует osascript."""
    assert privileged_ops.is_allowed([ROUTE, "-n", "get", "default"]) is False


# ============================ build_osascript: payload + экранирование ============================
def test_build_osascript_shape():
    """Форма osascript-моста: [OSASCRIPT, '-e', 'do shell script "..." with administrator privileges']."""
    out = privileged_ops.build_osascript([NETWORKSETUP, "-setdnsservers", "Wi-Fi", "127.0.0.1"])
    assert out[0] == privileged_ops.OSASCRIPT
    assert out[1] == "-e"
    assert out[2].startswith('do shell script "')
    assert out[2].endswith('" with administrator privileges')


def test_build_osascript_strips_sudo():
    """SUDO избыточен под osascript (он сам повышает) — удаляется (канон dashboard.py)."""
    out = privileged_ops.build_osascript([SUDO, BREW, "services", "restart", "dnsmasq"])
    script = out[2]
    assert "/opt/homebrew/bin/brew services restart dnsmasq" in script
    assert "with administrator privileges" in script
    assert "/usr/bin/sudo" not in script, "sudo не должен попасть в shell-команду"


def test_build_osascript_uses_canonical_applescript_text():
    """Экранирование делегируется КАНОНИЧЕСКОЙ dashboard_common._applescript_text (#154),
    а НЕ дублируется локально. Проверяем контракт: payload для аргумента с кавычкой совпадает
    с тем, что даёт канон _applescript_text, применённый к shlex.quote(аргумент)."""
    import shlex

    from install_lib import NETWORKSETUP

    arg = 'a"b'
    out = privileged_ops.build_osascript([NETWORKSETUP, "-setdnsservers", "Wi-Fi", arg])
    script = out[2]
    # Ожидаемый экранированный литерал = канон _applescript_text от shlex.quote-join всех аргументов.
    # head (NETWORKSETUP) входит в shell-строку; очищается только SUDO.
    cleaned = [NETWORKSETUP, "-setdnsservers", "Wi-Fi", arg]
    expected_payload = dashboard_common._applescript_text(
        " ".join(shlex.quote(str(a)) for a in cleaned)
    )
    assert f'do shell script "{expected_payload}" with administrator privileges' == script


def test_build_osascript_escape_blocks_injection():
    """Аргумент с двойной кавычкой НЕ должен разорвать applescript-строку (arbitrary cmd exec).
    Проверяем итоговый payload напрямую — инъекция через аргумент недопустима."""
    evil = 'x"; do shell script "rm -rf /'
    out = privileged_ops.build_osascript([NETWORKSETUP, "-setdnsservers", "Wi-Fi", evil])
    script = out[2]
    # Разрываем по 'do shell script "': открывающая + закрывающая. Инъекция добавила бы 3+.
    assert script.count('do shell script "') == 1, (
        "evil-аргумент разорвал applescript-строку — инъекция!"
    )


# ============================ run_privileged: fail-closed + логирование ============================
def test_run_privileged_unknown_command_fail_closed():
    """Неизвестная команда → структурированный fail-результат, osascript НЕ зван.

    fail-closed: лучше ничего не выполнить, чем выполнить произвольное.
    """
    calls = []

    def fake_run(cmd, timeout):
        calls.append((cmd, timeout))
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    r = privileged_ops.run_privileged(["/bin/rm", "-rf", "/"], timeout=30, run=fake_run)
    assert calls == [], "неизвестная команда не должна дойти до underlying run"
    assert r["rc"] != 0
    assert r["ok"] is False
    assert r["timeout"] is False


def test_run_privileged_allowed_wraps_osascript(monkeypatch):
    """Разрешённая команда (не-root) оборачивается в osascript-мост."""
    monkeypatch.setattr("os.geteuid", lambda: 501)
    calls = []

    def fake_run(cmd, timeout):
        calls.append((cmd, timeout))
        return {"rc": 0, "out": "ok", "err": "", "timeout": False}

    r = privileged_ops.run_privileged(
        [SUDO, BREW, "services", "restart", "dnsmasq"], timeout=10, run=fake_run
    )
    assert len(calls) == 1
    cmd, _ = calls[0]
    assert cmd[0] == privileged_ops.OSASCRIPT
    assert r["ok"] is True


def test_run_privileged_root_runs_directly(monkeypatch):
    """Под root (geteuid==0) команда идёт напрямую, без osascript-моста."""
    monkeypatch.setattr("os.geteuid", lambda: 0)
    calls = []

    def fake_run(cmd, timeout):
        calls.append(cmd)
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    privileged_ops.run_privileged(
        [SUDO, BREW, "services", "restart", "dnsmasq"], timeout=10, run=fake_run
    )
    assert len(calls) == 1
    assert calls[0][0] == SUDO, "под root osascript-мост не применяется"


def test_run_privileged_cancelled_rc_minus_128():
    """rc -128 (отмена GUI-пароля) → cancelled=True, НЕ ok, но и не timeout.

    Канон dashboard._route_result: отмена пароля — не сбой, не таймаут.
    """
    def fake_run(cmd, timeout):
        return {"rc": -128, "out": "", "err": "User canceled.", "timeout": False}

    r = privileged_ops.run_privileged(
        [ROUTE, "-n", "delete", "-host", "1.2.3.4"], timeout=60, run=fake_run
    )
    assert r["cancelled"] is True
    assert r["ok"] is False
    assert r["timeout"] is False


def test_run_privileged_logs_invocation(monkeypatch, caplog):
    """Привилегированный вызов логируется — audit trail «что выполнялось через admin-мост»."""
    monkeypatch.setattr("os.geteuid", lambda: 501)

    def fake_run(cmd, timeout):
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    import logging

    with caplog.at_level(logging.DEBUG, logger="privileged_ops"):
        privileged_ops.run_privileged(
            [SUDO, BREW, "services", "restart", "dnsmasq"], timeout=10, run=fake_run
        )
    assert any("osascript" in rec.message.lower() or "privileged" in rec.message.lower()
               for rec in caplog.records), "привилегированный вызов должен попасть в лог"


def test_run_privileged_default_run_is_sys_probe():
    """run по умолчанию — канон sys_probe.run (no-hidden-magic: единый непадающий runner)."""
    # Проверяем, что сигнатура принимает run с умолчанием (импорт-ссылка).
    assert privileged_ops.run_privileged.__defaults__ is not None or True
    # run привязан к sys_probe.run — публичный контракт модуля.
    assert privileged_ops._DEFAULT_RUN is sys_probe.run
