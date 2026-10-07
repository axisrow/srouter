"""ТДД-тесты health._claude_app_proxy_check: доктор видит Claude.app мимо туннеля.

Инцидент 2026-10-07: Claude.app дважды за день перезапускался из Dock мимо wrapper'а →
webview идёт напрямую → GFW рвёт TLS → ERR_CONNECTION_CLOSED, а doctor молчал (чек был
только для ChatGPT.app). Контракт (route-evidence по lsof, канон _codex_app_proxy_check):
  ok   — маршрут через privoxy 8118 (канон плечо Claude-приложений, wrapper ~/bin/claude-app);
  warn — маршрут через SOCKS5 10808 (#127: Claude-приложения на SOCKS5 ломаются);
  down — external-сокеты (прямой egress; GFW порвёт claude.ai);
  unknown — App не запущен / lsof недоказуем / idle (fail-closed; «не запущен» не деградация #362).
"""
import health

APP_CLAUDE_COMM = "/Applications/Claude.app/Contents/MacOS/Claude"
HELPER_COMM = ("/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/"
               "Contents/MacOS/Claude Helper")


def _fake(ps_out="", lsof_out="", lsof_rc=0, lsof_timeout=False, ps_timeout=False):
    """fake_run: ps → ps_out; lsof -p <pids> → lsof_out (rc/timeout имитируют сбой)."""
    def fake_run(cmd, timeout):
        if cmd and cmd[0] == "/bin/ps":
            if ps_timeout:
                return {"rc": None, "out": "", "err": "timeout", "timeout": True}
            return {"rc": 0, "out": ps_out, "err": "", "timeout": False}
        if cmd and cmd[0] == "/usr/sbin/lsof":
            if lsof_timeout:
                return {"rc": None, "out": "", "err": "timeout", "timeout": True}
            return {"rc": lsof_rc, "out": lsof_out, "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}
    return fake_run


def _lsof_proxied(pid, dst):
    return (f"Claude {pid} axisrow 22u IPv4 0xABC 0t0 "
            f"TCP 127.0.0.1:56113->{dst} (ESTABLISHED)\n")


def test_unknown_when_not_running(monkeypatch):
    monkeypatch.setattr(health.sys_probe, "run", _fake(""))
    res = health._claude_app_proxy_check()
    assert res["status"] == "unknown", f"App не запущен → unknown (idle, #362): got {res}"
    assert "не запущен" in res["detail"].lower()


def test_ok_when_route_privoxy(monkeypatch):
    ps = f"83907 {APP_CLAUDE_COMM}\n83912 {HELPER_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run",
                        _fake(ps, _lsof_proxied("83912", "127.0.0.1:8118")))
    res = health._claude_app_proxy_check()
    assert res["status"] == "ok", f"маршрут через privoxy 8118 (канон плечо) → ok; got {res}"


def test_warn_when_route_socks(monkeypatch):
    ps = f"83907 {APP_CLAUDE_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run",
                        _fake(ps, _lsof_proxied("83907", "127.0.0.1:10808")))
    res = health._claude_app_proxy_check()
    assert res["status"] == "warn", f"SOCKS5-плечо (#127 Claude ломается) → warn; got {res}"


def test_warn_when_mixed_proxied_and_external(monkeypatch):
    """Mixed: webview через privoxy + app-internal WS (remote-tools) напрямую → warn, НЕ down.

    Живой профиль wrapper-машины: основной трафик проксирован, один net.WebSocket (игнорирует
    и env, и --proxy-server) идёт напрямую. Вечный down на рабочей через wrapper машине =
    анти-паттерн ревью #403 («вечный down на здоровой машине»); warn держит утечку видимой."""
    ps = f"83907 {APP_CLAUDE_COMM}\n83912 {HELPER_COMM}\n"
    lsof = (_lsof_proxied("83912", "127.0.0.1:8118")
            + "Claude 83907 axisrow 122u IPv4 0xABC 0t0 "
              "TCP 10.1.0.73:56201->160.79.104.10:443 (ESTABLISHED)\n")
    monkeypatch.setattr(health.sys_probe, "run", _fake(ps, lsof))
    res = health._claude_app_proxy_check()
    assert res["status"] == "warn", f"mixed прокси+external → warn; got {res}"
    assert "PF" in res["detail"] or "enforcement" in res["detail"].lower(), \
        f"detail называет системный путь лечения; got {res}"


def test_down_when_route_direct(monkeypatch):
    """Живой профиль инцидента 2026-10-07: main-процесс держит external к 160.79.104.10."""
    ps = f"83907 {APP_CLAUDE_COMM}\n"
    lsof = (f"Claude 83907 axisrow 122u IPv4 0xABC 0t0 "
            f"TCP 10.1.0.73:56201->160.79.104.10:443 (ESTABLISHED)\n")
    monkeypatch.setattr(health.sys_probe, "run", _fake(ps, lsof))
    res = health._claude_app_proxy_check()
    assert res["status"] == "down", f"external-сокет → down; got {res}"
    assert "claude-app" in res["detail"].lower(), f"рецепт — wrapper ~/bin/claude-app; got {res}"


def test_unknown_when_lsof_timeout(monkeypatch):
    ps = f"83907 {APP_CLAUDE_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run", _fake(ps, lsof_timeout=True))
    res = health._claude_app_proxy_check()
    assert res["status"] == "unknown", "lsof недоступен → fail-closed unknown, не down"


def test_unknown_when_lsof_nonzero_rc(monkeypatch):
    ps = f"83907 {APP_CLAUDE_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run", _fake(ps, lsof_out="", lsof_rc=1))
    res = health._claude_app_proxy_check()
    assert res["status"] == "unknown", "lsof rc≠0 — не доказательство маршрута → unknown"


def test_unknown_when_idle_no_established(monkeypatch):
    """App активен, но ни одного ESTABLISHED (переподключение) → unknown, НЕ ok."""
    ps = f"83907 {APP_CLAUDE_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run", _fake(ps, lsof_out=""))
    res = health._claude_app_proxy_check()
    assert res["status"] == "unknown", f"idle без positive evidence → unknown; got {res}"


def test_unknown_when_ps_timeout(monkeypatch):
    monkeypatch.setattr(health.sys_probe, "run", _fake(ps_timeout=True))
    res = health._claude_app_proxy_check()
    assert res["status"] == "unknown", "ps timeout → unknown"


def test_helper_pid_detected_via_app_path(monkeypatch):
    """Helper (/Claude.app/ в comm, basename ≠ Claude) — тоже App-PID (канон path-сегмента)."""
    ps = f"72140 {HELPER_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run",
                        _fake(ps, _lsof_proxied("72140", "127.0.0.1:8118")))
    res = health._claude_app_proxy_check()
    assert res["status"] == "ok", f"helper /Claude.app/ детектен как App-PID; got {res}"


def test_registered_in_health_namespace():
    """star-import re-export (канон #158): имя доступно в health после __all__."""
    assert callable(health._claude_app_proxy_check), "health._claude_app_proxy_check существует"
