"""ТДД-тесты health._codex_proxy_probe: doctor видит РЕАЛЬНЫЙ маршрут codex-процесса (issue #120).

Корень #120 (выяснил сам codex): старая shell-сессия не получила новое окружение → codex резолвился
в brew-бинарь с унаследованным HTTP_PROXY=privoxy (8118) → long-lived WS рвался. Новая сессия через
shell-функцию → ~/bin/codex → SOCKS5 (10808) → работает. `which codex` НЕ доказательство (wrapper
использует exec, процесс выглядит как brew-codex). Единственный критерий — runtime-сокет PID к
10808 (ok) vs 8118 (warn, порвёт WS) vs напрямую (down).

Контракт _codex_proxy_probe() → {status, source, detail}:
  status="ok"      — codex-binary-PID держит коннект к 10808 (SOCKS5/xray, стабильно);
  status="warn"    — codex на 8118 (privoxy) — long-lived WS порвётся (#120);
  status="down"    — codex идёт напрямую (external IP, без localhost-прокси);
  status="mixed"   — несколько codex-PID на разных маршрутах (часть 10808, часть 8118);
  status="unknown" — codex не запущен (info-only, не роняет вердикт — как claude-proxy).
Классификация по lsof-сокетам (ps eww env на macOS не читается — права).
"""
import health

# Реальный codex-binary path (ps -axo comm= на macOS — ПОЛНЫЙ ПУТЬ):
#   /opt/homebrew/lib/node_modules/@openai/codex/.../vendor/aarch64-apple-darwin/bin/codex
CODEX_BIN_COMM = ("/opt/homebrew/lib/node_modules/@openai/codex/node_modules/"
                  "@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex")
# Соседний процесс — НЕ должен матчиться (mode-host, не основной codex-binary):
CODEX_MODE_HOST_COMM = ("/opt/homebrew/lib/node_modules/@openai/codex/node_modules/"
                        "@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex-code-mode-host")

# Реальный формат lsof-строки:
#   codex 22415 axisrow 32u IPv4 ... TCP 127.0.0.1:54813->127.0.0.1:10808 (ESTABLISHED)


def _lsof_line(pid, local_eph, target_port, state="ESTABLISHED"):
    return (f"codex {pid} axisrow 32u IPv4 0xABC 0t0 "
            f"TCP 127.0.0.1:{local_eph}->127.0.0.1:{target_port} ({state})\n")


def _fake(ps_out, lsof_out, lsof_timeout=False):
    """fake_run для monkeypatch: ps отдаёт ps_out, lsof — lsof_out (или timeout)."""
    def fake_run(cmd, timeout):
        if cmd and cmd[0] == "/bin/ps":
            return {"rc": 0, "out": ps_out, "err": "", "timeout": False}
        if cmd and cmd[0] == "/usr/sbin/lsof":
            if lsof_timeout:
                return {"rc": None, "out": "", "err": "timeout", "timeout": True}
            return {"rc": 0, "out": lsof_out, "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}
    return fake_run


def test_codex_probe_ok_when_socket_to_10808(monkeypatch):
    """codex-PID держит коннект к 10808 (SOCKS5/xray) → status=ok. Стабильный long-lived WS."""
    ps = f"22415 {CODEX_BIN_COMM}\n"
    lsof = _lsof_line(22415, 54813, health.XRAY_PORT)
    monkeypatch.setattr(health.sys_probe, "run", _fake(ps, lsof))
    res = health._codex_proxy_probe()
    assert res["status"] == "ok"
    assert res["source"] == "runtime"
    assert "10808" in res["detail"] or "22415" in res["detail"]


def test_codex_probe_warn_when_socket_to_8118_privoxy(monkeypatch):
    """codex-PID на 8118 (privoxy) → status=warn. Long-lived WS порвётся (#120). Главная диагностика."""
    ps = f"26279 {CODEX_BIN_COMM}\n"
    lsof = _lsof_line(26279, 54813, health.PRIVOXY_PORT)
    monkeypatch.setattr(health.sys_probe, "run", _fake(ps, lsof))
    res = health._codex_proxy_probe()
    assert res["status"] == "warn", "codex на privoxy 8118 → warn (WS порвётся, #120)"
    assert res["source"] == "runtime"


def test_codex_probe_down_when_direct_external_ip(monkeypatch):
    """codex-PID имеет external ESTABLISHED БЕЗ localhost-прокси → status=down (напрямую, PF режет)."""
    ps = f"30001 {CODEX_BIN_COMM}\n"
    # внешний IP (не 127.0.0.1) — codex идёт напрямую, мимо прокси
    lsof = ("codex 30001 axisrow 32u IPv4 0xABC 0t0 "
            "TCP 192.168.1.5:54813->104.244.46.93:443 (ESTABLISHED)\n")
    monkeypatch.setattr(health.sys_probe, "run", _fake(ps, lsof))
    res = health._codex_proxy_probe()
    assert res["status"] == "down", "codex напрямую (external IP) → down"


def test_codex_probe_mixed_when_some_10808_some_8118(monkeypatch):
    """Несколько codex-PID: один на 10808, другой на 8118 → status=mixed, detail перечисляет PID'ы.

    Сценарий #120: старая TUI-сессия (8118, ломается) + новая (10808, работает) одновременно.
    Doctor должен показать mixed, чтобы пользователь видел обе сессии и перезапустил ломаную.
    """
    ps = f"22415 {CODEX_BIN_COMM}\n26279 {CODEX_BIN_COMM}\n"
    lsof = _lsof_line(22415, 54813, health.XRAY_PORT) + _lsof_line(26279, 54814, health.PRIVOXY_PORT)
    monkeypatch.setattr(health.sys_probe, "run", _fake(ps, lsof))
    res = health._codex_proxy_probe()
    assert res["status"] == "mixed", "часть codex на 10808, часть на 8118 → mixed"
    assert "22415" in res["detail"] and "26279" in res["detail"], "detail перечисляет PID'ы"


def test_codex_probe_unknown_when_no_codex_running(monkeypatch):
    """codex не запущен → status=unknown (info-only, не роняет вердикт — как claude-proxy)."""
    monkeypatch.setattr(health.sys_probe, "run", _fake("", ""))
    res = health._codex_proxy_probe()
    assert res["status"] == "unknown"
    assert res["source"] == "n/a"


def test_codex_probe_ignores_non_binary_codex(monkeypatch):
    """Строгий паттерн: codex-code-mode-host / shell-обёртки НЕ матчатся (это не основной codex-binary).

    `which codex` НЕ доказательство — но и mode-host не главный процесс. Матчим только
    `codex-darwin.*/bin/codex$`, отбрасывая mode-host (другой binary).
    """
    ps = f"99999 {CODEX_MODE_HOST_COMM}\n"  # mode-host, не основной codex
    lsof = _lsof_line(99999, 54813, health.XRAY_PORT)
    monkeypatch.setattr(health.sys_probe, "run", _fake(ps, lsof))
    res = health._codex_proxy_probe()
    assert res["status"] == "unknown", "mode-host НЕ матчится как основной codex-binary"


def test_codex_probe_timeout_lsof_unknown(monkeypatch):
    """lsof timeout → status=unknown (не false-fail, как у claude-proxy — консистентно).

    Иначе пользователь получит ложный degraded + неверный совет «перезапусти TUI», хотя коннект жив.
    """
    ps = f"22415 {CODEX_BIN_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run", _fake(ps, "", lsof_timeout=True))
    res = health._codex_proxy_probe()
    assert res["status"] == "unknown", "lsof timeout → unknown (не false-warn/down)"
