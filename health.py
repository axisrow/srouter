"""Health-проверки стека srouter: общий движок для `srouter doctor`, `/health` и watchdog.

Переиспользует логику probe_tunnel (dashboard_network): curl через прокси к api.anthropic.com.
Прокси-трафик идёт через loopback (127.0.0.1:8118 → privoxy → xray → VPS IP), а PF-изоляция
режет только en*/ppp* — значит проверка НЕ блокируется даже при включённой изоляции.

Три потребителя:
  - `srouter doctor` (CLI) — разовый прогон, человекочитаемый отчёт.
  - `GET /health` (эндпоинт) — лёгкий, 200 ok / 503 degraded/down.
  - watchdog (launchd, раз в 90с) — фоновый пинг; нотификация при переходе ok→down.

Не бросает, всегда dict со status (probe-канон).
"""
from pathlib import Path

import sys_probe

import claude_proxy  # Claude Code HTTPS_PROXY в ~/.claude/settings.json — без него CLI «без ИИ»

# Абсолютные пути: launchd/GUI PATH их не содержит (канон проекта).
CURL = "/usr/bin/curl"
LSOF = "/usr/sbin/lsof"
OSASCRIPT = "/usr/bin/osascript"

# Прокси = privoxy (8118). Берём из dashboard_common если доступен; fallback на хардкод,
# чтобы модуль не падал в среде без srouter_config (как git_proxy/claude_proxy).
try:
    from dashboard_common import HTTP_PROXY_URL as _PROXY  # http://127.0.0.1:8118
except Exception:
    _PROXY = "http://127.0.0.1:8118"

# Порты компонентов стека.
PRIVOXY_PORT = 8118
XRAY_PORT = 10808
DASHBOARD_PORT = 8787

# Эндпоинт туннеля для проверки (как probe_tunnel).
TUNNEL_TARGET = "https://api.anthropic.com/"

# State watchdog'а (переход ok→down, чтобы не спамить). /tmp не переживает ребут — приемлемо:
# после ребута fresh state, первый прогон без нотификации если уже down.
WATCHDOG_STATE = Path("/tmp/srouter-watchdog.last")


def _port_up(port):
    """Слушает ли кто-то TCP порт (быстро, без сети). True/False."""
    r = sys_probe.run([LSOF, "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"], timeout=3)
    if r.get("timeout"):
        return False
    return bool((r.get("out") or "").strip())


def _tunnel_up():
    """Реальный туннель жив? curl через прокси к TUNNEL_TARGET (как probe_tunnel).

    НЕ блокируется PF — прокси-трафик через loopback, PF режет только en*/ppp*.
    Возвращает (ok: bool, detail: str — http-код или причина).
    """
    r = sys_probe.run([CURL, "-sS", "-o", "/dev/null", "-x", _PROXY,
                       "--connect-timeout", "4", "--max-time", "8",
                       "-w", "%{http_code}", TUNNEL_TARGET], timeout=10)
    if r.get("timeout"):
        return False, "timeout"
    code = (r.get("out") or "").strip()
    if not code:
        return False, "no-response"
    if code == "000":
        return False, "connection-failed"
    return True, f"HTTP {code}"


def _claude_proxy_on():
    """Claude Code настроен ходить через прокси? (env.HTTPS_PROXY в ~/.claude/settings.json).

    Без этого CLI идёт напрямую → при включённой PF-изоляции режется → «без ИИ». Это проверялось
    в инциденте: туннель жив, но proxy слетел → doctor врал OK. Теперь doctor это видит.
    """
    return bool(claude_proxy.status().get("enabled", False))


def check_all():
    """Все проверки стека. {status: ok|degraded|down, checks: [{name, ok, detail?}]}.

    status: ok (всё живо) / degraded (часть жива) / down (всё мертво). Не бросает.
    """
    checks = []
    checks.append({"name": f"privoxy ({PRIVOXY_PORT})", "ok": _port_up(PRIVOXY_PORT)})
    checks.append({"name": f"xray ({XRAY_PORT})", "ok": _port_up(XRAY_PORT)})
    checks.append({"name": f"dashboard ({DASHBOARD_PORT})", "ok": _port_up(DASHBOARD_PORT)})
    tun_ok, tun_detail = _tunnel_up()
    checks.append({"name": "туннель (api.anthropic.com через прокси)", "ok": tun_ok, "detail": tun_detail})
    # Claude Code настроен использовать туннель? Без proxy CLI идёт напрямую → PF режёт → «без ИИ».
    checks.append({"name": "claude-proxy (HTTPS_PROXY для CLI)", "ok": _claude_proxy_on()})
    all_ok = all(c["ok"] for c in checks)
    any_ok = any(c["ok"] for c in checks)
    status = "ok" if all_ok else ("degraded" if any_ok else "down")
    return {"status": status, "checks": checks}


def _notify(msg, sound="Glass"):
    """macOS-нотификация через osascript (встроенный, всегда доступен). Не бросает."""
    try:
        sys_probe.run([OSASCRIPT, "-e",
                       f'display notification "{msg}" with title "srouter" sound name "{sound}"'],
                      timeout=5)
    except Exception:
        pass  # нотификация — best-effort, не роняет watchdog


def _print_report(result):
    """Человекочитаемый отчёт check_all (для doctor). Вывод в stdout."""
    print(f"srouter health: {result['status'].upper()}\n")
    for c in result["checks"]:
        mark = "✅" if c["ok"] else "❌"
        detail = f" ({c['detail']})" if c.get("detail") else ""
        print(f"  {mark} {c['name']}{detail}")
    if result["status"] != "ok":
        print("\nЧто проверить:")
        failed_names = " ".join(c["name"] for c in result["checks"] if not c["ok"])
        if "privoxy" in failed_names or "xray" in failed_names:
            print("  • brew services restart xray privoxy  (или srouter install)")
        if "туннель" in failed_names:
            print("  • туннель: проверь узел (srouter status / дашборд nodes), возможно узел недоступен")
        if "dashboard" in failed_names:
            print("  • дашборд: srouter restart")
        if "claude-proxy" in failed_names:
            print("  • Claude Code proxy: включи в дашборде (карточка Claude Code proxy) или srouter install")


def cmd_watchdog():
    """Один прогон watchdog'а (запускается launchd раз в ~90с).

    Нотификация только при ПЕРЕХОДЕ состояния (ok→down — громко, down→ok — тихо), не при каждом
    прогоне — чтобы не спамить. State в WATCHDOG_STATE (/tmp).
    """
    # Сначала гарантировать split-route (если VPN перехватил default) — «пофигу VPN».
    # ensure_split_route добавит route до VPS через en0, и тогда check_all увидит живой туннель.
    try:
        import node_selector
        node_selector.ensure_split_route()
    except Exception:
        pass  # split-route — best-effort, не роняет watchdog

    result = check_all()
    is_ok = result["status"] == "ok"
    try:
        was_ok = WATCHDOG_STATE.exists() and WATCHDOG_STATE.read_text().strip() == "ok"
    except Exception:
        was_ok = False

    if not is_ok and was_ok:
        # Переход ok→down — кричим громко.
        failed = ", ".join(c["name"] for c in result["checks"] if not c["ok"])
        _notify(f"туннель/стек упал ({failed})", "Basso")
    elif is_ok and not was_ok:
        # Восстановление — тихое уведомление.
        _notify("стек восстановлен", "Glass")
    # down→down / ok→ok — молча (не спамим).

    try:
        WATCHDOG_STATE.write_text(result["status"])
    except Exception:
        pass  # state — best-effort
    return 0 if is_ok else 1


def main(argv=None):
    """CLI: check (отчёт) | watchdog (нотификация при переходе)."""
    import argparse
    p = argparse.ArgumentParser(prog="health", description="Health-проверки стека srouter.")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("check", help="Разовый прогон проверок, отчёт ✅/❌.")
    sub.add_parser("watchdog", help="Один прогон watchdog'а (для launchd): нотификация при переходе.")
    args = p.parse_args(argv)

    if args.cmd == "watchdog":
        return cmd_watchdog()
    # default / "check"
    result = check_all()
    _print_report(result)
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
