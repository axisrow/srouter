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

# Абсолютные пути: launchd/GUI PATH их не содержит (канон проекта).
CURL = "/usr/bin/curl"
LSOF = "/usr/sbin/lsof"
PS = "/bin/ps"
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


def _claude_proxy_probe():
    """Реально запущенный Claude Code использует прокси? Поведенческий proof (lsof), не файл.

    Решает дыру Codex review + инцидента «без ИИ»: claude_proxy.status() читает только ФАЙЛ
    settings.json, а не реальный CC. enable()/disable() пишут файл, но не перезапускают CC → окно
    рассинхрона файл↔процесс. Здесь — runtime-proof из ядерной таблицы сокетов: CC держит
    established TCP к privoxy (127.0.0.1:PRIVOXY_PORT). Надёжно для всех типов CC-сессий (daemon,
    GUI pty-host, orchestrator-обёртки) — ps eww/launchctl procinfo слепы для обёрток (измерено).

    Возвращает {status, source, detail} — ОДИН вызов, один срез (нет TOCTOU ok/detail):
      status="ok"      — CC запущен и держит коннект к privoxy (реально юзает прокси);
      status="down"    — CC запущен, но БЕЗ коннекта (идёт напрямую → PF режет → «без ИИ»);
      status="unknown" — CC не запущен (проверять нечего; check_all НЕ агрегирует этот check).
    """
    # 1. PID'ы процессов claude. ps comm= отдаёт basename бинаря (усечён до 15 символов ядром macOS),
    #    поэтому матчим по точному basename из whitelist, а не по substring пути — robust против
    #    ложных срабатываний (любой claude*-скрипт) и пропусков (Codex.app). Whitelist имён CC-бинаря.
    r = sys_probe.run([PS, "-axo", "pid=,comm="], timeout=3)
    if r.get("timeout"):
        return {"status": "unknown", "source": "n/a", "detail": "timeout ps"}
    pids = []
    for line in (r.get("out") or "").splitlines():
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        pid_s, comm = parts[0].strip(), parts[1].strip()
        # CC бинарь: ~/.local/bin/claude (comm="claude") или ClaudeCode.app (comm="Claude").
        if pid_s.isdigit() and comm in ("claude", "Claude"):
            pids.append(pid_s)
    if not pids:
        return {"status": "unknown", "source": "n/a", "detail": "Claude Code не запущен"}

    # 2. Один lsof на ВСЕ PID'ы (батч, не N вызовов). БЕЗ -iTCP: с -iTCP macOS тащит общий LISTEN-сокет
    #    privoxy для всех процессов → ложный позитив. Фильтруем по "->127.0.0.1:PORT" тут.
    needle = f"->127.0.0.1:{PRIVOXY_PORT}"
    lr = sys_probe.run([LSOF, "-nP", "-p", ",".join(pids)], timeout=3)
    if not lr.get("timeout"):
        for line in (lr.get("out") or "").splitlines():
            if "TCP" in line and needle in line:
                return {"status": "ok", "source": "runtime",
                        "detail": "runtime: Claude Code держит коннект к privoxy"}
    return {"status": "down", "source": "runtime",
            "detail": "runtime: Claude Code запущен, но без коннекта к privoxy (перезапусти CC)"}


def check_all():
    """Все проверки стека. {status: ok|degraded|down, checks: [{name, ok, detail?, info?}]}.

    status: ok (всё живо) / degraded (часть жива) / down (всё мертво). Не бросает.
    claude-proxy check имеет смысл только когда CC запущен: если unknown (CC не работает) — он
    добавляется в checks как info (не driver), чтобы не ронять вердикт без причины.
    """
    checks = []
    checks.append({"name": f"privoxy ({PRIVOXY_PORT})", "ok": _port_up(PRIVOXY_PORT)})
    checks.append({"name": f"xray ({XRAY_PORT})", "ok": _port_up(XRAY_PORT)})
    checks.append({"name": f"dashboard ({DASHBOARD_PORT})", "ok": _port_up(DASHBOARD_PORT)})
    tun_ok, tun_detail = _tunnel_up()
    checks.append({"name": "туннель (api.anthropic.com через прокси)", "ok": tun_ok, "detail": tun_detail})
    # Claude Code РЕАЛЬНО использует прокси? runtime (lsof), не файл. unknown (CC не запущен) →
    # info-only, не driver: проверять «CC юзает прокси» бессмысленно, если CC не работает.
    cp = _claude_proxy_probe()
    cp_check = {"name": "claude-proxy (HTTPS_PROXY для CLI)",
                "ok": cp["status"] == "ok", "detail": cp["detail"]}
    if cp["status"] == "unknown":
        cp_check["info"] = True  # не участвует в агрегации (drivers ниже фильтруют info)
    checks.append(cp_check)
    drivers = [c for c in checks if not c.get("info")]
    all_ok = all(c["ok"] for c in drivers)
    any_ok = any(c["ok"] for c in drivers)
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
            print("  • Claude Code proxy: включи в дашборде (карточка Claude Code proxy) и ПЕРЕЗАПУСТИ Claude Code")


def cmd_watchdog():
    """Один прогон watchdog'а (запускается launchd раз в ~20с).

    Нотификация только при ПЕРЕХОДЕ состояния (ok→down — громко, down→ok — тихо), не при каждом
    прогоне — чтобы не спамить. State в WATCHDOG_STATE (/tmp).

    Split-route НЕ делается тут — это ответственность ppp-hook (/etc/ppp/ip-up, мгновенно при VPN
    up, от root без osascript). Watchdog только детектит падение туннеля и нотифицирует. Если
    ppp-hook не сработал (utun-VPN) — пользователь видит нотификацию и手动но ensure-split-route-root.
    """
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
    sub.add_parser("ensure-split-route-root", help="Split-route при VPN up (ppp-hook, от root).")
    args = p.parse_args(argv)

    if args.cmd == "watchdog":
        return cmd_watchdog()
    if args.cmd == "ensure-split-route-root":
        # ppp-hook (/etc/ppp/ip-up) — от root, route add напрямую (без osascript).
        import node_selector
        r = node_selector.ensure_split_route()
        return 0 if r.get("enabled") else 1
    # default / "check"
    result = check_all()
    _print_report(result)
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
