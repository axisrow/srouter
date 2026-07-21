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
import json
import os
import re
import shutil
import tempfile
from urllib.parse import urlparse

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

# Эндпоинты туннеля для проверки — ДВА таргета, как probe_tunnel (dashboard_network): origin-5xx
# одного вендора (Anthropic лежит, но канал жив) не должен читаться как «туннель упал».
TUNNEL_TARGETS = ("https://api.anthropic.com/", "https://api.openai.com/")

# State watchdog'а (переход ok→down, чтобы не спамить). /tmp не переживает ребут — приемлемо:
# после ребута fresh state, первый прогон без нотификации если уже down.
WATCHDOG_STATE = Path("/tmp/srouter-watchdog.last")

# Real Claude Code transport probe is doctor-only: failed proxy negotiation may spend several
# seconds in retries. Dashboard /health and watchdog keep using lightweight passive checks.
CLAUDE_TRANSPORT_TIMEOUT = 8
CLAUDE_API_BASE_URL = "https://api.anthropic.com"
CLAUDE_DUMMY_API_KEY = "sk-ant-srouter-transport-probe-invalid"


def _port_up(port):
    """Слушает ли кто-то TCP порт (быстро, без сети). True/False."""
    r = sys_probe.run([LSOF, "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"], timeout=3)
    if r.get("timeout"):
        return False
    return bool((r.get("out") or "").strip())


def _tunnel_target_up(url):
    """Один таргет через прокси: (ok, detail). Живой = сервер ответил HTTP < 500
    (sys_probe.tunnel_code_up). 000/timeout/5xx — не жив. Не бросает."""
    r = sys_probe.run([CURL, "-sS", "-o", "/dev/null", "-x", _PROXY,
                       "--connect-timeout", "4", "--max-time", "8",
                       "-w", "%{http_code}", url], timeout=10)
    if r.get("timeout"):
        return False, "timeout"
    code = (r.get("out") or "").strip()
    if not code:
        return False, "no-response"
    if code == "000":
        return False, "connection-failed"
    try:
        code_int = int(code)
    except ValueError:
        return False, f"bad-code {code}"
    if not sys_probe.tunnel_code_up(code_int):
        return False, f"upstream-error HTTP {code}"
    return True, f"HTTP {code}"


def _tunnel_up():
    """Реальный туннель жив? curl через прокси к TUNNEL_TARGETS (ровно как probe_tunnel).

    Бьём ДВА таргета (Anthropic + OpenAI), up = первый OR второй — та же избыточность, что у
    probe_tunnel: origin-5xx одного вендора (сам вендор лежит, но канал жив) НЕ читается как
    «туннель упал», иначе watchdog поднимет ложную тревогу (issue #82). Единая семантика 5xx=down
    сохраняется, но применяется per-target, а решение — по обоим.
    НЕ блокируется PF — прокси-трафик через loopback, PF режет только en*/ppp*.
    Возвращает (ok: bool, detail: str — http-код живого таргета или причины провалов).
    """
    details = []
    for url in TUNNEL_TARGETS:
        ok, detail = _tunnel_target_up(url)
        if ok:
            return True, detail  # любой живой таргет = туннель жив (как up = a OR o)
        details.append(detail)
    # ни один таргет не ответил живым HTTP < 500 → туннель/прокси down (не origin одного вендора)
    return False, "; ".join(details)


def _is_claude_code_comm(comm):
    """Является ли comm (из `ps comm=`) процессом Claude Code?

    `ps comm=` на macOS отдаёт полный путь. Реальные CC-варианты:
      - basename "claude": CLI (~/.local/bin/claude), GUI pty-host (ClaudeCode.app/.../claude), bare "claude";
      - version-runner: путь содержит "/claude/versions/" (basename = номер версии, не "claude") — это
        основной движок CC, который реально держит коннект к privoxy.
    Отбрасывает desktop Claude.app helpers, codex, сторонние claude*-wrappers.
    """
    if not comm:
        return False
    if os.path.basename(comm) == "claude":
        return True
    return "/claude/versions/" in comm


def _claude_proxy_probe():
    """Какой локальный маршрут виден у запущенного Claude Code? Passive lsof evidence.

    Важно (#127): ESTABLISHED к 10808 доказывает только TCP до SOCKS listener, но не SOCKS
    handshake и не доставку запроса к API. Поэтому 10808 без active real-CLI probe никогда не
    получает ok. External socket остаётся доказательством direct leak.
    """
    r = sys_probe.run([PS, "-axo", "pid=,comm="], timeout=3)
    if r.get("timeout"):
        return {"status": "unknown", "source": "n/a", "detail": "timeout ps"}
    pids = []
    for line in (r.get("out") or "").splitlines():
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        pid_s, comm = parts[0].strip(), parts[1].strip()
        if pid_s.isdigit() and _is_claude_code_comm(comm):
            pids.append(pid_s)
    if not pids:
        return {"status": "unknown", "source": "n/a", "detail": "Claude Code не запущен"}

    # Один lsof на все PID'ы. Любой local proxy + external = mixed/direct leak.
    lr = sys_probe.run([LSOF, "-nP", "-p", ",".join(pids)], timeout=3)
    if lr.get("timeout"):
        return {"status": "unknown", "source": "n/a", "detail": "timeout lsof"}
    proxy_pids, socks_pids, external_pids = set(), set(), set()
    for line in (lr.get("out") or "").splitlines():
        if "TCP" not in line or "ESTABLISHED" not in line:
            continue
        fields = line.split()
        pid = fields[1] if len(fields) > 1 else ""
        if f"->127.0.0.1:{PRIVOXY_PORT}" in line:
            proxy_pids.add(pid)
        elif f"->127.0.0.1:{XRAY_PORT}" in line:
            socks_pids.add(pid)
        elif "->127.0.0.1:" not in line:
            # external ESTABLISHED (не localhost) — CC идёт напрямую, мимо прокси.
            external_pids.add(pid)
    local_pids = proxy_pids | socks_pids
    if local_pids and external_pids:
        return {"status": "down", "source": "runtime",
                "detail": (f"runtime: Claude Code MIXED — local proxy (PID {','.join(sorted(local_pids))}) "
                           f"+ direct-leak (PID {','.join(sorted(external_pids))}). "
                           f"Один из PID идёт напрямую — нарушение fail-closed. "
                           f"Проверь HTTPS_PROXY в ~/.claude/settings.json env.")}
    if proxy_pids and not socks_pids:
        return {"status": "ok", "source": "runtime",
                "detail": f"runtime: Claude Code через HTTP bridge 8118 (PID {','.join(sorted(proxy_pids))})"}
    if socks_pids:
        routes = f"; HTTP 8118 PID {','.join(sorted(proxy_pids))}" if proxy_pids else ""
        return {"status": "unknown", "source": "runtime",
                "detail": (f"runtime: TCP к SOCKS5 10808 (PID {','.join(sorted(socks_pids))}){routes} "
                           f"не доказывает API transport; нужен активный real-CLI probe")}
    if external_pids:
        return {"status": "down", "source": "runtime",
                "detail": (f"runtime: Claude Code идёт НАПРЯМУЮ (мимо прокси) — нарушение fail-closed. "
                           f"PID {','.join(sorted(external_pids))}. "
                           f"Проверь HTTPS_PROXY в ~/.claude/settings.json env "
                           f"(ожидается http://127.0.0.1:8118)")}
    return {"status": "unknown", "source": "runtime",
            "detail": "runtime: Claude Code запущен, но нет активных сокетов (idle)"}


def _find_claude_binary():
    """Найти настоящий Claude Code без зависимости от урезанного launchd PATH."""
    candidates = [
        Path.home() / ".local" / "bin" / "claude",
        Path("/opt/homebrew/bin/claude"),
        Path("/usr/local/bin/claude"),
    ]
    discovered = shutil.which("claude")
    if discovered:
        candidates.append(Path(discovered))
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return ""


def _has_expected_api_401(output):
    """Только structured api_error_status=401 считается положительным transport proof."""
    for line in output.splitlines():
        try:
            payload = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(payload, dict) and payload.get("api_error_status") == 401:
            return True
    return False


def _has_api_retry(output):
    """Есть ли structured retry без ответа API (формат stream-json может содержать пробелы)."""
    for line in output.splitlines():
        try:
            payload = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(payload, dict) and payload.get("subtype") == "api_retry":
            return True
    return False


def _claude_transport_once(proxy, timeout=CLAUDE_TRANSPORT_TIMEOUT):
    """Запустить настоящий Claude Code изолированно через один proxy.

    Dummy key гарантирует нулевой model-call: успешный транспорт заканчивается ожидаемым API 401.
    User settings, NO_PROXY, alternative base URL и реальные credentials не участвуют (#127).
    """
    claude = _find_claude_binary()
    if not claude:
        return {"status": "unknown", "proxy": proxy, "api_status": None,
                "error": "Claude Code binary not found", "detail": "Claude Code binary not found"}

    clean_keys = (
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "all_proxy", "no_proxy",
        "ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
    )
    with tempfile.TemporaryDirectory(prefix="srouter-claude-probe-") as temp_home:
        config_dir = Path(temp_home) / ".claude"
        config_dir.mkdir()
        env = os.environ.copy()
        for key in clean_keys:
            env.pop(key, None)
        env.update({
            "HOME": temp_home,
            "CLAUDE_CONFIG_DIR": str(config_dir),
            "ANTHROPIC_BASE_URL": CLAUDE_API_BASE_URL,
            "ANTHROPIC_API_KEY": CLAUDE_DUMMY_API_KEY,
            "HTTP_PROXY": proxy,
            "HTTPS_PROXY": proxy,
            "http_proxy": proxy,
            "https_proxy": proxy,
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "DISABLE_TELEMETRY": "1",
            "DISABLE_ERROR_REPORTING": "1",
        })
        cmd = [
            claude,
            "--bare",
            "--setting-sources", "",
            "--no-session-persistence",
            "--tools", "",
            "--max-budget-usd", "0.01",
            "--verbose",
            "--output-format", "stream-json",
            "-p", "srouter transport probe",
        ]
        run_result = sys_probe.run(cmd, timeout=timeout, env=env)

    output = "\n".join(
        part for part in (run_result.get("out", ""), run_result.get("err", "")) if part
    )
    if _has_expected_api_401(output):
        return {"status": "ok", "proxy": proxy, "api_status": 401, "error": "",
                "detail": "API returned expected 401 (transport works)"}
    if "UnsupportedProxyProtocol" in output:
        error = "UnsupportedProxyProtocol"
    elif run_result.get("timeout") or "Connection error" in output or _has_api_retry(output):
        error = "Connection error / timeout"
    elif run_result.get("rc") is None:
        error = (run_result.get("err") or "Claude Code launch failed").splitlines()[0][:160]
    else:
        error = f"Claude Code exited rc={run_result.get('rc')} before any API response"
    detail = error
    if run_result.get("timeout"):
        detail += " before any API response"
    return {"status": "down", "proxy": proxy, "api_status": None,
            "error": error, "detail": detail}


def _configured_claude_proxy():
    """Proxy из settings.json; local import сохраняет fail-soft границу health."""
    try:
        import claude_proxy
        return claude_proxy.status().get("proxy", "")
    except Exception:
        return ""


def _claude_transport_probe(proxy=None):
    """Doctor-only active proof. Для failed SOCKS запускает известный HTTP control."""
    configured = proxy if proxy is not None else _configured_claude_proxy()
    if not configured:
        return {"status": "unknown", "proxy": "", "api_status": None,
                "error": "proxy is not configured", "detail": "Claude Code proxy не настроен"}

    result = _claude_transport_once(configured)
    scheme = urlparse(configured).scheme.lower()
    if result["status"] != "down" or scheme not in {"socks", "socks5", "socks5h"}:
        return result

    control = _claude_transport_once(_PROXY)
    detail = f"configured proxy {configured}: {result['detail']}; HTTP control {_PROXY}: {control['detail']}"
    if control["status"] == "ok":
        detail += "; configured SOCKS path is unusable — configure Claude Code to use the HTTP bridge"
    result = dict(result)
    result["detail"] = detail
    result["control"] = control
    return result


# codex-binary comm-паттерн. Матчит ОСНОВНОЙ codex-binary по BASENAME (независимо от способа установки):
#   basename "codex"                       — npm-vendor (.../bin/codex), standalone (~/.local/bin/codex)
#   basename "codex-<arch>-apple-darwin"   — Homebrew cask / release-binary
# НЕ матчит (исключает по basename):
#   moonbridge, browser_crashpad_handler, ChatGPT for Chrome, node (Codex.app helpers / .codex/plugins),
#   codex-code-mode-host (вспомогательный binary, не основной движок).
# cycle-review #121 C1: npm-only regex пропускал brew-cask/standalone → doctor ложно «codex не запущен».
# cycle 2 cleanup: общий substring 'codex' over-matched helpers → matcher по basename (точно).
_CODEX_BIN_RE = re.compile(r"(^|/)codex(?:-(?:aarch64|x86_64)-apple-darwin)?$")


def _is_codex_binary_comm(comm):
    """Является ли comm основным codex-binary? По basename: 'codex' или 'codex-<arch>-apple-darwin'.

    Любой способ установки (npm/cask/standalone). Отбрасывает helpers (moonbridge, crashpad, node,
    ChatGPT-for-Chrome) и codex-code-mode-host (вспомогательный binary).
    """
    if not comm:
        return False
    return bool(_CODEX_BIN_RE.search(comm))


def _codex_proxy_probe():
    """Какой маршрут используют ЖИВЫЕ codex-процессы? Поведенческий proof (lsof), не файл/which.

    Решает #120: codex TUI рвёт long-lived WS через privoxy 8118, но стабилен через SOCKS5 10808.
    `which codex` НЕ доказательство — wrapper использует exec, процесс выглядит как brew-codex в ps.
    Единственный критерий — runtime-сокет конкретного PID к 10808 (ok) vs 8118 (warn, #120) vs напрямую
    (down). ps eww env на macOS не читается (права) → классификация по lsof-сокетам, как у claude-proxy.

    Возвращает {status, source, detail}:
      status="ok"      — codex-binary-PID держит коннект к 10808 (SOCKS5/xray, стабильно);
      status="warn"    — codex на 8118 (privoxy) — long-lived WS порвётся (#120);
      status="down"    — codex идёт напрямую (external IP, без localhost-прокси);
      status="mixed"   — несколько codex-PID на разных маршрутах;
      status="unknown" — codex не запущен ИЛИ lsof timeout (info-only, не роняет вердикт).
    """
    # 1. PID'ы codex-binary. ps -axo comm= отдаёт полный путь — матчим по vendor-binary-path.
    r = sys_probe.run([PS, "-axo", "pid=,comm="], timeout=3)
    if r.get("timeout"):
        return {"status": "unknown", "source": "n/a", "detail": "timeout ps"}
    pids = []
    for line in (r.get("out") or "").splitlines():
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        pid_s, comm = parts[0].strip(), parts[1].strip()
        if pid_s.isdigit() and _is_codex_binary_comm(comm):
            pids.append(pid_s)
    if not pids:
        return {"status": "unknown", "source": "n/a", "detail": "codex не запущен"}

    # 2. Один lsof на ВСЕ PID'ы (батч). Классифицируем по ->127.0.0.1:PORT (как claude-proxy).
    lr = sys_probe.run([LSOF, "-nP", "-p", ",".join(pids)], timeout=3)
    if lr.get("timeout"):
        return {"status": "unknown", "source": "n/a", "detail": "timeout lsof"}

    # 3. Классификация per-PID по множествам маршрутов. external_pids (per-PID, не bool) — критично для
    # C2: SOCKS-PID + direct-PID → mixed (не ok), иначе direct-сессия маскируется (#121 cycle 1 C2).
    socks_pids, privoxy_pids, external_pids = set(), set(), set()
    for line in (lr.get("out") or "").splitlines():
        if "TCP" not in line or "ESTABLISHED" not in line:
            continue
        # localhost-прокси: ->127.0.0.1:PORT. PID — fields[1] (COMMAND=0, PID=1 в lsof-выводе).
        fields = line.split()
        pid = fields[1] if len(fields) > 1 else ""
        if f"->127.0.0.1:{XRAY_PORT}" in line:
            socks_pids.add(pid)
        elif f"->127.0.0.1:{PRIVOXY_PORT}" in line:
            privoxy_pids.add(pid)
        elif "->127.0.0.1:" not in line:
            # external ESTABLISHED (не localhost) — codex идёт напрямую. Track per-PID.
            external_pids.add(pid)

    # 4. Классификация по комбинации множеств. Любая direct-сессия при SOCKS-сессии → mixed
    # (multi-session-утечка, которую probe должен ловить — #120/#121 C2).
    def _fmt(status, **kw):
        parts = []
        if kw.get("socks"):
            parts.append(f"10808 (PID {','.join(sorted(kw['socks']))})")
        if kw.get("privoxy"):
            parts.append(f"8118 (PID {','.join(sorted(kw['privoxy']))})")
        if kw.get("external"):
            parts.append(f"direct (PID {','.join(sorted(kw['external']))})")
        return ", ".join(parts)

    has_good = bool(socks_pids)
    has_bad = bool(privoxy_pids or external_pids)
    if has_good and has_bad:
        return {"status": "mixed", "source": "runtime",
                "detail": (f"runtime: смешанные сессии — {_fmt('mixed', socks=socks_pids, privoxy=privoxy_pids, external=external_pids)}; "
                           f"перезапусти ломаную TUI (exec zsh -l)")}
    if socks_pids:
        return {"status": "ok", "source": "runtime",
                "detail": f"runtime: codex через SOCKS5 10808 (PID {','.join(sorted(socks_pids))})"}
    if privoxy_pids and not external_pids:
        return {"status": "warn", "source": "runtime",
                "detail": (f"runtime: codex через privoxy 8118 — long-lived WS порвётся (#120); "
                           f"перезапусти TUI в новом терминале (exec zsh -l). PID {','.join(sorted(privoxy_pids))}")}
    if external_pids and not privoxy_pids:
        return {"status": "down", "source": "runtime",
                "detail": f"runtime: codex идёт напрямую (external IP, без прокси) — PF/провайдер режет. PID {','.join(sorted(external_pids))}"}
    if privoxy_pids and external_pids:
        # оба плохих, но без SOCKS — классифицируем как down (хуже warn).
        return {"status": "down", "source": "runtime",
                "detail": f"runtime: codex через privoxy 8118 + direct — нет SOCKS-маршрута. PID {_fmt('down', privoxy=privoxy_pids, external=external_pids)}"}
    return {"status": "unknown", "source": "runtime",
            "detail": f"runtime: codex запущен (PID {','.join(sorted(pids))}), но нет активных сокетов (idle)"}


# ============================ #129: endpoint-override detection ============================

_DEFAULT_ANTHROPIC_HOST = "api.anthropic.com"


def _read_endpoint_config():
    """Читает ANTHROPIC_BASE_URL + NO_PROXY из всех источников (#129).

    Источники (по приоритету): shell env → ~/.claude/settings.json env → launchctl getenv.
    Возвращает {base_url, no_proxy, source}. Не бросает.
    """
    import claude_proxy
    # settings.json env
    data = claude_proxy._load()
    env = data.get("env", {}) if isinstance(data, dict) else {}
    base = os.environ.get("ANTHROPIC_BASE_URL", "") or env.get("ANTHROPIC_BASE_URL", "")
    no_proxy = os.environ.get("NO_PROXY", "") or env.get("NO_PROXY", "")
    no_proxy += "," + (os.environ.get("no_proxy", "") or env.get("no_proxy", ""))
    source = "shell" if os.environ.get("ANTHROPIC_BASE_URL") else (
        "settings.json" if env.get("ANTHROPIC_BASE_URL") else "default")
    return {"base_url": base, "no_proxy": no_proxy, "source": source}


def _endpoint_override_check():
    """Детектит ANTHROPIC_BASE_URL override + NO_PROXY masking (#129).

    Если BASE_URL ≠ дефолт (api.anthropic.com) → info (WARN).
    Если домен в NO_PROXY → info «CC ходит напрямую, прокси/туннель-проверки нерелевантны».
    Урок #127: doctor был слеп к endpoint-override → ложный SOCKS5-тест.
    """
    cfg = _read_endpoint_config()
    base = cfg["base_url"]
    if not base or _DEFAULT_ANTHROPIC_HOST in base:
        return {"status": "ok", "detail": f"стандартный endpoint ({_DEFAULT_ANTHROPIC_HOST})"}
    host = (urlparse(base).hostname or "").lower()
    no_proxy = cfg["no_proxy"]
    in_no_proxy = any(
        h.strip() and (host == h.strip() or host.endswith("." + h.strip()))
        for h in no_proxy.split(",")
    )
    if in_no_proxy:
        return {"status": "info",
                "detail": f"endpoint override: {base} (в NO_PROXY → CC ходит напрямую, "
                          f"прокси/туннель-проверки нерелевантны)"}
    return {"status": "info", "detail": f"endpoint override: {base} (нестандартный endpoint)"}


def check_all(*, active_claude=False):
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
    if active_claude:
        active = _claude_transport_probe()
        active_check = {"name": "Claude Code transport (real CLI)",
                        "ok": active["status"] == "ok", "detail": active["detail"]}
        if active["status"] == "unknown":
            active_check["info"] = True
        checks.append(active_check)
    # endpoint-override (#129): WARN если ANTHROPIC_BASE_URL не стандартный
    eo = _endpoint_override_check()
    eo_check = {"name": "endpoint (ANTHROPIC_BASE_URL)", "ok": True, "detail": eo["detail"]}
    if eo["status"] == "info":
        eo_check["info"] = True
    checks.append(eo_check)
    # Codex-маршрут (#120): warn (privoxy 8118) — driver degraded (WS порвётся); down — driver;
    # mixed — driver (часть сессий ломаные); unknown (codex не запущен / lsof-timeout / idle) — info-only,
    # не роняет вердикт (как claude-proxy). ok — driver (всё ок).
    cx = _codex_proxy_probe()
    cx_check = {"name": "codex-proxy (маршрут TUI)",
                "ok": cx["status"] == "ok", "detail": cx["detail"]}
    if cx["status"] == "unknown":
        cx_check["info"] = True
    elif cx["status"] == "warn":
        cx_check["ok"] = False  # privoxy-сессия — degraded, но не «всё мертво»
    checks.append(cx_check)
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
        # info-only check (например claude-proxy когда CC не запущен) — ℹ️, не ❌: он не роняет
        # вердикт и не означает сбой, просто «не применимо сейчас».
        mark = "ℹ️" if c.get("info") else ("✅" if c["ok"] else "❌")
        detail = f" ({c['detail']})" if c.get("detail") else ""
        print(f"  {mark} {c['name']}{detail}")
    if result["status"] != "ok":
        print("\nЧто проверить:")
        failed_names = " ".join(c["name"] for c in result["checks"] if not c["ok"] and not c.get("info"))
        if "privoxy" in failed_names or "xray" in failed_names:
            print("  • brew services restart xray privoxy  (или srouter install)")
        if "туннель" in failed_names:
            print("  • туннель: проверь узел (srouter status / дашборд nodes), возможно узел недоступен")
        if "dashboard" in failed_names:
            print("  • дашборд: srouter restart")
        if "claude-proxy" in failed_names:
            print("  • Claude Code proxy: включи в дашборде (карточка Claude Code proxy) и ПЕРЕЗАПУСТИ Claude Code")
        if "Claude Code transport" in failed_names:
            print("  • Claude Code transport: используй HTTP bridge http://127.0.0.1:8118; "
                  "SOCKS TCP-соединение само по себе не доказывает работу API")
        if "codex-proxy" in failed_names:
            print("  • Codex TUI: перезапусти в НОВОМ терминале (exec zsh -l) — старая сессия не подхватила SOCKS5;")
            print("    через privoxy 8118 long-lived WS рвётся (#120); нужен SOCKS5 10808 (~/bin/codex)")


def cmd_watchdog():
    """Один прогон watchdog'а (запускается launchd раз в ~20с).

    Нотификация только при ПЕРЕХОДЕ состояния (ok→down — громко, down→ok — тихо), не при каждом
    прогоне — чтобы не спамить. State в WATCHDOG_STATE (/tmp).

    Split-route НЕ делается тут — это ответственность ppp-hook (/etc/ppp/ip-up, мгновенно при VPN
    up, от root без osascript). Watchdog только детектит падение туннеля и нотифицирует. Если
    ppp-hook не сработал (utun-VPN) — пользователь видит нотификацию и手动но ensure-split-route-root.
    """
    result = check_all(active_claude=False)
    is_ok = result["status"] == "ok"
    try:
        was_ok = WATCHDOG_STATE.exists() and WATCHDOG_STATE.read_text().strip() == "ok"
    except Exception:
        was_ok = False

    if not is_ok and was_ok:
        # Переход ok→down — кричим громко.
        failed = ", ".join(c["name"] for c in result["checks"] if not c["ok"] and not c.get("info"))
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
    result = check_all(active_claude=True)
    _print_report(result)
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
