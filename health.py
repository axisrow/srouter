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
import privoxy_system

# Абсолютные пути: launchd/GUI PATH их не содержит (канон проекта).
CURL = "/usr/bin/curl"
LSOF = "/usr/sbin/lsof"
PS = "/bin/ps"
OSASCRIPT = "/usr/bin/osascript"
LAUNCHCTL = "/bin/launchctl"

# Прокси = privoxy (8118). Берём из dashboard_common если доступен; fallback на хардкод,
# чтобы модуль не падал в среде без srouter_config (как git_proxy/claude_proxy).
try:
    from dashboard_common import HTTP_PROXY_URL as _PROXY  # http://127.0.0.1:8118
    # Порты компонентов стека — единый источник dashboard_common (issue #155).
    from dashboard_common import PRIVOXY_PORT, XRAY_SOCKS_PORT as XRAY_PORT
except Exception:
    _PROXY = "http://127.0.0.1:8118"
    # Fallback на то же каноническое значение. Ветка унаследована от канона (git_proxy/
    # claude_proxy); сегодня SystemExit от dashboard_common в среде без srouter_config
    # пробивает except Exception, поэтому health всё равно требует конфиг — но значения
    # здесь держат единый литерал, а не расходящийся хардкод. Маркер canonical-fallback-port
    # — tests/test_proxy_constants.py пропускает как осознанный fallback, не свежий дубликат.
    PRIVOXY_PORT = 8118  # canonical-fallback-port
    XRAY_PORT = 10808  # canonical-fallback-port

DASHBOARD_PORT = 8787

# Эндпоинты туннеля для проверки — ДВА таргета, как probe_tunnel (dashboard_network): origin-5xx
# одного вендора (Anthropic лежит, но канал жив) не должен читаться как «туннель упал».
TUNNEL_TARGETS = ("https://api.anthropic.com/", "https://api.openai.com/")

# State watchdog'а (переход ok→down, чтобы не спамить). /tmp не переживает ребут — приемлемо:
# после ребута fresh state, первый прогон без нотификации если уже down.
WATCHDOG_STATE = Path("/tmp/srouter-watchdog.last")
WATCHDOG_NOTIFY_LOG = Path.home() / "Library" / "Logs" / "srouter-watchdog.notify.log"
WATCHDOG_LIFECYCLE_STATE = Path("/tmp/srouter-watchdog.launchd.json")
WATCHDOG_LIFECYCLE_LOG = Path.home() / "Library" / "Logs" / "srouter-watchdog.lifecycle.jsonl"

# Real Claude Code transport probe is doctor-only: failed proxy negotiation may spend several
# seconds in retries. Dashboard /health and watchdog keep using lightweight passive checks.
CLAUDE_TRANSPORT_TIMEOUT = 8
CLAUDE_API_BASE_URL = "https://api.anthropic.com"
CLAUDE_DUMMY_API_KEY = "sk-ant-srouter-transport-probe-invalid"


def _port_up(port):
    """Слушает ли кто-то TCP порт (быстро, без сети). True/False."""
    if port == PRIVOXY_PORT and privoxy_system.protection_present():
        # macOS скрывает fd system-daemon пользователя `nobody` от обычного `lsof`, поэтому после
        # #122 lsof даёт ложный down. Loopback connect проверяет именно доступность 8118 без sudo.
        return sys_probe.port_open("127.0.0.1", port, timeout=0.5)
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


def _claude_code_pids():
    """CC PID'ы через `ps -axo pid=,comm=` (#143 — общий источник для runtime env-чека).

    Переиспользует _is_claude_code_comm (один критерий CC-процесса). Возвращает список PID-строк,
    [] если CC не запущен ИЛИ ps-timeout. Fail-soft: любой сбой ps → []. (Тот же парсинг, что в
    _claude_proxy_probe:145-155 — line.split(None,1) сохраняет пробелы в comm-пути.)
    НЕ трогает _claude_proxy_probe — там своя проверка timeout для двух разных detail-сообщений
    («timeout ps» vs «CC не запущен»), которые здесь схлопываются в один пустой результат.
    """
    r = sys_probe.run([PS, "-axo", "pid=,comm="], timeout=3)
    if r.get("timeout"):
        return []
    pids = []
    for line in (r.get("out") or "").splitlines():
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        pid_s, comm = parts[0].strip(), parts[1].strip()
        if pid_s.isdigit() and _is_claude_code_comm(comm):
            pids.append(pid_s)
    return pids


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
    (down). ps eww env ЧУЖОГО/системного codex-процесса на macOS не читается (права) → классификация по
    lsof-сокетам, как у claude-proxy. (Для same-UID CC env читается — см. #143 _read_runtime_endpoint_config;
    здесь lsof остаётся источником, т.к. codex-binary часто запущен под другим контекстом/правами.)

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


# ============================ #145: установленные codex/claude-code binary на диске ============================
# Дополняет runtime-probes (lsof по ЖИВЫМ proc) инвентаризацией ДИСКА. Несколько версий — ранний
# сигнал конфликта (#135 desktop-proxy-vs-managed-codex-socks5-conflict), но НЕ сбой стека → info-only
# (как claude-proxy когда CC не запущен). Doctor показывает картину, не угадывает за пользователя.

# Маркер srouter-wrapper в ~/bin/codex (первая строка шаблона srouter-codex-cli-wrapper.sh).
# Совпадает с CODEX_WRAPPERS[0] marker в srouter.py (канон: один источник правды для маркера).
_CODEX_WRAPPER_MARKER = "# srouter: codex CLI wrapper (managed)"

# Which(1) с -a печатает ВСЕ совпадения в PATH; абсолютные пути — только строки, начинающиеся с /
# (на zsh `which -a codex` печатает shell-функцию `codex () {...}` ПЕРЕД binary — её отбрасываем).
WHICH = "/usr/bin/which"
NPM = "/opt/homebrew/bin/npm"  # абсолютный путь: launchd/GUI PATH его не содержит (канон)


def _codex_wrapper_path():
    """Путь к codex-wrapper в ~/bin (динамически, для моков Path.home — канон srouter.py:290)."""
    return Path.home() / "bin" / "codex"


def _which_all(name):
    """`which -a <name>` → список абсолютных путей. Отбрасывает shell-функции/aliases (не начинаются с /).
    Не бросает (fail-soft: timeout/нет which → пустой список)."""
    r = sys_probe.run([WHICH, "-a", name], timeout=3)
    if r.get("timeout"):
        return []
    paths = []
    for line in (r.get("out") or "").splitlines():
        line = line.strip()
        # абсолютный путь = кандидат (zsh-функция/alias/описание — пропускаем).
        if line.startswith("/"):
            paths.append(line)
    return paths


def _binary_version(path):
    """`<path> --version` → первая непустая строка (версия). Пусто если не запустился. Не бросает."""
    r = sys_probe.run([path, "--version"], timeout=4)
    if r.get("timeout"):
        return ""
    out = (r.get("out") or "").strip()
    if not out:
        out = (r.get("err") or "").strip()
    return out.splitlines()[0].strip()[:120] if out else ""


def _is_srouter_codex_wrapper(path):
    """Файл path — наш srouter-wrapper? Путь == ~/bin/codex И маркер в содержимом (первая строка шаблона).
    Не полагается только на путь: чужой wrapper в ~/bin/codex без маркера — НЕ наш (regression-гвард).
    """
    try:
        if path == str(_codex_wrapper_path()):
            return _CODEX_WRAPPER_MARKER in Path(path).read_text(encoding="utf-8")
        return False
    except OSError:
        return False


def _codex_provenance(path):
    """Provenance codex-binary по его расположению: npm / homebrew / usr-local / bin / path.
    НЕ утверждает «обёрнут srouter» — это решает _is_srouter_codex_wrapper (по маркеру, не по пути),
    поэтому ~/bin/codex без маркера = provenance 'bin' (чужой/устаревший wrapper), не 'srouter-wrapper'."""
    p = str(path)
    if "/lib/node_modules/" in p or p.endswith(".js"):
        return "npm"
    if "/opt/homebrew/" in p:
        return "homebrew"
    if "/usr/local/bin/" in p:
        return "usr-local"
    if p == str(_codex_wrapper_path()):
        return "bin"
    return "path"


def _claude_provenance(path):
    """Provenance claude-code по расположению: CLI / GUI app / version-runner."""
    p = str(path)
    if "/versions/" in p:
        return "version-runner"
    if "/ClaudeCode.app" in p:
        return "gui-app"
    return "cli"


def _scan_codex_binaries():
    """Найти ВСЕ codex-binary на диске. Источники: which -a, homebrew-paths, ~/bin wrapper,
    npm global root (@openai/codex/bin/codex.js), brew-cask. Дедуп по нормализованному пути.
    Каждый: {path, provenance, version, wrapped}. Не бросает (fail-soft)."""
    candidates = []
    # 1. which -a codex (все в PATH, включая ~/bin/codex wrapper).
    candidates.extend(_which_all("codex"))
    # 2. well-known homebrew/standalone (Apple Silicon / Intel).
    for cand in ("/opt/homebrew/bin/codex", "/usr/local/bin/codex"):
        if Path(cand).is_file():
            candidates.append(cand)
    # 3. srouter-wrapper ~/bin/codex (явно — который() может не вернуть, если ~/bin не в PATH пробы).
    wrapper = str(_codex_wrapper_path())
    if Path(wrapper).is_file():
        candidates.append(wrapper)
    # 4. npm global root (@openai/codex) — отдельный источник (which может не показать .js).
    npm_r = sys_probe.run([NPM, "root", "-g"], timeout=4)
    if not npm_r.get("timeout"):
        npm_root = (npm_r.get("out") or "").strip()
        if npm_root:
            npm_codex = str(Path(npm_root) / "@openai" / "codex" / "bin" / "codex.js")
            if Path(npm_codex).is_file():
                candidates.append(npm_codex)
    # 5. brew-cask codex (отдельный binary, не npm).
    brew_r = sys_probe.run(["/opt/homebrew/bin/brew", "list", "--cask"], timeout=5)
    if not brew_r.get("timeout") and "codex" in (brew_r.get("out") or ""):
        for cand in ("/opt/homebrew/Caskroom/codex",):
            if Path(cand).is_dir():
                candidates.append(cand)

    # Дедуп по нормализованному пути (один файл через два имени — один).
    seen = set()
    results = []
    for cand in candidates:
        try:
            norm = str(Path(cand).resolve())
        except OSError:
            norm = cand
        if norm in seen or not Path(cand).is_file():
            continue
        seen.add(norm)
        results.append({
            "path": cand,
            "provenance": _codex_provenance(cand),
            "version": _binary_version(cand),
            "wrapped": _is_srouter_codex_wrapper(cand),
        })
    return results


def _scan_claude_code_binaries():
    """Найти claude-code на диске: CLI (~/.local/bin/claude), GUI app, version-runners (versions/*).
    Переиспользует path-семантику _is_claude_code_comm (basename/versions), но на диске, не на proc.
    Каждый: {path, provenance, version, wrapped}. wrapped всегда False (CC не оборачиваем srouter).
    Не бросает."""
    home = Path.home()
    candidates = []
    # CLI (в PATH + well-known) — which может найти иGUI-pty-host, но CLI — основной.
    candidates.extend(_which_all("claude"))
    cli = str(home / ".local" / "bin" / "claude")
    if Path(cli).is_file():
        candidates.append(cli)
    # GUI app (bundle).
    app = home / ".local" / "share" / "claude" / "ClaudeCode.app"
    if app.is_dir():
        candidates.append(str(app))
    # version-runners (основной движок CC) — каждый каталог-версия = отдельный binary.
    versions_dir = home / ".local" / "share" / "claude" / "versions"
    if versions_dir.is_dir():
        try:
            for child in sorted(versions_dir.iterdir()):
                if child.is_file():
                    candidates.append(str(child))
        except OSError:
            pass

    seen = set()
    results = []
    for cand in candidates:
        try:
            norm = str(Path(cand).resolve())
        except OSError:
            norm = cand
        if norm in seen:
            continue
        seen.add(norm)
        # version: только для исполняемых файлов (не .app bundle).
        version = _binary_version(cand) if Path(cand).is_file() else ""
        results.append({
            "path": cand,
            "provenance": _claude_provenance(cand),
            "version": version,
            "wrapped": False,
        })
    return results


def _format_versions_detail(codex_bins, claude_bins):
    """Человекочитаемый detail для doctor: буллеты provenance + версия + бейдж обёрнут/нет (issue #145)."""
    lines = []
    if codex_bins:
        lines.append(f"codex: {len(codex_bins)} установлено")
        for b in codex_bins:
            badge = "обёрнут srouter" if b["wrapped"] else "НЕ обёрнут"
            ver = b["version"] or "версия неизвестна"
            lines.append(f"  • {b['provenance']} {ver} → {b['path']} ({badge})")
    else:
        lines.append("codex: не установлен")
    if claude_bins:
        lines.append(f"claude-code: {len(claude_bins)} установлено")
        for b in claude_bins:
            ver = b["version"] or ("версия в имени" if b["provenance"] == "version-runner" else "версия неизвестна")
            lines.append(f"  • {b['provenance']} {ver} → {b['path']}")
    else:
        lines.append("claude-code: не установлен")
    return "; ".join(lines)


def _privoxy_log_observability_check(layout=privoxy_system.DEFAULT_LAYOUT):
    """Observability privoxy-лога под protected-mode (#152): молчалив ли privoxy? logfile жив?

    privoxy #141 ставится БЕЗ директивы debug → logfile всегда пустой → не поймать флап к github
    через 8118. Чек показывает картину (как claude-proxy/versions): не роняет вердикт, WARN живёт
    в detail. Возвращает {status, detail}:
      status="ok"   — debug выкл (осознанно тихий, дефолт #141) ИЛИ включён и logfile пишет;
      status="warn" — debug включён, но logfile пустой (privoxy не пишет? rights/logrotate/level?);
      status="info" — config/logfile не читаются без sudo (права/отсутствие) — fail-soft, не гадаем.

    Канон: privacy-no-content-hash-on-disk (debug 1=URLs — помечаем как чувствительный), noisy-log-
    better-than-no-log (молчаливый privoxy = observability-дыра, подсвечиваем подсказку SROUTER_PRIVOXY_DEBUG=2).
    """
    try:
        text = layout.config_path.read_text(encoding="utf-8", errors="ignore")[:16384]
    except OSError:
        return {"status": "info",
                "detail": "privoxy config не читается без sudo (protected-mode) — observability недоступна"}
    # debug-уровень из live-конфига. _config_directives из privoxy_system: ключ→значение, skip comments.
    try:
        directives = privoxy_system._config_directives(text)
    except ValueError:
        directives = {}
    debug_raw = directives.get("debug", "0").strip()
    try:
        debug = int(debug_raw)
    except ValueError:
        debug = 0

    # logfile = logdir + "logfile logfile" (ProtectedLayout.log_dir / "logfile").
    logfile = layout.log_dir / "logfile"
    logfile_size = -1
    try:
        logfile_size = logfile.stat().st_size
    except OSError:
        pass  # не существует / не читается — учтём ниже

    if debug == 0:
        # Молчаливый (дефолт #141) — это осознанно, но observability-дыра при флапе. Подсказка уровня.
        return {"status": "ok",
                "detail": ("privoxy: debug выкл (молчаливый); для диагностики флапа/таймаутов — "
                           "SROUTER_PRIVOXY_DEBUG=2 (connections, приватно: без URL/body)")}

    sensitive = " (⚠ URLs — чувствительно: токены/query пишутся на диск)" if debug == 1 else ""
    if logfile_size == 0:
        return {"status": "warn",
                "detail": (f"privoxy: debug {debug} включён{sensitive}, но logfile пуст — "
                           f"privoxy не пишет? (rights/logrotate/level/sudo при rotate)")}
    if logfile_size > 0:
        return {"status": "ok",
                "detail": f"privoxy: debug {debug} включён{sensitive}; logfile {logfile_size} байт"}
    # logfile не существует/не читается, но debug включён — странно, но не driver.
    return {"status": "info",
            "detail": f"privoxy: debug {debug} включён{sensitive}, но logfile не читается (права/отсутствие)"}


def _installed_versions_check():
    """Инвентаризация codex/claude-code binary на ДИСКЕ + их версии + обёрнут ли srouter (#145).

    Дополняет runtime-probes (живые proc): показывает, СКОЛЬКО версий установлено и какая обёрнута.
    Info-only: несколько версий — ранний сигнал конфликта (#135), но НЕ сбой стека → не роняет status.
    Возвращает {status, detail, codex:[...], claude_code:[...]}:
      status="ok"      — что-то установлено (картина показана);
      status="unknown" — ничего не найдено (info-only «не установлено»).
    Не бросает (fail-soft: каждый источник изолирован try/except в sys_probe.run)."""
    try:
        codex_bins = _scan_codex_binaries()
    except Exception:
        codex_bins = []
    try:
        claude_bins = _scan_claude_code_binaries()
    except Exception:
        claude_bins = []
    detail = _format_versions_detail(codex_bins, claude_bins)
    if not codex_bins and not claude_bins:
        return {"status": "unknown", "detail": detail, "codex": [], "claude_code": []}
    return {"status": "ok", "detail": detail, "codex": codex_bins, "claude_code": claude_bins}


# ============================ #129: endpoint-override detection ============================

_DEFAULT_ANTHROPIC_HOST = "api.anthropic.com"


def _read_endpoint_config():
    """Читает ANTHROPIC_BASE_URL + NO_PROXY из всех источников (#129).

    Источники (по приоритету): shell env → ~/.claude/settings.json env → launchctl getenv.
    Managed/local/project settings scopes (Claude Code docs) — НЕ покрыты: srouter не имеет доступа
    к этим scope'ам из Doctor. Если ни один источник не задан → source="default" (предполагаем
    стандартный api.anthropic.com).
    Возвращает {base_url, no_proxy, source}. Не бросает.
    """
    import claude_proxy
    # settings.json env
    data = claude_proxy._load()
    env = data.get("env", {}) if isinstance(data, dict) else {}
    # launchctl getenv (gui-домен) — фолбэк если shell/settings пусты.
    lc_base = sys_probe.run(["/bin/launchctl", "getenv", "ANTHROPIC_BASE_URL"], timeout=3)
    lc_base_val = (lc_base.get("out") or "").strip() if not lc_base.get("timeout") else ""
    lc_noproxy = sys_probe.run(["/bin/launchctl", "getenv", "NO_PROXY"], timeout=3)
    lc_noproxy_val = (lc_noproxy.get("out") or "").strip() if not lc_noproxy.get("timeout") else ""
    base = os.environ.get("ANTHROPIC_BASE_URL", "") or env.get("ANTHROPIC_BASE_URL", "") or lc_base_val
    no_proxy = os.environ.get("NO_PROXY", "") or env.get("NO_PROXY", "") or lc_noproxy_val
    no_proxy += "," + (os.environ.get("no_proxy", "") or env.get("no_proxy", ""))
    source = ("shell" if os.environ.get("ANTHROPIC_BASE_URL")
              else "settings.json" if env.get("ANTHROPIC_BASE_URL")
              else "launchctl" if lc_base_val
              else "default")
    return {"base_url": base, "no_proxy": no_proxy, "source": source}


def _endpoint_override_check():
    """Детектит ANTHROPIC_BASE_URL override + NO_PROXY masking (#129).

    Если hostname BASE_URL = api.anthropic.com (exact match) → ok (стандартный).
    Иначе → info (WARN). Если домен в NO_PROXY → info «CC ходит напрямую».
    Урок #127: doctor был слеп к endpoint-override → ложный SOCKS5-тест.
    cycle-review #131 C2: exact hostname match (не substring — lookalike-атака).
    """
    cfg = _read_endpoint_config()
    base = cfg["base_url"]
    if not base:
        return {"status": "ok", "detail": f"стандартный endpoint ({_DEFAULT_ANTHROPIC_HOST})"}
    host = (urlparse(base).hostname or "").lower().rstrip(".")
    if host == _DEFAULT_ANTHROPIC_HOST:
        return {"status": "ok", "detail": f"стандартный endpoint ({_DEFAULT_ANTHROPIC_HOST})"}
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


# ============================ #143: runtime env живого CC-процесса (ps eww) ============================
# Сценарий #143: CC запустился с ANTHROPIC_BASE_URL / ANTHROPIC_DEFAULT_*_MODEL override; затем
# пользователь сбросил settings.json/shell/launchctl на стандартные, а ЖИВОЙ процесс сохранил env.
# Doctor читает файлы (_read_endpoint_config, #129) → видит «стандартный endpoint», а CC реально
# ходит на подменённый сервер. Файлы слепы к runtime-override — нужно env ЖИВОГО процесса.
# На macOS `ps eww -p <pid>` читает env процесса ТОГО ЖЕ UID (эмпирически подтверждено: живой CC
# отдаёт ANTHROPIC_BASE_URL=api.z.ai + ANTHROPIC_DEFAULT_*_MODEL=glm-*). Чужой/системный UID →
# пустой вывод (fail-soft). НЕ противоречит докстрингу _codex_proxy_probe (:369 уточнён): там env
# чужого codex-процесса не читается → lsof-классификация; здесь — same-UID CC.

# Regex извлекает ANTHROPIC_* vars из вывода `ps eww`. Env разделяется ПРОБЕЛОМ (не \012); [^ ]*
# обрезает значение до следующего пробела. Ключи — только ANTHROPIC_* (наш trust boundary).
_RUNTIME_ENV_RE = re.compile(r"(ANTHROPIC_[A-Z_]+)=([^ ]*)")
# Каждая строка процесса в `ps eww` начинается с PID-цифр (`^[0-9]+ `); заголовок отбрасывается.
# Per-PID секционирование (см. _read_runtime_endpoint_config) — не слить env разных процессов.
_PID_LINE_RE = re.compile(r"^\s*(\d+)\s")


def _read_runtime_endpoint_config():
    """Читает env ЖИВОГО CC-процесса через `ps eww` (#143), per-PID.

    Возвращает {per_pid, pids, readable}:
      - readable=False, pids=[]   — CC не запущен (ps -axo пуст) ИЛИ ps-timeout;
      - readable=False, pids=[..] — CC запущен, но ps eww пуст/timeout/нет ANTHROPIC_* (чужой
        UID/sandbox — PID сохранены для forensics в detail чека);
      - readable=True, per_pid={pid: {KEY: value}} — env прочитан ПО PID'ам.
    per_pid: {pid: {ANTHROPIC_*: value}} для каждого CC PID (включая секреты — doctor доверяет
    тому же UID; фильтрацию секретов делает чек, НЕ эта функция). Per-PID, не merged — иначе
    dict(findall) перезаписал бы дубликаты ключей и ОДИН override-процесс маскировался бы
    standard-процессом (cycle-review Codex: false-negative ровно в сценарии #143 — несколько
    живых CC-сессий штатны). Один ps eww батчем; вывод секционируется по строкам `^[0-9]+ `.
    """
    pids = _claude_code_pids()
    if not pids:
        return {"per_pid": {}, "pids": [], "readable": False}
    # Один ps eww на ВСЕ PID батчем (запятая, как lsof в _claude_proxy_probe). ps eww отдаёт
    # каждую строку процесса с PID в начале — секционируем per-PID, не одним dict().
    r = sys_probe.run([PS, "eww", "-p", ",".join(pids)], timeout=3)
    if r.get("timeout") or not (r.get("out") or "").strip():
        return {"per_pid": {}, "pids": pids, "readable": False}
    per_pid = {}
    cur_pid, cur_lines = "", []
    for line in (r["out"] or "").splitlines():
        m = _PID_LINE_RE.match(line)
        if m:  # новая строка процесса — фиксируем предыдущую
            if cur_pid:
                per_pid[cur_pid] = dict(_RUNTIME_ENV_RE.findall("\n".join(cur_lines)))
            cur_pid, cur_lines = m.group(1), [line]
        elif cur_pid:
            cur_lines.append(line)  # продолжение env того же PID (маловероятно, но устойчиво)
    if cur_pid:
        per_pid[cur_pid] = dict(_RUNTIME_ENV_RE.findall("\n".join(cur_lines)))
    # НИ у одного PID нет ANTHROPIC_* (мусор/неполный env/чужой контекст) — evidence нет → НЕ
    # readable. Иначе чек дал бы ложный ok «стандартный endpoint» без proof (verify-dont-guess).
    if not any(per_pid.values()):
        return {"per_pid": {}, "pids": pids, "readable": False}
    return {"per_pid": per_pid, "pids": pids, "readable": True}


def _runtime_model_override_check():
    """Детектит env-override ЖИВОГО CC и расхождение runtime vs файлов doctor (#143).

    Возвращает {status, detail}. status:
      - "unknown" — CC не запущен / env не читается (fail-soft; info-only, как _claude_proxy_probe idle);
      - "ok"      — ВСЕ CC PID'ы на api.anthropic.com, без model-substitution, без расхождения с файлами;
      - "info"    — ХОТЯ БЫ ОДИН CC PID с override/substitution/расхождением.
    Per-PID агрегация: ЛЮБОЙ override-PID = unsafe runtime (стандартный процесс его НЕ маскирует —
    cycle-review Codex false-negative fix). Сигналы per-PID (накапливаются в detail):
      (a) runtime base_url override на нестандартный хост;
      (b) ANTHROPIC_DEFAULT_* присутствуют → slot-mapping модели подменён (даже при чистом base_url);
      (c) stale-process: runtime override есть, а файлы doctor ЧИСТЫ → ровно сценарий #143
          (живой CC держит override после сброса настроек);
      (d) runtime != files (PID и файлы на разных нестандартных endpoint'ах).
    Канон info-only: НЕ driver (как _endpoint_override_check) — картина для диагностики (#143 п.1+4).
    Security: detail выводит ТОЛЬКО base_url и ANTHROPIC_DEFAULT_* — никогда ANTHROPIC_API_KEY /
    ANTHROPIC_AUTH_TOKEN (doctor доверяет тому же UID, но логи/terminal не должны содержать секреты).
    """
    rt = _read_runtime_endpoint_config()
    if not rt["readable"]:
        detail = ("Claude Code не запущен" if not rt["pids"]
                  else f"env живого CC не читается (PID {','.join(rt['pids'])}) — возможно чужой UID/sandbox")
        return {"status": "unknown", "detail": detail}

    cfg = _read_endpoint_config()  # что видит doctor по файлам/сессии
    files_base = cfg["base_url"]
    files_host = (urlparse(files_base).hostname or "").lower().rstrip(".")
    files_clean = (not files_base) or files_host == _DEFAULT_ANTHROPIC_HOST

    signals = []
    ok_pids = []
    unreadable_pids = []  # PID без распарсенного env (per-process sandbox/permission/partial ps).
    for pid in rt["pids"]:
        env = rt["per_pid"].get(pid, {})
        if not env:
            # этого PID env не прочитан. Override-сигналов по нему нет, но и evidence «standard» тоже
            # нет — override-PID мог быть им (Codex c2: standard-PID не должен маскировать). Не ok.
            unreadable_pids.append(pid)
            continue
        runtime_base = env.get("ANTHROPIC_BASE_URL", "")
        runtime_host = (urlparse(runtime_base).hostname or "").lower().rstrip(".")
        model_keys = {k: v for k, v in env.items() if k.startswith("ANTHROPIC_DEFAULT_")}
        runtime_overridden = bool(runtime_base and runtime_host != _DEFAULT_ANTHROPIC_HOST)
        pid_signals = []
        if runtime_overridden:
            pid_signals.append(f"runtime endpoint: {runtime_base}")
        if model_keys:
            pairs = ", ".join(f"{k}={v}" for k, v in sorted(model_keys.items()))
            pid_signals.append(f"model substitution: {pairs}")
        if runtime_overridden and files_clean:
            pid_signals.append("stale process (override после сброса настроек, runtime != files)")
        if runtime_base and files_base and runtime_base != files_base:
            pid_signals.append(f"runtime != files ({runtime_base} vs {files_base})")
        if pid_signals:
            signals.append(f"PID {pid}: " + "; ".join(pid_signals))
        else:
            ok_pids.append(pid)

    pid_list = ",".join(rt["pids"])
    # Override приоритетнее (info). Но если override не найден и ХОТЯ БЫ ОДИН PID без evidence →
    # unknown: override-PID мог быть непрочитанным, а standard-PID его бы маскировал ложным ok
    # (verify-dont-guess: нет evidence для PID = не ok, Codex c2 false-negative fix). ok — только
    # когда ВСЕ PID прочитаны и standard.
    if not signals:
        if unreadable_pids:
            return {"status": "unknown",
                    "detail": (f"env не прочитан для PID {','.join(unreadable_pids)} "
                               f"(sandbox/права/partial ps) — override-PID мог быть непрочитанным; "
                               f"остальные standard: PID {','.join(ok_pids)}")}
        return {"status": "ok",
                "detail": f"runtime: стандартный endpoint, без model-substitution (PID {pid_list})"}
    detail = f"runtime override (PID {pid_list}): " + " | ".join(signals)
    extras = []
    if ok_pids:
        extras.append(f"остальные standard: PID {','.join(ok_pids)}")
    if unreadable_pids:
        extras.append(f"env не прочитан: PID {','.join(unreadable_pids)}")
    if extras:
        detail += " (" + "; ".join(extras) + ")"
    return {"status": "info", "detail": detail}




# ============================ #134: Desktop App proxy (launchctl getenv) ============================

# launchctl держит ТРИ прокси-ключа; Desktop App наследует все. Инцидент #127: SOCKS5 сидел в
# HTTP_PROXY (не HTTPS_PROXY) → doctor (читая только HTTPS_PROXY) сказал ✅. Обходим все три,
# НЕ угадывая selector приложения (он у Claude/Node/Electron разный) — показываем «как есть».
# NOTE: не то же что CODEX_LAUNCHCTL_ENV в srouter.py — там (key, SOCKS5-value)-пары для Codex
# install; здесь — диагностика Claude Desktop, другая семантика.
LAUNCHCTL_PROXY_KEYS = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY")

def _read_proxy_sources():
    """Читает Desktop App прокси (launchctl, все ключи) + CLI прокси (settings.json) — #134.

    Desktop App читает launchctl getenv (gui-домен), в отличие от CLI (settings.json). launchctl
    держит ТРИ ключа (LAUNCHCTL_PROXY_KEYS); инцидент #127 — SOCKS5 в HTTP_PROXY. Не угадываем
    приоритет приложения — собираем все найденные «как есть», классификацию делает _desktop_proxy_check.
    cli_proxy (settings.json HTTPS_PROXY) нужен для детекта расхождения CLI vs Desktop (issue #134 п.2) —
    один клиент может работать, другой быть сломан, а без сравнения doctor молчит (#127-класс инцидент).
    Возвращает {desktop_keys: {KEY: value}, cli_proxy: str}. Не бросает (fail-soft: timeout → пустой out,
    отфильтруется if val; import claude_proxy — local, сохраняет fail-soft границу health).
    """
    desktop_keys = {}
    for key in LAUNCHCTL_PROXY_KEYS:
        lc = sys_probe.run(["/bin/launchctl", "getenv", key], timeout=3)
        val = (lc.get("out") or "").strip()  # timeout → out="" → пропустится if val ниже
        if val:
            desktop_keys[key] = val
    try:
        import claude_proxy
        data = claude_proxy._load()
        env = data.get("env", {}) if isinstance(data, dict) else {}
        cli_proxy = env.get("HTTPS_PROXY", "") or os.environ.get("HTTPS_PROXY", "")
    except Exception:
        cli_proxy = ""
    return {"desktop_keys": desktop_keys, "cli_proxy": cli_proxy}


def _desktop_proxy_check():
    """Прокси Desktop App (launchctl getenv) — SOCKS5 в любом ключе → down (#127/#134).

    Не угадываем selector приложения (у Claude/Node/Electron разные). Для Claude SOCKS5 ломается
    везде (#127 fiasco), HTTP работает. SOCKS5 в любом launchctl-ключе — либо уже ломает, либо
    мина (вспыхнет при смене конфига) → down. Scheme-классификация через urlparse (эталон #127,
    не подстрока — иначе http://socks.example.com даст ложный down). detail перечисляет все
    найденные ключи «как есть».
    Расхождение settings.json (CLI) vs launchctl HTTPS_PROXY (Desktop) → warn (issue #134 п.2):
    один клиент может работать, другой сломан, а без этого сравнения doctor молчит (#127-класс).
    down (уже сломанный SOCKS5) важнее warn (потенциальное расхождение) — проверяется первым.
    """
    src = _read_proxy_sources()
    keys = src["desktop_keys"]
    cli_proxy = src.get("cli_proxy", "")
    if not keys:
        return {"status": "unknown",
                "detail": "launchctl proxy не задан — Desktop App идёт напрямую (ok для NO_PROXY-доменов, не защищён PF для остальных)"}
    # SOCKS-scheme в ЛЮБОМ ключе → down (Claude Code/Desktop App через SOCKS не умеют, #127).
    # urlparse по scheme, не подстрока — канон loose-validator (health.py:313).
    socks_keys = {k: v for k, v in keys.items()
                  if urlparse(v).scheme.lower() in {"socks", "socks5", "socks5h"}}
    if socks_keys:
        bad = ", ".join(f"{k}={v}" for k, v in socks_keys.items())
        return {"status": "down",
                "detail": f"SOCKS5 в launchctl ({bad}) — Desktop App UnsupportedProxyProtocol (#127)"}
    # Расхождение CLI (settings.json) vs Desktop (launchctl HTTPS_PROXY) — оба заданы и различны.
    desktop_https = keys.get("HTTPS_PROXY", "")
    if cli_proxy and desktop_https and cli_proxy != desktop_https:
        return {"status": "warn",
                "detail": f"CLI={cli_proxy}, Desktop={desktop_https} — расхождение прокси "
                          f"(один клиент может работать, другой — нет)"}
    # Только HTTP-прокси, без расхождения → ok, перечисляем все найденные ключи.
    found = ", ".join(f"{k}={v}" for k, v in keys.items())
    return {"status": "ok", "detail": f"Desktop App proxy (launchctl): {found}"}


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
    # Desktop App proxy (#134): SOCKS5 в launchctl = broken Desktop App; warn = CLI/Desktop
    # расхождение (driver degraded — реальный сигнал несоответствия, не info-only).
    dp = _desktop_proxy_check()
    dp_check = {"name": "desktop proxy (launchctl)", "ok": dp["status"] == "ok", "detail": dp["detail"]}
    if dp["status"] == "unknown":
        dp_check["info"] = True
    checks.append(dp_check)
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
    # Установленные codex/claude-code binary на диске (#145): инвентаризация, info-only ВСЕГДА
    # (несколько версий — ранний сигнал конфликта #135, не сбой стека). unknown (ничего не установлено)
    # тоже info — не роняет вердикт. Doctor показывает картину, не угадывает.
    # cycle-review round 1: disk inventory запускает npm/brew/which/<binary> --version — НЕ лёгкий,
    # выполняет arbitrary PATH-discovered binaries. check_all шарится между doctor (active_claude=True),
    # /health (dashboard.py:990 «Мгновенный, лёгкий») и watchdog (раз в ~20с). Инвентаризация —
    # ТОЛЬКО doctor-путь, иначе лёгкий healthcheck получит DoS-поверхность + overhead.
    if active_claude:
        # #143 runtime env живого CC: детект ANTHROPIC_BASE_URL/DEFAULT_*_MODEL override + stale-process
        # (живой CC держит override после сброса настроек — файлы doctor слепы). info-only (как
        # endpoint-override) — картина для диагностики (#143 п.1+4), НЕ driver. Под active_claude gate:
        # ps eww по живым PID + чтение env = overhead/поверхность, не для лёгкого /health/watchdog.
        rmo = _runtime_model_override_check()
        # info-only БЕЗУСЛОВНО (как _installed_versions_check/_privoxy_log_observability_check ниже):
        # диагностика подмены модели — картина, не сбой стека; ни ok, ни info, ни unknown не driver.
        rmo_check = {"name": "runtime env (ANTHROPIC_* живого CC)",
                     "ok": rmo["status"] == "ok", "info": True, "detail": rmo["detail"]}
        checks.append(rmo_check)
        iv = _installed_versions_check()
        iv_check = {"name": "версии (codex/claude-code на диске)",
                    "ok": True, "info": True, "detail": iv["detail"]}
        checks.append(iv_check)
        # Privoxy-log observability (#152): молчалив ли privoxy? debug включён? logfile пишет?
        # info-only (не driver) — картина для диагностики флапа к github через 8118; WARN в detail.
        plo = _privoxy_log_observability_check()
        plo_check = {"name": "privoxy-log (observability)",
                     "ok": plo["status"] != "warn", "info": True, "detail": plo["detail"]}
        checks.append(plo_check)
    drivers = [c for c in checks if not c.get("info")]
    all_ok = all(c["ok"] for c in drivers)
    any_ok = any(c["ok"] for c in drivers)
    status = "ok" if all_ok else ("degraded" if any_ok else "down")
    return {"status": status, "checks": checks}


def _notify(msg, sound="Glass"):
    """macOS-нотификация через osascript + audit trail в лог (#109).

    Логируем ВСЕГДА (даже если osascript не сработал) — audit trail «что пушалось и когда».
    osascript — best-effort (не роняет watchdog при сбое).
    """
    from datetime import datetime
    try:
        WATCHDOG_NOTIFY_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(WATCHDOG_NOTIFY_LOG, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} [{sound}] {msg}\n")
    except Exception:
        pass  # лог — best-effort
    try:
        sys_probe.run([OSASCRIPT, "-e",
                       f'display notification "{msg}" with title "srouter" sound name "{sound}"'],
                      timeout=5)
    except Exception:
        pass  # нотификация — best-effort, не роняет watchdog


def _launchd_field(output, key):
    """Первое scalar-поле из `launchctl print`; nested endpoint state не перетирает root state."""
    match = re.search(rf"^\s*{re.escape(key)}\s*=\s*(.*?)\s*;?\s*$", output or "", re.MULTILINE)
    return match.group(1) if match else None


def _launchd_int(output, key):
    value = _launchd_field(output, key)
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _launchd_job_snapshot(label, *, plist_path=None, domain=None):
    """Компактный forensic snapshot launchd job без домыслов о причине отсутствия.

    KeepAlive-restart сохраняет загруженный label и plist, но меняет pid/runs/last-exit. Внешний
    `bootout` даёт loaded=false; последующий `brew services start` обычно меняет plist mtime/inode и
    сбрасывает runs. Эта разница нужна для #132: строка startup banner сама по себе её не показывает.
    """
    domain = domain or f"gui/{os.getuid()}"
    if plist_path is None:
        if domain == "system":
            plist_path = Path("/Library/LaunchDaemons") / f"{label}.plist"
        else:
            plist_path = Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"
    else:
        plist_path = Path(plist_path)

    result = sys_probe.run(
        [LAUNCHCTL, "print", f"{domain}/{label}"],
        timeout=3,
    )
    output = result.get("out") or ""
    loaded = result.get("rc") == 0 and bool(output.strip())

    plist = {"exists": False, "mtime_ns": None, "inode": None}
    try:
        stat = plist_path.stat()
        plist = {"exists": True, "mtime_ns": stat.st_mtime_ns, "inode": stat.st_ino}
    except OSError:
        pass

    error = ""
    if not loaded:
        error = (result.get("err") or ("timeout" if result.get("timeout") else "not loaded"))[:240]

    return {
        "label": label,
        "domain": domain,
        "loaded": loaded,
        "state": _launchd_field(output, "state") if loaded else None,
        "pid": _launchd_int(output, "pid") if loaded else None,
        "runs": _launchd_int(output, "runs") if loaded else None,
        "last_exit_code": _launchd_field(output, "last exit code") if loaded else None,
        "last_terminating_signal": (
            _launchd_field(output, "last terminating signal") if loaded else None
        ),
        "plist": plist,
        "error": error,
    }


def _collect_launchd_lifecycle():
    """Privoxy снимается в фактическом domain; xray остаётся стабильным user-контролем."""
    protected = privoxy_system.protection_present()
    return {
        "privoxy": _launchd_job_snapshot(
            privoxy_system.SYSTEM_LABEL if protected else "homebrew.mxcl.privoxy",
            plist_path=(privoxy_system.DEFAULT_LAYOUT.launchdaemon_path if protected else None),
            domain=("system" if protected else None),
        ),
        "xray": _launchd_job_snapshot("homebrew.mxcl.xray"),
    }


def _record_watchdog_lifecycle():
    """Записать JSONL только при изменении launchd lifecycle; первый снимок — тихий baseline.

    Best-effort: forensic logging не меняет health status и никогда не роняет watchdog. Даже если
    stop/start целиком попал между watchdog ticks, изменение plist mtime/inode или pid/runs остаётся
    видимым в следующем снимке.
    """
    try:
        current = _collect_launchd_lifecycle()
    except Exception:
        return

    previous = None
    try:
        if WATCHDOG_LIFECYCLE_STATE.exists():
            previous = json.loads(WATCHDOG_LIFECYCLE_STATE.read_text(encoding="utf-8"))
    except Exception:
        previous = None

    if previous is not None and previous != current:
        try:
            from datetime import datetime

            WATCHDOG_LIFECYCLE_LOG.parent.mkdir(parents=True, exist_ok=True)
            event = {
                "timestamp": datetime.now().astimezone().isoformat(),
                "previous": previous,
                "current": current,
            }
            with open(WATCHDOG_LIFECYCLE_LOG, "a", encoding="utf-8") as log_file:
                log_file.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
        except Exception:
            pass

    try:
        WATCHDOG_LIFECYCLE_STATE.parent.mkdir(parents=True, exist_ok=True)
        WATCHDOG_LIFECYCLE_STATE.write_text(
            json.dumps(current, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )
    except Exception:
        pass


def _print_report(result):
    """Человекочитаемый отчёт check_all (для doctor). Вывод в stdout."""
    print(f"srouter health: {result['status'].upper()}\n")
    for c in result["checks"]:
        # info-only check: endpoint-override (WARN), claude-proxy idle (нейтрально).
        # ⚠️ — жёлтый треугольник (привлекает внимание, но не ❌): override/idle, а не «всё мертво».
        mark = "⚠️" if c.get("info") else ("✅" if c["ok"] else "❌")
        detail = f" ({c['detail']})" if c.get("detail") else ""
        print(f"  {mark} {c['name']}{detail}")
    if result["status"] != "ok":
        print("\nЧто проверить:")
        failed_names = " ".join(c["name"] for c in result["checks"] if not c["ok"] and not c.get("info"))
        if "privoxy" in failed_names:
            if privoxy_system.protection_present():
                print("  • Privoxy защищён: выполни `srouter privoxy status`, затем вручную "
                      "`srouter privoxy restart` (потребуется подтверждение)")
            else:
                print("  • privoxy: brew services restart privoxy  (или srouter install)")
        if "xray" in failed_names:
            print("  • xray: brew services restart xray  (или srouter install)")
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
    _record_watchdog_lifecycle()
    cur = result["status"]
    try:
        prev = WATCHDOG_STATE.read_text().strip() if WATCHDOG_STATE.exists() else ""
    except Exception:
        prev = ""

    # Exact-state transitions (#109 + cycle-review #133 C1):
    # Пуш при переходе ok/degraded → down (новое падение). Не пушить degraded→degraded (спам!).
    # Восстановление при down/degraded → ok.
    if cur == "down" and prev in ("ok", "degraded", ""):
        # Новое падение (ok→down, degraded→down, fresh→down).
        failed = ", ".join(c["name"] for c in result["checks"] if not c["ok"] and not c.get("info"))
        _notify(f"туннель/стек упал ({failed})", "Basso")
    elif cur == "ok" and prev in ("down", "degraded", ""):
        # Восстановление (down→ok, degraded→ok, fresh→ok не пушим — fresh = первый прогон).
        if prev in ("down", "degraded"):
            _notify("стек восстановлен", "Glass")
    # down→down, degraded→degraded, ok→degraded — молча (не спамим).
    # ok→degraded НЕ пушим (degraded — не «упал», просто «часть жива»).

    try:
        WATCHDOG_STATE.write_text(result["status"])
    except Exception:
        pass  # state — best-effort
    return 0 if cur == "ok" else 1


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
