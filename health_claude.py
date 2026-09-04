"""Health-пробы для Claude Code: runtime-маршрут (lsof), real CLI transport probe (#127).

Извлечено из health.py (issue #158 — разбиение крупного файла на модули по обязанностям).
health.py остаётся тонким фасадом: `from health_claude import *` ре-экспортирует все публичные
имена (канон star-import-reexport-contract) — существующие `health.<name>` и monkeypatch на
`health` module продолжают работать без изменений.
"""
from pathlib import Path
import json
import logging
import os
import shutil
import tempfile
from urllib.parse import urlparse

import sys_probe
import proxy_config_contract as _contract
from health_constants import _PROXY, PRIVOXY_PORT, XRAY_PORT

import health as _health_facade  # noqa: E402 — резолвит intra-module вызовы через health для monkeypatch (канон #158)

_log = logging.getLogger("srouter.health")

# star-import re-export (канон star-import-reexport-contract) — см. health_probes.py докстринг __all__.
__all__ = [
    "_is_claude_code_comm", "_claude_code_pids", "_claude_proxy_probe",
    "_find_claude_binary", "_has_expected_api_401", "_has_api_retry",
    "_claude_transport_once", "_configured_claude_proxy", "_claude_transport_probe",
    "_proxy_env_consistency",
    "CLAUDE_TRANSPORT_TIMEOUT", "CLAUDE_API_BASE_URL", "CLAUDE_DUMMY_API_KEY",
    "CONTROL_PROBE_TIMEOUT",
]

# Абсолютные пути: launchd/GUI PATH их не содержит (канон проекта).
LSOF = "/usr/sbin/lsof"
PS = "/bin/ps"

# Real Claude Code transport probe is doctor-only: failed proxy negotiation may spend several
# seconds in retries. Dashboard /health и watchdog остаются на lightweight passive checks.
# 20s (не 8s): эмпирически (2026-08-31) CLI init до первой строки api_retry занимает нестабильно
# 3.4-8+ сек (холодный старт с изолированным HOME/CLAUDE_CONFIG_DIR), а CLI не завершается сам
# после успешного 401 — уходит в retry-backoff (до 10 попыток). subprocess.run(timeout=...)
# ждёт завершения процесса, а не первой подходящей строки stdout — при 8s часть прогонов
# убивались раньше, чем 401 успевал попасть в захваченный буфер (ложный ❌ при живом канале).
CLAUDE_TRANSPORT_TIMEOUT = 20
CLAUDE_API_BASE_URL = "https://api.anthropic.com"
CLAUDE_DUMMY_API_KEY = "sk-ant-srouter-transport-probe-invalid"


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
    """Structured 401 от API — положительный transport proof (ответ реально дошёл).

    Два ключа, потому что формат stream-json разошёлся по версиям CLI: живой Claude Code
    2.1.x пишет error_status внутри строки api_retry, а исходный детектор (#127) искал
    api_error_status, которого CLI не выдаёт — успешная ветка была недостижима ПРИ ЛЮБОМ
    состоянии сети, и здоровый транспорт печатался как "Connection error / timeout".
    Сравниваем строго с 401: error_status=null (мёртвый прокси — контрольный замер на
    порту 9) НЕ должен пройти как успех, иначе проба перестанет отличать живой канал.
    """
    for line in output.splitlines():
        try:
            payload = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        for key in ("api_error_status", "error_status"):
            if payload.get(key) == 401:
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
    claude = _health_facade._find_claude_binary()
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
    except ImportError as exc:
        _log.debug("claude_proxy недоступен: %s — proxy считается не настроенным", exc)
        return ""


def _proxy_env_consistency():
    """Консистентность прокси-env Claude Code (issue #331). {status: ok|warn|unknown, detail}.

    Инвариант: managed CC-прокси ВКЛ (claude_proxy.enable) ⇒ SOCKS-плечо нейтрализовано
    (ALL_PROXY/all_proxy="" в settings.json). Нарушение = протечка: launchctl gui-домен
    (srouter-codex-env.sh) ставит ALL_PROXY/all_proxy=socks5h://...:10808 во все GUI-процессы,
    сессия CC наследует ОБА плеча → pip/requests через select_proxy маппят 'all' на ВСЕ схемы →
    SOCKSProxyManager → TypeError PoolKey key_proxy_ssl_context. Чистый живой env текущего
    процесса НЕ опровергает протечку (зависит от того, откуда запущен doctor) — решает
    settings-инвариант, живой env лишь иллюстрирует detail (канон verify-dont-guess).

    state unknown (битый settings.json, #307) / foreign (чужой HTTPS_PROXY) — outside
    контракта → unknown, не угадываем. mixed (наш ключ + чужой ключ) — оценивается: часть
    нашего прокси активна → neutral-инвариант применим, warn честный (review #338: симметрия
    out-of-contract семантики — foreign → unknown, mixed → evaluate). claude_proxy.status()
    не бросает (контракт); local import — fail-soft граница health (как
    _configured_claude_proxy). Без сети, не бросает.
    """
    try:
        import claude_proxy
        st = claude_proxy.status()
    except ImportError as exc:
        _log.debug("claude_proxy недоступен: %s — консистентность env не определить", exc)
        return {"status": "unknown", "detail": f"claude_proxy недоступен: {exc}"}
    state = st.get("state")
    if state == _contract.UNKNOWN:
        return {"status": "unknown",
                "detail": "settings.json нечитаем — консистентность прокси-env не определить (issue #307)"}
    if state == _contract.FOREIGN:
        return {"status": "unknown",
                "detail": "чужой HTTPS_PROXY (#307) — env вне контракта srouter, не оценивается"}
    # mixed: falling through осознанно — см. docstring (часть нашего прокси активна).
    if not st.get("enabled"):
        return {"status": "ok", "detail": "CC-прокси выключен — нейтрализация all_proxy не требуется"}
    if st.get("socks_neutralized"):
        return {"status": "ok",
                "detail": "SOCKS-плечо (all_proxy) нейтрализовано — privoxy единственное плечо CC"}
    live = [f"{key}={os.environ[key]}" for key in ("ALL_PROXY", "all_proxy") if os.environ.get(key)]
    leaked = f"; в env сейчас: {', '.join(live)}" if live else \
             "; в env этого процесса не видно (зависит от источника запуска doctor)"
    return {
        "status": "warn",
        "detail": ("SOCKS-плечо xray (ALL_PROXY/all_proxy из launchctl) не нейтрализовано в "
                   f"settings.json{leaked} — pip/requests падают (TypeError PoolKey, issue #331). "
                   "Фикс: 'srouter install' (enable ставит ALL_PROXY=\"\"), разово: "
                   "export ALL_PROXY= all_proxy="),
    }


# Control-проба (HTTP bridge) запускается только когда сконфигурированный SOCKS уже упал —
# это диагностика уже сломанного пути, не решающая проверка. Codex cycle-review (PR #321):
# без отдельного (более короткого) бюджета оба вызова _claude_transport_once по умолчанию
# используют CLAUDE_TRANSPORT_TIMEOUT (20s) — worst-case одного doctor-прогона вырастал до
# ~40s. CONTROL_PROBE_TIMEOUT короче: control нужен лишь чтобы подтвердить/опровергнуть "HTTP
# bridge жив, а SOCKS — нет", 401 там либо приходит быстро, либо путь тоже мёртв.
CONTROL_PROBE_TIMEOUT = 10


def _claude_transport_probe(proxy=None):
    """Doctor-only active proof. Для failed SOCKS запускает известный HTTP control."""
    configured = proxy if proxy is not None else _configured_claude_proxy()
    if not configured:
        return {"status": "unknown", "proxy": "", "api_status": None,
                "error": "proxy is not configured", "detail": "Claude Code proxy не настроен"}

    result = _health_facade._claude_transport_once(configured)
    scheme = urlparse(configured).scheme.lower()
    if result["status"] != "down" or scheme not in {"socks", "socks5", "socks5h"}:
        return result

    control = _health_facade._claude_transport_once(_PROXY, timeout=CONTROL_PROBE_TIMEOUT)
    detail = f"configured proxy {configured}: {result['detail']}; HTTP control {_PROXY}: {control['detail']}"
    if control["status"] == "ok":
        detail += "; configured SOCKS path is unusable — configure Claude Code to use the HTTP bridge"
    result = dict(result)
    result["detail"] = detail
    result["control"] = control
    return result
