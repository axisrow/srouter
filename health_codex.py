"""Health-пробы для Codex: runtime-маршрут (lsof), инвентаризация binary на диске, PF-изоляция.

Извлечено из health.py (issue #158 — разбиение крупного файла на модули по обязанностям).
health.py остаётся тонким фасадом: `from health_codex import *` ре-экспортирует все публичные
имена (канон star-import-reexport-contract) — существующие `health.<name>` и monkeypatch на
`health` module продолжают работать без изменений.
"""
from pathlib import Path
import logging
import re
import subprocess

import privoxy_system
import sys_probe
from health_constants import PRIVOXY_PORT, XRAY_PORT

import health as _health_facade  # noqa: E402 — резолвит intra-module вызовы через health для monkeypatch (канон #158)

_log = logging.getLogger("srouter.health")

# star-import re-export (канон star-import-reexport-contract) — см. health_probes.py докстринг __all__.
__all__ = [
    "_is_codex_app_comm", "_is_codex_binary_comm", "_codex_proxy_probe",
    "_codex_wrapper_path", "_which_all", "_binary_version", "_is_srouter_codex_wrapper",
    "_codex_provenance", "_claude_provenance", "_scan_codex_binaries", "_scan_claude_code_binaries",
    "_format_versions_detail", "_privoxy_log_observability_check", "_installed_versions_check",
    "_codex_isolation_check",
]

# Абсолютные пути: launchd/GUI PATH их не содержит (канон проекта).
LSOF = "/usr/sbin/lsof"
PS = "/bin/ps"
WHICH = "/usr/bin/which"
NPM = "/opt/homebrew/bin/npm"  # абсолютный путь: launchd/GUI PATH его не содержит (канон)

# codex-binary comm-паттерн. Матчит ОСНОВНОЙ codex-binary по BASENAME (независимо от способа установки):
#   basename "codex"                       — npm-vendor (.../bin/codex), standalone (~/.local/bin/codex)
#   basename "codex-<arch>-apple-darwin"   — Homebrew cask / release-binary
# НЕ матчит (исключает по basename):
#   moonbridge, browser_crashpad_handler, ChatGPT for Chrome, node (Codex.app helpers / .codex/plugins),
#   codex-code-mode-host (вспомогательный binary, не основной движок).
# cycle-review #121 C1: npm-only regex пропускал brew-cask/standalone → doctor ложно «codex не запущен».
# cycle 2 cleanup: общий substring 'codex' over-matched helpers → matcher по basename (точно).
_CODEX_BIN_RE = re.compile(r"(^|/)codex(?:-(?:aarch64|x86_64)-apple-darwin)?$")

# Issue #189: ChatGPT.app (com.openai.codex) бандлит свой Rust-binary по пути
# /Applications/ChatGPT.app/Contents/Resources/codex — basename 'codex' → МАТЧИТСЯ _CODEX_BIN_RE.
# Этот Rust app-server — основной WS-трафик к chatgpt.com, берёт прокси ТОЛЬКО из launchd gui-env
# (codenv), НЕ из CLI-shell-env → другой контекст, чем CLI codex (TUI/terminal). _codex_proxy_probe
# (TUI-чек) его НЕ учитывает; App-PID уходит в отдельный _codex_app_proxy_check (driver для gui-env).
# Разделение по path-сегменту .app/ (comm = полный путь): /ChatGPT.app/ или /Codex.app/ → App-context.
_CODEX_APP_PATH_RE = re.compile(r"/(?:ChatGPT|Codex)\.app/", re.IGNORECASE)


def _is_codex_app_comm(comm):
    """Codex.app/ChatGPT.app-bundled codex (Rust app-server, launchd-env контекст)?

    По path-сегменту .app/ в полном comm (ps -axo comm= отдаёт путь). App-PID — другой контекст
    прокси, чем CLI-codex: наследует launchd gui-env (codenv), а не shell-env. Детект нужен, чтобы
    _codex_proxy_probe (TUI/CLI-чек) исключил App-PID (иначе ложный mixed/down на нерелевантном PID —
    баг «❌ на VSCode PID 56748» #189). path-сегмент стабильнее bundle-id: comm не отдаёт signing_id,
    а /ChatGPT.app/ (com.openai.codex ребрендинг) и /Codex.app/ оба покрыты одним regex.
    """
    return bool(comm and _CODEX_APP_PATH_RE.search(comm))


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
    # Issue #189: делим на CLI-PID (TUI/terminal-контекст) и App-PID (ChatGPT.app launchd-контекст).
    # App-PID (Rust app-server, /ChatGPT.app/.../codex) — другой контекст прокси (codenv gui-env, не
    # shell-env) → уходит в отдельный _codex_app_proxy_check. Иначе App-PID direct (без codenv) +
    # CLI на SOCKS5 → ложный mixed; только-App direct → ложный down в TUI-чеке (баг «❌ на VSCode PID»).
    r = sys_probe.run([PS, "-axo", "pid=,comm="], timeout=3)
    if r.get("timeout"):
        return {"status": "unknown", "source": "n/a", "detail": "timeout ps"}
    cli_pids, app_pids = [], []
    for line in (r.get("out") or "").splitlines():
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        pid_s, comm = parts[0].strip(), parts[1].strip()
        if not (pid_s.isdigit() and _health_facade._is_codex_binary_comm(comm)):
            continue
        (app_pids if _health_facade._is_codex_app_comm(comm) else cli_pids).append(pid_s)
    if not cli_pids:
        # App-PID есть, но CLI/TUI-codex не запущен — это не TUI-сцена. App уходит в свой чек;
        # TUI-чек = unknown (info-only), не роняет вердикт (как claude-proxy когда CC не запущен).
        app_hint = (f" (App-codex PID {','.join(app_pids)} → см. codex-app-proxy check)"
                    if app_pids else "")
        return {"status": "unknown", "source": "n/a",
                "detail": f"codex CLI/TUI не запущен{app_hint}"}
    pids = cli_pids

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

# Маркер srouter-wrapper в ~/bin/codex-srouter (первая строка шаблона srouter-codex-cli-wrapper.sh).
# Совпадает с CODEX_WRAPPERS[0] marker в srouter.py (канон: один источник правды для маркера).
# Issue #169: wrapper файл переименован codex → codex-srouter, но МАРКЕР не менялся (идентифицирует
# «srouter-managed wrapper», не имя файла) → один и тот же маркер в health.py и srouter.py.
_CODEX_WRAPPER_MARKER = "# srouter: codex CLI wrapper (managed)"

# Which(1) с -a печатает ВСЕ совпадения в PATH; абсолютные пути — только строки, начинающиеся с /
# (на zsh `which -a codex` печатает shell-функцию `codex () {...}` ПЕРЕД binary — её отбрасываем).


def _codex_wrapper_path():
    """Путь к codex-wrapper в ~/bin/codex-srouter (динамически, для моков Path.home — канон srouter.py).
    Issue #169 rename: wrapper файл codex → codex-srouter (real binary по-прежнему зовётся codex)."""
    return Path.home() / "bin" / "codex-srouter"


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
    """Файл path — наш srouter-wrapper? Путь == ~/bin/codex-srouter И маркер в содержимом (первая строка шаблона).
    Не полагается только на путь: чужой wrapper в ~/bin/codex-srouter без маркера — НЕ наш (regression-гвард).
    Issue #169: путь к wrapper'у = ~/bin/codex-srouter (rename из codex).
    """
    try:
        if path == str(_health_facade._codex_wrapper_path()):
            return _CODEX_WRAPPER_MARKER in Path(path).read_text(encoding="utf-8")
        return False
    except OSError:
        return False


def _codex_provenance(path):
    """Provenance codex-binary по его расположению: npm / homebrew / usr-local / bin / path.
    НЕ утверждает «обёрнут srouter» — это решает _is_srouter_codex_wrapper (по маркеру, не по пути),
    поэтому ~/bin/codex-srouter без маркера = provenance 'bin' (чужой/устаревший wrapper), не 'srouter-wrapper'."""
    p = str(path)
    if "/lib/node_modules/" in p or p.endswith(".js"):
        return "npm"
    if "/opt/homebrew/" in p:
        return "homebrew"
    if "/usr/local/bin/" in p:
        return "usr-local"
    if p == str(_health_facade._codex_wrapper_path()):
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
    Каждый: {path, provenance, version, wrapped}. Не бросает (fail-soft).

    Issue #169: real binary зовётся codex (имя освобождено от wrapper'а при rename). srouter-wrapper
    живёт в ~/bin/codex-srouter и НЕ находится через `which -a codex` (другое имя) — добавляем его явно
    (шаг 3), чтобы doctor показывал wrapped-статус."""
    candidates = []
    # 1. which -a codex (real binary в PATH; старый устаревший ~/bin/codex тоже, если остался после rename).
    candidates.extend(_health_facade._which_all("codex"))
    # 2. well-known homebrew/standalone (Apple Silicon / Intel).
    for cand in ("/opt/homebrew/bin/codex", "/usr/local/bin/codex"):
        if Path(cand).is_file():
            candidates.append(cand)
    # 3. srouter-wrapper ~/bin/codex-srouter (явно — который() codex его не вернёт: имя codex-srouter,
    # и ~/bin может не быть в PATH пробы). Переименован в #169 из ~/bin/codex.
    wrapper = str(_health_facade._codex_wrapper_path())
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
    candidates.extend(_health_facade._which_all("claude"))
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
        codex_bins = _health_facade._scan_codex_binaries()
    except OSError as exc:
        _log.debug("_scan_codex_binaries: %s — codex-инвентаризация пропущена", exc)
        codex_bins = []
    try:
        claude_bins = _health_facade._scan_claude_code_binaries()
    except OSError as exc:
        _log.debug("_scan_claude_code_binaries: %s — claude-code-инвентаризация пропущена", exc)
        claude_bins = []
    detail = _format_versions_detail(codex_bins, claude_bins)
    if not codex_bins and not claude_bins:
        return {"status": "unknown", "detail": detail, "codex": [], "claude_code": []}
    return {"status": "ok", "detail": detail, "codex": codex_bins, "claude_code": claude_bins}


# ============================ #186: PF codex kill-switch (provisioning uid 503) ============================
def _codex_isolation_check():
    """Статус PF codex kill-switch — настоящая fail-closed граница (epic #166, #186).

    info-only для ВСЕХ «незамкнутых» состояний (НЕ driver — иначе doctor всегда degraded на
    нормальных установках, где codex идёт под user-UID 501, паттерн шума PR #135). ok — только
    при реальном процессе под UID 503. Возвращает {status, detail}, status: info|ok. НЕ бросает.

    Состояния:
      - нет lease (probe_codex_isolation.status != 'ok') → info «не установлен (по выбору)».
      - lease ok, НО probe_codex_user не provisioned → info «инфра загружена, UID не создан».
      - lease ok + user provisioned, НО нет процесса под UID 503 → info «PF standby, sudo -u = follow-up»
        (wrapper в проде НЕ запускает codex под uid 503 — осознанный scope #186).
      - lease ok + user provisioned + процесс под UID 503 → ok «real fail-closed активна».

    ps -u <uid> для без-процесса UID → rc=1 + пустой out (verify-dont-guess); has_proc требует
    rc=0 И непустой out (консервативно: сбой ps → info, не ложный ok).
    """
    try:
        import isolate_firewall
        lease = isolate_firewall.probe_codex_isolation()
        if lease.get("status") != "ok":
            return {"status": "info",
                    "detail": "PF codex kill-switch не установлен (lease отсутствует) — по выбору."}
        user = isolate_firewall.probe_codex_user()
        if not user.get("provisioned"):
            return {"status": "info",
                    "detail": "PF codex-изоляция: sub-anchor загружен, НО _srouter_codex (uid 503) "
                              "не создан → правила не матчат. Переустановите (install) для provisioning."}
        # ps -u <uid>: rc=0 + непустой вывод → процесс под этим UID есть.
        r = sys_probe.run([PS, "-u", isolate_firewall.CODEX_USER, "-o", "pid=,comm="], timeout=3)
        has_proc = (not r.get("timeout")) and r.get("rc") == 0 and bool((r.get("out") or "").strip())
        if has_proc:
            return {"status": "ok",
                    "detail": f"PF codex kill-switch активен: lease ok + uid "
                              f"{isolate_firewall.CODEX_USER} provisioned + процесс под этим UID "
                              f"работает (real fail-closed)."}
        return {"status": "info",
                "detail": f"PF codex kill-switch готов, но codex не запущен под uid "
                          f"{isolate_firewall.CODEX_USER} (sudo -u) — продакшн-запуск = follow-up."}
    except (ImportError, AttributeError, KeyError, OSError, subprocess.SubprocessError) as exc:
        # ImportError — isolate_firewall недоступен; AttributeError/KeyError — probe_* вернул
        # неожиданную форму (defensive); OSError/SubprocessError — сбой sys_probe.run/ps.
        _log.info("codex-isolation check: сбой (%s: %s)", type(exc).__name__, exc)
        return {"status": "info", "detail": f"codex-isolation check: сбой ({str(exc)[:80]})."}
