"""Вкл/откл scoped SOCKS5-прокси для codex-расширения openai.chatgpt через VSCode `http.proxy`.

Контекст (issue #185, эмпирика env-vs-PF вариант 1): VSCode-расширение `openai.chatgpt` запускает
свой codex-binary (`.vscode/extensions/openai.chatgpt-*/bin/macos-aarch64/codex`), МИМО wrapper
(`~/bin/codex-srouter`) и brew-binary. Этот codex наследует HTTP_PROXY=privoxy (8118) из
`~/.claude/settings.json` → privoxy рвёт long-lived WS (#96/#120). Раньше решение было глобальным —
LaunchAgent com.srouter.codenv делал `launchctl setenv SOCKS5` в GUI-домен — но это ломает Claude Code
(#130: CC не поддерживает SOCKS5), поэтому LaunchAgent НЕ загружался (мёртвый механизм).

Scoped-решение (verify из extension.js расширения openai.chatgpt, НЕ guess):
  function wnt(){ let t=workspace.getConfiguration("http"), e=t.get("proxy"), n={};
    return e&&e.trim().length>0 && (n.HTTP_PROXY=e, n.HTTPS_PROXY=e), n }
  function _ve(...){ let n=wnt(); ... c={...process.env,...n,...}  // spawn codex
Расширение ЧИТАЕТ VSCode-настройку `http.proxy` и СТРОИ HTTP_PROXY/HTTPS_PROXY В ENV ПОРОЖДАЕМОГО
codex-процессА (`{...process.env, ...n}`), а не системно. Расширение нативно поддерживает SOCKS5
(SocksProxyAgent, protocols socks/socks4/socks4a/socks5/socks5h). Claude Code CLI — отдельный процесс
со своим `~/.claude/settings.json` (docs.code.claude.com) → VSCode `http.proxy` на CC НЕ влияет.
Итог: scoped, не ломает CC.

Это ЧУЖОЙ конфиг (как ~/.claude/settings.json для claude_proxy, ~/.gitconfig для git_proxy) — правим
JSON read-modify-write (не строками), сохраняя все существующие настройки редактора. Atomic-запись
через tmp+replace. Не бросает (probe-канон). Provenance через ЗНАЧЕНИЕ-совпадение: disable убирает
ключ только если val == PROXY (чужой корпоративный/ручной http.proxy не трогаем — fail-closed #112).
"""
import json
import os
from pathlib import Path
from urllib.parse import urlparse

# Прокси codex = SOCKS5 xray 10808. Единый источник правды (issue #155) — dashboard_common.
# except SystemExit (НЕ BaseException): dashboard_common при отсутствии srouter_config.py поднимает
# SystemExit (BaseException) → except Exception его пропустит, fallback не сработает в install-пути.
# Ловим именно SystemExit, НЕ BaseException — иначе глотаем реальные ImportError/SyntaxError в самом
# dashboard_common (канон gen_xray_config.py:34 после PR #162; memory systemexit-breaks-except-...).
try:
    from dashboard_common import SOCKS_PROXY_URL as _PROXY  # socks5h://127.0.0.1:10808
except SystemExit:
    _PROXY = "socks5h://127.0.0.1:10808"
PROXY = _PROXY  # контракт для тестов/health

# Каноничная VSCode user-settings (Code + Cursor). Пользователь может пользоваться любым — покрываем оба.
# SROUTER_VSCODE_SETTINGS (more-options-better, канон InstallEnv.from_env) — env-override для тестов/кастома:
# список путей через os.pathsep (как PATH), tmp-файлы в pytest.
_DEFAULT_PATHS = (
    Path.home() / "Library" / "Application Support" / "Code" / "User" / "settings.json",
    Path.home() / "Library" / "Application Support" / "Cursor" / "User" / "settings.json",
)


def _settings_paths():
    """Список путей к user-settings редакторов. Env-override SROUTER_VSCODE_SETTINGS (os.pathsep)."""
    override = os.environ.get("SROUTER_VSCODE_SETTINGS")
    if override:
        return tuple(Path(p) for p in override.split(os.pathsep) if p.strip())
    return _DEFAULT_PATHS


# Доступно для monkeypatch в тестах (как claude_proxy.SETTINGS) — единый mutable-источник.
SETTINGS_PATHS = _settings_paths()

# VSCode-ключ прокси. Расширение openai.chatgpt читает именно его (workspace.getConfiguration("http").get("proxy")).
KEY = "http.proxy"


def _load(path):
    """Прочитать settings.json. Missing/non-JSON → None (файла нет / чужой мусор). Не бросает.

    None (не {}) сигнализирует «редактор не установлен / файла нет» — enable не создаёт его
    (VSCode сам создаст при первом запуске). {} = пустой валидный конфиг.
    """
    try:
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        # File read errors or JSON parsing failures: OSError on I/O errors,
        # JSONDecodeError on malformed JSON, ValueError/TypeError on type issues.
        # Return None (signals "file not present or invalid" to caller).
        return None


def _save(path, data):
    """Atomic-запись settings.json. tmp+replace — не теряем данные при сбое. {ok, err}.

    Родитель создаётся (mkdir parents) — но ВЫЗВАН только когда файл уже существовал (enable не
    создаёт settings.json с нуля, см. enable()).
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        tmp.replace(path)
        return {"ok": True}
    except (OSError, TypeError, ValueError) as exc:
        # File write errors: OSError on I/O failures, TypeError on invalid data types,
        # ValueError on JSON encoding failures. Return structured error (truncated).
        return {"ok": False, "err": str(exc)[:200]}


def status():
    """Состояние scoped-прокси: {enabled, proxy, paths}. Не бросает.

    enabled=True если ХОТЯ БЫ ОДИН существующий settings.json содержит KEY == PROXY. proxy — значение
    из первого найденного. paths — {str(path): {present, proxy}} для диагностики (health/doctor).
    Сырой state, НЕ probe — runtime-вердикт делает health._vscode_proxy_check().
    """
    found_any = False
    per_path = {}
    proxy = ""
    for path in SETTINGS_PATHS:
        data = _load(path)
        if data is None:
            per_path[str(path)] = {"present": False, "proxy": ""}
            continue
        val = data.get(KEY, "") if isinstance(data, dict) else ""
        per_path[str(path)] = {"present": True, "proxy": val}
        if val:
            found_any = True
            if not proxy:
                proxy = val
    return {"enabled": found_any and proxy == PROXY, "proxy": proxy, "paths": per_path}


def enable():
    """Прописать KEY = SOCKS5 в каждый СУЩЕСТВУЮЩИЙ settings.json редактора. {ok, err, paths}.

    Несуществующий файл НЕ создаём (VSCode сам создаст при первом запуске — не плодим мусор).
    Не трогает другие настройки (read-modify-write). Контракт: PROXY обязан быть socks5-схемы
    (#120 — privoxy/HTTP рвёт WS; #127-класс регрессии).
    """
    scheme = urlparse(PROXY).scheme.lower()
    if scheme not in {"socks", "socks5", "socks5h"}:
        return {"ok": False, "err": f"unsupported proxy scheme for codex (need socks5): {scheme or 'missing'}",
                "paths": []}
    changed = []
    for path in SETTINGS_PATHS:
        data = _load(path)
        if data is None:
            continue  # редактор не установлен — не создаём
        if not isinstance(data, dict):
            data = {}
        data[KEY] = PROXY
        r = _save(path, data)
        if not r["ok"]:
            return {"ok": False, "err": r["err"], "paths": changed}
        changed.append(str(path))
    return {"ok": True, "err": "", "paths": changed}


def disable():
    """Убрать KEY из settings.json, ТОЛЬКО если val == PROXY (чужой не трогаем). {ok, err}. Идемпотентно.

    fail-closed provenance (#112): корпоративный/ручной http.proxy ≠ PROXY → оставляем на месте.
    """
    for path in SETTINGS_PATHS:
        data = _load(path)
        if not isinstance(data, dict):
            continue
        if data.get(KEY) == PROXY:
            del data[KEY]
            r = _save(path, data)
            if not r["ok"]:
                return r
    return {"ok": True}
