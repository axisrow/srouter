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

Issue #307 (foreign/mixed/force, канон privileged-boundary-fail-closed): чужое значение http.proxy
— ОТДЕЛЬНОЕ состояние foreign в status() (не «не настроено»); mixed — у разных редакторов разные
значения (напр. наш в Code, чужой в Cursor). enable() на foreign/mixed отказывает ЯВНО (conflict)
без мутации; перезапись — только force=True, при этом чужое значение уходит в sidecar-backup
(прецедент #112), disable() после force восстанавливает его. Классификация состояний — общий
слой proxy_config_contract (канон third-module-breaks-reexport-cycle).
"""
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import proxy_config_contract as _contract

import backup_lib  # sidecar_path: единый источник суффикса lease-бэкапа (PR-1 #339)

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


def _read_settings(path):
    """(data, kind): kind ∈ 'missing' | 'ok' | 'invalid'; data None для missing/invalid.

    Issue #307 round 2 (Codex cycle-review PR #328 finding 3): раньше missing и invalid
    схлопывались в один None — битый/не-object файл классифицировался как «редактор не
    установлен» и молча заменялся нашим конфигом. Теперь caller видит разницу.
    """
    if not path.exists():
        return None, "missing"
    try:
        return json.loads(path.read_text(encoding="utf-8")), "ok"
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        return None, "invalid"


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
    """Состояние scoped-прокси: {enabled, proxy, state, paths}. Не бросает.

    state (issue #307) — absent/managed-on/foreign/mixed: чужое значение http.proxy — НЕ
    «не настроено», а foreign; разные значения в разных settings.json — mixed. enabled=True
    если ХОТЯ БЫ ОДИН существующий settings.json содержит KEY == PROXY. proxy — значение
    из первого найденного. paths — {str(path): {present, proxy, state}} для диагностики
    (health/doctor). Сырой state, НЕ probe — runtime-вердикт делает health._vscode_proxy_check().
    """
    found_any = False
    per_path = {}
    proxy = ""
    states = []
    for path in SETTINGS_PATHS:
        data, kind = _read_settings(path)
        if kind != "ok" or not isinstance(data, dict):
            # missing = редактор не установлен (ABSENT, не участник конфликта);
            # invalid / не-object = нечитаемый чужой документ — ЧЕСТНЫЙ unknown (finding 3).
            st = _contract.ABSENT if kind == "missing" else _contract.UNKNOWN
            per_path[str(path)] = {"present": kind == "ok", "proxy": "", "state": st}
            states.append(st)
            continue
        val = data.get(KEY, "")
        st = _contract.classify(KEY in data, val, PROXY)
        per_path[str(path)] = {"present": True, "proxy": val, "state": st}
        states.append(st)
        if val:
            found_any = True
            if not proxy:
                proxy = val
    return {"enabled": found_any and proxy == PROXY, "proxy": proxy,
            "state": _contract.aggregate(states), "paths": per_path}


def _backup_path(path):
    """Sidecar-backup чужого http.proxy, перезаписанного force-enable (прецедент #112).
    Живёт рядом с settings.json редактора; disable() восстанавливает из него и удаляет.
    Суффикс — единый источник backup_lib.SIDECAR_SUFFIX (PR-1 #339, контракт v2)."""
    return backup_lib.sidecar_path(path)


def _read_backup(path):
    """Прочитать sidecar-backup редактора. None если нет/битый. Не бросает."""
    try:
        p = _backup_path(path)
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        return None


def enable(force=False):
    """Прописать KEY = SOCKS5 в каждый СУЩЕСТВУЮЩИЙ settings.json редактора. {ok, err, paths, state?}.

    Несуществующий файл НЕ создаём (VSCode сам создаст при первом запуске — не плодим мусор).
    Не трогает другие настройки (read-modify-write). Контракт: PROXY обязан быть socks5-схемы
    (#120 — privoxy/HTTP рвёт WS; #127-класс регрессии).

    Issue #307: если в любом редакторе чужое значение http.proxy (или mixed) — отказ без
    мутации {ok: False, conflict: True, state}; перезапись только force=True, при этом
    чужое значение уходит в sidecar-backup (disable() потом его восстановит).

    Issue #307 round 2 (Codex cycle-review PR #328): битый/не-object settings.json — честный
    отказ БЕЗ замены файла (finding 3); состояние каждого файла перечитывается непосредственно
    перед записью — foreign, появившийся между gate и save, не затирается (finding 4).
    """
    scheme = urlparse(PROXY).scheme.lower()
    if scheme not in {"socks", "socks5", "socks5h"}:
        return {"ok": False, "err": f"unsupported proxy scheme for codex (need socks5): {scheme or 'missing'}",
                "paths": []}
    gate = {}  # path -> (kind, dict|None) — снапшот, на котором принимается решение
    states = []
    for path in SETTINGS_PATHS:
        data, kind = _read_settings(path)
        if kind == "invalid" or (kind == "ok" and not isinstance(data, dict)):
            return {"ok": False, "state": _contract.UNKNOWN,
                    "err": f"{path}: settings.json нечитаем/битый/не JSON-object — "
                           "перезапись чужого файла запрещена (issue #307)",
                    "paths": []}
        if kind == "missing":
            continue  # редактор не установлен — ABSENT не участник конфликта
        gate[path] = (data, _contract.classify(KEY in data, data.get(KEY, ""), PROXY))
        states.append(gate[path][1])
    state = _contract.aggregate(states)
    if _contract.needs_force(state) and not force:
        r = _contract.conflict_result(state)
        r["paths"] = []
        return r
    changed = []
    for path in SETTINGS_PATHS:
        data, kind = _read_settings(path)
        if kind == "missing":
            continue  # редактор не установлен — не создаём
        if kind == "invalid" or not isinstance(data, dict):
            return {"ok": False, "err": f"{path}: settings.json стал нечитаем во время операции",
                    "paths": changed}
        # TOCTOU re-check (finding 4): если KEY на диске изменился с момента gate-решения —
        # решение устарело, отказываем. Presence отдельно от значения (AO review round 3):
        # absent и JSON-null — разные состояния, иначе конкурентная вставка http.proxy: null
        # после gate сравнялась бы с absent и была бы затёрта.
        gate_data, _ = gate.get(path, (None, None))
        gate_snap = (KEY in gate_data, gate_data.get(KEY)) if isinstance(gate_data, dict) else (False, None)
        if (KEY in data, data.get(KEY)) != gate_snap:
            return {"ok": False, "conflict": True, "state": state,
                    "err": f"{path}: settings.json изменился во время операции — повторите",
                    "paths": changed}
        if force and KEY in data and data[KEY] != PROXY:
            # Provenance: чужое значение, которое сейчас затрём, — в sidecar-backup.
            backup = {"http.proxy": data[KEY]}
            try:
                bp = _backup_path(path)
                tmp = bp.with_suffix(".json.tmp")
                tmp.write_text(json.dumps(backup, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                tmp.replace(bp)
            except (OSError, TypeError, ValueError) as exc:
                return {"ok": False, "err": f"backup foreign value failed: {str(exc)[:150]}",
                        "paths": changed}
        data[KEY] = PROXY
        r = _save(path, data)
        if not r["ok"]:
            return {"ok": False, "err": r["err"], "paths": changed}
        changed.append(str(path))
    return {"ok": True, "err": "", "paths": changed}


def disable():
    """Убрать KEY из settings.json, ТОЛЬКО если val == PROXY (чужой не трогаем). {ok, err}. Идемпотентно.

    fail-closed provenance (#112): корпоративный/ручной http.proxy ≠ PROXY → оставляем на месте.
    Issue #307: если force-enable раньше перезаписал чужое значение — восстанавливаем его из
    sidecar-backup (вместо простого удаления нашего ключа) и backup потребляем.
    Issue #307 round 2 (Codex finding 2): backup удаляется ТОЛЬКО после подтверждённой записи —
    при упавшей _save() он остаётся единственной копией чужого значения.
    """
    for path in SETTINGS_PATHS:
        data = _load(path)
        if not isinstance(data, dict):
            continue  # missing/invalid — не наше, не трогаем (no mutation, ok)
        if data.get(KEY) == PROXY:
            backup = _read_backup(path)
            backup_consumed = False
            if isinstance(backup, dict) and backup.get(KEY) != PROXY:
                data[KEY] = backup[KEY]  # восстановить ЧУЖОЕ значение, не оставить дырку
                backup_consumed = True
            else:
                del data[KEY]
            r = _save(path, data)
            if not r["ok"]:
                return r
            if backup_consumed:
                try:
                    _backup_path(path).unlink()
                except OSError as exc:
                    # Данные уже восстановлены в settings.json; честно репортим cleanup.
                    return {"ok": True, "err": f"backup cleanup failed: {str(exc)[:120]}"}
    return {"ok": True}
