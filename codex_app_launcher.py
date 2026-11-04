"""ChatGPT.app/Codex.app Dock-launcher (managed): launcher .app-bundle + подмена Dock-тайла.

Контракт владельца (2026-11-05): ChatGPT.app = группа Claude.app — только 10808, никогда
direct. Dock не передаёт --proxy-server; при NE-VPN primary (HitVPN/VeePN ephemeral,
пустой scutil-снапшот — канон system_proxy.py) Chromium уходит direct даже при настроенных
именных network service. Ручная обёртка ~/bin/codex-app-proxy ставится install'ом, но
Dock-запуск мимо неё — тот же инцидент-класс, что claude-app (запуск из Dock дважды терял
wrapper). Заполнение: launcher .app-bundle в ~/Applications (скрипт exec codex-app-proxy)
+ тайл Dock подменяется на launcher (defaults export/write com.apple.dock
persistent-others + killall Dock); uninstall обратимо возвращает исходный тайл из state.

Канон — claude_wrappers/codex_wrappers: marker-gate «чужое не трогать» (#112), atomic
write, chmod +x. Two-phase state (канон AGENTS.md): pending-фаза + исходный тайл пишутся
ДО defaults-мутации (`swapping`/`restoring`), подтверждение после; crash оставляет на
диске backup, а не «Dock изменён, откат нигде».

Read-only источники (status): `defaults export com.apple.dock -` (XML plist —
`defaults read` печатает OpenStep-формат, plistlib его не парсит; снято с живой машины),
ps argv живого ChatGPT/Cod.app main-процесса (--proxy-server — канон ps-argv),
system_proxy.status() (scutil --proxy, canon system_proxy.py:95).
"""
from __future__ import annotations

import copy
import logging
import os
import plistlib
import re
import shutil
from pathlib import Path
from urllib.parse import quote

import local_state
import sys_probe
import system_proxy
from install_lib import _write_text_atomic

_log = logging.getLogger("srouter.codex_app_launcher")

# Маркер managed-launcher (первая строка комментария скрипта; канон codex_wrappers —
# маркер идентифицирует «srouter-managed», не имя файла).
LAUNCHER_MARKER = "# srouter: codex-app launcher (managed)"
LAUNCHER_BUNDLE_ID = "com.srouter.chatgpt-launcher"
# State-ключ runtime в srouter.local.json (канон unified local state).
LAUNCHER_STATE_KEY = "codex_app_launcher"

# Явные пути (канон: GUI/launchd PATH может не иметь /usr/bin — хотя defaults/killall всегда там).
DEFAULTS = "/usr/bin/defaults"
KILLALL = "/usr/bin/killall"
PS = "/bin/ps"
DOCK_DOMAIN = "com.apple.dock"
DOCK_KEY = "persistent-others"

# Кандидаты App — тот же порядок приоритета, что в codex-app-proxy wrapper (ChatGPT приоритет).
_APP_CANDIDATES = ("/Applications/ChatGPT.app", "/Applications/Codex.app")


def _app_candidates():
    """Список путей к App-bundle. Override: SROUTER_CODEX_APP_BUNDLE (канон «больше опций»,
    прецедент SROUTER_CLAUDE_APP_BIN) — prepend, чтобы тесты/нестандартные установки шли первыми."""
    override = os.environ.get("SROUTER_CODEX_APP_BUNDLE")
    if override:
        return [Path(override)] + [Path(p) for p in _APP_CANDIDATES]
    return [Path(p) for p in _APP_CANDIDATES]


def _find_app():
    """(path, name) первого существующего candidate (ChatGPT приоритет) или None. Гейт простой
    (каталог есть): полную валидацию (plutil/executable) при запуске делает сам
    codex-app-proxy — launcher только делегирует."""
    for candidate in _app_candidates():
        if candidate.is_dir():
            return candidate, candidate.stem  # ("…/ChatGPT.app", "ChatGPT")
    return None


def _launcher_root() -> Path:
    return Path.home() / "Applications"


def _launcher_path(app_name: str) -> Path:
    return _launcher_root() / f"{app_name} (srouter).app"


def _launcher_script_path(launcher: Path, app_name: str) -> Path:
    return launcher / "Contents" / "MacOS" / f"{app_name} (srouter)"


def _render_script() -> str:
    return (
        "#!/bin/zsh\n"
        f"{LAUNCHER_MARKER}\n"
        "#\n"
        "# ChatGPT.app/Codex.app из Dock → ~/bin/codex-app-proxy "
        "(--proxy-server=socks5://127.0.0.1:10808).\n"
        "# Dock флаги не передаёт; при NE-VPN primary scutil-снапшот пуст и Chromium уходит\n"
        "# direct — контракт владельца 2026-11-05: ChatGPT.app = группа Claude.app, только\n"
        "# 10808, никогда direct. Ставится `srouter wrappers codex-app install`; uninstall\n"
        "# возвращает исходный Dock-тайл.\n"
        "set -eu\n"
        'exec "$HOME/bin/codex-app-proxy" "$@"\n'
    )


def _render_info_plist(app_name: str) -> str:
    info = {
        "CFBundleName": f"{app_name} (srouter)",
        "CFBundleDisplayName": f"{app_name} (srouter)",
        "CFBundleIdentifier": LAUNCHER_BUNDLE_ID,
        "CFBundleExecutable": f"{app_name} (srouter)",
        "CFBundlePackageType": "APPL",
        "CFBundleVersion": "1.0",
    }
    return plistlib.dumps(info).decode("utf-8")


def _script_is_ours(script: Path) -> bool:
    try:
        return LAUNCHER_MARKER in script.read_text(encoding="utf-8")
    except OSError:
        return False


def _install_launcher_bundle(launcher: Path, script: Path, app_name: str) -> str | None:
    """Записать bundle (atomic + chmod +x). None = успех, иначе строка-отказ."""
    try:
        if not _write_text_atomic(script, _render_script()):
            return f"{launcher}: launcher-скрипт не записан (ошибка atomic write)."
        script.chmod(0o755)
        if not _write_text_atomic(launcher / "Contents" / "Info.plist",
                                  _render_info_plist(app_name)):
            return f"{launcher}: Info.plist не записан (ошибка atomic write)."
    except (OSError, ValueError, TypeError) as exc:
        return f"{launcher}: не записан ({str(exc)[:80]})."
    return None


# ============================== Dock-тайл ==============================


def _dock_export(runner):
    """XML plist домена Dock (defaults export). None = нечитаемо (fail-closed)."""
    r = runner([DEFAULTS, "export", DOCK_DOMAIN, "-"], 5)
    if r.get("timeout") or r.get("rc") not in (0, None):
        return None
    try:
        return plistlib.loads((r.get("out") or "").encode("utf-8"))
    except (ValueError, OSError):
        return None


def _tile_url_string(tile):
    try:
        return tile.get("tile-data", {}).get("file-data", {}).get("_CFURLString", "")
    except AttributeError:
        return ""


def _tile_matches(url_string, path: Path) -> bool:
    """Тайл указывает на path? Dock хранит file:// URL с percent-encoding (пробелы/скобки —
    %20%28%29), старые записи — plain path: сравниваем ОБЕ формы (raw + quoted)."""
    p = path.as_posix()
    return p in (url_string or "") or quote(p) in (url_string or "")


def _cfurl_for(path: Path, like: str) -> str:
    """URL тайла для path в формате исходного (file:// → quoted URL; plain → plain)."""
    quoted = quote(str(path))
    if like.startswith("file://"):
        return f"file://{quoted}/"
    return str(path)


def _write_dock_tiles(tiles, runner):
    """defaults write persistent-others целиком (XML одним argv-аргументом) + killall Dock.
    Возвращает строку-ошибку или None."""
    xml = plistlib.dumps({DOCK_KEY: list(tiles)}).decode("utf-8")
    r = runner([DEFAULTS, "write", DOCK_DOMAIN, DOCK_KEY, xml], 5)
    if r.get("timeout") or r.get("rc") not in (0, None):
        return f"defaults write {DOCK_DOMAIN} {DOCK_KEY} не выполнен ({r.get('err') or 'rc=?'})."
    r = runner([KILLALL, "Dock"], 5)
    if r.get("timeout") or r.get("rc") not in (0, None):
        return f"killall Dock не выполнен ({r.get('err') or 'rc=?'}) — перелогинься или перезапусти Dock."
    return None


def _load_swap(path):
    """runtime.codex_app_launcher → dict или None (как system_proxy_control._load_leases)."""
    state = local_state.load_state(path=path)
    section = (state.get("runtime") or {}).get(LAUNCHER_STATE_KEY)
    return section if isinstance(section, dict) else None


def _save_swap(path, section):
    """Записать секцию. False = state не читается/не пишется — вызывающий обязан
    отреагировать (канон issue #316: молчаливое проглатывание сбоя записи = фиктивный backup)."""
    state, readable = local_state.load_state_checked(path=path)
    if not readable:
        return False
    runtime = state.setdefault("runtime", {})
    if section is None:
        runtime.pop(LAUNCHER_STATE_KEY, None)
    else:
        runtime[LAUNCHER_STATE_KEY] = section
    return local_state.save_state(state, path) is not None


def _dock_swap_to_launcher(env, app: Path, launcher: Path, runner) -> str:
    """Подменить тайл app на launcher (two-phase). Строка-итог для note."""
    dock = _dock_export(runner)
    if dock is None:
        return ("Dock-тайл: defaults export com.apple.dock не прочитан — Dock не изменён "
                "(fail-closed); запускай App через ~/bin/codex-app-proxy.")
    tiles = dock.get(DOCK_KEY)
    if not isinstance(tiles, list):
        tiles = []
    index = next((i for i, t in enumerate(tiles) if _tile_matches(_tile_url_string(t), app)),
                 None)
    if index is None:
        return ("Dock-тайл: тайл ChatGPT/Codex не найден (App не закреплён?) — launcher "
                "установлен, закрепи launcher вручную (~/Applications).")
    original = tiles[index]
    section = {"phase": "swapping", "app": app.as_posix(),
               "launcher": launcher.as_posix(), "tile": original}
    # Two-phase: pending + исходный тайл НА ДИСКЕ до мутации (канон AGENTS.md two-phase).
    if not _save_swap(env.state_path, section):
        return ("Dock-тайл: state не записывается — backup исходного тайла невозможен, "
                "подмена отменена (fail-closed).")
    like = _tile_url_string(original)
    tiles[index] = _retarget_tile(original, launcher, like)
    err = _write_dock_tiles(tiles, runner)
    if err:
        return f"Dock-тайл: {err} Исходный тайл сохранён (state codex_app_launcher) — " \
               f"откат: srouter wrappers codex-app uninstall."
    if not _save_swap(env.state_path, {"phase": "active", "app": app.as_posix(),
                                       "launcher": launcher.as_posix(), "tile": original}):
        _log.warning("codex_app_launcher: swap применён, но фаза active не записалась — "
                     "uninstall всё равно откатит по сохранённому тайлу")
    return f"Dock-тайл: подменён на launcher, исходный сохранён в state (killall Dock выполнен)."


def _retarget_tile(original, launcher: Path, like: str):
    """Копия тайла с _CFURLString → launcher; остальное (GUID, label, book) сохранено."""
    tile = copy.deepcopy(original)
    tile.setdefault("tile-data", {}).setdefault("file-data", {})
    tile["tile-data"]["file-data"]["_CFURLString"] = _cfurl_for(launcher, like)
    return tile


def _restore_dock_tile(env, runner):
    """Вернуть исходный тайл из state (two-phase restoring). (note, restored: bool)."""
    section = _load_swap(env.state_path)
    if not section:
        return None, False
    original = section.get("tile")
    if not isinstance(original, dict):
        return ("Dock-тайл: в state нет сохранённого тайла — вернуть нечего "
                "(закрепи нужный вручную)."), False
    if not _save_swap(env.state_path, {"phase": "restoring", "app": section.get("app"),
                                       "tile": original}):
        return ("Dock-тайл: state не записывается — фаза restoring не сохранена, "
                "откат отменён (fail-closed)."), False
    dock = _dock_export(runner)
    if dock is None:
        return ("Dock-тайл: defaults export не прочитан — откат отменён (fail-closed), "
                "исходный тайл сохранён в state."), False
    tiles = dock.get(DOCK_KEY)
    if not isinstance(tiles, list):
        tiles = []
    # Наш тайл ищем по пути LAUNCHER'а (записан в state при swap): после подмены тайл
    # указывает на launcher, app-путь в нём уже не встречается.
    launcher_p = section.get("launcher") or ""
    index = next((i for i, t in enumerate(tiles)
                  if launcher_p and _tile_matches(_tile_url_string(t), Path(launcher_p))),
                 None)
    if index is None:
        # Тайл launcher'а уже исчез (убрали вручную) — просто возвращаем исходный.
        tiles.append(original)
    else:
        tiles[index] = original
    err = _write_dock_tiles(tiles, runner)
    if err:
        return f"Dock-тайл: {err} Исходный тайл сохранён в state — повтори uninstall.", False
    if not _save_swap(env.state_path, None):
        _log.warning("codex_app_launcher: тайл возвращён, но state-секция не расчищена")
    return "Dock-тайл: исходный возвращён (killall Dock выполнен).", True


# ============================== install / uninstall / status ==============================


def install_launcher(env, *, runner=sys_probe.run) -> str:
    """Поставить launcher .app-bundle в ~/Applications + подменить Dock-тайл. Marker-gate:
    чужой скрипт не трогаем (канон #112). Строка-статус (канон codex_wrappers)."""
    found = _find_app()
    if found is None:
        return ("codex-app launcher: ChatGPT.app/Codex.app не найден — launcher не "
                "установлен (установи App).")
    app, app_name = found
    launcher = _launcher_path(app_name)
    script = _launcher_script_path(launcher, app_name)
    if script.exists() and not _script_is_ours(script):
        return (f"codex-app launcher: {launcher} существует без srouter-маркера — не "
                f"трогаем (удали вручную, если это твой старый launcher).")
    err = _install_launcher_bundle(launcher, script, app_name)
    if err:
        return f"codex-app launcher: {err}"
    note = _dock_swap_to_launcher(env, app, launcher, runner)
    return f"codex-app launcher: установлен ({launcher} → ~/bin/codex-app-proxy). {note}"


def uninstall_launcher(env, *, runner=sys_probe.run) -> tuple[str, bool]:
    """Вернуть исходный Dock-тайл + удалить launcher (наш по маркеру). (note, ok):
    ok=False — сбой отката/удаления (вызывающий обязан показать это как ошибку)."""
    found = _find_app()
    launcher = None
    script = None
    if found:
        launcher = _launcher_path(found[1])
        script = _launcher_script_path(launcher, found[1])
    restore_note, _restored = _restore_dock_tile(env, runner)
    if script is None or not script.exists():
        if restore_note:
            return f"codex-app launcher: launcher не найден. {restore_note}", False
        return "codex-app launcher: не был установлен.", True
    if not _script_is_ours(script):
        if restore_note:
            return f"codex-app launcher: чужой {launcher} — не трогаем. {restore_note}", True
        return f"codex-app launcher: чужой {launcher} — не трогаем.", True
    try:
        assert launcher is not None  # script is not None → launcher задан (инвариант)
        shutil.rmtree(launcher)
    except OSError as exc:
        return f"codex-app launcher: не удалён ({str(exc)[:80]})." + (
            f" {restore_note}" if restore_note else ""), False
    if restore_note:
        return f"codex-app launcher: удалён. {restore_note}", True
    return ("codex-app launcher: удалён; сохранённого Dock-тайла нет — тайл не возвращён "
            "(закрепи App вручную, если нужно)."), True


def status(*, runner=sys_probe.run) -> dict:
    """Read-only: launcher стоит? тайл Dock на launcher? живой процесс несёт --proxy-server?
    эффективный снапшот (scutil). НИКАКИХ мутаций (defaults write/killall не вызываются)."""
    found = _find_app()
    launcher = None
    script = None
    if found:
        launcher = _launcher_path(found[1])
        script = _launcher_script_path(launcher, found[1])
    launcher_installed = bool(script and script.exists() and _script_is_ours(script))

    dock = _dock_export(runner)
    tiles = (dock or {}).get(DOCK_KEY)
    if dock is None or not isinstance(tiles, list):
        dock_tile_on_launcher = None
    elif launcher:
        dock_tile_on_launcher = any(
            _tile_matches(_tile_url_string(t), launcher) for t in tiles)
    else:
        dock_tile_on_launcher = False

    live_app_flag = None
    r = runner([PS, "-axo", "pid=,args="], 3)
    if not r.get("timeout") and r.get("rc") in (0, None):
        main_re = re.compile(r"/(?:ChatGPT|Codex)\.app/Contents/MacOS/", re.IGNORECASE)
        mains = [line for line in (r.get("out") or "").splitlines() if main_re.search(line)]
        if mains:
            live_app_flag = any("--proxy-server=" in line for line in mains)

    snap = system_proxy.status()
    snapshot_any_enabled = snap.get("any_enabled")

    if launcher_installed and dock_tile_on_launcher is True:
        overall = "ok"
    elif not launcher_installed:
        overall = "unknown"
    else:
        overall = "warn"
    return {"status": overall,
            "launcher_installed": launcher_installed,
            "dock_tile_on_launcher": dock_tile_on_launcher,
            "live_app_flag": live_app_flag,
            "snapshot_any_enabled": snapshot_any_enabled,
            "detail": (f"launcher={launcher_installed}, dock_tile={dock_tile_on_launcher}, "
                       f"argv_flag={live_app_flag}, snapshot_any_enabled={snapshot_any_enabled}")}
