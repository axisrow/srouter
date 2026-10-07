"""Claude.app wrapper (managed): точечный env + --proxy-server (контракт 2026-10-07).

Канон — codex_wrappers (_install_one_wrapper/_remove_one_wrapper): marker-gate «чужое не
трогать» (#112), atomic write, chmod +x, legacy-migration. Отличия от codex: плечо HTTP
privoxy (Claude-приложения ломаются на SOCKS5, #127), а не SOCKS5; Chromium-стеку нужен
argv --proxy-server (env Electron игнорирует, эмпирия 2026-10-07; тот же класс, что #189).
Без этого модуля wrapper жил руками в ~/bin/claude-app вне srouter и терялся при каждом
перезапуске App из Dock (инцидент 2026-10-07, дважды), doctor ничего не видел.
"""

from __future__ import annotations

import os
from pathlib import Path

from install_lib import _write_text_atomic, load_known_markers

# Плечо + NO_PROXY — единые источники правды (канон issue-155; ревью #404: NO_PROXY был
# байт-в-байт дубликатом CODEX_NO_PROXY — эволюция z.ai-политики разошлась бы тихо).
# except BaseException: dashboard_common raise SystemExit при отсутствии srouter_config.py,
# а SystemExit не ловится Exception — fallback обязан сработать и для него (канон codex_wrappers).
try:
    from dashboard_common import HTTP_PROXY_URL as _PROXY_URL, GUI_NO_PROXY as _GUI_NO_PROXY
except BaseException:
    _PROXY_URL = "http://127.0.0.1:8118"
    _GUI_NO_PROXY = "localhost,127.0.0.1,::1,z.ai,.z.ai"

# NO_PROXY: loopback (локальные сервисы) + z.ai,.z.ai — z.ai НЕ за GFW, всегда напрямую
# (канон zai-direct-no-proxy). Публичное имя модуля, значение — из единого источника.
CLAUDE_NO_PROXY = _GUI_NO_PROXY

CLAUDE_APP_WRAPPER_NAME = "claude-app"
# Маркер current-версии (идентифицирует «srouter-managed claude-app wrapper», не имя файла —
# канон #169: маркер переживает rename/миграцию).
CLAUDE_APP_MARKER = "# srouter: claude-app wrapper (managed)"
# Legacy-маркер ручной версии wrapper'а (жила на машинах до этого PR с первой строкой
# «# srouter: claude-app launcher …»). migration: install перезаписывает её current-маркером,
# remove удаляет как свою (канон #112 marker-migration / #169).
CLAUDE_APP_LEGACY_MARKERS = ("# srouter: claude-app launcher",)
CLAUDE_APP_TEMPLATE = "srouter-claude-app-wrapper.sh"
CLAUDE_APP_BIN_DEFAULT = "/Applications/Claude.app/Contents/MacOS/Claude"


def _claude_app_bin() -> str:
    """Путь к бинарнику Claude.app. Override: SROUTER_CLAUDE_APP_BIN (канон «больше опций»)."""
    return os.environ.get("SROUTER_CLAUDE_APP_BIN", CLAUDE_APP_BIN_DEFAULT)


def _claude_wrapper_path() -> Path:
    """Путь к wrapper в ~/bin (динамически — дружелюбно к мокам Path.home в тестах)."""
    return Path.home() / "bin" / CLAUDE_APP_WRAPPER_NAME


def _is_our_content(content: str) -> bool:
    """Текущий ИЛИ legacy srouter-маркер в содержимом (обе версии — «наш» wrapper)."""
    if CLAUDE_APP_MARKER in content:
        return True
    return any(m in content for m in CLAUDE_APP_LEGACY_MARKERS)


def _install_claude_app_wrapper(env) -> str:
    """Поставить ~/bin/claude-app. Marker-gate + legacy-migration + atomic write + chmod +x.

    Три случая при существующем файле (канон #112 Часть 4):
      - current-маркер → переустановить (idempotent, обновить рендер);
      - legacy-маркер (ручная версия до PR) → МИГРИРОВАТЬ (перезаписать current-маркером);
      - unmarked → WARN, НЕ adopt молча (fail-closed, чужое не трогаем).
    App-binary gate: без Claude.app на диске честный отказ (не ставим мёртвый wrapper).
    """
    wrapper_path = _claude_wrapper_path()
    try:
        if wrapper_path.exists():
            content = wrapper_path.read_text(encoding="utf-8")
            if not _is_our_content(content):
                # Ни current, ни legacy — проверить state-таблицу known_markers (state-based #112).
                known = load_known_markers(env.state_path, "wrappers", [CLAUDE_APP_MARKER])
                foreign_hits = [m for m in known
                                if m != CLAUDE_APP_MARKER and m in content]
                if not foreign_hits:
                    return (f"Claude {wrapper_path.name}: существует без srouter-маркера — "
                            f"не трогаем (удали вручную, если это твой старый wrapper).")
        app_bin = _claude_app_bin()
        if not Path(app_bin).exists():
            return (f"Claude {wrapper_path.name}: Claude.app не найден ({app_bin}) — "
                    f"wrapper не установлен.")
        template = (env.root / "launchagents" / CLAUDE_APP_TEMPLATE).read_text(encoding="utf-8")
        rendered = (template
                    .replace("__SROUTER_CLAUDE_APP_BIN__", app_bin)
                    .replace("__SROUTER_CLAUDE_PROXY_URL__", _PROXY_URL)
                    .replace("__SROUTER_CLAUDE_NO_PROXY__", CLAUDE_NO_PROXY))
        wrapper_path.parent.mkdir(parents=True, exist_ok=True)
        if not _write_text_atomic(wrapper_path, rendered):
            return f"Claude {wrapper_path.name}: не записан (ошибка atomic write)."
        wrapper_path.chmod(0o755)
        return (f"Claude {wrapper_path.name}: установлен ({wrapper_path} — env + --proxy-server "
                f"через {_PROXY_URL}; запускай Claude.app им: {wrapper_path}; из Dock — прямой "
                f"путь мимо туннеля).")
    except (OSError, ValueError, TypeError) as exc:
        # Файловые операции + env-чтение → OSError, ValueError, TypeError
        return f"Claude {wrapper_path.name}: не установлен ({str(exc)[:80]})."


def _remove_claude_app_wrapper() -> str:
    """Удалить wrapper (если srouter-managed: current ИЛИ legacy маркер). Симметрично install."""
    wrapper_path = _claude_wrapper_path()
    try:
        if not wrapper_path.exists():
            return f"Claude {wrapper_path.name}: не был установлен."
        if not _is_our_content(wrapper_path.read_text(encoding="utf-8")):
            return f"Claude {wrapper_path.name}: чужой {wrapper_path} — не трогаем."
        wrapper_path.unlink()
        return f"Claude {wrapper_path.name}: удалён."
    except (OSError, ValueError, TypeError) as exc:
        return f"Claude {wrapper_path.name}: не удалён ({str(exc)[:60]})."
