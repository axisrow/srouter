"""Общие константы health-модулей: прокси/порты стека (issue #158 — третий модуль без цикла).

Извлечено из health.py при разбиении на probes/claude/codex/endpoint/reporting (канон
third-module-breaks-reexport-cycle): health_probes.py и health.py оба нуждаются в _PROXY/
PRIVOXY_PORT/XRAY_PORT — общий слой здесь, а не делегация через __dict__ или взаимный импорт.

Прокси = privoxy (8118). Берём из dashboard_common если доступен; fallback на хардкод, чтобы
модуль не падал в среде без srouter_config (как git_proxy/claude_proxy).
"""
import logging
import os
from pathlib import Path

_log = logging.getLogger("srouter.health")

try:
    from dashboard_common import HTTP_PROXY_URL as _PROXY  # http://127.0.0.1:8118
    # Порты компонентов стека — единый источник dashboard_common (issue #155).
    from dashboard_common import PRIVOXY_PORT, XRAY_SOCKS_PORT as XRAY_PORT
except (ImportError, SystemExit) as exc:  # noqa: BLE001 — намеренно широкий top-level import-guard.
    # dashboard_common без srouter_config.py бросает SystemExit (не ImportError) — ветка унаследована
    # от канона (git_proxy/claude_proxy). Оба случая (модуль недоступен / конфиг не создан) равнозначны
    # для health: используем fallback-константы, не роняем модуль на import time (probe-канон — health
    # не бросает). Маркер canonical-fallback-port
    _log.info("dashboard_common недоступен (%s: %s) — health использует fallback-константы порта",
              type(exc).__name__, exc)
    _PROXY = "http://127.0.0.1:8118"
    # Fallback на то же каноническое значение. Значения здесь держат единый литерал, а не
    # расходящийся хардкод, даже когда srouter_config недоступен — tests/test_proxy_constants.py
    # пропускает как осознанный fallback, не свежий дубликат.
    PRIVOXY_PORT = 8118  # canonical-fallback-port
    XRAY_PORT = 10808  # canonical-fallback-port

DASHBOARD_PORT = 8787

# Err-лог демона — источник диагноза crash-loop'а (_dashboard_check, инцидент 2026-10-08:
# порт мёртв + ModuleNotFoundError в хвосте = plist отрендерен питоном без flask).
# SROUTER_LOG_DIR — тот же override, что резолвит install_config.InstallEnv.from_env.
DASHBOARD_ERR_LOG = Path(
    os.environ.get("SROUTER_LOG_DIR", str(Path.home() / "Library" / "Logs"))
) / "srouter-dashboard.err.log"
