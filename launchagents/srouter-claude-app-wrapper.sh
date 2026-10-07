# srouter: claude-app wrapper (managed)
# Явный точечный прокси для Claude.app (чат + Dispatch). Контракт маршрутизации 2026-10-07:
# ambient env-прокси в gui-домен launchd НЕ сеется — приложение ходит через туннель только
# если явно попросило. ДВА механизма, оба обязательны:
#   env HTTP(S)_PROXY  — Node-сторона main-процесса (sessions-bridge, axios);
#   --proxy-server     — Chromium-стек Electron env ИГНОРИРУЕТ (эмпирия 2026-10-07:
#                        с env-прокси сокеты оставались прямыми; тот же класс, что ChatGPT.app #189).
# Плечо — HTTP privoxy (Claude-приложения ломаются на SOCKS5, #127), НЕ SOCKS.
# --proxy-bypass-list: loopback мимо прокси. NO_PROXY: loopback + z.ai (канон
# zai-direct-no-proxy — z.ai НЕ за GFW, всегда напрямую).
# Управляется srouter install/remove (marker-gate); ручные правки будут перезаписаны.
# Запускать Claude.app ЧЕРЕЗ ЭТОТ WRAPPER: ~/bin/claude-app (env через `open` не передаётся).
set -eu
APP="__SROUTER_CLAUDE_APP_BIN__"
PROXY="__SROUTER_CLAUDE_PROXY_URL__"
NO_PROXY="__SROUTER_CLAUDE_NO_PROXY__"
[[ -x "$APP" ]] || { print -ru2 -- "Claude.app binary not found: $APP"; exit 1; }
exec /usr/bin/env \
  HTTPS_PROXY="$PROXY" HTTP_PROXY="$PROXY" \
  https_proxy="$PROXY" http_proxy="$PROXY" \
  NO_PROXY="$NO_PROXY" no_proxy="$NO_PROXY" \
  "$APP" \
  --proxy-server="$PROXY" --proxy-bypass-list="localhost;127.0.0.1;<local>" "$@"
