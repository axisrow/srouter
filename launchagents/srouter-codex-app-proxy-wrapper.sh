#!/bin/zsh
# srouter: codex-app-proxy wrapper (managed)
#
# Codex.app (GUI из Dock/Spotlight) → Chromium через SOCKS5 (--proxy-server=socks5://127.0.0.1:10808),
# минуя privoxy (портит WS-стриминг Codex). HTTP_PROXY env ставится srouter install глобально через
# LaunchAgent com.srouter.codenv (launchctl setenv в GUI-домен) — здесь НЕ дублируется.
#
# Запускать Codex.app ЧЕРЕЗ ЭТОТ WRAPPER, а не иконку Dock (Dock не передаёт --proxy-server).
# Electron single-instance: сначала quit/pkill старого Codex, иначе аргументы уйдут в старый процесс.
#
# Ставится srouter install в ~/bin/codex-app-proxy.
# Первый комментарий — маркер srouter (uninstall удаляет только своё).
set -eu

APP_BUNDLE="/Applications/Codex.app"
APP_EXEC="$APP_BUNDLE/Contents/MacOS/Codex"
APP_ID="com.openai.codex"
LOG="/tmp/codex-app-proxy.log"
CHROMIUM_PROXY_URL="socks5://127.0.0.1:10808"

if [[ ! -d "$APP_BUNDLE" || ! -x "$APP_EXEC" ]]; then
  print -ru2 -- "Codex.app not found or not executable: $APP_BUNDLE"
  exit 1
fi

# Single-instance: аргументы нового запуска уходят в уже running Codex → прокси не применится.
osascript -e "tell application id \"$APP_ID\" to quit" >/dev/null 2>&1 || true
pkill -x Codex 2>/dev/null || true
sleep 1

{
  print -r -- ""
  print -r -- "[$(date '+%Y-%m-%dT%H:%M:%S%z')] Starting Codex.app via $CHROMIUM_PROXY_URL (env from srouter install)"
} >>"$LOG"

open -na "$APP_BUNDLE" --args "--proxy-server=$CHROMIUM_PROXY_URL" "$@"

print -r -- "Started Codex.app through $CHROMIUM_PROXY_URL (env via srouter install LaunchAgent com.srouter.codenv)"
print -r -- "Log: $LOG"
