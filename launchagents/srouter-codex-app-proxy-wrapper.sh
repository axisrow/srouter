#!/bin/zsh
# srouter: codex-app-proxy wrapper (managed)
#
# ChatGPT/Codex.app (GUI из Dock/Spotlight) → Chromium через SOCKS5 (--proxy-server=socks5://127.0.0.1:10808),
# минуя privoxy (портит WS-стриминг Codex). HTTP_PROXY env ставится srouter install глобально через
# LaunchAgent com.srouter.codenv (launchctl setenv в GUI-домен) — здесь НЕ дублируется.
#
# Запускать Codex.app ЧЕРЕЗ ЭТОТ WRAPPER, а не иконку Dock (Dock не передаёт --proxy-server).
# Electron single-instance: сначала quit/pkill старого Codex, иначе аргументы уйдут в старый процесс.
#
# Ставится srouter install в ~/bin/codex-app-proxy.
# Первый комментарий — маркер srouter (uninstall удаляет только своё).
set -eu

APP_BUNDLE=""
APP_ID=""
APP_EXEC=""
APP_EXEC_NAME=""
for candidate in "/Applications/ChatGPT.app" "/Applications/Codex.app"; do
  [[ -d "$candidate" ]] || continue
  candidate_id=$(/usr/bin/plutil -extract CFBundleIdentifier raw -o - "$candidate/Contents/Info.plist" 2>/dev/null || true)
  candidate_executable=$(/usr/bin/plutil -extract CFBundleExecutable raw -o - "$candidate/Contents/Info.plist" 2>/dev/null || true)
  candidate_exec="$candidate/Contents/MacOS/$candidate_executable"
  [[ -n "$candidate_id" && -n "$candidate_executable" && -x "$candidate_exec" ]] || continue
  APP_BUNDLE="$candidate"
  APP_ID="$candidate_id"
  APP_EXEC="$candidate_exec"
  APP_EXEC_NAME="$candidate_executable"
  break
done
LOG="/tmp/codex-app-proxy.log"
CHROMIUM_PROXY_URL="socks5://127.0.0.1:10808"

if [[ -z "$APP_BUNDLE" || -z "$APP_ID" || ! -x "$APP_EXEC" ]]; then
  print -ru2 -- "ChatGPT.app/Codex.app not found or not executable: ${APP_BUNDLE:-none}"
  exit 1
fi

# Single-instance: аргументы нового запуска уходят в уже running Codex → прокси не применится.
osascript -e "tell application id \"$APP_ID\" to quit" >/dev/null 2>&1 || true
pkill -x "$APP_EXEC_NAME" 2>/dev/null || true
sleep 1

{
  print -r -- ""
  print -r -- "[$(date '+%Y-%m-%dT%H:%M:%S%z')] Starting $APP_BUNDLE via $CHROMIUM_PROXY_URL (env from srouter install)"
} >>"$LOG"

open -na "$APP_BUNDLE" --args "--proxy-server=$CHROMIUM_PROXY_URL" "$@"

print -r -- "Started $APP_BUNDLE through $CHROMIUM_PROXY_URL (env via srouter install LaunchAgent com.srouter.codenv)"
print -r -- "Log: $LOG"
