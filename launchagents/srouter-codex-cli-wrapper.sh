#!/bin/sh
# srouter: codex CLI wrapper (managed)
#
# Codex CLI → напрямую SOCKS5 (xray), минуя privoxy (HTTP-CONNECT-прокси на порту brew-сервиса).
# privoxy портит WebSocket-стриминг Codex → "Reconnecting 1..5/5 → request timed out".
# xray-native SOCKS5 держит WS стабильно. socks5h:// = DNS резолвится на стороне прокси
# (важно за GFW — не утекает локальный DNS). Claude Code остаётся на privoxy (ему нужен HTTP).
#
# Issue #96: terminal-shell наследует HTTP_PROXY=privoxy из ~/.claude/settings.json
# (Claude Code env), и это перебивает launchctl SOCKS5 → Codex молча идёт через privoxy → режёт WS.
# Поэтому launcher сначала СБРАСЫВАЕТ все 8 прокси-переменных через /usr/bin/env -u, а затем
# детерминированно выставляет SOCKS5. Это гарантирует SOCKS-маршрут независимо от того, кто и как
# испортил окружение до нас. Одного -u недостаточно (даст direct) — всегда переустанавливаем.
#
# Вызывается shell-функцией codex() из ~/.zshrc по абсолютному пути (srouter install) — тогда порядок
# brew в PATH не важен. Для не-zsh вызывающих сторон (bash, command codex, GUI) стабильная точка
# входа — сам этот launcher ~/bin/codex.
# Первый комментарий — маркер srouter (uninstall удаляет только своё, чужой wrapper не трогает).
PROXY="__SROUTER_CODEX_PROXY_URL__"
LOOPBACK="__SROUTER_CODEX_NO_PROXY__"

exec /usr/bin/env \
  -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  -u http_proxy -u https_proxy -u all_proxy \
  -u NO_PROXY -u no_proxy \
  HTTP_PROXY="$PROXY" HTTPS_PROXY="$PROXY" ALL_PROXY="$PROXY" \
  http_proxy="$PROXY" https_proxy="$PROXY" all_proxy="$PROXY" \
  NO_PROXY="$LOOPBACK" no_proxy="$LOOPBACK" \
  __SROUTER_CODEX_BIN__ "$@"
