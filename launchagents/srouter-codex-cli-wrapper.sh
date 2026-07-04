#!/bin/sh
# srouter: codex CLI wrapper (managed)
#
# Codex CLI → напрямую SOCKS5 (xray 10808), минуя privoxy (8118).
# privoxy (HTTP-CONNECT-прокси) портит WebSocket-стриминг Codex → "Reconnecting 1..5/5 → request
# timed out". xray-native SOCKS5 держит WS стабильно. socks5h:// = DNS резолвится на стороне прокси
# (важно за GFW — не утекает локальный DNS). Claude Code остаётся на privoxy (ему нужен HTTP).
#
# Ставится srouter install в ~/bin/codex (раньше в PATH, чем системный codex, через ~/.zshrc).
# Первый комментарий — маркер srouter (uninstall удаляет только своё, чужой wrapper не трогает).
export HTTP_PROXY=socks5h://127.0.0.1:10808
export HTTPS_PROXY=socks5h://127.0.0.1:10808
export http_proxy=socks5h://127.0.0.1:10808
export https_proxy=socks5h://127.0.0.1:10808
export NO_PROXY=localhost,127.0.0.1,::1
exec __SROUTER_CODEX_BIN__ "$@"
