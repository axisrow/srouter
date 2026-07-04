#!/bin/sh
# srouter: глобальный SOCKS5 env для GUI-приложений (Codex.app и др.) через launchctl setenv.
#
# Запускается LaunchAgent com.srouter.codex-env (RunAtLoad + каждые ~5мин, переживает ребут).
# launchctl setenv кладёт переменные в GUI-домен launchd → все GUI-приложения их видят.
# Эмпирически: Claude.app/ChatGPT.app на System Settings SOCKS, global env их не ломает.
# NO_PROXY=loopback — локальные сервисы (MCP/healthcheck) мимо прокси.
PROXY="socks5h://127.0.0.1:10808"
NO_PROXY="localhost,127.0.0.1,::1"
for key in HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; do
  launchctl setenv "$key" "$PROXY"
done
launchctl setenv NO_PROXY "$NO_PROXY"
launchctl setenv no_proxy "$NO_PROXY"
