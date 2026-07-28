#!/bin/sh
# srouter: глобальный SOCKS5 env для GUI-приложений (Codex.app и др.) через launchctl setenv.
#
# Запускается LaunchAgent com.srouter.codenv (RunAtLoad + каждые ~5мин, переживает ребут).
# launchctl setenv кладёт переменные в caller-context (man launchctl). Этот скрипт запускается
# launchd ВНУТРИ gui-домена → caller-context = gui → переменные попадают в gui-домен (видят все
# GUI-приложения). Поэтому setenv ЗДЕСЬ — БЕЗ домена намеренно: `setenv gui/<uid> ...` даёт rc=64
# (usage error) — доменный таргет setenv не принимает. Симметрия: uninstall (_remove_launchctl_env)
# делает `unsetenv gui/<uid> <key>` с ЯВНЫМ доменом (он бежит из процесса cmd_uninstall, чей
# caller-context может быть user/<uid> из SSH/cron — issue #94 DEFECT A).
# Эмпирически: Claude.app/ChatGPT.app на System Settings SOCKS, global env их не ломает.
#
# #197 direct-first: NO_PROXY динамический — direct_first.no_proxy_string() честным прямым
# TLS-test'ом (мимо прокси) проверяет candidate-домены (z.ai BUILTIN + user direct_domains из
# srouter.local.json), reachable → в NO_PROXY. Периодичность = этот же LaunchAgent (StartInterval
# 300с) — отдельный re-check-агент не нужен, GFW-флап подхватывается на следующем прогоне.
# Скрипт НЕ рендерится при install (запускается in-place из env.root/launchagents/, как
# health.py у watchdog) — сам резолвит ROOT_DIR через dirname (родитель launchagents/ = env.root),
# исключая класс багов «плейсхолдер не отрендерен» (PR #189 error 5 регрессия).
# При сбое Python/detect (сеть недоступна на install, srouter_config.py отсутствует и т.д.) →
# fallback на BUILTIN (z.ai всегда direct — канон zai-direct-no-proxy, srouter-critical-infra-24-7).
#
# ПОРЯДОК КРИТИЧЕН (#197 cycle-review, boot-race): PROXY-переменные + conservative fallback NO_PROXY
# выставляются СРАЗУ, ДО блокирующего direct_first.no_proxy_string() probe. no_proxy_string() бьёт
# serial curl per-domain (до MAX_CANDIDATE_DOMAINS × max_time ≈ сотни секунд worst-case); при
# RunAtLoad на буте launchctl-env пуст — если бы PROXY ставился ПОСЛЕ probe, GUI-процессы
# (Codex.app/ChatGPT.app), стартующие в окне probe, унаследовали бы отсутствие SOCKS → прямой egress
# под GFW (утечка реального IP). launchctl setenv не ретроактивен → уже запущенные не чинятся.
# Инвариант fail-closed-proxy-down: окно без прокси = 0. probe нужен ТОЛЬКО для NO_PROXY (логически
# независим от PROXY-vars) → сначала ставим прокси+безопасный NO_PROXY, потом уточняем NO_PROXY.
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="${SROUTER_PYTHON:-/usr/bin/python3}"
PROXY="socks5h://127.0.0.1:10808"
FALLBACK_NO_PROXY="localhost,127.0.0.1,::1,z.ai,.z.ai"
# 1) PROXY-переменные + conservative NO_PROXY — НЕМЕДЛЕННО (без сетевого ожидания), fail-closed.
for key in HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; do
  launchctl setenv "$key" "$PROXY"
done
launchctl setenv NO_PROXY "$FALLBACK_NO_PROXY"
launchctl setenv no_proxy "$FALLBACK_NO_PROXY"
# 2) Динамический NO_PROXY — ПОСЛЕ (блокирующий probe). Обновляет ТОЛЬКО NO_PROXY; PROXY уже стоит.
#    Пустой результат (Python/detect сбой) → оставляем conservative fallback, уже выставленный выше.
NO_PROXY="$("$PYTHON_BIN" -c "import sys; sys.path.insert(0, '$ROOT_DIR'); import direct_first; print(direct_first.no_proxy_string())" 2>/dev/null)"
if [ -n "$NO_PROXY" ]; then
  launchctl setenv NO_PROXY "$NO_PROXY"
  launchctl setenv no_proxy "$NO_PROXY"
fi
