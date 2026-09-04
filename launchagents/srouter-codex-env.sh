#!/bin/sh
# srouter: глобальный env для GUI-приложений через launchctl setenv (issue #340).
#
# Запускается LaunchAgent com.srouter.codenv (RunAtLoad + каждые ~5мин, переживает ребут).
# launchctl setenv кладёт переменные в caller-context (man launchctl). Этот скрипт запускается
# launchd ВНУТРИ gui-домена → caller-context = gui → переменные попадают в gui-домен (видят все
# GUI-приложения). Поэтому setenv ЗДЕСЬ — БЕЗ домена намеренно: `setenv gui/<uid> ...` даёт rc=64
# (usage error) — доменный таргет setenv не принимает. Симметрия: uninstall (_remove_launchctl_env)
# делает `unsetenv gui/<uid> <key>` с ЯВНЫМ доменом (он бежит из процесса cmd_uninstall, чей
# caller-context может быть user/<uid> из SSH/cron — issue #94 DEFECT A).
#
# #331/#340: scheme-ключи (HTTP(S)_PROXY, оба регистра) = privoxy 8118 — ТЕРМИНАЛЬНОЕ плечо.
# Раньше здесь стоял socks5h:10808 во ВСЕХ ключах, включая ALL_PROXY: каждый GUI-терминал
# наследовал socks5h, requests/pip через select_proxy берут scheme-ключ РАНЬШЕ 'all' →
# SOCKSProxyManager → TypeError PoolKey key_proxy_ssl_context на любом сетевом запросе (#340;
# удаление одного ALL_PROXY не помогло бы — socks5h в HTTPS_PROXY ломает так же). privoxy-http —
# рабочее прокси-плечо (privoxy→xray): pip в свежем терминале работает, прямой egress по-прежнему
# отсутствует (fail-closed, канон fail-closed-proxy-down). ALL_PROXY/all_proxy БОЛЬШЕ НЕ СТАВЯТСЯ:
# reqwest (Codex Rust app-server) тоже берёт scheme-ключ раньше 'all' (src/proxy.rs «Overwritten
# by the more specific HTTP_PROXY») → 'all'-ключ избыточен для потребителя; текущий app-server
# к тому же спавнится ChatGPT.app с санитизованным env без прокси-переменных (ps eww, #340) —
# gui-домен до него не доходит. CLI-codex wrapper'ы (~/bin/codex-srouter) продолжают ходить через
# socks5h:10808 ТОЧЕЧНО (privoxy рвёт их WS, #120) — этот скрипт к ним не относится.
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
# RunAtLoad на буте launchctl-env пуст — если бы PROXY ставился ПОСЛЕ probe, GUI-процессы,
# стартующие в окне probe, унаследовали бы отсутствие прокси → прямой egress под GFW (утечка
# реального IP). launchctl setenv не ретроактивен → уже запущенные не чинятся.
# Инвариант fail-closed-proxy-down: окно без прокси = 0. probe нужен ТОЛЬКО для NO_PROXY (логически
# независим от PROXY-vars) → сначала ставим прокси+безопасный NO_PROXY, потом уточняем NO_PROXY.
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="${SROUTER_PYTHON:-/usr/bin/python3}"
PROXY="http://127.0.0.1:8118"
FALLBACK_NO_PROXY="localhost,127.0.0.1,::1,z.ai,.z.ai"
# Статус сбоев launchctl (#340 cycle-review): job-check читает last exit code — «проглотивший»
# сбой скрипт (rc=0 при провале setenv/unsetenv) выглядит здоровым в launchd, пока gui-домен
# остаётся с pip-ломающим плечом или вообще без прокси. Накапливаем и отдаём ненулевой exit.
FAIL=0
# 1) PROXY-переменные + conservative NO_PROXY — НЕМЕДЛЕННО (без сетевого ожидания), fail-closed.
for key in HTTP_PROXY HTTPS_PROXY http_proxy https_proxy; do
  launchctl setenv "$key" "$PROXY" || FAIL=1
done
launchctl setenv NO_PROXY "$FALLBACK_NO_PROXY" || FAIL=1
launchctl setenv no_proxy "$FALLBACK_NO_PROXY" || FAIL=1
# 1b) residual-чистка #331/#340: старые версии этого скрипта ставили ALL_PROXY/all_proxy=socks5h
#     в gui-домен; launchctl setenv не ретроактивен и не снимает то, чего не ставит → без явного
#     unsetenv residual socks5h жил бы в gui-домене вечно и продолжал ломать pip/requests.
launchctl unsetenv ALL_PROXY || FAIL=1
launchctl unsetenv all_proxy || FAIL=1
# 2) Динамический NO_PROXY — ПОСЛЕ (блокирующий probe). Обновляет ТОЛЬКО NO_PROXY; PROXY уже стоит.
#    Пустой результат (Python/detect сбой) → оставляем conservative fallback, уже выставленный выше.
NO_PROXY="$("$PYTHON_BIN" -c "import sys; sys.path.insert(0, '$ROOT_DIR'); import direct_first; print(direct_first.no_proxy_string())" 2>/dev/null)"
if [ -n "$NO_PROXY" ]; then
  launchctl setenv NO_PROXY "$NO_PROXY" || FAIL=1
  launchctl setenv no_proxy "$NO_PROXY" || FAIL=1
fi
exit "$FAIL"
