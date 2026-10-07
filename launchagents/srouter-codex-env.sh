#!/bin/sh
# srouter: контракт маршрутизации 2026-10-07 — ambient env-прокси НЕ сеется ни в один слой.
#
# Единый источник whitelist — srouter.local.json (routing.active/active_ips): через туннель
# ходит только явно попросившее (xray-правила, srouter git-proxy, per-tool wrappers, curl -x),
# всё остальное — напрямую. История: раньше этот скрипт ставил HTTP(S)_PROXY=privoxy 8118 в
# gui-домен launchd (issue #340, fail-closed «нет прямого egress»; до того — socks5h:10808 во
# всех ключах, ломавший pip/requests через SOCKSProxyManager, #331/#340). Контракт сменился
# осознанно: ложные «прямые» пробы диагностики (sub-ms time_connect до удалённого хоста),
# рестарт xray рвал TLS чужого не-туннельного трафика, privoxy — SPOF сессий.
#
# Роль скрипта теперь — ГАРАНТИРОВАННАЯ чистка residual-ключей в gui-домене. launchctl setenv
# не ретроактивен и не снимает то, чего не ставит: старые версии этого скрипта сеяли socks5h
# ALL_PROXY/all_proxy (#331/#340) и privoxy 8118 scheme-ключи — без явного unsetenv residual
# жил бы в gui-домене вечно и молча заворачивал GUI/терминальный трафик в цепочку. Периодичность
# агента (RunAtLoad + 300с) превращает чистку в инвариант: что бы ни вписало сторонее ПО в
# gui-домен, в течение 5 минут прокси-ключи вычищены. Список ключей = CODEX_LAUNCHCTL_UNSET_KEYS
# (codex_wrappers.py) — тот же список итерирует uninstall; паритет гвардится
# tests/test_codex_env_contract.py (ревью #403: NO_PROXY/no_proxy тоже сеялись до контракта —
# динамический NO_PROXY #197, — и без unsetenv residual жил бы в gui-домене вечно).
#
# Динамический NO_PROXY (#197, direct_first.no_proxy_string) без ambient-прокси инертен —
# посев снят вместе с serial-curl probe (он же — сотни секунд блокировки worst-case).
# CLI-codex wrapper'ы (~/bin/codex-srouter) ходят через socks5h:10808 ТОЧЕЧНО (#120) —
# от gui-домена не зависят, этот скрипт к ним не относится.
FAIL=0
for key in HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy; do
  launchctl unsetenv "$key" || FAIL=1
done
exit "$FAIL"
