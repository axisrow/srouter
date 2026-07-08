#!/usr/bin/env bash
# Диагностика доступности хостов Claude Code. Запускать ДВАЖДЫ: с VPN и без VPN, сравнить.
# Использование:  ./diag-proxy.sh           (попросит пометку vpn/novpn)
#                 ./diag-proxy.sh novpn      (метка сразу аргументом)

LABEL="${1:-?}"
BRIDGE="http://127.0.0.1:8118"
SOCKS="socks5h://USER:PASS@YOUR_VPS_IP:1080"

# Бинарники параметризуемы через env — тот же канон подмены, что в srouter-diag.sh
# (shell-тесты подставляют fake curl/dig, чтобы гонять скрипт без реальной сети).
CURL_BIN="${SROUTER_CURL:-curl}"
DIG_BIN="${SROUTER_DIG:-dig}"

HOSTS=(api.anthropic.com claude.ai platform.claude.com downloads.claude.ai \
       storage.googleapis.com bridge.claudeusercontent.com raw.githubusercontent.com \
       statsig.anthropic.com api.statsig.com)

STAMP=$(date "+%Y-%m-%d %H:%M:%S")
echo "================ Claude Code proxy diag @ $STAMP ================"
echo "## Окружение"
echo "Метка запуска (vpn / novpn): $LABEL"
echo "privoxy listeners on 8118: $(lsof -nP -iTCP:8118 -sTCP:LISTEN 2>/dev/null | grep -ci privoxy)"
echo "shell proxy env: HTTP_PROXY=${HTTP_PROXY:-<none>} HTTPS_PROXY=${HTTPS_PROXY:-<none>}"
echo "claude version: $(claude --version 2>&1 | head -1)"
echo

# probe URL через заданный режим. Возвращает "код/время" или "FAIL(код выхода curl)".
probe() { # $1=host  $2..=доп.аргументы curl
  local host="$1"; shift
  local out
  out=$("$CURL_BIN" "$@" -s -o /dev/null --max-time 12 \
        -w "%{http_code}/%{time_total}s" "https://$host/" 2>/dev/null)
  local rc=$?
  if [ $rc -ne 0 ]; then echo "FAIL($rc)"; else echo "$out"; fi
}

# DIRECT: принудительно БЕЗ прокси (сбрасываем env и --noproxy), чтобы тест был реально прямым.
# rc ловим отдельно (как в probe()): при провале curl -w печатает частичный write-out
# ('000/...') в stdout, а '|| echo FAIL' его бы приклеил — колонка DIRECT исказилась бы.
probe_direct() {
  local out
  out=$(env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy -u ALL_PROXY \
        "$CURL_BIN" --noproxy '*' -s -o /dev/null --max-time 12 \
        -w "%{http_code}/%{time_total}s" "https://$1/" 2>/dev/null)
  local rc=$?
  if [ $rc -ne 0 ]; then echo "FAIL($rc)"; else echo "$out"; fi
}

printf "%-30s | %-15s | %-10s | %-10s | %-10s\n" "HOST" "DNS" "DIRECT" "BRIDGE" "SOCKS5"
printf -- "-------------------------------+-----------------+------------+------------+-----------\n"
for h in "${HOSTS[@]}"; do
  dns=$("$DIG_BIN" +short +time=3 +tries=1 "$h" 2>/dev/null | grep -E '^[0-9]' | head -1)
  [ -z "$dns" ] && dns="NXDOMAIN"
  direct=$(probe_direct "$h")
  bridge=$(probe "$h" -x "$BRIDGE")
  socks=$(probe "$h" -x "$SOCKS")
  printf "%-30s | %-15s | %-10s | %-10s | %-10s\n" "$h" "$dns" "$direct" "$bridge" "$socks"
done

echo
echo "## Доп: реальный канал, которым ходит Claude Code (HTTPS_PROXY из его env)"
echo -n "claude env proxy -> api.anthropic.com: "
probe api.anthropic.com -x "${HTTPS_PROXY:-$BRIDGE}"
echo

echo "## Трактовка"
echo " DIRECT ok без VPN          → хост НЕ заблокирован, прокси для него не нужен"
echo " DIRECT=FAIL, BRIDGE=ok     → хост блокируется, мост спасает (это норма для Китая)"
echo " BRIDGE=FAIL, SOCKS5=ok     → проблема в privoxy/HTTP-слое, не в SOCKS"
echo " BRIDGE=FAIL и SOCKS5=FAIL  → GFW режет хост даже через VPS SOCKS5 (по SNI) → нужна обфускация"
echo " код 000 / FAIL             → соединение оборвано/таймаут (блок); 2xx-4xx = хост ответил (ok)"
echo "================================================================"
