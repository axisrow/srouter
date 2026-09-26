#!/usr/bin/env bash
# Диагностика доступности хостов Claude Code. Запускать ДВАЖДЫ: с VPN и без VPN, сравнить.
# Использование:  ./diag-proxy.sh           (попросит пометку vpn/novpn)
#                 ./diag-proxy.sh novpn      (метка сразу аргументом)

LABEL="${1:-?}"
# Бинарники параметризуемы через env — тот же канон подмены, что в srouter-diag.sh
# (shell-тесты подставляют fake curl/dig, чтобы гонять скрипт без реальной сети).
CURL_BIN="${SROUTER_CURL:-curl}"
DIG_BIN="${SROUTER_DIG:-dig}"
PY_BIN="${SROUTER_PYTHON:-python3}"

BRIDGE="http://127.0.0.1:8118"

# SOCKS5-плечо (issue #366): цель берём из local.json (первый enabled node →
# probe.socks_port), а не из плейсхолдера: заглушка YOUR_VPS_IP давала вечный FAIL(6)
# и ложную тревогу «SOCKS сломан» при живой сети. Override: SROUTER_SOCKS=<proxy-url>.
# Не настроено → колонка честно SKIPPED, а не FAIL.
STATE_PATH="${SROUTER_STATE_PATH:-$(dirname "$0")/srouter.local.json}"
SOCKS="${SROUTER_SOCKS:-}"
if [ -z "$SOCKS" ] && [ -f "$STATE_PATH" ]; then
  SOCKS_PORT=$("$PY_BIN" - "$STATE_PATH" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        state = json.load(fh)
except Exception:
    raise SystemExit(0)
for node in state.get("nodes") or []:
    if not (isinstance(node, dict) and node.get("enabled")):
        continue
    probe = node.get("probe") if isinstance(node.get("probe"), dict) else {}
    port = probe.get("socks_port")
    if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
        print(port)
    break
PY
)
  [ -n "$SOCKS_PORT" ] && SOCKS="socks5h://127.0.0.1:$SOCKS_PORT"
fi

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
  if [ -n "$SOCKS" ]; then
    socks=$(probe "$h" -x "$SOCKS")
  else
    socks="SKIPPED"
  fi
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
echo " SOCKS5=SKIPPED             → per-node SOCKS не настроен (нет local.json/probe.socks_port); задай SROUTER_SOCKS"
echo " код 000 / FAIL             → соединение оборвано/таймаут (блок); 2xx-4xx = хост ответил (ok)"
echo "================================================================"
