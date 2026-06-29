#!/usr/bin/env bash
# Диагностика цепочки srouter. Запускать ДВАЖДЫ: с VPN и без VPN, сравнить.
# Использование:  ./srouter-diag.sh                 (пометка "?")
#                 ./srouter-diag.sh novpn           (метка сразу аргументом)
#                 ./srouter-diag.sh vpn --state /path/to/srouter.local.json
set -euo pipefail

LABEL="?"
STATE_PATH="${SROUTER_STATE_PATH:-}"
BRIDGE="http://127.0.0.1:8118"
XRAY_SOCKS_PORT="10808"
PRIVOXY_PORT="8118"
DNSMASQ_PORT="53"
PROBE_SOCKS_HOST="127.0.0.1"

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="${SCRIPT_PATH%/*}"
if [[ "$SCRIPT_DIR" == "$SCRIPT_PATH" ]]; then
  SCRIPT_DIR="."
fi
ROOT_DIR="$(cd "$SCRIPT_DIR" && pwd -P)"

PYTHON_BIN="${SROUTER_PYTHON:-/usr/bin/python3}"
CURL_BIN="${SROUTER_CURL:-/usr/bin/curl}"
DIG_BIN="${SROUTER_DIG:-/usr/bin/dig}"
LSOF_BIN="${SROUTER_LSOF:-/usr/sbin/lsof}"
ROUTE_BIN="${SROUTER_ROUTE:-/sbin/route}"

die() {
  printf '[srouter-diag] ОШИБКА: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  ./srouter-diag.sh [vpn|novpn] [--state /path/to/srouter.local.json]

Скрипт только читает unified local state. Он не пишет srouter.local.json,
не аллоцирует probe-порты и не перезапускает xray/privoxy/dnsmasq.
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "не найдена команда '$1'"
}

LABEL_SET=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --state)
      [[ $# -ge 2 ]] || die "--state требует путь"
      STATE_PATH="$2"
      shift 2
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    --*)
      die "неизвестный аргумент '$1'"
      ;;
    *)
      if [[ "$LABEL_SET" -eq 1 ]]; then
        die "лишняя метка запуска '$1'"
      fi
      LABEL="$1"
      LABEL_SET=1
      shift
      ;;
  esac
done

need_cmd "$PYTHON_BIN"
need_cmd "$CURL_BIN"

check_local_state() {
  local module_path="${ROOT_DIR}/local_state.py"
  local rc
  [[ -f "$module_path" ]] || die "local_state не найден рядом со скриптом ($module_path)"
  set +e
  "$PYTHON_BIN" - "$ROOT_DIR" >/dev/null 2>&1 <<'PY'
import sys

root_dir = sys.argv[1]
sys.path.insert(0, root_dir)
import local_state  # noqa: F401,E402
PY
  rc=$?
  set -e
  [[ "$rc" -eq 0 ]] || die "local_state не импортируется рядом со скриптом ($module_path)"
}

# Читаем state через local_state: он валидирует узлы и даёт safe-defaults.
read_state() {
  "$PYTHON_BIN" - "$ROOT_DIR" "$STATE_PATH" <<'PY'
import sys
from pathlib import Path

root_dir = sys.argv[1]
state_path = sys.argv[2] or None
sys.path.insert(0, root_dir)

import local_state  # noqa: E402


def clean(value):
    return str(value if value is not None else "").replace("\t", " ").replace("\n", " ").replace("\r", " ").strip()


def http_url(value):
    return isinstance(value, str) and value.startswith(("http://", "https://"))


def safe_seconds(value, default):
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return default
    if seconds <= 0 or seconds > 120:
        return default
    return int(seconds) if seconds.is_integer() else seconds


def seconds_text(value):
    return str(int(value)) if isinstance(value, int) or float(value).is_integer() else str(value)


def safe_port(value):
    if isinstance(value, bool):
        return ""
    try:
        port = int(value)
    except (TypeError, ValueError):
        return ""
    return str(port) if 1 <= port <= 65535 else ""


state = local_state.load_state(path=state_path)
defaults = local_state._DEFAULT_STATE.get("probes", {})
probes = state.get("probes") if isinstance(state.get("probes"), dict) else {}
targets_raw = probes.get("reachability_targets")
targets = [x for x in targets_raw if http_url(x)] if isinstance(targets_raw, list) else []
if not targets:
    targets = [x for x in defaults.get("reachability_targets", []) if http_url(x)]

connect_timeout = safe_seconds(probes.get("connect_timeout_sec"), defaults.get("connect_timeout_sec", 4))
max_time = safe_seconds(probes.get("max_time_sec"), defaults.get("max_time_sec", 8))
active = local_state.active_node(path=state_path)
nodes = local_state.enabled_nodes(path=state_path)
state_display = str(Path(state_path).expanduser()) if state_path else str(local_state._DEFAULT_PATH)

print("meta\tstate_path\t" + clean(state_display))
print("meta\tactive_node\t" + clean(active.get("name") or ""))
print("meta\tconnect_timeout\t" + seconds_text(connect_timeout))
print("meta\tmax_time\t" + seconds_text(max_time))
print("meta\tenabled_count\t" + str(len(nodes)))
for target in targets:
    print("target\t" + clean(target))
for node in nodes:
    probe = node.get("probe") if isinstance(node.get("probe"), dict) else {}
    route_ip = local_state.resolve_route_ip(node, path=state_path) or node.get("route_ip") or node.get("endpoint_host") or ""
    active_mark = "*" if node.get("name") == active.get("name") else "-"
    print(
        "node\t{active}\t{name}\t{endpoint}\t{route_ip}\t{socks_port}".format(
            active=active_mark,
            name=clean(node.get("name")),
            endpoint=clean(node.get("endpoint_host")),
            route_ip=clean(route_ip),
            socks_port=safe_port(probe.get("socks_port")),
        )
    )
PY
}

check_local_state
STATE_DUMP=""
STATE_RC=0
set +e
STATE_DUMP="$(read_state 2>/dev/null)"
STATE_RC=$?
set -e
if [[ "$STATE_RC" -ne 0 ]]; then
  die "не удалось прочитать srouter.local.json через local_state (${STATE_PATH:-${ROOT_DIR}/srouter.local.json})"
fi
STATE_DISPLAY=""
ACTIVE_NODE=""
CONNECT_TIMEOUT="4"
MAX_TIME="8"
ENABLED_COUNT="0"
declare -a TARGETS=()
declare -a NODE_ACTIVE=()
declare -a NODE_NAMES=()
declare -a NODE_ENDPOINTS=()
declare -a NODE_ROUTE_IPS=()
declare -a NODE_SOCKS_PORTS=()

while IFS=$'\t' read -r kind key value extra1 extra2 extra3; do
  [[ -z "${kind:-}" ]] && continue
  case "$kind" in
    meta)
      case "$key" in
        state_path) STATE_DISPLAY="$value" ;;
        active_node) ACTIVE_NODE="$value" ;;
        connect_timeout) CONNECT_TIMEOUT="$value" ;;
        max_time) MAX_TIME="$value" ;;
        enabled_count) ENABLED_COUNT="$value" ;;
      esac
      ;;
    target)
      TARGETS+=("$key")
      ;;
    node)
      NODE_ACTIVE+=("$key")
      NODE_NAMES+=("$value")
      NODE_ENDPOINTS+=("$extra1")
      NODE_ROUTE_IPS+=("$extra2")
      NODE_SOCKS_PORTS+=("$extra3")
      ;;
  esac
done <<< "$STATE_DUMP"

run_curl() {
  local url="$1"
  shift
  local out
  local rc
  set +e
  out=$("$CURL_BIN" "$@" -sS -o /dev/null \
    --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" \
    -w "%{http_code}/%{time_total}s" "$url" 2>/dev/null)
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    printf 'FAIL(%s)' "$rc"
  else
    printf '%s' "$out"
  fi
}

probe_direct() {
  local url="$1"
  local out
  local rc
  set +e
  out=$(env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy -u ALL_PROXY -u all_proxy \
    "$CURL_BIN" --noproxy '*' -sS -o /dev/null \
    --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" \
    -w "%{http_code}/%{time_total}s" "$url" 2>/dev/null)
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    printf 'FAIL(%s)' "$rc"
  else
    printf '%s' "$out"
  fi
}

probe_bridge() {
  run_curl "$1" -x "$BRIDGE"
}

probe_node_socks() {
  local url="$1"
  local port="$2"
  if [[ -z "$port" ]]; then
    printf 'NO_PORT'
    return
  fi
  run_curl "$url" -x "socks5h://${PROBE_SOCKS_HOST}:${port}"
}

tcp_listener_status() {
  local port="$1"
  local out
  local count
  if ! command -v "$LSOF_BIN" >/dev/null 2>&1; then
    printf 'unknown'
    return
  fi
  out=$("$LSOF_BIN" -nP "-iTCP:${port}" -sTCP:LISTEN 2>/dev/null || true)
  count=$(printf '%s\n' "$out" | awk '$0 != "" && $1 != "COMMAND" {count++} END {print count + 0}')
  if [[ "$count" -gt 0 ]]; then
    printf 'open(%s)' "$count"
  else
    printf 'closed'
  fi
}

dns_listener_status() {
  local port="$1"
  local tcp_out
  local udp_out
  local count
  if ! command -v "$LSOF_BIN" >/dev/null 2>&1; then
    printf 'unknown'
    return
  fi
  tcp_out=$("$LSOF_BIN" -nP "-iTCP:${port}" -sTCP:LISTEN 2>/dev/null || true)
  udp_out=$("$LSOF_BIN" -nP "-iUDP:${port}" 2>/dev/null || true)
  count=$(printf '%s\n%s\n' "$tcp_out" "$udp_out" | awk '$0 != "" && $1 != "COMMAND" {count++} END {print count + 0}')
  if [[ "$count" -gt 0 ]]; then
    printf 'open(%s)' "$count"
  else
    printf 'closed'
  fi
}

dns_lookup() {
  local host="$1"
  local out
  if [[ -z "$host" ]]; then
    printf '-'
    return
  fi
  if [[ "$host" =~ ^[0-9]+(\.[0-9]+){3}$ || "$host" == *:* ]]; then
    printf '%s' "$host"
    return
  fi
  if ! command -v "$DIG_BIN" >/dev/null 2>&1; then
    printf 'NO_DIG'
    return
  fi
  out=$("$DIG_BIN" +short +time=3 +tries=1 "$host" 2>/dev/null | awk '/^[0-9]/ {print; exit}' || true)
  if [[ -n "$out" ]]; then
    printf '%s' "$out"
  else
    printf 'NXDOMAIN'
  fi
}

route_summary() {
  local target="$1"
  local out
  local iface
  local gateway
  if [[ -z "$target" ]]; then
    printf '-'
    return
  fi
  if [[ ! -x "$ROUTE_BIN" ]]; then
    printf 'NO_ROUTE'
    return
  fi
  out=$("$ROUTE_BIN" -n get -host "$target" 2>/dev/null || true)
  iface=$(printf '%s\n' "$out" | awk '/interface:/ {print $2; exit}')
  gateway=$(printf '%s\n' "$out" | awk '/gateway:/ {print $2; exit}')
  if [[ -n "$iface" || -n "$gateway" ]]; then
    printf 'iface=%s gw=%s' "${iface:-?}" "${gateway:-?}"
  else
    printf 'ROUTE_FAIL'
  fi
}

STAMP=$(date "+%Y-%m-%d %H:%M:%S")
echo "================ srouter diag @ $STAMP ================"
echo "## Окружение"
echo "Метка запуска (vpn / novpn): $LABEL"
echo "state: $STATE_DISPLAY"
echo "enabled nodes: $ENABLED_COUNT"
echo "active node: ${ACTIVE_NODE:-<none>}"
echo "timeouts: connect=${CONNECT_TIMEOUT}s max=${MAX_TIME}s"
echo "privoxy 127.0.0.1:${PRIVOXY_PORT}: $(tcp_listener_status "$PRIVOXY_PORT")"
echo "xray SOCKS 127.0.0.1:${XRAY_SOCKS_PORT}: $(tcp_listener_status "$XRAY_SOCKS_PORT")"
echo "dnsmasq 127.0.0.1:${DNSMASQ_PORT}: $(dns_listener_status "$DNSMASQ_PORT")"
echo "shell proxy env: HTTP_PROXY=${HTTP_PROXY:-<none>} HTTPS_PROXY=${HTTPS_PROXY:-<none>}"
echo

echo "## Узлы из srouter.local.json"
if [[ "${#NODE_NAMES[@]}" -eq 0 ]]; then
  echo "Нет enabled nodes: проверь nodes[].enabled и active_node в srouter.local.json."
else
  printf "%-14s | %-3s | %-22s | %-22s | %-13s | %-22s\n" \
    "NODE" "ACT" "ENDPOINT" "ROUTE_IP" "SOCKS" "ROUTE"
  printf -- "---------------+-----+------------------------+------------------------+---------------+-----------------------\n"
  for i in "${!NODE_NAMES[@]}"; do
    socks_status="NO_PORT"
    if [[ -n "${NODE_SOCKS_PORTS[$i]}" ]]; then
      socks_status="${NODE_SOCKS_PORTS[$i]}/$(tcp_listener_status "${NODE_SOCKS_PORTS[$i]}")"
    fi
    route=$(route_summary "${NODE_ROUTE_IPS[$i]}")
    printf "%-14s | %-3s | %-22s | %-22s | %-13s | %-22s\n" \
      "${NODE_NAMES[$i]}" "${NODE_ACTIVE[$i]}" "${NODE_ENDPOINTS[$i]}" "${NODE_ROUTE_IPS[$i]}" \
      "$socks_status" "$route"
  done
fi
echo

echo "## Проверка endpoint_host узлов"
if [[ "${#NODE_NAMES[@]}" -eq 0 ]]; then
  echo "Нет enabled nodes, endpoint_host проверять не на чем."
else
  printf "%-14s | %-22s | %-15s | %-12s | %-12s | %-12s\n" "NODE" "HOST" "DNS" "DIRECT" "BRIDGE" "NODE_SOCKS"
  printf -- "---------------+------------------------+-----------------+--------------+--------------+-------------\n"
  for i in "${!NODE_NAMES[@]}"; do
    dns=$(dns_lookup "${NODE_ENDPOINTS[$i]}")
    url="https://${NODE_ENDPOINTS[$i]}/"
    direct=$(probe_direct "$url")
    bridge=$(probe_bridge "$url")
    node_socks=$(probe_node_socks "$url" "${NODE_SOCKS_PORTS[$i]}")
    printf "%-14s | %-22s | %-15s | %-12s | %-12s | %-12s\n" \
      "${NODE_NAMES[$i]}" "${NODE_ENDPOINTS[$i]}" "$dns" "$direct" "$bridge" "$node_socks"
  done
fi
echo

echo "## Проверка target URLs из probes.reachability_targets"
if [[ "${#TARGETS[@]}" -eq 0 ]]; then
  echo "Нет валидных http(s) probes.reachability_targets."
elif [[ "${#NODE_NAMES[@]}" -eq 0 ]]; then
  echo "Нет enabled nodes, per-node SOCKS проверять не на чем."
else
  printf "%-14s | %-34s | %-12s | %-12s | %-12s\n" "NODE" "TARGET" "DIRECT" "BRIDGE" "NODE_SOCKS"
  printf -- "---------------+------------------------------------+--------------+--------------+-------------\n"
  for i in "${!NODE_NAMES[@]}"; do
    for target in "${TARGETS[@]}"; do
      direct=$(probe_direct "$target")
      bridge=$(probe_bridge "$target")
      node_socks=$(probe_node_socks "$target" "${NODE_SOCKS_PORTS[$i]}")
      printf "%-14s | %-34s | %-12s | %-12s | %-12s\n" \
        "${NODE_NAMES[$i]}" "$target" "$direct" "$bridge" "$node_socks"
    done
  done
fi

echo
echo "## Трактовка"
echo " DIRECT ok без VPN              -> цель доступна напрямую, ускоритель для неё не нужен"
echo " DIRECT=FAIL, BRIDGE=ok         -> локальная цепочка privoxy -> xray -> active node помогает"
echo " BRIDGE=FAIL, NODE_SOCKS=ok     -> per-node SOCKS жив, проблема в privoxy/main xray/active chain"
echo " NODE_SOCKS=NO_PORT             -> node.probe.socks_port отсутствует/битый; #17 его не аллоцирует"
echo " per-node SOCKS                 -> читается из node.probe.socks_port; #5 генерирует inbound, #7/#17 только проверяют"
echo " code 000 / FAIL                -> соединение оборвано/таймаут; 2xx-4xx = удалённый хост ответил"
echo "======================================================"
