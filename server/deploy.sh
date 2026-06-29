#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN_KEYS="${SCRIPT_DIR}/gen-keys.sh"

MODE=""
BUNDLE_DIR=""
NODE_NAME=""
ENDPOINT_HOST=""
ROUTE_IP=""
COUNTRY_CODE=""
ENABLED="true"
COMPOSE_WAIT_TIMEOUT="${COMPOSE_WAIT_TIMEOUT:-60}"
PROBE_SOCKS_PORT="11080"
LISTEN_PORT="443"
XRAY_DEST="www.163.com:443"
XRAY_SNI="www.163.com"
XRAY_FLOW="xtls-rprx-vision"

XRAY_UUID=""
XRAY_PRIVATE_KEY=""
XRAY_PUBLIC_KEY=""
XRAY_SHORT_ID=""

ENV_PATH=""
COMPOSE_PATH=""
NODE_OBJECT_PATH=""

log() {
  printf '[srouter-deploy] %s\n' "$*" >&2
}

die() {
  log "ОШИБКА: $*"
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage:
  server/deploy.sh generate --endpoint-host HOST [options]
  server/deploy.sh deploy   --endpoint-host HOST [options]

Modes:
  generate  render-only: создать bundle и полный node-object, без Docker/Compose
  deploy    apply: проверить Docker Compose, поднять контейнер и напечатать node-object

Options:
  --bundle-dir PATH          Куда писать deploy bundle (default: server/.generated/<node>)
  --name NAME                nodes[].name (default: из country/endpoint_host)
  --endpoint-host HOST       Публичный host/IP сервера, обязательно
  --route-ip HOST            IP/host для route_ip; default = endpoint-host, если это IPv4
  --country-code CC          Двухбуквенный country_code
  --probe-socks-port PORT    nodes[].probe.socks_port (default: 11080)
  --listen-port PORT         VLESS/Reality port (default: 443)
  --xray-dest HOST:PORT      Reality dest (default: www.163.com:443)
  --xray-sni HOST            Reality SNI (default: www.163.com)
  --xray-flow FLOW           VLESS flow (default: xtls-rprx-vision)
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "не найдена команда '$1'"
}

arg_value() {
  local flag="$1"
  local value="${2:-}"

  [[ -n "$value" ]] || die "${flag} требует значение"
  printf '%s\n' "$value"
}

write_atomic() {
  local path="$1"
  local content="$2"
  local mode="$3"
  local dir
  local tmp_path

  dir="$(dirname "$path")"
  mkdir -p "$dir"
  umask 077
  tmp_path="$(mktemp "${dir}/.tmp.XXXXXX")"
  printf '%s\n' "$content" > "$tmp_path"
  chmod "$mode" "$tmp_path"
  mv "$tmp_path" "$path"
  chmod "$mode" "$path"
}

is_port() {
  local value="$1"
  local number

  case "$value" in
    ''|*[!0-9]*)
      return 1
      ;;
  esac
  number=$((10#$value))
  (( number >= 1 && number <= 65535 ))
}

is_ipv4() {
  local value="$1"
  local IFS=.
  local parts
  local part

  [[ "$value" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  # shellcheck disable=SC2206
  parts=($value)
  for part in "${parts[@]}"; do
    (( 10#$part <= 255 )) || return 1
  done
}

validate_token() {
  local name="$1"
  local value="$2"

  [[ -n "$value" ]] || die "${name} пуст"
  [[ "$value" =~ ^[A-Za-z0-9._-]+$ ]] || die "${name} содержит недопустимые символы"
}

validate_dest() {
  local dest_port
  local dest_port_num

  [[ "$XRAY_DEST" =~ ^[A-Za-z0-9._-]+:[0-9]{1,5}$ ]] \
    || die "XRAY_DEST должен иметь формат host:port без кавычек"
  dest_port="${XRAY_DEST##*:}"
  dest_port_num=$((10#$dest_port))
  (( dest_port_num >= 1 && dest_port_num <= 65535 )) || die "XRAY_DEST port вне диапазона 1..65535"
}

validate_keys() {
  [[ "$XRAY_UUID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
    || die "XRAY_UUID должен быть UUID в canonical-формате"
  [[ "$XRAY_PRIVATE_KEY" =~ ^[A-Za-z0-9_-]{40,64}$ ]] \
    || die "XRAY_PRIVATE_KEY должен быть base64url-ключом X25519 без кавычек"
  [[ "$XRAY_PUBLIC_KEY" =~ ^[A-Za-z0-9_-]{40,64}$ ]] \
    || die "XRAY_PUBLIC_KEY должен быть base64url-ключом X25519 без кавычек"
  [[ "$XRAY_SHORT_ID" =~ ^[0-9a-fA-F]+$ ]] || die "XRAY_SHORT_ID должен быть hex-строкой"
  (( ${#XRAY_SHORT_ID} <= 16 )) || die "XRAY_SHORT_ID длиннее 16 hex-символов"
  (( ${#XRAY_SHORT_ID} % 2 == 0 )) || die "XRAY_SHORT_ID должен иметь чётную длину"
  XRAY_SHORT_ID="$(printf '%s' "$XRAY_SHORT_ID" | tr 'A-F' 'a-f')"
}

default_node_name() {
  local source="$1"
  local slug

  slug="$(printf '%s' "$source" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '-')"
  slug="$(printf '%s' "$slug" | sed -E 's/^-+//; s/-+$//; s/-+/-/g')"
  if [[ -z "$slug" ]]; then
    slug="node"
  fi
  printf '%s-1\n' "$slug"
}

parse_args() {
  MODE="${1:-}"
  if [[ -z "$MODE" ]]; then
    usage
    die "mode обязателен: generate или deploy"
  fi

  case "$MODE" in
    generate|deploy)
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      die "неизвестный mode: ${MODE}"
      ;;
  esac
  shift

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --bundle-dir)
        BUNDLE_DIR="$(arg_value "$1" "${2:-}")"
        shift 2
        ;;
      --name)
        NODE_NAME="$(arg_value "$1" "${2:-}")"
        shift 2
        ;;
      --endpoint-host)
        ENDPOINT_HOST="$(arg_value "$1" "${2:-}")"
        shift 2
        ;;
      --route-ip)
        ROUTE_IP="$(arg_value "$1" "${2:-}")"
        shift 2
        ;;
      --country-code)
        COUNTRY_CODE="$(arg_value "$1" "${2:-}")"
        shift 2
        ;;
      --probe-socks-port)
        PROBE_SOCKS_PORT="$(arg_value "$1" "${2:-}")"
        shift 2
        ;;
      --listen-port)
        LISTEN_PORT="$(arg_value "$1" "${2:-}")"
        shift 2
        ;;
      --xray-dest)
        XRAY_DEST="$(arg_value "$1" "${2:-}")"
        shift 2
        ;;
      --xray-sni)
        XRAY_SNI="$(arg_value "$1" "${2:-}")"
        shift 2
        ;;
      --xray-flow)
        XRAY_FLOW="$(arg_value "$1" "${2:-}")"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        usage
        die "неизвестный аргумент: $1"
        ;;
    esac
  done
}

normalize_options() {
  [[ -n "$ENDPOINT_HOST" ]] || die "--endpoint-host обязателен"
  validate_token "--endpoint-host" "$ENDPOINT_HOST"

  if [[ -z "$ROUTE_IP" ]]; then
    if is_ipv4 "$ENDPOINT_HOST"; then
      ROUTE_IP="$ENDPOINT_HOST"
    else
      die "--route-ip обязателен, если --endpoint-host не IPv4"
    fi
  fi
  validate_token "--route-ip" "$ROUTE_IP"

  if [[ -n "$COUNTRY_CODE" ]]; then
    COUNTRY_CODE="$(printf '%s' "$COUNTRY_CODE" | tr '[:lower:]' '[:upper:]')"
    [[ "$COUNTRY_CODE" =~ ^[A-Z]{2}$ ]] || die "--country-code должен быть двухбуквенным кодом"
  fi

  if [[ -z "$NODE_NAME" ]]; then
    if [[ -n "$COUNTRY_CODE" ]]; then
      NODE_NAME="$(default_node_name "$COUNTRY_CODE")"
    else
      NODE_NAME="$(default_node_name "$ENDPOINT_HOST")"
    fi
  fi
  validate_token "--name" "$NODE_NAME"

  is_port "$LISTEN_PORT" || die "--listen-port должен быть числом от 1 до 65535"
  is_port "$PROBE_SOCKS_PORT" || die "--probe-socks-port должен быть числом от 1 до 65535"
  validate_token "XRAY_SNI" "$XRAY_SNI"
  validate_token "XRAY_FLOW" "$XRAY_FLOW"
  validate_dest

  if [[ -z "$BUNDLE_DIR" ]]; then
    BUNDLE_DIR="${SCRIPT_DIR}/.generated/${NODE_NAME}"
  fi
  ENV_PATH="${BUNDLE_DIR}/.env"
  COMPOSE_PATH="${BUNDLE_DIR}/docker-compose.yml"
  NODE_OBJECT_PATH="${BUNDLE_DIR}/node_object.json"
}

read_env_value() {
  local key="$1"
  local path="$2"

  [[ -f "$path" ]] || return 1
  awk -F= -v key="$key" '
    $1 == key {
      print substr($0, index($0, "=") + 1)
      found = 1
      exit
    }
    END { if (!found) exit 1 }
  ' "$path"
}

load_keys_from_env() {
  XRAY_UUID="$(read_env_value XRAY_UUID "$ENV_PATH" || true)"
  XRAY_PRIVATE_KEY="$(read_env_value XRAY_PRIVATE_KEY "$ENV_PATH" || true)"
  XRAY_PUBLIC_KEY="$(read_env_value XRAY_PUBLIC_KEY "$ENV_PATH" || true)"
  XRAY_SHORT_ID="$(read_env_value XRAY_SHORT_ID "$ENV_PATH" || true)"
}

generate_keys() {
  local output
  local key
  local value

  [[ -x "$GEN_KEYS" ]] || die "gen-keys.sh не найден или не исполняемый: ${GEN_KEYS}"
  output="$("$GEN_KEYS")"
  while IFS='=' read -r key value; do
    case "$key" in
      XRAY_UUID) XRAY_UUID="$value" ;;
      XRAY_PRIVATE_KEY) XRAY_PRIVATE_KEY="$value" ;;
      XRAY_PUBLIC_KEY) XRAY_PUBLIC_KEY="$value" ;;
      XRAY_SHORT_ID) XRAY_SHORT_ID="$value" ;;
    esac
  done <<< "$output"
}

ensure_keys() {
  load_keys_from_env
  if [[ -z "$XRAY_UUID" || -z "$XRAY_PRIVATE_KEY" || -z "$XRAY_PUBLIC_KEY" || -z "$XRAY_SHORT_ID" ]]; then
    generate_keys
  fi
  validate_keys
}

write_env_file() {
  local content

  content="$(cat <<EOF
LISTEN_PORT=${LISTEN_PORT}
XRAY_UUID=${XRAY_UUID}
XRAY_PRIVATE_KEY=${XRAY_PRIVATE_KEY}
XRAY_PUBLIC_KEY=${XRAY_PUBLIC_KEY}
XRAY_SHORT_ID=${XRAY_SHORT_ID}
XRAY_DEST=${XRAY_DEST}
XRAY_SNI=${XRAY_SNI}
XRAY_FLOW=${XRAY_FLOW}
PRINT_NODE_OBJECT=0
EOF
)"
  write_atomic "$ENV_PATH" "$content" 600
}

copy_bundle_assets() {
  mkdir -p "$BUNDLE_DIR"
  chmod 700 "$BUNDLE_DIR"
  cp "$SCRIPT_DIR/docker-compose.yml" "$COMPOSE_PATH"
  cp "$SCRIPT_DIR/Dockerfile" "${BUNDLE_DIR}/Dockerfile"
  cp "$SCRIPT_DIR/config.template.json" "${BUNDLE_DIR}/config.template.json"
  cp "$SCRIPT_DIR/entrypoint.sh" "${BUNDLE_DIR}/entrypoint.sh"
  chmod 644 "$COMPOSE_PATH" "${BUNDLE_DIR}/Dockerfile" "${BUNDLE_DIR}/config.template.json"
  chmod 755 "${BUNDLE_DIR}/entrypoint.sh"
}

partial_node_from_env() {
  need_cmd python3
  python3 - "$LISTEN_PORT" "$XRAY_UUID" "$XRAY_PUBLIC_KEY" "$XRAY_SHORT_ID" "$XRAY_SNI" "$XRAY_DEST" "$XRAY_FLOW" <<'PY'
import json
import sys

port, uuid, public_key, short_id, sni, dest, flow = sys.argv[1:]
print(json.dumps({
    "port": int(port),
    "uuid": uuid,
    "reality": {
        "public_key": public_key,
        "short_id": short_id,
        "sni": sni,
        "dest": dest,
        "flow": flow,
    },
}, ensure_ascii=False, indent=2))
PY
}

complete_node_object() {
  local partial_path="$1"

  need_cmd python3
  python3 - "$partial_path" "$NODE_NAME" "$ENDPOINT_HOST" "$ROUTE_IP" "$COUNTRY_CODE" "$ENABLED" "$PROBE_SOCKS_PORT" <<'PY'
import json
import sys
from pathlib import Path

partial_path, name, endpoint_host, route_ip, country_code, enabled, socks_port = sys.argv[1:]
partial = json.loads(Path(partial_path).read_text(encoding="utf-8"))

node = {
    "name": name,
    "endpoint_host": endpoint_host,
    "route_ip": route_ip,
    "port": int(partial["port"]),
    "country_code": country_code,
    "enabled": enabled == "true",
    "uuid": partial["uuid"],
    "reality": partial["reality"],
    "probe": {"socks_port": int(socks_port)},
}

required = {"name", "endpoint_host", "route_ip", "port", "country_code", "enabled", "uuid", "reality", "probe"}
missing = sorted(required - set(node))
if missing:
    raise SystemExit(f"missing node keys: {', '.join(missing)}")
for key in ("public_key", "short_id", "sni", "dest", "flow"):
    if key not in node["reality"]:
        raise SystemExit(f"missing reality key: {key}")
if "socks_port" not in node["probe"]:
    raise SystemExit("missing probe.socks_port")

print(json.dumps(node, ensure_ascii=False, indent=2))
PY
}

write_full_node_from_partial() {
  local partial_json="$1"
  local partial_path="${BUNDLE_DIR}/node_object.partial.json"
  local full_node

  write_atomic "$partial_path" "$partial_json" 600
  full_node="$(complete_node_object "$partial_path")"
  write_atomic "$NODE_OBJECT_PATH" "$full_node" 600
  printf '%s\n' "$full_node"
}

print_rendered_node_object() {
  [[ -s "$NODE_OBJECT_PATH" ]] || die "node-object bundle не найден: ${NODE_OBJECT_PATH}"
  cat "$NODE_OBJECT_PATH"
}

render_bundle() {
  local partial_json

  ensure_keys
  copy_bundle_assets
  write_env_file
  partial_json="$(partial_node_from_env)"
  write_full_node_from_partial "$partial_json"
}

assert_docker_compose() {
  need_cmd docker
  if ! docker compose version >/dev/null 2>&1; then
    die "Docker Compose недоступен: нужна рабочая команда 'docker compose'. Ничего не устанавливаю."
  fi
}

docker_compose() {
  docker compose --env-file "$ENV_PATH" -f "$COMPOSE_PATH" "$@"
}

deploy_bundle() {
  assert_docker_compose
  render_bundle >/dev/null
  docker_compose up -d --build --wait --wait-timeout "$COMPOSE_WAIT_TIMEOUT"
  # Не читаем node_object.json из persistent volume: при повторном deploy там может
  # лежать старый объект до завершения entrypoint. Источник истины для вывода —
  # текущий bundle/.env; health wait выше подтверждает, что контейнер применился.
  print_rendered_node_object
}

main() {
  parse_args "$@"
  normalize_options

  case "$MODE" in
    generate)
      render_bundle
      ;;
    deploy)
      deploy_bundle
      ;;
  esac
}

main "$@"
