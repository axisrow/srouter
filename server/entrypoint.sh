#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="${XRAY_STATE_DIR:-/var/lib/srouter-reality}"
TEMPLATE_PATH="${XRAY_TEMPLATE_PATH:-/etc/srouter-reality/config.template.json}"
RENDERED_CONFIG="${XRAY_RENDERED_CONFIG:-/etc/xray/rendered/config.json}"
NODE_OBJECT_PATH="${XRAY_NODE_OBJECT_PATH:-${STATE_DIR}/node_object.json}"

log() {
  printf '[srouter-reality] %s\n' "$*"
}

die() {
  log "ОШИБКА: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "не найдена команда '$1'"
}

read_state_value() {
  local path="$1"
  tr -d '\r\n' < "$path"
}

write_state_value() {
  local path="$1"
  local value="$2"
  local path_dir
  local tmp_path

  path_dir="$(dirname "$path")"
  mkdir -p "$path_dir"
  umask 077
  tmp_path="$(mktemp "${path_dir}/.tmp.XXXXXX")"
  printf '%s\n' "$value" > "$tmp_path"
  chmod 600 "$tmp_path"
  mv "$tmp_path" "$path"
  chmod 600 "$path"
}

parse_x25519_field() {
  local field="$1"
  awk -F': ' -v field="$field" '$1 == field { print $2 }'
}

derive_public_key() {
  local private_key="$1"
  local output

  output="$(xray x25519 -i "$private_key")"
  printf '%s\n' "$output" | parse_x25519_field "Public key"
}

load_or_generate_uuid() {
  local state_path="${STATE_DIR}/xray_uuid"

  if [[ -n "${XRAY_UUID:-}" ]]; then
    return
  fi

  if [[ -s "$state_path" ]]; then
    XRAY_UUID="$(read_state_value "$state_path")"
    return
  fi

  XRAY_UUID="$(xray uuid)"
  [[ -n "$XRAY_UUID" ]] || die "xray uuid вернул пустое значение"
  write_state_value "$state_path" "$XRAY_UUID"
  log "XRAY_UUID сгенерирован и сохранён в state volume"
}

load_or_generate_short_id() {
  local state_path="${STATE_DIR}/xray_short_id"

  if [[ -n "${XRAY_SHORT_ID:-}" ]]; then
    return
  fi

  if [[ -s "$state_path" ]]; then
    XRAY_SHORT_ID="$(read_state_value "$state_path")"
    return
  fi

  XRAY_SHORT_ID="$(openssl rand -hex 8)"
  [[ -n "$XRAY_SHORT_ID" ]] || die "openssl rand вернул пустой short_id"
  write_state_value "$state_path" "$XRAY_SHORT_ID"
  log "XRAY_SHORT_ID сгенерирован и сохранён в state volume"
}

load_or_generate_private_key() {
  local state_path="${STATE_DIR}/xray_private_key"
  local output

  if [[ -n "${XRAY_PRIVATE_KEY:-}" ]]; then
    return
  fi

  if [[ -s "$state_path" ]]; then
    XRAY_PRIVATE_KEY="$(read_state_value "$state_path")"
    return
  fi

  output="$(xray x25519)"
  XRAY_PRIVATE_KEY="$(printf '%s\n' "$output" | parse_x25519_field "Private key")"
  [[ -n "$XRAY_PRIVATE_KEY" ]] || die "xray x25519 не вернул private key"
  write_state_value "$state_path" "$XRAY_PRIVATE_KEY"
  log "XRAY_PRIVATE_KEY сгенерирован и сохранён в state volume"
}

validate_config_values() {
  local dest_host
  local dest_port
  local dest_port_num
  local listen_port_num

  case "$LISTEN_PORT" in
    ''|*[!0-9]*)
      die "LISTEN_PORT должен быть числом от 1 до 65535"
      ;;
  esac
  listen_port_num=$((10#$LISTEN_PORT))
  (( listen_port_num >= 1 && listen_port_num <= 65535 )) || die "LISTEN_PORT вне диапазона 1..65535"

  [[ -n "$XRAY_UUID" ]] || die "XRAY_UUID пуст"
  [[ -n "$XRAY_PRIVATE_KEY" ]] || die "XRAY_PRIVATE_KEY пуст"
  [[ -n "$XRAY_SHORT_ID" ]] || die "XRAY_SHORT_ID пуст"
  [[ -n "$XRAY_DEST" ]] || die "XRAY_DEST пуст"
  [[ -n "$XRAY_SNI" ]] || die "XRAY_SNI пуст"
  [[ -n "$XRAY_FLOW" ]] || die "XRAY_FLOW пуст"

  [[ "$XRAY_UUID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
    || die "XRAY_UUID должен быть UUID в canonical-формате"
  [[ "$XRAY_PRIVATE_KEY" =~ ^[A-Za-z0-9_-]{40,64}$ ]] \
    || die "XRAY_PRIVATE_KEY должен быть base64url-ключом X25519 без кавычек"
  [[ "$XRAY_SHORT_ID" =~ ^[0-9a-fA-F]+$ ]] || die "XRAY_SHORT_ID должен быть hex-строкой"
  (( ${#XRAY_SHORT_ID} <= 16 )) || die "XRAY_SHORT_ID длиннее 16 hex-символов"
  (( ${#XRAY_SHORT_ID} % 2 == 0 )) || die "XRAY_SHORT_ID должен иметь чётную длину"
  [[ "$XRAY_FLOW" =~ ^[A-Za-z0-9._-]+$ ]] || die "XRAY_FLOW содержит недопустимые символы"
  [[ "$XRAY_SNI" =~ ^[A-Za-z0-9._-]+$ ]] || die "XRAY_SNI содержит недопустимые символы"
  [[ "$XRAY_DEST" =~ ^[A-Za-z0-9._-]+:[0-9]{1,5}$ ]] \
    || die "XRAY_DEST должен иметь формат host:port без кавычек"

  XRAY_SHORT_ID="$(printf '%s' "$XRAY_SHORT_ID" | tr 'A-F' 'a-f')"

  dest_host="${XRAY_DEST%:*}"
  dest_port="${XRAY_DEST##*:}"
  dest_port_num=$((10#$dest_port))
  [[ -n "$dest_host" ]] || die "XRAY_DEST host пуст"
  (( dest_port_num >= 1 && dest_port_num <= 65535 )) || die "XRAY_DEST port вне диапазона 1..65535"
}

render_config() {
  local rendered_dir
  local tmp_path

  [[ -f "$TEMPLATE_PATH" ]] || die "шаблон не найден: ${TEMPLATE_PATH}"

  rendered_dir="$(dirname "$RENDERED_CONFIG")"
  mkdir -p "$rendered_dir"
  tmp_path="$(mktemp "${rendered_dir}/config.json.XXXXXX")"

  export LISTEN_PORT XRAY_UUID XRAY_PRIVATE_KEY XRAY_SHORT_ID XRAY_DEST XRAY_SNI XRAY_FLOW
  envsubst '${LISTEN_PORT} ${XRAY_UUID} ${XRAY_PRIVATE_KEY} ${XRAY_SHORT_ID} ${XRAY_DEST} ${XRAY_SNI} ${XRAY_FLOW}' \
    < "$TEMPLATE_PATH" > "$tmp_path"

  chmod 600 "$tmp_path"
  mv "$tmp_path" "$RENDERED_CONFIG"
}

test_rendered_config() {
  local output

  if ! output="$(xray run -test -config "$RENDERED_CONFIG" 2>&1)"; then
    printf '%s\n' "$output" >&2
    die "xray не принял rendered config: ${RENDERED_CONFIG}"
  fi
}

node_object_json() {
  cat <<EOF
{
  "port": ${LISTEN_PORT},
  "uuid": "${XRAY_UUID}",
  "reality": {
    "public_key": "${XRAY_PUBLIC_KEY}",
    "short_id": "${XRAY_SHORT_ID}",
    "sni": "${XRAY_SNI}",
    "dest": "${XRAY_DEST}",
    "flow": "${XRAY_FLOW}"
  }
}
EOF
}

write_node_object() {
  local node_object
  local node_object_dir

  node_object="$(node_object_json)"
  node_object_dir="$(dirname "$NODE_OBJECT_PATH")"
  mkdir -p "$node_object_dir"
  write_state_value "$NODE_OBJECT_PATH" "$node_object"
  log "node-object для #4 записан в ${NODE_OBJECT_PATH}"

  if [[ "${PRINT_NODE_OBJECT:-0}" == "1" ]]; then
    log "PRINT_NODE_OBJECT=1: печатаю node-object в stdout"
    printf '%s\n' "$node_object"
  fi
}

main() {
  need_cmd xray
  need_cmd envsubst
  need_cmd openssl

  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"

  LISTEN_PORT="${LISTEN_PORT:-443}"
  XRAY_DEST="${XRAY_DEST:-www.163.com:443}"
  XRAY_SNI="${XRAY_SNI:-www.163.com}"
  XRAY_FLOW="${XRAY_FLOW:-xtls-rprx-vision}"

  load_or_generate_uuid
  load_or_generate_short_id
  load_or_generate_private_key

  XRAY_PUBLIC_KEY="$(derive_public_key "$XRAY_PRIVATE_KEY")"
  [[ -n "$XRAY_PUBLIC_KEY" ]] || die "не удалось получить public key из XRAY_PRIVATE_KEY"

  validate_config_values
  render_config
  test_rendered_config
  write_node_object

  if [[ $# -eq 0 ]]; then
    set -- xray run -config "$RENDERED_CONFIG"
  fi

  exec "$@"
}

main "$@"
