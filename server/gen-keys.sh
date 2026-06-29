#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[srouter-gen-keys] %s\n' "$*" >&2
}

die() {
  log "ОШИБКА: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "не найдена команда '$1'"
}

parse_x25519_field() {
  local field="$1"
  awk -F': *' -v field="$field" '
    function matches(label) {
      return label == field ||
        (field == "Private key" && label == "PrivateKey") ||
        (field == "Public key" && label == "PublicKey") ||
        (field == "Public key" && label == "Password (PublicKey)")
    }
    matches($1) { print $2; exit }
  '
}

validate_uuid() {
  [[ "$1" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
    || die "XRAY_UUID должен быть UUID в canonical-формате"
}

validate_x25519_key() {
  local name="$1"
  local value="$2"

  [[ "$value" =~ ^[A-Za-z0-9_-]{40,64}$ ]] \
    || die "${name} должен быть base64url-ключом X25519 без кавычек"
}

validate_short_id() {
  [[ "$1" =~ ^[0-9a-fA-F]+$ ]] || die "XRAY_SHORT_ID должен быть hex-строкой"
  (( ${#1} <= 16 )) || die "XRAY_SHORT_ID длиннее 16 hex-символов"
  (( ${#1} % 2 == 0 )) || die "XRAY_SHORT_ID должен иметь чётную длину"
}

main() {
  local output
  local xray_uuid
  local xray_private_key
  local xray_public_key
  local xray_short_id

  need_cmd xray
  need_cmd openssl

  # Команды и формат парсинга синхронизированы с server/entrypoint.sh.
  xray_uuid="$(xray uuid)"
  [[ -n "$xray_uuid" ]] || die "xray uuid вернул пустое значение"

  xray_short_id="$(openssl rand -hex 8)"
  [[ -n "$xray_short_id" ]] || die "openssl rand вернул пустой short_id"
  xray_short_id="$(printf '%s' "$xray_short_id" | tr 'A-F' 'a-f')"

  output="$(xray x25519)"
  xray_private_key="$(printf '%s\n' "$output" | parse_x25519_field "Private key")"
  [[ -n "$xray_private_key" ]] || die "xray x25519 не вернул private key"

  output="$(xray x25519 -i "$xray_private_key")"
  xray_public_key="$(printf '%s\n' "$output" | parse_x25519_field "Public key")"
  [[ -n "$xray_public_key" ]] || die "не удалось получить public key из XRAY_PRIVATE_KEY"

  validate_uuid "$xray_uuid"
  validate_x25519_key XRAY_PRIVATE_KEY "$xray_private_key"
  validate_x25519_key XRAY_PUBLIC_KEY "$xray_public_key"
  validate_short_id "$xray_short_id"

  printf 'XRAY_UUID=%s\n' "$xray_uuid"
  printf 'XRAY_PRIVATE_KEY=%s\n' "$xray_private_key"
  printf 'XRAY_PUBLIC_KEY=%s\n' "$xray_public_key"
  printf 'XRAY_SHORT_ID=%s\n' "$xray_short_id"
}

main "$@"
