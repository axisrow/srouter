#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_SH="${SCRIPT_DIR}/deploy.sh"
UNIT_TEMPLATE="${SCRIPT_DIR}/srouter-reality.service"

MODE=""
BUNDLE_DIR=""
NODE_NAME=""
ENDPOINT_HOST=""
ROUTE_IP=""
COUNTRY_CODE=""
PROBE_SOCKS_PORT=""
LISTEN_PORT=""
XRAY_DEST=""
XRAY_SNI=""
XRAY_FLOW=""
ROLLBACK_BACKUP_DIR=""

INSTALL_ROOT="${SROUTER_BARE_ROOT:-}"
XRAY_VERSION="${SROUTER_XRAY_VERSION:-25.6.8}"
XRAY_SOURCE_DIR="${SROUTER_XRAY_SOURCE_DIR:-}"
SERVICE_NAME="${SROUTER_XRAY_SERVICE_NAME:-srouter-reality.service}"

STATE_DIR=""
STATE_ENV_PATH=""
STATE_NODE_OBJECT_PATH=""
BACKUP_ROOT=""
LATEST_BACKUP_PATH=""
TEMPLATE_PATH=""
RENDERED_CONFIG=""
UNIT_TARGET=""
XRAY_BIN=""
XRAY_SHARE_DIR=""
APPLY_BACKUP_DIR=""
ROLLBACK_ON_ERROR=0

log() {
  printf '[srouter-bare] %s\n' "$*" >&2
}

die() {
  log "ОШИБКА: $*"
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage:
  server/bare-install.sh install   --endpoint-host HOST [options]
  server/bare-install.sh update    [--endpoint-host HOST] [options]
  server/bare-install.sh rollback  [--backup-dir PATH]

Modes:
  install   поставить Xray на Debian/Ubuntu host, создать config/unit и запустить service
  update    обновить Xray/config с backup и auto-rollback при ошибке
  rollback  восстановить последний backup после успешного update

Options:
  --bundle-dir PATH          ignored bundle для deploy.sh generate (default: server/.generated/bare-<node>)
  --name NAME                nodes[].name
  --endpoint-host HOST       публичный host/IP сервера; обязателен для первого install
  --route-ip HOST            nodes[].route_ip; default берёт deploy.sh
  --country-code CC          двухбуквенный country_code
  --probe-socks-port PORT    nodes[].probe.socks_port (default: 11080)
  --listen-port PORT         VLESS/Reality port (default: 443)
  --xray-dest HOST:PORT      Reality dest (default: www.163.com:443)
  --xray-sni HOST            Reality SNI (default: www.163.com)
  --xray-flow FLOW           VLESS flow (default: xtls-rprx-vision)
  --xray-version VERSION     Xray release без префикса v (default: 25.6.8)
  --backup-dir PATH          rollback: конкретный backup вместо latest

Scope:
  Только Debian/Ubuntu с apt и systemd. Docker не используется.
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

root_path() {
  local path="$1"

  if [[ -n "$INSTALL_ROOT" ]]; then
    printf '%s%s\n' "$INSTALL_ROOT" "$path"
  else
    printf '%s\n' "$path"
  fi
}

set_paths() {
  STATE_DIR="$(root_path /var/lib/srouter-reality)"
  STATE_ENV_PATH="${STATE_DIR}/.env"
  STATE_NODE_OBJECT_PATH="${STATE_DIR}/node_object.json"
  BACKUP_ROOT="${STATE_DIR}/backups"
  LATEST_BACKUP_PATH="${BACKUP_ROOT}/latest"
  TEMPLATE_PATH="$(root_path /etc/srouter-reality/config.template.json)"
  RENDERED_CONFIG="$(root_path /etc/xray/rendered/config.json)"
  UNIT_TARGET="$(root_path "/etc/systemd/system/${SERVICE_NAME}")"
  XRAY_BIN="$(root_path /usr/local/bin/xray)"
  XRAY_SHARE_DIR="$(root_path /usr/local/share/xray)"
}

normalize_install_root() {
  if [[ -n "$INSTALL_ROOT" ]]; then
    [[ "$INSTALL_ROOT" = /* ]] || die "SROUTER_BARE_ROOT должен быть абсолютным путём"
    INSTALL_ROOT="${INSTALL_ROOT%/}"
  fi
}

parse_args() {
  MODE="${1:-}"
  if [[ -z "$MODE" ]]; then
    usage
    die "mode обязателен: install, update или rollback"
  fi

  case "$MODE" in
    install|update|rollback)
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
      --xray-version)
        XRAY_VERSION="$(arg_value "$1" "${2:-}")"
        shift 2
        ;;
      --backup-dir)
        ROLLBACK_BACKUP_DIR="$(arg_value "$1" "${2:-}")"
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

read_key_value() {
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

json_value() {
  local path="$1"
  local dotted_key="$2"

  [[ -f "$path" ]] || return 1
  need_cmd python3
  python3 - "$path" "$dotted_key" <<'PY'
import json
import sys
from pathlib import Path

path, dotted_key = sys.argv[1:]
value = json.loads(Path(path).read_text(encoding="utf-8"))
for part in dotted_key.split("."):
    value = value[part]
print(value)
PY
}

load_existing_defaults() {
  if [[ -f "$STATE_NODE_OBJECT_PATH" ]]; then
    if [[ -z "$NODE_NAME" ]]; then
      NODE_NAME="$(json_value "$STATE_NODE_OBJECT_PATH" name)"
    fi
    if [[ -z "$ENDPOINT_HOST" ]]; then
      ENDPOINT_HOST="$(json_value "$STATE_NODE_OBJECT_PATH" endpoint_host)"
    fi
    if [[ -z "$ROUTE_IP" ]]; then
      ROUTE_IP="$(json_value "$STATE_NODE_OBJECT_PATH" route_ip)"
    fi
    if [[ -z "$COUNTRY_CODE" ]]; then
      COUNTRY_CODE="$(json_value "$STATE_NODE_OBJECT_PATH" country_code)"
    fi
    if [[ -z "$PROBE_SOCKS_PORT" ]]; then
      PROBE_SOCKS_PORT="$(json_value "$STATE_NODE_OBJECT_PATH" probe.socks_port)"
    fi
  fi

  if [[ -f "$STATE_ENV_PATH" ]]; then
    if [[ -z "$LISTEN_PORT" ]]; then
      LISTEN_PORT="$(read_key_value LISTEN_PORT "$STATE_ENV_PATH")"
    fi
    if [[ -z "$XRAY_DEST" ]]; then
      XRAY_DEST="$(read_key_value XRAY_DEST "$STATE_ENV_PATH")"
    fi
    if [[ -z "$XRAY_SNI" ]]; then
      XRAY_SNI="$(read_key_value XRAY_SNI "$STATE_ENV_PATH")"
    fi
    if [[ -z "$XRAY_FLOW" ]]; then
      XRAY_FLOW="$(read_key_value XRAY_FLOW "$STATE_ENV_PATH")"
    fi
  fi
}

safe_slug() {
  local value="$1"
  local slug

  slug="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '-')"
  slug="$(printf '%s' "$slug" | sed -E 's/^-+//; s/-+$//; s/-+/-/g')"
  [[ -n "$slug" ]] || slug="node"
  printf '%s\n' "$slug"
}

normalize_node_options() {
  [[ "$MODE" == "install" || "$MODE" == "update" ]] || return 0

  load_existing_defaults

  PROBE_SOCKS_PORT="${PROBE_SOCKS_PORT:-11080}"
  LISTEN_PORT="${LISTEN_PORT:-443}"
  XRAY_DEST="${XRAY_DEST:-www.163.com:443}"
  XRAY_SNI="${XRAY_SNI:-www.163.com}"
  XRAY_FLOW="${XRAY_FLOW:-xtls-rprx-vision}"

  [[ -n "$ENDPOINT_HOST" ]] || die "--endpoint-host обязателен для первого install/update без сохранённого node-object"

  if [[ -z "$BUNDLE_DIR" ]]; then
    if [[ -n "$NODE_NAME" ]]; then
      BUNDLE_DIR="${SCRIPT_DIR}/.generated/bare-$(safe_slug "$NODE_NAME")"
    else
      BUNDLE_DIR="${SCRIPT_DIR}/.generated/bare-$(safe_slug "$ENDPOINT_HOST")"
    fi
  fi
}

read_os_release_key() {
  local key="$1"
  local path="$2"

  awk -F= -v key="$key" '
    $1 == key {
      value = substr($0, index($0, "=") + 1)
      gsub(/^"/, "", value)
      gsub(/"$/, "", value)
      print value
      found = 1
      exit
    }
    END { if (!found) exit 1 }
  ' "$path"
}

assert_supported_linux() {
  local os_release
  local distro_id
  local distro_like

  [[ "$(uname -s)" == "Linux" ]] || die "bare install поддержан только на Linux"
  os_release="$(root_path /etc/os-release)"
  [[ -f "$os_release" ]] || die "не найден ${os_release}; поддержаны Debian/Ubuntu"

  distro_id="$(read_os_release_key ID "$os_release" || true)"
  distro_like="$(read_os_release_key ID_LIKE "$os_release" || true)"
  case " ${distro_id} ${distro_like} " in
    *" debian "*|*" ubuntu "*)
      ;;
    *)
      die "поддержан только Debian/Ubuntu family через apt + systemd"
      ;;
  esac

  need_cmd systemctl
  if [[ -z "$INSTALL_ROOT" && ! -d /run/systemd/system ]]; then
    die "systemd не выглядит активным на этом host"
  fi
}

require_root_for_real_host() {
  if [[ -z "$INSTALL_ROOT" && "$(id -u)" != "0" ]]; then
    die "запусти install/update/rollback от root или через sudo"
  fi
}

install_dependencies() {
  need_cmd apt-get

  log "ставлю зависимости Debian/Ubuntu: ca-certificates curl unzip gettext-base openssl python3"
  DEBIAN_FRONTEND=noninteractive apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates curl unzip gettext-base openssl python3

  need_cmd envsubst
  need_cmd python3
  need_cmd openssl
}

xray_asset_arch() {
  case "$(uname -m)" in
    x86_64|amd64)
      printf '64\n'
      ;;
    aarch64|arm64)
      printf 'arm64-v8a\n'
      ;;
    *)
      die "архитектура $(uname -m) не поддержана этим bare installer"
      ;;
  esac
}

install_xray_from_dir() {
  local source_dir="$1"

  [[ -x "${source_dir}/xray" ]] || die "в ${source_dir} нет исполняемого xray"
  copy_file_atomic "${source_dir}/xray" "$XRAY_BIN" 755
  mkdir -p "$XRAY_SHARE_DIR"
  chmod 755 "$XRAY_SHARE_DIR"
  if [[ -f "${source_dir}/geoip.dat" ]]; then
    copy_file_atomic "${source_dir}/geoip.dat" "${XRAY_SHARE_DIR}/geoip.dat" 644
  fi
  if [[ -f "${source_dir}/geosite.dat" ]]; then
    copy_file_atomic "${source_dir}/geosite.dat" "${XRAY_SHARE_DIR}/geosite.dat" 644
  fi
}

install_xray_binary() {
  local version_tag
  local asset_arch
  local url
  local tmp_dir
  local archive_path
  local unpack_dir

  if [[ -n "$XRAY_SOURCE_DIR" ]]; then
    log "ставлю Xray из локального source-dir: ${XRAY_SOURCE_DIR}"
    install_xray_from_dir "$XRAY_SOURCE_DIR"
    return
  fi

  need_cmd curl
  need_cmd unzip

  version_tag="${XRAY_VERSION#v}"
  asset_arch="$(xray_asset_arch)"
  url="https://github.com/XTLS/Xray-core/releases/download/v${version_tag}/Xray-linux-${asset_arch}.zip"
  tmp_dir="$(mktemp -d)"
  archive_path="${tmp_dir}/xray.zip"
  unpack_dir="${tmp_dir}/xray"

  log "скачиваю Xray ${version_tag} для linux-${asset_arch}"
  curl -fsSL "$url" -o "$archive_path"
  mkdir -p "$unpack_dir"
  unzip -q "$archive_path" -d "$unpack_dir"
  install_xray_from_dir "$unpack_dir"
  rm -rf "$tmp_dir"
}

copy_file_atomic() {
  local source="$1"
  local target="$2"
  local mode="$3"
  local target_dir
  local tmp_path

  target_dir="$(dirname "$target")"
  mkdir -p "$target_dir"
  umask 077
  tmp_path="$(mktemp "${target_dir}/.tmp.XXXXXX")"
  cp "$source" "$tmp_path"
  chmod "$mode" "$tmp_path"
  mv "$tmp_path" "$target"
  chmod "$mode" "$target"
}

write_content_atomic() {
  local target="$1"
  local content="$2"
  local mode="$3"
  local target_dir
  local tmp_path

  target_dir="$(dirname "$target")"
  mkdir -p "$target_dir"
  umask 077
  tmp_path="$(mktemp "${target_dir}/.tmp.XXXXXX")"
  printf '%s\n' "$content" > "$tmp_path"
  chmod "$mode" "$tmp_path"
  mv "$tmp_path" "$target"
  chmod "$mode" "$target"
}

preseed_bundle_env() {
  [[ -f "$STATE_ENV_PATH" ]] || return 0

  mkdir -p "$BUNDLE_DIR"
  chmod 700 "$BUNDLE_DIR"
  copy_file_atomic "$STATE_ENV_PATH" "${BUNDLE_DIR}/.env" 600
}

deploy_generate_args() {
  local -a args
  args=(bash "$DEPLOY_SH" generate --bundle-dir "$BUNDLE_DIR" --endpoint-host "$ENDPOINT_HOST")

  [[ -z "$NODE_NAME" ]] || args+=(--name "$NODE_NAME")
  [[ -z "$ROUTE_IP" ]] || args+=(--route-ip "$ROUTE_IP")
  [[ -z "$COUNTRY_CODE" ]] || args+=(--country-code "$COUNTRY_CODE")
  [[ -z "$PROBE_SOCKS_PORT" ]] || args+=(--probe-socks-port "$PROBE_SOCKS_PORT")
  [[ -z "$LISTEN_PORT" ]] || args+=(--listen-port "$LISTEN_PORT")
  [[ -z "$XRAY_DEST" ]] || args+=(--xray-dest "$XRAY_DEST")
  [[ -z "$XRAY_SNI" ]] || args+=(--xray-sni "$XRAY_SNI")
  [[ -z "$XRAY_FLOW" ]] || args+=(--xray-flow "$XRAY_FLOW")

  printf '%s\0' "${args[@]}"
}

render_node_bundle() {
  local node_object
  local -a args=()

  preseed_bundle_env
  while IFS= read -r -d '' item; do
    args+=("$item")
  done < <(deploy_generate_args)

  PATH="$(dirname "$XRAY_BIN"):${PATH}"
  export PATH
  node_object="$("${args[@]}")"

  copy_file_atomic "${BUNDLE_DIR}/.env" "$STATE_ENV_PATH" 600
  copy_file_atomic "${BUNDLE_DIR}/node_object.json" "$STATE_NODE_OBJECT_PATH" 600
  printf '%s\n' "$node_object"
}

install_template() {
  copy_file_atomic "${SCRIPT_DIR}/config.template.json" "$TEMPLATE_PATH" 644
}

load_render_env() {
  LISTEN_PORT="$(read_key_value LISTEN_PORT "$STATE_ENV_PATH")"
  XRAY_UUID="$(read_key_value XRAY_UUID "$STATE_ENV_PATH")"
  XRAY_PRIVATE_KEY="$(read_key_value XRAY_PRIVATE_KEY "$STATE_ENV_PATH")"
  XRAY_SHORT_ID="$(read_key_value XRAY_SHORT_ID "$STATE_ENV_PATH")"
  XRAY_DEST="$(read_key_value XRAY_DEST "$STATE_ENV_PATH")"
  XRAY_SNI="$(read_key_value XRAY_SNI "$STATE_ENV_PATH")"
  XRAY_FLOW="$(read_key_value XRAY_FLOW "$STATE_ENV_PATH")"
  export LISTEN_PORT XRAY_UUID XRAY_PRIVATE_KEY XRAY_SHORT_ID XRAY_DEST XRAY_SNI XRAY_FLOW
}

render_config() {
  local rendered_dir
  local tmp_path

  load_render_env
  rendered_dir="$(dirname "$RENDERED_CONFIG")"
  mkdir -p "$rendered_dir"
  umask 077
  tmp_path="$(mktemp "${rendered_dir}/config.json.XXXXXX")"

  # envsubst должен видеть literal ${...}; Bash не должен раскрывать placeholders.
  # shellcheck disable=SC2016
  envsubst '${LISTEN_PORT} ${XRAY_UUID} ${XRAY_PRIVATE_KEY} ${XRAY_SHORT_ID} ${XRAY_DEST} ${XRAY_SNI} ${XRAY_FLOW}' \
    < "$TEMPLATE_PATH" > "$tmp_path"
  chmod 600 "$tmp_path"
  mv "$tmp_path" "$RENDERED_CONFIG"
  chmod 600 "$RENDERED_CONFIG"

  "$XRAY_BIN" run -test -config "$RENDERED_CONFIG"
}

install_unit() {
  local unit_dir
  local tmp_path

  [[ -f "$UNIT_TEMPLATE" ]] || die "systemd template не найден: ${UNIT_TEMPLATE}"
  unit_dir="$(dirname "$UNIT_TARGET")"
  mkdir -p "$unit_dir"
  tmp_path="$(mktemp "${unit_dir}/srouter-reality.service.XXXXXX")"
  awk -v xray_bin="$XRAY_BIN" -v rendered_config="$RENDERED_CONFIG" '
    {
      gsub(/__XRAY_BIN__/, xray_bin)
      gsub(/__XRAY_CONFIG__/, rendered_config)
      print
    }
  ' "$UNIT_TEMPLATE" > "$tmp_path"
  chmod 644 "$tmp_path"
  mv "$tmp_path" "$UNIT_TARGET"
  chmod 644 "$UNIT_TARGET"
}

reload_and_start_service() {
  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"
}

reload_and_restart_service() {
  systemctl daemon-reload
  systemctl restart "$SERVICE_NAME"
}

rel_path_for_backup() {
  local target="$1"

  if [[ -n "$INSTALL_ROOT" ]]; then
    printf '%s\n' "${target#"${INSTALL_ROOT}"/}"
  else
    printf '%s\n' "${target#/}"
  fi
}

target_from_rel_path() {
  local rel_path="$1"

  if [[ -n "$INSTALL_ROOT" ]]; then
    printf '%s/%s\n' "$INSTALL_ROOT" "$rel_path"
  else
    printf '/%s\n' "$rel_path"
  fi
}

backup_entry() {
  local backup_dir="$1"
  local manifest="$2"
  local expected_kind="$3"
  local target="$4"
  local rel_path
  local backup_path

  rel_path="$(rel_path_for_backup "$target")"
  backup_path="${backup_dir}/${rel_path}"

  if [[ -e "$target" ]]; then
    mkdir -p "$(dirname "$backup_path")"
    cp -a "$target" "$backup_path"
    if [[ -d "$target" ]]; then
      printf 'dir\t%s\n' "$rel_path" >> "$manifest"
    else
      printf '%s\t%s\n' "$expected_kind" "$rel_path" >> "$manifest"
    fi
  else
    printf 'missing\t%s\n' "$rel_path" >> "$manifest"
  fi
}

create_backup() {
  local backup_dir
  local manifest

  mkdir -p "$BACKUP_ROOT"
  chmod 700 "$BACKUP_ROOT"
  backup_dir="$(mktemp -d "${BACKUP_ROOT}/$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")"
  chmod 700 "$backup_dir"
  manifest="${backup_dir}/manifest.tsv"
  : > "$manifest"

  backup_entry "$backup_dir" "$manifest" file "$XRAY_BIN"
  backup_entry "$backup_dir" "$manifest" dir "$XRAY_SHARE_DIR"
  backup_entry "$backup_dir" "$manifest" file "$TEMPLATE_PATH"
  backup_entry "$backup_dir" "$manifest" file "$RENDERED_CONFIG"
  backup_entry "$backup_dir" "$manifest" file "$UNIT_TARGET"
  backup_entry "$backup_dir" "$manifest" file "$STATE_ENV_PATH"
  backup_entry "$backup_dir" "$manifest" file "$STATE_NODE_OBJECT_PATH"
  chmod 600 "$manifest"

  printf '%s\n' "$backup_dir"
}

write_latest_backup() {
  local backup_dir="$1"

  write_content_atomic "$LATEST_BACKUP_PATH" "$backup_dir" 600
}

restore_backup() {
  local backup_dir="$1"
  local manifest
  local kind
  local rel_path
  local target
  local backup_path

  [[ -n "$backup_dir" ]] || die "backup-dir пуст"
  manifest="${backup_dir}/manifest.tsv"
  [[ -f "$manifest" ]] || die "backup manifest не найден: ${manifest}"

  while IFS=$'\t' read -r kind rel_path; do
    [[ -n "$kind" ]] || continue
    target="$(target_from_rel_path "$rel_path")"
    backup_path="${backup_dir}/${rel_path}"
    case "$kind" in
      missing)
        rm -rf "$target"
        ;;
      file)
        mkdir -p "$(dirname "$target")"
        rm -rf "$target"
        cp -a "$backup_path" "$target"
        ;;
      dir)
        mkdir -p "$(dirname "$target")"
        rm -rf "$target"
        cp -a "$backup_path" "$target"
        ;;
      *)
        die "неизвестный тип backup entry: ${kind}"
        ;;
    esac
  done < "$manifest"
}

on_apply_error() {
  local status=$?

  if [[ "$ROLLBACK_ON_ERROR" == "1" && -n "$APPLY_BACKUP_DIR" ]]; then
    log "update завершился ошибкой; восстанавливаю backup: ${APPLY_BACKUP_DIR}"
    if restore_backup "$APPLY_BACKUP_DIR"; then
      reload_and_restart_service || log "ОШИБКА: backup восстановлен, но service restart не удался"
    else
      log "ОШИБКА: автоматический rollback не удался"
    fi
  fi
  exit "$status"
}

prepare_host_for_apply() {
  assert_supported_linux
  require_root_for_real_host
  install_dependencies
}

apply_server_state() {
  local action="$1"
  local node_object
  local node_tmp

  install_xray_binary
  node_tmp="$(mktemp)"
  render_node_bundle > "$node_tmp"
  node_object="$(cat "$node_tmp")"
  rm -f "$node_tmp"
  install_template
  render_config
  install_unit

  case "$action" in
    install)
      reload_and_start_service
      ;;
    update)
      reload_and_restart_service
      ;;
    *)
      die "неизвестное apply action: ${action}"
      ;;
  esac

  printf '%s\n' "$node_object"
}

run_install() {
  local node_tmp

  prepare_host_for_apply
  normalize_node_options
  node_tmp="$(mktemp)"
  apply_server_state install > "$node_tmp"
  cat "$node_tmp"
  rm -f "$node_tmp"
}

run_update() {
  local node_tmp

  prepare_host_for_apply
  normalize_node_options
  APPLY_BACKUP_DIR="$(create_backup)"
  ROLLBACK_ON_ERROR=1
  trap on_apply_error ERR
  node_tmp="$(mktemp)"
  apply_server_state update > "$node_tmp"
  trap - ERR
  ROLLBACK_ON_ERROR=0
  write_latest_backup "$APPLY_BACKUP_DIR"
  cat "$node_tmp"
  rm -f "$node_tmp"
}

latest_backup_dir() {
  if [[ -n "$ROLLBACK_BACKUP_DIR" ]]; then
    printf '%s\n' "$ROLLBACK_BACKUP_DIR"
    return
  fi
  [[ -f "$LATEST_BACKUP_PATH" ]] || die "latest backup не найден: ${LATEST_BACKUP_PATH}"
  tr -d '\r\n' < "$LATEST_BACKUP_PATH"
}

run_rollback() {
  local backup_dir

  assert_supported_linux
  require_root_for_real_host
  backup_dir="$(latest_backup_dir)"
  restore_backup "$backup_dir"
  reload_and_restart_service
  if [[ -s "$STATE_NODE_OBJECT_PATH" ]]; then
    cat "$STATE_NODE_OBJECT_PATH"
  fi
}

main() {
  parse_args "$@"
  normalize_install_root
  set_paths

  case "$MODE" in
    install)
      run_install
      ;;
    update)
      run_update
      ;;
    rollback)
      run_rollback
      ;;
  esac
}

main "$@"
