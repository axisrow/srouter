#!/usr/bin/env bash
# Rollback entrypoint. Опасные действия живут в install_lib.py и покрыты pytest:
# этот wrapper только выбирает plan/apply и не делает silent root/system changes.
set -euo pipefail

log() {
  printf '[srouter-uninstall] %s\n' "$*"
}

die() {
  log "ОШИБКА: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "не найдена команда '$1'"
}

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="${SCRIPT_PATH%/*}"
if [[ "$SCRIPT_DIR" == "$SCRIPT_PATH" ]]; then
  SCRIPT_DIR="."
fi
ROOT_DIR="$(cd "$SCRIPT_DIR" && pwd -P)"
PYTHON_BIN="${SROUTER_PYTHON:-/usr/bin/python3}"

need_cmd "$PYTHON_BIN"

mode="${1:-plan}"
if [[ $# -gt 0 ]]; then
  shift
fi

case "$mode" in
  plan)
    exec "$PYTHON_BIN" "$ROOT_DIR/install_lib.py" uninstall-plan "$@"
    ;;
  apply)
    exec "$PYTHON_BIN" "$ROOT_DIR/install_lib.py" uninstall-apply "$@"
    ;;
  -h|--help|help)
    cat <<'EOF'
Usage:
  ./uninstall.sh plan
  ./uninstall.sh apply [--restore-configs] [--stop-services] [--restore-dns] [--unload-launchagent]

Без category-флагов apply спросит интерактивное подтверждение по каждой категории.
User-data по умолчанию не удаляются: srouter.local.json, deploy/key bundles, backups.
EOF
    ;;
  *)
    die "неизвестный режим '$mode' (ожидалось plan/apply)"
    ;;
esac
