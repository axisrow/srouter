#!/usr/bin/env bash
# Локальная точка входа. Вся логика живёт в install_lib.py, чтобы plan/apply
# и conflict-detection покрывались pytest без реальных записей на машине.
set -euo pipefail

log() {
  printf '[srouter-install] %s\n' "$*"
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
if [ "$SCRIPT_DIR" = "$SCRIPT_PATH" ]; then
  SCRIPT_DIR="."
fi
ROOT_DIR="$(cd "$SCRIPT_DIR" && pwd -P)"
PYTHON_BIN="${SROUTER_PYTHON:-/usr/bin/python3}"

need_cmd "$PYTHON_BIN"

exec "$PYTHON_BIN" "$ROOT_DIR/install_lib.py" "$@"
