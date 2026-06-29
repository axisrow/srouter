#!/usr/bin/env bash
# Локальная точка входа. Вся логика живёт в install_lib.py, чтобы plan/apply
# и conflict-detection покрывались pytest без реальных записей на машине.
set -u

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="${SCRIPT_PATH%/*}"
if [ "$SCRIPT_DIR" = "$SCRIPT_PATH" ]; then
  SCRIPT_DIR="."
fi
ROOT_DIR="$(cd "$SCRIPT_DIR" && pwd -P)"
PYTHON_BIN="${SROUTER_PYTHON:-/usr/bin/python3}"

if [ ! -x "$PYTHON_BIN" ]; then
  echo "Не найден Python: $PYTHON_BIN" >&2
  exit 127
fi

exec "$PYTHON_BIN" "$ROOT_DIR/install_lib.py" "$@"
