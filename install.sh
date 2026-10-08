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
PYTHON_BIN="${SROUTER_PYTHON:-python3}"

need_cmd "$PYTHON_BIN"

# Инцидент 2026-10-08: дефолт /usr/bin/python3 (Apple, без flask) рендерил plist
# демона без зависимостей → CrashLoop ModuleNotFoundError. PATH-python активной
# установки (pip install -e .) — честный дефолт; for apply выбранный python обязан
# быть годен демону (import flask) — иначе fail-closed с ремонтом, а не тихий
# запуск с последующим краш-лупом (фикс from_env sys.executable здесь no-op:
# протаскивает тот же неверный интерпретатор).
case " $* " in
  *" apply "*)
    if ! "$PYTHON_BIN" -c "import flask" 2>/dev/null; then
      die "SROUTER_PYTHON=$PYTHON_BIN не может import flask — демон получит CrashLoop. Укажи SROUTER_PYTHON=<python с pip install -e '.[dev]'>"
    fi ;;
esac

exec "$PYTHON_BIN" "$ROOT_DIR/install_lib.py" "$@"
