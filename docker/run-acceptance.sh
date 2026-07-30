#!/bin/sh
# srouter acceptance-полигон: собрать Docker-образ и прогнать приёмочные тесты.
# issue #112. Запускать из корня репозитория: ./docker/run-acceptance.sh
#
# Что делает: собирает docker/acceptance.Dockerfile (Linux + srouter + тупые macOS-binary stub'ы),
# затем запускает pytest tests/acceptance/ с SROUTER_ACCEPTANCE=1 (включает skip'нутые вне полигона
# end-to-end тесты реального CLI srouter). Живой macOS-стек НЕ затрагивается — всё в контейнере.
set -e

IMAGE="srouter-acceptance"
DOCKERFILE="docker/acceptance.Dockerfile"

cd "$(dirname "$0")/.."

echo "==> Сборка образа $IMAGE ($DOCKERFILE)..."
docker build -f "$DOCKERFILE" -t "$IMAGE" .

echo ""
echo "==> Прогон acceptance-тестов (SROUTER_ACCEPTANCE=1)..."
# -n 0 (issue #252): acceptance-тесты мутируют общесистемное состояние контейнера (brew-stub
# singleton listener/pid-файл) — не безопасны для параллельного xdist-запуска.
docker run --rm \
    -e SROUTER_ACCEPTANCE=1 \
    -e PYTHONUNBUFFERED=1 \
    "$IMAGE" \
    pytest tests/acceptance/ -v -n 0 "$@"

echo ""
echo "==> Готово. Контейнер удалён (--rm). Живой стек не затронут."
