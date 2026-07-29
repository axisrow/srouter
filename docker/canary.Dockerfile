# Docker-native build-context canary (issue #116, follow-up #114 Codex cycle 4).
#
# Ручной parse .dockerignore в test_secret_paths_ignored_by_dockerignore (regex-трансляция glob)
# приближает Docker-семантику, но не гарантирует 100% совпадение с реальным движком (directory-only
# паттерны, ** в середине пути и т.п.). Этот Dockerfile — независимый canary: реальный `docker build`
# копирует ВЕСЬ build-context (после .dockerignore), без установки зависимостей (быстро, не нужен
# рабочий srouter — только факт «файл попал/не попал в build-context»).
#
# Тест кладёт временный секретный файл по каждому пути из _SECRET_PATHS, собирает образ, затем
# проверяет `docker run ... test -e <path>` — должен вернуть rc!=0 (файла нет).
FROM python:3.12-slim

WORKDIR /ctx
COPY . /ctx
