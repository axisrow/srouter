# srouter acceptance-полигон: изолированная Linux-среда для live-приёмки install/uninstall цикла
# без риска для рабочего macOS-стека (issue #112).
#
# Идея: srouter macOS-native (launchctl/brew/networksetup/osascript/route), НО вся бизнес-логика
# install/uninstall дёргает ОС только через runner= и пути через env (InstallEnv.from_env). Поэтому
# вместо macOS-VM кладём ТУПЫЕ shell-stub'ы по тем же абсолютным macOS-путям — srouter находит их по
# константам, код править не нужно (канон: ноль правок бизнес-логики).
#
# База: python:3.12-slim (Debian, НЕ alpine — musl ломает flask-wheels и editable-install).
# Сборка: docker build -f docker/acceptance.Dockerfile -t srouter-acceptance .
# Запуск:  docker run --rm -e SROUTER_ACCEPTANCE=1 srouter-acceptance pytest tests/acceptance/ -v
#          (или ./docker/run-acceptance.sh)
#
# Registry: Docker Hub (registry-1.docker.io) недоступен/замедлен за GFW. Тянем через зеркало
# docker.m.daocloud.io (issue #113). Registry-mirror в daemon.json ломал старт Docker Desktop
# (health-check зеркал при boot висел) — поэтому зеркало в FROM, а не в daemon-конфиге. У кого Docker Hub
# доступен напрямую — может заменить на `FROM python:3.12-slim`.
FROM docker.m.daocloud.io/library/python:3.12-slim

# lsof — реальный (кросс-платформенный), srouter зовёт /usr/sbin/lsof. Остальные macOS-binary = stub'ы.
# curl — probe-команды (probe_tunnel/probe_exit_ip). git — для pytest discovery + возможных проверок.
RUN apt-get update \
    && apt-get install -y --no-install-recommends lsof curl git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srouter

# Копируем репо целиком (editable-install ссылается на файлы из этой директории — templates/,
# launchagents/ нужны в рантайме через package-data + env.root).
COPY . /srouter

# Editable-install (PEP 660): ставит пакет srouter + entry-point `srouter` + dev-deps (pytest).
# pip в 3.12-slim уже ≥21.3. setuptools нужен для editable-build.
RUN pip install --no-cache-dir --upgrade pip setuptools>=61 wheel \
    && pip install --no-cache-dir -e '.[dev]'

# Bootstrap конфиг из example-шаблонов (плейсхолдеры, НЕ секреты). .dockerignore исключает настоящий
# srouter_config.py/srouter.local.json (защита от утечки секретов), но srouter-CLI требует их для запуска
# (dashboard_common поднимает SystemExit без srouter_config.py). Копируем example → рабочий файл с
# плейсхолдерами (как cp srouter_config.example.py srouter_config.py в CLAUDE.md). Секретов тут нет.
RUN cp srouter_config.example.py srouter_config.py \
    && cp srouter.local.example.json srouter.local.json

# macOS-binary stub'ы по тем же абсолютным путям, что в константах srouter
# (install_lib.py: BREW=/opt/homebrew/bin/brew, LAUNCHCTL=/bin/launchctl, NETWORKSETUP=/usr/sbin/networksetup,
#  ROUTE=/sbin/route; srouter.py: OSASCRIPT=/usr/bin/osascript). srouter найдёт их без правки кода.
# Путь 3 (итеративно): сначала тупые stateless stub'ы. Усиливаем до stateful только если cycle-review
# найдёт, что логика зависит от state между вызовами.
COPY docker/stubs/launchctl.sh     /tmp/stubs/launchctl.sh
COPY docker/stubs/brew.sh          /tmp/stubs/brew.sh
COPY docker/stubs/networksetup.sh  /tmp/stubs/networksetup.sh
COPY docker/stubs/osascript.sh     /tmp/stubs/osascript.sh
COPY docker/stubs/route.sh         /tmp/stubs/route.sh
COPY docker/stubs/sudo.sh          /tmp/stubs/sudo.sh

RUN mkdir -p /opt/homebrew/bin /usr/sbin /sbin /usr/bin /bin \
    && install -m 0755 /tmp/stubs/launchctl.sh    /bin/launchctl \
    && install -m 0755 /tmp/stubs/brew.sh         /opt/homebrew/bin/brew \
    && install -m 0755 /tmp/stubs/networksetup.sh /usr/sbin/networksetup \
    && install -m 0755 /tmp/stubs/osascript.sh    /usr/bin/osascript \
    && install -m 0755 /tmp/stubs/route.sh        /sbin/route \
    && install -m 0755 /tmp/stubs/sudo.sh         /usr/bin/sudo \
    && rm -rf /tmp/stubs

# Контейнер запускается от root → make_privileged_runner идёт по am_root-ветке (osascript не нужен),
# но stub всё равно стоит (если код дойдёт до _to_osascript — no-op вместо command-not-found).
USER root

# Sentinel (cycle-review #114 C2): acceptance-тест требует /srouter-acceptance-sentel для прогона.
# Файл существует ТОЛЬКО в образе → даже если SROUTER_ACCEPTANCE=1 задан на macOS host (вне контейнера),
# тест skip'нется (нет sentinel + не Linux) → не снесёт рабочий стек. Один env-var не авторизует прогон.
RUN touch /srouter-acceptance-sentinel

# Дефолтный cmd — прогон acceptance-тестов с SROUTER_ACCEPTANCE=1 (включает skip'нутые вне полигона).
CMD ["pytest", "tests/acceptance/", "-v"]
