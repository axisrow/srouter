# Docker: приёмочный полигон (acceptance)

Изолированная Linux-среда для live-приёмки цикла `srouter install`/`uninstall` **без риска для рабочего macOS-стека**. issue #112, #113.

## Зачем

`srouter install`/`uninstall` на рабочей машине сносит прокси-стек (privoxy/xray/dnsmasq, LaunchAgent, DNS, routes). Герметичные pytest (744 шт.) покрывают бизнес-логику через `FakeRunner`, но **не запускают реальный CLI**. Этот полигон закрывает зазор: `srouter` как subprocess против macOS-binary stub'ов в Linux-контейнере.

## Запуск

```bash
./docker/run-acceptance.sh
```

Соберёт образ `srouter-acceptance` (из `docker/acceptance.Dockerfile`) и прогонит `pytest tests/acceptance/` с `SROUTER_ACCEPTANCE=1`. Контейнер удаляется автоматически (`--rm`). Живой macOS-стек не затрагивается.

## Как это работает

- srouter macOS-native (`launchctl`/`brew`/`networksetup`/`osascript`/`route`), но вся бизнес-логика дёргает ОС **только через параметр `runner=`**, а пути — через env (`SROUTER_PREFIX`/`SROUTER_STATE_PATH`/...).
- Вместо macOS-VM кладём **тупые shell-stub'ы** (`docker/stubs/`) по тем же абсолютным macOS-путям. srouter находит их по константам — **код править не нужно**.
- База: `python:3.12-slim` (Debian). `lsof`/`curl`/`git` — реальные; `launchctl`/`brew`/`networksetup`/`osascript`/`route`/`sudo` — stub'ы.

## Registry за GFW

Docker Hub (`registry-1.docker.io`) недоступен/замедлен за GFW. Базовый образ тянется через зеркало `docker.m.daocloud.io` (см. `FROM` в `acceptance.Dockerfile`). Registry-mirror в `daemon.json` ломал старт Docker Desktop (health-check зеркал при boot висел) — поэтому зеркало в `FROM`, не в daemon-конфиге. У кого Docker Hub доступен — замените `FROM` на `python:3.12-slim`.

## Stub-детализация

Тупые stateless stub'ы (каждый вызов exit 0 с минимальным правдоподобным выводом) — `launchctl`/`networksetup`/`osascript`/`route`/`sudo`. install/uninstall идут по «чистой» ветке (как установка с нуля).

`brew` — **stateful** (issue #116 п.2, усилено по реальной потребности, не заранее): `install_lib.py::_restart_component` (issue #115) poll'ит РЕАЛЬНЫЙ TCP/UDP порт (`sys_probe.port_open`) после `brew services start <name>`, не только rc=0. #115 смёрджен ПОСЛЕ #114 — полигон не был адаптирован, из-за отсутствия CI (issue #116 п.3) регрессия (`<name>_restart_failed` на каждом install) не была поймана. `docker/stubs/brew.sh` на `services start/restart <name>` реально поднимает listener (`docker/stubs/port_listener.py`) на порту сервиса (xray=10808/tcp, privoxy=8118/tcp, dnsmasq=53/tcp+udp — реальный dnsmasq слушает оба транспорта, TCP для больших DNS-ответов), на `stop` — останавливает по pid-файлу в `/tmp/srouter-acceptance-ports/`.

## `.dockerignore` security gate: Docker-native canary (issue #116)

`tests/acceptance/test_dockerignore_secrets.py` держит ручной parse-гвард (glob→regex) **и**
Docker-native canary: `docker/canary.Dockerfile` — минимальный образ (без pip install), в
build-context которого тест кладёт временные секретные файлы по всем путям из `_SECRET_PATHS`,
собирает образ реальным `docker build`, затем проверяет `docker run ... test -e` — файл не должен
быть найден. Это независимая проверка от реального движка Docker, а не от regex-приближения его
семантики. Требует Docker; skip если `docker info` недоступен. Canary не трогает пути, которые уже
существуют на диске (защита от повреждения реальных локальных секретов разработчика).

## CI (issue #116)

`.github/workflows/acceptance.yml` собирает образ (с `--build-arg BASE_IMAGE=python:3.12-slim` —
GitHub Actions runners тянут Docker Hub напрямую, зеркало не нужно) и прогоняет `pytest
tests/acceptance/ -v` на каждый PR и push в `main`.

## Расширенные сценарии (issue #116 п.4)

`tests/acceptance/test_cli_scenarios.py` дополняет идемпотентность install/uninstall:
- `srouter status`/`srouter doctor` — read-only цикл, детерминированные exit codes без реального стека.
- conflict-resolution (adopt/overwrite/skip) против «чужого» (non-srouter) xray config — реальный
  `install_lib.py apply --xray <choice>` CLI (не FakeRunner). `srouter install` (entry-point из
  `pyproject.toml`) не имеет CLI-флага для программного выбора — только интерактивный prompt при TTY;
  non-TTY без готового выбора всегда rc=2. `install_lib.py`/`install.sh` — параллельный CLI-путь с
  `--<component> adopt|overwrite|skip`.
- edge-case #110/#111 (cycle-review #111 cycle 2 finding B): свежий install без backup → uninstall
  НЕ репортит leftover — end-to-end версия юнит-теста
  `tests/test_uninstall_flow.py::test_apply_uninstall_no_leftover_for_fresh_install_without_backup`.
