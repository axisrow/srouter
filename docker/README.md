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

Тупые stateless stub'ы (каждый вызов exit 0 с минимальным правдоподобным выводом). install/uninstall идут по «чистой» ветке (как установка с нуля). Если cycle-review найдёт, что логика зависит от state между вызовами — усилим до stateful в отдельном цикле.
