# srouter Reality node

Docker-first серверный узел Xray VLESS + Reality для Linux Docker host.
Pinned-версия upstream Xray задаётся в `server/Dockerfile` через `XRAY_VERSION`.

## Быстрый старт

Из корня репозитория:

```bash
docker build -t srouter-reality server/
```

Через Compose:

```bash
cd server
cp .env.example .env
docker compose up -d --build
docker compose logs -f reality-node
```

## Registry-mirror для Docker Hub (GFW / registry-1.docker.io)

На dev-машине за GFW: если `docker build` / `docker pull` падают с `DeadlineExceeded` или надолго
зависают на pulling `alpine`/`python`/других образов с Docker Hub
(`registry-1.docker.io`), причина — блокировка/замедление хаба Great Firewall
или аналогичным фильтром. Симптом: тот же тег тянется минутами или рвётся по
таймауту, при этом `ghcr.io` (откуда берётся `xtls/xray-core`) отвечает нормально.

Решение — **registry-mirror в настройках Docker Desktop/Engine, а не `FROM <зеркало>`
в Dockerfile**. Dockerfile остаётся чистым и портируемым (на хостах без GFW
никаких правок), а зеркала — локальная настройка daemon, которую каждый dev в
GFW включает под себя.

Вариант A — GUI (Docker Desktop на macOS/Windows dev-машине): **Settings →
Docker Engine**, добавить ключ `"registry-mirrors"` и применить (Docker
перезапустится сам).

Вариант B — `~/.docker/daemon.json` вручную (та же настройка для Linux):

```json
{
  "builder": { "gc": { "defaultKeepStorage": "20GB", "enabled": true } },
  "experimental": false,
  "registry-mirrors": [
    "https://docker.m.daocloud.io",
    "https://docker.1ms.run"
  ]
}
```

Затем перезапустить Docker Desktop (или `sudo systemctl restart docker` на Linux).
Список зеркал — fallback-цепочка: движок идёт по ним по порядку, пока одно не
ответит. Указывайте только проверенные живые зеркала — мёртвый хост в начале
списка просто тратит таймаут перед каждым pull (поэтому `dockerproxy.net`,
указанный в части трекеров третьим, сюда не включён — на проверке он молчал по
таймауту; добавляйте только если `curl -sI https://dockerproxy.net/v2/` снова
жив). Актуальность зеркал лучше сверять периодически:
`curl -sI https://docker.m.daocloud.io/v2/` (живое зеркало отвечает
`401 Unauthorized` на анонимный `/v2/`; пустой ответ/таймаут — зеркало мёртво).

Проверить, что зеркало подхвачено движком:

```bash
docker info | grep -A5 'Registry Mirrors'
```

После этого обычный `docker build`/`docker pull` резолвят Docker Hub-образы
через зеркало без правки Dockerfile.

## Двухфазный deploy workflow

`deploy.sh` создаёт ignored bundle в `server/.generated/<node>/` и печатает полный JSON-объект,
который можно вставить в `srouter.local.json.nodes[]` без конверсии схемы:

```bash
./server/deploy.sh generate --endpoint-host 203.0.113.10 --name sg-1 --country-code SG
```

`generate` только рендерит bundle: `.env`, Docker assets и `node_object.json`; Docker Compose в этом
режиме не запускается. `deploy` сначала проверяет доступность `docker compose`, затем применяет тот же
bundle с `docker compose up -d --build --wait` и печатает node-object из текущего bundle:

```bash
./server/deploy.sh deploy --endpoint-host 203.0.113.10 --name sg-1 --country-code SG
```

Ключи генерирует `gen-keys.sh` теми же командами и форматами, что entrypoint контейнера. Deploy-фаза
передаёт эти значения в контейнер через `.env`, чтобы не было второй независимой генерации. Вывод
deploy не читает `/var/lib/srouter-reality/node_object.json` из persistent volume: при повторном deploy
там может временно лежать старый объект до завершения entrypoint.

Compose читает значения из `server/.env`. Если `XRAY_UUID`, `XRAY_PRIVATE_KEY` или
`XRAY_SHORT_ID` оставить пустыми, `entrypoint.sh` сгенерирует их при первом старте и сохранит в
volume `srouter-reality-state`. Private key остаётся только на сервере; node-object для #4
записывается в `/var/lib/srouter-reality/node_object.json` с правами `0600`.

Чтобы забрать node-object без записи access-параметров в Docker-логи:

```bash
docker compose exec reality-node cat /var/lib/srouter-reality/node_object.json
```

Если нужен явный вывод в stdout, выставь `PRINT_NODE_OBJECT=1` в `server/.env` и перезапусти
контейнер. Это opt-in режим: `uuid` и `short_id` попадут в Docker-логи.

## Env

| Переменная | Default | Назначение |
|---|---:|---|
| `LISTEN_PORT` | `443` | Порт VLESS inbound внутри контейнера и на host |
| `XRAY_UUID` | генерируется | `nodes[].uuid` / `clients[].id` |
| `XRAY_PRIVATE_KEY` | генерируется | Reality private key, хранится на сервере |
| `XRAY_SHORT_ID` | генерируется | `nodes[].reality.short_id` / `shortIds[]` |
| `XRAY_DEST` | `www.163.com:443` | Reality fallback destination |
| `XRAY_SNI` | `www.163.com` | Разрешённый SNI / `serverNames[]` |
| `XRAY_FLOW` | `xtls-rprx-vision` | VLESS flow |
| `PRINT_NODE_OBJECT` | `0` | Печатать node-object в stdout только при `1` |

## Проверка

```bash
bash -n server/entrypoint.sh
```

`config.template.json` содержит `${...}` placeholders, поэтому JSON проверяется после рендера.
Финальный rendered config создаётся внутри контейнера в `/etc/xray/rendered/config.json` и
entrypoint проверяет его командой:

```bash
xray run -test -config /etc/xray/rendered/config.json
```

Для ротации автоматически созданных ключей останови контейнер и удали volume
`srouter-reality-state`.

## Bare Linux install без Docker

`bare-install.sh` — отдельный future-path для Reality-узла без Docker. Scope намеренно узкий:
Debian/Ubuntu family с `apt` и `systemd`. Скрипт ставит официальный bare-бинарь Xray той же
версии, что Dockerfile (`25.6.8` по умолчанию), рендерит тот же `config.template.json` в
host-конфиг и ставит `srouter-reality.service`.

Install:

```bash
sudo ./server/bare-install.sh install --endpoint-host 203.0.113.10 --name sg-1 --country-code SG
```

Update с сохранением ключей и node defaults из `/var/lib/srouter-reality`:

```bash
sudo ./server/bare-install.sh update
```

Rollback к backup, созданному перед последним успешным `update`:

```bash
sudo ./server/bare-install.sh rollback
```

Bare-путь не генерирует ключи и node-object сам: он вызывает `deploy.sh generate`, который, в свою
очередь, использует `gen-keys.sh` и печатает тот же полный объект для `srouter.local.json.nodes[]`,
что Docker workflow. Секреты остаются на host в `/var/lib/srouter-reality/.env` и
`/var/lib/srouter-reality/node_object.json` с правами `0600`; rendered config пишется в
`/etc/xray/rendered/config.json`.

Backup перед `update` лежит в `/var/lib/srouter-reality/backups/`. Если проверка нового config
через `xray run -test -config ...` падает, скрипт автоматически восстанавливает предыдущие binary,
geodata, config, unit и state-файлы, затем делает `systemctl restart srouter-reality.service`.
