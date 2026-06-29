# srouter Reality node

Docker-first серверный узел Xray VLESS + Reality для Linux Docker host.

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
