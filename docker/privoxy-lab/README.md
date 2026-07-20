# Docker: privoxy-лаборатория (изолированная среда для поимки причины самопадений)

issue #123. host-privoxy (8118) фликает/падает сам по себе (без `srouter install`/`brew services`). На хосте 300+ процессов — отделить «privoxy-баг» от «хост-эффект» (launchd KeepAlive, memory jettison, чужой signal) нельзя. Контейнер = контролируемая среда для решающего эксперимента.

## Решающий эксперимент

| Контейнер стабилен? | Вывод → куда чинить |
|---|---|
| ✅ Не падает N часов | Корень на ХОСТЕ (launchd KeepAlive / memory jettison). Чинить хост-launchd/throttle (#115). |
| ❌ Падает так же | Корень в PRIVOXY (конфиг / elliptic / bug). Чинить конфиг/шаблон. |

## Топология

```
[ client/агент ] → [ container privoxy 0.0.0.0:8119 ]
                          │
                          │ forward-socks5t / host.docker.internal:10808 .
                          ▼
                    [ host xray 127.0.0.1:10808 ]
                          │
                          ▼ Reality → VPS → freedom
```

Контейнер = только privoxy (8119). host-xray (10808) остаётся (стабилен с 3 июля). Порт 8119 — не конфликт с host-privoxy (8118).

## Запуск

```bash
docker compose -f docker/privoxy-lab/docker-compose.yml up -d
```

## Мониторинг эксперимента

```bash
# Рестарты (каждое падение/подъём видно здесь — частота фликера):
docker events --filter container=srouter-privoxy-lab

# Логи (crash/signal виден — tini + --no-daemon дают stdout в docker logs):
docker logs -f srouter-privoxy-lab

# Smoke-тест цепочки (exit-IP должен быть VPS, не local):
curl -x http://127.0.0.1:8119 https://api.ip.sb/ip
```

## Ключевое для поимки причины

- **tini PID-1** — catch SIGPIPE/SIGSEGV/signal (частая причина молчаливых падений; без tini privoxy падает без записи в лог).
- **`--no-daemon`** — privoxy foreground, stdout → `docker logs` (crash виден).
- **`debug 8192`** — трассировка коннектов (host-config этого не делал — слепое пятно).
- **`elliptic-curve-keys` убран** — чистый сигнал падения без non-fatal-error-шума.
- **`restart: unless-stopped`** — Docker поднимает при падении, частота видна в `docker events`.

## Агенты на резерв (8119)

Пока эксперимент идёт, агенты могут ходить на 8119 (контейнер) как на стабильный прокси — он изолирован от `srouter install`/`brew services` на хосте:
```
HTTP_PROXY=http://127.0.0.1:8119
```
