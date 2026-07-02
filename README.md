# srouter — smart router

> **Умное ускорение доступа.** srouter **автоматически восстанавливает пропущенные узлы сети** и
> находит более быстрые маршруты прохождения трафика вместо стандартных, когда те демонстрируют
> повышенные задержки или нестабильность. Это **адаптивная маршрутизация**: запросы к ресурсам со
> сниженной скоростью доступа направляются по оптимизированному пути через зарубежный
> узел‑ретранслятор, остальной трафик идёт напрямую.
>
> *Если «замедление» — это избирательная фильтрация маршрутов, то «ускорение» — это автоматический
> подбор быстрых маршрутов и восстановление пропущенных узлов сети. Закон надо чтить.* 🎩

*(English version below — [jump to English](#srouter--smart-router-english))*

---

## Что это

srouter — тулкит **адаптивной маршрутизации трафика** и **обхода замедлений**. Он делает так,
чтобы доступ к ресурсам, которые «замедлены» на стандартном маршруте, был быстрым и стабильным —
за счёт автоматического выбора лучшего пути и постоянной оптимизации.

Тулкит состоит из **двух частей**:

1. **Серверная часть — Docker‑контейнеры узлов‑ускорителей.** Разворачивается на VPS за пределами
   региона ограничений. Можно поднять **несколько** узлов в разных локациях и подключить их все —
   srouter сам выберет самый быстрый.
2. **Локальная часть — установщик клиента.** Ставится на рабочую машину (macOS): клиент
   маршрутизации, быстрый DNS и веб‑дашборд мониторинга/управления.

## Адаптивность: три уровня

srouter адаптируется к состоянию сети на трёх уровнях:

| Уровень | Что выбирается/оптимизируется | Как |
|---|---|---|
| **Узел‑ускоритель** | самый быстрый из подключённых Docker‑узлов | непрерывный замер задержки и пропускной способности до каждого, выбор лучшего |
| **Маршрут** | оптимальный путь для конкретного ресурса | автоопределение «горячих» (популярных) маршрутов, их кэш и приоритезация |
| **Физический канал** | рабочий сетевой интерфейс | Wi‑Fi → мобильный (USB / Wi‑Fi‑hotspot / **Bluetooth‑tethering**) при недоступности |

То есть: «замедлили» маршрут — srouter уводит трафик через быстрый узел; маршрут часто
используется — он закэширован и выбирается мгновенно; пропал Wi‑Fi — переключился на мобильный
любым доступным способом. Стандартный (не замедленный) трафик всегда идёт напрямую и быстро.

## Самооптимизация (что система делает сама)

srouter не статичен — он **постоянно учится и подстраивается**:

- **Автоопределение популярных маршрутов.** Система отслеживает, к каким ресурсам обращаются чаще
  всего, и держит для них заранее выбранный оптимальный путь — это сокращает время нахождения
  маршрута (не нужно каждый раз решать заново).
- **Оптимизация скорости нахождения маршрута.** «Горячие» маршруты кэшируются; решение о пути
  принимается по предвычисленной таблице, а не на лету.
- **Оптимизация пропускной способности.** Узлы оцениваются не только по задержке (ping), но и по
  реальной пропускной способности; трафик балансируется на узел с лучшим сочетанием latency +
  throughput.
- **Health‑check и авто‑переключение.** Каждый узел периодически проверяется; при деградации
  (рост задержки, падение скорости, потери) трафик автоматически уходит на следующий лучший узел.

## Архитектура

```
   ФИЗИЧЕСКИЕ КАНАЛЫ (failover по приоритету)
   ┌──────────┐  ┌──────────┐  ┌──────────────┐
   │ Wi-Fi    │  │ USB-тел. │  │ Bluetooth-тел.│
   │ (en0)    │  │(Personal │  │ (PAN)         │
   └────┬─────┘  │ Hotspot) │  └──────┬───────┘
        │        └────┬─────┘         │
        └─────────────┴───────────────┘
                      │  ← srouter держит активным быстрейший доступный канал
   ┌──────────────────┴──────────────────────────────────────────┐
   │                  ЛОКАЛЬНАЯ ЧАСТЬ (macOS)                       │
   │  приложения ─► privoxy(HTTP:8118) ─► xray(SOCKS5:10808)        │
   │                                          │                    │
   │   АДАПТИВНАЯ МАРШРУТИЗАЦИЯ + САМООПТИМИЗАЦИЯ:                  │
   │   ┌──────────────────────────────────────┴────────────────┐  │
   │   │ замедленные/популярные домены → лучший узел (кэш путей) │  │
   │   │ остальное                     → напрямую                │  │
   │   └───────────────────┬──────────────────────────────────-─┘  │
   │   dnsmasq (быстрый DNS)│   dashboard (замер узлов, выбор, метрики)│
   └───────────────────────┼───────────────────────────────────────┘
                           │ VLESS+Reality (маскировка под TLS-сайт)
       ┌───────────────────┼────────────────────┬────────────────────┐
       ▼                   ▼                    ▼                    ▼
 ┌──────────┐       ┌──────────┐         ┌──────────┐         ┌──────────┐
 │ Узел A 🇧🇬│       │ Узел B 🇩🇪│         │ Узел C 🇸🇬│   ...   │ Узел N   │
 │Docker:443│       │Docker:443│         │Docker:443│         │          │
 └────┬─────┘       └────┬─────┘         └────┬─────┘         └────┬─────┘
      │  ◄── srouter ранжирует по latency + throughput, шлёт на лучший ──►│
      └─────────────────────────── интернет ──────────────────────────────┘
```

---

## Компоненты

### 1. Серверная часть — узлы‑ускорители (Docker)

Каждый узел — Docker‑контейнер с **Xray (VLESS + Reality)** на порту 443. Reality маскирует трафик
под настоящее TLS‑соединение к реальному сайту (например `www.163.com`) — со стороны узел
неотличим от обычного веб‑сервера.

- **Масштабируемость:** разворачивай узлы в разных странах/у разных провайдеров через
  `docker compose up`. Больше узлов — больше вариантов для выбора быстрейшего и выше
  отказоустойчивость.
- **Реестр узлов** читается локальной частью; добавление узла = добавление записи (адрес + ключи
  Reality).
- **Маскировка:** VLESS+Reality, SNI подделывается под популярный «скучный» домен; один порт 443,
  выглядит как обычный HTTPS.

### 2. Локальная часть — клиент маршрутизации

```
приложение → privoxy (127.0.0.1:8118, HTTP) → xray (127.0.0.1:10808, SOCKS5) → лучший узел
```

- **xray‑клиент** — локальный SOCKS5 с **вайтлист‑роутингом**: замедленные/популярные домены идут
  в туннель к узлу, остальное — `direct` (напрямую, с реального IP, быстро).
- **privoxy** — HTTP‑мост поверх SOCKS5 (многие инструменты понимают только HTTP‑прокси, не SOCKS).
- **Выбор узла** — дашборд ранжирует узлы по latency + throughput и маршрутизирует через лучший,
  переключаясь при деградации.

### 3. DNS — быстрый резолвинг без зависаний

`dnsmasq` локально с параллельным опросом upstream (`all-servers`): запрос уходит всем DNS сразу,
берётся первый ответ + кэш. Решает 5‑секундные зависания стандартного резолвера на «замедленном»
DNS‑сервере.

```
listen-address=127.0.0.1
all-servers              # параллельный опрос, первый ответ побеждает
server=223.5.5.5         # AliDNS
server=8.8.8.8           # Google
cache-size=1000
```

### 4. Дашборд (`dashboard.py`)

Веб‑панель `http://127.0.0.1:8787` (Flask, Bootstrap 5, офлайн‑ассеты — работает без внешних CDN):

- **Схема соединения** — flow‑диаграмма с флагами стран, гео (город/ISP/ASN), задержками хопов.
- **Мониторинг:** узлы, туннель, выходной IP, ping, пропускная способность, публичные DNS (со
  статусом каждого), сетевые интерфейсы, дистанция до узла.
- **Управление:** адаптивный маршрут (split‑route), сервисы, выбор/переключение узла.
- **Режимы:** Simple / Cinematic (кнопка‑глаз). **i18n:** English / Русский / 中文, авто‑тема ОС.

### 5. Канальный фоллбэк (Wi‑Fi → мобильный)

srouter следит за связностью активного интерфейса и при пропаже интернета на Wi‑Fi (`en0`)
переключается на любой доступный канал по приоритету: **USB‑телефон** (Personal Hotspot),
**Bluetooth‑tethering** (PAN), другая Wi‑Fi‑сеть. Реализуется через приоритет сетевых сервисов
macOS + активную проверку связности (не просто «линк есть», а «интернет реально доступен»).

---

## Установка (локальная часть, macOS)

> Нужен Homebrew. Часть действий (DNS на :53, маршруты) требует пароль администратора.

```bash
brew install xray privoxy dnsmasq

# конфиги:
#   /opt/homebrew/etc/xray/config.json      — узлы (реестр) + вайтлист‑роутинг
#   /opt/homebrew/etc/privoxy/config        — forward-socks5t / 127.0.0.1:10808 .
#   /opt/homebrew/etc/dnsmasq.conf          — all-servers + upstream

brew services start xray
brew services start privoxy
sudo brew services start dnsmasq            # порт 53 → root
sudo networksetup -setdnsservers "Wi-Fi" 127.0.0.1

# Консольная точка входа srouter (установка в системный Python):
pip install -e .

srouter apply          # загрузить LaunchAgent дашборда (демон, loopback 127.0.0.1:8787)
srouter status         # статус демона и PID
srouter run            # foreground-запуск (без launchd) — http://127.0.0.1:8787

# Либо напрямую (legacy/foreground):
python3 dashboard.py                        # http://127.0.0.1:8787
```

`srouter` — устанавливаемый Python-пакет (`pyproject.toml`). `apply` ставит LaunchAgent (автозапуск
при загрузке мака, перезапуск при падении), `status` проверяет демон, `run` запускает дашборд в окне.
Полная установка brew-стека (конфиги/сервисы/DNS) — через `./install.sh apply` (см. `install_lib.py`).

## Интеграции

| Инструмент | Подключение |
|---|---|
| **Claude Code** | `HTTPS_PROXY=http://127.0.0.1:8118` в `~/.claude/settings.json` |
| **Codex CLI/App** | `[network] proxy_url = "http://127.0.0.1:8118"` в `~/.codex/config.toml` (env‑прокси Codex игнорирует) |
| **git / gh** | домены GitHub в вайтлисте узла → резолв и трафик через ускоритель |
| **Браузер** | системный SOCKS5 `127.0.0.1:10808` (вайтлист разруливает сам) |

## Откат

```bash
sudo networksetup -setdnsservers "Wi-Fi" Empty
sudo brew services stop dnsmasq
brew services stop xray privoxy
```

---

# srouter — smart router (English)

> **Smart access acceleration.** srouter **restores network nodes missing from the path** and
> automatically discovers faster routes instead of the standard ones whenever the latter show
> increased latency or instability. This is **adaptive routing**: requests to resources with
> reduced access speed are sent over an optimized path through an overseas relay node, while all
> other traffic goes directly.

## What it is

A toolkit for **adaptive traffic routing** that bypasses throttling by always choosing the best
path and continuously optimizing it. Two parts:

1. **Server side — Docker accelerator nodes.** Deploy on a VPS outside the restricted region. Run
   **multiple** nodes and connect them all — srouter picks the fastest.
2. **Local side — client installer.** Routing client, fast DNS, and a monitoring/control dashboard
   (macOS).

## Adaptivity: three levels

| Level | Chosen / optimized | How |
|---|---|---|
| **Accelerator node** | fastest connected Docker node | continuous latency + throughput probing |
| **Route** | optimal path per resource | auto‑detected hot (popular) routes, cached & prioritized |
| **Physical link** | working interface | Wi‑Fi → mobile (USB / hotspot / **Bluetooth tethering**) on failure |

## Self‑optimization (what it does on its own)

- **Auto‑detects popular routes** and keeps a pre‑selected optimal path for them — cutting
  path‑selection time.
- **Optimizes path‑selection speed** via a hot‑route cache (decisions from a precomputed table).
- **Optimizes throughput** — nodes ranked by latency *and* real bandwidth; traffic goes to the best
  combination.
- **Health‑checks & auto‑failover** — degraded node (latency/throughput/loss) → traffic shifts to
  the next best automatically.

## Components

- **Accelerator nodes (Docker):** Xray **VLESS + Reality** on :443, masqueraded as a real TLS site.
  Scalable via `docker compose up`.
- **Routing client:** `app → privoxy (HTTP) → xray (SOCKS5) → best node`, with **whitelist routing**.
- **Fast DNS:** local `dnsmasq` with `all-servers` (parallel queries, first answer wins).
- **Dashboard** (`dashboard.py`): connection‑flow, geo/IP/latency/throughput monitoring, DNS health,
  interfaces, node selection. Simple/Cinematic modes, i18n EN/RU/ZH.
- **Link failover:** Wi‑Fi → mobile (USB / hotspot / Bluetooth) by priority on connectivity loss.

## Install (local, macOS)

```bash
brew install xray privoxy dnsmasq
brew services start xray
brew services start privoxy
sudo brew services start dnsmasq            # port 53 → root
sudo networksetup -setdnsservers "Wi-Fi" 127.0.0.1

# Console entry point srouter (installed into system Python):
pip install -e .

srouter apply          # load the dashboard LaunchAgent (daemon, loopback 127.0.0.1:8787)
srouter status         # daemon status and PID
srouter run            # foreground run (without launchd) — http://127.0.0.1:8787

# Or directly (legacy/foreground):
python3 dashboard.py                         # http://127.0.0.1:8787
```

`srouter` is an installable Python package (`pyproject.toml`). `apply` installs the LaunchAgent
(autostart at login, restart on crash), `status` checks the daemon, `run` starts the dashboard in a
window. Full brew-stack install (configs/services/DNS) is via `./install.sh apply` (see `install_lib.py`).

## Integrations

| Tool | Wiring |
|---|---|
| **Claude Code** | `HTTPS_PROXY=http://127.0.0.1:8118` in `~/.claude/settings.json` |
| **Codex** | `[network] proxy_url` in `~/.codex/config.toml` (it ignores env proxy) |
| **git / gh** | GitHub domains whitelisted on the node |
| **Browser** | system SOCKS5 `127.0.0.1:10808` |

---

*srouter — adaptive routing & throttle bypass. Fast, resilient, self‑optimizing access.*
