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

> Нужен Homebrew. Часть действий (DNS на :53, маршруты) требует пароль администратора —
> `srouter install` спросит его через GUI macOS (osascript), либо запустите под `sudo`.

```bash
# 1. Поставить команду srouter (в активный python3 — в нём же лежит flask как зависимость):
python3 -m pip install --upgrade pip          # нужен pip ≥ 21.3 для PEP 660 editable-install
pip install -e .

# 2. Полная установка стека одной командой:
srouter install
#   • ставит brew-сервисы xray/privoxy/dnsmasq и пишет их конфиги;
#   • настраивает DNS (networksetup ... 127.0.0.1) и устанавливает LaunchAgent дашборда;
#   • показывает план и спрашивает подтверждение; при конфликте чужих конфигов — adopt/overwrite/skip;
#   • под sudo привилегированные шаги идут напрямую, без sudo — через GUI-пароль macOS.
srouter status         # проверить, что демон работает (http://127.0.0.1:8787)

# Управление демоном дашборда (стек не трогается):
srouter start          # запустить демон (если LaunchAgent уже установлен)
srouter stop           # остановить демон (plist сохранён)
srouter restart        # перезапустить демон (применить правки кода)

# Foreground-запуск дашборда для отладки (без launchd, блокирует терминал):
python3 dashboard.py
```

`srouter install` / `uninstall` управляют **всем стеком** (brew-сервисы, конфиги, DNS, LaunchAgent);
`start`/`stop`/`restart` — только запущенным процессом дашборда. Конфиги и логика конфликтов живут в
`install_lib.py`; неинтерактивный путь для CI/скриптов — `./install.sh apply` (см. `install_lib.py`).

## Интеграции

| Инструмент | Подключение |
|---|---|
| **Claude Code** | `HTTPS_PROXY=http://127.0.0.1:8118` в `~/.claude/settings.json` |
| **Codex CLI/App** | `[network] proxy_url = "http://127.0.0.1:8118"` в `~/.codex/config.toml` (env‑прокси Codex игнорирует) |
| **git / gh** | домены GitHub в вайтлисте узла → резолв и трафик через ускоритель |
| **Браузер** | системный SOCKS5 `127.0.0.1:10808` (вайтлист разруливает сам) |

## Откат

```bash
srouter uninstall      # полный откат к дефолту:
#   останавливает brew-сервисы, восстанавливает чужие конфиги из бэкапов,
#   сбрасывает DNS (networksetup ... Empty), удаляет LaunchAgent и split-route до VPS.
```

## PF-изоляция доменов (опционально)

**Цель:** пакеты к Proxy-доменам (`api.anthropic.com`, `console.anthropic.com`, `claude.ai`) физически
не могут уйти через реальный интерфейс (en0/ppp0) — даже если Claude Code забудет `HTTPS_PROXY` или
любая программа полезет напрямую. PF режет в ядре macOS. Если прокси упал — трафик в ниду
(fail-closed), НЕ напрямую.

Управление — через карточку «Изоляция доменов (PF)» в дашборде: кнопки **Включить / Выключить / Обновить IP**.
Или через CLI:

```bash
python3 isolate_firewall.py enable       # dig домены → IP → блок в ядре
python3 isolate_firewall.py disable      # снять блок
python3 isolate_firewall.py refresh      # re-dig (IP меняются у CloudFront/Anthropic)
python3 isolate_firewall.py status       # текущее состояние
```

**Как это работает (механика «глаза и руки»):**
- `dig @8.8.8.8 <domain>` — узнать IP домена («глаза»: домен → IP).
- `pfctl -a com.apple/srouter_isolate -t srouter_proxy_ips -T replace <ips>` — положить IP в таблицу
  файрвола («руки»: охранник PF в ядре + листок с номерами). Всё, что идёт на эти IP через en0/ppp0
  по портам 80/443 — умирает. Через прокси (xray→VPS) — работает: xray шлёт на IP VPS, не на IP Claude.

**Двухфазная загрузка** закрывает стартовое окно (между бутом и `dig`+`pfctl`): при загрузке macOS
сначала блокируются подсети Anthropic (`160.79.104.0/21`) — claude.ai отрезан с первой секунды,
интернет жив; когда srouter собрал конкретные IP — блок сужается до точных адресов.

### 🚨 Если интернет сломался

PF-изоляция режет в ядре — если что-то пошло не так, **вернуть сеть одной командой**:

```bash
sudo pfctl -a "com.apple/srouter_isolate" -F all   # снять правила изоляции
```

Если не помогло (или anchor не виноват), **полностью выключить PF** (ядерный вариант, возвращает
всю сеть, но отключает и Traffic Guard throttle):

```bash
sudo pfctl -d                                     # выключить PF целиком
```

После восстановления сети — разберитесь, что сломалось (`~/Library/Logs/srouter-dashboard.err.log`),
почините, и включите PF обратно (`sudo pfctl -E`) перед повторной изоляцией.

**Ограничения:** блок по IP (не SNI — SNI потребует TUN/Mihomo, отложено); подсети на старте режут
чуть шире (соседние Anthropic-домены напрямую отрезаны, через прокси работают); IP меняются →
обновление каждые 6 ч (устаревший IP в таблице безвреден — мы блокируем, не разрешаем).


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

> Requires Homebrew. Some steps (DNS on :53, routes) need an administrator password —
> `srouter install` will prompt for it via the macOS GUI (osascript), or run under `sudo`.

```bash
# 1. Install the srouter command (into the active python3 — it holds flask as a dependency):
python3 -m pip install --upgrade pip          # needs pip >= 21.3 for PEP 660 editable install
pip install -e .

# 2. Install the full stack with one command:
srouter install
#   • installs brew services xray/privoxy/dnsmasq and writes their configs;
#   • sets DNS (networksetup ... 127.0.0.1) and installs the dashboard LaunchAgent;
#   • prints a plan and asks for confirmation; on a foreign-config conflict — adopt/overwrite/skip;
#   • under sudo privileged steps run directly, otherwise via the macOS GUI password.
srouter status         # check the daemon is up (http://127.0.0.1:8787)

# Dashboard daemon control (the stack is untouched):
srouter start          # start the daemon (if the LaunchAgent is already installed)
srouter stop           # stop the daemon (the plist is kept)
srouter restart        # restart the daemon (apply code changes)

# Foreground dashboard run for debugging (without launchd, blocks the terminal):
python3 dashboard.py
```

`srouter install` / `uninstall` manage the **entire stack** (brew services, configs, DNS, LaunchAgent);
`start`/`stop`/`restart` — only the running dashboard process. Configs and conflict logic live in
`install_lib.py`; the non-interactive path for CI/scripts is `./install.sh apply` (see `install_lib.py`).

## Rollback

```bash
srouter uninstall      # full rollback to defaults:
#   stops brew services, restores foreign configs from backups, resets DNS
#   (networksetup ... Empty), removes the LaunchAgent and the split-route to the VPS.
```

## PF domain isolation (optional)

**Goal:** packets to Proxy domains (`api.anthropic.com`, `console.anthropic.com`, `claude.ai`)
physically cannot leave via the real interface (en0/ppp0) — even if Claude Code forgets
`HTTPS_PROXY` or any app goes direct. PF cuts at the macOS kernel. If the proxy is down, traffic
goes nowhere (fail-closed), NOT direct.

Manage via the "Domain isolation (PF)" card in the dashboard: **Enable / Disable / Refresh IPs** buttons.
Or via CLI:

```bash
python3 isolate_firewall.py enable       # dig domains → IPs → kernel block
python3 isolate_firewall.py disable      # remove the block
python3 isolate_firewall.py refresh      # re-dig (IPs change at CloudFront/Anthropic)
python3 isolate_firewall.py status       # current state
```

**How it works ("eyes and hands"):**
- `dig @8.8.8.8 <domain>` — resolve the domain's IP ("eyes": domain → IP).
- `pfctl -a com.apple/srouter_isolate -t srouter_proxy_ips -T replace <ips>` — put IPs into the
  firewall table ("hands": PF guard in the kernel + a list of numbers). Anything to these IPs via
  en0/ppp0 on ports 80/443 dies. Via the proxy (xray→VPS) it works: xray talks to the VPS IP, not the
  Claude IP.

**Two-phase boot** closes the startup window (between boot and `dig`+`pfctl`): on macOS boot, Anthropic
subnets (`160.79.104.0/21`) are blocked first — claude.ai is cut from second one, internet stays alive;
once srouter resolves concrete IPs, the block narrows to exact addresses.

### 🚨 If the internet broke

PF isolation cuts at the kernel — if something went wrong, **restore the network with one command**:

```bash
sudo pfctl -a "com.apple/srouter_isolate" -F all   # remove isolation rules
```

If that doesn't help (or the anchor isn't at fault), **disable PF entirely** (nuclear option, restores
all network but also disables Traffic Guard throttle):

```bash
sudo pfctl -d                                     # turn PF off completely
```

After the network is back — figure out what broke (`~/Library/Logs/srouter-dashboard.err.log`), fix
it, and re-enable PF (`sudo pfctl -E`) before isolating again.

**Limitations:** blocks by IP (not SNI — SNI needs TUN/Mihomo, deferred); subnets at boot cut slightly
wider (neighboring Anthropic domains are direct-blocked, but work via proxy); IPs change → refresh
every 6 h (a stale IP in the table is harmless — we block, not permit).


## Integrations

| Tool | Wiring |
|---|---|
| **Claude Code** | `HTTPS_PROXY=http://127.0.0.1:8118` in `~/.claude/settings.json` |
| **Codex** | `[network] proxy_url` in `~/.codex/config.toml` (it ignores env proxy) |
| **git / gh** | GitHub domains whitelisted on the node |
| **Browser** | system SOCKS5 `127.0.0.1:10808` |

---

*srouter — adaptive routing & throttle bypass. Fast, resilient, self‑optimizing access.*
