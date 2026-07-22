# srouter — smart router

> **Умное ускорение доступа.** srouter **находит более быстрые маршруты** прохождения трафика
> вместо стандартных, когда те демонстрируют повышенные задержки или нестабильность. Это
> **адаптивная маршрутизация**: запросы к ресурсам со сниженной скоростью доступа направляются по
> оптимизированному пути через зарубежный узел‑ретранслятор, остальной трафик идёт напрямую.
>
> *Если «замедление» — это избирательная фильтрация маршрутов, то «ускорение» — это подбор быстрых
> маршрутов и приоритизация «горячих» путей. Закон надо чтить.* 🎩

*(English version below — [jump to English](#srouter--smart-router-english))*

---

## Что это

srouter — тулкит **адаптивной маршрутизации трафика** и **обхода замедлений**. Он делает так,
чтобы доступ к ресурсам, которые «замедлены» на стандартном маршруте, был быстрым и стабильным —
за счёт приоритизации «горячих» маршрутов и рекомендации самого быстрого узла (переключение —
вручную, кнопкой в дашборде).

Тулкит состоит из **двух частей**:

1. **Серверная часть — Docker‑контейнеры узлов‑ускорителей.** Разворачивается на VPS за пределами
   региона ограничений. Можно поднять **несколько** узлов в разных локациях и подключить их все —
   srouter ранжирует их по скорости и рекомендует лучший (переключение — вручную).
2. **Локальная часть — установщик клиента.** Ставится на рабочую машину (macOS): клиент
   маршрутизации, быстрый DNS и веб‑дашборд мониторинга/управления.

## Адаптивность: три уровня

srouter адаптируется к состоянию сети на трёх уровнях:

| Уровень | Что выбирается/оптимизируется | Как |
|---|---|---|
| **Узел‑ускоритель** | самый быстрый из подключённых Docker‑узлов | непрерывный замер задержки и пропускной способности до каждого, ранжирование + рекомендация лучшего (переключение вручную) |
| **Маршрут** | оптимальный путь для конкретного ресурса | автоопределение «горячих» (популярных) маршрутов, их кэш и приоритезация |
| **Физический канал** | рабочий сетевой интерфейс | Wi‑Fi → мобильный (USB / Wi‑Fi‑hotspot) при недоступности |

То есть: «замедлили» маршрут — srouter уводит трафик через быстрый узел; маршрут часто
используется — он закэширован и выбирается мгновенно; пропал Wi‑Fi — переключился на мобильный
любым доступным способом. Стандартный (не замедленный) трафик всегда идёт напрямую и быстро.

## Самооптимизация (что система делает сама)

srouter не статичен — он **постоянно измеряет сеть и подстраивает маршруты**. Сбор метрик, кэш
маршрутов и ранжирование узлов идут автоматически; смена активного узла — по рекомендации, вручную:

- **Автоопределение популярных маршрутов.** Система отслеживает, к каким ресурсам обращаются чаще
  всего, и держит для них заранее выбранный оптимальный путь — это сокращает время нахождения
  маршрута (не нужно каждый раз решать заново).
- **Оптимизация скорости нахождения маршрута.** «Горячие» маршруты кэшируются; решение о пути
  принимается по предвычисленной таблице, а не на лету.
- **Оценка по пропускной способности.** Узлы оцениваются не только по задержке (ping), но и по
  реальной пропускной способности; дашборд ранжирует их по сочетанию latency + throughput и
  **рекомендует** лучший (переключение — вручную).
- **Health‑check и рекомендация лучшего узла.** Каждый узел периодически проверяется; при
  деградации (рост задержки, падение скорости, потери) дашборд ранжирует узлы и **рекомендует**
  переключиться на лучший. Переключение — ручное (кнопкой в дашборде): в v1 автопереключения нет,
  чтобы смена активного узла всегда была осознанной. *(Авто‑failover — в планах.)*

## Архитектура

```
   ФИЗИЧЕСКИЕ КАНАЛЫ (failover по приоритету)
   ┌──────────┐  ┌──────────┐
   │ Wi-Fi    │  │ USB-тел. │
   │ (en0)    │  │(Personal │
   └────┬─────┘  │ Hotspot) │
        │        └────┬─────┘
        └─────────────┘
                      │  ← srouter держит активным быстрейший доступный канал
   ┌──────────────────┴──────────────────────────────────────────┐
   │                  ЛОКАЛЬНАЯ ЧАСТЬ (macOS)                       │
   │  приложения ─► privoxy(HTTP:8118) ─► xray(SOCKS5:10808)        │
   │                                          │                    │
   │   АДАПТИВНАЯ МАРШРУТИЗАЦИЯ + САМООПТИМИЗАЦИЯ:                  │
   │   ┌──────────────────────────────────────┴────────────────┐  │
   │   │ замедленные/популярные домены → активный узел (кэш пути)│  │
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
      │  ◄── srouter ранжирует по latency + throughput, шлёт на выбранный ─►│
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
приложение → privoxy (127.0.0.1:8118, HTTP) → xray (127.0.0.1:10808, SOCKS5) → выбранный активный узел
```

- **xray‑клиент** — локальный SOCKS5 с **вайтлист‑роутингом**: замедленные/популярные домены идут
  в туннель к узлу, остальное — `direct` (напрямую, с реального IP, быстро).
- **privoxy** — HTTP‑мост поверх SOCKS5 (многие инструменты понимают только HTTP‑прокси, не SOCKS).
- **Выбор узла** — дашборд ранжирует узлы по latency + throughput и **рекомендует** лучший;
  активный узел переключается вручную (кнопкой). Автопереключения в v1 нет.

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
переключается на доступный мобильный канал по приоритету: **USB‑телефон** (Personal Hotspot),
затем другая Wi‑Fi‑сеть. Реализуется через приоритет сетевых сервисов macOS + активную проверку
связности (не просто «линк есть», а «интернет реально доступен»). *(Bluetooth‑tethering/PAN — в
планах; сейчас каналы — только Wi‑Fi и USB.)*

---

## Установка (локальная часть, macOS)

> Нужен Homebrew. Часть действий (DNS на :53, маршруты) требует пароль администратора.
> Два пути: **sudo** (один пароль, потом ноль диалогов) или **osascript** (GUI-диалог при каждом
> привилегированном действии). Выбирайте под свои условия.

```bash
# 1. Поставить команду srouter (в активный python3 — в нём же лежит flask как зависимость):
python3 -m pip install --upgrade pip          # нужен pip ≥ 21.3 для PEP 660 editable-install
pip install -e .

# 2. Создать локальный конфиг из шаблона и вписать свои адреса (иначе дашборд упадёт
#    с понятной ошибкой — srouter_config.py не в репозитории):
cp srouter_config.example.py srouter_config.py
#    → открыть srouter_config.py и заполнить GATEWAY / VPN_SERVER / VPN_EXIT_IP.

# 3. Полная установка стека одной командой:
#    Сценарий A — sudo (один ввод пароля, потом ноль osascript-диалогов; для серверов/dev):
sudo srouter install --python $(which python3) -y
#    Сценарий B — osascript (GUI-диалог при каждом привилегированном действии; для user-mac):
srouter install
#   • ставит brew-сервисы xray/privoxy/dnsmasq и пишет их конфиги;
#   • настраивает DNS, устанавливает LaunchAgent дашборда и watchdog;
#   • ставит ppp-hook для мгновенного split-route при VPN;
#   • настраивает прокси для Claude Code и git (github.com);
#   • ставит Codex SOCKS5-wrappers (~/bin/codex + codex-app-proxy) + глобальный env через
#     LaunchAgent + ~/bin в PATH — чтобы Codex (CLI и App) ходил напрямую в xray, минуя privoxy;
#   • показывает план и спрашивает подтверждение.
srouter status         # проверить, что демон работает (http://127.0.0.1:8787)
srouter doctor         # диагностика: порты + туннель + Claude-proxy (✅/❌)

# Управление демоном дашборда (стек не трогается):
srouter start          # запустить демон (если LaunchAgent уже установлен)
srouter stop           # остановить демон (plist сохранён)
srouter restart        # перезапустить демон (применить правки кода)

# Радикальная защита Privoxy от команд пользовательских агентов (#122):
srouter privoxy protect --strict  # разовый перенос в system-domain; потребует пароль
srouter privoxy status            # read-only, без пароля
srouter privoxy restart           # каждый раз требует пароль/Touch ID
srouter privoxy unprotect         # защищённый откат к прежней user-службе

# Пассивно записывать будущие попытки трогать Privoxy (#122):
srouter privoxy audit install     # потребует пароль и Full Disk Access для /usr/bin/eslogger
srouter privoxy audit status      # состояние аудитора, без пароля
srouter privoxy audit report      # последние подходящие команды, без пароля
srouter privoxy audit uninstall   # служба удаляется, журнал сохраняется
```

`srouter install` / `uninstall` управляют **всем стеком** (brew-сервисы, конфиги, DNS, LaunchAgent,
watchdog, ppp-hook, Claude Code/git-прокси, Codex SOCKS5-wrappers + env). `start`/`stop`/`restart` — только демоном дашборда.
`doctor` — разовая диагностика здоровья. Watchdog (запускается автоматически) — нотификация при
падении туннеля. Неинтерактивный путь для CI/скриптов — `./install.sh apply` (см. `install_lib.py`).

`privoxy protect --strict` переносит только Privoxy в root-controlled LaunchDaemon, но запускает
сам proxy от бесправного пользователя `nobody`. Его plist/config становятся недоступны для записи
обычным процессам. Исполняемый файл и нужные библиотеки копируются из Homebrew в root-owned каталог,
поэтому последующее изменение/обновление Homebrew не подменяет запущенную службу. Strict-режим
устанавливает `sudo timestamp_timeout=0`: любое `sudo` на этом Mac после этого требует нового
подтверждения. Dashboard не может управлять защищённым Privoxy — только показывает состояние и
направляет к ручной CLI-команде. `srouter install` распознаёт этот режим и не создаёт конкурирующий
пользовательский Privoxy.

`privoxy audit` ничего не меняет в Privoxy и не пытается автоматически его «лечить». Системная
служба читает события запуска программ, сохраняет только команды, относящиеся к lifecycle Privoxy,
и отбрасывает остальные события в памяти. macOS требует вручную добавить `/usr/bin/eslogger` в
System Settings → Privacy & Security → Full Disk Access; `audit status` явно покажет отказ. Формат
`eslogger` не стабилен, поэтому ошибки разбора видны в статусе, а не игнорируются. Удаление аудитора
сохраняет `/Library/Logs/srouter/privoxy-audit/command-audit.jsonl`; удалить его можно только явным
`audit uninstall --purge-log`.

## VPN и split-route

Трафик к Reality-узлу VPS всегда идёт через физический интерфейс (en0), **не через VPN** — даже когда
VPN (ppp0) перехватил default-маршрут. Мгновенно: `/etc/ppp/ip-up` hook срабатывает в момент поднятия
VPN и добавляет split-route (от root, без osascript). Дашборд показывает статус маршрута (карточка
«Схема соединения», split_active). Если VPN не через ppp0 (utun) — `srouter doctor` подскажет.

## Здоровье и защита от «остался без ИИ»

| Средство | Что делает |
|---|---|
| **`srouter doctor`** | Разовая диагностика: порты, туннель и активный transport-test настоящего Claude Code в изолированной конфигурации. Dummy API key исключает model call; ожидаемый API 401 доказывает, что proxy transport работает. |
| **`GET /health`** | Лёгкий HTTP-эндпоинт (`http://127.0.0.1:8787/health`). 200=ok, 503=degraded/down. Не запускает Claude Code. |
| **watchdog** (авто) | launchd-задача (раз в 20с): пассивные проверки и пинг туннеля, без запуска Claude Code. При падении — **macOS-нотификация** + звук. При восстановлении — тихое уведомление. |
| **PF-изоляция** | fail-closed: прокси упал → трафик в никуда, не напрямую. См. ниже. |

## Codex через SOCKS5 (CLI и App)

Codex (CLI и App) нестабилен через privoxy (8118, HTTP-CONNECT) — тот портит WebSocket-стриминг →
`Reconnecting 1..5/5` → `request timed out` в интерактиве. Codex умеет SOCKS5 нативно, поэтому
`srouter install` пускает его **напрямую в xray (10808)**, минуя privoxy (Claude Code остаётся на
privoxy — он SOCKS5 не умеет):

- **`~/bin/codex`** — wrapper CLI: выставляет `HTTP_PROXY/HTTPS_PROXY=socks5h://127.0.0.1:10808`
  перед вызовом реального codex (`socks5h` = DNS резолвится прокси, важно за GFW).
- **`~/bin/codex-app-proxy`** — wrapper App: `open -na Codex.app --args --proxy-server=socks5://...`
  (Chromium flag; env не дублирует). **Codex.app запускать через него, а не иконку Dock**
  (Dock не передаёт `--proxy-server`).
- **LaunchAgent `com.srouter.codenv`** — глобальный env (`socks5h://...` + `NO_PROXY=localhost,127.0.0.1,::1`)
  через plist с `EnvironmentVariables` (переживает ребут). Эмпирически: Claude.app/ChatGPT.app на
  System Settings SOCKS, global env их не ломает.
- **`~/bin` в `~/.zshrc`** — чтобы wrapper был раньше системного codex в PATH.

Всё ставит/убирает `srouter install`/`uninstall` (marker-gate: чужой wrapper/плагин не трогает).
Проверка: `which codex` → `~/bin/codex`; `codex doctor` → `proxy env vars: HTTP_PROXY, HTTPS_PROXY`.

> Почему не `[network] proxy_url` в `~/.codex/config.toml`? Ключ валидный, но управляет
> execution-scoped sandbox-прокси для субпроцессов codex, а не HTTP-клиентом к `chatgpt.com`. Для
> клиента работает только env (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`).
> Почему не отдельный WS-proxy env? `WS_PROXY`/`WSS_PROXY` тоже игнорируются (проверено в 0.142.5).
> Профиль `openai-http` с `supports_websockets=false` даёт 401 с ChatGPT-подпиской. Поэтому — SOCKS5
> напрямую, единый рабочий путь.

> **Ограничение wrapper'а (AO worktree):** `~/bin/codex` + zsh-функция работают **только** в
> интерактивном zsh. В AO worktree claude-code (Go) резолвит codex через Go `exec.LookPath`, который
> игнорирует zsh-функции и берёт `/opt/homebrew/bin/codex` (поз.5 в PATH) мимо `~/bin/codex` (поз.7).
> Без wrapper privoxy не снят → режёт WS. Симлинк `~/.local/bin/codex` **не помогает** (поз.24).
> Фикс — на стороне AO (`ALL_PROXY=socks5h://127.0.0.1:10808` + снять privoxy в env воркера), **не**
> srouter.

## Интеграции

| Инструмент | Подключение |
|---|---|
| **Claude Code** | `HTTPS_PROXY=http://127.0.0.1:8118` в `~/.claude/settings.json` (privoxy HTTP; SOCKS5 CC не умеет) |
| **Codex CLI/App** | **напрямую SOCKS5 в xray** (`socks5h://127.0.0.1:10808`) через wrappers + LaunchAgent env, минуя privoxy. privoxy портит WS-стриминг Codex (`Reconnecting`/`request timed out`); для клиента Codex↔`chatgpt.com` работает только env (`[network] proxy_url` в `~/.codex/config.toml` управляет execution-scoped sandbox-прокси для субпроцессов, не клиентом) — поэтому wrappers в `~/bin/codex` (CLI) + `~/bin/codex-app-proxy` (App, `--proxy-server` для Chromium) + глобальный env через `com.srouter.codenv` LaunchAgent (переживает ребут). Запускать Codex **App** через `~/bin/codex-app-proxy`, а не иконку Dock (Dock не передаёт `--proxy-server`). |
| **git / gh** | домены GitHub в вайтлисте узла → резолв и трафик через ускоритель |
| **Браузер** | системный SOCKS5 `127.0.0.1:10808` (вайтлист разруливает сам) |

## Откат

```bash
srouter uninstall      # полный откат к дефолту:
#   останавливает brew-сервисы, восстанавливает чужие конфиги из бэкапов,
#   сбрасывает DNS (networksetup ... Empty), удаляет LaunchAgent, watchdog, ppp-hook,
#   split-route до VPS, Claude Code/git-прокси, Codex SOCKS5-wrappers + env + PATH.
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
- `dig @8.8.8.8 <domain>` (A) и `dig @8.8.8.8 <domain> AAAA` — узнать IP домена **обоих семейств**
  (IPv4 и IPv6). Без v6 изоляция бесполезна: программы предпочитают IPv6 при наличии AAAA, и трафик
  уходит по v6 мимо v4-блока («глаза»: домен → IPv4 + IPv6).
- `pfctl -a com.apple/srouter_isolate -t srouter_proxy_ips -T replace <ips>` — положить оба семейства
  в таблицу файрвола («руки»: охранник PF в ядре + листок с номерами). PF mixed-таблица принимает
  IPv4 и IPv6 вместе. Всё, что идёт на эти IP через en0/ppp0 по портам 80/443 — умирает. Через прокси
  (xray→VPS) — работает: xray шлёт на IP VPS, не на IP Claude.

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

> **Smart access acceleration.** srouter **finds faster routes** instead of the standard ones
> whenever the latter show increased latency or instability. This is **adaptive routing**: requests
> to resources with reduced access speed are sent over an optimized path through an overseas relay
> node, while all other traffic goes directly.

## What it is

A toolkit for **adaptive traffic routing** that bypasses throttling by always choosing the best
path and continuously optimizing it. Two parts:

1. **Server side — Docker accelerator nodes.** Deploy on a VPS outside the restricted region. Run
   **multiple** nodes and connect them all — srouter ranks them by speed and recommends the fastest
   (switching is manual).
2. **Local side — client installer.** Routing client, fast DNS, and a monitoring/control dashboard
   (macOS).

## Adaptivity: three levels

| Level | Chosen / optimized | How |
|---|---|---|
| **Accelerator node** | ranked by speed, fastest recommended | continuous latency + throughput probing; manual switch |
| **Route** | optimal path per resource | auto‑detected hot (popular) routes, cached & prioritized |
| **Physical link** | working interface | Wi‑Fi → mobile (USB / hotspot) on failure |

## Self‑optimization (what it does on its own)

Metric collection, route caching and node ranking are automatic; changing the active node is manual,
on the dashboard's recommendation.

- **Auto‑detects popular routes** and keeps a pre‑selected optimal path for them — cutting
  path‑selection time.
- **Optimizes path‑selection speed** via a hot‑route cache (decisions from a precomputed table).
- **Scores by throughput** — nodes ranked by latency *and* real bandwidth; the dashboard
  **recommends** the best combination (switching is manual).
- **Health‑checks & best‑node recommendation** — a degraded node (latency/throughput/loss) makes
  the dashboard rank nodes and **recommend** the best; switching the active node is manual (a button).
  v1 has no auto‑failover — node changes stay deliberate. *(Auto‑failover is on the roadmap.)*

## Components

- **Accelerator nodes (Docker):** Xray **VLESS + Reality** on :443, masqueraded as a real TLS site.
  Scalable via `docker compose up`.
- **Routing client:** `app → privoxy (HTTP) → xray (SOCKS5) → selected active node`, with **whitelist routing**.
- **Fast DNS:** local `dnsmasq` with `all-servers` (parallel queries, first answer wins).
- **Dashboard** (`dashboard.py`): connection‑flow, geo/IP/latency/throughput monitoring, DNS health,
  interfaces, node selection. Simple/Cinematic modes, i18n EN/RU/ZH.
- **Link failover:** Wi‑Fi → mobile (USB / hotspot) by priority on connectivity loss. *(Bluetooth/PAN
  is on the roadmap; channels today are Wi‑Fi and USB only.)*

## Install (local, macOS)

> Requires Homebrew. Some steps (DNS on :53, routes) need an administrator password.
> Two paths: **sudo** (one password, then zero dialogs) or **osascript** (GUI prompt on each
> privileged action). Choose what fits your setup.

```bash
# 1. Install the srouter command (into the active python3 — it holds flask as a dependency):
python3 -m pip install --upgrade pip          # needs pip >= 21.3 for PEP 660 editable install
pip install -e .

# 2. Create the local config from the template and fill in your addresses (otherwise the
#    dashboard exits with a friendly error — srouter_config.py is not in the repo):
cp srouter_config.example.py srouter_config.py
#    → open srouter_config.py and fill GATEWAY / VPN_SERVER / VPN_EXIT_IP.

# 3. Install the full stack with one command:
#    Scenario A — sudo (one password entry, then zero osascript dialogs; for servers/dev):
sudo srouter install --python $(which python3) -y
#    Scenario B — osascript (GUI dialog on each privileged action; for user mac):
srouter install
#   • installs brew services xray/privoxy/dnsmasq and writes their configs;
#   • sets DNS, installs the dashboard LaunchAgent and watchdog;
#   • sets up ppp-hook for instant split-route on VPN up;
#   • configures proxy for Claude Code and git (github.com);
#   • installs Codex SOCKS5-wrappers (~/bin/codex + codex-app-proxy) + global env via
#     LaunchAgent + ~/bin in PATH — so Codex (CLI and App) goes straight to xray, bypassing privoxy;
#   • prints a plan and asks for confirmation.
srouter status         # check the daemon is up (http://127.0.0.1:8787)
srouter doctor         # diagnostics: ports + tunnel + Claude-proxy (✅/❌)

# Dashboard daemon control (the stack is untouched):
srouter start          # start the daemon (if the LaunchAgent is already installed)
srouter stop           # stop the daemon (the plist is kept)
srouter restart        # restart the daemon (apply code changes)

# Protect Privoxy from unprivileged agent lifecycle commands (#122):
srouter privoxy protect --strict  # one-time system-domain migration; asks for authorization
srouter privoxy status            # read-only, no password
srouter privoxy restart           # requires password/Touch ID every time
srouter privoxy unprotect         # privileged rollback to the previous user service

# Passively record future attempts to mutate Privoxy (#122):
srouter privoxy audit install     # asks for authorization; /usr/bin/eslogger needs Full Disk Access
srouter privoxy audit status      # read-only auditor state
srouter privoxy audit report      # recent matching commands, read-only
srouter privoxy audit uninstall   # removes daemon but preserves evidence log
```

`srouter install` / `uninstall` manage the **entire stack** (brew services, configs, DNS, LaunchAgent,
watchdog, ppp-hook, Claude Code/git proxy). `start`/`stop`/`restart` — only the dashboard daemon.
`doctor` — one-shot health diagnostics. Watchdog (auto-loaded) — notification on tunnel drop.
Non-interactive path for CI/scripts — `./install.sh apply` (see `install_lib.py`).

`privoxy protect --strict` moves only Privoxy to a root-controlled LaunchDaemon while the proxy
itself runs as the unprivileged `nobody` user. Its plist/config are not writable by normal processes.
The Privoxy executable and required libraries are copied out of user-owned Homebrew into a root-owned
directory, so a later Homebrew change cannot replace the running service. Strict mode installs
`sudo timestamp_timeout=0`, so every sudo command on this Mac requires fresh authorization. The
dashboard cannot mutate protected Privoxy, and later `srouter install` runs keep the protected service
instead of creating a competing user service.

`privoxy audit` never changes or automatically repairs Privoxy. Its system daemon consumes process
execution events, persists only commands related to the Privoxy lifecycle, and discards everything
else in memory. macOS requires `/usr/bin/eslogger` to be added manually under System Settings →
Privacy & Security → Full Disk Access; `audit status` reports a denial explicitly. Because eslogger's
JSON schema is not stable, parse failures are surfaced as degraded status. Uninstall preserves
`/Library/Logs/srouter/privoxy-audit/command-audit.jsonl` unless `audit uninstall --purge-log` is explicit.

## VPN and split-route

Traffic to the Reality VPS node always goes via the physical interface (en0), **not via VPN** — even
when VPN (ppp0) captures the default route. Instantly: the `/etc/ppp/ip-up` hook fires the moment VPN
goes up and adds the split-route (as root, no osascript). The dashboard shows the route status
(connection-flow card, split_active). For utun-based VPNs — `srouter doctor` will guide you.

## Health and protection from "stuck without AI"

| Tool | What it does |
|---|---|
| **`srouter doctor`** | One-shot diagnostics: ports, tunnel, and an active real-Claude-Code transport test with isolated settings. A dummy API key prevents model calls; the expected API 401 proves proxy transport. |
| **`GET /health`** | Lightweight HTTP endpoint (`http://127.0.0.1:8787/health`). 200=ok, 503=degraded/down. Never launches Claude Code. |
| **watchdog** (auto) | launchd job (every 20s): passive checks and tunnel ping without launching Claude Code. On drop — **macOS notification** + sound; recovery is quiet. |
| **PF isolation** | fail-closed: proxy down → traffic to nowhere, not direct. See below. |

## Codex via SOCKS5 (CLI and App)

Codex (CLI and App) is unstable through privoxy (8118, HTTP-CONNECT) — it corrupts WebSocket
streaming → `Reconnecting 1..5/5` → `request timed out` in interactive mode. Codex supports SOCKS5
natively, so `srouter install` routes it **straight to xray (10808)**, bypassing privoxy (Claude Code
stays on privoxy — it can't do SOCKS5):

- **`~/bin/codex`** — CLI wrapper: sets `HTTP_PROXY/HTTPS_PROXY=socks5h://127.0.0.1:10808` before
  calling the real codex (`socks5h` = DNS resolved by the proxy, matters behind GFW).
- **`~/bin/codex-app-proxy`** — App wrapper: `open -na Codex.app --args --proxy-server=socks5://...`
  (Chromium flag; no env duplication). **Launch Codex.app via this, not the Dock icon** (Dock doesn't
  pass `--proxy-server`).
- **LaunchAgent `com.srouter.codenv`** — global env (`socks5h://...` + `NO_PROXY=localhost,127.0.0.1,::1`) via a
  plist with `EnvironmentVariables` (survives reboot). Empirically: Claude.app/ChatGPT.app use System
  Settings SOCKS, so the global env doesn't break them.
- **`~/bin` in `~/.zshrc`** — so the wrapper precedes the system codex in PATH.

All installed/removed by `srouter install`/`uninstall` (marker-gate: a foreign wrapper/plugin is left
untouched). Verify: `which codex` → `~/bin/codex`; `codex doctor` → `proxy env vars: HTTP_PROXY, HTTPS_PROXY`.

> Why not `[network] proxy_url` in `~/.codex/config.toml`? It is a valid key, but it controls the
> execution-scoped sandbox proxy for spawned `codex` subprocesses — not the HTTP client to
> `chatgpt.com`. For that client, only env works (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`).
> Why not a separate WS-proxy env? `WS_PROXY`/`WSS_PROXY` are also ignored (verified in 0.142.5).
> The `openai-http` profile with `supports_websockets=false` 401s on a ChatGPT subscription. So —
> SOCKS5 directly, the one working path.

> **Wrapper limitation (AO worktree):** `~/bin/codex` + the zsh function only work inside interactive
> zsh. In an AO worktree, claude-code (Go) resolves `codex` via Go `exec.LookPath`, which ignores zsh
> functions and picks `/opt/homebrew/bin/codex` (PATH position 5) past `~/bin/codex` (position 7).
> Without the wrapper, the privoxy env is still set → it cuts WS. A `~/.local/bin/codex` symlink does
> **not** help (position 24). The fix belongs on the AO side (`ALL_PROXY=socks5h://127.0.0.1:10808` +
> drop privoxy from the worker env), **not** srouter.

## Rollback

```bash
srouter uninstall      # full rollback to defaults:
#   stops brew services, restores foreign configs from backups, resets DNS
#   (networksetup ... Empty), removes the LaunchAgent, watchdog, ppp-hook,
#   split-route to the VPS, Claude Code/git proxy, Codex SOCKS5-wrappers + env + PATH.
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
- `dig @8.8.8.8 <domain>` (A) and `dig @8.8.8.8 <domain> AAAA` — resolve the domain's IPs in **both
  families** (IPv4 and IPv6). Without v6 isolation is useless: apps prefer IPv6 when AAAA exists, and
  traffic escapes via v6 past a v4-only block ("eyes": domain → IPv4 + IPv6).
- `pfctl -a com.apple/srouter_isolate -t srouter_proxy_ips -T replace <ips>` — put both families into
  the firewall table ("hands": PF guard in the kernel + a list of numbers). The PF table accepts IPv4
  and IPv6 together. Anything to these IPs via en0/ppp0 on ports 80/443 dies. Via the proxy (xray→VPS)
  it works: xray talks to the VPS IP, not the Claude IP.

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
| **Codex** | env only for the Codex↔`chatgpt.com` client: `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` (e.g. `socks5h://127.0.0.1:10808` via wrappers + LaunchAgent). `[network] proxy_url` in `~/.codex/config.toml` does NOT drive that client — it configures the execution-scoped sandbox proxy for spawned `codex` subprocesses. |
| **git / gh** | GitHub domains whitelisted on the node |
| **Browser** | system SOCKS5 `127.0.0.1:10808` |

---

*srouter — adaptive routing & throttle bypass. Fast, resilient, self‑optimizing access.*
