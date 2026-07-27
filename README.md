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
#   • изолирует Codex тремя живыми путями + будущей fail-closed границей: SOCKS5-wrappers
#     (~/bin/codex-srouter + codex-app-proxy, zsh-функция — CLI/Chromium-оболочка App),
#     LaunchAgent com.srouter.codenv (#189/#190 — gui-SOCKS5 env для Rust app-server ChatGPT.app;
#     setenv не ретроактивен — запущенный до install ChatGPT.app требует полного перезапуска Cmd+Q),
#     scoped VSCode http.proxy (#185 — расширение openai.chatgpt; только если install обновил
#     существующий settings.json редактора) — все три минуют privoxy, направляя Codex напрямую в xray;
#     + PF kill-switch в ядре (#168) как будущая fail-closed граница (режет прямой TCP-выход codex на
#     en0–en6/ppp0–ppp1, разрешая loopback SOCKS5 по TCP); install создаёт пользователя uid 503 (#186),
#     но правила пока дормантны — активируются после полной активации (запуск codex под uid 503
#     НЕЗАВИСИМО от wrapper'а (не sudo -u в wrapper, а напр. launchd-служба) + доменная изоляция + TCP
#     на en/ppp, отдельный follow-up);
#   • показывает план и спрашивает подтверждение.
srouter status         # проверить, что демон работает (http://127.0.0.1:8787)
srouter doctor         # диагностика: порты + туннель + Claude-proxy (✅/❌)
srouter sync           # импорт endpoint из рабочего xray в local.json (рассинхрон placeholder, #200)

# Управление демоном дашборда (стек не трогается):
srouter start          # запустить демон (если LaunchAgent уже установлен)
srouter stop           # остановить демон (plist сохранён)
srouter restart        # перезапустить демон (применить правки кода)

# Радикальная защита Privoxy от команд пользовательских агентов (#122):
srouter privoxy protect --strict  # разовый перенос в system-domain; потребует пароль
srouter privoxy status            # read-only, без пароля
srouter privoxy restart           # каждый раз требует пароль/Touch ID
srouter privoxy unprotect         # защищённый откат к прежней user-службе

# Observability privoxy-лога (#152): по умолчанию защищённый Privoxy МОЛЧАЛИВ (privacy — на диск
# ничего не пишется), logfile пустой. Чтобы поймать флап/таймауты к github через 8118, включи
# логирование connections (приватно: без URL/body) при ПЕРВИЧНОЙ защите:
SROUTER_PRIVOXY_DEBUG=2 srouter privoxy protect --strict   # debug 2 = connections в config
# Уровни (privoxy user-manual, битовые): 2=connections (рекомендуется),
# 1=URLs (⚠ чувствительно: токены/query пишутся на диск — только осознанно).
# 8 (header parsing) и 32768 (raw) НЕ доступны через env — они пишут заголовки/тело на диск.
# СМЕНА уровня на УЖЕ защищённом privoxy: protect --strict видит службу здоровой и не трогает
# config. Чтобы изменить debug, сначала откатись: `srouter privoxy unprotect`, затем protect
# с новым SROUTER_PRIVOXY_DEBUG (транзакционный реконфиг без unprotect — follow-up issue).
# `srouter doctor` покажет: debug включён? logfile пуст при включённом → WARN.

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
| **runtime model-override** | Claude Code не проверяет подлинность модели — только совместимость API. Через штатный `ANTHROPIC_BASE_URL` (+ `ANTHROPIC_DEFAULT_*_MODEL`) сторонний сервер **молча подменяет модель**, и клиент не может это доказать. `srouter doctor` читает env **живого** CC-процесса (`ps eww`, тот же UID) и WARN'ует на нестандартный endpoint, `ANTHROPIC_DEFAULT_*_MODEL`-подмену слотов и **stale-process** — когда настройки уже сброшены на стандартные, а запущенный CC всё ещё держит override (#143). Единственный сигнал подмены — поле `message.model` в ответе; клиентское имя модели в статус-баре его не отражает. |
| **`GET /health`** | Лёгкий HTTP-эндпоинт (`http://127.0.0.1:8787/health`). 200=ok, 503=degraded/down. Не запускает Claude Code. |
| **watchdog** (авто) | launchd-задача (раз в 20с): пассивные проверки и пинг туннеля, без запуска Claude Code. При падении — **macOS-нотификация** + звук. При восстановлении — тихое уведомление. |
| **PF-изоляция** | fail-closed: прокси упал → трафик в никуда, не напрямую. См. ниже. |

## Изоляция Codex: PF kill-switch + SOCKS5-wrappers

Codex (CLI и App) нестабилен через privoxy (8118, HTTP-CONNECT) — тот портит WebSocket-стриминг →
`Reconnecting 1..5/5` → `request timed out` в интерактиве. Codex умеет SOCKS5 нативно, поэтому Codex
надо пускать **напрямую в xray (10808)**, минуя privoxy (Claude Code остаётся на privoxy — он SOCKS5
не умеет). Реализовано **двумя слоями** — настоящая граница и best-effort переход:

**1. PF kill-switch — будущая fail-closed граница (основной механизм, #168).** Правила в ядре PF режут
**прямой TCP-выход codex, запущенного под системным UID 503**, на физических интерфейсах `en0`–`en6`,
`ppp0`–`ppp1` и разрешают TCP на loopback SOCKS5 `127.0.0.1:10808` (→ xray → VPS); UDP и неучтённые
интерфейсы правилом не покрываются. Это более сильная граница, чем wrappers, **но не абсолютная** (см.
ниже). ⚠️ **Сейчас это dormant foundation, НЕ активная защита.** Install уже создаёт пользователя
`_srouter_codex` uid 503 (#186), но для реальной блокировки нужно ещё: (а) запуск codex под этим UID
(`sudo -u _srouter_codex` в wrapper — отдельный follow-up, пока codex бежит под 501 и PF-правило его
**не видит**: правило матчит только `user 503`), (б) включённая доменная PF-изоляция (без её родительской
директивы `anchor "codex"` sub-anchor не вычисляется), (в) трафик по TCP через `en0`–`en6`/`ppp0`–`ppp1`
(`utun`-туннели намеренно исключены — блок убил бы прокси; высшие `en*`/`ppp*` и UDP не покрыты).

**Важно про обход wrapper'а:** PF защищает **только процесс под UID 503**. Пока назначение этого UID
идёт через сам wrapper (`sudo -u`, follow-up), обход wrapper'а (прямой binary, Go `exec.LookPath` в AO
worktree, чужой wrapper) оставляет codex под 501 — **вне PF**. Так что утверждение «обход wrapper'а
нерелевантен» станет верным **только** когда codex принудительно запускается под 503 независимо от
wrapper (например, launchd-служба, а не wrapper-команда). Значит **прямо сейчас** единственная живая
защита от прямого выхода — wrappers + codenv + scoped VSCode env (слой 2). Полные детали — в разделе «🔒 PF codex-изоляция».

**2. SOCKS5-wrappers — defense-in-depth / best-effort переход.** Прокладки, которые выставляют
codex'у env на SOCKS5, чтобы трафик шёл правильным путём *до того*, как PF его всё равно защитит.
Wrappers **не являются границей изоляции** — у них нет замкнутого инварианта (обходятся PATH/чужим
binary/exec.LookPath), поэтому границей служит именно PF. Wrappers остаются как переходный слой и
оптимизация (направляют трафик по нужному каналу без необходимости полагаться на блок):

- **`~/bin/codex-srouter`** — wrapper CLI: выставляет `HTTP_PROXY/HTTPS_PROXY=socks5h://127.0.0.1:10808`
  перед вызовом реального codex (`socks5h` = DNS резолвится прокси, важно за GFW). Имя `codex-srouter`
  (не `codex`) убирает коллизию неймспейса wrapper↔real-binary (issue #169). В интерактивном zsh
  shell-функция `codex()` зовёт его по абсолютному пути — привычный `codex …` сохранён.
- **`~/bin/codex-app-proxy`** — wrapper App: `open -na Codex.app --args --proxy-server=socks5://...`
  (Chromium flag; env не дублирует). **Codex.app запускать через него, а не иконку Dock**
  (Dock не передаёт `--proxy-server`).
- **LaunchAgent `com.srouter.codenv` (восстановлен, #189/#190)** — глобальный env
  (`socks5h://127.0.0.1:10808` + `NO_PROXY=localhost,127.0.0.1,::1`) в launchd gui-домен: агент
  (RunAtLoad + StartInterval=300, переживает ребут) запускает скрипт `srouter-codex-env.sh`, который
  делает `launchctl setenv` (сам по себе setenv ребут не переживает — поэтому периодический Refresh).
  Нужен для **Rust app-server ChatGPT.app/Codex.app** (основной WS к `wss://chatgpt.com`): он не уважает
  ни системный SOCKS (только Chromium-оболочка), ни `[network] proxy_url` (мёртв в codex 0.146) — только
  env SOCKS5. **Claude Code не конфликтует** (#130 снят): CC CLI читает прокси из
  `~/.claude/settings.json`, а не из launchd gui-env. ⚠️ **setenv не ретроактивен**: если ChatGPT.app уже
  запущен на момент install, его Rust app-server останется с прямыми сокетами (stale) — полностью
  перезапустите ChatGPT.app (Cmd+Q из Dock, не «закрыть окно»); `srouter doctor` детектит stale-App.
  ⚠️ Побочный эффект: gui-SOCKS5 ломает **Claude Desktop App** (#127, не CC CLI) — `srouter doctor`
  покажет; митигация отдельной историей.
- **VSCode `http.proxy` (scoped, #185)** — `socks5h://127.0.0.1:10808` в настройке VSCode/Cursor.
  **Комплементарен codenv**: расширение `openai.chatgpt` в Code/Cursor — отдельный клиент от ChatGPT.app;
  строит `HTTP_PROXY`/`HTTPS_PROXY` **в env порождаемого codex-процесса**, не трогая Claude Code.
  ⚠️ Install правит **только существующий** `settings.json` редактора и **не создаёт** его сам — если
  VSCode/Cursor отсутствуют на момент install, этот guard не активен (`srouter doctor` покажет);
  повторите `srouter install` после установки редактора.
- **`~/bin` в `~/.zshrc`** — чтобы wrapper был раньше системного codex в PATH.

Всё ставит/убирает `srouter install`/`uninstall` (marker-gate: чужой wrapper/плагин не трогает).
Проверка wrappers: `which codex` → `/opt/homebrew/bin/codex` (real binary); `which codex-srouter` →
`~/bin/codex-srouter`; `codex doctor` → `proxy env vars: HTTP_PROXY, HTTPS_PROXY`.
Состояние PF-codex (записанное состояние установки, **не** живая проверка границы — `status-codex`
читает lease, не зовёт `pfctl` и не проверяет, что codex реально бежит под uid 503):
`python3 isolate_firewall.py status-codex` (см. секцию PF ниже).

> Почему не `[network] proxy_url` в `~/.codex/config.toml`? Ключ валидный, но управляет
> execution-scoped sandbox-прокси для субпроцессов codex, а не HTTP-клиентом к `chatgpt.com`. Для
> клиента работает только env (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`).
> Почему не отдельный WS-proxy env? `WS_PROXY`/`WSS_PROXY` тоже игнорируются (проверено в 0.142.5).
> Профиль `openai-http` с `supports_websockets=false` даёт 401 с ChatGPT-подпиской. Поэтому — SOCKS5
> напрямую, единый рабочий путь. **Гарантию блокировки прямого TCP-выхода codex на en0–en6/ppp0–ppp1
> даст PF kill-switch — но только когда codex запущен под uid 503 независимо от wrapper'а (не командой
> wrapper'а `sudo -u`, а, например, launchd-службой), плюс доменная изоляция и TCP на en/ppp; пользователь
> uid 503 уже создаётся install, #186.** env/wrapper обходятся PATH; PF сильнее — но лишь для процесса
> под 503. Пока эта активация не завершена (follow-up — независимый запуск под 503),
> единственная живая защита от прямого выхода — wrappers + codenv + scoped VSCode env (слой 2).

> **Обход wrappers и статус изоляции.** Ранее wrapper был единственным слоем, и его обходы были
> дырами: в AO worktree claude-code (Go) резолвит codex через Go `exec.LookPath`, который
> игнорирует zsh-функции и берёт `/opt/homebrew/bin/codex` (real binary), а wrapper не зовётся.
> PF закроет такой обход **только если** codex запущен под uid 503 **независимо от wrapper'а**
> (например, launchd-службой, а не командой wrapper'а): тогда обход wrapper'а не меняет UID и PF
> дропнет TCP на en0–en6/ppp0–ppp1. Но пока назначение uid 503 — через тот же wrapper (`sudo -u`,
> follow-up), обход wrapper'а оставляет codex под 501 = вне PF. То есть обход wrapper'а = дыра и
> **до**, и **после** текущего follow-up, пока запуск под 503 не стал независимым от wrapper.
> Фикс на стороне AO — `ALL_PROXY=socks5h://127.0.0.1:10808` в env воркера. Для AO-воркеров всё же лучше
> держать `ALL_PROXY`, чтобы трафик шёл по нужному каналу сразу.

## Интеграции

| Инструмент | Подключение |
|---|---|
| **Claude Code** | `HTTPS_PROXY=http://127.0.0.1:8118` в `~/.claude/settings.json` (privoxy HTTP; SOCKS5 CC не умеет) |
| **Codex CLI/App** | **напрямую SOCKS5 в xray** (`socks5h://127.0.0.1:10808`) тремя живыми путями, минуя privoxy: wrappers (CLI + `--proxy-server` для Chromium-оболочки App), LaunchAgent `com.srouter.codenv` (gui-SOCKS5 env для Rust app-server ChatGPT.app, #189/#190; setenv не ретроактивен — запущенный до install ChatGPT.app перезапустите Cmd+Q), scoped VSCode `http.proxy` (расширение `openai.chatgpt`, #185; только если install обновил существующий settings.json); + **PF kill-switch в ядре** (#168) как будущая fail-closed граница (режет прямой TCP-выход codex на en0–en6/ppp0–ppp1, разрешая loopback SOCKS5 по TCP; пока дормантен — пользователь uid 503 уже создаётся install (#186), активируется после полной активации: запуск codex под uid 503 **независимо от wrapper'а** (не sudo -u в wrapper) + доменная изоляция + TCP на en/ppp, отдельный follow-up). privoxy портит WS-стриминг Codex (`Reconnecting`/`request timed out`); `[network] proxy_url` в `~/.codex/config.toml` мёртв в codex 0.146 (управляет execution-scoped sandbox-прокси для субпроцессов, не клиентом) — поэтому wrappers в `~/bin/codex-srouter` (CLI, имя `codex-srouter` убирает коллизию wrapper↔real-binary #169) + `~/bin/codex-app-proxy` (App Chromium) + `com.srouter.codenv` (Rust app-server) + scoped VSCode `http.proxy` (расширение). Запускать Codex **App** через `~/bin/codex-app-proxy`, а не иконку Dock (Dock не передаёт `--proxy-server`). См. раздел «Изоляция Codex». |
| **git / gh** | scoped git-прокси `http.https://github.com.proxy → privoxy 8118` (`git_proxy.py`); gh работает **напрямую** через Go-стек (GFW не режет) → для VPS-независимости: `gh` через `env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy` (оба регистра), `git` через `git -c http.https://github.com.proxy=` (env -u НЕ трогает git-config) — см. раздел «gh / git: прямой доступ» |
| **Браузер** | системный SOCKS5 `127.0.0.1:10808` (вайтлист разруливает сам) |

## Откат

```bash
srouter uninstall      # полный откат к дефолту:
#   останавливает brew-сервисы, восстанавливает чужие конфиги из бэкапов,
#   сбрасывает DNS (networksetup ... Empty), удаляет LaunchAgent, watchdog, ppp-hook,
#   split-route до VPS, Claude Code/git-прокси, Codex SOCKS5-wrappers + env + PATH.
```

## gh / git: прямой доступ, не через прокси (#199)

`gh` и `git` к github.com **запускайте с прямым доступом** — это **VPS-независимый** dev-workflow:
github-операции переживают смерть VPS (24/7 resilience). Но `gh` и `git` — **разные стеки прокси**,
им нужны **разные команды** (verify 2026-07-27).

**Эмпирический диагноз (verify, 2026-07-27):** github TCP напрямую открыт (`nc github.com 443`
= OPEN — GFW не режет TCP-слой). Разница стеков решает исход:

| Путь | Результат | Причина |
|---|---|---|
| `gh api user` напрямую (снят env-прокси) | ✅ работает (3/3) | **gh (Go)** — свой HTTP/TLS-стек + resolver, обходит GFW TLS-блокировку |
| `curl https://api.github.com` напрямую | ❌ timeout (5/5) | LibreSSL + системный resolver → GFW-заблокированный IP, TLS режется |
| `gh`/`git` через прокси (`HTTP_PROXY=8118` → VPS) | ❌ timeout когда VPS мёртв | зависит от VPS; выглядело как «флап gh» |

То, что казалось флапом `gh` = смешанные сценарии: то через прокси (наследуется из env caller'а),
то напрямую — в зависимости от `HTTP_PROXY` в окружении.

**Два источника прокси → две команды.** srouter ставит прокси в **двух** местах, и `env -u`
снимает только один из них:

| Стек | Источник прокси | Что снимает | Команда прямого доступа |
|---|---|---|---|
| **gh (Go)** | env (`HTTP_PROXY`/`http_proxy`, оба регистра — Go `httpproxy` fallback) | `env -u` (оба регистра!) | `env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY -u http_proxy -u https_proxy -u all_proxy -u no_proxy gh ...` |
| **git over https** | git-config `http.https://github.com.proxy` (scoped, `git_proxy.py`) | `git -c` (env -u **НЕ** трогает git-config) | `git -c http.https://github.com.proxy= fetch\|pull\|push` |

```bash
# gh — снять env-прокси ОБА регистра (Go fallback на lowercase http_proxy/https_proxy):
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY \
    -u http_proxy -u https_proxy -u all_proxy -u no_proxy gh pr merge 123
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY \
    -u http_proxy -u https_proxy -u all_proxy -u no_proxy gh issue create ...

# git over https — env -u НЕ трогает scoped git-config, нужен git -c (пустое значение перекрывает):
git -c http.https://github.com.proxy= fetch
git -c http.https://github.com.proxy= pull

# clone: gh repo clone ДЕЛЕГИРУЕТ внутреннему git → scoped git-config применяется к clone.
# VPS-независимый clone — через git -c (или gh api, или ssh:22):
git -c http.https://github.com.proxy= clone https://github.com/axisrow/srouter.git
git clone git@github.com:axisrow/srouter.git   # ssh:22 открыт напрямую (nc github.com 22 = OPEN)
```

**Связь с srouter:** `srouter install` ставит scoped git-прокси `http.https://github.com.proxy →
privoxy 8118` (`git_proxy.py`) — он направляет `git` к github через ускоритель. Это полезно, когда
ускоритель жив, но делает `git` **VPS-зависимым**: `env -u` его **не** снимает (это git-config, не
env), нужен `git -c http.https://github.com.proxy=`. `gh` снимается `env -u` (оба регистра env).
`srouter doctor` показывает этот чек (`gh/git direct`) с подсказкой обеих команд, когда git-proxy
включён — info-only, не роняет вердикт.

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
sudo pfctl -a "com.apple/srouter_isolate" -F all          # снять доменную изоляцию
sudo pfctl -a "com.apple/srouter_isolate/codex" -F all    # снять codex-изоляцию (sub-anchor)
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

### 🔒 PF codex-изоляция (kill-switch)

codex — отдельная fail-closed граница в том же PF-ядре, но в **sub-anchor**
`com.apple/srouter_isolate/codex` (живёт под доменной изоляцией выше — вычисляется только при её
активной родительской директиве, см. ограничения ниже). После активации правила режут **прямой
TCP-выход codex, запущенного под системным UID 503**, на физических интерфейсах `en0`–`en6`,
`ppp0`–`ppp1` и разрешают TCP на loopback SOCKS5 `127.0.0.1:10808` (→ xray → VPS); UDP и неучтённые
интерфейсы правилом не покрываются. PF матчит **только** трафик `user 503` — обход wrapper'а (rename
PATH, прямой binary, чужой wrapper), оставляющий codex под 501, **не покрывается**, пока запуск под 503
не станет независимым от wrapper (см. known-limitations).

**Статус:** install **автоматически создаёт** системного пользователя `_srouter_codex` (uid 503,
не-логин: `UserShell=/usr/bin/false`, `NFSHomeDirectory=/var/empty`, dedicated gid 503) и грузит
ruleset в sub-anchor (матч по `user 503`). Это **инфраструктура**, но не активная защита — см.
known-limitations ниже (пока ни одно условие не выполнено, ни один codex-процесс не защищён).
Doctor показывает состояние через чек `codex-isolation (PF kill-switch)`.

**Known-limitations (почему пока standby, не полная kill-switch):**

1. **Codex ещё бежит под пользовательским UID (501), не под 503** — PF-правила загружены, но
   простаивают (матчат только трафик UID 503, которого пока ни один процесс не генерирует). Интеграция
   `sudo -u _srouter_codex` в wrapper — отдельный follow-up.
2. **Codex.app (GUI/Cocoa)** не покрывается (изоляция под не-логин UID проблематична для Cocoa-app,
   дизайн #167 §7 R1) — только codex CLI.
3. **Включённая доменная PF-изоляция выше.** Sub-anchor вычисляется только при наличии родительской
   директивы `anchor "codex"`, которая живёт в strict/working-ruleset доменной изоляции. macOS
   wildcard-anchors не спускаются рекурсивно — без доменной изоляции sub-anchor **не вычисляется
   вовсе**, даже если ruleset загружен (см. комментарий в `isolate_firewall.py`).
4. **Трафик по TCP через `en0`–`en6`/`ppp0`–`ppp1`.** Это **не замкнутый инвариант на все интерфейсы**:
   `utun`-туннели намеренно исключены (блок убил бы сам прокси), а высшие `en*`/`ppp*` и **любой UDP**
   правилом не покрыты. Реальная площадь блокировки — TCP-выход на перечисленных физических
   интерфейсах.

Пока эти ограничения не закрыты — единственная живая защита от прямого выхода codex остаётся
SOCKS5-wrappers + codenv + scoped VSCode env (слой 2 выше). Снять вручную: `sudo pfctl -a "com.apple/srouter_isolate/codex" -F all`
(правила PF) и/или `sudo dscl . -delete /Users/_srouter_codex` (системный пользователь, если uninstall
не удалил).


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
#   • isolates Codex via three live paths plus a future fail-closed boundary: SOCKS5 wrappers
#     (~/bin/codex-srouter + codex-app-proxy, zsh function — CLI / App Chromium shell), the
#     com.srouter.codenv LaunchAgent (#189/#190 — gui-SOCKS5 env for ChatGPT.app's Rust app-server;
#     setenv is non-retroactive — a ChatGPT.app already running before install needs a full Cmd+Q
#     restart), and scoped VSCode http.proxy (#185 — the openai.chatgpt extension; only if install
#     updated an existing editor settings.json) — all three bypass privoxy, routing Codex straight to
#     xray; + a PF kill-switch in the kernel (#168) as the future fail-closed boundary (cuts codex
#     direct TCP egress on en0–en6/ppp0–ppp1, allowing TCP to loopback SOCKS5); install creates the
#     uid 503 user (#186), but the rules stay dormant — they activate after full activation (launching
#     codex under uid 503 INDEPENDENTLY of the wrapper, not via wrapper sudo -u — e.g. a launchd
#     service; + domain isolation + TCP on en/ppp, a separate follow-up);
#   • prints a plan and asks for confirmation.
srouter status         # check the daemon is up (http://127.0.0.1:8787)
srouter doctor         # diagnostics: ports + tunnel + Claude-proxy (✅/❌)
srouter sync           # import endpoint from the live xray into local.json (placeholder drift, #200)

# Dashboard daemon control (the stack is untouched):
srouter start          # start the daemon (if the LaunchAgent is already installed)
srouter stop           # stop the daemon (the plist is kept)
srouter restart        # restart the daemon (apply code changes)

# Protect Privoxy from unprivileged agent lifecycle commands (#122):
srouter privoxy protect --strict  # one-time system-domain migration; asks for authorization
srouter privoxy status            # read-only, no password
srouter privoxy restart           # requires password/Touch ID every time
srouter privoxy unprotect         # privileged rollback to the previous user service

# Privoxy log observability (#152): by default protected Privoxy is SILENT (privacy — nothing is
# written to disk), logfile is empty. To catch flap/timeouts to github over 8118, enable connection
# logging (private: no URL/body) at FIRST protection:
SROUTER_PRIVOXY_DEBUG=2 srouter privoxy protect --strict   # debug 2 = connections in config
# Levels (privoxy user-manual, bitmask): 2=connections (recommended),
# 1=URLs (⚠ sensitive: tokens/query are written to disk — opt-in only).
# 8 (header parsing) and 32768 (raw) are NOT exposed via env — they write headers/body to disk.
# CHANGING the level on an ALREADY protected privoxy: protect --strict sees a healthy service and
# leaves the config untouched. To change debug, roll back first: `srouter privoxy unprotect`, then
# protect with a new SROUTER_PRIVOXY_DEBUG (transactional reconfigure without unprotect is a follow-up).
# `srouter doctor` shows: is debug on? empty logfile while on → WARN.

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
| **runtime model-override** | Claude Code never verifies model authenticity — only API compatibility. Via the standard `ANTHROPIC_BASE_URL` (+ `ANTHROPIC_DEFAULT_*_MODEL`) a third-party server **silently substitutes the model**, and the client cannot prove it. `srouter doctor` reads the env of the **live** CC process (`ps eww`, same UID) and warns on a non-standard endpoint, `ANTHROPIC_DEFAULT_*_MODEL` slot substitution, and **stale-process** — when settings have been reset to standard but the running CC still holds the override (#143). The only signal of substitution is the `message.model` field in the response; the status-bar client model name does not reflect it. |
| **`GET /health`** | Lightweight HTTP endpoint (`http://127.0.0.1:8787/health`). 200=ok, 503=degraded/down. Never launches Claude Code. |
| **watchdog** (auto) | launchd job (every 20s): passive checks and tunnel ping without launching Claude Code. On drop — **macOS notification** + sound; recovery is quiet. |
| **PF isolation** | fail-closed: proxy down → traffic to nowhere, not direct. See below. |

## Codex isolation: PF kill-switch + SOCKS5 wrappers

Codex (CLI and App) is unstable through privoxy (8118, HTTP-CONNECT) — it corrupts WebSocket
streaming → `Reconnecting 1..5/5` → `request timed out` in interactive mode. Codex supports SOCKS5
natively, so Codex must go **straight to xray (10808)**, bypassing privoxy (Claude Code stays on
privoxy — it can't do SOCKS5). This is implemented in **two layers** — a real boundary and a
best-effort transition:

**1. PF kill-switch — the future fail-closed boundary (primary mechanism, #168).** Kernel PF rules cut
**direct TCP egress of codex running under system UID 503** on the physical interfaces `en0`–`en6`,
`ppp0`–`ppp1` and allow TCP to loopback SOCKS5 `127.0.0.1:10808` (→ xray → VPS); UDP and unlisted
interfaces are not covered. This is a stronger boundary than wrappers, **but not absolute** (see below).
⚠️ **Right now this is a dormant foundation, NOT an active guard.** Install already creates the user
`_srouter_codex` uid 503 (#186), but real blocking still needs: (a) launching codex under that UID
(`sudo -u _srouter_codex` in the wrapper — a separate follow-up; codex still runs under 501 so the PF
rule does **not** see it — the rule matches only `user 503`), (b) domain PF isolation enabled (without
its parent directive `anchor "codex"` the sub-anchor is never evaluated), (c) traffic over TCP on
`en0`–`en6`/`ppp0`–`ppp1` (`utun` tunnels are intentionally excluded — a block would kill the proxy;
higher `en*`/`ppp*` and UDP are not covered).

**Important about wrapper bypass:** PF protects **only a process running under UID 503**. While that
UID is assigned by the wrapper itself (`sudo -u`, follow-up), a wrapper bypass (direct binary, Go
`exec.LookPath` in an AO worktree, foreign wrapper) leaves codex under 501 — **outside PF**. So the
claim "a wrapper bypass is irrelevant" becomes true **only** once codex is launched under 503
independently of the wrapper (e.g. a launchd service, not a wrapper command). So **today** the single
live guard against direct egress is the wrappers + codenv + scoped VSCode env (layer 2). Full details in the "🔒 PF codex
isolation" section below.

**2. SOCKS5 wrappers — defense-in-depth / best-effort transition.** Shims that set Codex's env to
SOCKS5 so traffic takes the correct path *before* PF guards it anyway. Wrappers **are not the
isolation boundary** — they have no closed invariant (bypassed via PATH / foreign binary /
exec.LookPath), which is why PF is the real boundary. Wrappers remain as a transition layer and an
optimization (they route traffic through the right channel without relying on the block):

- **`~/bin/codex-srouter`** — CLI wrapper: sets `HTTP_PROXY/HTTPS_PROXY=socks5h://127.0.0.1:10808` before
  calling the real codex (`socks5h` = DNS resolved by the proxy, matters behind GFW). The name
  `codex-srouter` (not `codex`) removes the wrapper↔real-binary namespace collision (issue #169). In
  interactive zsh a shell function `codex()` calls it by absolute path — the familiar `codex …` stays.
- **`~/bin/codex-app-proxy`** — App wrapper: `open -na Codex.app --args --proxy-server=socks5://...`
  (Chromium flag; no env duplication). **Launch Codex.app via this, not the Dock icon** (Dock doesn't
  pass `--proxy-server`).
- **LaunchAgent `com.srouter.codenv` (restored, #189/#190)** — global env
  (`socks5h://127.0.0.1:10808` + `NO_PROXY=localhost,127.0.0.1,::1`) into the launchd gui-domain: the
  agent (RunAtLoad + StartInterval=300, survives reboot) runs `srouter-codex-env.sh`, which calls
  `launchctl setenv` (setenv alone does not survive reboot — hence the periodic refresh). Required for
  the **Rust app-server of ChatGPT.app/Codex.app** (the main WS to `wss://chatgpt.com`): it honors
  neither system SOCKS (only the Chromium shell does) nor `[network] proxy_url` (dead in codex 0.146) —
  only env SOCKS5. **Claude Code does not conflict** (#130 resolved): the CC CLI reads its proxy from
  `~/.claude/settings.json`, not launchd gui-env. ⚠️ **setenv is not retroactive**: if ChatGPT.app is
  already running at install time, its Rust app-server keeps its direct sockets (stale) — fully restart
  ChatGPT.app (Cmd+Q from the Dock, not "close window"); `srouter doctor` detects a stale App. ⚠️ Side
  effect: gui-SOCKS5 breaks the **Claude Desktop App** (#127, not the CC CLI) — `srouter doctor` will
  show it; mitigation is a separate story.
- **VSCode `http.proxy` (scoped, #185)** — `socks5h://127.0.0.1:10808` in the VSCode/Cursor setting.
  **Complementary to codenv**: the `openai.chatgpt` extension in Code/Cursor is a separate client from
  ChatGPT.app; it builds `HTTP_PROXY`/`HTTPS_PROXY` **in the env of the spawned codex process**, leaving
  Claude Code untouched. ⚠️ Install only edits an **existing** editor `settings.json` and **does not
  create** one itself — if VSCode/Cursor is absent at install time, this guard is not active
  (`srouter doctor` will show this); re-run `srouter install` after installing the editor.
- **`~/bin` in `~/.zshrc`** — so the wrapper precedes the system codex in PATH.

All installed/removed by `srouter install`/`uninstall` (marker-gate: a foreign wrapper/plugin is left
untouched). Verify wrappers: `which codex` → `/opt/homebrew/bin/codex` (real binary);
`which codex-srouter` → `~/bin/codex-srouter`; `codex doctor` → `proxy env vars: HTTP_PROXY, HTTPS_PROXY`.
PF-codex state (the recorded install state, **not** a live boundary check — `status-codex` reads the
lease, does not call `pfctl`, and does not verify codex actually runs under uid 503):
`python3 isolate_firewall.py status-codex` (see the PF section below).

> Why not `[network] proxy_url` in `~/.codex/config.toml`? It is a valid key, but it controls the
> execution-scoped sandbox proxy for spawned `codex` subprocesses — not the HTTP client to
> `chatgpt.com`. For that client, only env works (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`).
> Why not a separate WS-proxy env? `WS_PROXY`/`WSS_PROXY` are also ignored (verified in 0.142.5).
> The `openai-http` profile with `supports_websockets=false` 401s on a ChatGPT subscription. So —
> SOCKS5 directly, the one working path. **The guarantee of blocking codex direct TCP egress on
> en0–en6/ppp0–ppp1 will come from the PF kill-switch — but only once codex is launched under uid 503
> independently of the wrapper (not via the wrapper's own `sudo -u` — e.g. a launchd service), plus
> domain isolation and TCP on en/ppp; the uid 503 user is already created by install, #186.** env/wrappers
> are bypassable via PATH; PF is stronger — but only for a process under 503. Until that activation lands
> (follow-up — independent launch under 503), the only live guard against direct egress is the
> wrappers + codenv + scoped VSCode env (layer 2).

> **Wrapper bypass and the isolation status.** Previously the wrapper was the only layer, so its
> bypasses were holes: in an AO worktree, claude-code (Go) resolves `codex` via Go `exec.LookPath`,
> which ignores zsh functions and picks `/opt/homebrew/bin/codex` (the real binary), so the wrapper is
> never called. PF closes such a bypass **only if** codex is running under uid 503 **independently of
> the wrapper** (e.g. a launchd service, not a wrapper command): then bypassing the wrapper doesn't
> change the UID and PF drops the TCP on en0–en6/ppp0–ppp1. But while the uid 503 assignment goes
> through the same wrapper (`sudo -u`, follow-up), a wrapper bypass leaves codex under 501 = outside PF.
> So a wrapper bypass is a hole **both before and after** the current follow-up, until launching under
> 503 becomes wrapper-independent. The fix is on the AO side — `ALL_PROXY=socks5h://127.0.0.1:10808` in
> the worker env. AO workers should still
> the fix is on the AO side (`ALL_PROXY=socks5h://127.0.0.1:10808` in the worker env). AO workers
> should still keep `ALL_PROXY` so traffic takes the right channel immediately.

## Rollback

```bash
srouter uninstall      # full rollback to defaults:
#   stops brew services, restores foreign configs from backups, resets DNS
#   (networksetup ... Empty), removes the LaunchAgent, watchdog, ppp-hook,
#   split-route to the VPS, Claude Code/git proxy, Codex SOCKS5-wrappers + env + PATH.
```

## gh / git: direct access, not via proxy (#199)

Run `gh` and `git` against github.com **with direct access** — this is a **VPS-independent**
dev-workflow: github operations survive a dead VPS (24/7 resilience). But `gh` and `git` are
**different proxy stacks** and need **different commands** (verify 2026-07-27).

**Empirical diagnosis (verify, 2026-07-27):** github TCP is directly reachable (`nc github.com 443`
= OPEN — the GFW does not cut the TCP layer). The stack decides the outcome:

| Path | Result | Reason |
|---|---|---|
| `gh api user` direct (env proxy unset) | ✅ works (3/3) | **gh (Go)** — its own HTTP/TLS stack + resolver, bypasses GFW TLS blocking |
| `curl https://api.github.com` direct | ❌ timeout (5/5) | LibreSSL + system resolver → GFW-blocked IP, TLS cut |
| `gh`/`git` via proxy (`HTTP_PROXY=8118` → VPS) | ❌ timeout when VPS is dead | depends on VPS; looked like "gh flapping" |

What looked like `gh` flapping = mixed scenarios: sometimes via proxy (inherited from the caller's
env), sometimes direct — depending on `HTTP_PROXY` in the environment.

**Two proxy sources → two commands.** srouter installs the proxy in **two** places, and `env -u`
clears only one of them:

| Stack | Proxy source | What clears it | Direct-access command |
|---|---|---|---|
| **gh (Go)** | env (`HTTP_PROXY`/`http_proxy`, both cases — Go `httpproxy` fallback) | `env -u` (both cases!) | `env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY -u http_proxy -u https_proxy -u all_proxy -u no_proxy gh ...` |
| **git over https** | git-config `http.https://github.com.proxy` (scoped, `git_proxy.py`) | `git -c` (env -u does **NOT** touch git-config) | `git -c http.https://github.com.proxy= fetch\|pull\|push` |

```bash
# gh — unset env proxy BOTH cases (Go falls back to lowercase http_proxy/https_proxy):
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY \
    -u http_proxy -u https_proxy -u all_proxy -u no_proxy gh pr merge 123
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY \
    -u http_proxy -u https_proxy -u all_proxy -u no_proxy gh issue create ...

# git over https — env -u does NOT touch scoped git-config, use git -c (empty value overrides):
git -c http.https://github.com.proxy= fetch
git -c http.https://github.com.proxy= pull

# clone: gh repo clone DELEGATES to the internal git → scoped git-config applies to the clone.
# VPS-independent clone — via git -c (or gh api, or ssh:22):
git -c http.https://github.com.proxy= clone https://github.com/axisrow/srouter.git
git clone git@github.com:axisrow/srouter.git   # ssh:22 is open directly (nc github.com 22 = OPEN)
```

**Relation to srouter:** `srouter install` sets a scoped git proxy `http.https://github.com.proxy →
privoxy 8118` (`git_proxy.py`) — it routes `git` to github through the accelerator. That's useful
when the accelerator is alive, but it makes `git` **VPS-dependent**: `env -u` does **not** clear it
(it's git-config, not env) — use `git -c http.https://github.com.proxy=`. `gh` is cleared with
`env -u` (both env cases). `srouter doctor` surfaces this check (`gh/git direct`) with both commands
as a hint when the git proxy is enabled — info-only, it does not lower the verdict.

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
sudo pfctl -a "com.apple/srouter_isolate" -F all        # remove domain isolation rules
sudo pfctl -a "com.apple/srouter_isolate/codex" -F all  # remove codex isolation (sub-anchor)
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

### 🔒 PF codex isolation (kill-switch)

codex is a separate fail-closed boundary in the same PF kernel, but in a **sub-anchor**
`com.apple/srouter_isolate/codex` (it lives under the domain isolation above — it is only evaluated
when the latter's parent directive is active, see the limitations below). Once active, the rules cut
**direct TCP egress of codex running under system UID 503** on the physical interfaces `en0`–`en6`,
`ppp0`–`ppp1` and allow TCP to loopback SOCKS5 `127.0.0.1:10808` (→ xray → VPS); UDP and unlisted
interfaces are not covered. PF matches **only** `user 503` traffic — a wrapper bypass (PATH rename,
direct binary, foreign wrapper) that leaves codex under 501 is **not covered**, until launching under
503 becomes independent of the wrapper (see known-limitations).

**Status:** install **automatically creates** the system user `_srouter_codex` (uid 503, non-login:
`UserShell=/usr/bin/false`, `NFSHomeDirectory=/var/empty`, dedicated gid 503) and loads the ruleset
into the sub-anchor (matching by `user 503`). This is **infrastructure**, not an active guard — see
the known-limitations below (until any condition is met, no codex process is protected). Doctor
surfaces the state via the `codex-isolation (PF kill-switch)` check.

**Known-limitations (why standby today, not a full kill-switch):**

1. **Codex still runs under your user UID (501), not 503** — the PF rules are loaded but idle (they
   match only uid 503 traffic, which no process currently generates). Wiring
   `sudo -u _srouter_codex` into the wrapper is a separate follow-up.
2. **Codex.app (GUI/Cocoa)** is not covered (isolation under a non-login UID is problematic for a
   Cocoa app, design #167 §7 R1) — codex CLI only.
3. **Domain PF isolation (above) enabled.** The sub-anchor is only evaluated when the parent directive
   `anchor "codex"` is present, which lives in the strict/working ruleset of domain isolation. macOS
   wildcard anchors do not descend recursively — without domain isolation the sub-anchor is **never
   evaluated at all**, even if its ruleset is loaded (see the comment in `isolate_firewall.py`).
4. **Traffic over TCP on `en0`–`en6`/`ppp0`–`ppp1`.** This is **not a closed invariant across all
   interfaces**: `utun` tunnels are intentionally excluded (a block would kill the proxy itself), and
   higher-numbered `en*`/`ppp*` plus **any UDP** are not covered. The real block surface is the TCP
   egress on the listed physical interfaces.

Until these limitations are closed, the only live guard against direct codex egress stays the
SOCKS5 wrappers + codenv + scoped VSCode env (layer 2 above). Remove manually: `sudo pfctl -a "com.apple/srouter_isolate/codex" -F all`
(PF rules) and/or `sudo dscl . -delete /Users/_srouter_codex` (system user, if uninstall did not
remove it).


## Integrations

| Tool | Wiring |
|---|---|
| **Claude Code** | `HTTPS_PROXY=http://127.0.0.1:8118` in `~/.claude/settings.json` |
| **Codex** | **straight to xray** (`socks5h://127.0.0.1:10808`) via three live paths that bypass privoxy: wrappers (CLI + `--proxy-server` for the App Chromium shell), the `com.srouter.codenv` LaunchAgent (gui-SOCKS5 env for ChatGPT.app's Rust app-server, #189/#190; setenv is non-retroactive — restart an already-running ChatGPT.app with Cmd+Q), and scoped VSCode `http.proxy` (the `openai.chatgpt` extension, #185; only if install updated an existing settings.json); + **a PF kill-switch in the kernel** (#168) as the future fail-closed boundary (cuts codex direct TCP egress on en0–en6/ppp0–ppp1, allowing TCP to loopback SOCKS5; dormant today — the uid 503 user is already created by install (#186), and activation requires full activation: launching codex under uid 503 **independently of the wrapper** (not via wrapper sudo -u) + domain isolation + TCP on en/ppp, a separate follow-up). `[network] proxy_url` in `~/.codex/config.toml` is dead in codex 0.146 (it configures the execution-scoped sandbox proxy for spawned `codex` subprocesses, not the client) — hence wrappers + codenv + VSCode http.proxy. See the "Codex isolation" section. |
| **git / gh** | scoped git proxy `http.https://github.com.proxy → privoxy 8118` (`git_proxy.py`); gh works **direct** via its Go stack (GFW does not cut it) → for VPS-independence: `gh` with `env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy` (both cases), `git` with `git -c http.https://github.com.proxy=` (env -u does NOT touch git-config) — see "gh / git: direct access" |
| **Browser** | system SOCKS5 `127.0.0.1:10808` |

---

*srouter — adaptive routing & throttle bypass. Fast, resilient, self‑optimizing access.*
