# Дизайн: PF-изоляция codex под user-UID (investigation-first)

**Дата:** 2026-07-23
**Связано:** эпик #166, sub-issue #167 (этот док), блокирует #168 (реализация).
**Тип:** design/investigation-документ. **Без этого дизайна — не кодить #168.**
**Канон:** `verify-dont-guess` (первоисточник — `man pf.conf` на macOS, не аналогия), `tun-no-direct-path-ever`, `fail-closed-proxy-down`, `privileged-boundary-fail-closed`, `best-effort-layer-cycle-review-never-converges`.

---

## 0. TL;DR — выбранная схема

**Вердикт: схема B — выделенный системный UID `_srouter_codex` (503) + `block ... user` whitelist.**

codex запускается под отдельным системным пользователем (как privoxy под `nobody`). PF-правило в существующем anchor `com.apple/srouter_isolate` разрешает этому UID **только** loopback SOCKS5 (127.0.0.1:10808) + служебные, всё остальное — `block drop quick`. Это единственный замкнутый инвариант: codex **физически** не может уйти напрямую, независимо от имени binary, способа запуска, Go-`exec.LookPath` (#144) или foreign-wrapper (#150/#153).

**Почему не «user match на твоём UID»** (схема A) — см. §3: codex = uid 501 → правило `block ... user axisrow` убивает ВЕСЬ сетевой трафик пользователя. **user-match на user-UID фундаментально неприменим** — это и есть корень design-вопроса (1) issue.

**Почему не transparent-rdr** (схема C) — §4: macOS pf `rdr` работает на входящем на интерфейс трафике; локально-инициированный loopback codex→chatgpt.com rdr не перехватывает чисто (нужна сложная `route-to`+`rdr-on lo0` связка, ломается `set skip on lo0`). rdr — избыточен: codex **уже** умеет SOCKS5 нативно, задача PF — **запретить прямой путь**, а не подменять проксирование.

**Готовность к #168:** ✅ схема зафиксирована, threat model закрыта, файлы/таблицы/интеграция в `isolate_firewall.py` определены (§6). Реализация может стартовать.

---

## 1. Постановка проблемы

Эпик #166: codex-wrapper порочен (коллизия неймспейса «два `codex` в PATH»). Три итерации adversarial cycle-review (#141/#146/#153) не сошлись на wrapper-слое — у него нет замкнутого инварианта (`best-effort-layer-cycle-review-never-converges`). Решение — сменить слой: **PF kill-switch** = настоящая fail-closed граница (как для proxy-доменов в `isolate_firewall.py`).

**Фундаментальная трудность (issue #167 design-вопрос 1):** в отличие от privoxy (который бежит под `nobody`, uid -2, и PF может матчить его чисто), **codex запускается под user-UID (uid 501 `axisrow`)**. Наивное PF-правило «блокировать codex» = «блокировать uid 501» = **заблокировать весь сетевой трафик пользователя** (браузер, git, Claude Code, ssh — всё). Нужно различать «codex-трафик» от «остального трафика того же UID».

## 2. Что подтверждено из первоисточника (verify, не аналогия)

> `man pf.conf` на macOS (Darwin 25.5), секция PACKET FILTERING → параметры:

1. **`user ⟨user⟩` match существует и поддерживается** на macOS pf.
   > «This rule only applies to packets of sockets owned by the specified user.»
2. **Работает ТОЛЬКО для TCP и UDP** (для остальных протоколов параметры игнорируются). codex ходит по TCP — подходит.
3. **UID = effective ID, фиксируется при создании сокета.** setuid/setgid-процесс сохраняет root-credentials даже после drop-privileges. → Это базис схемы B: если codex-процесс дропает привилегии до `_srouter_codex`, **все его сокеты** помечены этим UID, и PF-`user` их матчит надёжно.
4. **Forwarded-соединения → `user`/`group` = `unknown`** (firewall не endpoint). Ключевое слово `unknown` работает только с `=`/`!=`. → Это **ограничивает** схему C (rdr): после перенаправления upstream-пакеты перестают быть привязаны к UID.
5. **`group ⟨group⟩`** — аналогично, по сокету группы.
6. **`set skip on ⟨ifspec⟩`** — пакеты на перечисленных интерфейсах **вообще не фильтруются**. man приводит пример `set skip on lo0`. → Критично: если main ruleset уже `set skip on lo0`, то loopback (codex → xray на 127.0.0.1:10808) **не доходит до нашего anchor** на интерфейсе lo0. Это **полезно** (прокси-трафик не режется) и **не мешает** схеме B — блок идёт на `en*`/`ppp*` (прямой выход), не на lo0 (см. §5 совместимость).
7. **Anchor** (`com.apple/srouter_isolate`) — контейнер правил/таблиц; main ruleset НЕ трогаем. Существующая инфраструктура в `isolate_firewall.py` уже это использует.

**Эмпирические факты машины:**
- Текущий пользователь: `uid=501(axisrow) gid=20(staff)`, член `admin`.
- Системный `nobody`: `UniqueID=-2` (privoxy бежит здесь).
- `/etc/pf.conf` (main) — пуст/минимален; anchor-инфраструктура srouter самодостаточна.

## 3. Варианты идентификации codex-трафика (design-вопрос 1) — с вердиктом

### Схема A — `user` match на **текущем** user-UID ❌ ОТВЕРГНУТА
```
# ПЛОХО: codex == uid 501 == весь пользователь
block drop out quick on { en0 ... } proto tcp user axisrow
```
**Проблема:** блокирует браузер, git, Claude Code, ssh — весь трафик uid 501. Не различает codex от остального. **Фундаментально неприменимо**, это и есть корень проблемы.

### Схема B — выделенный системный UID `_srouter_codex` ✅ ПРИНЯТА
codex запускается под отдельным системным пользователем (uid 503 `_srouter_codex`, не-админ, не-логин-оболочка). PF whitelist:
```
# в anchor com.apple/srouter_isolate
table <srouter_codex_loopback> persist { 127.0.0.1, ::1 }
pass out quick on lo0 proto tcp user _srouter_codex to <srouter_codex_loopback> port 10808 keep state
block drop out quick on { en0 en1 ... ppp0 ppp1 } proto tcp user _srouter_codex
# (служебные через туннель — pass к route_ip узла; см. §6)
```
**Почему работает:** все сокеты codex-процесса помечены uid 503 (man §2.3). Только codex под этим UID. Остальной трафик пользователя (uid 501) правилами не трогается.

**Trade-off / цена:** меняется способ запуска codex. Запуск через `sudo -u _srouter_codex` или LaunchDaemon от этого пользователя. Нужен provisioning UID (создание системного юзера install-тайм, как делает brew для своих сервисов). **Codex.app (GUI)** — отдельный вопрос: Cocoa-приложение под не-логин-UID запускать проблематично (sandbox, keychain, файловый доступ в `~/Library/Application Support/Codex`). См. §7 риск R3 — **схема B покрывает codex CLI; Codex.app требует дополнения**.

### Схема C — transparent `rdr` (PF redirect в SOCKS5) ❌ ОТВЕРГНУТА как primary
Идея: не блокировать, а **перенаправлять** весь codex-трафик на 127.0.0.1:10808 через `rdr`.
```
rdr on en0 proto tcp user _srouter_codex to any -> 127.0.0.1 port 10808
```
**Проблемы (verify из man):**
1. `rdr` применяется к трафику, **входящему на интерфейс**. Локально-инициированный codex→chatgpt.com сначала попадает в **output**-обработку (по маршруту), а не input — rdr-on-en0 его не видит так же, как входящий снаружи.
2. Чтобы rdr сработал для локального-origin, нужна связка `route-to lo0` + `rdr on lo0` — но `set skip on lo0` (man §2.6) исключает lo0 из фильтрации → rdr на lo0 молча игнорируется. Снимать `set skip on lo0` ломает приватность остальных loopback-сервисов (MCP, healthcheck).
3. **После rdr upstream-пакеты = `unknown` user** (forwarded, man §2.4) — теряется привязка к codex-UID → нельзя дальше различать.
4. SOCKS5 после transparent-rdr: xray получает «голый» TCP без SOCKS-хендшейка → нужен redsocks/прокси-антиципатор. **Большая новая зависимость** на 24/7-инфре (`srouter-critical-infra-24-7`).

**Вердикт C:** rdr избыточен. codex **уже умеет SOCKS5 нативно** (wrapper выставляет `socks5h://`, см. `srouter-codex-cli-wrapper.sh`). Задача PF — **запретить прямой путь** (как делает `isolate_firewall.py` для proxy-доменов), а не подменять проксирование. **Block, не redirect.**

### Схема D — `authpf` ❌ НЕ ПРИМЕНИМА на macOS
`authpf` — FreeBSD-демон (ssh-триггер для динамических anchor-правил). На macOS **не входит в поставку pf** (нет `/usr/sbin/authpf`). Исключена без эмпирической проверки платформы.

### Схема E — `route-to` + per-process routing table ❌ ОТЛОЖЕНА (overkill)
Per-process alternate routing table через `route-to`. Работает, но требует, чтобы codex-процесс помечался/маршрутизировался отдельно — те же затраты, что схема B, но без чистого `user` match. Нет преимуществ над B.

---

## 4. Threat model (issue #167 §3)

**In-scope:** codex (CLI и App) делает сетевые запросы к `chatgpt.com` / `api.openai.com` (endpoint `wss://chatgpt.com/backend-api/`, см. канон `codex-routes-via-chatgpt-com-rebranding`).

| Канал | Должен ли | Как обеспечивается (схема B) |
|-------|-----------|------------------------------|
| codex → SOCKS5 127.0.0.1:10808 (→ xray → VPS) | ✅ РАЗРЕШЁН | `pass out on lo0 user _srouter_codex to <loopback> port 10808` |
| codex → служебные (xray route_ip узла, DNS) | ✅ РАЗРЕШЁН (через туннель/loopback) | xray сам ходит на route_ip — codex до него не доходит (он говорит только с loopback xray) |
| codex → chatgpt.com/api.openai.com НАПРЯМУЮ | ❌ БЛОКИРОВАТЬ (утечка IP за GFW) | `block drop quick user _srouter_codex on { en*, ppp* }` |
| codex → локальный DNS (53) напрямую | ❌ БЛОКИРОВАТЬ (DNS-утечка) | `socks5h://` уже резолвит на прокси; PF `block user _srouter_codex` на en* покрывает и это |

**До редизайна:** codex может уйти напрямую (рекурсия wrapper #150, Go-`exec.LookPath`-worktree #144, foreign-wrapper) → утечка IP. Best-effort.
**После (схема B):** PF физически блокирует прямой выход → **fail-closed** (`fail-closed-proxy-down`): если SOCKS5 упал, codex **не уходит напрямую** — пакеты дропаются, запрос падает, не утекает.

**Out-of-scope (явно):** вредоносный код *внутри* сессии codex под `_srouter_codex` может слать пакеты на loopback MCP-сервисы пользователя. Это **изолирует codex от утечки наружу**, но не наоборот. Приемлемо: угроза = утечка IP за GFW, а не латеральное движение (codex = tool, не untrusted workload).

---

## 5. Совместимость с общим TUN/PF-изоляцией (design-вопрос 2)

Канон `tun-no-direct-path-ever`: TUN/PF-изоляция обязательна; HTTPS_PROXY/xray-rules без неё не дают гарантии невытекания.

**Существующая изоляция** (`isolate_firewall.py`): блокирует **destination** = IP proxy-доменов (`<srouter_proxy_ips>`, `<srouter_cloudfront_subnets>`) на en*/ppp*. Это **доменная** изоляция для Claude Code/общего трафика.

**Новая codex-изоляция (схема B):** блокирует **по source-UID** = `_srouter_codex` на en*/ppp*. Это **процессная** изоляция.

**Два слоя НЕ конфликтуют, они ортогональны и складываются (defense-in-depth):**
- Доменная изоляция: «никто не ходит напрямую к api.anthropic.com».
- codex-изоляция: «codex не ходит напрямую НИКУДЕ, кроме loopback SOCKS5».
- Оба в одном anchor `com.apple/srouter_isolate`, оба на тех же интерфейсах `en*/ppp*`, оба **fail-closed** (block по умолчанию).
- **TUN/utun не трогаем** (как и существующая изоляция — `DIRECT_IFACES = en*, ppp*`, utun исключён, это туннель xray).
- `set skip on lo0` (если есть в main) **помогает**: codex→xray на loopback проходит без фильтрации, а блок стоит на en* — прямого пути нет.

**Invariant (замкнутый):** codex (uid 503) может отправить TCP-пакет наружу (en*) ТОЛЬКО если он не заблокирован. Блок покрывает **весь** прямой выход. → Любой способ обхода wrapper'а (rename PATH, Go-LookPath, foreign-wrapper, env-reset) **нерелевантен**: пакет всё равно дропнется на en*. Это и есть замкнутый инвариант, которого не было у wrapper-слоя.

## 6. Интеграция в `isolate_firewall.py` (для #168)

Существующий модуль (`isolate_firewall.py`) расширяется, **не переписывается** (`no-hidden-magic-follow-canon`, эталон `sys_probe` #35):

**Новые константы:**
```python
CODEX_USER = "_srouter_codex"          # системный UID (provisioning install-тайм)
CODEX_SOCKS_TABLE = "srouter_codex_loopback"  # { 127.0.0.1, ::1 }
SOCKS5_PORT = "10808"                  # из dashboard_common.XRAY_SOCKS_PORT (issue #155 — единый источник)
```

**Новый ruleset-генератор** (по образцу `_strict_ruleset`/`_working_ruleset`):
```python
def _codex_ruleset():
    return (
        f"table <{CODEX_SOCKS_TABLE}> persist {{ 127.0.0.1 ::1 }}\n"
        f"pass out quick on lo0 proto tcp user {CODEX_USER} "
        f"to <{CODEX_SOCKS_TABLE}> port {SOCKS5_PORT} keep state\n"
        f"block drop out quick on {_ifaces_spec()} proto tcp user {CODEX_USER}\n"
    )
```

**Новый публичный API** (по образцу `enable_isolation`/`disable_isolation`, тот же osascript admin-мост, тот же `pfctl -E/-X` token):
- `enable_codex_isolation(token=None)` — загрузить codex-ruleset в anchor.
- `disable_codex_isolation(token=None)` — flush codex-правил из anchor.
- `probe_codex_isolation(state_path=None)` — status-only (как `probe_isolation`).

**CLI** (`main`) — новые subcommands: `enable-codex`, `disable-codex`, `status-codex`.

**Provisioning UID** (отдельный шаг в `srouter.py install`): создание системного пользователя `_srouter_codex` (uid 503) через `dscl`/`sysadminctl`, не-логин. **Это новая поверхность** — вынести в отдельную функцию, протестировать идемпотентность (создан → повторно не падает, удалён при uninstall).

**Активация:** `srouter install` применяет codex-PF + создаёт UID; codex-wrapper (`#169` rename → `codex-srouter`) запускает real codex через `sudo -u _srouter_codex`. **Координация с #169**: rename и схема B независимы по слоям, но install-флоу связан — фиксировать порядок в реализации.

## 7. Риски и митигации

| # | Риск | Severity | Митигация |
|---|------|----------|-----------|
| **R1** | Codex.app (GUI, Cocoa) под `_srouter_codex` ломается (keychain, sandbox, `~/Library/Application Support/Codex`) | **High** | Схема B изначально покрывает **codex CLI**. Codex.app — **отдельный sub-scope**: либо остаётся на wrapper+env (best-effort), либо исследуется run-as в реализации #168. Зафиксировать в #168 как known-limitation, не блокировать CLI-изоляцию. |
| **R2** | Provisioning системного UID — привилегированная поверхность (dscl/sysadminctl), может сломать аккаунт-БД macOS | Medium | Идемпотентное создание (dscl -read → create if missing); фиксированный UID 503 (не из динамического диапазона); uninstall удаляет чисто; эвакуационная инструкция (см. R5). |
| **R3** | codex под другим UID теряет доступ к `~/.codex/` (config, sessions, auth) | Medium | `chown -R _srouter_codex` на `~/.codex/` install-тайм ИЛИ общий каталог; исследовать реально ли codex пишет в HOME в #168. |
| **R4** | Поломка сети при падении srouter | Medium | `com.apple/srouter_isolate-escape` LaunchDaemon уже снимает strict при сбое (паттерн `isolate-recovery-instructions`). Codex-PF наследует тот же escape-hatch. README: команда вернуть интернет (§8). |
| **R5** | Блок остаётся после uninstall → «нет интернета у codex» | Medium | `uninstall` обязан `disable_codex_isolation` + удалить UID. Эвакуация: `pfctl -a "com.apple/srouter_isolate" -F all` (одна команда, README). |
| **R6** | UDP-трафик codex (если есть) не покрыт (user-match работает для TCP+UDP, но правила пишем proto tcp) | Low | codex = чистый TCP/WS. Если появится UDP — добавить `proto { tcp udp }`. |
| **R7** | «Предсуществующая tech-debt» вне scope (как PR #162 → #165, канон `codex-scope-claim-vs-pr-regression`) | Low | #168 = только codex-изоляция; найденные смежные дыры → отдельный issue, не в scope. |

## 8. Готовность к #168 (sub-2, реализация)

✅ **Схема зафиксирована:** B (выделенный UID + whitelist `user` match).
✅ **Threat model закрыт:** codex только loopback SOCKS5 + служебные, прямой = block (fail-closed).
✅ **Совместимость с TUN-PF:** ортогональные слои, складываются, не конфликтуют (§5).
✅ **Файлы определены:** `isolate_firewall.py` (ruleset + API + CLI), `srouter.py` (UID-provisioning + активация), `tests/test_isolate_firewall.py` (эмпирические PF-тесты).
✅ **Канон соблюдён:** verify из `man pf.conf` (§2), fail-closed, замкнутый инвариант.
✅ **TDD-подход:** эмпирический тест — codex под `_srouter_codex` не доходит напрямую (curl chatgpt.com падает), через SOCKS5 — работает (`verify-dont-guess`, runtime-proof).

**Блокеры для старта #168 — НЕТ.** Рекомендация: начать с CLI-изоляции (schema B ядро), Codex.app (R1) вынести как known-limitation + follow-up.

## 9. Open questions для реализации #168 (не блокируют дизайн)

1. **Codex.app run-as:** реально ли запустить Cocoa-app под не-логин UID без потери keychain? (R1) — эмпирически в #168.
2. **HOME для `_srouter_codex`:** общий `~/.codex/` или отдельный? (R3) — проверить, куда codex пишет auth.
3. **UID выбор:** 503 — убедиться, что не занят (`dscl . -read /Users/_srouter_codex`), fallback на следующий свободный.
4. **`set skip on lo0` в main:** проверить, есть ли он на целевой машине (`pfctl -s rules`); если нет — `pass out on lo0` в anchor всё равно работает.

---

## Ссылки
- Эпик #166 (родитель), #168 (реализация, blocked-by этот док), #169 (rename wrapper), #170 (doctor), #171 (docs).
- `isolate_firewall.py` — существующая PF-инфра (anchor `com.apple/srouter_isolate`, таблицы strict/working, `pfctl -E/-X`).
- Канон-память: `tun-no-direct-path-ever`, `fail-closed-proxy-down`, `privileged-boundary-fail-closed`, `best-effort-layer-cycle-review-never-converges`, `verify-dont-guess`, `codex-routes-via-chatgpt-com-rebranding`, `srouter-critical-infra-24-7`, `issue-155-proxy-constants-single-source`.
