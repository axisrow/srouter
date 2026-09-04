"""Explicit repair/restore для системного macOS SOCKS-прокси активного network service.

Зачем этот модуль отдельно от `system_proxy.py`. `system_proxy.py` — намеренно READ-ONLY
(канон: смена системного прокси меняет поведение ВСЕЙ ОС для всех приложений сразу, выходит
за границу «дашборд управляет своим стеком»). Живая регрессия показала, что этой границы
недостаточно: у Wi-Fi адрес был сохранён верно (`127.0.0.1:10808`), но канал SOCKS был
выключен — Chromium network-service процесс ChatGPT.app (обычный запуск из Dock, БЕЗ
`--proxy-server`) уходил напрямую, пока Rust app-server уже работал через launchd-env
(codenv). doctor не мог это ни увидеть, ни починить — единственным «фиксом» оставался ручной
`~/bin/codex-app-proxy`, что и было неверным контрактом (issue-обсуждение зафиксировало: normal
Dock-launch обязан снова работать сам по себе).

Этот модуль — explicit, отдельно вызываемая операция (`srouter system-proxy repair|restore`),
НЕ скрытая часть install/start/watchdog. Она:
  - определяет активный network service по default route (`route -n get default` → interface →
    `networksetup -listnetworkserviceorder` → сервис для этого device);
  - читает текущий SOCKS endpoint этого сервиса (`networksetup -getsocksfirewallproxy`);
  - если endpoint уже наш (127.0.0.1:10808) — просто включает канал (state=on), если выключен;
  - если endpoint чужой и ВЫКЛЮЧЕН — бэкапит его в srouter.local.json (runtime.system_proxy),
    затем выставляет наш endpoint и включает;
  - если endpoint чужой и УЖЕ ВКЛЮЧЁН (или authenticated) — отказывает без мутации: это чей-то
    реальный прокси, перезаписывать нельзя (канон privileged-boundary-fail-closed).
  - `restore()` возвращает сохранённый endpoint, но ТОЛЬКО если текущее состояние совпадает с
    тем, что мы применили (никакого внешнего дрейфа) — иначе отказ (conflict), без мутации.

============================== lease-машина (issue #316) ==============================

State: `runtime.system_proxy.leases` — словарь per-service (находка 3): один слот не переживал
Wi-Fi↔Ethernet и перезаписывал чужой backup при повторном repair. Формат записи:

    {"phase": "repairing"|"active"|"restoring", "service": <name>, "previous": {socks}}

Фазы — двухшаговая запись (write-preflight, находка 1): durable-состояние пишется ДО мутаций,
которые оно описывает; подтверждение — после. SIGKILL/ENOSPC в любой точке оставляет на диске
промежуточную фазу с previous, а не «система изменена, backup нигде»:

  repairing  — previous сохранён, networksetup-мутации repair в процессе или оборвались crash'ем.
               Reconcile при следующем запуске: наш endpoint+enabled → подтверждаем active;
               наш endpoint+disabled → repair оборвался посередине (не leak: канал выключен);
               чужой endpoint → мутации не применились, stale-lease сбрасывается.
  active     — repair подтверждён: наш endpoint стоит и включён, restore имеет право разворачивать.
  restoring  — restore в процессе (фаза пишется ДО его мутаций по тому же preflight-принципу).
               Reconcile: наш endpoint → дочитываем с начала; endpoint уже previous → дочитываем
               остаток; endpoint previous + state уже как previous → restore фактически завершён
               (crash перед расчисткой) — чистим lease без мутаций; иначе — внешний drift во
               время restore, отказ с сохранением lease.

Порядок мутаций restore — off-first (находка 2, вариант 2): state off → endpoint → финальный
state по previous.enabled. Выключенный канал с ЛЮБЫМ endpoint не может направить трафик ОС на
чужой прокси (канон fail-closed-proxy-down: лучше сломать, чем утечь). Фаза restoring при этом
закрывает и «залипание в conflict» (вариант 3): crash после записи endpoint оставлял
previous+disabled с вечным «conflict: изменилось извне» при retry — теперь это распознаваемая
resume-ветка, а не тупик.

Вариант 3 находки 2 взят в этот же PR (а не follow-up), т.к. machinery фаз и так нужна находке 1
(repairing + reconcile) — отдельная полумашину для restore писать дороже, чем доиспользовать ту
же; залипание доказуемо: crash между endpoint-записью и финальным state оставляет
previous+enabled=False навсегда с диагностированием «внешний drift».

Миграция формата (обратная совместимость, прецедент #326): legacy `{"active": {...}}` с дисков
уже установленных машин нормализуется в leases при первом чтении и переписывается при первой
записи. Старые версии кода, читающие новый формат, видят отсутствие `active` → безопасное
«нет сохранённого состояния», без crash.

============================== межпроцессная блокировка (находка 4) ==============================

repair()/restore() — транзакция read(state)→несколько networksetup→write(state); атомарность
одиночного rename в save_state не сериализует ПОСЛЕДОВАТЕЛЬНОСТЬ. Вся транзакция берёт
эксклюзивный flock (LOCK_NB-poll с bounded-ожиданием) на `<state>.system_proxy.lock` рядом с
state-файлом — паттерн git_proxy._mutation_lock / local_state._routing_config_lock / watchdog
лок (#326), не новый примитив. Таймаут по умолчанию 120 с (networksetup-команды по 20 с ×
несколько штук; интерактивный admin-диалог может держать дольше), override
SROUTER_SYSTEM_PROXY_LOCK_TIMEOUT_SEC (0 = ждать вечно, как blocking-flock в git_proxy). Занято
→ явный busy-отказ с нулём мутаций; лок недоступен физически → fail-closed отказ (мутация без
сериализации = сам баг находки 4, канон: явный отказ лучше тихой потери данных). Лок — ЛИСТ в
графе локов (#159): внутри транзакции не берётся ни один threading.Lock (только subprocess +
json I/O), вложенности нет, DAG не нарушается.
"""
import contextlib
import fcntl
import logging
import os
import time

import local_state
import sys_probe
from install_lib import NETWORKSETUP, ROUTE

try:
    from dashboard_common import XRAY_SOCKS_ADDR as _XRAY_SOCKS_ADDR  # noqa: F401 (canonical-fallback-port)
except SystemExit:  # без srouter_config.py (install-путь) — тот же fallback, что в других модулях
    _XRAY_SOCKS_ADDR = ("127.0.0.1", 10808)  # canonical-fallback-port

_log = logging.getLogger("srouter.system_proxy_control")

# Канонический endpoint — единый источник dashboard_common.XRAY_SOCKS_ADDR (issue #155).
TARGET_SERVER, TARGET_PORT = _XRAY_SOCKS_ADDR

# --- фазы lease (см. докстринг модуля) ---
_PHASE_REPAIRING = "repairing"
_PHASE_ACTIVE = "active"
_PHASE_RESTORING = "restoring"

# --- межпроцессный lock (находка 4) ---
_LOCK_SUFFIX = ".system_proxy.lock"
_LOCK_POLL_SEC = 0.05
_LOCK_TIMEOUT_DEFAULT_SEC = 120.0


def _run(cmd, timeout, runner):
    return runner(cmd, timeout)


def _mutate(cmd, runner, *, timeout=20):
    """Выполнить привилегированную networksetup-мутацию. (result, err) — err=None при успехе.

    Единая точка rc/timeout-проверки для repair()/restore() (мутирующие вызовы используют
    один и тот же fail-closed паттерн — timeout ИЛИ rc не в {0, None} = сбой).
    """
    r = _run(cmd, timeout, runner)
    if r.get("timeout") or r.get("rc") not in (0, None):
        return None, r.get("err", "")
    return r, None


def _default_interface(runner):
    """Интерфейс default route. Не переиспользует health_probes._route_default_interface —
    та жёстко привязана к sys_probe.run (без инъекции runner), а этот модуль тестируется
    fake-runner'ом; кроме того health_probes/health_codenv образуют цикл импортов с этим модулем
    (health_codenv импортирует system_proxy_control на уровне модуля). Тот же формат `route -n
    get default` → строка 'interface:' (см. health_probes.py канон), парсинг сознательно локальный.
    """
    r = _run([ROUTE, "-n", "get", "default"], 3, runner)
    if r.get("timeout") or r.get("rc") not in (0, None):
        return ""
    for line in (r.get("out") or "").splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            return line.split(":", 1)[1].strip()
    return ""


def _service_for_interface(iface, runner):
    """Имя network service (`networksetup` label) для устройства iface, или ''.

    `networksetup -listnetworkserviceorder` печатает пары строк:
        (1) Wi-Fi
        (Hardware Port: Wi-Fi, Device: en0)
    Первая непустая непронумерованная строка выше — имя сервиса.
    """
    r = _run([NETWORKSETUP, "-listnetworkserviceorder"], 4, runner)
    if r.get("timeout") or r.get("rc") not in (0, None):
        return ""
    pending_name = ""
    for raw in (r.get("out") or "").splitlines():
        line = raw.strip()
        if line.startswith("(") and "Hardware Port" not in line and ")" in line:
            # "(1) Wi-Fi" -> "Wi-Fi"
            pending_name = line.split(")", 1)[1].strip()
            continue
        if line.startswith("(Hardware Port"):
            # codex-review (PR #314): "Device: {iface}" as substring матчил "en1" внутри "en10" —
            # точное имя устройства кончается либо на ')' (последний в строке), либо на ', ' (перед
            # следующим полем, напр. "Ethernet Address: ..."). Парсим значение целиком и сравниваем
            # точным равенством, не подстрокой.
            marker = "Device: "
            idx = line.find(marker)
            if idx != -1:
                rest = line[idx + len(marker):]
                device = rest.split(")", 1)[0].split(",", 1)[0].strip()
                if device == iface:
                    return pending_name
    return ""


def _read_socks(service, runner):
    r = _run([NETWORKSETUP, "-getsocksfirewallproxy", service], 4, runner)
    if r.get("timeout") or r.get("rc") not in (0, None):
        return None
    fields = {}
    for line in (r.get("out") or "").splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    return {
        "enabled": fields.get("Enabled", "No").strip().lower() == "yes",
        "server": fields.get("Server", ""),
        "port": int(fields["Port"]) if fields.get("Port", "").isdigit() else None,
        "authenticated": fields.get("Authenticated Proxy Enabled", "0").strip() == "1",
    }


def status(*, runner=sys_probe.run):
    """Текущее состояние системного SOCKS активного network service. Не бросает.

    {status: ok|unknown, interface, service, socks: {...}, target: bool}
    target=True когда endpoint уже наш (127.0.0.1:10808) И канал включён.
    """
    iface = _default_interface(runner)
    if not iface:
        return {"status": "unknown", "interface": "", "service": "", "socks": None, "target": False,
                "detail": "нет активного default route — network service не определён"}
    service = _service_for_interface(iface, runner)
    if not service:
        return {"status": "unknown", "interface": iface, "service": "", "socks": None, "target": False,
                "detail": f"не найден network service для интерфейса {iface}"}
    socks = _read_socks(service, runner)
    if socks is None:
        return {"status": "unknown", "interface": iface, "service": service, "socks": None,
                "target": False, "detail": f"networksetup -getsocksfirewallproxy {service} не отвечает"}
    is_target = bool(socks["enabled"] and socks["server"] == TARGET_SERVER
                      and socks["port"] == TARGET_PORT)
    return {"status": "ok", "interface": iface, "service": service, "socks": socks, "target": is_target}


# ============================== lease-хранилище (issue #316) ==============================


def _lease_key():
    return "system_proxy"


def _normalize_leases(sp):
    """runtime.system_proxy-секция → leases-словарь. Миграция legacy {active: ...} на чтении
    (прецедент миграции state #326): старые установки хранят единственный слот `active`;
    переезжает в leases[service] с фазой active. Чего-то иного (битая секция) → {} — lease
    невалиден, восстановление честно говорит «нет сохранённого состояния»."""
    if not isinstance(sp, dict):
        return {}
    raw = sp.get("leases")
    if isinstance(raw, dict):
        return {svc: dict(lease) for svc, lease in raw.items() if isinstance(lease, dict)}
    legacy = sp.get("active")
    if isinstance(legacy, dict) and legacy.get("service"):
        return {legacy["service"]: {"phase": _PHASE_ACTIVE, "service": legacy["service"],
                                    "previous": dict(legacy.get("previous") or {})}}
    return {}


def _load_leases(path):
    state = local_state.load_state(path)
    return _normalize_leases((state.get("runtime") or {}).get(_lease_key()))


def _save_leases(path, leases):
    """Записать leases в state. False = state не читаем/не пишем — вызывающий обязан отреагировать
    (issue #316 находка 1: молчаливое проглатывание сбоя записи делало backup фиктивным)."""
    state, readable = local_state.load_state_checked(path)
    if not readable:
        return False
    runtime = state.setdefault("runtime", {})
    runtime[_lease_key()] = {"leases": leases}
    return local_state.save_state(state, path) is not None


def _drop_lease_best_effort(path, leases, service):
    """Убрать lease сервиса и записать; неудача записи не фатальна — reconcile при следующем
    запуске распознаёт stale-фазу и дочистит (все ветки reconcile безопасны при повторном входе)."""
    leases.pop(service, None)
    if not _save_leases(path, leases):
        _log.warning("system_proxy_control: lease %s не расчищен (state не записался) — "
                     "дочистится reconcile'ом при следующем repair/restore", service)


def _is_target_endpoint(socks):
    return socks["server"] == TARGET_SERVER and socks["port"] == TARGET_PORT


def _same_endpoint(socks, server, port):
    return socks["server"] == server and socks["port"] == port


# ============================== межпроцессный lock (находка 4) ==============================


def _lock_timeout_sec(lock_timeout):
    """Bounded-ожидание flock. lock_timeout (сек) > env SROUTER_SYSTEM_PROXY_LOCK_TIMEOUT_SEC >
    дефолт 120. 0 = ждать вечно (семантика blocking-flock git_proxy). Мусор в env → дефолт."""
    if lock_timeout is not None:
        return lock_timeout
    raw = os.environ.get("SROUTER_SYSTEM_PROXY_LOCK_TIMEOUT_SEC")
    if raw is None:
        return _LOCK_TIMEOUT_DEFAULT_SEC
    try:
        return float(raw)
    except (TypeError, ValueError):
        return _LOCK_TIMEOUT_DEFAULT_SEC


@contextlib.contextmanager
def _transaction_lock(path, lock_timeout):
    """Эксклюзивный flock на ВСЮ транзакцию read→networksetup→save (issue #316 находка 4).

    Паттерн — git_proxy._mutation_lock / local_state._routing_config_lock: адаптивный lockfile
    РЯДОМ с управляемым ресурсом (нельзя flock сам srouter.local.json — он rewrite'ится через
    tmp+rename, fd остался бы на пере-созданный inode), файл-пустышка только под flock.
    Отличие от эталонов: bounded-ожидание (watchdog-паттерн #326 LOCK_NB) — CLI не должен висеть
    вечно, пока конкурент завис на интерактивном admin-диалоге networksetup. Занято дольше
    таймаута → yield False (caller даёт явный busy-отказ); lock-файл недоступен физически →
    тоже False (fail-closed: мутация без сериализации — и есть баг находки 4).

    flock конфликтует между file descriptions даже в одном процессе — гонки тестируемы без
    subprocess (поток/второй open в тесте).
    """
    state_p = local_state.state_path(path)
    lock_p = state_p.with_name(state_p.name + _LOCK_SUFFIX)
    try:
        lock_p.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(lock_p, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError as exc:
        _log.warning("system_proxy_control: lock-файл недоступен (%s) — отказ без мутации", exc)
        yield False
        return
    deadline = time.monotonic() + lock_timeout if lock_timeout and lock_timeout > 0 else None
    acquired = False
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
            break
        except OSError:
            if deadline is not None and time.monotonic() >= deadline:
                break
            time.sleep(_LOCK_POLL_SEC)
    if not acquired:
        os.close(fd)
        yield False
        return
    try:
        yield True
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def _busy_result(path, lock_timeout):
    return {"ok": False, "conflict": False, "busy": True,
            "err": f"другая операция system-proxy держит {local_state.state_path(path).name}"
                   f"{_LOCK_SUFFIX} дольше {lock_timeout:g} с (параллельный repair/restore? "
                   f"зависший admin-диалог?) — повторите команду позже"}


# ============================== repair ==============================


def repair(*, path=None, runner=sys_probe.run, lock_timeout=None):
    """Включить/выставить наш системный SOCKS endpoint на активном network service.

    Идемпотентно: уже настроено и включено -> ok без мутации. Выключен наш endpoint ->
    только `-setsocksfirewallproxystate on` (существующий lease НЕ перезаписывается — чужой
    backup неприкосновенен, #316-3). Чужой ВЫКЛЮЧЕННЫЙ endpoint -> preflight-запись previous в
    repairing-фазу ДО мутаций (#316-1), затем перезапись и включение, затем подтверждение в
    active. Чужой ВКЛЮЧЁННЫЙ/authenticated endpoint -> отказ БЕЗ мутации (conflict=True) — это
    может быть настоящий рабочий прокси пользователя, перезаписывать нельзя (fail-closed).
    Исключение из идемпотентности: незавершённый restore (restoring-lease) — отказ с указанием
    сначала дочинить restore.
    """
    timeout = _lock_timeout_sec(lock_timeout)
    with _transaction_lock(path, timeout) as acquired:
        if not acquired:
            return _busy_result(path, timeout)
        return _repair_locked(path, runner)


def _repair_locked(path, runner):
    leases = _load_leases(path)
    st = status(runner=runner)
    if st["status"] != "ok":
        return {"ok": False, "conflict": False, "err": st.get("detail", "система не определена")}

    service = st["service"]
    socks = st["socks"]
    lease = leases.get(service)

    if lease and lease.get("phase") == _PHASE_RESTORING:
        # Незавершённый restore (crash между шагами): repair поверх него создал бы lease-запись,
        # противоречащую полу-применённому restore. Явный отказ — сначала `restore` дочитывает.
        return {"ok": False, "conflict": False,
                "err": f"{service}: не завершён предыдущий restore (crash между шагами?) — "
                       f"выполните `srouter system-proxy restore`, затем повторите repair"}

    if _is_target_endpoint(socks):
        # Наш endpoint уже стоит — просто включаем канал, если выключен.
        if socks["enabled"]:
            return _promote_repairing(path, leases, service, lease, changed=False)
        _, err = _mutate([NETWORKSETUP, "-setsocksfirewallproxystate", service, "on"], runner)
        if err is not None:
            return {"ok": False, "conflict": False, "err": err}
        return _promote_repairing(path, leases, service, lease, changed=True, previous=dict(socks))

    if socks["enabled"] or socks["authenticated"]:
        # Чужой прокси уже активен — не трогаем (может быть реальный рабочий прокси пользователя).
        _log.warning("system_proxy_control: %s уже настроен на чужой SOCKS (%s:%s), repair отказал",
                     service, socks["server"], socks["port"])
        return {"ok": False, "conflict": True,
                "err": f"{service}: уже настроен чужой SOCKS-прокси "
                       f"({socks['server']}:{socks['port']}), не перезаписываю"}

    # Чужой endpoint, выключен — бэкапим ДО мутаций (write-preflight, #316-1), потом подменяем.
    previous = dict(socks)
    leases[service] = {"phase": _PHASE_REPAIRING, "service": service, "previous": previous}
    if not _save_leases(path, leases):
        # На диске остался прежний lease (запись не прошла целиком) — ничего не потеряно.
        return {"ok": False, "conflict": False,
                "err": "state не читается/не записывается — backup предыдущего endpoint "
                       "невозможен, мутация отменена (fail-closed)"}
    _, err1 = _mutate(
        [NETWORKSETUP, "-setsocksfirewallproxy", service, TARGET_SERVER, str(TARGET_PORT)], runner)
    if err1 is not None:
        # Система не тронута — pending не нужен (не расчищается — reconcile сбросит при следующем
        # запуске, это best-effort).
        _drop_lease_best_effort(path, leases, service)
        return {"ok": False, "conflict": False, "err": err1}
    _, err2 = _mutate([NETWORKSETUP, "-setsocksfirewallproxystate", service, "on"], runner)
    if err2 is not None:
        # Rollback endpoint (state ещё не тронут — networksetup default state = off не зависит
        # от endpoint, поэтому endpoint-write назад достаточно для восстановления prior state).
        _, rb_err = _mutate(
            [NETWORKSETUP, "-setsocksfirewallproxy", service,
             previous["server"] or "", str(previous["port"] or 0)], runner)
        if rb_err is None:
            _drop_lease_best_effort(path, leases, service)
        # rollback не удался: система осталась с нашим endpoint (выключен — не leak), а pending —
        # единственная копия previous; ОСТАВЛЯЕМ его, reconcile дочитает (issue #316-1).
        return {"ok": False, "conflict": False,
                "err": err2 if rb_err is None else f"{err2}; откат endpoint тоже не удался "
                                                   f"({rb_err}) — lease оставлен для докрутки"}
    leases[service] = {"phase": _PHASE_ACTIVE, "service": service, "previous": previous}
    if not _save_leases(path, leases):
        # previous уже durably записан preflight'ом; не хватает только подтверждения фазы —
        # следующий repair/restore сам поднимет repairing→active по reconcile.
        _log.warning("system_proxy_control: repair применён, но promote lease в state не записался")
        return {"ok": True, "conflict": False, "changed": True,
                "warning": "repair применён, но подтверждение lease не записалось — "
                           "доподтвердится при следующем repair/restore"}
    return {"ok": True, "conflict": False, "changed": True}


def _promote_repairing(path, leases, service, lease, *, changed, previous=None):
    """Ветка «наш endpoint уже стоит» (#316-3): существующий lease НЕ перезаписывается —
    перезапись previous=target-disabled уничтожала бы backup чужого прокси навсегда. Лишь
    repairing-фаза (crash посреди repair) подтверждается в active; lease отсутствует — создаётся
    с честным previous (что реально было до включения канала)."""
    warning = None
    if lease and lease.get("phase") == _PHASE_REPAIRING:
        leases[service] = {"phase": _PHASE_ACTIVE, "service": service,
                           "previous": dict(lease.get("previous") or {})}
        if not _save_leases(path, leases):
            warning = "repair применён, но подтверждение lease не записалось — " \
                      "доподтвердится при следующем repair/restore"
    elif not lease:
        leases[service] = {"phase": _PHASE_ACTIVE, "service": service,
                           "previous": previous or {}}
        if not _save_leases(path, leases):
            warning = "repair применён, но lease не записался в state"
    result = {"ok": True, "conflict": False, "changed": changed}
    if warning:
        result["warning"] = warning
    return result


# ============================== restore ==============================


def restore(*, path=None, runner=sys_probe.run, service=None, lock_timeout=None):
    """Вернуть сохранённый endpoint, только если текущее состояние совпадает с тем, что мы
    применили (repair). Внешний дрейф (кто-то сам поменял прокси после repair) -> отказ,
    без мутации — иначе можно затереть чужое намеренное изменение.

    Восстанавливает все известные leases (Wi-Fi↔Ethernet переключения оставляют по lease на
    сервис, #316-3) или один — параметр service. Порядок мутаций off-first (#316-2), фаза
    restoring пишется ДО мутаций (#316-1) — crash на любом шаге дочитывается следующим вызовом.
    """
    timeout = _lock_timeout_sec(lock_timeout)
    with _transaction_lock(path, timeout) as acquired:
        if not acquired:
            return _busy_result(path, timeout)
        return _restore_locked(path, runner, service)


def _restore_locked(path, runner, service):
    leases = _load_leases(path)
    if service is not None:
        if service not in leases:
            return {"ok": False, "conflict": False, "results": [],
                    "err": f"нет сохранённого состояния для сервиса {service!r}"}
        names = [service]
    else:
        names = sorted(leases)
    if not names:
        return {"ok": False, "conflict": False, "results": [],
                "err": "нет сохранённого состояния для восстановления"}

    results = []
    for svc in names:
        results.append({"service": svc,
                        **_restore_one(path, leases, svc, runner)})
    ok = all(r["ok"] for r in results)
    return {"ok": ok,
            "conflict": any(r.get("conflict") for r in results),
            "err": None if ok else "; ".join(r["err"] for r in results if not r["ok"] and r.get("err")),
            "results": results}


def _restore_one(path, leases, service, runner):
    """Restore одного сервиса. leases мутируется (pop при успехе), каждая фазовая запись —
    через _save_leases с проверкой возврата. Все отказные ветки оставляют lease в состоянии,
    из которого повторный вызов корректно продолжает (reconcile-инвариант докстринга модуля)."""
    lease = leases.get(service)
    if not lease:
        return {"ok": False, "err": f"{service}: lease исчез (конкурентное изменение?)"}
    phase = lease.get("phase")
    previous = dict(lease.get("previous") or {})

    current = _read_socks(service, runner)
    if current is None:
        return {"ok": False, "err": f"{service}: не удалось прочитать текущее состояние"}

    if phase == _PHASE_REPAIRING:
        # Repair не был подтверждён (crash до promote). Наш endpoint на сервисе значит, что
        # мутации применились — разворачиваем их по previous; чужой endpoint — мутаций не было
        # (или внешний откат), восстанавливать нечего, stale-lease сбрасывается.
        if _is_target_endpoint(current):
            return _restore_apply(path, leases, service, previous, current, runner)
        leases.pop(service, None)
        if _save_leases(path, leases):
            return {"ok": False,
                    "err": f"{service}: repair не был завершён, система уже настроена иначе — "
                           f"stale lease сброшен, восстанавливать нечего"}
        return {"ok": False, "err": f"{service}: repair не был завершён; сброс stale lease не "
                                    f"удался (state не записывается)"}

    if phase == _PHASE_RESTORING:
        if _is_target_endpoint(current):
            # Restore оборвался до/на записи endpoint — дочитываем с начала (off-first: если
            # канал включён, первый же шаг его выключит).
            return _restore_apply(path, leases, service, previous, current, runner)
        if _same_endpoint(current, previous.get("server"), previous.get("port")):
            if current["enabled"] == bool(previous.get("enabled")):
                # Restore фактически завершён (crash между последней мутацией и расчисткой
                # lease) — чистим без единой мутации.
                leases.pop(service, None)
                if _save_leases(path, leases):
                    return {"ok": True}
                return {"ok": False, "err": f"{service}: restore уже завершён, но расчистить "
                                            f"lease не удалось (state не записывается)"}
            # Endpoint уже вернули (off-first), остался финальный state.
            _, err = _mutate([NETWORKSETUP, "-setsocksfirewallproxystate", service,
                              "on" if previous.get("enabled") else "off"], runner)
            if err is not None:
                return {"ok": False, "err": err}  # lease остаётся — retry дочитает
            leases.pop(service, None)
            if _save_leases(path, leases):
                return {"ok": True}
            return {"ok": True, "warning": "restore завершён, но lease не расчищен — "
                                           "дочистится при следующем restore"}
        return {"ok": False, "conflict": True,
                "err": f"{service}: внешний drift во время незавершённого restore — lease "
                       f"сохранён, повторите, когда сервис вернётся в известное состояние"}

    # phase == active: restore имеет право разворачивать только ровно то, что применили.
    if not (current["enabled"] and _is_target_endpoint(current)):
        return {"ok": False, "conflict": True,
                "err": f"{service}: состояние изменилось извне с момента repair, restore отменён"}

    # Write-preflight фазы restoring (#316-1 для restore): без durable-маркера на диске
    # crash посреди мутаций оставлял бы lease в active (вечный conflict при retry).
    leases[service] = {"phase": _PHASE_RESTORING, "service": service, "previous": previous}
    if not _save_leases(path, leases):
        return {"ok": False, "err": "state не записывается — фаза restoring не сохранена, "
                                    "мутации отменены (fail-closed)"}
    return _restore_apply(path, leases, service, previous, current, runner)


def _restore_apply(path, leases, service, previous, current, runner):
    """Мутации restore в off-first порядке (#316-2): выключенный канал с любым endpoint не может
    направить трафик ОС на чужой прокси. Любой сбой оставляет lease в текущей фазе — повторный
    restore продолжает с того же места (см. reconcile-ветки _restore_one)."""
    if current["enabled"]:
        _, err = _mutate([NETWORKSETUP, "-setsocksfirewallproxystate", service, "off"], runner)
        if err is not None:
            return {"ok": False, "err": err}
    _, err = _mutate([NETWORKSETUP, "-setsocksfirewallproxy", service,
                      previous.get("server") or "", str(previous.get("port") or 0)], runner)
    if err is not None:
        return {"ok": False, "err": err}
    _, err = _mutate([NETWORKSETUP, "-setsocksfirewallproxystate", service,
                      "on" if previous.get("enabled") else "off"], runner)
    if err is not None:
        return {"ok": False, "err": err}
    leases.pop(service, None)
    if _save_leases(path, leases):
        return {"ok": True}
    # Система уже полностью восстановлена; lease (restoring) дочистится reconcile-веткой
    # «endpoint previous + state как previous» при следующем restore.
    _log.warning("system_proxy_control: restore %s применён, но lease не расчился", service)
    return {"ok": True, "warning": "restore применён, но расчистить lease не удалось — "
                                   "дочистится при следующем restore"}
