"""Defensive stdlib-only helper над unified local state `srouter.local.json`.

Контракт (#2): функции НИКОГДА не бросают; невалидный ввод деградирует в empty/default.
Path по умолчанию — рядом с модулем (не cwd), чтобы работал под launchd.
Каждая public функция принимает path= для тестов (tmp_path fixture).

Этот модуль — core state I/O (default state, load/save, atomic write, cross-process lock,
_is_valid_host) + фасад с полным ре-экспортом (issue #158, декомпозиция крупных файлов, канон
star-import-reexport-contract). Специализированная логика вынесена в подмодули по обязанностям:
  - local_state_traffic_guard.py — Traffic Guard валидация/config + throttle runtime-lease
  - local_state_isolate.py       — PF-изоляция доменов + codex-изоляция (#168), runtime-lease
  - local_state_nodes.py         — узлы: CRUD, active_node, resolve_route_ip
  - local_state_xray.py          — #200: sync endpoint local.json ↔ рабочий xray-конфиг
  - local_state_routing.py       — #136: routing-domains в production xray-config (hybrid adopt)

Подмодули обращаются к core I/O ЧЕРЕЗ этот фасад (`import local_state`,
`local_state._load_state_checked(...)`), а не через прямой импорт друг друга — канон
moving-caller-inverts-mock-ownership: тесты патчат `local_state._load_state_checked` /
`local_state.save_state` и ожидают, что функции-обёртки (sync_route_ip_from_xray, routing_apply,
save_active_isolate, ...) это увидят. Если бы caller и callee физически разъехались и caller
резолвил callee забинженной ссылкой на другой подмодуль (`from local_state_core import X`), патчи
на фасаде стали бы тихим no-op. Facade-lookup (module-attribute lookup в момент вызова, а не при
импорте) сохраняет существующий контракт патчинга без изменений в тестах. Цикла импорта нет —
`import local_state` внутри подмодулей только регистрирует модуль в sys.modules; атрибуты читаются
в момент ВЫЗОВА функции, когда local_state.py уже полностью инициализирован (подмодули
импортируются последними, в самом низу этого файла).
"""
import json
import os
import re
import socket  # noqa: F401 — re-export surface: local_state.socket патчится тестами (canon
                # star-import-reexport-contract), реальный resolve_route_ip теперь в
                # local_state_nodes.py, но это ТОТ ЖЕ объект модуля socket (sys.modules) — патч
                # local_state.socket.gethostbyname виден и там.
from pathlib import Path

# Путь к локальному state по умолчанию — рядом с этим модулем, не cwd.
_DEFAULT_PATH = Path(__file__).resolve().parent / "srouter.local.json"

# D2: валидация хоста — только безопасные символы, shell-метасимволы запрещены.
# Переиспользовано из закрытого PR #19; закреплено в #2. Единственный источник для всех подмодулей.
_HOST_RE = re.compile(r"^[A-Za-z0-9.:_-]+\Z")


def _is_valid_host(host):
    """True если строка содержит только безопасные для shell символы."""
    return bool(isinstance(host, str) and _HOST_RE.match(host))


# Safe-default state: секции v1 (#2). probes — эталонные defaults (G3);
# реальную запись делает #5 setup/check на реальной машине.
_DEFAULT_STATE = {
    "schema_version": 1,
    "nodes": [],
    "active_node": {"name": None, "pending": None},
    "probes": {
        "reachability_targets": ["https://api.ip.sb/ip", "https://www.cloudflare.com/cdn-cgi/trace"],
        "throughput_targets": [{"url": "https://speed.cloudflare.com/__down?bytes=1048576", "bytes": 1048576}],
        "connect_timeout_sec": 4,
        "max_time_sec": 8,
        # Heartbeat-метрики туннеля (observe-only): timing уже идущего curl-watchdog
        # пишется в ~/Library/Logs/srouter-watchdog.metrics.jsonl. Включено по
        # умолчанию — доп. сетевого трафика ноль.
        "metrics_enabled": True,
        "metrics_interval_sec": 60,
        "metrics_retention_days": 7,
    },
    "network": {"gateway": "", "vpn_server": "", "vpn_exit_ip": "", "channels": {}},
    "traffic_guard": {"mode": "off", "domains": {}},
    # PF-изоляция Proxy-доменов: прямой путь к этим доменам отрезается в ядре PF.
    # domains — дефолт Claude (меняется в дашборде). ports 80/443 (CloudFront IP хостят
    # много доменов). enabled=False по умолчанию — изоляция включается явно через UI/CLI.
    "isolate": {
        "enabled": False,
        "domains": ["api.anthropic.com", "console.anthropic.com", "claude.ai"],
        "ports": [80, 443],
    },
    "detected_environment": {
        "last_checked_at": None,
        "brew": None,
        "xray": None,
        "privoxy": None,
        "dnsmasq": None,
        "launchagent": None,
    },
    # active_throttle — runtime-lease активного Traffic Guard throttle (#13/#22).
    # None когда throttle не активен. При активном: {domain, rate, token, applied_at}.
    # Персист именно token обязателен — без него clear_throttle не освободит pf
    # enable-ref (pfctl -X) после рестарта дашборда (issue #61). Это чистый runtime,
    # НЕ policy: держим отдельно от traffic_guard.domains (одно-pipe'овый движок,
    # один активный throttle за раз). Секретов нет; Reality-ключи/конфиги не трогаем.
    "runtime": {"last_apply": None, "last_error": None, "active_throttle": None,
                 "active_isolate": None, "active_codex_isolate": None,
                 # system_proxy — runtime-lease системного macOS SOCKS-repair (srouter system-proxy
                 # repair/restore). leases — per-service слоты с фазами
                 # repairing/active/restoring (write-preflight + reconcile, issue #316); миграция
                 # legacy {"active": {...}} — на чтении в system_proxy_control._normalize_leases.
                 # Отдельный ключ, т.к. это независимая привилегированная операция
                 # (repair CLI, не Traffic Guard/PF).
                 "system_proxy": {"leases": {}}},
    # auto_route_sync — opt-in split-route до VPS через en0 (мимо VPN). Top-level ключ (читается
    # node_selector._auto_route_sync_enabled строго is True). По умолчанию ON — «пофигу VPN»:
    # watchdog (ensure_split_route) держит route через физический шлюз при любом состоянии VPN.
    "auto_route_sync": True,
    # direct_domains (#197): opt-in user-домены для direct_first.candidate_domains — проверяются
    # честным прямым TLS-test (мимо прокси), reachable → идут в NO_PROXY (переживают смерть VPS).
    # BUILTIN z.ai добавляется в direct_first независимо от этого списка (канон zai-direct-no-proxy).
    # Пустой список по умолчанию — opt-in (реальный IP виден домену, privacy-решение пользователя).
    "direct_domains": [],
}


def load_state(path=None):
    """Загрузить state. Missing/broken/non-object -> безопасный _DEFAULT_STATE (копия).
    Никогда не бросает.
    """
    state, _readable = _load_state_checked(path)
    return state


def state_path(path=None):
    """Резолв пути state-файла (public с #316): рядом-лежащие артефакты (lock-файлы system-proxy,
    будущие аудиты) обязаны резолвить «рядом с state» этим же правилом, а не своей копией
    _DEFAULT_PATH — иначе path= в функциях и path= в локах разъезжаются."""
    return Path(path) if path else _DEFAULT_PATH


def load_state_checked(path=None):
    """Загрузить state и вернуть (state, readable) для мутирующих операций.

    readable=False означает: файл существует, но его нельзя безопасно
    перезаписывать без явного backup/решения вызывающего кода.
    """
    return _load_state_checked(path)


def _load_state_checked(path=None):
    """Загрузить state и отличить missing file от битого existing file.

    readable=False значит: файл был найден, но его нельзя безопасно перезаписывать мутатором.
    """
    p = Path(path) if path else _DEFAULT_PATH
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return _copy_default(), True
    except (OSError, ValueError):
        return _copy_default(), False
    if not isinstance(data, dict):
        return _copy_default(), False
    # Не возвращаем мутируемый _DEFAULT_STATE напрямую — глубокая копия секций.
    merged = _copy_default()
    for k, v in data.items():
        merged[k] = v
    return merged, True


def save_state(state, path=None):
    """Атомарная запись (temp + rename). Возвращает state при успехе, None при ошибке. Не бросает."""
    p = Path(path) if path else _DEFAULT_PATH
    tmp = p.with_suffix(p.suffix + ".tmp")
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(p)  # atomic rename
        _fsync_parent_dir(p)
    except (OSError, TypeError, ValueError):
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return None
    return state


def _fsync_parent_dir(path):
    """Best-effort fsync каталога после atomic rename; не все FS это поддерживают."""
    try:
        fd = os.open(path.parent, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _atomic_write_text(path, text):
    """Атомарная запись произвольного текста в path (tmp + flush + fsync + rename + fsync_dir).

    Канон atomic-save (эталон save_state): никогда не truncate production-файл напрямую — пишем во
    временный файл, затем atomic-rename. Если диск откажет (ENOSPC/IO-error) на любой стадии —
    production-файл остаётся НЕТРОНУТЫМ (либо старое содержимое целиком, либо успешно заменённое
    новое), никогда не в промежуточном/truncated состоянии. #139: единый примитив для шага modify
    И обоих rollback-веток routing_apply, чтобы откат конфига тоже был атомарным.

    Возвращает True при успехе, False при OSError/любом провале записи (не бросает)."""
    p = Path(path)
    tmp = p.with_suffix(p.suffix + ".tmp")
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)  # atomic rename
        _fsync_parent_dir(p)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False
    return True


def _routing_config_lock(config_path):
    """Context-manager process-safe exclusive lock на xray-config.json (flock LOCK_EX).

    #139 Finding 2: serialize concurrent routing_apply (ручной `srouter routing` + install/future
    gen_xray_config). Канон — однопользовательский CLI, не демон; реалистичный race — два
    одновременных вызова в узкое окно read->write. flock блокирующий: второй apply ждёт отпускания
    lock первым, не читая stale snapshot -> нет lost-update (затирания доменов). Блокировка
    намеренно держится через restart xray, т.к. stale-snapshot замена после restart — ядро дыры.

    Адаптивный lockfile: создаётся .lock рядом с config. Файл НЕ читается/не пишется как данные —
    только flock по fd; содержимое не валидируется (наследует failure-mode flock: lock-файл может
    остаться на диске, но это безобидно — следующий apply открывает и flock'ит его же)."""
    import contextlib
    import fcntl

    lock_p = Path(config_path).with_name(Path(config_path).name + ".lock")

    @contextlib.contextmanager
    def _cm():
        lock_p.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(lock_p, os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)  # блокирует до отпускания другим процессом/потоком
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)

    return _cm()


def preflight_state_write(path=None):
    """Проверить реальный atomic-write путь для state до privileged throttle apply.

    load_state_checked() доказывает только parse/read. Для throttle этого мало:
    pf enable-ref нельзя создавать, пока не доказано, что тот же save_state path
    способен записать recoverable lease. Под dashboard mutation-lock делаем no-op
    rewrite текущего state через точный save_state.
    """
    state, readable = load_state_checked(path)
    if not readable:
        return False
    return save_state(state, path) is not None


def _copy_default():
    """Глубокая копия дефолтного state, чтобы тесты/мутирующие вызовы не портили константу."""
    import copy

    return copy.deepcopy(_DEFAULT_STATE)


def _nodes_from_state(state):
    """Тонкая обёртка над local_state_nodes._nodes_from_state — используется local_state_xray
    и local_state_routing через фасад (facade-lookup), см. docstring модуля."""
    import local_state_nodes
    return local_state_nodes._nodes_from_state(state)


# ============================ подмодули (lazy facade re-export) ============================
# КРИТИЧНО: реэкспорт делается ЛЕНИВО через module-level __getattr__ (PEP 562), НЕ module-level
# bound assignment (`_is_valid_node = local_state_nodes._is_valid_node`). Двусторонний импорт
# (local_state.py импортирует local_state_nodes.py В КОНЦЕ файла; local_state_nodes.py импортирует
# local_state в НАЧАЛЕ) сам по себе не циклится — Python спокойно регистрирует оба модуля в
# sys.modules без обращения к их атрибутам. Но если бы local_state.py в конце файла СРАЗУ читал
# `local_state_nodes._is_valid_node` (module-level assignment), а кто-то извне импортировал бы
# `local_state_nodes` НАПРЯМУЮ (раньше `local_state`), то `local_state_nodes.py` начал бы с
# `import local_state`, что запустило бы ВЕСЬ local_state.py с начала (включая его собственный
# `import local_state_nodes` в конце) — а local_state_nodes уже в sys.modules, но недоинициализирован
# (Python видит частично выполненный модуль) → AttributeError "partially initialized module".
# Воспроизводится эмпирически: `python3 -c "import local_state_nodes"` в изолированной копии
# (без предварительного `import local_state`) падал именно так до этого фикса. __getattr__
# резолвит имя ТОЛЬКО когда кто-то реально обращается к `local_state.<name>` (после того, как оба
# модуля уже полностью проинициализированы) — тот же паттерн, что privoxy_system.py применяет для
# privoxy_control.py (см. его docstring). star-import-reexport-contract: экспортируем ВСЮ
# публичную и внутреннюю (используемую снаружи как local_state._X, см. grep-consumer surface)
# поверхность.

_SUBMODULE_NAMES = {
    # --- nodes ---
    "_is_valid_node": "local_state_nodes",
    "load_nodes": "local_state_nodes",
    "enabled_nodes": "local_state_nodes",
    "get_node": "local_state_nodes",
    "active_node": "local_state_nodes",
    "begin_active_node_change": "local_state_nodes",
    "commit_active_node_change": "local_state_nodes",
    "clear_pending": "local_state_nodes",
    "_looks_like_ip": "local_state_nodes",
    "resolve_route_ip": "local_state_nodes",
    # --- traffic guard ---
    "_TRAFFIC_GUARD_MODES": "local_state_traffic_guard",
    "_TRAFFIC_GUARD_POLICIES": "local_state_traffic_guard",
    "_TRAFFIC_GUARD_CHANNELS": "local_state_traffic_guard",
    "_TRAFFIC_GUARD_AUTO_DOMAINS_ERROR": "local_state_traffic_guard",
    "_normalize_traffic_guard_domain": "local_state_traffic_guard",
    "_traffic_guard_domain_matches": "local_state_traffic_guard",
    "_normalize_traffic_guard_channel": "local_state_traffic_guard",
    "_validate_traffic_guard_domain_map": "local_state_traffic_guard",
    "_validate_traffic_guard_channel_domains": "local_state_traffic_guard",
    "_normalized_traffic_guard_domain_map": "local_state_traffic_guard",
    "_normalized_traffic_guard_channel_domains": "local_state_traffic_guard",
    "_traffic_guard_state_channel": "local_state_traffic_guard",
    "_traffic_guard_domains_for_channel": "local_state_traffic_guard",
    "validate_traffic_guard": "local_state_traffic_guard",
    "traffic_guard_config": "local_state_traffic_guard",
    "_valid_throttle_rate": "local_state_traffic_guard",
    "validate_throttle_request": "local_state_traffic_guard",
    "_valid_active_throttle": "local_state_traffic_guard",
    "load_active_throttle": "local_state_traffic_guard",
    "save_active_throttle": "local_state_traffic_guard",
    "clear_active_throttle": "local_state_traffic_guard",
    # --- PF isolate ---
    "_valid_isolate_ports": "local_state_isolate",
    "validate_isolate": "local_state_isolate",
    "_valid_active_isolate": "local_state_isolate",
    "load_active_isolate": "local_state_isolate",
    "save_active_isolate": "local_state_isolate",
    "clear_active_isolate": "local_state_isolate",
    "_valid_active_codex_isolate": "local_state_isolate",
    "load_active_codex_isolate": "local_state_isolate",
    "save_active_codex_isolate": "local_state_isolate",
    "clear_active_codex_isolate": "local_state_isolate",
    # --- xray endpoint sync (#200) ---
    "XRAY_CONFIG_PATH": "local_state_xray",
    "_TESTNET_203_PREFIX": "local_state_xray",
    "read_xray_active_address": "local_state_xray",
    "_read_xray_vless_address": "local_state_xray",
    "sync_route_ip_from_xray": "local_state_xray",
    "_is_testnet_placeholder": "local_state_xray",
    "active_endpoint_host": "local_state_xray",
    "compare_endpoint_with_xray": "local_state_xray",
    "sync_endpoint_from_xray": "local_state_xray",
    # --- routing domains (#136) ---
    "ROUTING_MARKER": "local_state_routing",
    "DEFAULT_ROUTING_OUTBOUND": "local_state_routing",
    "routing_plan": "local_state_routing",
    "_routing_find_managed_rule": "local_state_routing",
    "_routing_domains_hash": "local_state_routing",
    "routing_apply": "local_state_routing",
    "_routing_apply_locked": "local_state_routing",
}


def __getattr__(name):
    module_name = _SUBMODULE_NAMES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib
    submodule = importlib.import_module(module_name)
    return getattr(submodule, name)


def __dir__():
    # PEP 562: без этого dir(local_state)/hasattr-интроспекция не видит lazy-реэкспортированные
    # имена (только то, что реально в globals() на момент вызова). Явный __dir__ держит полный
    # re-export surface видимым для интроспекции, не только для прямого атрибутного доступа.
    return sorted(set(globals()) | set(_SUBMODULE_NAMES))
