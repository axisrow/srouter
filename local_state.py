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
                 "active_isolate": None, "active_codex_isolate": None},
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
    return local_state_nodes._nodes_from_state(state)


# ============================ подмодули (facade re-export) ============================
# Импортируются В КОНЦЕ файла: к этому моменту core I/O (load_state/save_state/_load_state_checked/
# _atomic_write_text/_routing_config_lock/_is_valid_host/_DEFAULT_PATH) уже определён в globals
# этого модуля — подмодули могут безопасно резолвить `local_state.<name>` при вызове функций
# (facade-lookup, не при импорте). star-import-reexport-contract: реэкспортируем ВСЮ публичную и
# внутреннюю (используемую снаружи как local_state._X, см. grep-consumer surface) поверхность.

import local_state_nodes  # noqa: E402 — намеренно после core (facade-lookup)
import local_state_traffic_guard  # noqa: E402
import local_state_isolate  # noqa: E402
import local_state_xray  # noqa: E402
import local_state_routing  # noqa: E402

# --- nodes ---
_is_valid_node = local_state_nodes._is_valid_node
load_nodes = local_state_nodes.load_nodes
enabled_nodes = local_state_nodes.enabled_nodes
get_node = local_state_nodes.get_node
active_node = local_state_nodes.active_node
begin_active_node_change = local_state_nodes.begin_active_node_change
commit_active_node_change = local_state_nodes.commit_active_node_change
clear_pending = local_state_nodes.clear_pending
_looks_like_ip = local_state_nodes._looks_like_ip
resolve_route_ip = local_state_nodes.resolve_route_ip

# --- traffic guard ---
_normalize_traffic_guard_domain = local_state_traffic_guard._normalize_traffic_guard_domain
_traffic_guard_domain_matches = local_state_traffic_guard._traffic_guard_domain_matches
_normalize_traffic_guard_channel = local_state_traffic_guard._normalize_traffic_guard_channel
_validate_traffic_guard_domain_map = local_state_traffic_guard._validate_traffic_guard_domain_map
_validate_traffic_guard_channel_domains = local_state_traffic_guard._validate_traffic_guard_channel_domains
_normalized_traffic_guard_domain_map = local_state_traffic_guard._normalized_traffic_guard_domain_map
_normalized_traffic_guard_channel_domains = local_state_traffic_guard._normalized_traffic_guard_channel_domains
_traffic_guard_state_channel = local_state_traffic_guard._traffic_guard_state_channel
_traffic_guard_domains_for_channel = local_state_traffic_guard._traffic_guard_domains_for_channel
validate_traffic_guard = local_state_traffic_guard.validate_traffic_guard
traffic_guard_config = local_state_traffic_guard.traffic_guard_config
_valid_throttle_rate = local_state_traffic_guard._valid_throttle_rate
validate_throttle_request = local_state_traffic_guard.validate_throttle_request
_valid_active_throttle = local_state_traffic_guard._valid_active_throttle
load_active_throttle = local_state_traffic_guard.load_active_throttle
save_active_throttle = local_state_traffic_guard.save_active_throttle
clear_active_throttle = local_state_traffic_guard.clear_active_throttle

# --- PF isolate ---
_valid_isolate_ports = local_state_isolate._valid_isolate_ports
validate_isolate = local_state_isolate.validate_isolate
_valid_active_isolate = local_state_isolate._valid_active_isolate
load_active_isolate = local_state_isolate.load_active_isolate
save_active_isolate = local_state_isolate.save_active_isolate
clear_active_isolate = local_state_isolate.clear_active_isolate
_valid_active_codex_isolate = local_state_isolate._valid_active_codex_isolate
load_active_codex_isolate = local_state_isolate.load_active_codex_isolate
save_active_codex_isolate = local_state_isolate.save_active_codex_isolate
clear_active_codex_isolate = local_state_isolate.clear_active_codex_isolate

# --- xray endpoint sync (#200) ---
XRAY_CONFIG_PATH = local_state_xray.XRAY_CONFIG_PATH
read_xray_active_address = local_state_xray.read_xray_active_address
_read_xray_vless_address = local_state_xray._read_xray_vless_address
sync_route_ip_from_xray = local_state_xray.sync_route_ip_from_xray
_is_testnet_placeholder = local_state_xray._is_testnet_placeholder
active_endpoint_host = local_state_xray.active_endpoint_host
compare_endpoint_with_xray = local_state_xray.compare_endpoint_with_xray
sync_endpoint_from_xray = local_state_xray.sync_endpoint_from_xray

# --- routing domains (#136) ---
ROUTING_MARKER = local_state_routing.ROUTING_MARKER
DEFAULT_ROUTING_OUTBOUND = local_state_routing.DEFAULT_ROUTING_OUTBOUND
routing_plan = local_state_routing.routing_plan
_routing_find_managed_rule = local_state_routing._routing_find_managed_rule
_routing_domains_hash = local_state_routing._routing_domains_hash
routing_apply = local_state_routing.routing_apply
_routing_apply_locked = local_state_routing._routing_apply_locked
