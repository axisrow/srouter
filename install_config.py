#!/usr/bin/env python3
"""Config-логика install: InstallEnv, discovery, build_plan/apply_install (issue #229, экстракция
из install_lib.py).

InstallEnv (env-переменные → runtime paths), маркер-детекция конфигов, discovery компонентов
(xray/privoxy/dnsmasq), plan/apply install-потока. LaunchAgent-специфика (рендер/загрузка plist) —
в install_plist.py, uninstall-логика — в install_cleanup.py. Публичные функции возвращают dict/result
и не бросают наружу (тот же контракт, что был у install_lib.py).
"""
from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import gen_xray_config
import local_state
import privoxy_system
from sys_probe import BREW_COMPONENTS
from sys_probe import parse_brew_services as _parse_brew_services
from sys_probe import port_open, run

from install_plist import (
    LAUNCHAGENT_LABEL,
    LAUNCHAGENT_FILE,
    _has_launchagent_marker,
    _install_launchagent,
    _launchagent_template_path,
    _write_text_atomic,
)


MARKER = "srouter-managed"
TEXT_MARKER = "srouter-managed-config-v1"
ROOT = Path(__file__).resolve().parent

# Whitelist директив privoxy 4.2.0, гарантированно распознаваемых базовой сборкой. Строгий
# первоисточник — privoxy 4.2.0 user-manual (https://www.privoxy.org/user-manual/config.html),
# разделы 7.1-7.6 (Local Set-up / Locations / Debugging / Access Control / Forwarding /
# Miscellaneous). Намеренно НЕ включаем раздел 7.7 «HTTPS Inspection» (elliptic-curve-keys,
# ca-directory, ca-cert-file, ca-key-file, ca-password, certificate-directory, cipher-list,
# trusted-cas-file) — эти директивы валидны ТОЛЬКО при FEATURE_HTTPS_INSPECTION; без неё privoxy
# 4.2.0 логирует "Ignoring unrecognized directive" и launchd KeepAlive может молотить рестарты
# на error-выхлопе (issue #115 симптом 1). Инвариант-тест ловит будущий regression: если в
# templates/privoxy.config попадёт feature-gated директива. Канон: семантика probe — по
# первоисточнику, не аналогия.
PRIVOXY_KNOWN_DIRECTIVES = frozenset({
    # 7.1 Local Set-up Documentation
    "user-manual", "trust-info-url", "admin-address", "proxy-info-url",
    # 7.2 Configuration and Log File Locations
    "confdir", "templdir", "temporary-directory", "logdir", "actionsfile",
    "filterfile", "logfile", "trustfile",
    # 7.3 Debugging
    "debug", "single-threaded", "hostname",
    # 7.4 Access Control and Security
    "listen-address", "toggle", "enable-remote-toggle", "enable-remote-http-toggle",
    "enable-edit-actions", "enforce-blocks", "permit-access", "deny-access",
    "buffer-limit", "enable-proxy-authentication-forwarding", "trusted-cgi-referer",
    "cors-allowed-origin",
    # 7.5 Forwarding
    "forward", "forward-socks4", "forward-socks4a", "forward-socks5", "forward-socks5t",
    "forwarded-connect-retries",
    # 7.6 Miscellaneous
    "accept-intercepted-requests", "allow-cgi-request-crunching", "split-large-forms",
    "keep-alive-timeout", "tolerate-pipelining", "default-server-timeout", "connection-sharing",
    "socket-timeout", "max-client-connections", "listen-backlog", "enable-accept-filter",
    "handle-as-empty-doc-returns-ok", "enable-compression", "compression-level",
    "client-header-order", "client-specific-tag", "client-tag-lifetime", "trust-x-forwarded-for",
    "receive-buffer-size",
})

BREW = "/opt/homebrew/bin/brew"
CURL = "/usr/bin/curl"
ROUTE = "/sbin/route"
LSOF = "/usr/sbin/lsof"
NETWORKSETUP = "/usr/sbin/networksetup"
SUDO = "/usr/bin/sudo"

COMPONENTS = BREW_COMPONENTS
CHOICES = ("adopt", "overwrite", "skip")

# Прокси-порты (8118/10808) — единый источник dashboard_common (issue #155/#165), НЕ локальные
# литералы: при смене канонического порта installer должен целить в тот же порт, иначе privoxy/xray
# стартуют на одном порту, а install-проверки и рестарты смотрят на другой → полный отказ прокси.
# install_config обязан работать в среде без srouter_config (install-путь): dashboard_common при
# отсутствии конфига поднимает SystemExit (BaseException, не Exception) — ловим именно SystemExit,
# чтобы не маскировать РЕАЛЬНЫЕ ошибки источника (SyntaxError/ImportError). Fallback = то же
# каноническое значение; строки помечены canonical-fallback-port (гвард test_proxy_constants.py
# разрешает их как осознанный fallback, не свежий дубликат). dnsmasq UDP 53 — НЕ прокси-порт,
# остаётся локальным литералом (вне scope централизации прокси).
try:
    from dashboard_common import PRIVOXY_PORT as _PRIVOXY_PORT  # noqa: F401  (canonical-fallback-port)
    from dashboard_common import XRAY_SOCKS_PORT as _XRAY_SOCKS_PORT  # noqa: F401  (canonical-fallback-port)
except SystemExit:  # dashboard_common без srouter_config поднимает SystemExit (install-путь)
    _PRIVOXY_PORT = 8118  # canonical-fallback-port
    _XRAY_SOCKS_PORT = 10808  # canonical-fallback-port
PORTS = {
    "xray": ("tcp", _XRAY_SOCKS_PORT),
    "privoxy": ("tcp", _PRIVOXY_PORT),
    "dnsmasq": ("udp", 53),
}

# Надёжный рестарт brew-сервиса: `brew services restart` атомарно убивает старый и поднимает новый
# процесс, но старый может ещё держать порт (TIME_WAIT / медленный shutdown) → новый падает
# `Fatal: can't bind to 127.0.0.1:8118` → launchd молотит рестарты (issue #115 симптом 2). Лечится
# разнесением на stop → poll освобождения порта → start → poll поднятия порта. Симметрично канонному
# эталону _launchd_reload (bootout→poll→bootstrap-retry). Константы уровня модуля → тесты зануляют.
_PORT_SETTLE_POLL_INTERVAL = 0.5  # шаг poll «порт освободился/поднялся?» (сек)
_PORT_SETTLE_MAX_WAIT = 3.0       # потолок ожидания освобождения порта после stop (сек)
_PORT_UP_MAX_WAIT = 5.0           # потолок ожидания поднятия порта после start (сек)


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class InstallEnv:
    root: Path = ROOT
    prefix: Path = Path("/opt/homebrew")
    state_path: Path = ROOT / "srouter.local.json"
    launchagent_dir: Path = Path.home() / "Library" / "LaunchAgents"
    python_bin: str = "/usr/bin/python3"
    log_out: Path = Path.home() / "Library/Logs/srouter-dashboard.out.log"
    log_err: Path = Path.home() / "Library/Logs/srouter-dashboard.err.log"
    now: str = ""

    @classmethod
    def from_env(cls, *, state_path=None, prefix=None):
        log_dir = Path(os.environ.get("SROUTER_LOG_DIR", Path.home() / "Library/Logs"))
        return cls(
            root=ROOT,
            prefix=Path(prefix or os.environ.get("SROUTER_PREFIX", "/opt/homebrew")),
            state_path=Path(state_path or os.environ.get("SROUTER_STATE_PATH", ROOT / "srouter.local.json")),
            launchagent_dir=Path(os.environ.get("SROUTER_LAUNCHAGENTS_DIR", Path.home() / "Library" / "LaunchAgents")),
            python_bin=os.environ.get("SROUTER_PYTHON", "/usr/bin/python3"),
            log_out=log_dir / "srouter-dashboard.out.log",
            log_err=log_dir / "srouter-dashboard.err.log",
            now=os.environ.get("SROUTER_NOW", "") or _now(),
        )

    def component_paths(self, name):
        etc = self.prefix / "etc"
        paths = {
            "xray": {
                "config": etc / "xray" / "config.json",
                "brew_binary": self.prefix / "bin" / "xray",
                "non_brew": [Path("/usr/local/bin/xray"), Path("/usr/bin/xray")],
            },
            "privoxy": {
                "config": etc / "privoxy" / "config",
                "brew_binary": self.prefix / "sbin" / "privoxy",
                "non_brew": [Path("/usr/local/sbin/privoxy"), Path("/usr/sbin/privoxy")],
            },
            "dnsmasq": {
                "config": etc / "dnsmasq.conf",
                "brew_binary": self.prefix / "sbin" / "dnsmasq",
                "non_brew": [Path("/usr/local/sbin/dnsmasq"), Path("/usr/sbin/dnsmasq")],
            },
        }
        return paths[name]

    def launchagent_path(self):
        return self.launchagent_dir / LAUNCHAGENT_FILE


def _read_head(path, limit=4096):
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")[:limit]
    except OSError:
        return ""


def _json_has_marker(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return False
    marker = data.get("srouter", {}).get("marker") if isinstance(data, dict) else None
    return marker == MARKER


def _has_marker(path):
    head = _read_head(path)
    if not head:
        return False
    if head.lstrip().startswith("{"):
        return _json_has_marker(path)
    first_line = head.splitlines()[0].strip() if head.splitlines() else ""
    if first_line.startswith("#"):
        first_line = first_line[1:].strip()
    return first_line == TEXT_MARKER


# ============================ known_markers migration table (issue #112 Часть 4) ============================
# State-based migration: detected_environment.known_markers = {surface: [marker, ...]}.
# install распознаёт ЛЮБОЙ маркер из таблицы как «свой» → мигрирует old→current. unmarked (нет ни current,
# ни legacy) → WARN, не adopt (канон fail-closed «никогда молча не adopt»). State может опережать код
# (новая версия маркера) или отставать — current всегда валиден.
def load_known_markers(state_path, surface, current_markers):
    """Union(current_markers, state.known_markers[surface]) без дубликатов.

    srouter.py (wrappers/zshrc/codenv) и configs-side переиспользуют: current из кода (всегда валиден) +
    legacy из state (migration). Без state/таблицы → только current (безопасный fallback, не угадываем).
    """
    state = local_state.load_state(path=state_path)
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    table = detected.get("known_markers") if isinstance(detected.get("known_markers"), dict) else {}
    known = list(table.get(surface) or [])
    for m in current_markers:
        if m not in known:
            known.append(m)
    return known


def populate_known_markers(state_path, surface, markers):
    """CLI-слой (srouter.py) регистрирует markers wrappers/zshrc/codenv в state (issue #112 Часть 4).

    lib НЕ знает о wrappers (layers: CLI зависит от lib, не наоборот) — данные передаются сверху.
    Idempotent: дубликаты не накапливаются. При install с новой версией маркера — old остаётся в таблице
    как legacy → следующий install мигрирует.
    """
    state, readable = local_state.load_state_checked(path=state_path)
    if not readable:
        return "state_unreadable"
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    table = detected.get("known_markers") if isinstance(detected.get("known_markers"), dict) else {}
    existing = list(table.get(surface) or [])
    for m in markers:
        if m not in existing:
            existing.append(m)
    table[surface] = existing
    detected["known_markers"] = table
    state["detected_environment"] = detected
    if local_state.save_state(state, path=state_path) is None:
        return "state_write_failed"
    return ""


def _port_owner(name, runner):
    proto, port = PORTS[name]
    if proto == "udp":
        cmd = [LSOF, "-nP", f"-iUDP:{port}"]
    else:
        cmd = [LSOF, "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"]
    result = runner(cmd, 5)
    out = result.get("out") or ""
    if result.get("timeout") or not out:
        return {}
    for line in out.splitlines():
        if line.upper().startswith("COMMAND"):
            continue
        fields = line.split()
        if len(fields) >= 2:
            return {"command": fields[0], "pid": fields[1], "user": fields[2] if len(fields) > 2 else "", "raw": line}
    return {}


# Конфликты, которые reclaimable («свой старый»: state.managed=True, маркер пропал) авто-разрешает.
# cycle-review #111 cycle 1 finding 2: reclaimable покрывает ТОЛЬКО stale-marker-состояние
# (foreign_config — конфиг без маркера, foreign_port — порт занят). non_brew_binary — отдельная угроза
# (чужой бинарник рядом), НЕ должна поглощаться reclaimable → install/restart brew-сервиса при живом
# чужом бинарнике = конкуренция/падение. downstream-фильтры (apply_install, cmd_install) exempt компонент
# только если reclaimable И ВСЕ его конфликты ∈ RECLAIMABLE_RESOLVES.
RECLAIMABLE_RESOLVES = frozenset({"foreign_config", "foreign_port"})


def _reclaimable_resolves_all_conflicts(item):
    """True если reclaimable-компонент можно авторазрешить без явного adopt/overwrite/skip.

    reclaimable должен покрывать КАЖДЫЙ конфликт компонента. non_brew_binary (или будущий conflict-тип)
    НЕ покрыт → компонент блокируется (требует решения), даже если reclaimable=True.
    """
    if not item.get("reclaimable"):
        return False
    conflicts = item.get("conflicts") or []
    return all(c in RECLAIMABLE_RESOLVES for c in conflicts)


def _inspect_component(name, env, runner, port_checker, prior_detected=None):
    """Инспекция одного компонента для build_plan (discovery, ничего не пишет).

    `managed` определяется ДВУМЯ арбитрами (issue #110 Дефект 2):
      - marker_managed: srouter-маркер в самом конфиге («живой» арбитр, но теряется при смене версии/правке).
      - state_managed:  detected_environment[name].management из srouter.local.json («память» — install сам
        пишет её через _write_state_after_apply). До #110 install её игнорировал → «свой старый» конфиг
        (state.managed=True, маркер пропал) считался foreign → конфликт → non-TTY install падал rc=2 сразу
        после uninstall. Корень #110: двойное определение managed (uninstall верил state, install — файлу).

    reclaimable = state_managed AND NOT marker_managed AND NOT state_restored — «свой старый»: install
    ставил, маркер пропал. Авторазрешается с backup (apply_install), НЕ требует adopt/overwrite/skip.
    state_restored (mode='restored') — легально возвращённый uninstall'ом чужой конфиг → НЕ reclaimable,
    остаётся foreign_config (install не должен молча перезаписать чужое).
    """
    prior_detected = prior_detected or {}
    paths = env.component_paths(name)
    config_path = paths["config"]
    marker_managed = config_path.exists() and _has_marker(config_path)
    prior = prior_detected.get(name) if isinstance(prior_detected.get(name), dict) else {}
    state_managed = _is_managed_entry(prior)
    state_restored = _is_restored_entry(prior)
    # Привязка ownership к пути (cycle-review #111 cycle 1 finding 1): state.managed авторизует только
    # конфиг по ТОМУ ЖЕ пути, что записан в state. Смена --prefix (/opt/homebrew → /usr/local) или любое
    # другое перемещение → state от старого расположения НЕ делает чужой markerless-конфиг по новому пути
    # reclaimable (иначе install молча перезаписал бы его + рестарт сервиса без adopt/overwrite/skip).
    prior_path = prior.get("config_path") if isinstance(prior.get("config_path"), str) else ""
    state_owns_path = bool(prior_path) and str(Path(prior_path)) == str(config_path)
    managed = marker_managed or (state_managed and state_owns_path)
    stale_managed = state_managed and state_owns_path and not marker_managed
    owner = _port_owner(name, runner)
    _proto, port = PORTS[name]
    try:
        listening = bool(port_checker("127.0.0.1", port, timeout=0.5))
    except (OSError, TimeoutError, ValueError, TypeError, OverflowError) as exc:
        listening = False

    non_brew = [str(p) for p in paths["non_brew"] if p.exists()]
    config_present = config_path.exists()
    # reclaimable: «свой старый» (state помнит install по этому пути, маркер пропал), НЕ restored-чужой.
    # config_present обязан быть True — иначе восстанавливать нечего (install создаст новый конфиг).
    reclaimable = stale_managed and config_present and not state_restored
    conflicts = []
    if config_present and not managed:
        conflicts.append("foreign_config")
    # foreign_port: порт занят И слушатель НЕ подтверждён наш. Для marker_managed (маркер на месте) — слушатель
    # это наш brew-сервис (мы им владеем), конфликта нет. Для stale-managed (state managed, маркер пропал) —
    # слушатель МОЖЕТ быть чужим (cycle-review #111 cycle 2 finding D): brew restart поверх чужого процесса =
    # конкуренция/падение. Гасим foreign_port только по marker_managed (живой арбитр), не по state.
    if owner and not marker_managed:
        conflicts.append("foreign_port")
    if non_brew:
        conflicts.append("non_brew_binary")

    return {
        "name": name,
        "port": port,
        "protocol": PORTS[name][0],
        "config_path": str(config_path),
        "config_present": config_present,
        "config_managed": managed,
        "reclaimable": reclaimable,
        "brew_binary_present": paths["brew_binary"].exists(),
        "non_brew_binaries": non_brew,
        "service": "unknown",
        "listening": listening,
        "port_owner": owner,
        "conflicts": conflicts,
        "conflict": bool(conflicts),
    }


def _discover_network(runner):
    gateway = ""
    route = runner([ROUTE, "-n", "get", "default"], 3)
    for line in (route.get("out") or "").splitlines():
        line = line.strip()
        if line.startswith("gateway:"):
            gateway = line.split(":", 1)[1].strip()
            break

    wifi_service = ""
    usb_service = ""
    services = runner([NETWORKSETUP, "-listallnetworkservices"], 4)
    for raw in (services.get("out") or "").splitlines():
        name = raw.strip().lstrip("*").strip()
        low = name.lower()
        if not wifi_service and ("wi-fi" in low or "wifi" in low):
            wifi_service = name
        if not usb_service and ("usb" in low or "iphone" in low or "tether" in low):
            usb_service = name

    # cycle-review PR #295 (Codex): вызывающий код (_restore_dns) обязан отличать "сервисов
    # реально нет" от "сам запрос -listallnetworkservices провалился/протаймаутил" — иначе
    # transient-сбой discovery молча трактуется как легитимно-пустой список. Пробрасываем
    # rc/timeout самого probe-вызова отдельным полем, не трогая существующую форму channels.
    probe_ok = not services.get("timeout") and services.get("rc") == 0
    return {
        "gateway": gateway,
        "channels": {"wifi_service": wifi_service, "usb_tether_service": usb_service},
        "services_probe": {"ok": probe_ok, "rc": services.get("rc"), "timeout": services.get("timeout")},
    }


def _discover_probe_readiness(state_path, port_checker):
    readiness = {}
    for node in local_state.load_nodes(path=state_path):
        probe = node.get("probe") if isinstance(node.get("probe"), dict) else {}
        port = probe.get("socks_port")
        try:
            port = int(port)
            ready = bool(port_checker("127.0.0.1", port, timeout=0.25))
        except (OSError, TimeoutError, ValueError, TypeError, OverflowError) as exc:
            ready = False
        readiness[node.get("name") or ""] = {"socks_port": port, "ready": ready}
    return readiness


def _homebrew_available(runner):
    if Path(BREW).exists():
        return True
    result = runner([BREW, "--version"], 5)
    return result.get("rc") == 0


def _privoxy_protected_for_env(env):
    """State — главный контракт; physical fallback только для канонического production state.

    Иначе unit/acceptance с временным --state начали бы зависеть от живого /Library на host после
    активации защиты (#122) и скрывали бы legacy install-ветки.
    """
    if privoxy_system.state_protected(env.state_path):
        return True
    try:
        canonical = (ROOT / "srouter.local.json").resolve()
        requested = Path(env.state_path).resolve()
    except OSError:
        return False
    return requested == canonical and privoxy_system.protection_present()


def build_plan(env=None, runner=run, port_checker=port_open):
    """Discovery-only: ничего не пишет."""
    env = env or InstallEnv.from_env()
    # State грузим ОДИН раз ВВЕРХ (issue #110 Дефект 2): detected_environment нужен в _inspect_component
    # как второй арбитр managed (stateManaged) — без него «свой старый» конфиг = foreign. Раньше state
    # грузился после цикла inspect и читал только probes; теперь пробрасываем detected_env в inspect.
    state = local_state.load_state(path=env.state_path)
    detected_env = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    brew_services = runner([BREW, "services", "list"], 8)
    service_states = _parse_brew_services(brew_services.get("out") or "")
    components = {}
    for name in COMPONENTS:
        item = _inspect_component(name, env, runner, port_checker, prior_detected=detected_env)
        if name == "privoxy" and _privoxy_protected_for_env(env):
            # Protected mode — отдельная system-domain ownership boundary. Legacy install обязан
            # сохранить её и НЕ создавать конкурирующий user LaunchAgent через brew services.
            item.update({
                "protected": True,
                "config_path": str(privoxy_system.DEFAULT_LAYOUT.config_path),
                "config_present": privoxy_system.DEFAULT_LAYOUT.config_path.exists(),
                "config_managed": True,
                "reclaimable": False,
                "conflicts": [],
                "conflict": False,
                "service": "protected-system",
            })
        else:
            item["service"] = service_states.get(name, "none" if brew_services.get("rc") == 0 else "unknown")
        components[name] = item

    probes = state.get("probes") if isinstance(state.get("probes"), dict) else {}
    return {
        "mode": "plan",
        "state_path": str(env.state_path),
        "homebrew": {"available": _homebrew_available(runner), "path": BREW},
        "components": components,
        "network": _discover_network(runner),
        "probes": {
            "reachability_targets": probes.get("reachability_targets", []),
            "throughput_targets": probes.get("throughput_targets", []),
            "connect_timeout_sec": probes.get("connect_timeout_sec"),
            "max_time_sec": probes.get("max_time_sec"),
            "per_node_socks": _discover_probe_readiness(env.state_path, port_checker),
        },
        "launchagent": {
            "label": LAUNCHAGENT_LABEL,
            "template_path": str(_launchagent_template_path(env)),
            "plist_path": str(env.launchagent_path()),
            "dashboard_path": str(env.root / "dashboard.py"),
            "python_bin": env.python_bin,
            "loopback_only": True,
            "managed": env.launchagent_path().exists() and _has_launchagent_marker(env.launchagent_path()),
        },
        "state_sections_to_write": ["detected_environment", "network", "runtime"],
        "backup_suffix": ".srouter-backup-<timestamp>",
    }


def format_plan(plan):
    lines = [
        "srouter install plan",
        f"- state: {plan.get('state_path')}",
        f"- Homebrew: {'ok' if plan.get('homebrew', {}).get('available') else 'missing'} ({BREW})",
        "- apply запишет секции local-state: " + ", ".join(plan.get("state_sections_to_write", [])),
        "- root/system действия: brew services restart dnsmasq; networksetup DNS для найденного Wi-Fi",
        "- backup при overwrite: <config>" + plan.get("backup_suffix", ""),
        "",
        "Компоненты:",
    ]
    for name, item in plan.get("components", {}).items():
        conflict = "CONFLICT" if item.get("conflict") else "ok"
        if item.get("protected"):
            conflict = "PROTECTED"
        lines.append(
            f"- {name}: {conflict}; config={item.get('config_path')}; "
            f"managed={item.get('config_managed')}; service={item.get('service')}; "
            f"port_owner={item.get('port_owner') or '-'}"
        )
        if item.get("conflicts"):
            lines.append(f"  выбор обязателен: --{name} adopt|overwrite|skip; причины: {', '.join(item['conflicts'])}")
    lines.append("")
    launchagent = plan.get("launchagent") or {}
    lines.append(
        f"- LaunchAgent: {launchagent.get('label')} -> {launchagent.get('plist_path')} "
        f"(dashboard loopback-only 127.0.0.1)"
    )
    lines.append("")
    lines.append("plan ничего не пишет. Для применения: ./install.sh apply --yes [--xray ... --privoxy ... --dnsmasq ...]")
    return "\n".join(lines)


_BACKUP_INFIX = ".srouter-backup-"


def _backup_suffix(now):
    """Timestamp-суффикс имени backup: env.now с вырезанными недопустимыми в имени файла символами."""
    return now.replace(":", "").replace("/", "-")


def _backup(path, env):
    if not path.exists():
        return ""
    backup = path.with_name(path.name + _BACKUP_INFIX + _backup_suffix(env.now))
    try:
        shutil.copy2(path, backup)
        return str(backup)
    except OSError:
        return ""


def _record_state_effect(env, mutate):
    """Единый примитив effect-time записи state (issue #293, структурный фикс).

    Канон two-phase (AGENTS.md) в форме write-близко-к-side-effect: каждый side-effect apply_install
    фиксирует свой УЖЕ СВЕРШИВШИЙСЯ результат в state сразу (load → mutate → save), а не батчит его
    в финальную _write_state_after_apply. Три раунда cycle-review PR #290 находили по одному полю за
    раунд в одной модели («финальная запись как proof of recency для фактов, случившихся раньше») —
    список полей открытый, поэтому закрыт СЛОЙ, а не поле.

    FAIL-CLOSED: не удалось прочитать/записать state → вызывающий обязан прервать apply; продолжать
    side-effect'ы, чья rollback-история не фиксируется, нельзя (та же граница, что _record_backup_intent).

    Возвращает "" при успехе, иначе код ошибки ("state_unreadable" | "state_write_failed").
    """
    state, readable = local_state.load_state_checked(path=env.state_path)
    if not readable:
        return "state_unreadable"
    mutate(state)
    if local_state.save_state(state, path=env.state_path) is None:
        return "state_write_failed"
    return ""


def _record_backup_intent(env, name, config_path, backup):
    """State-first (issue #124, часть 2/2): зафиксировать ссылку на backup ДО мутации target.

    ПОЧЕМУ. backup-файл на диске и entry в state — два независимо-атомарных артефакта. До этой
    функции state писался ОДИН раз, в самом конце apply_install (_write_state_after_apply), а между
    созданием backup и этой записью лежат МИНУТЫ: до трёх `brew install` (timeout 180s), три
    _restart_component (stop+poll+start+poll), _apply_dns, _install_launchagent. Любой ранний return
    внутри цикла по COMPONENTS или обрыв процесса минуют финальную запись — и ссылка на уже созданный
    backup испаряется вместе с локальным dict. Дефект эксплуатируется БЕЗ всякого crash: достаточно
    штатного сбоя `brew install` на ВТОРОМ компоненте после успешного overwrite первого.

    ПОЧЕМУ ГОЛЫЙ ENTRY, БЕЗ management. Владение файлом арбитрируется маркером на диске
    (component_facts, часть 1/2), а не памятью state — entry здесь несёт ТОЛЬКО config_path и backup.
    Managed-запись ДО мутации target объявила бы владение файлом, который ещё не тронут: обрыв в
    зазоре между этой функцией и _write_component_config оставил бы target = чистый оригинал
    пользователя, а state утверждал бы managed/overwrote → uninstall докладывал бы leftover rc=2 на
    абсолютно чистой системе (issue #110 Дефект 1 — ложь оператору). Голый entry инертен для всех
    предикатов (_is_managed_entry/_is_adopted_entry/_is_restored_entry/_provenance_of → False/None) и
    классифицируется component_facts верно на ОБОИХ концах окна: target нетронут → 'none', target
    перезаписан → 'orphaned_backup' (restore). Окончательную форму владения (mode/managed/provenance)
    дописывает _write_state_after_apply при успешном завершении apply.

    ПОЧЕМУ НЕ pending/promote. Канон two-phase (AGENTS.md) требует pending intent → apply → promote.
    Здесь он не применим буквально: pending — заявка о том, что ЕЩЁ НЕ случилось, и ей нужен promote,
    а promote заводит собственное окно, требующее своего патча (так в PR #119 родился F1). Здесь же
    фиксируется факт, который УЖЕ случился и подтверждён на диске (shutil.copy2 отработал) — факт не
    нуждается в промоушене, только в том, чтобы быть записанным раньше, чем станет незаменимым.
    С issue #293 это не отдельный приём, а первый экземпляр общего слоя _record_state_effect:
    каждый side-effect пишет свой результат сам, финальная запись — сверка.

    FAIL-CLOSED: не удалось прочитать/записать state → вызывающий обязан прервать apply ДО мутации
    target — иначе конфиг пользователя был бы перезаписан, а ссылку на его копию восстановить неоткуда.

    Возвращает "" при успехе, иначе код ошибки ("state_unreadable" | "state_write_failed").
    """
    def mutate(state):
        detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
        prev = detected.get(name) if isinstance(detected.get(name), dict) else {}
        entry = dict(prev)  # merge: если prev уже нёс management (idempotent/reclaimable) — не сносим его
        entry["config_path"] = str(config_path)
        entry["backup"] = str(backup)
        detected[name] = entry
        state["detected_environment"] = detected

    return _record_state_effect(env, mutate)


def _parse_backup_stamp(name):
    """'2026-06-29T000000Z' → datetime, иначе None. Единственный источник правды о формате имени.

    Формат задаёт _backup: _backup_suffix(env.now), где env.now — ISO-8601 UTC-Z из _now() с
    вырезанными ':' и '/'. Разбор ОБРАТНОЙ операцией (а не «почти-regex» вроде \\d+) — канон
    probe-semantics-from-primary-source / loose-validator-recurring-leak: не парсится этим форматом —
    значит файл создан не нами.
    """
    try:
        return datetime.strptime(name, "%Y-%m-%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _parse_backup_stamp_or_none(value):
    """entry['created_at'] (ISO-8601 из env.now, формат _now()) → datetime, иначе None.

    Отдельно от _parse_backup_stamp: created_at хранится в НЕОБРЕЗАННОМ ISO-8601 (с ':'), потому что
    он пишется в state как обычная временная метка (симметрично restored_at/removed_at), а не как
    часть имени файла — обрезка нужна только там, где ':' недопустим в имени. Разбор обратной
    операцией к _now(); не парсится — значит поле повреждено/чужеродно, границу не применяем
    (fail-closed в сторону «не сужать» — отсутствие валидной границы не должно ложно отбрасывать
    настоящие кандидаты).
    """
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def discover_backups(config_path):
    """Валидные srouter-backup'ы, лежащие рядом с config_path, от старых к новым (issue #124).

    ЗАЧЕМ. Ссылка на backup хранится в state, но между созданием backup-файла и записью state лежат
    минуты (brew install/restart всех компонентов). Обрыв в этом окне терял ссылку, и uninstall
    оставлял пользовательский оригинал orphaned навсегда (P1-3, самый дорогой из 6 P1 issue #124).
    Backup-файл самоописывающийся и лежит ВПЛОТНУЮ к target, поэтому он обнаружим из одного лишь
    config_path — как srouter-маркер в самом конфиге, который проект уже канонизировал как «живой
    арбитр» (_has_marker). Разница между «state помнит backup» и «backup сам себя предъявляет» — это
    разница между памятью и доказательством; канон verify-dont-guess требует второго.

    ГРАНИЦА СЛОЯ. Функция отвечает на вопрос о МИРЕ («какие backup'ы этого конфига существуют»), а не
    о механике install'а («был ли crash / в какой фазе / был ли pending»). Поэтому её вправе звать и
    uninstall — он не узнаёт ничего о том, как install пишет. Утечка WAL-механики в uninstall и была
    провалом PR #119 (см. tests/test_install_layering.py).

    FAIL-CLOSED. Похожее имя ещё не делает файл нашим:
      - fullmatch с якорем, а не glob: glob('config.srouter-backup-*') поймал бы хвостовой
        'config.srouter-backup-x.tmp' от атомарной записи и вложенный двойной суффикс;
      - суффикс обязан парситься форматом _backup (_parse_backup_stamp);
      - только regular file: симлинк с валидным именем — вектор подмены (restore записал бы
        содержимое по чужому пути), directory — не backup.
    Возврат отсортирован по метке времени ДЕТЕРМИНИРОВАННО — для воспроизводимых сообщений оператору,
    но НЕ для автовыбора «самого свежего»: при обрыве второго install свежий backup — копия
    srouter-конфига, а оригинал пользователя в самом старом (см. _resolve_backup).
    """
    path = Path(config_path)
    try:
        candidates = list(path.parent.iterdir())
    except OSError:
        return []
    prefix = path.name + _BACKUP_INFIX
    found = []
    for candidate in candidates:
        if not candidate.name.startswith(prefix):
            continue
        stamp = _parse_backup_stamp(candidate.name[len(prefix):])
        if stamp is None:
            continue
        try:
            if candidate.is_symlink() or not candidate.is_file():
                continue
        except OSError:
            continue
        found.append((stamp, candidate))
    return [candidate for _stamp, candidate in sorted(found, key=lambda pair: (pair[0], pair[1].name))]


def _write_component_config(name, env):
    path = env.component_paths(name)["config"]
    if name == "xray":
        return gen_xray_config.write_config(path, state_path=env.state_path)
    template = env.root / "templates" / ("privoxy.config" if name == "privoxy" else "dnsmasq.conf")
    try:
        text = template.read_text(encoding="utf-8")
    except OSError:
        return False
    return _write_text_atomic(path, text)


def _traffic_guard_preflight_error(env):
    errors = gen_xray_config.traffic_guard_validation_errors(state_path=env.state_path)
    if not errors:
        return ""
    return "traffic_guard невалиден: " + "; ".join(errors)


def _ensure_package(name, runner):
    listed = runner([BREW, "list", "--versions", name], 12)
    if listed.get("rc") == 0 and listed.get("out"):
        return True
    installed = runner([BREW, "install", name], 180)
    return installed.get("rc") == 0


def _restart_component(name, runner, *, port_checker=port_open):
    """Рестарт brew-сервиса без гонки за порт: stop → poll освобождения порта → start → poll поднятия.

    Раньше был слепой `brew services restart` — он атомарно убивает старый и поднимает новый процесс,
    но старый может ещё держать порт (TIME_WAIT / медленный shutdown) → новый падает `Fatal: can't
    bind to 127.0.0.1:8118` → launchd KeepAlive молотит рестарты (issue #115 симптом 2). Гонка
    исключена СТРУКТУРНО: новый процесс стартует ТОЛЬКО после подтверждённого освобождения порта, а
    успех подтверждается поднятием порта. Симметрично канонному эталону _launchd_reload
    (bootout→poll выгрузки→bootstrap-retry).

    poll доказывает состояние порта через port_checker (verify-dont-guess: не фиксированный sleep).
    Константы _PORT_SETTLE_* / _PORT_UP_MAX_WAIT уровня модуля → тесты зануляют для мгновенных прогонов.

    dnsmasq (UDP 53) идёт под sudo, как и прежде. Возвращает dict как runner (rc/out/err/timeout);
    при провале stop/start/poll — ненулевой rc с причиной в err, не бросает.
    """
    _proto, port = PORTS[name]
    host = "127.0.0.1"

    def _port_busy():
        return bool(port_checker(host, port, 0.5))

    # 1. stop (игнорируем rc — «уже остановлен» = не ошибка, симметрично bootout в _launchd_unload).
    if name == "dnsmasq":
        runner([SUDO, BREW, "services", "stop", "dnsmasq"], 60)
        start_cmd = [SUDO, BREW, "services", "start", "dnsmasq"]
    else:
        runner([BREW, "services", "stop", name], 40)
        start_cmd = [BREW, "services", "start", name]

    # 2. poll освобождения порта: ждём, пока старый процесс реально отпустит порт. deadline по часам
    #    (как _launchd_unload), иначе при interval=0 (тесты) цикл был бы бесконечным. Один poll-loop
    #    проверяет каждое состояние ОДИН раз — повторный вызов port_checker между while и if дал бы
    #    расхождение с эмулированной последовательностью состояний в тестах.
    deadline = time.monotonic() + _PORT_SETTLE_MAX_WAIT
    busy = _port_busy()
    while busy and time.monotonic() < deadline:
        time.sleep(_PORT_SETTLE_POLL_INTERVAL)
        busy = _port_busy()
    if busy:
        # fail-closed: порт не освободился → НЕ поднимаем новый поверх (петля рестартов / конкуренция).
        return {"rc": 1, "out": "", "err": f"{name}_port_still_busy", "timeout": False}

    # 3. start.
    started = runner(start_cmd, 60 if name == "dnsmasq" else 40)
    if started.get("timeout") or started.get("rc") != 0:
        return started

    # 4. poll поднятия порта: brew services start асинхронен, порт поднимается с задержкой.
    deadline = time.monotonic() + _PORT_UP_MAX_WAIT
    up = _port_busy()
    while not up and time.monotonic() < deadline:
        time.sleep(_PORT_SETTLE_POLL_INTERVAL)
        up = _port_busy()
    if not up:
        return {"rc": 1, "out": "", "err": f"{name}_port_not_up", "timeout": False}
    return {"rc": 0, "out": "", "err": "", "timeout": False}


def _apply_dns(env, plan, runner):
    service = plan.get("network", {}).get("channels", {}).get("wifi_service") or ""
    if not service:
        return {"rc": 0, "out": "", "err": "wifi service not found", "timeout": False}
    return runner([NETWORKSETUP, "-setdnsservers", service, "127.0.0.1"], 20)


def _management_for(mode, item, *, provenance=None):
    # provenance (issue #112 Часть 1): 'created' | 'overwrote' | None. Только для mode=='managed':
    # created = config_path НЕ существовал до install (нет backup), overwrote = существовал (есть backup).
    # Uninstall (Часть 2) различает: created → удалить, overwrote → restore. None — adopted/skipped/restored
    # (srouter не перезаписывал, semantics не применима). Опускается, если None (обратная совместимость state).
    management = {"mode": mode, "managed": mode == "managed"}
    if provenance is not None:
        management["provenance"] = provenance
    return {
        "config_path": item.get("config_path"),
        "port": item.get("port"),
        "service": item.get("service"),
        "port_owner": item.get("port_owner"),
        "management": management,
    }


def _applied_component_entry(prev, item, mode, backup, *, now):
    """Единственный редьюсер entry компонента в detected_environment после его apply-эффекта.

    ОБЩИЙ СЛОЙ (issue #293, структурный фикс): эту форму раньше вычисляла ТОЛЬКО финальная
    _write_state_after_apply — теперь её же вычисляет effect-time _record_component_applied сразу
    после config-write+restart. Одна реализация для обоих писателей — иначе расхождение двух
    реализаций одной истины (корневой класс #110/#124) воспроизвелось бы на новом уровне.

    provenance (issue #112 Часть 1): только для managed. backup truthy ⟺ config существовал до
    install (needs_backup): created = свежий с нуля, overwrote = перезаписан чужой.
    """
    provenance = None
    if mode == "managed":
        provenance = "overwrote" if backup else "created"
    # cycle-review cloud (@bbc356a) P1: idempotent reinstall НЕ должен терять существующий backup/provenance.
    # Если этот apply не создавал/не перезаписывал файл (backup пуст — target уже marker-managed,
    # не конфликт) НО prev уже managed с backup — preserve prev.backup/provenance. Иначе _management_for
    # перезаписывал entry → provenance='created' + backup утерян → следующий uninstall УДАЛЯЛ srouter-config
    # вместо restore пользовательского оригинала (потеря в цикле install→reinstall→uninstall).
    # cycle-review cloud round 2 (@307bb34) P1: path-ownership guard. Preserve ТОЛЬКО когда prev.config_path
    # совпадает с текущим item.config_path. Смена --prefix (A→B): prev под путём A, текущий B → backup A НЕ
    # переносится на B (иначе uninstall restore'ит A's foreign-конфиг в B, обход path-ownership, cycle-review
    # #111 finding 1). Привязка ownership к пути — тот же канон, что _inspect_component state_owns_path.
    prev_same_path = (str(Path(prev.get("config_path") or "")) == str(item.get("config_path"))
                      if prev.get("config_path") else False)
    # issue #124 (F3/P1-2), часть 2/2: backup — свойство ПРОШЛОГО (файл .srouter-backup-* лежит
    # на диске и не исчезает от смены режима), provenance — свойство ТЕКУЩЕГО apply (создали/
    # перезаписали именно сейчас). Поэтому carried_backup вычисляется по одному-единственному
    # ограничителю (prev_same_path — path-ownership guard, cycle-review #111 finding 1) и НЕ
    # гейтится mode=='managed': раньше обе ветки preserve гейтились managed, и повторный apply со
    # skip/adopt после оборванного overwrite перезаписывал entry БЕЗ backup — оригинал пользователя
    # осиротевал, хотя его копия лежала рядом с target (_record_backup_intent пишет голый entry
    # без management, поэтому _is_managed_entry(prev) на нём ложен — гейтить backup-ветку им нельзя).
    # provenance-ветка гейт managed СОХРАНЯЕТ: при skip/adopt действия «создали/перезаписали» не
    # было, поле неприменимо (test_install_skipped_has_no_provenance) и не влияет на классификацию
    # component_facts для не-managed entry — писать его значило бы плодить противоречивый мусор.
    carried_backup = prev.get("backup") if prev_same_path else None
    if mode == "managed" and not backup and _is_managed_entry(prev) and carried_backup:
        provenance = _provenance_of(prev) or "overwrote"
    entry = _management_for(mode, item, provenance=provenance)
    backup_ref = backup or carried_backup
    if backup_ref:
        entry["backup"] = backup_ref
    # cycle-review PR #290 (Codex + /review, независимо): created_at — нижняя граница возраста
    # backup'а, который discover_backups вправе засчитать за «доказательство overwrite ЭТОГО
    # install». Без неё retained backup (сохраняется НАМЕРЕННО, user_data_retained) от давно
    # завершённого install→uninstall цикла неотличим от backup'а текущего цикла: пользователь
    # вручную удаляет восстановленный файл, следующий install создаёт конфиг с нуля
    # (provenance='created', backup не пишется), а uninstall всё ещё находит СТАРЫЙ backup рядом
    # и восстанавливает устаревший чужой контент вместо удаления свежесозданного конфига.
    # Пишем только при 'created' — тем самым фиксируя момент, раньше которого валидных backup'ов
    # для ЭТОГО конфига быть не может; 'overwrote' в этой границе не нуждается (backup уже
    # известен по имени). Idempotent reinstall (той же строкой provenance) обязан СОХРАНИТЬ
    # исходный created_at, а не обновлять его на новый now — иначе повторный install молча
    # расширял бы окно доверия и снова впускал тот же старый backup.
    if provenance == "created":
        entry["created_at"] = (
            prev.get("created_at")
            if mode == "managed" and _is_managed_entry(prev) and prev_same_path and prev.get("created_at")
            else now
        )
    return entry


def _launchagent_entry(launchagent, now):
    """Форма detected_environment.launchagent (общий слой effect-time записи и финальной сверки)."""
    return {
        "label": launchagent.get("label"),
        "plist_path": launchagent.get("plist_path"),
        "dashboard_path": launchagent.get("dashboard_path"),
        "python_bin": launchagent.get("python_bin"),
        "management": {"mode": "managed", "managed": True},
        "last_loaded_at": now,
    }


def _record_network_channels(env, network):
    """Effect-time запись discovery-факта (network.channels) — ДО любых side-effect'ов apply.

    Каналы открываются в build_plan (discovery), и это факт о мире независимо от того, докатится ли
    apply до финальной записи. Раньше channels писались ТОЛЬКО в конце: холодный старт (state-файла
    ещё нет) + обрыв после _apply_dns = DNS реально указан на 127.0.0.1, а state не знает канала —
    rollback молча no-op'ился (issue #293 P1b, точечно закрыт #295 live-discovery; здесь закрыт
    СЛОЙ: знание пишется там же, где открыто). Fail-closed: отказ записи прерывает apply.
    """
    def mutate(state):
        merged = state.get("network") if isinstance(state.get("network"), dict) else {}
        merged.update(network or {})
        state["network"] = merged

    return _record_state_effect(env, mutate)


def _record_component_applied(env, name, item, mode, backup):
    """Effect-time запись формы владения компонента сразу после config-write+restart.

    mode/provenance/created_at существовали только в локальных переменных apply_install до финальной
    записи — обрыв испарял их, и каждое новое поле того же класса требовало очередного раунда
    cycle-review (issue #293 диагноз). Теперь эффект дописывает свою форму сам через ОБЩИЙ редьюсер
    _applied_component_entry — та же форма, которую сверит финальная запись.
    """
    def mutate(state):
        detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
        prev = detected.get(name) if isinstance(detected.get(name), dict) else {}
        detected[name] = _applied_component_entry(prev, item, mode, backup, now=env.now)
        state["detected_environment"] = detected

    return _record_state_effect(env, mutate)


def _record_launchagent_applied(env, plan):
    """Effect-time запись факта установки LaunchAgent (симметрично _record_component_applied)."""
    launchagent = plan.get("launchagent") or {}

    def mutate(state):
        detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
        detected["launchagent"] = _launchagent_entry(launchagent, env.now)
        state["detected_environment"] = detected

    return _record_state_effect(env, mutate)


def _write_state_after_apply(env, plan, modes, backups, launchagent_action=None):
    """Финальная СВЕРКА state (reconciliation), не единственный источник фактов (issue #293).

    После структурного фикса каждый side-effect уже записал свой результат (_record_backup_intent,
    _record_network_channels, _record_component_applied, _record_launchagent_applied); здесь те же
    значения пересчитываются теми же редьюсерами (_applied_component_entry/_launchagent_entry) —
    запись идемпотентна и не изобретает новых фактов. Единственное содержательно новое здесь —
    bookkeeping без side-effect-семантики: brew/last_checked_at/runtime.last_apply.
    """
    state, readable = local_state.load_state_checked(path=env.state_path)
    if not readable:
        return "state_unreadable"
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    for name, item in plan["components"].items():
        mode = modes.get(name, "skipped")
        prev = detected.get(name) if isinstance(detected.get(name), dict) else {}
        if mode == "protected":
            # Не переписываем protection/previous/backup, которые создала двухфазная root-транзакция.
            # Reinstall лишь подтверждает, что защищённый компонент намеренно оставлен как есть.
            detected[name] = dict(prev)
            detected[name]["service"] = "protected-system"
            continue
        detected[name] = _applied_component_entry(prev, item, mode, backups.get(name), now=env.now)
    if launchagent_action:
        detected["launchagent"] = _launchagent_entry(plan.get("launchagent") or {}, env.now)
    detected["brew"] = plan.get("homebrew")
    detected["last_checked_at"] = env.now
    state["detected_environment"] = detected

    network = state.get("network") if isinstance(state.get("network"), dict) else {}
    network.update(plan.get("network") or {})
    state["network"] = network

    runtime = state.get("runtime") if isinstance(state.get("runtime"), dict) else {}
    runtime["last_apply"] = env.now
    runtime["last_error"] = None
    state["runtime"] = runtime
    if local_state.save_state(state, path=env.state_path) is None:
        return "state_write_failed"
    return ""


def apply_install(env=None, *, confirm=False, choices=None, runner=run, port_checker=port_open, install_launchagent=True, force_endpoint_overwrite=False):
    """Применить план. Без confirm или без выбора по конфликту ничего не пишет."""
    env = env or InstallEnv.from_env()
    choices = choices or {}
    if not confirm:
        return {"ok": False, "blocked": ["confirmation_required"], "actions": []}

    plan = build_plan(env=env, runner=runner, port_checker=port_checker)
    unresolved = []
    for name, item in plan["components"].items():
        choice = choices.get(name)
        # reclaimable («свой старый»: state.managed=True, маркер пропал) — НЕ конфликт для пользователя
        # (issue #110 Дефект 2): авторазрешается в managed-режим с backup. Иначе non-TTY install падал
        # rc=2 сразу после uninstall. НО только если reclaimable покрывает ВСЕ конфликты (cycle-review
        # #111 cycle 1 finding 2): non_brew_binary и будущие conflict-типы НЕ поглощаются → блокируют.
        if item.get("conflict") and not _reclaimable_resolves_all_conflicts(item) and choice not in CHOICES:
            unresolved.append(name)
    if unresolved:
        return {"ok": False, "blocked": unresolved, "actions": [], "plan": plan}

    _state, state_readable = local_state.load_state_checked(path=env.state_path)
    if not state_readable:
        return {"ok": False, "blocked": ["state_unreadable"], "actions": [], "plan": plan}

    modes = {}
    for name, item in plan["components"].items():
        if item.get("protected"):
            modes[name] = "protected"
        elif choices.get(name) == "adopt":
            modes[name] = "adopted"
        elif choices.get(name) == "skip":
            modes[name] = "skipped"
        else:
            modes[name] = "managed"

    if modes.get("xray") == "managed":
        guard_error = _traffic_guard_preflight_error(env)
        if guard_error:
            return {"ok": False, "blocked": ["traffic_guard_invalid"], "error": guard_error, "actions": [], "plan": plan}

    needs_brew = any(mode == "managed" for mode in modes.values())
    if needs_brew and not plan.get("homebrew", {}).get("available"):
        return {"ok": False, "blocked": ["homebrew_missing"], "actions": [], "plan": plan}

    # issue #293 (структурный фикс): discovery-факт (network.channels) фиксируется ПЕРВЫМ — до любых
    # мутаций. Все preflight-гейты выше уже прошли: дальше apply собирается мутировать мир, и знание,
    # нужное rollback'у (канал DNS), обязано быть в state раньше первого side-effect'а.
    channels_error = _record_network_channels(env, plan.get("network"))
    if channels_error:
        return {"ok": False, "blocked": [channels_error], "actions": [], "plan": plan}

    actions = []
    backups = {}
    for name in COMPONENTS:
        mode = modes.get(name)
        item = plan["components"][name]
        if mode in ("adopted", "skipped", "protected"):
            actions.append({"component": name, "mode": mode, "changed": False})
            continue

        if not _ensure_package(name, runner):
            return {"ok": False, "blocked": [f"{name}_install_failed"], "actions": actions, "plan": plan}
        config_path = Path(item["config_path"])
        # backup при overwrite ИЛИ reclaimable (issue #110 Дефект 2). reclaimable = «свой старый»
        # (state.managed=True, маркер пропал) — ВСЕГДА backup перед перезаписью (канон fail-closed):
        # если state устарел и под «своим старым» оказался чужой конфиг, он сохранится в .srouter-backup-*.
        # Без этого (раньше backup только при choice=='overwrite') reclaimable перезаписался бы без бэкапа.
        needs_backup = config_path.exists() and (choices.get(name) == "overwrite" or item.get("reclaimable"))
        if needs_backup:
            backup = _backup(config_path, env)
            if not backup:
                return {"ok": False, "blocked": [f"{name}_backup_failed"], "actions": actions, "plan": plan}
            # state-first (issue #124): порядок «backup на диск → state знает → мутация target»
            # обязателен без исключений. Между _backup и следующим оператором, способным завершить
            # функцию (включая xray endpoint-guard ниже — он бэкапится ДО этой проверки при
            # choices['xray']=='overwrite'/reclaimable), ничего не должно быть, иначе окно остаётся,
            # просто уже. Fail-closed: не смогли зафиксировать — не продолжаем, target не мутирован.
            intent_error = _record_backup_intent(env, name, config_path, backup)
            if intent_error:
                return {"ok": False, "blocked": [f"{name}_backup_state_write_failed"],
                        "error": intent_error, "actions": actions, "plan": plan}
            backups[name] = backup
        # #200: защита от перезаписи рабочего xray config placeholder'ом. gen_xray_config генерит из
        # local_state.active_node() — если state держит placeholder test-IP 203.0.113.x, а существующий
        # РАБОЧИЙ xray config — реальный VPS-address (вписан руками / старая генерация), apply перезаписал
        # бы рабочий config placeholder'ом и сломал прокси (когда VPS оживёт). srouter-critical-infra-24-7:
        # лучше заблокировать apply, чем затереть рабочий конфиг. force_endpoint_overwrite — осознанный
        # escape-hatch (как adopt для foreign-config): пользователь подтверждает перезапись.
        # cycle-review Codex critical 0.94: блокируем и когда СУЩЕСТВУЮЩИЙ xray config unreadable/no_active
        # (битый JSON / без active) при placeholder local — это НЕ fresh install (config существует),
        # перезапись + restart превратит recoverable on-disk corruption в outage. xray_status=absent
        # (= fresh install, файла нет) — единственный случай, где apply свободен.
        if name == "xray" and mode == "managed" and not force_endpoint_overwrite:
            cmp = local_state.compare_endpoint_with_xray(
                state_path=env.state_path, xray_config_path=config_path
            )
            if cmp["placeholder"] and not cmp["synced"]:
                xray_status = cmp.get("xray_status", "absent")
                if xray_status == "absent":
                    pass  # fresh install — нечего ломать, apply свободен
                elif xray_status in ("unreadable", "no_active"):
                    return {"ok": False, "blocked": ["xray_endpoint_overwrite_blocked"],
                            "error": (f"active_node endpoint_host={cmp['local']!r} — placeholder, а "
                                      f"СУЩЕСТВУЮЩИЙ xray config {config_path} — {xray_status} (битый/без "
                                      f"active). xray ещё может крутить ранее загруженный реальный endpoint; "
                                      f"apply перезапишет config placeholder'ом + restart → outage. "
                                      f"Почини xray config или --force-endpoint-overwrite для осознанной "
                                      f"перезаписи."),
                            "actions": actions, "plan": plan}
                else:  # ok + drift: рабочий xray держит реальный address, отличающийся от placeholder local
                    return {"ok": False, "blocked": ["xray_endpoint_overwrite_blocked"],
                            "error": (f"active_node endpoint_host={cmp['local']!r} — placeholder, а рабочий "
                                      f"xray config держит реальный address {cmp['xray']!r}. apply перезапишет "
                                      f"рабочий xray placeholder'ом и сломает прокси. "
                                      f"Запусти `srouter sync` (импорт address из xray в local.json) "
                                      f"или --force-endpoint-overwrite для осознанной перезаписи."),
                            "actions": actions, "plan": plan}
        if not _write_component_config(name, env):
            return {"ok": False, "blocked": [f"{name}_config_write_failed"], "actions": actions, "plan": plan}
        restart = _restart_component(name, runner, port_checker=port_checker)
        if restart.get("timeout") or restart.get("rc") != 0:
            return {"ok": False, "blocked": [f"{name}_restart_failed"], "actions": actions, "plan": plan}
        # issue #293 (структурный фикс): полный эффект компонента (config+restart) фиксирует форму
        # владения (mode/provenance/created_at/backup) СРАЗУ — до _apply_dns и до следующих
        # компонентов, не дожидаясь финальной сверки. Записано ровно то, что уже произошло:
        # маркер на диске подтверждает владение, значит claim managed честен (#110 Дефект 1 не
        # воспроизводится). Fail-closed: не зафиксировано — не продолжаем.
        effect_error = _record_component_applied(env, name, item, mode, backups.get(name))
        if effect_error:
            return {"ok": False, "blocked": [f"{name}_state_write_failed"], "error": effect_error,
                    "actions": actions, "plan": plan}
        if name == "dnsmasq":
            _apply_dns(env, plan, runner)
        actions.append({"component": name, "mode": mode, "changed": True})

    launchagent_action = None
    if install_launchagent:
        launchagent_ok, launchagent_error = _install_launchagent(env, runner)
        if not launchagent_ok:
            return {"ok": False, "blocked": [launchagent_error], "actions": actions, "plan": plan}
        # Префикс стадии — симметрично {name}_state_write_failed у компонентов: blocked-код обязан
        # быть самодостаточным (отказ effect-записи launchagent ≠ отказ финальной сверки в логе).
        la_state_error = _record_launchagent_applied(env, plan)
        if la_state_error:
            return {"ok": False, "blocked": [f"launchagent_{la_state_error}"],
                    "error": la_state_error, "actions": actions, "plan": plan}
        launchagent_action = {"component": "launchagent", "mode": "managed", "changed": True}
        actions.append(launchagent_action)

    state_error = _write_state_after_apply(env, plan, modes, backups, launchagent_action=launchagent_action)
    if state_error:
        return {"ok": False, "blocked": [state_error], "actions": actions, "plan": plan}
    return {"ok": True, "blocked": [], "actions": actions, "plan": plan}


def _is_managed_entry(entry):
    if not isinstance(entry, dict):
        return False
    management = entry.get("management") if isinstance(entry.get("management"), dict) else {}
    return management.get("managed") is True or management.get("mode") == "managed"


def _is_adopted_entry(entry):
    if not isinstance(entry, dict):
        return False
    management = entry.get("management") if isinstance(entry.get("management"), dict) else {}
    return management.get("mode") == "adopted"


def _is_restored_entry(entry):
    if not isinstance(entry, dict):
        return False
    management = entry.get("management") if isinstance(entry.get("management"), dict) else {}
    return management.get("mode") == "restored"


def _provenance_of(entry):
    """provenance компонента: 'created' | 'overwrote' | None (issue #112 Часть 2).

    None = legacy state (до #112, нет поля) или non-managed (adopted/skipped/restored — semantics
    не применима). created = srouter создал конфиг с нуля (нет backup). overwrote = перезаписал чужой.
    Симметрично по стилю _is_managed_entry/_is_adopted_entry/_is_restored_entry.
    """
    if not isinstance(entry, dict):
        return None
    management = entry.get("management") if isinstance(entry.get("management"), dict) else {}
    return management.get("provenance")


def _is_created_entry(entry):
    return _provenance_of(entry) == "created"


def _resolve_backup(entry, discovered, *, not_before=None, config_path=None):
    """Какой backup считать оригиналом пользователя: (path|None, ambiguous: bool).

    ПРИОРИТЕТ: названное state — сильнее найденного на диске. Discovery восполняет МОЛЧАНИЕ state
    (обрыв до записи), но не переспаривает его: подменить названный backup «похожим» соседом значит
    тихо восстановить чужой контент, выдав это за успешный откат.
      state назвал backup, файл жив   → (он, False)  — даже вне parent-директории target;
      state назвал backup, файл мёртв → (None, False) — НЕ подставляем найденное; component_facts
                                        даст leftover по state_backup_missing (оператор узнает);
      state молчит, 0 кандидатов (после фильтра not_before) → (None, False) — восстанавливать нечего;
      state молчит, ровно 1 (после фильтра)                 → (он, False)  — ради этого случая и
                                                                затевалась disk-discovery;
      state молчит, >1 (после фильтра)                      → (None, True) — ambiguous: оператору
                                                                список, fail-closed.

    Политика при НЕСКОЛЬКИХ кандидатах — не угадывать. Цикл install→uninstall→install штатно
    оставляет несколько .srouter-backup-*, и «взять самый свежий» — ловушка: при обрыве ВТОРОГО
    install самый свежий backup является копией srouter-конфига, а оригинал пользователя лежит в
    самом СТАРОМ. Молчаливый автовыбор потерял бы его — ровно тот класс последствий, что мы чиним.

    ФИЛЬТР not_before (cycle-review этого PR, Codex + /review независимо, оба нашли один P1): backup,
    ОСТАВШИЙСЯ от давно завершённого install→uninstall цикла (retained НАМЕРЕННО, user_data_retained),
    физически неотличим от backup'а ЭТОГО цикла — оба лежат рядом с config_path и парсятся как валидный
    timestamp. Без фильтра: install перезаписал foreign A (backup создан) → uninstall восстановил A,
    backup остался на диске → пользователь вручную удалил A → новый install создал конфиг с нуля
    (provenance='created', backup не пишется — нечего было бэкапить) → uninstall снова находит СТАРЫЙ
    backup как единственного кандидата → component_facts классифицирует как restore вместо remove →
    восстанавливается устаревший чужой контент поверх только что созданного конфига. not_before —
    момент создания ТЕКУЩЕГО конфига (entry['created_at'], пишут _record_component_applied /
    _write_state_after_apply через общий редьюсер — только для provenance='created'); кандидаты со
    stamp строго раньше этого момента доказанно принадлежат
    ПРЕДЫДУЩЕМУ install-циклу и отбрасываются ДО подсчёта len(discovered) — иначе retained-relic мог бы
    выдать себя за «единственного» и обойти даже политику ambiguous.
    """
    stated = entry.get("backup") if isinstance(entry, dict) else None
    if stated:
        # state НАЗВАЛ конкретный backup — это сильнейшее из доступных утверждений о том, где лежит
        # оригинал. Discovery существует, чтобы восполнить МОЛЧАНИЕ state (обрыв до записи), а не
        # чтобы переспорить его: подмена названного файла найденным «похожим» тихо восстановила бы
        # чужой контент. Поэтому:
        #   - названный файл жив → берём его (даже вне parent-директории target: legacy/ручной путь);
        #   - названный файл мёртв → НЕ подставляем найденное молча (cycle-review #124 P1: ровно один
        #     случайный сосед подменял названный backup, и apply_uninstall докладывал ok без leftover).
        #     Возвращаем «нечего восстанавливать» — дальше component_facts даст leftover по
        #     state_backup_missing, и оператор увидит, что откат НЕ состоялся.
        #
        # ИСКЛЮЧЕНИЕ (найдено при слиянии части 1/2 с частью 2/2, до открытия PR): not_before обязан
        # применяться и здесь, не только к discovered ниже. preserve-логика _write_state_after_apply
        # (carried_backup) переносит backup НЕЗАВИСИМО от provenance — значит entry с
        # provenance='created' (target пересоздан с нуля, needs_backup=False в ЭТОМ apply) теперь
        # может нести stated backup из ПРЕДЫДУЩЕГО managed/restored-цикла того же пути. Раньше эта
        # комбинация была недостижима (created гарантированно означал backup=None), поэтому проверка
        # здесь отсутствовала — но once carried_backup стал не гейтиться managed, гарантия исчезла.
        # not_before (created_at) — тот же сигнал, которым мы уже отсекаем retained-relic в discovered;
        # применяем его симметрично и к stated, иначе устаревший pointer обходит защиту через «сильный»
        # приоритет над discovery.
        #
        # cycle-review PR #294 (Codex): непарсимое имя — НЕ доказательство recency, а её ОТСУТСТВИЕ.
        # Названный backup вправе иметь произвольное (legacy/ручное) имя — _parse_backup_stamp вернёт
        # None не только для retained-relic, но и для ЛЮБОГО non-canonical имени. Раньше stated_stamp
        # is None пропускал ветку not_before целиком (конъюнкция требовала stated_stamp is not None) и
        # падал в безусловный accept ниже — устаревший legacy-pointer, унесённый carried_backup из
        # mode='restored'/'adopted' prev-entry (гейт по нему снят, только prev_same_path), обходил
        # not_before и восстанавливался поверх свежесозданного (provenance='created') конфига (issue
        # #124 P1: silent data loss, воспроизведено end-to-end). Fail-closed: когда recency вообще
        # нельзя подтвердить (not_before задан, а имя не парсится), не доверяем — так же, как мёртвому
        # named backup ниже.
        stated_stamp = _parse_backup_stamp(Path(stated).name[len(Path(config_path).name + _BACKUP_INFIX):]) \
            if config_path and Path(stated).name.startswith(Path(config_path).name + _BACKUP_INFIX) else None
        if not_before is not None and stated_stamp is None:
            stated = None
        elif not_before is not None and stated_stamp < not_before:
            stated = None
        elif Path(stated).is_file():
            return Path(stated), False
        else:
            return None, False
    if not_before is not None:
        # Suffix вычисляем ТЕМ ЖЕ способом, что и discover_backups (slice от длины конкретного
        # config_path.name + INFIX), а не split(INFIX, 1) по первому вхождению: если бы имя самого
        # target когда-нибудь содержало ".srouter-backup-" как подстроку (сейчас невозможно — три
        # компонента с фиксированными именами config/config.json/dnsmasq.conf, но это внутренний
        # инвариант _resolve_backup не обязан предполагать), split молча срезал бы suffix неверно и
        # фильтр давал бы неправильный результат вместо явного None → fail-open (не сужать).
        prefix = (Path(config_path).name + _BACKUP_INFIX) if config_path else _BACKUP_INFIX
        discovered = [candidate for candidate in discovered
                      if (_parse_backup_stamp(candidate.name[len(prefix):]) or not_before)
                      >= not_before]
    if not discovered:
        return None, False
    if len(discovered) == 1:
        # state молчит (обрыв до записи) — единственный кандидат однозначен: это ровно тот случай,
        # ради которого затевалась disk-discovery (P1-3/F1).
        return discovered[0], False
    return None, True


def component_facts(name, env, entry, *, config_path=None):
    """Единый редьюсер состояния компонента: три факта о мире → безопасное действие (issue #124).

    ЗАЧЕМ ОДНА ФУНКЦИЯ НА ДВА ПОТОКА. До неё вывод «что это за компонент» существовал в двух
    независимых реализациях — _inspect_component (install) и _component_uninstall_item (uninstall).
    Корень issue #110 был сформулирован ровно так: «install верил файлу, uninstall верил state».
    issue #124 — рецидив того же на третьем факте (backup): install знал про backup, uninstall не мог
    узнать. Общий редьюсер закрывает класс, а не очередной экземпляр.

    ТРИ ИСТОЧНИКА (ничего не пишет, subprocess не зовёт — чистая функция от диска и state):
      1. target на диске: существует ли, есть ли srouter-маркер («живой арбитр», _has_marker);
      2. backup'ы на диске: discover_backups рядом с config_path (доказательство);
      3. state-entry: management.mode/managed/provenance + backup (память) + created_at (нижняя
         граница возраста backup'а, которую cycle-review этого PR добавил вместе с фиксом P1 ниже).

    КЛЮЧЕВОЕ СВОЙСТВО: функция НЕ ЗНАЕТ, был ли crash. Она не различает «install завершился» и
    «install оборвался» — смотрит на три факта и выводит, что безопасно сделать. Поэтому crash
    перестаёт быть отдельным случаем, требующим отдельной ветки кода; шесть P1 issue #124 — это шесть
    комбинаций тех же трёх фактов, и все шесть попадают в одну таблицу ниже.

    recovery:
      none            — трогать нечего (конфига нет / он чужой без нашей истории);
      restore         — вернуть оригинал пользователя из backup;
      remove          — удалить конфиг, созданный srouter'ом с нуля (provenance='created', backup нет);
      orphaned_backup — наш конфиг + backup на диске, но state молчит (обрыв ДО записи state):
                        восстановимо, отличается от restore только происхождением знания;
      ambiguous       — несколько backup'ов, state не разрешает → оператору (fail-closed);
      leftover        — состояние определённо небезопасное для записи → сообщить, ничего не трогать.

    Таблица (маркер | state.managed | state.backup | disk backups → recovery):
      нет маркера, файла нет            → none              ничего не делали
      маркер, managed, backup жив       → restore           штатный overwrite
      маркер, managed, backup мёртв, 0  → leftover          state лжёт — не удалять вслепую
      маркер, managed created, 0        → remove            штатный created
      маркер, managed created, >=1      → restore           F2/P1-1: диск бьёт деградировавший state,
                                                              НО только backup ⩾ created_at (cycle-review
                                                              этого PR: retained-relic прошлого цикла
                                                              не считается — см. _resolve_backup not_before)
      маркер, entry НЕТ, ровно 1        → orphaned_backup   P1-3/F1: обрыв до записи state
      маркер, entry НЕТ, 0              → leftover          наш конфиг без backup — не гадаем
      маркер, >1 backup, state молчит   → ambiguous         не выбираем «свежий»
      БЕЗ маркера, managed              → leftover          stale-managed (#110 Дефект 1)
      БЕЗ маркера, не managed           → none              true-foreign: чужое рядом легитимно (#110)
      adopted/restored (любые факты)    → none              srouter намеренно не владеет файлом

    Порядок ветвления — часть контракта: adopted/restored → «не наш файл» (маркер) → ambiguous →
    действия. Каждая следующая проверка имеет смысл только если предыдущая подтвердила право писать.
    """
    path = Path(config_path or (entry.get("config_path") if isinstance(entry, dict) else None)
                or env.component_paths(name)["config"])
    entry = entry if isinstance(entry, dict) else {}
    marker_present = path.exists() and _has_marker(path)
    managed = _is_managed_entry(entry)
    adopted = _is_adopted_entry(entry)
    restored = _is_restored_entry(entry)
    provenance = _provenance_of(entry)
    discovered = discover_backups(path)
    # not_before (cycle-review этого PR): для created-конфига entry несёт created_at — момент, раньше
    # которого валидных backup'ов для ЭТОГО config_path быть не может. Отсекает retained-relic от
    # предыдущего install→uninstall цикла, не давая ему выдать себя за «единственного» кандидата.
    not_before = _parse_backup_stamp_or_none(entry.get("created_at")) if provenance == "created" else None
    backup, ambiguous = _resolve_backup(entry, discovered, not_before=not_before, config_path=path)

    facts = {
        "name": name,
        "config_path": str(path),
        "config_present": path.exists(),
        "marker_present": marker_present,
        "managed": managed,
        "adopted": adopted,
        "restored": restored,
        "provenance": provenance,
        "backup": str(backup) if backup else "",
        "discovered_backups": [str(p) for p in discovered],
        "state_backup_missing": bool(entry.get("backup")) and not Path(entry["backup"]).is_file(),
    }

    # adopted/restored — srouter намеренно не владеет файлом; чужая история не даёт прав (канон
    # «никогда молча не adopt» в обратную сторону: и не откатывать чужое молча).
    #
    # cycle-review этого PR (Codex, round 2): доверяем adopted/restored ТОЛЬКО когда маркер на target
    # отсутствует. Сценарий-нарушитель: компонент adopted → пользователь ЯВНО выбирает overwrite в
    # следующем apply (modes строится из choices.get(name), prev-state НЕ проверяется — adopted не
    # блокирует выбор overwrite) → target реально перезаписан srouter'ом, backup adopted-оригинала
    # создан → crash ДО финальной _write_state_after_apply → entry в state ВСЁ ЕЩЁ несёт mode='adopted'
    # (запись, которая заменила бы его, не состоялась). Без этой проверки component_facts короткое
    # замыкание на устаревшем adopted=True игнорировало бы живой маркер и новый backup — uninstall
    # репортил бы «adopted — left untouched», оставляя srouter-конфиг на месте и осиротив backup
    # истинного adopted-оригинала НАВСЕГДА (тот же класс потери, что и P1-3, просто через adopted/
    # restored вместо managed). Живой маркер — то же самое доказательство «install реально произошёл
    # ПОСЛЕ adopt/restore», что уже используется для managed-веток ниже (state деградировал, диск
    # бьёт); симметрия здесь обязательна, а не опция.
    if (adopted or restored) and not marker_present:
        facts["recovery"] = "none"
        return facts
    if not marker_present:
        # Живой арбитр говорит «файл не наш». Проверяется РАНЬШЕ ambiguous: неоднозначность backup'ов
        # имеет смысл только для файла, который мы вправе трогать. Иначе чужой конфиг, рядом с которым
        # случайно лежат похожие по имени файлы (остатки давнего install по этому пути), попадал бы в
        # ambiguous → leftover → rc=2, нарушая границу #110: «true-foreign (srouter не ставил) → НЕ
        # leftover, чужое рядом легитимно» (cycle-review #111 cycle 2 finding B).
        # Единственное, что требует внимания, — след в state о том, что srouter сюда ставил
        # (stale-managed, #110 Дефект 1) → leftover, но по-прежнему без записи на диск.
        facts["recovery"] = "leftover" if managed else "none"
        return facts
    if ambiguous:
        # Файл наш (маркер), но какой из backup'ов оригинал пользователя — неизвестно. Любое действие
        # рискует записать не тот контент, поэтому раньше remove/restore и без записи на диск.
        facts["recovery"] = "ambiguous"
        return facts
    # Дальше: маркер на месте — файл ДОКАЗАННО наш, писать по нему безопасно.
    if backup:
        # backup есть — значит был overwrite, и у пользователя есть что вернуть. Работает и когда
        # state деградировал до provenance='created' (F2/P1-1), и когда entry потерян целиком
        # (P1-3/F1): диск — доказательство, state — лишь память о нём.
        facts["recovery"] = "restore" if managed else "orphaned_backup"
        return facts
    if managed and provenance == "created":
        facts["recovery"] = "remove"
        return facts
    if managed and entry.get("backup"):
        # state обещает backup, которого на диске нет — состояние неопределённое: удалить нельзя
        # (вдруг оригинал ещё вернётся), восстановить нечем. Сообщаем, не трогаем.
        facts["recovery"] = "leftover"
        return facts
    # Наш конфиг (маркер), но история неизвестна: legacy-state без provenance либо обрыв до любой
    # записи state и без backup (значит и overwrite не было — терять нечего, но и удалять вслепую
    # нельзя: канон fail-safe leftover, как created-без-маркера в issue #112 Часть 2).
    facts["recovery"] = "leftover" if managed or facts["config_present"] else "none"
    return facts
