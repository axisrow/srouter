#!/usr/bin/env python3
"""Тестируемое ядро install.sh: plan/apply, discovery и conflict-detection.

Все subprocess-вызовы идут списком аргументов и через абсолютные пути. Публичные
функции возвращают dict/result и не бросают наружу.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from pathlib import Path

import gen_xray_config
import local_state
from sys_probe import BREW_COMPONENTS
from sys_probe import parse_brew_services as _parse_brew_services
from sys_probe import port_open, run


MARKER = "srouter-managed"
TEXT_MARKER = "srouter-managed-config-v1"
ROOT = Path(__file__).resolve().parent

BREW = "/opt/homebrew/bin/brew"
CURL = "/usr/bin/curl"
ROUTE = "/sbin/route"
LSOF = "/usr/sbin/lsof"
NETWORKSETUP = "/usr/sbin/networksetup"
SUDO = "/usr/bin/sudo"
LAUNCHCTL = "/bin/launchctl"

COMPONENTS = BREW_COMPONENTS
CHOICES = ("adopt", "overwrite", "skip")
PORTS = {"xray": ("tcp", 10808), "privoxy": ("tcp", 8118), "dnsmasq": ("udp", 53)}
LAUNCHAGENT_LABEL = "com.srouter.dashboard"
LAUNCHAGENT_FILE = f"{LAUNCHAGENT_LABEL}.plist"
LAUNCHAGENT_MARKER = "srouter-managed-launchagent-v1"
UNINSTALL_CATEGORIES = ("configs", "services", "dns", "launchagent")


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


def _has_launchagent_marker(path):
    return LAUNCHAGENT_MARKER in _read_head(path)


def _launchd_domain():
    return f"gui/{os.getuid()}"


def _launchagent_template_path(env):
    return env.root / "launchagents" / LAUNCHAGENT_FILE


def _render_launchagent_plist(env):
    """Рендерим LaunchAgent из шаблона: абсолютные пути и только loopback dashboard.py."""
    template = _launchagent_template_path(env).read_text(encoding="utf-8")
    replacements = {
        "__SROUTER_LAUNCHAGENT_MARKER__": LAUNCHAGENT_MARKER,
        "__SROUTER_LAUNCHAGENT_LABEL__": LAUNCHAGENT_LABEL,
        "__SROUTER_PYTHON_BIN__": env.python_bin,
        "__SROUTER_DASHBOARD_PATH__": str(env.root / "dashboard.py"),
        "__SROUTER_ROOT_DIR__": str(env.root),
        "__SROUTER_LOG_OUT__": str(env.log_out),
        "__SROUTER_LOG_ERR__": str(env.log_err),
    }
    for key, value in replacements.items():
        template = template.replace(key, escape(str(value)))
    return template


def _write_launchagent(env):
    try:
        rendered = _render_launchagent_plist(env)
    except OSError:
        return False
    return _write_text_atomic(env.launchagent_path(), rendered)


def _install_launchagent(env, runner):
    plist_path = env.launchagent_path()
    if plist_path.exists() and not _has_launchagent_marker(plist_path):
        return False, "launchagent_foreign"
    if not _write_launchagent(env):
        return False, "launchagent_write_failed"

    domain = _launchd_domain()
    # bootout может вернуть ошибку, если агент ещё не загружен; это не blocker.
    runner([LAUNCHCTL, "bootout", domain, str(plist_path)], 10)
    bootstrap = runner([LAUNCHCTL, "bootstrap", domain, str(plist_path)], 15)
    if not bootstrap.get("timeout") and bootstrap.get("rc") == 0:
        return True, ""
    fallback = runner([LAUNCHCTL, "load", "-w", str(plist_path)], 15)
    if fallback.get("timeout") or fallback.get("rc") != 0:
        return False, "launchagent_load_failed"
    return True, ""


# ============================ обобщённый рендер/загрузка plists (watchdog/isolate/...) ============================
def _render_generic_launchagent(env, *, template_name, label, marker, script_path):
    """Рендерить произвольный LaunchAgent из шаблона launchagents/<template_name>.

    Обобщение _render_launchagent_plist: разные label/marker/script (health.py, isolate_firewall.py,
    и т.д.). Подставляет __SROUTER_<LABEL>_LABEL__, __SROUTER_<X>_MARKER__, __SROUTER_<X>_PATH__,
    плюс общие PYTHON_BIN/ROOT_DIR/LOG_*. escape — как в dashboard.
    """
    template = (env.root / "launchagents" / template_name).read_text(encoding="utf-8")
    # Префикс для плейсхолдеров LABEL/MARKER/PATH — из label (напр. com.srouter.watchdog → WATCHDOG).
    # Из label надёжнее, чем из marker (marker может иметь -v1 суффикс → WATCHDOG_V1 ≠ WATCHDOG).
    prefix = label.rsplit(".", 1)[-1].upper()  # com.srouter.watchdog → WATCHDOG
    replacements = {
        f"__SROUTER_{prefix}_LABEL__": label,
        f"__SROUTER_{prefix}_MARKER__": marker,
        f"__SROUTER_{prefix}_PATH__": str(script_path),
        "__SROUTER_PYTHON_BIN__": env.python_bin,
        "__SROUTER_ROOT_DIR__": str(env.root),
        "__SROUTER_LOG_OUT__": str(env.log_out),
        "__SROUTER_LOG_ERR__": str(env.log_err),
    }
    for key, value in replacements.items():
        template = template.replace(key, escape(str(value)))
    return template


def _install_generic_launchagent(env, runner, *, template_name, label, marker, script_path):
    """Рендер + загрузка произвольного LaunchAgent (watchdog/isolate/...). Возвращает (ok, err).

    Симметрично _install_launchagent, но с заданным label/marker/script. Путь plist =
    launchagent_dir/<label>.plist. bootout (ignore) → bootstrap (fallback load -w). main ruleset НЕ
    трогается (anchor com.apple/* уже в /etc/pf.conf — но это LaunchAgent, не PF; просто под-anchor).
    """
    plist_path = env.launchagent_dir / f"{label}.plist"
    # Если чужой plist без нашего маркера — не трогаем.
    if plist_path.exists():
        try:
            existing = plist_path.read_text(encoding="utf-8")
            if marker not in existing:
                return False, f"{label}_foreign"
        except OSError:
            return False, f"{label}_read_failed"
    try:
        rendered = _render_generic_launchagent(env, template_name=template_name, label=label,
                                               marker=marker, script_path=script_path)
    except OSError as exc:
        return False, f"{label}_template_failed: {exc}"
    if not _write_text_atomic(plist_path, rendered):
        return False, f"{label}_write_failed"

    domain = _launchd_domain()
    runner([LAUNCHCTL, "bootout", f"{domain}/{label}"], 10)  # ignore если не загружен
    bootstrap = runner([LAUNCHCTL, "bootstrap", domain, str(plist_path)], 15)
    if not bootstrap.get("timeout") and bootstrap.get("rc") == 0:
        return True, ""
    fallback = runner([LAUNCHCTL, "load", "-w", str(plist_path)], 15)
    if fallback.get("timeout") or fallback.get("rc") != 0:
        return False, f"{label}_load_failed"
    return True, ""


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


def _inspect_component(name, env, runner, port_checker):
    paths = env.component_paths(name)
    config_path = paths["config"]
    managed = config_path.exists() and _has_marker(config_path)
    owner = _port_owner(name, runner)
    _proto, port = PORTS[name]
    try:
        listening = bool(port_checker("127.0.0.1", port, timeout=0.5))
    except Exception:
        listening = False

    non_brew = [str(p) for p in paths["non_brew"] if p.exists()]
    config_present = config_path.exists()
    conflicts = []
    if config_present and not managed:
        conflicts.append("foreign_config")
    if owner and not managed:
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

    return {"gateway": gateway, "channels": {"wifi_service": wifi_service, "usb_tether_service": usb_service}}


def _discover_probe_readiness(state_path, port_checker):
    readiness = {}
    for node in local_state.load_nodes(path=state_path):
        probe = node.get("probe") if isinstance(node.get("probe"), dict) else {}
        port = probe.get("socks_port")
        try:
            port = int(port)
            ready = bool(port_checker("127.0.0.1", port, timeout=0.25))
        except Exception:
            ready = False
        readiness[node.get("name") or ""] = {"socks_port": port, "ready": ready}
    return readiness


def _homebrew_available(runner):
    if Path(BREW).exists():
        return True
    result = runner([BREW, "--version"], 5)
    return result.get("rc") == 0


def build_plan(env=None, runner=run, port_checker=port_open):
    """Discovery-only: ничего не пишет."""
    env = env or InstallEnv.from_env()
    brew_services = runner([BREW, "services", "list"], 8)
    service_states = _parse_brew_services(brew_services.get("out") or "")
    components = {}
    for name in COMPONENTS:
        item = _inspect_component(name, env, runner, port_checker)
        item["service"] = service_states.get(name, "none" if brew_services.get("rc") == 0 else "unknown")
        components[name] = item

    state = local_state.load_state(path=env.state_path)
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


def _backup(path, env):
    if not path.exists():
        return ""
    suffix = env.now.replace(":", "").replace("/", "-")
    backup = path.with_name(path.name + f".srouter-backup-{suffix}")
    try:
        shutil.copy2(path, backup)
        return str(backup)
    except OSError:
        return ""


def _write_text_atomic(path, text):
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(path)
        return True
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False


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


def _restart_component(name, runner):
    if name == "dnsmasq":
        return runner([SUDO, BREW, "services", "restart", "dnsmasq"], 60)
    return runner([BREW, "services", "restart", name], 40)


def _apply_dns(env, plan, runner):
    service = plan.get("network", {}).get("channels", {}).get("wifi_service") or ""
    if not service:
        return {"rc": 0, "out": "", "err": "wifi service not found", "timeout": False}
    return runner([NETWORKSETUP, "-setdnsservers", service, "127.0.0.1"], 20)


def _management_for(mode, item):
    return {
        "config_path": item.get("config_path"),
        "port": item.get("port"),
        "service": item.get("service"),
        "port_owner": item.get("port_owner"),
        "management": {"mode": mode, "managed": mode == "managed"},
    }


def _write_state_after_apply(env, plan, modes, backups, launchagent_action=None):
    state, readable = local_state.load_state_checked(path=env.state_path)
    if not readable:
        return "state_unreadable"
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    for name, item in plan["components"].items():
        mode = modes.get(name, "skipped")
        detected[name] = _management_for(mode, item)
        if backups.get(name):
            detected[name]["backup"] = backups[name]
    if launchagent_action:
        launchagent = plan.get("launchagent") or {}
        detected["launchagent"] = {
            "label": launchagent.get("label"),
            "plist_path": launchagent.get("plist_path"),
            "dashboard_path": launchagent.get("dashboard_path"),
            "python_bin": launchagent.get("python_bin"),
            "management": {"mode": "managed", "managed": True},
            "last_loaded_at": env.now,
        }
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


def apply_install(env=None, *, confirm=False, choices=None, runner=run, port_checker=port_open, install_launchagent=True):
    """Применить план. Без confirm или без выбора по конфликту ничего не пишет."""
    env = env or InstallEnv.from_env()
    choices = choices or {}
    if not confirm:
        return {"ok": False, "blocked": ["confirmation_required"], "actions": []}

    plan = build_plan(env=env, runner=runner, port_checker=port_checker)
    unresolved = []
    for name, item in plan["components"].items():
        choice = choices.get(name)
        if item.get("conflict") and choice not in CHOICES:
            unresolved.append(name)
    if unresolved:
        return {"ok": False, "blocked": unresolved, "actions": [], "plan": plan}

    _state, state_readable = local_state.load_state_checked(path=env.state_path)
    if not state_readable:
        return {"ok": False, "blocked": ["state_unreadable"], "actions": [], "plan": plan}

    modes = {}
    for name, item in plan["components"].items():
        if choices.get(name) == "adopt":
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

    actions = []
    backups = {}
    for name in COMPONENTS:
        mode = modes.get(name)
        item = plan["components"][name]
        if mode in ("adopted", "skipped"):
            actions.append({"component": name, "mode": mode, "changed": False})
            continue

        if not _ensure_package(name, runner):
            return {"ok": False, "blocked": [f"{name}_install_failed"], "actions": actions, "plan": plan}
        config_path = Path(item["config_path"])
        if config_path.exists() and choices.get(name) == "overwrite":
            backup = _backup(config_path, env)
            if not backup:
                return {"ok": False, "blocked": [f"{name}_backup_failed"], "actions": actions, "plan": plan}
            backups[name] = backup
        if not _write_component_config(name, env):
            return {"ok": False, "blocked": [f"{name}_config_write_failed"], "actions": actions, "plan": plan}
        restart = _restart_component(name, runner)
        if restart.get("timeout") or restart.get("rc") != 0:
            return {"ok": False, "blocked": [f"{name}_restart_failed"], "actions": actions, "plan": plan}
        if name == "dnsmasq":
            _apply_dns(env, plan, runner)
        actions.append({"component": name, "mode": mode, "changed": True})

    launchagent_action = None
    if install_launchagent:
        launchagent_ok, launchagent_error = _install_launchagent(env, runner)
        if not launchagent_ok:
            return {"ok": False, "blocked": [launchagent_error], "actions": actions, "plan": plan}
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


def _component_uninstall_item(name, env, detected):
    entry = detected.get(name) if isinstance(detected.get(name), dict) else {}
    config_path = Path(entry.get("config_path") or env.component_paths(name)["config"])
    backup_path = Path(entry["backup"]) if entry.get("backup") else None
    marker_present = config_path.exists() and _has_marker(config_path)
    managed = _is_managed_entry(entry)
    adopted = _is_adopted_entry(entry)
    restored = _is_restored_entry(entry)
    restorable = managed and marker_present and bool(backup_path and backup_path.exists())
    if adopted:
        status = "adopted — left untouched"
    elif restored:
        status = "restored — left untouched"
    elif restorable:
        status = "managed — restore available"
    elif managed:
        status = "managed — no safe backup/marker, left untouched"
    else:
        status = "unmanaged — left untouched"
    return {
        "name": name,
        "config_path": str(config_path),
        "backup": str(backup_path) if backup_path else "",
        "managed": managed,
        "adopted": adopted,
        "restored": restored,
        "marker_present": marker_present,
        "restorable": restorable,
        "status": status,
    }


def _launchagent_uninstall_item(env, detected):
    entry = detected.get("launchagent") if isinstance(detected.get("launchagent"), dict) else {}
    plist_path = Path(entry.get("plist_path") or env.launchagent_path())
    marker_present = plist_path.exists() and _has_launchagent_marker(plist_path)
    managed = _is_managed_entry(entry) or marker_present
    adopted = _is_adopted_entry(entry)
    if adopted:
        status = "adopted — left untouched"
    elif managed and marker_present:
        status = "managed — unload/remove available"
    elif managed:
        status = "managed — marker missing, left untouched"
    else:
        status = "unmanaged — left untouched"
    return {
        "label": entry.get("label") or LAUNCHAGENT_LABEL,
        "plist_path": str(plist_path),
        "managed": managed,
        "adopted": adopted,
        "marker_present": marker_present,
        "removable": managed and marker_present,
        "status": status,
    }


def build_uninstall_plan(env=None, runner=run):
    """Rollback discovery-only: не вызывает subprocess и не пишет файлы."""
    del runner
    env = env or InstallEnv.from_env()
    state, readable = local_state.load_state_checked(path=env.state_path)
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    network = state.get("network") if isinstance(state.get("network"), dict) else {}
    return {
        "mode": "uninstall-plan",
        "state_path": str(env.state_path),
        "state_readable": readable,
        "categories": list(UNINSTALL_CATEGORIES),
        "components": [_component_uninstall_item(name, env, detected) for name in COMPONENTS],
        "network": network,
        "launchagent": _launchagent_uninstall_item(env, detected),
        "user_data_retained": [
            "srouter.local.json",
            "generated key/deploy bundles",
            "*.srouter-backup-*",
        ],
    }


def format_uninstall_plan(plan):
    lines = [
        "srouter uninstall rollback plan",
        f"- state: {plan.get('state_path')}",
        "- plan ничего не меняет; apply спрашивает подтверждение по категориям.",
        "- user-data остаются на месте: " + ", ".join(plan.get("user_data_retained", [])),
        "",
        "Категории apply:",
        "- configs: restore из #5 backup только если текущий config всё ещё srouter-managed",
        "- services: stop только srouter-managed brew services",
        "- dns: networksetup Empty только для srouter-managed dnsmasq/Wi-Fi",
        "- launchagent: bootout/unload и удаление plist только если есть srouter marker",
        "",
        "Компоненты:",
    ]
    for item in plan.get("components", []):
        lines.append(
            f"- {item.get('name')}: {item.get('status')}; "
            f"config={item.get('config_path')}; backup={item.get('backup') or '-'}"
        )
    launchagent = plan.get("launchagent") or {}
    lines.extend(
        [
            "",
            f"LaunchAgent: {launchagent.get('status')}; plist={launchagent.get('plist_path')}",
            "",
            "Для применения: ./uninstall.sh apply и подтвердить нужные категории.",
        ]
    )
    return "\n".join(lines)


def _restore_backup(backup_path, target_path):
    tmp = target_path.with_name(target_path.name + ".srouter-restore-tmp")
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup_path, tmp)
        tmp.replace(target_path)
        return True
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False


def _mark_component_restored(env, item):
    state, readable = local_state.load_state_checked(path=env.state_path)
    if not readable:
        return "state_unreadable"
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    entry = detected.get(item["name"]) if isinstance(detected.get(item["name"]), dict) else {}
    entry["config_path"] = item.get("config_path")
    if item.get("backup"):
        entry["backup"] = item["backup"]
        entry["restored_from_backup"] = item["backup"]
    # После restore текущий config снова принадлежит пользователю/системе.
    # Это фиксирует прогресс rollback и не даёт повторному apply остановить foreign service.
    entry["management"] = {"mode": "restored", "managed": False}
    entry["restored_at"] = env.now
    detected[item["name"]] = entry
    state["detected_environment"] = detected

    runtime = state.get("runtime") if isinstance(state.get("runtime"), dict) else {}
    runtime["last_uninstall_restore"] = env.now
    state["runtime"] = runtime
    if local_state.save_state(state, path=env.state_path) is None:
        return "state_write_failed"
    return ""


def _stop_service(name, runner):
    if name == "dnsmasq":
        return runner([SUDO, BREW, "services", "stop", "dnsmasq"], 40)
    return runner([BREW, "services", "stop", name], 40)


def _restore_dns(plan, runner):
    dnsmasq = next((item for item in plan.get("components", []) if item.get("name") == "dnsmasq"), {})
    if not dnsmasq.get("managed"):
        return {"rc": 0, "out": "", "err": "dnsmasq unmanaged", "timeout": False}
    channels = plan.get("network", {}).get("channels") if isinstance(plan.get("network"), dict) else {}
    service = channels.get("wifi_service") if isinstance(channels, dict) else ""
    if not service:
        return {"rc": 0, "out": "", "err": "wifi service not found", "timeout": False}
    return runner([NETWORKSETUP, "-setdnsservers", service, "Empty"], 20)


def _unload_launchagent(item, runner):
    plist_path = item.get("plist_path") or ""
    if not item.get("removable") or not plist_path:
        return {"ok": True, "changed": False}
    domain = _launchd_domain()
    bootout = runner([LAUNCHCTL, "bootout", domain, plist_path], 15)
    if bootout.get("timeout") or bootout.get("rc") != 0:
        fallback = runner([LAUNCHCTL, "unload", "-w", plist_path], 15)
        if fallback.get("timeout") or fallback.get("rc") != 0:
            return {"ok": False, "blocked": "launchagent_unload_failed"}
    try:
        Path(plist_path).unlink(missing_ok=True)
    except OSError:
        return {"ok": False, "blocked": "launchagent_remove_failed"}
    return {"ok": True, "changed": True}


def apply_uninstall(env=None, *, confirmations=None, runner=run):
    """Apply rollback. Каждая категория должна быть явно подтверждена вызывающим кодом."""
    env = env or InstallEnv.from_env()
    confirmations = confirmations or {}
    plan = build_uninstall_plan(env=env)
    if not plan.get("state_readable"):
        return {"ok": False, "blocked": ["state_unreadable"], "actions": [], "plan": plan}

    actions = []
    components = []
    if confirmations.get("configs"):
        for item in plan["components"]:
            components.append(item)
            if not item.get("restorable"):
                continue
            if not _restore_backup(Path(item["backup"]), Path(item["config_path"])):
                return {"ok": False, "blocked": [f"{item['name']}_restore_failed"], "actions": actions, "plan": plan}
            state_error = _mark_component_restored(env, item)
            if state_error:
                return {"ok": False, "blocked": [state_error], "actions": actions, "plan": plan}
            actions.append({"category": "configs", "component": item["name"], "changed": True})
    else:
        components.extend(plan["components"])

    if confirmations.get("services"):
        for item in plan["components"]:
            if not item.get("managed"):
                continue
            stopped = _stop_service(item["name"], runner)
            if stopped.get("timeout") or stopped.get("rc") != 0:
                return {"ok": False, "blocked": [f"{item['name']}_stop_failed"], "actions": actions, "plan": plan}
            actions.append({"category": "services", "component": item["name"], "changed": True})

    if confirmations.get("dns"):
        restored = _restore_dns(plan, runner)
        if restored.get("timeout") or restored.get("rc") != 0:
            return {"ok": False, "blocked": ["dns_restore_failed"], "actions": actions, "plan": plan}
        if not restored.get("err"):
            actions.append({"category": "dns", "component": "networksetup", "changed": True})

    if confirmations.get("launchagent"):
        unloaded = _unload_launchagent(plan["launchagent"], runner)
        if not unloaded["ok"]:
            return {"ok": False, "blocked": [unloaded["blocked"]], "actions": actions, "plan": plan}
        if unloaded.get("changed"):
            actions.append({"category": "launchagent", "component": LAUNCHAGENT_LABEL, "changed": True})

    return {"ok": True, "blocked": [], "actions": actions, "components": components, "plan": plan}


def _prompt_bool(label):
    answer = input(f"{label} [y/N]: ").strip().lower()
    return answer in {"y", "yes", "д", "да"}


def _collect_uninstall_confirmations(args, plan):
    confirmations = {
        "configs": bool(args.restore_configs),
        "services": bool(args.stop_services),
        "dns": bool(args.restore_dns),
        "launchagent": bool(args.unload_launchagent),
    }
    if any(confirmations.values()):
        return confirmations
    if not sys.stdin.isatty():
        return None
    print(format_uninstall_plan(plan))
    print("")
    return {
        "configs": _prompt_bool("Восстановить managed service-конфиги из #5 backup?"),
        "services": _prompt_bool("Остановить только srouter-managed brew services?"),
        "dns": _prompt_bool("Сбросить DNS через networksetup для srouter-managed dnsmasq?"),
        "launchagent": _prompt_bool("Выгрузить и удалить srouter-managed LaunchAgent?"),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Локальный установщик srouter")
    parser.add_argument("mode", nargs="?", choices=("plan", "apply", "init", "uninstall-plan", "uninstall-apply"), default="plan")
    parser.add_argument("-y", "--yes", action="store_true", help="Явное подтверждение apply/init")
    parser.add_argument("--state", default=None, help="Путь к srouter.local.json")
    parser.add_argument("--prefix", default=None, help="Homebrew prefix, по умолчанию /opt/homebrew")
    parser.add_argument("--launchagents-dir", default=None, help="Каталог LaunchAgents для тестов/нестандартного HOME")
    parser.add_argument("--restore-configs", action="store_true", help="uninstall apply: restore managed configs from backups")
    parser.add_argument("--stop-services", action="store_true", help="uninstall apply: stop managed brew services")
    parser.add_argument("--restore-dns", action="store_true", help="uninstall apply: reset DNS for managed dnsmasq")
    parser.add_argument("--unload-launchagent", action="store_true", help="uninstall apply: unload/remove managed LaunchAgent")
    for name in COMPONENTS:
        parser.add_argument(f"--{name}", choices=CHOICES, default=None, help=f"Выбор для конфликтов {name}")
    args = parser.parse_args(argv)

    env = InstallEnv.from_env(state_path=args.state, prefix=args.prefix)
    if args.launchagents_dir:
        env.launchagent_dir = Path(args.launchagents_dir)
    if args.mode == "plan":
        print(format_plan(build_plan(env=env)))
        return 0
    if args.mode == "uninstall-plan":
        print(format_uninstall_plan(build_uninstall_plan(env=env)))
        return 0
    if args.mode == "uninstall-apply":
        plan = build_uninstall_plan(env=env)
        confirmations = _collect_uninstall_confirmations(args, plan)
        if confirmations is None:
            print(format_uninstall_plan(plan), file=sys.stderr)
            print("uninstall apply остановлен: нужно подтвердить категории restore/stop/unload", file=sys.stderr)
            return 2
        result = apply_uninstall(env=env, confirmations=confirmations)
        if result["ok"]:
            print("uninstall apply завершён: изменены только подтверждённые srouter-managed категории.")
            return 0
        print("uninstall apply остановлен: " + ", ".join(result.get("blocked") or ["unknown"]), file=sys.stderr)
        return 2

    choices = {name: getattr(args, name) for name in COMPONENTS if getattr(args, name)}
    install_launchagent = True
    if args.mode == "init":
        choices = {name: "skip" for name in COMPONENTS} | choices
        install_launchagent = False
    result = apply_install(env=env, confirm=args.yes, choices=choices, install_launchagent=install_launchagent)
    if result["ok"]:
        print("apply завершён: изменения записаны только после явного подтверждения.")
        return 0
    print("apply остановлен: " + ", ".join(result.get("blocked") or ["unknown"]), file=sys.stderr)
    if "plan" in result:
        print(format_plan(result["plan"]), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
