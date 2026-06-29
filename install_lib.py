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
import socket
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import gen_xray_config
import local_state


MARKER = "srouter-managed"
ROOT = Path(__file__).resolve().parent

BREW = "/opt/homebrew/bin/brew"
CURL = "/usr/bin/curl"
ROUTE = "/sbin/route"
LSOF = "/usr/sbin/lsof"
NETWORKSETUP = "/usr/sbin/networksetup"
SUDO = "/usr/bin/sudo"

COMPONENTS = ("xray", "privoxy", "dnsmasq")
CHOICES = ("adopt", "overwrite", "skip")
PORTS = {"xray": ("tcp", 10808), "privoxy": ("tcp", 8118), "dnsmasq": ("udp", 53)}


def run(cmd_list, timeout):
    """Паттерн как в dashboard.py: список аргументов, не бросает."""
    try:
        p = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "out": p.stdout.strip(), "err": p.stderr.strip(), "timeout": False}
    except subprocess.TimeoutExpired:
        return {"rc": None, "out": "", "err": "timeout", "timeout": True}
    except Exception as exc:
        return {"rc": None, "out": "", "err": str(exc), "timeout": True}


def port_open(host, port, timeout=0.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class InstallEnv:
    root: Path = ROOT
    prefix: Path = Path("/opt/homebrew")
    state_path: Path = ROOT / "srouter.local.json"
    now: str = ""

    @classmethod
    def from_env(cls, *, state_path=None, prefix=None):
        return cls(
            root=ROOT,
            prefix=Path(prefix or os.environ.get("SROUTER_PREFIX", "/opt/homebrew")),
            state_path=Path(state_path or os.environ.get("SROUTER_STATE_PATH", ROOT / "srouter.local.json")),
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
    return first_line == MARKER or first_line.startswith(MARKER + ":")


def _parse_brew_services(text):
    services = {}
    if not isinstance(text, str):
        return services
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] in COMPONENTS:
            services[fields[0]] = fields[1]
    return services


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


def _write_state_after_apply(env, plan, modes, backups):
    state, readable = local_state.load_state_checked(path=env.state_path)
    if not readable:
        return "state_unreadable"
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    for name, item in plan["components"].items():
        mode = modes.get(name, "skipped")
        detected[name] = _management_for(mode, item)
        if backups.get(name):
            detected[name]["backup"] = backups[name]
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


def apply_install(env=None, *, confirm=False, choices=None, runner=run, port_checker=port_open):
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

    state_error = _write_state_after_apply(env, plan, modes, backups)
    if state_error:
        return {"ok": False, "blocked": [state_error], "actions": actions, "plan": plan}
    return {"ok": True, "blocked": [], "actions": actions, "plan": plan}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Локальный установщик srouter")
    parser.add_argument("mode", nargs="?", choices=("plan", "apply", "init"), default="plan")
    parser.add_argument("-y", "--yes", action="store_true", help="Явное подтверждение apply/init")
    parser.add_argument("--state", default=None, help="Путь к srouter.local.json")
    parser.add_argument("--prefix", default=None, help="Homebrew prefix, по умолчанию /opt/homebrew")
    for name in COMPONENTS:
        parser.add_argument(f"--{name}", choices=CHOICES, default=None, help=f"Выбор для конфликтов {name}")
    args = parser.parse_args(argv)

    env = InstallEnv.from_env(state_path=args.state, prefix=args.prefix)
    if args.mode == "plan":
        print(format_plan(build_plan(env=env)))
        return 0

    choices = {name: getattr(args, name) for name in COMPONENTS if getattr(args, name)}
    if args.mode == "init":
        choices = {name: "skip" for name in COMPONENTS} | choices
    result = apply_install(env=env, confirm=args.yes, choices=choices)
    if result["ok"]:
        print("apply завершён: изменения записаны только после явного подтверждения.")
        return 0
    print("apply остановлен: " + ", ".join(result.get("blocked") or ["unknown"]), file=sys.stderr)
    if "plan" in result:
        print(format_plan(result["plan"]), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
