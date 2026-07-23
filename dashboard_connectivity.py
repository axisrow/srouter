"""Connectivity/channel helpers dashboard без импорта Flask/dashboard."""

import re
import shlex

import local_state
import sys_probe
from dashboard_common import (
    CHANNEL_SERVICE_KEYS,
    CHANNEL_TARGETS,
    CURL,
    IFCONFIG,
    NETWORKSETUP,
    OSASCRIPT,
    ROUTE,
    _applescript_text,
    _first,
    _http_url,
    _probe_options,
)


__all__ = [
    "_parse_hardware_ports",
    "_hardware_ports",
    "_channel_for_iface",
    "_parse_ifconfig_ifaces",
    "_connectivity_target",
    "_probe_direct_reachability",
    "_metered_guess",
    "probe_connectivity",
    "probe_ifaces",
    "_exit_ip_via_iface",
    "probe_exit_ips_per_iface",
    "_parse_network_services",
    "_known_service_name",
    "_configured_channel_service",
    "_hardware_channel_service",
    "_channel_service_name",
    "_channel_result",
    "_shell_join",
    "_applescript_text",
    "switch_channel",
]


def _parse_hardware_ports(text):
    """networksetup -> device -> hardware port. Битый вывод просто даёт пустую карту."""
    ports = {}
    current = {}

    def flush():
        device = current.get("device", "")
        if device:
            ports[device] = dict(current)

    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            flush()
            current = {}
            continue
        if line.startswith("Hardware Port:"):
            if current:
                flush()
                current = {}
            current["hardware_port"] = line.split(":", 1)[1].strip()
        elif line.startswith("Device:"):
            current["device"] = line.split(":", 1)[1].strip()
        elif line.startswith("Ethernet Address:"):
            current["ethernet_address"] = line.split(":", 1)[1].strip()
    flush()
    return ports


def _hardware_ports():
    r = sys_probe.run([NETWORKSETUP, "-listallhardwareports"], timeout=4)
    if r["timeout"] or not r["out"]:
        return {}
    return _parse_hardware_ports(r["out"])


def _channel_for_iface(name, hardware_port, ifconfig_block):
    """Классификация канала без угадывания: Wi-Fi и известный USB-tether, иначе other/unknown."""
    text = f"{hardware_port or ''}\n{ifconfig_block or ''}".lower()
    if "wi-fi" in text or "wifi" in text or "airport" in text:
        return "wifi"
    usb_tether_tokens = ("iphone usb", "android", "rndis", "usb tether", "tether")
    if any(token in text for token in usb_tether_tokens):
        return "usb_tether"
    if not name and not hardware_port and not ifconfig_block:
        return "unknown"
    return "other"


def _parse_ifconfig_ifaces(text, default_iface, hardware_ports):
    ifaces = []
    if not text:
        return ifaces
    for b in re.split(r"\n(?=\S)", text):
        head = re.match(r"^(\w[\w.]*?):\s.*?mtu\s+(\d+)", b)
        if not head:
            continue
        name, mtu = head.group(1), head.group(2)
        if not re.match(r"(en\d|ppp\d|utun\d)", name):
            continue
        addr = _first(r"inet\s+(\d+\.\d+\.\d+\.\d+)", b)
        if not addr and name not in (default_iface, "ppp0"):
            continue
        port = hardware_ports.get(name, {}) if isinstance(hardware_ports, dict) else {}
        hardware_port = port.get("hardware_port", "") if isinstance(port, dict) else ""
        ifaces.append({"name": name, "addr": addr or "", "mtu": mtu,
                       "is_default": name == default_iface,
                       "hardware_port": hardware_port,
                       "channel": _channel_for_iface(name, hardware_port, b)})
    ifaces.sort(key=lambda x: (not x["is_default"], x["name"]))
    return ifaces


def _connectivity_target():
    try:
        targets = _probe_options().get("reachability_targets", [])
    except Exception:
        targets = []
    for target in targets:
        if _http_url(target):
            return target
    return "https://api.ip.sb/ip"


def _probe_direct_reachability():
    """Реальная проверка интернета: curl до HTTP target, а не только link-up интерфейса."""
    target = _connectivity_target()
    cmd = [CURL, "-sS", "-o", "/dev/null", "--connect-timeout", "4", "--max-time", "8",
           "-w", "%{http_code} %{time_total}", target]
    r = sys_probe.run(cmd, timeout=10)
    base = {"target": target, "code": "000", "ms": None, "reachable": None, "status": "unknown"}
    if r["timeout"]:
        return base
    if not r["out"]:
        return base
    parts = r["out"].split()
    if len(parts) < 2:
        return base
    code, elapsed = parts[0], parts[1]
    try:
        ms = round(float(elapsed) * 1000)
    except (TypeError, ValueError):
        ms = None
    if code == "000":
        return {"target": target, "code": code, "ms": ms, "reachable": False, "status": "down"}
    try:
        code_int = int(code)
    except (TypeError, ValueError):
        return base
    if 100 <= code_int < 600:
        return {"target": target, "code": code, "ms": ms, "reachable": True, "status": "ok"}
    return base


def _metered_guess(channel):
    # На macOS нет стабильного metered API; честно отмечаем только очевидный USB-tether.
    if channel == "usb_tether":
        return True, "usb_tether"
    return None, "unknown"


def probe_connectivity():
    """Активный канал + real reachability. Наблюдает, ничего не переключает."""
    try:
        dr = sys_probe.run([ROUTE, "-n", "get", "default"], timeout=3)
        default_iface = _first(r"interface:\s*(\S+)", dr["out"]) if not dr["timeout"] else ""
        hardware_ports = _hardware_ports()
        ic = sys_probe.run([IFCONFIG], timeout=4)
        ifaces = _parse_ifconfig_ifaces(ic["out"] if not ic["timeout"] else "", default_iface, hardware_ports)
        active = next((item for item in ifaces if item["name"] == default_iface), None)
        port = hardware_ports.get(default_iface, {}) if default_iface else {}
        hardware_port = ""
        if isinstance(port, dict):
            hardware_port = port.get("hardware_port", "") or ""
        if active and not hardware_port:
            hardware_port = active.get("hardware_port", "") or ""
        channel = active.get("channel", "") if active else _channel_for_iface(default_iface, hardware_port, "")
        if (not default_iface or (not active and not hardware_port)) and channel == "other":
            channel = "unknown"

        reach = _probe_direct_reachability()
        metered, reason = _metered_guess(channel)
        status = reach.get("status", "unknown")
        if channel == "unknown" and status == "ok":
            status = "unknown"
        return {
            "active_iface": default_iface,
            "default_iface": default_iface,
            "addr": active.get("addr", "") if active else "",
            "hardware_port": hardware_port,
            "channel": channel,
            "link_up": bool(active),
            "reachable": reach.get("reachable"),
            "reachability": reach,
            "metered": metered,
            "limited": metered,
            "metered_reason": reason,
            "status": status,
        }
    except Exception as e:
        return {
            "active_iface": "",
            "default_iface": "",
            "addr": "",
            "hardware_port": "",
            "channel": "unknown",
            "link_up": False,
            "reachable": None,
            "reachability": {"target": "", "code": "000", "ms": None,
                             "reachable": None, "status": "unknown"},
            "metered": None,
            "limited": None,
            "metered_reason": "unknown",
            "status": "unknown",
            "error": str(e) or e.__class__.__name__,
        }


def probe_ifaces():
    """Активные интерфейсы (en0/ppp0/utunN) addr+MTU, маркер default-маршрута."""
    dr = sys_probe.run([ROUTE, "-n", "get", "default"], timeout=3)
    default_iface = _first(r"interface:\s*(\S+)", dr["out"]) if not dr["timeout"] else ""
    hardware_ports = _hardware_ports()
    r = sys_probe.run([IFCONFIG], timeout=4)
    ifaces = _parse_ifconfig_ifaces(r["out"] if not r["timeout"] else "", default_iface, hardware_ports)
    return {"ifaces": ifaces[:8], "default": default_iface,
            "status": "ok" if ifaces else "down"}


def _exit_ip_via_iface(iface):
    """Выходной IP при запросе, привязанном к конкретному интерфейсу (--interface iface).

    `--interface` заставляет curl отправлять пакеты через заданный интерфейс, обходя
    default-маршрут ОС. Так можно увидеть реальный выход КАЖДОГО канала (VPN vs прямой),
    не отключая VPN и не меняя маршруты. Аналог _exit_ip из dashboard_geo, но с iface
    и без прокси (нас интересует сам интерфейс, а не цепочка privoxy→xray).
    """
    r = sys_probe.run([CURL, "-sS", "--interface", iface, "--connect-timeout", "4",
                       "--max-time", "8", "https://api.ip.sb/ip"], timeout=10)
    ip = r["out"].strip() if not r["timeout"] else ""
    return ip if (ip and len(ip) <= 45 and (":" in ip or ip.count(".") == 3)) else ""


def probe_exit_ips_per_iface():
    """Exit-IP для каждого активного интерфейса (en0/ppp0/...): показывает реальный выход
    каждого канала — через VPN и прямой — одновременно, не отключая VPN.

    Переиспользует probe_ifaces() для списка интерфейсов (фильтр en*/ppp*/utun*, без lo0).
    """
    ifaces_data = probe_ifaces()
    default_iface = ifaces_data.get("default", "")
    exits = []
    for it in ifaces_data.get("ifaces", []):
        name = it["name"]
        # интерфейс без локального IP и не default — не опрашиваем (нет смысла)
        if not it.get("addr") and name != default_iface:
            continue
        exits.append({"iface": name,
                      "local_ip": it.get("addr", ""),
                      "is_default": bool(it.get("is_default", name == default_iface)),
                      "exit_ip": _exit_ip_via_iface(name)})
    return {"exits": exits, "default_iface": default_iface,
            "status": "ok" if any(e["exit_ip"] for e in exits) else "down"}


def _parse_network_services(text):
    """networksetup -listallnetworkservices -> ordered service names, disabled marker stripped."""
    services = []
    for raw in (text or "").splitlines():
        name = raw.strip()
        if not name or name.startswith("An asterisk"):
            continue
        if name.startswith("*"):
            name = name[1:].strip()
        if name:
            services.append(name)
    return services


def _known_service_name(name, services):
    if not isinstance(name, str):
        return ""
    wanted = name.strip()
    if not wanted:
        return ""
    for service in services:
        if service == wanted:
            return service
    wanted_low = wanted.lower()
    for service in services:
        if service.lower() == wanted_low:
            return service
    return ""


def _configured_channel_service(target, services):
    try:
        state = local_state.load_state()
    except Exception:
        state = {}
    network = state.get("network") if isinstance(state, dict) else {}
    channels = network.get("channels") if isinstance(network, dict) else {}
    if not isinstance(channels, dict):
        return ""
    return _known_service_name(channels.get(CHANNEL_SERVICE_KEYS[target], ""), services)


def _hardware_channel_service(target, services):
    expected = "usb_tether" if target == "usb" else target
    for port in _hardware_ports().values():
        if not isinstance(port, dict):
            continue
        hardware_port = port.get("hardware_port", "") or ""
        device = port.get("device", "") or ""
        if _channel_for_iface(device, hardware_port, "") != expected:
            continue
        service = _known_service_name(hardware_port, services)
        if service:
            return service
    return ""


def _channel_service_name(target, services):
    return (
        _configured_channel_service(target, services)
        or _hardware_channel_service(target, services)
    )


def _channel_result(target, result, service=""):
    err = result.get("err") or ""
    cancelled = result.get("rc") == -128 or bool(re.search(r"\(-128\)\s*\Z", err))
    timeout = bool(result.get("timeout"))
    return {
        "ok": result.get("rc") == 0 and not timeout,
        "rc": result.get("rc"),
        "out": result.get("out") or "",
        "err": err,
        "cancelled": cancelled,
        "timeout": timeout,
        "target": target,
        "service": service,
    }


def _shell_join(args):
    return " ".join(shlex.quote(str(arg)) for arg in args)


def switch_channel(target):
    if target not in CHANNEL_TARGETS:
        return _channel_result(target, {"rc": None, "out": "", "err": "bad channel target", "timeout": False})

    listed = sys_probe.run([NETWORKSETUP, "-listallnetworkservices"], timeout=4)
    if listed["timeout"] or listed["rc"] != 0:
        return _channel_result(target, listed)

    services = _parse_network_services(listed["out"])
    service = _channel_service_name(target, services)
    if not service:
        return _channel_result(
            target,
            {"rc": None, "out": "", "err": f"network service not found for channel: {target}", "timeout": False},
        )

    ordered_services = [service] + [item for item in services if item != service]
    enable_cmd = _shell_join([NETWORKSETUP, "-setnetworkserviceenabled", service, "on"])
    reorder_cmd = _shell_join([NETWORKSETUP, "-ordernetworkservices", *ordered_services])
    shell_cmd = f"{enable_cmd} && {reorder_cmd}"

    # ВАЖНО: target проходит strict whitelist, а shell_cmd собран только из констант,
    # флагов-литералов и network-service names, подтверждённых networksetup. Ввод
    # запроса в shell-строку не попадает; новые динамические части требуют whitelist + escaping.
    applescript = f'do shell script "{_applescript_text(shell_cmd)}" with administrator privileges'
    result = sys_probe.run([OSASCRIPT, "-e", applescript], timeout=60)
    return _channel_result(target, result, service=service)
