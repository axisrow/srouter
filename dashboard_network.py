"""Сетевые probe-хелперы dashboard без импорта Flask/dashboard."""

import sys_probe
from dashboard_common import (
    BREW,
    CURL,
    GATEWAY,
    HTTP_PROXY_URL,
    IFCONFIG,
    PHYSICAL_IFACE_PREFIXES,
    PING,
    PRIVOXY,
    ROUTE,
    VPN_EXIT_IP,
    VPN_SERVER,
    XRAY_SOCKS,
    _active_route_ip,
    _first,
    _iface_is_physical,
)


__all__ = [
    "probe_services",
    "_curl_through",
    "probe_tunnel",
    "probe_exit_ip",
    "probe_vpn",
    "probe_route_to_vps",
    "probe_direct",
    "_parse_ping_stats",
    "_ping_avg",
    "probe_ping",
]


def probe_services():
    """Порты (быстрая правда) + brew-статус (может быть unknown)."""
    privoxy_up = sys_probe.port_open(*PRIVOXY)
    xray_up = sys_probe.port_open(*XRAY_SOCKS)
    r = sys_probe.run([BREW, "services", "list"], timeout=8)

    def brew_state(name):
        if r["timeout"]:
            return "unknown"
        for line in r["out"].splitlines():
            f = line.split()
            if f and f[0] == name:
                return f[1] if len(f) > 1 else "unknown"
        return "none"

    return {
        "privoxy": {"listening": privoxy_up, "brew": brew_state("privoxy"),
                    "status": "ok" if privoxy_up else "down"},
        "xray": {"listening": xray_up, "brew": brew_state("xray"),
                 "status": "ok" if xray_up else "down"},
    }


def _curl_through(url, proxy=True):
    cmd = [CURL, "-sS", "-o", "/dev/null", "--connect-timeout", "4", "--max-time", "8",
           "-w", "%{http_code} %{time_total}"]
    if proxy:
        cmd += ["-x", HTTP_PROXY_URL]
    cmd.append(url)
    r = sys_probe.run(cmd, timeout=10)
    if r["timeout"] or not r["out"]:
        return {"code": "000", "ms": None, "up": False}
    parts = r["out"].split()
    if len(parts) < 2:
        return {"code": "000", "ms": None, "up": False}
    code, t = parts[0], parts[1]
    try:
        code_int = int(code)
    except (TypeError, ValueError):
        return {"code": "000", "ms": None, "up": False}
    try:
        ms = round(float(t) * 1000)
    except (TypeError, ValueError):
        ms = None
    return {"code": code, "ms": ms, "up": sys_probe.tunnel_code_up(code_int)}


def probe_tunnel():
    a = _curl_through("https://api.anthropic.com/")
    o = _curl_through("https://api.openai.com/")
    up = a["up"] or o["up"]
    return {"anthropic": a, "openai": o, "status": "ok" if up else "down"}


def probe_exit_ip(route_ip=None):
    # api.ip.sb доступен и через VPS-туннель, и через VPN/прямой выход — поэтому честно
    # показывает РЕАЛЬНУЮ точку выхода (VPS vs VPN). api.ipify.org из Китая часто таймаутит
    # и давал ложный "цепочка недоступна".
    r = sys_probe.run([CURL, "-sS", "-x", HTTP_PROXY_URL, "--connect-timeout", "4",
                       "--max-time", "8", "https://api.ip.sb/ip"], timeout=10)
    ip = r["out"] if not r["timeout"] else ""
    if route_ip is None:
        route_ip = _active_route_ip()
    if route_ip and ip == route_ip:
        return {"ip": ip, "label_key": "vps_direct",
                "label": "VPS (direct exit)", "status": "ok"}
    elif ip == VPN_EXIT_IP:
        return {"ip": ip, "label_key": "via_vpn",
                "label": "via VPN — split-route needed", "status": "warn"}
    elif not ip:
        return {"ip": "", "label_key": "chain_down",
                "label": "chain unavailable", "status": "down"}
    return {"ip": ip, "label_key": "unexpected",
            "label": "unexpected exit", "status": "warn"}


def probe_vpn():
    ic = sys_probe.run([IFCONFIG, "ppp0"], timeout=3)
    vpn_up = ic["rc"] == 0
    dr = sys_probe.run([ROUTE, "-n", "get", "default"], timeout=3)
    iface = _first(r"interface:\s*(\S+)", dr["out"])
    return {"vpn_up": vpn_up, "default_iface": iface, "vpn_server": VPN_SERVER,
            "status": "warn" if iface == "ppp0" else "ok"}


def _physical_iface_prefixes():
    """Префиксы физических интерфейсов — источник истины из config (мокабельно в тестах)."""
    return PHYSICAL_IFACE_PREFIXES


def probe_route_to_vps(route_ip=None):
    if route_ip is None:
        route_ip = _active_route_ip()
    if not route_ip:
        return {"interface": "", "gateway": "", "split_active": False, "status": "down"}
    r = sys_probe.run([ROUTE, "-n", "get", "-host", route_ip], timeout=3)
    iface = _first(r"interface:\s*(\S+)", r["out"]) if not r["timeout"] else ""
    gw = _first(r"gateway:\s*(\S+)", r["out"]) if not r["timeout"] else ""
    # split активен если route идёт через физический интерфейс (config-префиксы, не литерал 'en')
    # ЛИБО через наш физический шлюз (строгий сигнал gw==GATEWAY).
    bypass = _iface_is_physical(iface, _physical_iface_prefixes()) or (gw == GATEWAY)
    return {"interface": iface, "gateway": gw, "split_active": bypass,
            "status": "ok" if bypass else "warn"}


def probe_direct():
    # api.ip.sb доступен из Китая напрямую (в отличие от ipify) — карточка "прямой доступ"
    # показывает реальную работу сети без прокси, а не вечный DOWN.
    d = _curl_through("https://api.ip.sb/ip", proxy=False)
    return {"code": d["code"], "ms": d["ms"], "status": "ok" if d["up"] else "down"}


def _parse_ping_stats(text):
    """Разобрать macOS ping summary: avg RTT + packet loss. Не бросает."""
    if not text:
        return (None, None)
    avg = _first(r"=\s*[\d.]+/([\d.]+)/", text)
    loss = _first(r"([\d.]+)%\s*packet loss", text)
    try:
        return (round(float(avg)) if avg else None, float(loss) if loss else None)
    except ValueError:
        return (None, None)


def _ping_avg(host):
    if not host:
        return (None, None)
    r = sys_probe.run([PING, "-c", "3", "-t", "4", host], timeout=8)
    return _parse_ping_stats(r["out"])


# Пороги packet loss (первоисточник — ping summary '% packet loss'). 100% = канал мёртв
# даже при просочившемся avg; заметная частичная потеря деградирует до warn. Ниже LOSS_WARN
# — шум (единичные пропуски), не сигналим.
_LOSS_WARN_PCT = 20.0
_LOSS_DOWN_PCT = 100.0


def _ping_status(ms, loss):
    """Статус канала по RTT И packet loss. Нет данных RTT или 100% потерь → down;
    заметная частичная потеря или высокий RTT → warn; иначе ok."""
    if ms is None:
        return "down"
    if loss is not None and loss >= _LOSS_DOWN_PCT:
        return "down"
    if loss is not None and loss >= _LOSS_WARN_PCT:
        return "warn"
    return "ok" if ms < 120 else "warn"


def probe_ping(route_ip=None):
    """avg RTT до VPS и VPN-сервера + потери."""
    if route_ip is None:
        route_ip = _active_route_ip()
    vps_ms, vps_loss = _ping_avg(route_ip)
    vpn_ms, vpn_loss = _ping_avg(VPN_SERVER)
    st = _ping_status(vps_ms, vps_loss)
    return {"vps_ms": vps_ms, "vps_loss": vps_loss, "vpn_ms": vpn_ms,
            "vpn_loss": vpn_loss, "status": st}
