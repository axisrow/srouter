"""Сетевые probe-хелперы dashboard без импорта Flask/dashboard."""

import sys_probe
from dashboard_common import (
    BREW,
    CURL,
    GATEWAY,
    HTTP_PROXY_URL,
    IFCONFIG,
    PING,
    PRIVOXY,
    ROUTE,
    VPN_EXIT_IP,
    VPN_SERVER,
    XRAY_SOCKS,
    _active_route_ip,
    _first,
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
    try:
        code, t = r["out"].split()
        return {"code": code, "ms": round(float(t) * 1000), "up": code != "000"}
    except ValueError:
        return {"code": "000", "ms": None, "up": False}


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


def probe_route_to_vps(route_ip=None):
    if route_ip is None:
        route_ip = _active_route_ip()
    if not route_ip:
        return {"interface": "", "gateway": "", "split_active": False, "status": "down"}
    r = sys_probe.run([ROUTE, "-n", "get", "-host", route_ip], timeout=3)
    iface = _first(r"interface:\s*(\S+)", r["out"]) if not r["timeout"] else ""
    gw = _first(r"gateway:\s*(\S+)", r["out"]) if not r["timeout"] else ""
    bypass = iface.startswith("en") or (gw == GATEWAY)
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


def probe_ping(route_ip=None):
    """avg RTT до VPS и VPN-сервера + потери."""
    if route_ip is None:
        route_ip = _active_route_ip()
    vps_ms, vps_loss = _ping_avg(route_ip)
    vpn_ms, vpn_loss = _ping_avg(VPN_SERVER)
    st = "down" if vps_ms is None else ("ok" if vps_ms < 120 else "warn")
    return {"vps_ms": vps_ms, "vps_loss": vps_loss, "vpn_ms": vpn_ms,
            "vpn_loss": vpn_loss, "status": st}
