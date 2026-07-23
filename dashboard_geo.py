"""Geo/telemetry helpers dashboard без импорта Flask/dashboard."""

import json
import math
import threading
import time

import sys_probe
from dashboard_common import CURL, HTTP_PROXY_URL, _active_route_ip


__all__ = [
    "_GEO_TTL",
    "_geo_cache",
    "_geo_lock",
    "_country_flag",
    "_geo_lookup",
    "_exit_ip",
    "probe_ips",
    "probe_geo_distance",
]


_GEO_TTL = 3600
_geo_cache = {}            # ip -> {"ts": float, "data": dict}
_geo_lock = threading.Lock()


def _country_flag(cc):
    if not cc or len(cc) != 2 or not cc.isalpha():
        return ""
    cc = cc.upper()
    return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)


def _geo_lookup(ip):
    """{country_code,country,city,isp,asn,asn_org,lat,lon,flag}. Кэш _GEO_TTL. Всегда dict."""
    if not ip:
        return {}
    now = time.time()
    with _geo_lock:
        c = _geo_cache.get(ip)
        if c and now - c["ts"] < _GEO_TTL:
            return c["data"]
    r = sys_probe.run([CURL, "-sS", "-A", "Mozilla/5.0", "--connect-timeout", "3", "--max-time", "5",
                       "https://api.ip.sb/geoip/" + ip], timeout=6)   # UA обязателен (без него 403); вызов ВНЕ lock
    data = {}
    if not r["timeout"] and r["out"]:
        try:
            j = json.loads(r["out"])
            cc = j.get("country_code", "") or ""
            data = {"country_code": cc, "country": j.get("country", "") or "",
                    "city": j.get("city", "") or "", "isp": j.get("isp", "") or "",
                    "asn": j.get("asn", "") or "", "asn_org": j.get("asn_organization", "") or "",
                    "lat": j.get("latitude"), "lon": j.get("longitude"), "flag": _country_flag(cc)}
        except (ValueError, TypeError):
            data = {}
    with _geo_lock:
        _geo_cache[ip] = {"ts": now, "data": data}   # кэшируем даже пустой (нет retry-штормов)
    return data


def _exit_ip(via_proxy):
    cmd = [CURL, "-sS", "--connect-timeout", "4", "--max-time", "8"]
    if via_proxy:
        cmd += ["-x", HTTP_PROXY_URL]
    cmd.append("https://api.ip.sb/ip")
    r = sys_probe.run(cmd, timeout=10)
    ip = r["out"].strip() if not r["timeout"] else ""
    return ip if (ip and len(ip) <= 45 and (":" in ip or ip.count(".") == 3)) else ""


def probe_ips(route_ip=None):
    """3 IP (прямой/VPN, выход цепочки, VPS) + гео каждого."""
    chain_ip = _exit_ip(via_proxy=True)
    direct_ip = _exit_ip(via_proxy=False)
    if route_ip is None:
        route_ip = _active_route_ip()

    def node(ip, role):
        g = _geo_lookup(ip) if ip else {}
        return {"ip": ip or "", "role": role, "flag": g.get("flag", ""),
                "country_code": g.get("country_code", ""), "country": g.get("country", ""),
                "city": g.get("city", ""), "isp": g.get("isp", ""), "asn": g.get("asn", ""),
                "asn_org": g.get("asn_org", ""), "lat": g.get("lat"), "lon": g.get("lon")}

    if chain_ip and route_ip and chain_ip == route_ip:
        status = "ok"
    elif chain_ip and direct_ip and chain_ip == direct_ip:
        status = "warn"
    elif not chain_ip and not direct_ip:
        status = "down"
    else:
        status = "warn"
    return {"direct": node(direct_ip, "direct"), "chain": node(chain_ip, "chain"),
            "vps": node(route_ip, "vps"), "status": status}


def probe_geo_distance(route_ip=None):
    """Великокружная дистанция (км) от локального выхода до VPS (haversine)."""
    if route_ip is None:
        route_ip = _active_route_ip()
    here = _geo_lookup(_exit_ip(via_proxy=False))
    there = _geo_lookup(route_ip)
    la1, lo1, la2, lo2 = here.get("lat"), here.get("lon"), there.get("lat"), there.get("lon")
    if la1 is None or lo1 is None or la2 is None or lo2 is None:
        return {"km": None, "from_city": here.get("city", ""),
                "to_city": there.get("city", ""), "status": "down"}
    la1, lo1, la2, lo2 = float(la1), float(lo1), float(la2), float(lo2)
    R = 6371.0
    p1, p2 = math.radians(la1), math.radians(la2)
    dp, dl = math.radians(la2 - la1), math.radians(lo2 - lo1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    km = round(2 * R * math.asin(min(1.0, math.sqrt(a))))
    return {"km": km, "from_city": here.get("city", ""), "from_flag": here.get("flag", ""),
            "to_city": there.get("city", ""), "to_flag": there.get("flag", ""), "status": "ok"}
