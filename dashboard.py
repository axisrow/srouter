#!/usr/bin/env python3
"""Локальный дашборд: мониторинг и управление цепочкой privoxy→xray→Reality + VPN/маршруты.

Запуск:  python3 dashboard.py   →   http://127.0.0.1:8787
Только loopback, debug=False. Privileged-действия (route) спрашивают пароль macOS через osascript.
"""
import socket
import subprocess
import threading
import time
import re
import json
import math
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, jsonify, Response

# --- захардкоженные факты окружения (проверены) ---
BREW = "/opt/homebrew/bin/brew"          # абсолютный путь: launchd/GUI PATH его не содержит
CURL = "/usr/bin/curl"
ROUTE = "/sbin/route"
IFCONFIG = "/sbin/ifconfig"
OSASCRIPT = "/usr/bin/osascript"
PING = "/sbin/ping"
SCUTIL = "/usr/sbin/scutil"

# Адреса инфраструктуры — из локального srouter_config.py (не в репозитории).
# Скопируй шаблон: cp srouter_config.example.py srouter_config.py
try:
    import srouter_config as _cfg
    GATEWAY = _cfg.GATEWAY
    VPN_SERVER = _cfg.VPN_SERVER
    VPN_EXIT_IP = _cfg.VPN_EXIT_IP
    _CFG_VPS_IP = getattr(_cfg, "VPS_IP", "")   # legacy fallback
    import node_registry
    def _active_host():
        return node_registry.active_node().get("host") or _CFG_VPS_IP
    VPS_IP = _active_host()
except ImportError:
    raise SystemExit("Нет srouter_config.py — скопируй: cp srouter_config.example.py srouter_config.py")

PRIVOXY = ("127.0.0.1", 8118)
XRAY_SOCKS = ("127.0.0.1", 10808)
HTTP_PROXY_URL = "http://127.0.0.1:8118"
PORT = 8787

app = Flask(__name__)


# ============================ базовые помощники ============================
def run(cmd_list, timeout):
    """Всегда список аргументов, НИКОГДА shell=True. Возвращает dict, не бросает."""
    try:
        p = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "out": p.stdout.strip(),
                "err": p.stderr.strip(), "timeout": False}
    except subprocess.TimeoutExpired:
        return {"rc": None, "out": "", "err": "timeout", "timeout": True}
    except Exception as e:
        return {"rc": None, "out": "", "err": str(e), "timeout": True}


def port_open(host, port, timeout=0.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _first(pattern, text):
    m = re.search(pattern, text)
    return m.group(1) if m else ""


# ============================ probe-функции ============================
def probe_services():
    """Порты (быстрая правда) + brew-статус (может быть unknown)."""
    privoxy_up = port_open(*PRIVOXY)
    xray_up = port_open(*XRAY_SOCKS)
    r = run([BREW, "services", "list"], timeout=8)

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
    r = run(cmd, timeout=10)
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


def probe_exit_ip():
    # api.ip.sb доступен и через VPS-туннель, и через VPN/прямой выход — поэтому честно
    # показывает РЕАЛЬНУЮ точку выхода (VPS vs VPN). api.ipify.org из Китая часто таймаутит
    # и давал ложный "цепочка недоступна".
    r = run([CURL, "-sS", "-x", HTTP_PROXY_URL, "--connect-timeout", "4",
             "--max-time", "8", "https://api.ip.sb/ip"], timeout=10)
    ip = r["out"] if not r["timeout"] else ""
    if ip == VPS_IP:
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
    ic = run([IFCONFIG, "ppp0"], timeout=3)
    vpn_up = ic["rc"] == 0
    dr = run([ROUTE, "-n", "get", "default"], timeout=3)
    iface = _first(r"interface:\s*(\S+)", dr["out"])
    return {"vpn_up": vpn_up, "default_iface": iface, "vpn_server": VPN_SERVER,
            "status": "warn" if iface == "ppp0" else "ok"}


def probe_route_to_vps():
    r = run([ROUTE, "-n", "get", "-host", VPS_IP], timeout=3)
    iface = _first(r"interface:\s*(\S+)", r["out"]) if not r["timeout"] else ""
    gw = _first(r"gateway:\s*(\S+)", r["out"]) if not r["timeout"] else ""
    bypass = (iface == "en0") or (gw == GATEWAY)
    return {"interface": iface, "gateway": gw, "split_active": bypass,
            "status": "ok" if bypass else "warn"}


def probe_direct():
    # api.ip.sb доступен из Китая напрямую (в отличие от ipify) — карточка "прямой доступ"
    # показывает реальную работу сети без прокси, а не вечный DOWN.
    d = _curl_through("https://api.ip.sb/ip", proxy=False)
    return {"code": d["code"], "ms": d["ms"], "status": "ok" if d["up"] else "down"}


# ============================ киношная телеметрия: гео-кэш + хелперы ============================
_GEO_TTL = 3600
_geo_cache = {}            # ip -> {"ts": float, "data": dict}
_geo_lock = threading.Lock()

_DNS_KNOWN = {
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "8.8.8.8": "Google", "8.8.4.4": "Google",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard",
    "223.5.5.5": "AliDNS", "223.6.6.6": "AliDNS",
    "119.29.29.29": "DNSPod", "180.76.76.76": "Baidu",
}
# публичные DNS для проверки доступности
_DNS_PUBLIC = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222",
               "94.140.14.14", "223.5.5.5", "119.29.29.29"]


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
    r = run([CURL, "-sS", "-A", "Mozilla/5.0", "--connect-timeout", "3", "--max-time", "5",
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
    r = run(cmd, timeout=10)
    ip = r["out"].strip() if not r["timeout"] else ""
    return ip if (ip and len(ip) <= 45 and (":" in ip or ip.count(".") == 3)) else ""


def probe_ips():
    """3 IP (прямой/VPN, выход цепочки, VPS) + гео каждого."""
    chain_ip = _exit_ip(via_proxy=True)
    direct_ip = _exit_ip(via_proxy=False)

    def node(ip, role):
        g = _geo_lookup(ip) if ip else {}
        return {"ip": ip or "", "role": role, "flag": g.get("flag", ""),
                "country_code": g.get("country_code", ""), "country": g.get("country", ""),
                "city": g.get("city", ""), "isp": g.get("isp", ""), "asn": g.get("asn", ""),
                "asn_org": g.get("asn_org", ""), "lat": g.get("lat"), "lon": g.get("lon")}

    if chain_ip and chain_ip == VPS_IP:
        status = "ok"
    elif chain_ip and direct_ip and chain_ip == direct_ip:
        status = "warn"
    elif not chain_ip and not direct_ip:
        status = "down"
    else:
        status = "warn"
    return {"direct": node(direct_ip, "direct"), "chain": node(chain_ip, "chain"),
            "vps": node(VPS_IP, "vps"), "status": status}


def _ping_avg(host):
    r = run([PING, "-c", "3", "-t", "4", host], timeout=8)
    avg = _first(r"=\s*[\d.]+/([\d.]+)/", r["out"])
    loss = _first(r"([\d.]+)%\s*packet loss", r["out"])
    try:
        return (round(float(avg)) if avg else None, float(loss) if loss else None)
    except ValueError:
        return (None, None)


def probe_ping():
    """avg RTT до VPS и VPN-сервера + потери."""
    vps_ms, vps_loss = _ping_avg(VPS_IP)
    vpn_ms, vpn_loss = _ping_avg(VPN_SERVER)
    st = "down" if vps_ms is None else ("ok" if vps_ms < 120 else "warn")
    return {"vps_ms": vps_ms, "vps_loss": vps_loss, "vpn_ms": vpn_ms,
            "vpn_loss": vpn_loss, "status": st}


def _dns_check(ip):
    """TCP :53 доступность + грубый ms."""
    t0 = time.time()
    up = port_open(ip, 53, timeout=1.5)
    ms = round((time.time() - t0) * 1000) if up else None
    return {"ip": ip, "name": _DNS_KNOWN.get(ip, ""), "up": up, "ms": ms}


def probe_dns():
    """Системные резолверы (scutil) + проверка доступности публичных DNS."""
    r = run([SCUTIL, "--dns"], timeout=4)
    seen, servers = set(), []
    if not r["timeout"]:
        for line in r["out"].splitlines():
            m = re.search(r"nameserver\[\d+\]\s*:\s*(\S+)", line)
            if m and m.group(1) not in seen:
                seen.add(m.group(1))
                servers.append({"ip": m.group(1), "name": _DNS_KNOWN.get(m.group(1), "")})
            if len(servers) >= 6:
                break
    with ThreadPoolExecutor(max_workers=len(_DNS_PUBLIC)) as ex:
        public = list(ex.map(_dns_check, _DNS_PUBLIC))
    return {"servers": servers, "public": public, "count": len(servers),
            "status": "ok" if servers else "down"}


def probe_ifaces():
    """Активные интерфейсы (en0/ppp0/utunN) addr+MTU, маркер default-маршрута."""
    dr = run([ROUTE, "-n", "get", "default"], timeout=3)
    default_iface = _first(r"interface:\s*(\S+)", dr["out"]) if not dr["timeout"] else ""
    r = run([IFCONFIG], timeout=4)
    ifaces = []
    if not r["timeout"] and r["out"]:
        for b in re.split(r"\n(?=\S)", r["out"]):
            head = re.match(r"^(\w[\w.]*?):\s.*?mtu\s+(\d+)", b)
            if not head:
                continue
            name, mtu = head.group(1), head.group(2)
            if not re.match(r"(en\d|ppp\d|utun\d)", name):
                continue
            addr = _first(r"inet\s+(\d+\.\d+\.\d+\.\d+)", b)
            if not addr and name not in (default_iface, "ppp0"):
                continue
            ifaces.append({"name": name, "addr": addr or "", "mtu": mtu,
                           "is_default": name == default_iface})
    ifaces.sort(key=lambda x: (not x["is_default"], x["name"]))
    return {"ifaces": ifaces[:8], "default": default_iface,
            "status": "ok" if ifaces else "down"}


def probe_geo_distance():
    """Великокружная дистанция (км) от локального выхода до VPS (haversine)."""
    here = _geo_lookup(_exit_ip(via_proxy=False))
    there = _geo_lookup(VPS_IP)
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


# ============================ сборка статуса ============================
_cache = {"ts": 0.0, "data": None}
_lock = threading.Lock()


def gather_status():
    with _lock:
        now = time.time()
        if _cache["data"] and now - _cache["ts"] < 1.5:
            return _cache["data"]
        probes = {"services": probe_services, "tunnel": probe_tunnel,
                  "exit_ip": probe_exit_ip, "vpn": probe_vpn,
                  "route": probe_route_to_vps, "direct": probe_direct,
                  # --- киношная телеметрия ---
                  "ips": probe_ips, "ping": probe_ping, "dns": probe_dns,
                  "ifaces": probe_ifaces, "geo_distance": probe_geo_distance}
        out = {}
        with ThreadPoolExecutor(max_workers=11) as ex:
            futs = {k: ex.submit(fn) for k, fn in probes.items()}
            for k, f in futs.items():
                try:
                    out[k] = f.result(timeout=12)
                except Exception as e:
                    out[k] = {"status": "unknown", "error": str(e)}
        out["ts"] = now
        _cache.update(ts=now, data=out)
        return out


# ============================ privileged: osascript-мост ============================
def sudo_route(action):
    if action == "add":
        shell_cmd = f"{ROUTE} -n add -host {VPS_IP} {GATEWAY}"
    elif action == "remove":
        shell_cmd = f"{ROUTE} -n delete -host {VPS_IP}"
    else:
        raise ValueError("bad action")        # глубокая защита
    # ВАЖНО: shell_cmd собран ТОЛЬКО из констант, ввод запроса сюда не попадает никогда.
    # Если кто-то добавит динамическую команду — обязан добавить вайтлист + экранирование.
    applescript = f'do shell script "{shell_cmd}" with administrator privileges'
    return run([OSASCRIPT, "-e", applescript], timeout=60)


# ============================ non-privileged: сервисы ============================
def service_control(name, action):
    return run([BREW, "services", action, name], timeout=20)


# ============================ Flask-роуты ============================
@app.get("/api/status")
def api_status():
    return jsonify(gather_status())


@app.post("/api/route/<action>")
def api_route(action):
    if action not in ("add", "remove"):
        return jsonify({"ok": False, "err": "bad action"}), 400
    r = sudo_route(action)
    cancelled = r["rc"] not in (0, None) and "-128" in (r["err"] or "")
    return jsonify({"ok": r["rc"] == 0, "cancelled": cancelled, **r})


@app.post("/api/service/<name>/<action>")
def api_service(name, action):
    if name not in ("xray", "privoxy") or action not in ("start", "stop", "restart"):
        return jsonify({"ok": False, "err": "not allowed"}), 400
    r = service_control(name, action)
    return jsonify({"ok": r["rc"] == 0, **r})


@app.get("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")


# ============================ одностраничный UI ============================
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Tunnel Dashboard</title>
  <link rel="stylesheet" href="/static/bootstrap.min.css">
  <link rel="stylesheet" href="/static/bootstrap-icons.min.css">
  <style>
    body { padding-bottom: 3rem; }
    .spark { display: block; }
    .val-big { font-size: 1.9rem; font-weight: 600; line-height: 1.1; }
    .val-xl  { font-size: 2.6rem; font-weight: 700; line-height: 1.05; }
    .card-icon { font-size: 1.25rem; opacity: .75; }
    .sub { font-size: .85rem; }
    .mono { font-variant-numeric: tabular-nums; }
    .headline-card { border-width: 2px; }
    .pulse { animation: pulse 1s ease-in-out infinite; }
    @keyframes pulse { 50% { opacity: .35; } }
    .toast-container { z-index: 1090; }
    /* cinematic */
    body.mode-simple .cine { display: none !important; }
    .flow-strip { display:flex; flex-wrap:wrap; align-items:stretch; gap:.5rem; }
    .flow-node { flex:1 1 0; min-width:150px; border:1px solid var(--bs-border-color);
      border-radius:.6rem; padding:.6rem .75rem; background:var(--bs-body-bg);
      position:relative; overflow:hidden; }
    .flow-node .flag { font-size:1.6rem; line-height:1; }
    .flow-node .ip { font-size:1.05rem; font-weight:600; }
    .flow-node .role { font-size:.7rem; letter-spacing:.06em; text-transform:uppercase; opacity:.6; }
    .flow-node .meta { font-size:.72rem; opacity:.75; margin-top:.2rem; }
    .flow-arrow { display:flex; flex-direction:column; align-items:center; justify-content:center;
      min-width:54px; color:var(--bs-secondary-color); font-family:var(--bs-font-monospace); }
    .flow-arrow .rtt { font-size:.7rem; opacity:.85; }
    .flow-node.live::after { content:""; position:absolute; left:0; top:0; height:2px; width:100%;
      background:linear-gradient(90deg,transparent,var(--bs-primary),transparent);
      animation:scan 2.2s linear infinite; }
    @keyframes scan { 0%{transform:translateX(-100%);} 100%{transform:translateX(100%);} }
    .ops { font-family:var(--bs-font-monospace); font-size:.82rem; }
    .ops .k { opacity:.6; }
    .dns-pill { font-family:var(--bs-font-monospace); font-size:.75rem; }
    .dns-dot { display:inline-block; width:7px; height:7px; border-radius:50%; margin-left:4px; }
    .dns-up { background:#3fb950; } .dns-down { background:#f85149; }
  </style>
</head>
<body>
  <nav class="navbar navbar-expand bg-body-tertiary border-bottom mb-3">
    <div class="container-fluid">
      <span class="navbar-brand mb-0 h1">
        <i class="bi bi-shield-lock-fill text-primary"></i>
        <span data-i18n="brand">Tunnel Dashboard</span>
      </span>
      <div class="d-flex align-items-center gap-2 ms-auto">
        <span id="updated" class="text-secondary small mono d-none d-sm-inline">—</span>
        <select id="langSel" class="form-select form-select-sm" style="width:auto"
                data-i18n-title="lang_title" data-i18n-aria="lang_title">
          <option value="en">EN</option>
          <option value="ru">RU</option>
          <option value="zh">中文</option>
        </select>
        <select id="themeSel" class="form-select form-select-sm" style="width:auto"
                data-i18n-title="theme_title" data-i18n-aria="theme_title">
          <option value="auto" data-i18n="theme_auto">Auto</option>
          <option value="light" data-i18n="theme_light">Light</option>
          <option value="dark" data-i18n="theme_dark">Dark</option>
        </select>
        <button id="modeBtn" class="btn btn-sm btn-outline-secondary" type="button"
                data-i18n-title="mode_cinematic" data-i18n-aria="mode_cinematic">
          <i class="bi bi-eye"></i>
        </button>
        <button id="refreshBtn" class="btn btn-sm btn-outline-primary" type="button">
          <i class="bi bi-arrow-clockwise"></i>
          <span class="d-none d-md-inline" data-i18n="refresh">Refresh</span>
        </button>
      </div>
    </div>
  </nav>

  <div class="container-fluid">
    <div class="card mb-3">
      <div class="card-header d-flex align-items-center">
        <i class="bi bi-diagram-3 me-2"></i>
        <span data-i18n="flow_title">Connection flow</span>
        <span class="ms-auto badge bg-secondary ops" id="flow-badge">—</span>
      </div>
      <div class="card-body">
        <div id="flow-strip" class="flow-strip"></div>
      </div>
    </div>

    <div id="cards" class="row g-3"></div>

    <div class="card mt-3">
      <div class="card-header d-flex align-items-center">
        <i class="bi bi-sliders me-2"></i> <span data-i18n="ctrl_title">Control</span>
      </div>
      <div class="card-body">
        <div class="row g-3">
          <div class="col-12 col-lg-6">
            <div class="fw-semibold mb-2"><i class="bi bi-funnel"></i> privoxy</div>
            <div class="btn-group w-100" role="group">
              <button class="btn btn-outline-success act" data-url="/api/service/privoxy/start"><span class="lbl">Start</span></button>
              <button class="btn btn-outline-danger act"  data-url="/api/service/privoxy/stop"><span class="lbl">Stop</span></button>
              <button class="btn btn-outline-secondary act" data-url="/api/service/privoxy/restart"><span class="lbl">Restart</span></button>
            </div>
          </div>

          <div class="col-12 col-lg-6">
            <div class="fw-semibold mb-2"><i class="bi bi-lightning-charge"></i> xray</div>
            <div class="btn-group w-100" role="group">
              <button class="btn btn-outline-success act" data-url="/api/service/xray/start"><span class="lbl">Start</span></button>
              <button class="btn btn-outline-danger act"  data-url="/api/service/xray/stop"><span class="lbl">Stop</span></button>
              <button class="btn btn-outline-secondary act" data-url="/api/service/xray/restart"><span class="lbl">Restart</span></button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="toast-container position-fixed bottom-0 end-0 p-3"></div>

  <script src="/static/bootstrap.bundle.min.js"></script>
  <script>
  (function () {
    "use strict";

    /* ============================ i18n ============================ */
    var I18N = {
      en: {
        brand: "Tunnel Dashboard", theme_title: "Theme", theme_auto: "Auto",
        theme_light: "Light", theme_dark: "Dark", refresh: "Refresh", lang_title: "Language",
        exit_point: "Exit point (Exit IP)", loading: "loading…",
        card_anthropic: "Anthropic (via tunnel)", card_openai: "OpenAI (via tunnel)",
        card_tunnel: "Tunnel (overall)", card_direct: "Direct access", card_vpn: "VPN",
        card_route: "Route", card_privoxy: "privoxy", card_xray: "xray",
        on: "ON", off: "OFF", reachable: "reachable", unreachable: "unreachable",
        listening: "listening", not_listening: "not listening",
        split_on: "split: ON", split_off: "split: OFF", ms: "ms", tunnel_sub: "anthropic + openai",
        iface: "iface:", srv: "srv:", gw: "gw:", no_data: "no data",
        no_server: "no connection to server", status_failed: "failed to get status",
        ctrl_title: "Control", split_route: "Split route", add: "Add", remove: "Remove",
        split_enable: "Enable split", split_disable: "Disable split",
        exit_vps_direct: "VPS (direct exit)", exit_via_vpn: "via VPN — split-route needed",
        exit_chain_down: "chain unavailable", exit_unexpected: "unexpected exit",
        updated_at: "updated {0}", fetch_status_failed: "Failed to fetch /api/status: {0}",
        cancelled: "Cancelled", ok_req: "OK: {0}", ok_req_out: "OK: {0} — {1}",
        err_req: "Error {0}: {1}", req_failed: "Request failed {0}: {1}",
        spark_empty: "no data", spark_label: "{0} samples, last {1} ms",
        flow_title: "Connection flow", node_vpn_exit: "VPN / direct exit", node_vps: "VPS relay",
        node_internet: "Internet", node_world: "world", node_world_sub: "AI endpoints",
        card_ip_direct: "Direct / VPN exit IP", card_ip_chain: "Chain exit IP",
        card_ip_vps: "VPS endpoint", card_ping: "Ping → VPS", ping_sub: "loss {0}% · VPN {1}",
        card_distance: "Distance to VPS", km: "km", card_dns: "DNS resolvers", resolvers: "resolvers",
        card_dns_public: "Public DNS", card_ifaces: "Interfaces", active: "active",
        no_geo: "no geo data", mode_simple: "Simple mode", mode_cinematic: "Cinematic mode"
      },
      ru: {
        brand: "Tunnel Dashboard", theme_title: "Тема", theme_auto: "Авто",
        theme_light: "Светлая", theme_dark: "Тёмная", refresh: "Обновить", lang_title: "Язык",
        exit_point: "Точка выхода (Exit IP)", loading: "загрузка…",
        card_anthropic: "Anthropic (через туннель)", card_openai: "OpenAI (через туннель)",
        card_tunnel: "Туннель (итог)", card_direct: "Прямой доступ", card_vpn: "VPN",
        card_route: "Маршрут", card_privoxy: "privoxy", card_xray: "xray",
        on: "ВКЛ", off: "ВЫКЛ", reachable: "доступен", unreachable: "недоступен",
        listening: "слушает", not_listening: "не слушает",
        split_on: "split: ВКЛ", split_off: "split: ВЫКЛ", ms: "мс", tunnel_sub: "anthropic + openai",
        iface: "iface:", srv: "srv:", gw: "gw:", no_data: "нет данных",
        no_server: "нет связи с сервером", status_failed: "не удалось получить статус",
        ctrl_title: "Управление", split_route: "Split-маршрут", add: "Добавить", remove: "Убрать",
        split_enable: "Включить split", split_disable: "Выключить split",
        exit_vps_direct: "VPS (прямой выход)", exit_via_vpn: "через VPN — нужен split-route",
        exit_chain_down: "цепочка недоступна", exit_unexpected: "неожиданный выход",
        updated_at: "обновлено {0}", fetch_status_failed: "Не удалось получить /api/status: {0}",
        cancelled: "Отменено", ok_req: "OK: {0}", ok_req_out: "OK: {0} — {1}",
        err_req: "Ошибка {0}: {1}", req_failed: "Сбой запроса {0}: {1}",
        spark_empty: "нет данных", spark_label: "{0} замеров, последний {1} мс",
        flow_title: "Схема соединения", node_vpn_exit: "VPN / прямой выход", node_vps: "VPS-ретранслятор",
        node_internet: "Интернет", node_world: "мир", node_world_sub: "AI-сервисы",
        card_ip_direct: "IP прямого / VPN-выхода", card_ip_chain: "IP выхода цепочки",
        card_ip_vps: "Точка VPS", card_ping: "Пинг → VPS", ping_sub: "потери {0}% · VPN {1}",
        card_distance: "Расстояние до VPS", km: "км", card_dns: "DNS-серверы", resolvers: "серверов",
        card_dns_public: "Публичные DNS", card_ifaces: "Интерфейсы", active: "активно",
        no_geo: "нет гео-данных", mode_simple: "Простой режим", mode_cinematic: "Кинорежим"
      },
      zh: {
        brand: "隧道仪表盘", theme_title: "主题", theme_auto: "自动",
        theme_light: "浅色", theme_dark: "深色", refresh: "刷新", lang_title: "语言",
        exit_point: "出口节点（出口 IP）", loading: "加载中…",
        card_anthropic: "Anthropic（经隧道）", card_openai: "OpenAI（经隧道）",
        card_tunnel: "隧道（汇总）", card_direct: "直连", card_vpn: "VPN",
        card_route: "路由", card_privoxy: "privoxy", card_xray: "xray",
        on: "开", off: "关", reachable: "可达", unreachable: "不可达",
        listening: "监听中", not_listening: "未监听",
        split_on: "分流：开", split_off: "分流：关", ms: "毫秒", tunnel_sub: "anthropic + openai",
        iface: "接口:", srv: "服务器:", gw: "网关:", no_data: "无数据",
        no_server: "无法连接服务器", status_failed: "获取状态失败",
        ctrl_title: "控制", split_route: "分流路由", add: "添加", remove: "移除",
        split_enable: "启用分流", split_disable: "关闭分流",
        exit_vps_direct: "VPS（直接出口）", exit_via_vpn: "经 VPN — 需要分流路由",
        exit_chain_down: "链路不可用", exit_unexpected: "出口异常",
        updated_at: "已更新 {0}", fetch_status_failed: "获取 /api/status 失败：{0}",
        cancelled: "已取消", ok_req: "成功：{0}", ok_req_out: "成功：{0} — {1}",
        err_req: "错误 {0}：{1}", req_failed: "请求失败 {0}：{1}",
        spark_empty: "无数据", spark_label: "{0} 次采样，最近 {1} 毫秒",
        flow_title: "连接链路", node_vpn_exit: "VPN / 直连出口", node_vps: "VPS 中继",
        node_internet: "互联网", node_world: "世界", node_world_sub: "AI 服务",
        card_ip_direct: "直连 / VPN 出口 IP", card_ip_chain: "链路出口 IP",
        card_ip_vps: "VPS 节点", card_ping: "延迟 → VPS", ping_sub: "丢包 {0}% · VPN {1}",
        card_distance: "到 VPS 距离", km: "公里", card_dns: "DNS 解析器", resolvers: "个解析器",
        card_dns_public: "公共 DNS", card_ifaces: "网络接口", active: "活动",
        no_geo: "无地理数据", mode_simple: "简洁模式", mode_cinematic: "影院模式"
      }
    };

    function detectLang() {
      var saved = localStorage.getItem('lang');
      if (saved && I18N[saved]) return saved;
      var nav = (navigator.language || navigator.userLanguage || 'en').toLowerCase();
      if (nav.indexOf('zh') === 0) return 'zh';
      if (nav.indexOf('ru') === 0) return 'ru';
      return 'en';
    }
    var LANG = detectLang();
    function t(key) {
      var table = I18N[LANG] || I18N.en;
      var s = table[key];
      if (s == null) s = I18N.en[key];
      if (s == null) return key;
      if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
          s = s.replace('{' + (i - 1) + '}', String(arguments[i]));
        }
      }
      return s;
    }
    function applyStaticI18n() {
      document.documentElement.lang = LANG;
      document.querySelectorAll('[data-i18n]').forEach(function (el) {
        el.textContent = t(el.getAttribute('data-i18n'));
      });
      document.querySelectorAll('[data-i18n-title]').forEach(function (el) {
        el.setAttribute('title', t(el.getAttribute('data-i18n-title')));
      });
      document.querySelectorAll('[data-i18n-aria]').forEach(function (el) {
        el.setAttribute('aria-label', t(el.getAttribute('data-i18n-aria')));
      });
    }

    /* ============================ Theme ============================ */
    var mql = window.matchMedia('(prefers-color-scheme: dark)');
    function applyTheme() {
      var pref = localStorage.getItem('theme') || 'auto';
      var dark = (pref === 'auto') ? mql.matches : (pref === 'dark');
      document.documentElement.setAttribute('data-bs-theme', dark ? 'dark' : 'light');
    }
    var themeSel = document.getElementById('themeSel');
    themeSel.value = localStorage.getItem('theme') || 'auto';
    themeSel.addEventListener('change', function () {
      localStorage.setItem('theme', themeSel.value);
      applyTheme();
    });
    mql.addEventListener('change', applyTheme);
    applyTheme();

    /* ============================ Helpers ============================ */
    var BADGE = { ok: 'bg-success', warn: 'bg-warning text-dark', down: 'bg-danger' };
    function badgeClass(s) { return BADGE[s] || 'bg-secondary'; }
    function badgeText(s) {
      return ({ ok: 'OK', warn: 'WARN', down: 'DOWN' })[s] || (s ? String(s).toUpperCase() : 'N/A');
    }
    function esc(v) {
      return String(v == null ? '' : v)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }
    function flag(cc) {
      if (!cc || cc.length !== 2 || !/^[A-Za-z]{2}$/.test(cc)) return '';
      cc = cc.toUpperCase();
      return String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65) +
             String.fromCodePoint(0x1F1E6 + cc.charCodeAt(1) - 65);
    }
    function geoLine(n) {
      if (!n || !n.ip) return t('no_data');
      var loc = [n.city, n.country].filter(Boolean).map(esc).join(', ');
      var isp = n.isp ? esc(n.isp) : '';
      var asn = n.asn ? ('AS' + esc(String(n.asn).replace(/^AS/i, ''))) : '';
      return [loc, isp, asn].filter(Boolean).join(' · ') || t('no_geo');
    }

    /* ============================ Sparkline ============================ */
    var HISTORY = {};
    var MAXH = 20;
    function pushHistory(key, ms) {
      if (typeof ms !== 'number' || !isFinite(ms)) return;
      var a = HISTORY[key] || (HISTORY[key] = []);
      a.push(ms);
      if (a.length > MAXH) a.shift();
    }
    function sparkline(key, color) {
      var a = HISTORY[key] || [];
      var W = 110, H = 30, pad = 2;
      if (a.length < 2) {
        return '<svg class="spark" width="' + W + '" height="' + H + '" role="img" aria-label="' + esc(t('spark_empty')) + '">' +
               '<text x="' + (W / 2) + '" y="' + (H / 2 + 4) + '" text-anchor="middle" ' +
               'font-size="10" fill="currentColor" opacity="0.5">—</text></svg>';
      }
      var min = Math.min.apply(null, a), max = Math.max.apply(null, a);
      var span = (max - min) || 1;
      var n = a.length;
      var pts = a.map(function (v, i) {
        var x = pad + (W - 2 * pad) * (i / (n - 1));
        var y = pad + (H - 2 * pad) * (1 - (v - min) / span);
        return x.toFixed(1) + ',' + y.toFixed(1);
      });
      var last = a[a.length - 1];
      var lastPt = pts[pts.length - 1].split(',');
      return '<svg class="spark" width="' + W + '" height="' + H + '" role="img" ' +
             'aria-label="' + esc(t('spark_label', n, last)) + '">' +
             '<polyline fill="none" stroke="' + color + '" stroke-width="1.5" ' +
             'stroke-linejoin="round" stroke-linecap="round" points="' + pts.join(' ') + '"/>' +
             '<circle cx="' + lastPt[0] + '" cy="' + lastPt[1] + '" r="2" fill="' + color + '"/>' +
             '</svg>';
    }
    function sparkColor(status) {
      return status === 'down' ? '#dc3545' : status === 'warn' ? '#ffc107' : '#0d6efd';
    }

    /* ============================ Toasts ============================ */
    var toastBox = document.querySelector('.toast-container');
    function toast(msg, kind) {
      var cls = ({ ok: 'text-bg-success', warn: 'text-bg-warning', err: 'text-bg-danger' })[kind] || 'text-bg-secondary';
      var el = document.createElement('div');
      el.className = 'toast align-items-center border-0 ' + cls;
      el.setAttribute('role', 'alert');
      el.innerHTML =
        '<div class="d-flex">' +
          '<div class="toast-body">' + esc(msg) + '</div>' +
          '<button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>' +
        '</div>';
      toastBox.appendChild(el);
      var tt = new bootstrap.Toast(el, { delay: 5000 });
      tt.show();
      el.addEventListener('hidden.bs.toast', function () { el.remove(); });
    }

    /* ============================ Card builder ============================ */
    function card(opts) {
      var col = opts.col || 'col-12 col-md-6 col-xl-4';
      var spark = opts.sparkKey
        ? '<div class="mt-2 text-secondary">' + sparkline(opts.sparkKey, sparkColor(opts.status)) + '</div>'
        : '';
      return '' +
        '<div class="' + col + '">' +
          '<div class="card h-100">' +
            '<div class="card-body">' +
              '<div class="d-flex align-items-start">' +
                '<div class="me-auto">' +
                  '<div class="text-secondary text-uppercase small fw-semibold">' +
                    '<i class="bi ' + opts.icon + ' card-icon"></i> ' + esc(opts.title) + '</div>' +
                  '<div class="val-big mono">' + esc(opts.value) + '</div>' +
                  '<div class="sub text-secondary">' + opts.sub + '</div>' +
                '</div>' +
                '<span class="badge ' + badgeClass(opts.status) + '">' + esc(badgeText(opts.status)) + '</span>' +
              '</div>' +
              spark +
            '</div>' +
          '</div>' +
        '</div>';
    }

    function svcLine(s) {
      if (!s) return t('no_data');
      return (s.listening ? t('listening') : t('not_listening')) +
             ' · brew: ' + esc(s.brew || 'unknown');
    }

    /* ============================ Render ============================ */
    function render(d) {
      var tun = d.tunnel || {};
      var an = tun.anthropic || {}, oa = tun.openai || {};
      pushHistory('anthropic', an.ms);
      pushHistory('openai', oa.ms);
      pushHistory('direct', (d.direct || {}).ms);

      var html = '';

      html += card({
        icon: 'bi-reception-4', title: t('card_anthropic'),
        value: (an.ms != null ? an.ms + ' ' + t('ms') : '—'),
        sub: 'HTTP ' + esc(an.code != null ? an.code : '—') + ' · ' + (an.up ? t('reachable') : t('unreachable')),
        status: (an.up ? 'ok' : 'down'), sparkKey: 'anthropic'
      });

      html += card({
        icon: 'bi-reception-4', title: t('card_openai'),
        value: (oa.ms != null ? oa.ms + ' ' + t('ms') : '—'),
        sub: 'HTTP ' + esc(oa.code != null ? oa.code : '—') + ' · ' + (oa.up ? t('reachable') : t('unreachable')),
        status: (oa.up ? 'ok' : 'down'), sparkKey: 'openai'
      });

      html += card({
        icon: 'bi-hdd-network', title: t('card_tunnel'),
        value: badgeText(tun.status),
        sub: t('tunnel_sub'),
        status: tun.status
      });

      var di = d.direct || {};
      html += card({
        icon: 'bi-globe', title: t('card_direct'),
        value: (di.ms != null ? di.ms + ' ' + t('ms') : '—'),
        sub: 'HTTP ' + esc(di.code != null ? di.code : '—'),
        status: di.status, sparkKey: 'direct'
      });

      var vp = d.vpn || {};
      html += card({
        icon: 'bi-shield-lock', title: t('card_vpn'),
        value: (vp.vpn_up ? t('on') : t('off')),
        sub: t('iface') + ' ' + esc(vp.default_iface || '—') + ' · ' + t('srv') + ' ' + esc(vp.vpn_server || '—'),
        status: vp.status
      });

      var rt = d.route || {};
      var routeBtn = rt.split_active
        ? '<button class="btn btn-sm btn-outline-danger act mt-2" data-url="/api/route/remove">' +
          '<span class="lbl"><i class="bi bi-dash-lg"></i> ' + esc(t('split_disable')) + '</span></button>'
        : '<button class="btn btn-sm btn-success act mt-2" data-url="/api/route/add">' +
          '<span class="lbl"><i class="bi bi-plus-lg"></i> ' + esc(t('split_enable')) + '</span></button>';
      html += card({
        icon: 'bi-signpost-2', title: t('card_route'),
        value: (rt.split_active ? t('split_on') : t('split_off')),
        sub: t('iface') + ' ' + esc(rt.interface || '—') + ' · ' + t('gw') + ' ' + esc(rt.gateway || '—') +
             '<div>' + routeBtn + '</div>',
        status: rt.status
      });

      var sv = d.services || {};
      var pv = sv.privoxy || {};
      html += card({
        icon: 'bi-funnel', title: t('card_privoxy'),
        value: badgeText(pv.status),
        sub: svcLine(pv),
        status: pv.status
      });

      var xr = sv.xray || {};
      html += card({
        icon: 'bi-lightning-charge', title: t('card_xray'),
        value: badgeText(xr.status),
        sub: svcLine(xr),
        status: xr.status
      });

      /* ---------- киношные карточки (класс cine → скрываются в Simple) ---------- */
      /* IP-карточки убраны — их полностью показывает flow-схема наверху (без дублей). */
      function cineCard(o) { o.col = (o.col || 'col-12 col-md-6 col-xl-4') + ' cine'; return card(o); }

      var pg = d.ping || {};
      pushHistory('ping_vps', pg.vps_ms);
      html += cineCard({ icon: 'bi-speedometer2', title: t('card_ping'),
        value: (pg.vps_ms != null ? pg.vps_ms + ' ' + t('ms') : '—'),
        sub: t('ping_sub', (pg.vps_loss != null ? pg.vps_loss : 0),
                (pg.vpn_ms != null ? pg.vpn_ms + ' ' + t('ms') : '—')),
        status: pg.status, sparkKey: 'ping_vps' });

      var gd = d.geo_distance || {};
      html += cineCard({ icon: 'bi-rulers', title: t('card_distance'),
        value: (gd.km != null ? gd.km.toLocaleString() + ' ' + t('km') : '—'),
        sub: (gd.from_city || gd.to_city) ? esc(gd.from_city || '?') + ' → ' + esc(gd.to_city || '?') : t('no_geo'),
        status: gd.status });

      var dns = d.dns || {};
      var dnsList = (dns.public || []).map(function (s) {
        return '<span class="badge text-bg-light dns-pill me-1 mb-1">' + esc(s.ip) +
               (s.name ? ' <span class="opacity-75">' + esc(s.name) + '</span>' : '') +
               '<span class="dns-dot ' + (s.up ? 'dns-up' : 'dns-down') + '"></span></span>';
      }).join('');
      html += cineCard({ icon: 'bi-globe-americas', title: t('card_dns_public'),
        value: (dns.public || []).filter(function (s) { return s.up; }).length + '/' +
               (dns.public || []).length,
        sub: dnsList || t('no_data'), status: dns.status, col: 'col-12 col-md-6 col-xl-4' });

      var ifd = d.ifaces || {};
      var ifList = (ifd.ifaces || []).map(function (i) {
        return '<div class="ops">' +
          (i.is_default ? '<i class="bi bi-star-fill text-warning"></i> ' : '<span class="opacity-0">★</span> ') +
          '<span class="fw-semibold">' + esc(i.name) + '</span> <span class="k">' + esc(i.addr || '—') +
          '</span> <span class="k">MTU ' + esc(i.mtu) + '</span></div>';
      }).join('');
      html += cineCard({ icon: 'bi-ethernet', title: t('card_ifaces'),
        value: (ifd.ifaces || []).length + ' ' + t('active'),
        sub: ifList || t('no_data'), status: ifd.status, col: 'col-12 col-md-6 col-xl-8' });

      document.getElementById('cards').innerHTML = html;
      renderFlow(d);

      var ts = d.ts ? new Date(d.ts * 1000) : new Date();
      document.getElementById('updated').textContent = t('updated_at', ts.toLocaleTimeString());
    }

    function flowNode(n, roleLabel, live) {
      var fl = n && n.country_code ? flag(n.country_code) : '';
      return '<div class="flow-node' + (live ? ' live' : '') + '">' +
               '<div class="role">' + esc(roleLabel) + '</div>' +
               '<div class="d-flex align-items-center gap-2">' +
                 '<span class="flag">' + (fl || '🌐') + '</span>' +
                 '<span class="ip mono">' + esc((n && n.ip) || '—') + '</span>' +
               '</div><div class="meta">' + geoLine(n) + '</div></div>';
    }
    function flowArrow(rttMs) {
      var r = (typeof rttMs === 'number') ? (rttMs + ' ' + t('ms')) : '';
      return '<div class="flow-arrow"><div>→</div>' +
             (r ? '<div class="rtt mono">' + esc(r) + '</div>' : '') + '</div>';
    }
    function renderFlow(d) {
      var ips = d.ips || {}, ping = d.ping || {};
      var strip =
        flowNode(ips.direct, t('node_vpn_exit'), true) +
        flowArrow(ping.vpn_ms) +
        flowNode(ips.vps, t('node_vps'), true) +
        flowArrow(ping.vps_ms) +
        '<div class="flow-node"><div class="role">' + esc(t('node_internet')) +
          '</div><div class="d-flex align-items-center gap-2"><span class="flag">🌍</span>' +
          '<span class="ip">' + esc(t('node_world')) + '</span></div>' +
          '<div class="meta">' + esc(t('node_world_sub')) + '</div></div>';
      document.getElementById('flow-strip').innerHTML = strip;
      var fb = document.getElementById('flow-badge');
      fb.className = 'ms-auto badge ops ' + badgeClass(ips.status);
      fb.textContent = badgeText(ips.status);
    }

    function renderFetchFailed() {
      var keys = [
        ['bi-reception-4', 'card_anthropic'],
        ['bi-reception-4', 'card_openai'],
        ['bi-hdd-network', 'card_tunnel'],
        ['bi-globe', 'card_direct'],
        ['bi-shield-lock', 'card_vpn'],
        ['bi-signpost-2', 'card_route'],
        ['bi-funnel', 'card_privoxy'],
        ['bi-lightning-charge', 'card_xray']
      ];
      var html = keys.map(function (k) {
        return card({ icon: k[0], title: t(k[1]), value: '—', sub: t('no_server'), status: 'unknown' });
      }).join('');
      document.getElementById('cards').innerHTML = html;
      var fs = document.getElementById('flow-strip');
      if (fs) fs.innerHTML = '<div class="text-secondary ops">' + esc(t('no_server')) + '</div>';
    }

    /* ============================ Polling ============================ */
    var inFlight = false;
    var paused = false;
    var refreshBtn = document.getElementById('refreshBtn');

    function setRefreshing(on) {
      refreshBtn.disabled = on;
      refreshBtn.querySelector('i').className = on ? 'bi bi-arrow-clockwise pulse' : 'bi bi-arrow-clockwise';
    }

    function poll(manual) {
      if (inFlight) return;
      if (paused && !manual) return;
      inFlight = true;
      setRefreshing(true);
      fetch('/api/status', { headers: { 'Accept': 'application/json' }, cache: 'no-store' })
        .then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json();
        })
        .then(function (d) { render(d); })
        .catch(function (e) {
          renderFetchFailed();
          toast(t('fetch_status_failed', e.message), 'err');
        })
        .finally(function () { inFlight = false; setRefreshing(false); });
    }

    refreshBtn.addEventListener('click', function () { poll(true); });

    /* ============================ Actions ============================ */
    document.addEventListener('click', function (ev) {
      var btn = ev.target.closest('.act');
      if (!btn) return;
      var url = btn.getAttribute('data-url');
      var group = btn.closest('.btn-group');
      var siblings = group ? group.querySelectorAll('.act') : [btn];

      paused = true;
      siblings.forEach(function (b) { b.disabled = true; });
      var lbl = btn.querySelector('.lbl');
      var orig = lbl ? lbl.innerHTML : '';
      if (lbl) lbl.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';

      fetch(url, { method: 'POST', headers: { 'Accept': 'application/json' } })
        .then(function (r) { return r.json().catch(function () { return { ok: r.ok }; }); })
        .then(function (res) {
          if (res && res.cancelled) {
            toast(t('cancelled'), 'warn');
          } else if (res && res.ok) {
            toast(res.out ? t('ok_req_out', url, String(res.out).slice(0, 120))
                          : t('ok_req', url), 'ok');
          } else {
            var msg = (res && (res.err || res.out)) ? String(res.err || res.out).slice(0, 200)
                                                    : ('rc=' + (res && res.rc));
            toast(t('err_req', url, msg), 'err');
          }
        })
        .catch(function (e) { toast(t('req_failed', url, e.message), 'err'); })
        .finally(function () {
          if (lbl) lbl.innerHTML = orig;
          siblings.forEach(function (b) { b.disabled = false; });
          paused = false;
          poll(true);
        });
    });

    /* ============================ Language wiring ============================ */
    var langSel = document.getElementById('langSel');
    langSel.value = LANG;
    langSel.addEventListener('change', function () {
      LANG = langSel.value;
      localStorage.setItem('lang', LANG);
      applyStaticI18n();
      poll(true);
    });
    applyStaticI18n();

    /* ============================ Mode (Simple / Cinematic) ============================ */
    var modeBtn = document.getElementById('modeBtn');
    function applyMode() {
      var simple = localStorage.getItem('mode') === 'simple';
      document.body.classList.toggle('mode-simple', simple);
      modeBtn.querySelector('i').className = simple ? 'bi bi-eye-slash' : 'bi bi-eye';
      modeBtn.setAttribute('title', t(simple ? 'mode_simple' : 'mode_cinematic'));
    }
    modeBtn.addEventListener('click', function () {
      localStorage.setItem('mode', localStorage.getItem('mode') === 'simple' ? 'cinematic' : 'simple');
      applyMode();
    });
    applyMode();

    /* ============================ Boot ============================ */
    poll(true);
    setInterval(poll, 5000);
  })();
  </script>
</body>
</html>
"""


# ============================ запуск ============================
if __name__ == "__main__":
    print(f"Dashboard: http://127.0.0.1:{PORT}")
    app.run(host="127.0.0.1", port=PORT, threaded=True, debug=False)  # loopback, debug OFF!
