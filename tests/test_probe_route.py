"""ТДД-тесты probe_route_to_vps: split_active должен работать для en1 (USB-tether), не только en0.

Часть D: хардкод iface=="en0" → обобщить на iface.startswith("en") (en0/en1/en2 — физические).
"""
import dashboard_network


def _route_get_resp(iface, gateway=""):
    """Mock-ответ `route -n get -host <ip>`: interface + gateway в выводе."""
    out = f"route: bad command\n"
    if iface:
        out += f"interface: {iface}\n"
    if gateway:
        out += f"gateway: {gateway}\n"
    return out


def test_probe_route_to_vps_split_active_on_en0(monkeypatch):
    """en0 → split_active=True, status=ok (существующее поведение, не ломаем)."""
    monkeypatch.setattr(dashboard_network.sys_probe, "run",
                        lambda cmd, timeout: {"rc": 0, "out": _route_get_resp("en0"), "err": "", "timeout": False})
    r = dashboard_network.probe_route_to_vps(route_ip="1.2.3.4")
    assert r["split_active"] is True
    assert r["status"] == "ok"


def test_probe_route_to_vps_split_active_on_en1(monkeypatch):
    """en1 (USB-tether) → split_active=True. ДЫРА: сейчас хардкод en0 даёт False (ложный warn)."""
    monkeypatch.setattr(dashboard_network.sys_probe, "run",
                        lambda cmd, timeout: {"rc": 0, "out": _route_get_resp("en1"), "err": "", "timeout": False})
    r = dashboard_network.probe_route_to_vps(route_ip="1.2.3.4")
    assert r["split_active"] is True, f"en1 тоже физический → split активен, а получили {r}"
    assert r["status"] == "ok"


def test_probe_route_to_vps_split_active_via_gateway(monkeypatch):
    """ppp0 iface, но gateway=GATEWAY → split активен (через шлюз)."""
    gw = dashboard_network.GATEWAY  # реальная константа из srouter_config
    monkeypatch.setattr(dashboard_network.sys_probe, "run",
                        lambda cmd, timeout: {"rc": 0, "out": _route_get_resp("ppp0", gw), "err": "", "timeout": False})
    r = dashboard_network.probe_route_to_vps(route_ip="1.2.3.4")
    assert r["split_active"] is True


def test_probe_route_to_vps_warn_on_ppp0_without_gateway(monkeypatch):
    """ppp0, gateway != GATEWAY → split_active=False, status=warn (VPN перехватил, без split)."""
    monkeypatch.setattr(dashboard_network.sys_probe, "run",
                        lambda cmd, timeout: {"rc": 0, "out": _route_get_resp("ppp0", "10.0.0.1"), "err": "", "timeout": False})
    r = dashboard_network.probe_route_to_vps(route_ip="1.2.3.4")
    assert r["split_active"] is False
    assert r["status"] == "warn"


def test_probe_route_to_vps_down_on_empty_route_ip(monkeypatch):
    """route_ip пустой → status=down (контракт probe)."""
    r = dashboard_network.probe_route_to_vps(route_ip="")
    assert r["status"] == "down"
    assert r["split_active"] is False
