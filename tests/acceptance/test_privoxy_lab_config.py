"""ТДД-гард: конфиг privoxy-лаборатории (#123) корректен для эксперимента.

privoxy-lab.conf должен:
- forward в host-xray (host.docker.internal:10808) — цепочка контейнер→host-xray→Reality.
- НЕ содержать elliptic-curve-keys (non-fatal error — шум, маскирующий причину падения).
- содержать debug 8192 (трассировка коннектов — host-config этого не делал, слепое пятно).
- listen 0.0.0.0:8119 (проброс наружу, не конфликт с host 8118).

Static (read-only) — как test_dockerignore_secrets.py. Не skip'ится SROUTER_ACCEPTANCE.
"""
from pathlib import Path

_CONF = Path(__file__).resolve().parents[2] / "docker" / "privoxy-lab" / "privoxy-lab.conf"


def test_privoxy_lab_config_forwards_to_host_xray():
    """privoxy-lab.conf форвардит в host-xray (host.docker.internal:10808) — цепочка работает."""
    assert _CONF.exists(), "docker/privoxy-lab/privoxy-lab.conf отсутствует"
    content = _CONF.read_text(encoding="utf-8")
    assert "forward-socks5t / host.docker.internal:10808 ." in content, (
        "privoxy-lab должен форвардить в host-xray (host.docker.internal:10808) — цепочка контейнер→host-xray→Reality"
    )


def test_privoxy_lab_config_no_elliptic_curve_keys():
    """privoxy-lab.conf НЕ содержит активную директиву elliptic-curve-keys (non-fatal error — шум)."""
    content = _CONF.read_text(encoding="utf-8")
    # Только активные директивы (не комментарии): строка начинается с 'elliptic-curve-keys'.
    active = [ln.strip() for ln in content.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    has_directive = any(ln.startswith("elliptic-curve-keys") for ln in active)
    assert not has_directive, (
        "elliptic-curve-keys — non-fatal error в privoxy 4.2.0, маскирует реальную причину падения. "
        "Убрать для чистого сигнала эксперимента (в комментарии — допустимо, в активной директиве — нет)."
    )


def test_privoxy_lab_config_has_debug_tracing():
    """privoxy-lab.conf содержит debug 8192 (трассировка коннектов — host-config не делал)."""
    content = _CONF.read_text(encoding="utf-8")
    assert "debug 8192" in content, (
        "debug 8192 — трассировка коннектов; host-config этого не делал (слепое пятно для поимки причины)"
    )


# ============================ cycle-review #125: adversarial findings ============================

_COMPOSE = Path(__file__).resolve().parents[2] / "docker" / "privoxy-lab" / "docker-compose.yml"


def test_privoxy_lab_ports_bound_to_loopback_only():
    """C2 (CRITICAL): ports 8119 должны быть 127.0.0.1:8119:8119 (НЕ wildcard 0.0.0.0).

    0.0.0.0 = open-proxy на LAN: любой в сети получает неаутентифицированный HTTP-CONNECT-proxy через
    Reality → VPS exit-IP. Только loopback — агенты на 127.0.0.1:8119, никто извне.
    """
    content = _COMPOSE.read_text(encoding="utf-8")
    # Должна быть строка с 127.0.0.1:8119 (loopback binding).
    assert "127.0.0.1:8119:8119" in content, (
        "ports 8119 должны быть привязаны к 127.0.0.1 (loopback-only). "
        "0.0.0.0 = open proxy на LAN — злоупотребление VPS exit-IP (cycle-review #125 C2)."
    )
