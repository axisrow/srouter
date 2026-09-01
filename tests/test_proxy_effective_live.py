"""Живой (skip-if-no-privoxy) тест guard'а синтетического 5xx посредника (issue #323).

Парный живой тест к замоканным (canon mock-format-must-come-from-live-capture): моки
заголовков в test_proxy_effective.py захвачены с privoxy 4.2.0 на стенде research #301
(2026-09-01). Этот тест доказывает на ТЕКУЩЕМ установленном privoxy, что его синтетика
по-прежнему несёт те же magic-даты и что связка живая целиком:
privoxy (мёртвый upstream) -> curl -D -> _parse_header_dump -> _is_synthetic_middleware_5xx.

Прод-инстансы (8118/10808) не задействуются: изолированный privoxy на свободном порту,
forward-socks5t на порт, где ничего не слушает.
"""
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

import dashboard_network
import proxy_effective

PRIVOXY_BIN = Path("/opt/homebrew/opt/privoxy/sbin/privoxy")
PRIVOXY_TEMPLATES = Path("/opt/homebrew/etc/privoxy/templates")

pytestmark = pytest.mark.skipif(
    not PRIVOXY_BIN.is_file() or not PRIVOXY_TEMPLATES.is_dir(),
    reason="Homebrew privoxy/templates не установлены (канон skip-is-fine-in-tests)",
)


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def dead_upstream_privoxy(tmp_path):
    """Изолированный privoxy: слушает свободный порт, форвардит на заведомо мёртвый."""
    listen_port = _free_port()
    dead_port = _free_port()  # никто не слушает -> connection refused на dial
    confdir = tmp_path / "confdir"
    (confdir / "templates").mkdir(parents=True)
    shutil.copytree(PRIVOXY_TEMPLATES, confdir / "templates", dirs_exist_ok=True)
    conf = tmp_path / "privoxy.conf"
    conf.write_text(
        f"listen-address 127.0.0.1:{listen_port}\n"
        "toggle 1\n"
        f"confdir {confdir}\n"
        f"forward-socks5t / 127.0.0.1:{dead_port} .\n",
        encoding="utf-8",
    )
    proc = subprocess.Popen(
        [str(PRIVOXY_BIN), "--no-daemon", str(conf)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", listen_port)) == 0:
                    break
            time.sleep(0.1)
        else:
            pytest.fail("тестовый privoxy не поднялся за 5s")
        yield f"http://127.0.0.1:{listen_port}"
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_live_privoxy_synthetic_5xx_carries_guard_signature(dead_upstream_privoxy):
    """Живой privoxy + мёртвый upstream: код >= 500 и magic-даты, guard признаёт синтетику."""
    r = dashboard_network._curl_through(
        "http://example.com/", proxy=True,
        proxy_url=dead_upstream_privoxy, capture_headers=True)
    assert int(r["code"]) >= 500, f"ожидали синтетический 5xx от живого privoxy, получили {r}"
    assert r["headers"].get("expires") == proxy_effective._SYNTHETIC_EXPIRES, (
        f"живой privoxy изменил magic-Expires — моки test_proxy_effective.py устарели: {r['headers']}"
    )
    assert r["headers"].get("last-modified") == proxy_effective._SYNTHETIC_LAST_MODIFIED, (
        f"живой privoxy изменил magic-Last-Modified: {r['headers']}"
    )
    assert proxy_effective._is_synthetic_middleware_5xx(r) is True
