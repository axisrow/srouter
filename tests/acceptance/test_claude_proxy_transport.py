"""Live black-box acceptance for issue #127: real Claude Code against both local proxies."""
import os
import sys

import pytest

import health
from dashboard_common import HTTP_PROXY_URL, SOCKS_PROXY_URL


pytestmark = [
    pytest.mark.acceptance,
    pytest.mark.skipif(
        not (os.environ.get("SROUTER_CLAUDE_ACCEPTANCE") == "1" and sys.platform == "darwin"),
        reason="set SROUTER_CLAUDE_ACCEPTANCE=1 explicitly on macOS",
    ),
]


def test_real_claude_http_control_works_but_socks_transport_fails():
    """Current behavior contract; a future SOCKS 401 must fail and trigger reevaluation."""
    assert health._find_claude_binary(), "real Claude Code binary is required"
    assert health._port_up(health.PRIVOXY_PORT), "privoxy 8118 must be listening"
    assert health._port_up(health.XRAY_PORT), "xray SOCKS 10808 must be listening"

    http = health._claude_transport_once(HTTP_PROXY_URL)
    socks = health._claude_transport_once(SOCKS_PROXY_URL)

    assert http["status"] == "ok" and http["api_status"] == 401, http
    assert socks["status"] == "down" and socks["api_status"] is None, socks
    assert socks["error"] in {"UnsupportedProxyProtocol", "Connection error / timeout"}, socks
