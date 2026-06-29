import re

import local_state


def test_host_regex_accepts_valid():
    assert local_state._is_valid_host("203.0.113.10")
    assert local_state._is_valid_host("node-1.example.com")
    assert local_state._is_valid_host("vps.local")


def test_host_regex_rejects_shell_metachars():
    # D2: shell-метасимволы запрещены в endpoint_host/route_ip
    for bad in ["a;rm -rf /", "$(reboot)", "host|cat", "a b", "x`y", "';--"]:
        assert not local_state._is_valid_host(bad), bad


def test_default_state_has_sections():
    for key in (
        "nodes",
        "active_node",
        "probes",
        "network",
        "traffic_guard",
        "detected_environment",
        "runtime",
    ):
        assert key in local_state._DEFAULT_STATE
