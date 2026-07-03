"""Тесты srouter._is_ip_literal.

route_ip интерполируется в shell-команду `route -n delete -host <ip>` (под osascript-мост),
поэтому строгая проверка критична: только canonical IP-литералы, без zone-id и альтернативных форм.
Канон — dashboard_common._ip_literal, но без импорта dashboard_common (тянет srouter_config).
"""
import srouter


def _check(value, expected):
    got = srouter._is_ip_literal(value)
    assert got == expected, f"{value!r} → {got}, expected {expected}"


def test_ipv4_literal():
    _check("1.2.3.4", True)
    _check("203.0.113.10", True)
    _check("127.0.0.1", True)


def test_ipv6_literal():
    _check("::1", True)
    _check("2001:db8::1", True)


def test_rejects_non_canonical_ipv4():
    """Ведущие нули, лишние формы — НЕ canonical, отклоняем (защита от неоднозначностей в shell)."""
    _check("01.02.03.04", False)
    _check("1.2.3.4.5", False)
    _check("256.1.1.1", False)


def test_rejects_zone_id():
    _check("1.2.3.4%eth0", False)
    _check("fe80::1%en0", False)


def test_rejects_hostname_and_garbage():
    _check("example.com", False)
    _check("node-sg-1", False)
    _check("1.2.3", False)
    _check("not an ip", False)


def test_rejects_empty_and_non_string():
    _check("", False)
    assert srouter._is_ip_literal(None) is False
    assert srouter._is_ip_literal(12345) is False
    assert srouter._is_ip_literal(["1.2.3.4"]) is False
