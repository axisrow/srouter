"""Контракты шаблонов dnsmasq: клиентский upstream и референс VPS-резолвера.

Клиентский шаблон (templates/dnsmasq.conf): зарубежные upstream'ы — ТОЛЬКО собственные
резолверы на VPS (порт 5353 — GFW-инъекция DNS живёт на порту 53, на 5353 путь чист);
заблокированные из Китая 1.1.1.1/8.8.8.8 не должны возвращаться в клиентский конфиг
(прямые запросы к ним висят в таймаутах). Китайские upstream'ы остаются — операторские
CDN-ответы для китайских доменов.

Референс VPS (templates/vps-dnsmasq.conf): резолвер на нестандартном порту, upstream
с самого VPS (1.1.1.1/8.8.8.8 оттуда доступны), кэш. Секретов в файле нет — IP VPS
и так лежит в README/пробах.
"""

from pathlib import Path

_TEMPLATES = Path(__file__).resolve().parent.parent / "templates"
_CLIENT = (_TEMPLATES / "dnsmasq.conf").read_text(encoding="utf-8")
_VPS_PATH = _TEMPLATES / "vps-dnsmasq.conf"


def test_client_template_foreign_upstreams_are_own_vps_resolvers():
    assert "server=85.136.181.198#5353" in _CLIENT, "основной резолвер (xray-VPS) отсутствует"
    assert "server=78.47.183.125#5353" in _CLIENT, "резервный резолвер (Hetzner) отсутствует"
    assert "server=1.1.1.1" not in _CLIENT, "1.1.1.1 блокирован из Китая — прямой upstream недопустим"
    assert "server=8.8.8.8" not in _CLIENT, "8.8.8.8 блокирован из Китая — прямой upstream недопустим"


def test_client_template_keeps_chinese_upstreams_and_mode():
    assert "server=223.5.5.5" in _CLIENT, "китайские upstream'ы нужны для операторских CDN-ответов"
    assert "server=119.29.29.29" in _CLIENT
    assert "all-servers" in _CLIENT
    assert "srouter-managed-config-v1" in _CLIENT, "маркер managed-конфига обязателен"


def test_vps_template_reference_exists():
    text = _VPS_PATH.read_text(encoding="utf-8")
    assert "port=5353" in text, "резолвер обязан жить на нестандартном порту (GFW-53-инъекция)"
    assert "no-resolv" in text
    assert "server=1.1.1.1" in text and "server=8.8.8.8" in text, (
        "upstream с VPS — публичные резолверы (оттуда доступны)"
    )
    assert "cache-size" in text
