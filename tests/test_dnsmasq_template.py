"""Контракты шаблонов dnsmasq: split DNS и референс VPS-резолвера.

Клиентский шаблон (templates/dnsmasq.conf) — split DNS: китайские домены уходят в
операторские DNS через список dnsmasq-china-list (conf-dir), всё прочее — в собственный
резолвер на VPS (порт 5353 — GFW-инъекция DNS живёт на 53, на 5353 путь чист).
Общий пул all-servers запрещён контрактом: китайский DNS отвечает за 16-35 мс и
выигрывает гонку даже на отравленных доменах — честный резолвер в общем пуле бесполезен.
Заблокированные из Китая 1.1.1.1/8.8.8.8 не должны возвращаться в конфиг.

Референс VPS (templates/vps-dnsmasq.conf): резолвер на нестандартном порту, upstream
с самого VPS (1.1.1.1/8.8.8.8 оттуда доступны), кэш. Секретов в файле нет.
"""

from pathlib import Path

_TEMPLATES = Path(__file__).resolve().parent.parent / "templates"
_CLIENT = (_TEMPLATES / "dnsmasq.conf").read_text(encoding="utf-8")
_VPS_PATH = _TEMPLATES / "vps-dnsmasq.conf"


def test_client_template_default_upstream_is_own_vps_resolver():
    assert "server=78.47.183.125#5353" in _CLIENT, "дефолтный upstream — свой резолвер (Hetzner)"
    assert "server=1.1.1.1" not in _CLIENT, "1.1.1.1 блокирован из Китая — прямой upstream недопустим"
    assert "server=8.8.8.8" not in _CLIENT, "8.8.8.8 блокирован из Китая — прямой upstream недопустим"


def test_client_template_is_split_dns_not_all_servers():
    assert "all-servers" not in _CLIENT, (
        "общий пул запрещён: китайский DNS выигрывает гонку на отравленных доменах, "
        "честный резолвер в all-servers бесполезен — только split через conf-dir"
    )
    assert "conf-dir=" in _CLIENT, "список китайских доменов подключается через conf-dir"
    # code-review #377: glob ",*" грузит ВСЕ файлы каталога (бэкапы редактора отравят
    # резолвер) — только суффикс .conf
    assert ".conf" in _CLIENT.split("conf-dir=")[1].splitlines()[0], "conf-dir фильтрует по .conf"
    assert "min-cache-ttl" in _CLIENT, "холодный зарубежный резолв ~225 мс — кэш обязан держаться"


def test_client_template_keeps_guard_options_and_marker():
    assert "srouter-managed-config-v1" in _CLIENT, "маркер managed-конфига обязателен"
    assert "bogus-priv" in _CLIENT and "domain-needed" in _CLIENT
    assert "no-resolv" in _CLIENT


def test_vps_template_reference_exists():
    text = _VPS_PATH.read_text(encoding="utf-8")
    assert "port=5353" in text, "резолвер обязан жить на нестандартном порту (GFW-53-инъекция)"
    assert "no-resolv" in text
    assert "server=1.1.1.1" in text and "server=8.8.8.8" in text, (
        "upstream с VPS — публичные резолверы (оттуда доступны)"
    )
    assert "cache-size" in text


def test_vps_template_is_fail_closed():
    """code-review #377: активный listen — только loopback; 0.0.0.0 закомментирован.
    Иначе пропущенный шаг rate-limit даёт открытый DNS-amplification relay."""
    active = [l for l in _VPS_PATH.read_text(encoding="utf-8").splitlines()
              if l.startswith("listen-address")]
    assert active == ["listen-address=127.0.0.1"], (
        f"fail-closed нарушен: активные listen-address = {active}"
    )
    assert any(l.strip().startswith("# listen-address=0.0.0.0") for l in
               _VPS_PATH.read_text(encoding="utf-8").splitlines()), (
        "открытие наружу — закомментированное осознанное действие"
    )
