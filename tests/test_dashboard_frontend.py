"""Frontend-контракт static/index.html: чистые render-функции прогоняются через node.

Канон проекта — pytest, JS-фреймворков нет. Поэтому не тащим jest/karma: извлекаем
конкретные чистые функции из index.html по маркеру `function <name>` (до сбалансированной
закрывающей скобки), окружаем минимальными заглушками (I18N/t/esc/flag/...) и исполняем
node-ом. Проверяем ровно контракт рендера, а не DOM.

Покрывает находки триажа issue #82:
  #4  renderFlow должен показывать ips.chain (иначе leak-сигнал chain==direct невиден);
  #5  RTT на flow-стрелках: vps_ms — до VPS (route_ip), vpn_ms — до VPN-сервера;
  #6  badge карточки Public DNS считается из dns.public (reachability), не из dns.status
      (системный scutil-resolver);
  #12 t() не должен разворачивать $-паттерны ($&, $`, $', $n) в подставляемом тексте.
"""
import json
import shutil
import subprocess

import pytest

from _frontend_extract import HTML, extract_functions

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node не установлен")


def _run_node(src):
    """Исполнить JS и вернуть распарсенный JSON, который скрипт печатает в stdout."""
    r = subprocess.run(["node", "-e", src], capture_output=True, text=True, timeout=20)
    if r.returncode != 0:
        raise AssertionError("node упал:\n" + r.stderr + "\n---stdout---\n" + r.stdout)
    return json.loads(r.stdout.strip().splitlines()[-1])


# --- общая обвязка: заглушки зависимостей render-функций ---------------------
_STUBS = r"""
var LANG = 'en';
var I18N = { en: {
  node_vpn_exit: 'VPN / direct exit', node_vps: 'VPS relay', node_internet: 'Internet',
  node_world: 'world', node_world_sub: 'AI endpoints', node_chain: 'Chain exit',
  ms: 'ms', no_data: 'no data', no_geo: 'no geo data', card_ip_chain: 'Chain exit IP',
  flow_leak: 'LEAK', err_req: 'Error {0}: {1}'
} };
function esc(v){ return String(v==null?'':v)
  .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function flag(cc){ if(!cc||cc.length!==2||!/^[A-Za-z]{2}$/.test(cc)) return '';
  cc=cc.toUpperCase();
  return String.fromCodePoint(0x1F1E6+cc.charCodeAt(0)-65)+String.fromCodePoint(0x1F1E6+cc.charCodeAt(1)-65); }
function geoLine(n){ if(!n||!n.ip) return t('no_data');
  var loc=[n.city,n.country].filter(Boolean).map(esc).join(', ');
  return loc || t('no_geo'); }
function badgeClass(s){ return ({ok:'bg-success',warn:'bg-warning text-dark',down:'bg-danger'})[s]||'bg-secondary'; }
function badgeText(s){ return ({ok:'OK',warn:'WARN',down:'DOWN'})[s]||(s?String(s).toUpperCase():'N/A'); }
var _flowStrip='', _flowBadge={};
var document = { getElementById: function(id){
  if(id==='flow-strip') return { set innerHTML(v){ _flowStrip=v; }, get innerHTML(){ return _flowStrip; } };
  return { className:'', textContent:'', set innerHTML(v){}, get innerHTML(){ return ''; } };
} };
"""


def _harness(func_names, body):
    """Собрать node-скрипт: t() + заглушки + извлечённые функции + тело теста."""
    funcs = extract_functions(HTML, ["t"] + list(func_names))
    return _STUBS + "\n" + funcs + "\n" + body


# --- #12: t() не искажает $-паттерны ----------------------------------------

def test_t_preserves_dollar_patterns():
    """Server error с $&, $`, $', $1 должен вставиться литерально, не как replace-паттерн."""
    hostile = "boom $& and $` and $' and $1 tail"
    body = (
        "var out = t('err_req', 'https://x/y', " + json.dumps(hostile) + ");"
        "console.log(JSON.stringify({out: out}));"
    )
    res = _run_node(_harness([], body))
    # Полный литерал сохранён внутри "Error {0}: {1}" -> {1} = hostile.
    assert hostile in res["out"], f"$-паттерны исказились: {res['out']!r}"
    assert res["out"] == "Error https://x/y: " + hostile


def test_t_preserves_dollar_ampersand_specifically():
    """Изолированный кейс '$&' (весь матч) — самый частый источник искажения."""
    body = (
        "var out = t('err_req', 'U', 'a $& b');"
        "console.log(JSON.stringify({out: out}));"
    )
    res = _run_node(_harness([], body))
    assert res["out"] == "Error U: a $& b"


# --- #4/#5: renderFlow — chain-узел и корректные RTT -------------------------

def _render_flow(d):
    body = (
        "renderFlow(" + json.dumps(d) + ");"
        "console.log(JSON.stringify({strip: document.getElementById('flow-strip').innerHTML}));"
    )
    return _run_node(_harness(["flowNode", "flowArrow", "renderFlow"], body))["strip"]


def test_render_flow_shows_chain_ip():
    """#4: ips.chain.ip обязан появиться во flow (сейчас renderFlow его игнорирует).

    chain.ip уникален (не совпадает ни с direct, ни с vps), чтобы его присутствие в
    strip доказывало отрисовку именно chain-узла, а не случайное совпадение с vps.
    """
    d = {
        "ips": {
            "direct": {"ip": "203.0.113.9", "country_code": "US"},
            "chain": {"ip": "192.0.2.55", "country_code": "NL"},
            "vps": {"ip": "198.51.100.7", "country_code": "SG"},
            "status": "ok",
        },
        "ping": {"vps_ms": 40, "vpn_ms": 30},
    }
    strip = _render_flow(d)
    assert "192.0.2.55" in strip, "chain exit-IP не отрисован во flow"


def test_render_flow_marks_leak_when_chain_equals_direct():
    """#4: chain == direct — реальный IP утёк мимо цепочки. UI обязан это подсветить."""
    leak_ip = "203.0.113.9"
    d = {
        "ips": {
            "direct": {"ip": leak_ip, "country_code": "US"},
            "chain": {"ip": leak_ip, "country_code": "US"},
            "vps": {"ip": "198.51.100.7", "country_code": "SG"},
            "status": "warn",
        },
        "ping": {"vps_ms": 40, "vpn_ms": 30},
    }
    strip = _render_flow(d)
    assert "leak" in strip.lower(), "leak-сценарий chain==direct не подсвечен"


def test_render_flow_rtt_labels_match_segments():
    """#5: vps_ms относится к пути до VPS, vpn_ms — до VPN-сервера. Не перепутать.

    Контракт (dashboard_network.probe_ping): vps_ms = ping до route_ip (VPS relay),
    vpn_ms = ping до VPN server. Ставим различимые значения и проверяем, что
    большое vps_ms НЕ оказалось на сегменте VPS->Internet и рядом с VPS-узлом
    стоит именно vps_ms.
    """
    # У каждого узла уникальный IP, иначе find() поймает не тот узел.
    d = {
        "ips": {
            "direct": {"ip": "203.0.113.9", "country_code": "US"},
            "chain": {"ip": "192.0.2.55", "country_code": "NL"},
            "vps": {"ip": "198.51.100.7", "country_code": "SG"},
            "status": "ok",
        },
        "ping": {"vps_ms": 250, "vpn_ms": 30},
    }
    strip = _render_flow(d)
    # Оба значения где-то есть.
    assert "250" in strip, "vps_ms (250) потерялся"

    vps_pos = strip.find("198.51.100.7")  # позиция VPS-узла (route_ip)
    assert vps_pos != -1
    # Ребро, ведущее В VPS (local->VPS), должно нести vps_ms=250: оно ЛЕВЕЕ VPS-узла.
    before_vps = strip[:vps_pos]
    assert "250" in before_vps, (
        "RTT до VPS (vps_ms=250) не стоит на сегменте, входящем в VPS-узел — "
        "подписи перепутаны (regression находки #5)"
    )
    # Между VPS-узлом и Internet измеряемого RTT нет: vps_ms не должен висеть ПОСЛЕ VPS.
    after_vps = strip[vps_pos + len("198.51.100.7"):]
    assert "250" not in after_vps, (
        "vps_ms=250 стоит на неизмеряемом сегменте VPS->Internet (regression находки #5)"
    )


# --- #6: DNS-карточка ------------------------------------------------------
# Функция статуса карточки Public DNS должна опираться на dns.public reachability,
# а не на dns.status (системный scutil-resolver). Извлекаем dnsCardStatus().

def _dns_card_status(dns):
    body = (
        "console.log(JSON.stringify({st: dnsCardStatus(" + json.dumps(dns) + ")}));"
    )
    return _run_node(_harness(["dnsCardStatus"], body))["st"]


def test_dns_card_not_down_when_public_reachable_but_no_system_resolver():
    """#6: пустой scutil (dns.status='down'), но все public DNS up -> карточка НЕ down."""
    dns = {
        "servers": [], "status": "down", "count": 0,
        "public": [
            {"ip": "1.1.1.1", "up": True}, {"ip": "8.8.8.8", "up": True},
            {"ip": "9.9.9.9", "up": True},
        ],
    }
    assert _dns_card_status(dns) != "down", (
        "Public DNS badge берётся из системного resolver (dns.status), "
        "а не из public reachability (regression находки #6)"
    )


def test_dns_card_down_when_all_public_unreachable():
    """#6: если публичные DNS все недоступны — карточка обязана быть down."""
    dns = {
        "servers": [{"ip": "192.168.0.1"}], "status": "ok", "count": 1,
        "public": [{"ip": "1.1.1.1", "up": False}, {"ip": "8.8.8.8", "up": False}],
    }
    assert _dns_card_status(dns) == "down"
