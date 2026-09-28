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
import re
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


def test_t_does_not_reexpand_brace_token_in_value():
    """#88: значение с литералом {N} НЕ должно переэкспандиться следующим аргументом.

    При итеративном split/join arguments[1]='{1}injected' на проходе {1} подставлялся бы
    вторым аргументом. Single-pass replace обрабатывает все {N} за один проход по ИСХОДНОЙ
    строке шаблона — литерал {1} внутри значения остаётся как есть.
    """
    body = (
        "var out = t('err_req', '{1}injected', 'REALSECOND');"
        "console.log(JSON.stringify({out: out}));"
    )
    res = _run_node(_harness([], body))
    # {0}=аргумент1 (буквально '{1}injected'), {1}=аргумент2 ('REALSECOND').
    # Литерал '{1}' внутри первого значения НЕ должен превратиться в 'REALSECOND'.
    assert res["out"] == "Error {1}injected: REALSECOND", res["out"]


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


def test_render_flow_no_leak_when_chain_equals_vps():
    """#4: chain == route(vps) — цепочка честно выходит через VPS, это НЕ утечка.

    Контракт dashboard_geo.probe_ips: приоритет 1 (chain==route_ip -> status='ok')
    перекрывает приоритет 2 (chain==direct -> 'warn'). Значит при
    chain == direct == vps бэк отдаёт 'ok'. Фронт не должен рисовать leak-рамку,
    иначе красная 'утечка' противоречит зелёному flow-badge (ips.status='ok').
    Сценарий: прямой выход численно равен IP VPS-узла (direct == vps).
    """
    same = "198.51.100.7"
    d = {
        "ips": {
            "direct": {"ip": same, "country_code": "SG"},
            "chain": {"ip": same, "country_code": "SG"},
            "vps": {"ip": same, "country_code": "SG"},
            "status": "ok",
        },
        "ping": {"vps_ms": 40, "vpn_ms": 30},
    }
    strip = _render_flow(d)
    assert "leak" not in strip.lower(), (
        "ложная leak-рамка при chain==route (бэк отдаёт status='ok') — "
        "UI противоречит flow-badge"
    )


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


# --- вкладки дашборда: applyTab / initialTab / разметка ----------------------

def test_tab_functions_present_in_html():
    """Экстракция не бросает = функции вкладок существуют в index.html."""
    extract_functions(HTML, ["validTab", "applyTab", "initialTab"])


_TAB_DOM = r"""
document = {
  body: { _a: {}, setAttribute: function (k, v) { this._a[k] = v; },
          getAttribute: function (k) { return this._a[k]; } },
  _btns: ['overview', 'proxy', 'history', 'diag'].map(function (name) {
    var b = { name: name, active: false,
      getAttribute: function () { return b.name; },
      classList: { toggle: function (c, on) { b.active = !!on; } } };
    return b;
  }),
  querySelectorAll: function () { return this._btns; }
};
"""


def _apply_tab(name):
    body = _TAB_DOM + "applyTab(" + json.dumps(name) + ");" + \
        "console.log(JSON.stringify({ok: true, tab: document.body.getAttribute('data-tab'), " + \
        "active: document._btns.filter(function (b) { return b.active; }).map(function (b) { return b.name; })}));"
    return _run_node(_harness(["validTab", "applyTab"], body))


def test_apply_tab_sets_body_attr_and_active_button():
    res = _apply_tab("history")
    assert res["tab"] == "history"
    assert res["active"] == ["history"], "активен ровно один таб"


def test_apply_tab_rejects_unknown():
    body = _TAB_DOM + "console.log(JSON.stringify({changed: applyTab('javascript:alert(1)'), " + \
        "tab: document.body.getAttribute('data-tab') || null}));"
    res = _run_node(_harness(["validTab", "applyTab"], body))
    assert res["changed"] is False
    assert res["tab"] is None, "неизвестная вкладка не применяётся (вайтлист)"


def _initial_tab(hash_v, stored):
    body = _TAB_DOM + "console.log(JSON.stringify({tab: initialTab(" + \
        json.dumps(hash_v) + ", " + json.dumps(stored) + ")}));"
    return _run_node(_harness(["validTab", "initialTab"], body))["tab"]


def test_initial_tab_precedence_hash_then_stored_then_default():
    assert _initial_tab("#proxy", "history") == "proxy", "hash сильнее localStorage"
    assert _initial_tab("", "history") == "history", "без hash — запомненная вкладка"
    assert _initial_tab("#мусор", None) == "overview", "битый hash — дефолт"
    assert _initial_tab(None, None) == "overview"
    assert _initial_tab("#javascript:alert(1)", "diag") == "diag", "невалидный hash игнорируется"


def test_static_cards_carry_data_tab_and_tabbar_exists():
    """Разметка: каждая статическая карточка помечена data-tab; таб-бар с 4 кнопками;
    JS-карточки (card()) выводят data-tab из opts."""
    cards = re.findall(r'<div class="card(?: mb-3| mt-3)"[^>]*>', HTML)
    assert len(cards) >= 9, f"ожидаются статические карточки, найдено {len(cards)}"
    missing = [c for c in cards if 'data-tab="' not in c]
    assert not missing, f"карточки без data-tab: {missing}"
    for tab in ("overview", "proxy", "history", "diag"):
        assert f'data-tab-btn="{tab}"' in HTML, f"нет кнопки вкладки {tab}"
    assert 'data-tab="' in extract_functions(HTML, ["card"]), \
        "card() обязан выводить data-tab из opts (JS-карточки #cards)"


# --- lazy load: двухволновый /api/status per-tab ------------------------------
# Контракт: light-волна — только локальные пробы (мгновенный первый рендер), heavy —
# сетевые пробы активной вкладки; ключи = ключи gather_status, бэкенд ?only= гоняет
# только запрошенное. Наборы light/TAB_HEAVY проверяем ТОЧНЫМ множеством, чтобы
# нельзя было молча протащить тяжёлую пробу в light (и наоборот).

_LIGHT_KEYS = {"services", "vpn", "route", "traffic_guard", "hot_routes", "isolate", "ifaces"}
_TAB_HEAVY_KEYS = {
    "overview": {"tunnel", "direct", "ping", "ips", "geo_distance"},
    "proxy": {"connectivity"},
    "history": set(),
    "diag": {"dns", "exit_ips"},
}


def _query_keys(tab, wave):
    q = _run_node(_harness(["statusQuery", "tabHeavy", "validTab"], (
        "console.log(JSON.stringify({q: statusQuery(" + json.dumps(tab) + ", " +
        json.dumps(wave) + ")}));"
    )))["q"]
    assert q.startswith("only="), q
    return set(filter(None, q[len("only="):].split(",")))


def test_status_query_light_has_local_probes_only():
    """light-волна: ровно локальные пробы, ни одной сетевой — иначе первый рендер ждёт сеть."""
    assert _query_keys("overview", "light") == _LIGHT_KEYS
    assert _query_keys("diag", "light") == _LIGHT_KEYS, "light не зависит от вкладки"


def test_status_query_heavy_per_tab():
    """heavy-волна: ровно сетевые пробы активной вкладки (map TAB_HEAVY)."""
    for tab, keys in _TAB_HEAVY_KEYS.items():
        assert _query_keys(tab, "heavy") == keys, tab


def test_status_query_unknown_tab_falls_back_to_empty_heavy():
    """Невалидная вкладка не должна протащить чужой heavy-набор (validTab-гвард)."""
    assert _query_keys("javascript:alert(1)", "heavy") == set()
    assert _query_keys("", "heavy") == set()


def test_merge_status_is_shallow_and_null_safe():
    """mergeStatus: shallow-merge волн в LAST_STATUS, null-ответ волны — no-op."""
    body = (
        "LAST_STATUS = { ping: { status: 'ok' } };"
        "mergeStatus({ services: { status: 'ok' } });"
        "mergeStatus(null);"
        "var s = LAST_STATUS;"
        "console.log(JSON.stringify({ keys: Object.keys(s).sort(), "
        "ping: s.ping.status, services: s.services.status }));"
    )
    res = _run_node(_harness(["mergeStatus"], body))
    assert res["keys"] == ["ping", "services"], "волны мержатся, а не затираются"
    assert res["ping"] == "ok" and res["services"] == "ok"


_LAZY_STUBS = r"""
LAST_STATUS = null;
LAST_RANKING = {};
inFlight = false; currentPoll = null; paused = false;
refreshBtn = { disabled: false, querySelector: function () { return { className: '' }; } };
var _calls = [], _renders = [], _failed = 0, _toasts = 0;
function fetchJson(url) {
  _calls.push(url);
  if (url.indexOf('tunnel') !== -1) return Promise.reject(new Error('heavy boom'));
  if (url.indexOf('services') !== -1) return Promise.resolve({ services: { status: 'ok' } });
  if (url.indexOf('connectivity') !== -1) return Promise.resolve({ connectivity: { status: 'ok' } });
  return Promise.resolve({ ping: { status: 'ok' } });
}
function render(d, r) { _renders.push(JSON.parse(JSON.stringify(d || {}))); }
function renderFetchFailed() { _failed++; }
function toast() { _toasts++; }
function setRefreshing() {}
var document = { body: { getAttribute: function () { return 'overview'; } } };
"""


def _run_pollScenario():
    body = _LAZY_STUBS + (
        "poll(true).then(function () {"
        "  console.log(JSON.stringify({ calls: _calls, renders: _renders, "
        "failed: _failed, toasts: _toasts }));"
        "});"
    )
    return _run_node(_harness(
        ["poll", "statusQuery", "tabHeavy", "mergeStatus", "curTab", "validTab"], body,
    ))


def test_poll_two_waves_render_light_before_heavy():
    """Light-волна рендерит страницу до heavy; провал heavy — тихий (страница уже отрисована)."""
    res = _run_pollScenario()
    assert res["failed"] == 0 and res["toasts"] == 0, "провал heavy не должен будить no_server-тост"
    assert res["renders"], "light-волна обязана отрисовать страницу"
    assert "services" in res["renders"][-1]
    assert "ping" not in res["renders"][-1], "упавший heavy не подменяет данные"
    # ranking на overview не запрашивается (нужен только вкладке прокси)
    assert not any("ranking" in c for c in res["calls"])


def test_poll_light_failure_is_loud():
    """Провал light-волны — видимый: renderFetchFailed + toast (как раньше)."""
    body = _LAZY_STUBS.replace(
        "function fetchJson(url) {",
        "function fetchJson(url) { if (url.indexOf('services') !== -1) return Promise.reject(new Error('down'));",
    )
    body += (
        "poll(true).then(function () {"
        "  console.log(JSON.stringify({ calls: _calls, renders: _renders, "
        "failed: _failed, toasts: _toasts }));"
        "});"
    )
    res = _run_node(_harness(["poll", "statusQuery", "tabHeavy", "mergeStatus", "curTab", "validTab"], body))
    assert res["failed"] == 1 and res["toasts"] == 1, "падение light обязано быть видимым"
    assert res["renders"] == [], "без light-данных рендера нет"


def test_poll_heavy_success_after_light_failure_renders_nothing():
    """Находка code-review #376: успешный heavy при упавшем light не должен
    перерендерить страницу (render глушит FETCH_FAILED) и маскировать сбой."""
    body = _LAZY_STUBS.replace(
        "function fetchJson(url) {",
        "function fetchJson(url) {"
        "  if (url.indexOf('services') !== -1) return Promise.reject(new Error('down'));"
        "  if (url.indexOf('tunnel') !== -1) return Promise.resolve({ ping: { status: 'ok' } });",
    )
    body += (
        "poll(true).then(function () {"
        "  console.log(JSON.stringify({ calls: _calls, renders: _renders, "
        "failed: _failed, toasts: _toasts }));"
        "});"
    )
    res = _run_node(_harness(["poll", "statusQuery", "tabHeavy", "mergeStatus", "curTab", "validTab"], body))
    assert res["failed"] == 1, "сбой light обязан остаться видимым"
    assert res["renders"] == [], "heavy не рендерит страницу при упавшем light"


def test_poll_heavy_success_rerenders_merged_after_light():
    """Happy path: обе волны ок — heavy перерендеривает merged LAST_STATUS."""
    body = _LAZY_STUBS.replace(
        "function fetchJson(url) {",
        "function fetchJson(url) {"
        "  if (url.indexOf('tunnel') !== -1) return Promise.resolve({ ping: { status: 'ok' } });",
    )
    body += (
        "poll(true).then(function () {"
        "  console.log(JSON.stringify({ renders: _renders }));"
        "});"
    )
    res = _run_node(_harness(["poll", "statusQuery", "tabHeavy", "mergeStatus", "curTab", "validTab"], body))
    assert len(res["renders"]) == 2, "два рендера: light и heavy"
    # light-данные не затёрты heavy-волной; heavy смержен и отрисован.
    # (порядок волн не фиксируем: с instant-стабами heavy может смержиться до light-рендера)
    assert all("services" in r for r in res["renders"]), "light-данные не затёрты heavy-волной"
    assert res["renders"][-1].get("ping", {}).get("status") == "ok", "heavy-данные смержены и отрисованы"


def test_ensure_tab_data_loads_history_panels_only_on_history():
    """observe-панели истории грузятся только при входе на history; poll — на любой вкладке."""
    body = (
        "var calls = [];"
        "loadMetricsPanel = function () { calls.push('metrics'); };"
        "loadIncidentsPanel = function () { calls.push('incidents'); };"
        "poll = function (m) { calls.push('poll:' + m); };"
        "ensureTabData('history'); ensureTabData('proxy'); ensureTabData('overview');"
        "console.log(JSON.stringify({ calls: calls }));"
    )
    res = _run_node(_harness(["ensureTabData"], body))
    assert res["calls"] == ["metrics", "incidents", "poll:true", "poll:true", "poll:true"]
