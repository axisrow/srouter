"""Frontend-контракт панели «Качество туннеля»: тренд деградации виден и читаем.

Чистые функции (metricsRowHtml/sparklineFromValues/metricsTrendBadge/
metricsBaselineLabel) гоняются через node — тот же приём, что
test_dashboard_frontend.py / test_dashboard_proxy_panel.py (JS-фреймворков нет).
"""
import json
import shutil
import subprocess

import pytest

from _frontend_extract import HTML, extract_functions

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node не установлен")

_STUBS = r"""
var LANG = 'ru';
var _KEYS = {
  ms: 'мс',
  spark_empty: 'нет данных', spark_label: '{0} замеров, последний {1} мс',
  metrics_phase_connect: 'connect → прокси', metrics_phase_tls: 'путь + TLS',
  metrics_phase_ttfb: 'ответ сервера', metrics_phase_total: 'итог',
  metrics_trend_stable: 'стабильно', metrics_trend_degraded: 'деградация',
  metrics_trend_insufficient: 'мало данных',
  metrics_baseline_hour: 'тот же час прошлых дней',
  metrics_baseline_trail: '2–24 ч назад', metrics_baseline_none: 'базы ещё нет',
  metrics_attrib: 'что тормозит:', metrics_targets_kind: 'класс'
};
var I18N = { ru: _KEYS, en: _KEYS };
function t(key) {
  var s = I18N[LANG][key];
  if (s == null) return key;
  if (arguments.length > 1) {
    var argv = arguments;
    s = s.replace(/\{(\d+)\}/g, function (m, n) {
      var idx = Number(n) + 1;
      return idx < argv.length ? String(argv[idx]) : m;
    });
  }
  return s;
}
function esc(v){ return String(v==null?'':v)
  .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
"""


def _run_node(src):
    r = subprocess.run(["node", "-e", src], capture_output=True, text=True, timeout=20)
    if r.returncode != 0:
        raise AssertionError("node упал:\n" + r.stderr + "\n---stdout---\n" + r.stdout)
    return json.loads(r.stdout.strip().splitlines()[-1])


def _call(func_name, args):
    funcs = extract_functions(HTML, ["t", func_name])
    body = "console.log(JSON.stringify({out: %s(%s)}));" % (func_name, ", ".join(args))
    return _run_node(_STUBS + "\n" + funcs + "\n" + body)["out"]


def test_metrics_row_formats_ms_value():
    html = _call("metricsRowHtml", ["'metrics_phase_total'", "250.4"])
    assert "250 мс" in html
    assert "итог" in html


def test_metrics_row_null_value_renders_dash():
    html = _call("metricsRowHtml", ["'metrics_phase_tls'", "null"])
    assert "—" in html
    assert "мс" not in html


def test_sparkline_two_points_draws_polyline():
    svg = _call("sparklineFromValues", ["[100,300]", "'#0d6efd'"])
    assert "<polyline" in svg
    assert "points=" in svg


def test_sparkline_single_point_draws_placeholder():
    svg = _call("sparklineFromValues", ["[100]", "'#0d6efd'"])
    assert "<polyline" not in svg


def test_sparkline_skips_null_points_without_breaking():
    """Провальные замеры (total_ms=null) не рвут отрисовку: линия по выжившим точкам."""
    svg = _call("sparklineFromValues", ["[100,null,200]", "'#0d6efd'"])
    assert "<polyline" in svg


def test_trend_badge_colors():
    assert _call("metricsTrendBadge", ["'degraded'"])["cls"] == "bg-danger"
    assert _call("metricsTrendBadge", ["'stable'"])["cls"] == "bg-success"
    assert _call("metricsTrendBadge", ["'insufficient'"])["cls"] == "bg-secondary"
    # неизвестный тренд — тоже secondary (fail-нейтрально)
    assert _call("metricsTrendBadge", ["'weird'"])["cls"] == "bg-secondary"


def test_baseline_label_sources():
    assert "тот же час" in _call("metricsBaselineLabel", ["'same-hour'"])
    assert "24" in _call("metricsBaselineLabel", ["'trailing'"])
    assert "базы" in _call("metricsBaselineLabel", ["'none'"])


# ============================ мульти-таргет: таблица сайтов (2026-09-29) ============================

def _targets_call(payload):
    return _call("metricsTargetsSectionHtml", [json.dumps(payload, ensure_ascii=False)])


def test_metrics_targets_table_renders_all_sites():
    """Все цели из payload попадают в таблицу: ok-rate в %, мс-фазы, последний статус."""
    html = _targets_call([
        {"target": "api.anthropic.com", "ok_rate_1h": 1.0, "ok_rate_24h": 0.98,
         "tls_ms": 40, "ttfb_ms": 60, "last_status": "ok"},
        {"target": "github.com", "ok_rate_1h": 0.5, "ok_rate_24h": 0.9,
         "tls_ms": None, "ttfb_ms": None, "last_status": "connection-failed"},
    ])
    assert "api.anthropic.com" in html and "github.com" in html
    assert "100%" in html and "50%" in html
    assert "connection-failed" in html
    assert "<table" in html


def test_metrics_targets_empty_payload_renders_nothing():
    """Без целей (старый payload/нет данных) секция не рисуется вовсе."""
    assert _targets_call([]) == ""
    assert _targets_call(None) == ""


def test_metrics_targets_low_sample_rate_hidden():
    """#397-followup: ok-rate на малой выборке (samples < 10) — не «100%», а «—».
    3 ok-замера за сутки не дают права писать 100%; legacy payload без samples
    рисуется по-старому (percent виден)."""
    html = _targets_call([
        {"target": "api.z.ai", "kind": "direct", "ok_rate_1h": 1.0, "ok_rate_24h": 1.0,
         "samples": 3, "tls_ms": 28, "ttfb_ms": 74, "last_status": "ok"},
        {"target": "chatgpt.com", "kind": "tunnel", "ok_rate_1h": 1.0, "ok_rate_24h": 1.0,
         "samples": 4400, "tls_ms": 700, "ttfb_ms": 900, "last_status": "ok"},
    ])
    assert html.count("100%") == 2, html
    assert _targets_call([
        {"target": "legacy.example", "ok_rate_1h": 1.0, "ok_rate_24h": 1.0,
         "tls_ms": 1, "ttfb_ms": 1, "last_status": "ok"},
    ]).count("100%") == 2


def test_metrics_targets_escapes_host_html():
    """target из state (не доверенный) экранируется — без HTML-инъекции в панель."""
    html = _targets_call([{"target": "<script>alert(1)</script>", "ok_rate_1h": 1.0,
                           "ok_rate_24h": 1.0, "tls_ms": 1, "ttfb_ms": 1, "last_status": "ok"}])
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


# ============================ атрибуция «что тормозит» + классы (#396) ============================

def _attr_call(payload):
    return _call("attributionHtml", [json.dumps(payload, ensure_ascii=False)])


def test_attribution_hidden_when_null_or_unknown():
    """Fail-open: нет кэша или выборка мала — строка не рендерится, UI не гадает."""
    assert _attr_call(None) == ""
    assert _attr_call({"verdict": "unknown", "culprit": None, "detail": "мало"}) == ""


def test_attribution_ok_renders_green_with_detail():
    html = _attr_call({"verdict": "ok", "culprit": None,
                       "detail": "прямые 10/10, туннель 9/10 за 10м"})
    assert "text-success" in html
    assert "что тормозит:" in html
    assert "прямые 10/10" in html


def test_attribution_problem_renders_red_with_culprit():
    html = _attr_call({"verdict": "chain-wedge",
                       "culprit": "залипание прокси-стека (privoxy/xray)",
                       "detail": "via-proxy молчит при живом direct"})
    assert "text-danger" in html
    assert "залипание прокси-стека" in html and "via-proxy молчит" in html
    assert "рестарт" not in html.split("via-proxy")[0], "кульпит первым — это заголовок строки"


def test_attribution_site_renders_warning():
    html = _attr_call({"verdict": "site", "culprit": "netflix.com", "detail": "ok 1/7 за 1ч"})
    assert "text-warning" in html and "netflix.com" in html


def test_attribution_escapes_server_text():
    """Поле culprit идёт из sidecar-state — экранируем на всякий случай (fail-safe UI)."""
    html = _attr_call({"verdict": "site", "culprit": "<img onerror=x>", "detail": ""})
    assert "<img" not in html
    assert "&lt;img" in html


def test_metrics_targets_kind_column_class_vs_direct():
    """#396: колонка «класс» различает tunnel/direct; легаси-ряд без kind = tunnel."""
    html = _targets_call([
        {"target": "github.com", "kind": "tunnel", "ok_rate_1h": 0.5, "ok_rate_24h": 0.9,
         "tls_ms": None, "ttfb_ms": None, "last_status": "ok"},
        {"target": "github.com", "kind": "direct", "ok_rate_1h": 1.0, "ok_rate_24h": 1.0,
         "tls_ms": 30, "ttfb_ms": 10, "last_status": "ok"},
        {"target": "legacy.example", "ok_rate_1h": 1.0, "ok_rate_24h": 1.0,
         "tls_ms": 1, "ttfb_ms": 1, "last_status": "ok"},
    ])
    assert "класс" in html
    assert html.count(">github.com<") == 2, "одна цель, два класса — два ряда"
    assert ">direct<" in html and ">tunnel<" in html
