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
  metrics_baseline_trail: '2–24 ч назад', metrics_baseline_none: 'базы ещё нет'
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
