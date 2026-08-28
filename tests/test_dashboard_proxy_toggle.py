"""toggleProxyConsumer — обработчик клика на тоггл потребителя прокси в панели.

ДЫРА (cycle-review PR #300, /review): `row && row.configured === true` коротит в `undefined`
(falsy), когда `row` не найден (устаревший PROXY_DATA, гонка с обновлением панели, или id не
совпал) — action тихо становится 'enable' даже для уже настроенного потребителя, без ошибки
пользователю. Функция делает `fetch`, DOM-манипуляции и глобальное состояние мутации — тестируем
через node с полностью застабленным окружением (тот же приём extract_functions, что и
test_dashboard_proxy_panel.py, но с ручными стабами вместо чистого render).
"""
import json
import shutil
import subprocess

import pytest

from _frontend_extract import HTML, extract_functions

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node не установлен")

# Стабы всего, что toggleProxyConsumer трогает снаружи себя: mutation-guard, toast/i18n,
# DOM btn-объект (простой mock), и fetch — перехватываем вызов, не бьём по сети.
_STUBS = r"""
var LANG = 'ru';
var MUTATION = null;
var PROXY_DATA = null;
var _calls = { fetch: null, toast: [], loadProxyPanel: 0, finishMutation: 0 };

function mutationInFlight() { return !!MUTATION; }
function setMutationControlsDisabled(on) {}
function tryBeginMutation(kind) {
  if (mutationInFlight()) return false;
  MUTATION = { kind: kind };
  return true;
}
function finishMutation() { MUTATION = null; _calls.finishMutation++; }
function t(key, arg) { return arg !== undefined ? (key + ':' + arg) : key; }
function toast(msg, kind) { _calls.toast.push({ msg: msg, kind: kind }); }
function loadProxyPanel(probe) {
  _calls.loadProxyPanel++;
  return { finally: function (cb) { cb && cb(); return this; } };
}

function makeBtn(cid) {
  return {
    _cid: cid,
    innerHTML: 'orig',
    disabled: false,
    getAttribute: function (name) { return name === 'data-consumer' ? this._cid : null; },
  };
}
"""


def _run_node(src):
    r = subprocess.run(["node", "-e", src], capture_output=True, text=True, timeout=20)
    if r.returncode != 0:
        raise AssertionError("node упал:\n" + r.stderr + "\n---stdout---\n" + r.stdout)
    return json.loads(r.stdout.strip().splitlines()[-1])


def _run_toggle(*, proxy_data, cid, fetch_stub="function fetch(){ return new Promise(function(){}); }"):
    """Запускает toggleProxyConsumer(btn) с заданным PROXY_DATA и cid; fetch не резолвится
    по умолчанию (нам нужно только состояние ДО сетевого вызова — синхронная часть)."""
    func = extract_functions(HTML, ["toggleProxyConsumer"])
    body = (
        "PROXY_DATA = %s;\n"
        "%s\n"
        "var btn = makeBtn(%s);\n"
        "%s\n"
        "toggleProxyConsumer(btn);\n"
        "console.log(JSON.stringify({calls: _calls, mutation: MUTATION, btnDisabled: btn.disabled}));"
    ) % (json.dumps(proxy_data), fetch_stub, json.dumps(cid), func)
    return _run_node(_STUBS + "\n" + body)


def test_missing_row_does_not_silently_default_to_enable():
    """ГЛАВНЫЙ случай дыры: cid не найден в PROXY_DATA.consumers -> НЕ должен уйти в fetch
    с угаданным action. Должен: показать ошибку, перечитать панель, отпустить mutation-lock."""
    res = _run_toggle(proxy_data={"consumers": [{"id": "git", "configured": True}]}, cid="vscode")
    assert res["calls"]["fetch"] is None, "не должен был вызывать /api/proxy/* без найденной строки"
    assert res["calls"]["toast"], "пользователь должен увидеть ошибку, а не тишину"
    assert res["calls"]["toast"][0]["kind"] == "err"
    assert res["calls"]["loadProxyPanel"] == 1, "обязан перечитать актуальное состояние с сервера"
    assert res["calls"]["finishMutation"] == 1, "mutation-lock обязан освободиться"
    assert res["mutation"] is None


def test_null_proxy_data_does_not_silently_default_to_enable():
    """PROXY_DATA ещё не загружен (null) — тот же честный отказ, не угаданный action."""
    res = _run_toggle(proxy_data=None, cid="git")
    assert res["calls"]["fetch"] is None
    assert res["calls"]["toast"]
    assert res["calls"]["toast"][0]["kind"] == "err"


def test_found_configured_row_computes_disable_action():
    """Контрольный случай: row найден, настроен -> action='disable', уходит в сетевой вызов
    (сам fetch не резолвим — проверяем через какой URL он был вызван)."""
    fetch_stub = (
        "var _url = null;"
        "function fetch(url, opts) { _url = url; _calls.fetch = url; return new Promise(function(){}); }"
    )
    res = _run_toggle(
        proxy_data={"consumers": [{"id": "git", "configured": True}]},
        cid="git",
        fetch_stub=fetch_stub,
    )
    assert res["calls"]["fetch"] == "/api/proxy/disable"


def test_found_unconfigured_row_computes_enable_action():
    fetch_stub = (
        "function fetch(url, opts) { _calls.fetch = url; return new Promise(function(){}); }"
    )
    res = _run_toggle(
        proxy_data={"consumers": [{"id": "git", "configured": False}]},
        cid="git",
        fetch_stub=fetch_stub,
    )
    assert res["calls"]["fetch"] == "/api/proxy/enable"
