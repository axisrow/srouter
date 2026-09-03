"""Frontend-контракт панели «Прокси»: одна таблица вместо разрозненных тогглов.

Ключевое требование редизайна — ДВЕ НЕЗАВИСИМЫЕ КОЛОНКИ: «настроен» (из конфига) и
«физически» (замер трафика). Старый UI показывал только первую и потому рапортовал
зелёный ON при мёртвом туннеле.

Тестируем чистую функцию proxyRowHtml(consumer) через node — тот же приём, что в
test_dashboard_frontend.py (JS-фреймворков в проекте нет).
"""
import json
import shutil
import subprocess

import pytest

from _frontend_extract import HTML, extract_functions

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node не установлен")

_STUBS = r"""
var LANG = 'ru';
// t() при отсутствии ключа падает обратно в I18N.en — заглушка обязана его определить,
// иначе node роняется на TypeError вместо проверки контракта рендера.
var _KEYS = {
  proxy_yes: 'да', proxy_no: 'нет', proxy_unknown: '?',
  proxy_works: 'работает', proxy_broken: 'не идёт', proxy_na: '—',
  proxy_state_unknown: 'неизвестно', proxy_mixed: 'частично',
  // issue #307: новые ключи маппятся сами в себя — ассерт «proxy_foreign in html» ловит
  // именно использование ключа, а не совпадение человеческого текста.
  proxy_foreign: 'proxy_foreign', proxy_mixed_state: 'proxy_mixed_state',
  proxy_on: 'Включить', proxy_off: 'Выключить'
};
var I18N = { ru: _KEYS, en: _KEYS };
function esc(v){ return String(v==null?'':v)
  .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
"""


def _run_node(src):
    r = subprocess.run(["node", "-e", src], capture_output=True, text=True, timeout=20)
    if r.returncode != 0:
        raise AssertionError("node упал:\n" + r.stderr + "\n---stdout---\n" + r.stdout)
    return json.loads(r.stdout.strip().splitlines()[-1])


def _render(consumer):
    funcs = extract_functions(HTML, ["t", "proxyRowHtml"])
    body = "console.log(JSON.stringify({html: proxyRowHtml(%s)}));" % json.dumps(consumer)
    return _run_node(_STUBS + "\n" + funcs + "\n" + body)["html"]


def test_configured_and_working_shows_both_positive():
    html = _render({"id": "vscode", "title": "VSCode / codex", "configured": True,
                    "runtime": "ok", "proxy": "socks5h://127.0.0.1:10808",
                    "detail": "", "manageable": True})
    assert "VSCode / codex" in html
    assert "socks5h://127.0.0.1:10808" in html


def test_configured_but_broken_is_visually_marked_as_problem():
    """ГЛАВНАЯ строка: настроен, но трафик не идёт. Ради неё вся панель и делается."""
    html = _render({"id": "claude", "title": "Claude Code", "configured": True,
                    "runtime": "down", "proxy": "http://127.0.0.1:8118",
                    "detail": "идёт напрямую", "manageable": True})
    # Расхождение обязано быть видно как опасность, а не как нейтральная строка.
    assert "text-danger" in html or "bg-danger" in html


def test_not_configured_does_not_render_as_working():
    """«не настроен» не имеет права выглядеть как работающий прокси."""
    html = _render({"id": "git", "title": "git → github", "configured": False,
                    "runtime": "n/a", "proxy": "", "detail": "", "manageable": True})
    assert "bg-success" not in html


def test_unmanageable_consumer_gets_no_toggle_button():
    """Системный прокси read-only: кнопки быть не должно, иначе обещаем несуществующее."""
    html = _render({"id": "system", "title": "Система (macOS)", "configured": False,
                    "runtime": "n/a", "proxy": "", "detail": "", "manageable": False})
    assert "proxy-toggle" not in html


def test_manageable_consumer_gets_toggle_button():
    html = _render({"id": "git", "title": "git → github", "configured": True,
                    "runtime": "ok", "proxy": "socks5h://x", "detail": "", "manageable": True})
    assert "proxy-toggle" in html
    assert 'data-consumer="git"' in html


def test_hostile_detail_is_escaped_not_injected():
    """detail приходит из health-проб (там PID/пути/вывод команд) — экранируем всегда."""
    html = _render({"id": "git", "title": "git", "configured": True, "runtime": "down",
                    "proxy": "", "detail": "<img src=x onerror=alert(1)>", "manageable": True})
    assert "<img" not in html
    assert "&lt;img" in html


def test_hostile_title_is_escaped():
    html = _render({"id": "x", "title": "<script>bad()</script>", "configured": None,
                    "runtime": "unknown", "proxy": "", "detail": "", "manageable": False})
    assert "<script>bad()" not in html


def test_long_detail_is_truncated_in_the_row():
    """detail от health-проб бывает многострочной инструкцией на сотни символов.

    Обнаружено на живых данных: _github_direct_check() возвращает ~700 символов с
    переносами строк — в ячейке таблицы это ломает вёрстку. В строке показываем
    короткую выжимку, полный текст уходит в title (tooltip).
    """
    long_detail = "первая строка причины. " + ("подробность " * 60) + "\nвторая строка"
    html = _render({"id": "git", "title": "git", "configured": True, "runtime": "down",
                    "proxy": "", "detail": long_detail, "manageable": True})
    # В видимом тексте — обрезанный вариант, не полотно.
    visible = html.split('title="')[0] if 'title="' in html else html
    assert len(visible) < 1200, "строка таблицы не должна нести полотно текста"
    assert "…" in html or "..." in html


def test_multiline_detail_does_not_break_row_layout():
    """Переносы строк из вывода команд не должны попадать в ячейку как есть."""
    html = _render({"id": "git", "title": "git", "configured": True, "runtime": "down",
                    "proxy": "", "detail": "строка один\nстрока два\nстрока три",
                    "manageable": True})
    body = html.split("</tr>")[-2] if "</tr>" in html else html
    assert "\n" not in body.replace("\\n", "")


# ==================== issue #307: foreign/mixed видны пользователю ====================

def test_foreign_state_is_shown_distinctly_not_as_not_configured():
    """ДЫРА #307: чужое значение НЕ имеет права выглядеть как «нет» (не настроено) —
    обычный клик «Включить» выглядит безобидно, а уничтожил бы чужую настройку."""
    html = _render({"id": "git", "title": "git → github", "configured": False,
                    "state": "foreign", "runtime": "n/a",
                    "proxy": "https://corp-proxy:8443", "detail": "", "manageable": True})
    assert "proxy_foreign" in html, "чужое значение подписано отдельным состоянием"
    assert "text-warning" in html, "чужое значение подсвечено как требующее внимания"


def test_mixed_state_is_shown_distinctly():
    html = _render({"id": "vscode", "title": "VSCode / codex", "configured": False,
                    "state": "mixed", "runtime": "n/a",
                    "proxy": "http://corp-proxy:3128", "detail": "", "manageable": True})
    assert "proxy_mixed_state" in html


def test_absent_state_keeps_plain_no_label():
    """Обычное «не настроено» (absent) не превращается в warning — сигнал не размывается."""
    html = _render({"id": "git", "title": "git → github", "configured": False,
                    "state": "absent", "runtime": "n/a",
                    "proxy": "", "detail": "", "manageable": True})
    assert "proxy_foreign" not in html
