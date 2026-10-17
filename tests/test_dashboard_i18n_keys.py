"""Гвард i18n-словарей static/index.html: en/ru/zh — одно множество ключей; used ⊆ en.

#429: в zh отсутствовали proxy_force_confirm / proxy_foreign / proxy_mixed_state —
confirm перезаписи чужого прокси и статусы карточки «Прокси» приезжали на английском
(fallback t(): zh → en → сырой ключ, index.html:709-713). Часть ключей используется
ДИНАМИЧЕСКИ (confKey = 'proxy_foreign' → t(confKey), index.html:1622-1624) — литеральный
grep t('...') их не видит, поэтому главный инвариант — РАВЕНСТВО множеств ключей трёх
словарей. Парс точный: I18N целиком eval-ится в node (канон test_dashboard_frontend),
никаких регулярок по значениям и захардкоженных диапазонов строк.
"""
import json
import re
import shutil

import pytest

from _frontend_extract import HTML
from test_dashboard_frontend import _run_node

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node не установлен")


def _dict_keys():
    """Точные множества ключей en/ru/zh из I18N (eval среза index.html в node)."""
    i18n_src = HTML[HTML.index("var I18N = {"):HTML.index("function detectLang")]
    src = (
        "var i18n_src = " + json.dumps(i18n_src) + ";\n"
        "eval(i18n_src);\n"
        "console.log(JSON.stringify({\n"
        "  en: Object.keys(I18N.en).sort(),\n"
        "  ru: Object.keys(I18N.ru).sort(),\n"
        "  zh: Object.keys(I18N.zh).sort(),\n"
        "}));\n"
    )
    return _run_node(src)


def test_i18n_dicts_have_identical_key_sets():
    """en == ru == zh по множеству ключей: динамические t(confKey) идут в любой язык,
    отсутствие ключа в одном словаре = английский fallback в чужой локали (#429)."""
    keys = _dict_keys()
    en, ru, zh = (set(keys[l]) for l in ("en", "ru", "zh"))
    assert en == ru == zh, (
        "расхождение множеств ключей i18n — недостающий ключ даёт английский fallback: "
        f"en-ru={sorted(en - ru)} ru-en={sorted(ru - en)} "
        f"en-zh={sorted(en - zh)} zh-en={sorted(zh - en)}"
    )


def test_used_literal_keys_exist_in_dicts():
    """Каждый литеральный t('…') и data-i18n*-ключ есть в словарях (ловит опечатки в ключах).

    Динамические t(k[1]) из renderFetchFailed покрыты: все их card_*-ключи используются
    и литерально в основном пути рендера.
    """
    used = set(re.findall(r"\bt\('([a-z0-9_]+)'", HTML))
    used |= set(re.findall(r'data-i18n(?:-title|-aria|-placeholder)?="([a-z0-9_]+)"', HTML))
    keys = set(_dict_keys()["en"])
    missing = sorted(used - keys)
    assert not missing, f"ключи t()/data-i18n отсутствуют в I18N.en: {missing}"
