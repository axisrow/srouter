"""Класс-гвард #427: одно имя функции не определяется в двух health_*-модулях.

health.py собирает фасад звёздными ре-экспортами (from health_X import *). Дубликат имени
между модулями молча перетирается последним импортом: health_devworkflow._github_direct_check
(#199) перетёр health_probes._github_direct_check (#423) — doctor звал не ту функцию, а моки
на health.<имя> держали тесты зелёными (перетёртое имя одно на оба вызова check_all).

Проверяем РАНТАЙМ-биндинг (__module__ каждого объекта), не AST — канон
star-cascade-verify-runtime-not-ast: каскад живёт в порядке импортов фасада.
"""
import importlib

import pytest

HEALTH_MODULES = ("health_probes", "health_claude", "health_codex", "health_codenv",
                  "health_devworkflow", "health_endpoint", "health_backups")


@pytest.mark.parametrize("mod_name", HEALTH_MODULES)
def test_modules_importable(mod_name):
    """Каждый health_*-модуль импортируется (гвард не молчит при битом импорте)."""
    assert importlib.import_module(mod_name) is not None


def test_no_function_name_defined_in_two_health_modules():
    """Ни одно имя callable не определяется в 2+ health_*-модулях.

    Дубль = последний star-import в health.py перетирает предыдущий биндинг; вызовы
    через фасад получают не ту функцию, которую читает автор строки вызова.
    """
    owners: dict = {}
    for mod_name in HEALTH_MODULES:
        mod = importlib.import_module(mod_name)
        for name in dir(mod):
            obj = getattr(mod, name)
            if callable(obj) and getattr(obj, "__module__", None) == mod_name:
                owners.setdefault(name, []).append(mod_name)
    dups = {name: mods for name, mods in owners.items() if len(mods) > 1}
    assert not dups, (
        "имя определено в 2+ health_*-модулях — последний star-import перетирает "
        f"предыдущий биндинг, вызовы через фасад зовут не ту функцию: {dups}"
    )
