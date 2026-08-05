"""Гвард изоляции слоёв install↔uninstall (issue #124).

ЧТО ПРОВАЛИЛОСЬ В ПРОШЛЫЙ РАЗ. В PR #119 WAL-логика ПРОТЕКЛА в uninstall: restorable-gate
_component_uninstall_item пришлось патчить ради «WAL-only state» (P1-3), то есть uninstall стал знать
МЕХАНИКУ ЗАПИСИ install'а — что бывает pending-состояние, что оно требует promote, в каком порядке
install пишет state и файл. Такая связь делает каждое новое crash-окно поводом для правки ОБОИХ
слоёв, из-за чего точечные патчи и не сходились.

ГРАНИЦА. Uninstall имеет право знать факты о МИРЕ: существует ли конфиг, есть ли в нём srouter-маркер,
лежат ли рядом валидные backup-файлы. Это свойства файловой системы — они верны независимо от того,
кто и как их создал (install, предыдущая версия srouter, человек руками). Uninstall НЕ имеет права
знать механику install'а: шаблон имени backup, детали атомарной записи, наличие промежуточных фаз.

Отсюда — литералы под запретом в install_cleanup.py. Разрешён `.srouter-restore-tmp` (собственная
механика восстановления uninstall'а, а не заимствованная у install).

Этот тест КРАСНЫЙ на HEAD: install_cleanup.py держит мёртвые pending_backup/pending_written_at —
остатки удалённого WAL (единственные вхождения в репозитории, их никто не пишет).
"""
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent

# (литерал, почему он не должен встречаться в слое uninstall)
_FORBIDDEN_IN_CLEANUP = [
    ("srouter-backup", "шаблон имени backup — механика ИМЕНОВАНИЯ, принадлежащая install; "
                       "спрашивать надо через install_config.discover_backups(config_path)"),
    ("pending", "остаток WAL-словаря: промежуточные фазы install'а не должны быть видны uninstall'у"),
]


def _code_lines(path):
    """Строки кода без комментариев и docstring-прозы.

    Гвард ловит ЗАВИСИМОСТЬ, а не упоминание. Комментарий «этот ключ был мёртвым остатком WAL» —
    документация решения (её проект требует каноном fix-once-document-decisions), а не связь со
    слоем install. Сравнивать надо исполняемый код.
    """
    import ast
    import io
    import tokenize

    source = path.read_text(encoding="utf-8")
    docstrings = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                docstrings.add(doc)
    lines = {}
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type == tokenize.COMMENT:
            continue
        if tok.type == tokenize.STRING and tok.string.strip("rbuf")[1:-1].strip("\"'") in docstrings:
            continue
        if tok.type == tokenize.STRING and any(doc in tok.string for doc in docstrings):
            continue
        lines.setdefault(tok.start[0], []).append(tok.string)
    return {n: " ".join(parts) for n, parts in lines.items()}


@pytest.mark.parametrize("literal, reason", _FORBIDDEN_IN_CLEANUP,
                         ids=[lit for lit, _ in _FORBIDDEN_IN_CLEANUP])
def test_install_cleanup_has_no_install_write_mechanics(literal, reason):
    hits = [f"{n}: {code.strip()}"
            for n, code in _code_lines(_ROOT / "install_cleanup.py").items() if literal in code]
    assert not hits, (
        f"install_cleanup.py содержит {literal!r} в исполняемом коде — утечка слоя install в "
        f"uninstall ({reason}). Строки: {hits}"
    )


def test_install_config_does_not_import_cleanup():
    """Направление зависимости: cleanup → config, но не обратно (иначе цикл и размывание границы).

    Проверяем именно ИМПОРТЫ через AST, а не вхождение подстроки: install_config.py упоминает
    install_cleanup в докстринге-описании фасада (issue #229), и это законно — ссылка в прозе не
    создаёт зависимости.
    """
    import ast

    tree = ast.parse((_ROOT / "install_config.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert "install_cleanup" not in imported, (
        "install_config не должен импортировать install_cleanup — направление слоёв только cleanup→config"
    )
