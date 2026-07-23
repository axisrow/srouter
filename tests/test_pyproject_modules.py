r"""Гвард packaging: все root-level .py-модули в pyproject.toml py-modules (cycle-review PR #172).

Контекст (cycle-review F3, issue #156): новый модуль `privileged_ops` импортируется
на top-level в srouter.py, но отсутствовал в `[tool.setuptools] py-modules`. Тесты
проходят из корня исходников (исходник на месте), но собранный wheel не содержал
файла → `pip install <wheel>` падал `ModuleNotFoundError: privileged_ops` до main,
ломая ВСЕ команды CLI (`srouter = "srouter:main"`).

Этот тест — регрессионный гвард: КАЖДЫЙ root-level .py-модуль (сосед srouter.py)
должен быть перечислен в py-modules, иначе wheel его не упакует. Эталон паттерна:
test_proxy_constants (#155) — grep-гвард против re-рассинхрона единого источника.

Дополнительный контракт (эталон #155, [[issue-155-proxy-constants-single-source]]):
py-modules — ЕДИНЫЙ источник правды о том, что входит в пакет. Любой новый модуль,
импортируемый CLI, обязан быть здесь, иначе packaging тихо ломается (dev-install
маскирует ошибку — исходник виден из checkout'а).
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"


def _root_level_modules():
    """Root-level .py-модули (соседи srouter.py) — кандидаты на упаковку в wheel.

    excludes: __init__, setup, conftest, примеры/шаблоны, модули внутри пакетов (server/, docker/).
    """
    skip = {"__init__", "setup", "conftest", "srouter_config", "srouter_config.example"}
    for p in ROOT.glob("*.py"):
        stem = p.stem
        if stem in skip or stem.endswith(".example"):
            continue
        yield stem


def _py_modules_list():
    """Список модулей из [tool.setuptools] py-modules в pyproject.toml."""
    text = PYPROJECT.read_text(encoding="utf-8")
    # Извлечь блок py-modules = [ ... ] (многострочный).
    m = re.search(r"py-modules\s*=\s*\[(.*?)\]", text, re.DOTALL)
    assert m, "py-modules block not found in pyproject.toml"
    return [s.strip().strip('"').strip("'") for s in re.findall(r'["\']([^"\']+)["\']', m.group(1))]


def test_all_root_modules_in_pyproject():
    """Каждый root-level .py-модуль обязан быть в py-modules — иначе wheel его не упакует.

    Регрессия F3: privileged_ops отсутствовал → ModuleNotFoundError в установленном CLI.
    """
    declared = set(_py_modules_list())
    missing = [m for m in sorted(_root_level_modules()) if m not in declared]
    assert not missing, (
        f"Root-level модули не в pyproject.toml py-modules → wheel их не упакует "
        f"(ModuleNotFoundError в pip install): {missing}"
    )


def test_srouter_imports_are_packaged():
    """Модули, импортируемые srouter.py на top-level, обязаны быть в py-modules.

    Прямой контракт точки входа `srouter = "srouter:main"`: любой top-level import
    в srouter.py должен попасть в wheel, иначе CLI падает на загрузке.
    """
    srouter_src = (ROOT / "srouter.py").read_text(encoding="utf-8")
    # Top-level `import X` / `from X import ...` (не внутри def/класса/try — грубая эвристика
    # по строкам без отступа). stdlib (argparse, os, ...) отфильтровываем по наличию в py-modules
    # только если они там — реально проверяем упаковку srouter-модулей.
    declared = set(_py_modules_list())
    import_re = re.compile(r"^(?:import|from)\s+([a-zA-Z_][\w.]*)")
    imported = set()
    for line in srouter_src.splitlines():
        m = import_re.match(line)
        if not m:
            continue
        name = m.group(1).split(".")[0]
        # Только srouter-модули (root-level файлы), не stdlib/third-party.
        if (ROOT / f"{name}.py").exists():
            imported.add(name)
    missing = sorted(imported - declared)
    assert not missing, (
        f"srouter.py top-level импорты не в py-modules → ModuleNotFoundError в wheel: {missing}"
    )
