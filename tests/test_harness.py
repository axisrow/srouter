"""Self-contained harness smoke. НЕ импортирует dashboard (требует реальный srouter_config.py)
и НЕ зависит от srouter.local.example.json (это артефакт #2, тестируется в test_local_state.py).
"""
import json
from pathlib import Path


def test_harness_runs():
    """pytest обнаруживает tests/ и запускает этот файл."""
    assert True


def test_root_module_importable():
    """conftest добавил корень в sys.path — root-level модуль импортируется из tests/.
    Реальная проверка инъекции: local_state лежит в корне, не в tests/, и виден
    только через conftest.
    """
    import local_state  # noqa: F401 — падает, если conftest не добавил корень

    assert Path(__file__).resolve().parent.parent.is_dir()


def test_tmp_path_fixture_pattern(tmp_path):
    """Демонстрирует паттерн для #2/#5/#7/#8/#12: tmp_path fixture изолирует тесты
    от реальной локальной машины — никакой реальный srouter.local.json не трогается.
    """
    fake = tmp_path / "srouter.local.json"
    fake.write_text(json.dumps({"nodes": []}), encoding="utf-8")
    assert fake.exists()
    assert json.loads(fake.read_text(encoding="utf-8"))["nodes"] == []
