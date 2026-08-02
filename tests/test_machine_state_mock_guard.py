"""Guard: канонический machine-state mock-список (test_health.py::_all_up_monkey) и его
производная в test_health_versions.py (_machine_state_monkey) не должны расходиться по НАБОРУ
замоканных атрибутов (issue #267, follow-up #251/PR #263).

Обе функции гасят одни и те же реальные пробы машинного состояния (порты, туннель, ps/lsof,
launchctl, DNS, local.json), чтобы check_all()-тесты не зависели от того, что запущено на
dev-машине. Если в check_all появится новый такой probe, его мокают в обоих местах — иначе тест
в файле, где мока нет, тихо словит недетерминированный вердикт (класс бага из PR #263).

Полное объединение в общий helper признано нецелесообразным (#267 п.2): versions-вариант
осознанно использует другие status-заглушки для proxy-пробов (unknown вместо ok, см. docstring
_machine_state_monkey) и добавляет свой info-only чек (_endpoint_override_check). Вместо
слияния — машинно-проверяемый гвард: канонический набор test_health.py обязан быть
подмножеством набора test_health_versions.py. Новый probe, добавленный в канон и забытый в
versions-варианте, ловится здесь; проверено вручную (временное добавление мока только в одном
файле роняет этот тест)."""
import ast
from pathlib import Path

_TESTS_DIR = Path(__file__).resolve().parent


def _setattr_targets(path, funcname):
    """Множество "obj.attr" строк из monkeypatch.setattr(obj, "attr", ...) внутри функции funcname."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == funcname:
            targets = set()
            for call in ast.walk(node):
                if (isinstance(call, ast.Call)
                        and isinstance(call.func, ast.Attribute)
                        and call.func.attr == "setattr"
                        and len(call.args) >= 2
                        and isinstance(call.args[1], ast.Constant)):
                    targets.add(f"{ast.unparse(call.args[0])}.{call.args[1].value}")
            return targets
    raise AssertionError(f"функция {funcname!r} не найдена в {path}")


def test_machine_state_mock_lists_stay_in_sync():
    canon = _setattr_targets(_TESTS_DIR / "test_health.py", "_all_up_monkey")
    versions = _setattr_targets(_TESTS_DIR / "test_health_versions.py", "_machine_state_monkey")

    missing_in_versions = canon - versions
    assert not missing_in_versions, (
        "Новый machine-state probe замокан в tests/test_health.py::_all_up_monkey, но НЕ в "
        f"tests/test_health_versions.py::_machine_state_monkey: {sorted(missing_in_versions)}. "
        "Добавь мок и туда (issue #267) — иначе test_health_versions.py словит недетерминированный "
        "вердикт от немоканного probe на dev-машине (класс бага PR #263)."
    )
