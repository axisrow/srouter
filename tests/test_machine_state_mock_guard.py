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
файле роняет этот тест).

Второй гвард (issue #271, follow-up #267/PR #268): Codex adversarial review показал, что
проверка «canon ⊆ versions» — недостаточный инвариант. Она ловит расхождение МЕЖДУ двумя
списками, но не проверяет, что канонический список сам покрывает ВСЕ real machine-dependent
probes внутри health.check_all(). Новый probe, забытый в ОБОИХ helper'ах одновременно (или
добавленный в check_all и не замоканный нигде), оставлял бы первый гвард зелёным, а тесты
продолжали бы зависеть от состояния машины. test_all_up_monkey_covers_every_check_all_probe
парсит check_all() и требует прямой мок (или явную запись в allowlist) для каждого вызываемого
_xxx(...)."""
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


def _direct_calls(path, funcname):
    """Имена функций вида `_xxx(...)`, вызываемых НАПРЯМУЮ (без атрибутного доступа) внутри funcname.

    Ловит только вызовы верхнего уровня модуля (`ast.Name`, не `obj._xxx()`) — ровно тот класс,
    что check_all() использует для своих helper-проб (см. health.py, все `_port_up(...)`,
    `_dns_up()` и т.п. без префикса `health.`, т.к. сам файл — модуль health)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == funcname:
            calls = set()
            for call in ast.walk(node):
                if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                        and call.func.id.startswith("_")):
                    calls.add(call.func.id)
            return calls
    raise AssertionError(f"функция {funcname!r} не найдена в {path}")


# issue #271: Codex adversarial review на PR #268 показал, что предыдущий гвард (выше) проверял
# только «canon ⊆ versions», а не «canon покрывает ВСЕ real machine-dependent probes внутри
# check_all()». Новый probe, забытый в ОБОИХ helper'ах — уходит незамеченным. Этот гвард парсит
# health.py::check_all() и требует, чтобы каждый прямой вызов _xxx(...) верхнего уровня был либо
# замокан НАПРЯМУЮ в _all_up_monkey (health.setattr(health, "_xxx", ...)), либо явно занесён в
# allowlist ниже — с обоснованием, почему он безопасен без прямого мока (обычно: единственный
# реальный syscall внутри уже перекрыт другим замоканным примитивом ниже по стеку).
_REAL_HEALTH_PATH = _TESTS_DIR.parent / "health.py"

# Примитивы, чьё присутствие в check_all() безопасно БЕЗ прямого мока — они сами не делают
# machine-dependent I/O (чистая обёртка/дедупликация над уже замоканными funcs) либо их
# единственный реальный вызов дальше по стеку уже замокан (_resolve_host/_service_running/
# local_state.active_node — см. _all_up_monkey).
_SAFE_WITHOUT_DIRECT_MOCK = {
    "_dns_up",              # -> _resolve_host (мокан)
    "_local_proxy_up",      # -> _port_up + _service_running (оба мокан)
    "_upstream_vps_reachable",  # -> local_state.active_node (мокан пустым — port_open не вызывается)
    "_endpoint_override_check",  # -> _read_endpoint_config: читает settings.json — info-only,
    # НЕ покрыт прямым моком осознанно (issue #271 п.3, аллоулист): ok/warn статус этого чека
    # никогда не влияет на assert'ы существующих check_all-тестов (detail игнорируется), но
    # если появится тест, чувствительный к его detail — замокай явно и убери из allowlist.
    "_codenv_job_check",  # -> _codenv_job_state (реальный launchctl print), НЕ покрыт безусловным
    # моком в _all_up_monkey осознанно (issue #271): tests/test_health_codenv_job.py::_codenv_checks
    # вызывает _all_up_monkey ПОСЛЕ того, как caller-тест уже замокал health._codenv_job_check
    # своим сценарием (ok/down/unknown) — безусловный мок здесь перезаписал бы более поздний
    # тестовый мок (monkeypatch.setattr — последний вызов побеждает). Тесты, которые НЕ мокают
    # _codenv_job_check явно (в tests/test_health.py), получают реальный launchctl print —
    # безопасно, потому что codenv опционален и unknown/ok/down не роняют их конкретные assert'ы.
}


def test_all_up_monkey_covers_every_check_all_probe():
    canon = _setattr_targets(_TESTS_DIR / "test_health.py", "_all_up_monkey")
    mocked_health_funcs = {t.split(".", 1)[1] for t in canon if t.startswith("health.")}

    real_probes = _direct_calls(_REAL_HEALTH_PATH, "check_all")
    uncovered = real_probes - mocked_health_funcs - _SAFE_WITHOUT_DIRECT_MOCK
    assert not uncovered, (
        "check_all() вызывает machine-dependent probe(s), не замоканные напрямую в "
        f"tests/test_health.py::_all_up_monkey и не занесённые в allowlist: {sorted(uncovered)}. "
        "Либо добавь monkeypatch.setattr(health, <имя>, ...) в _all_up_monkey (issue #271), либо "
        "явно задокументируй в _SAFE_WITHOUT_DIRECT_MOCK этого файла, почему probe безопасен без "
        "прямого мока (например его единственный реальный syscall уже перекрыт другим мокан "
        "примитивом). Немоканный probe на dev-машине даёт недетерминированный вердикт (класс "
        "бага PR #263, verify-dont-guess)."
    )
