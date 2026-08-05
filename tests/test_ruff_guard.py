"""Regress-гвард для ruff-конфигурации (issue #161).

Проверяет две вещи эмпирически, реальным вызовом `ruff check`, а не догадкой
по содержимому pyproject.toml:

1. Текущий HEAD зелёный — E722/BLE001 не регрессируют на существующем коде.
2. Гвард реально работает: bare except / голый except Exception в файле без
   per-file-ignore ловится ruff'ом (мутационная проверка — портим временную
   копию файла, а не рабочее дерево).

Канон: no-hidden-magic-follow-canon, verify-dont-guess — эмпирический
эксперимент вместо гипотезы, что конфиг "должен" работать.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(shutil.which("ruff") is None, reason="ruff не установлен")


def _run_ruff(*args, cwd=REPO_ROOT):
    return subprocess.run(
        ["ruff", "check", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_ruff_check_clean_on_head():
    """Текущее состояние репозитория обязано быть зелёным для E722/BLE001."""
    result = _run_ruff(".")
    assert result.returncode == 0, (
        f"ruff check упал на HEAD (ожидался зелёный CI):\nstdout={result.stdout}\nstderr={result.stderr}"
    )


def test_ruff_guard_catches_new_bare_except_and_blind_except(tmp_path):
    """Мутационная проверка: bare except / except Exception в чистом файле без
    per-file-ignore обязаны ловиться ruff'ом. Портим ИЗОЛИРОВАННУЮ временную
    копию (не рабочее дерево), чтобы не задеть код других воркеров.
    """
    probe_dir = tmp_path / "ruff_guard_probe"
    probe_dir.mkdir()
    (probe_dir / "pyproject.toml").write_text(
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    probe_file = probe_dir / "_ruff_guard_mutation_probe.py"
    probe_file.write_text(
        "def f():\n"
        "    try:\n"
        "        pass\n"
        "    except Exception:\n"
        "        pass\n"
        "    try:\n"
        "        pass\n"
        "    except:\n"
        "        pass\n",
        encoding="utf-8",
    )

    result = _run_ruff(str(probe_file), cwd=probe_dir)

    assert result.returncode != 0, "ruff обязан упасть на bare except + except Exception без ignore"
    assert "BLE001" in result.stdout
    assert "E722" in result.stdout


def test_per_file_ignore_files_still_need_it():
    """Точечная проверка: файлы из per-file-ignores реально содержат BLE001-нарушение
    (иначе ignore устарел и его пора снять по мере дочистки — issue #161).
    """
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "[tool.ruff.lint.per-file-ignores]" in pyproject

    ignored_files = ["codex_wrappers.py", "tests/conftest.py", "tests/test_dashboard_hotroutes.py"]
    for rel_path in ignored_files:
        assert rel_path in pyproject, f"{rel_path} упомянут в комментарии, но не в per-file-ignores"

    # Без per-file-ignores эти файлы обязаны падать на BLE001/E722 — иначе ignore мёртвый груз.
    result = _run_ruff(*ignored_files, "--select", "E722,BLE001", "--config", "per-file-ignores={}")
    assert result.returncode != 0, (
        "Ожидался хотя бы один BLE001/E722 в файлах из per-file-ignores без применения ignore — "
        "если тест падает здесь, значит файл уже дочищен и ignore пора снять"
    )
