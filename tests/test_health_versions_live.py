"""Живой (skip-if-no-brew) тест brew-cask ветки _scan_codex_binaries (issue #310).

Парный живой тест к замоканным (канон mock-format-must-come-from-live-capture): мок
_BREW_CASK_LIVE в test_health_versions.py захвачен с этой машины (/opt/homebrew/bin/brew
list --cask, Homebrew 6.0.20, 2026-09-04). Этот тест доказывает на ТЕКУЩЕМ установленном
Homebrew, что формат вывода не дрейфнул (по одному каску в строке, без пробелов) и что
предположение о layout Caskroom (артефакт каска codex — bin/codex (Binary), brew info
--cask codex) выполняется на реальной установке.
"""
import subprocess
from pathlib import Path

import pytest

import health

BREW = Path("/opt/homebrew/bin/brew")

pytestmark = pytest.mark.skipif(
    not BREW.is_file(),
    reason="Homebrew не установлен (канон skip-is-fine-in-tests)",
)


def _brew_list_cask():
    r = subprocess.run([str(BREW), "list", "--cask"], capture_output=True, timeout=15)
    assert r.returncode == 0, f"brew list --cask rc={r.returncode}: {r.stderr.decode()[:200]}"
    return r.stdout.decode()


def test_brew_cask_live_format_one_token_per_line():
    """Формат живого `brew list --cask`: по одному каску в строке, без пробелов/табов внутри
    строки (Homebrew 6.0.20, 2026-09-04). Дрейф формата = мок _BREW_CASK_LIVE устарел →
    тест падает и требует перезахвата (канон mock-format-must-come-from-live-capture)."""
    out = _brew_list_cask()
    lines = [l for l in out.splitlines() if l.strip()]
    if not lines:
        pytest.skip("brew list --cask пуст — касков нет, формат не проверить "
                    "(красный цвет зарезервирован за дрейфом формата)")
    bad = [l for l in lines if " " in l or "\t" in l]
    assert not bad, \
        f"формат дрейфнул (пробелы внутри строки): {bad[:3]!r} — перезахвати _BREW_CASK_LIVE"


def test_brew_cask_live_gate_and_caskroom_layout():
    """Гейт на живом списке + layout Caskroom: если каск codex установлен, гейт это видит
    (точная строка) И в Caskroom/codex/<версия>/bin/codex лежит исполняемый файл — то, что
    ищет шаг 5. На машине без каска проверяется только не-срабатывание (codexbar-сосед
    реален на dev-машине)."""
    out = _brew_list_cask()
    installed = health._cask_codex_installed(out)
    tokens = out.split()
    if "codex" in tokens:
        assert installed is True, "каск codex в списке → гейт True"
        cask_dir = Path("/opt/homebrew/Caskroom/codex")
        assert cask_dir.is_dir(), f"установленный каск обязан иметь {cask_dir}"
        exes = [d / "bin" / "codex" for d in cask_dir.iterdir()
                if d.is_dir() and (d / "bin" / "codex").is_file()]
        assert exes, \
            "layout-предположение шага 5 нарушено: нет Caskroom/codex/<ver>/bin/codex (артефакт 'bin/codex (Binary)' из brew info)"
    else:
        assert installed is False, \
            f"точного 'codex' в списке нет → гейт False (соседи вроде codexbar не матчатся), список: {tokens[:12]}"
