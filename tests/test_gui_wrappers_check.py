"""ТДД-тесты health._gui_wrappers_check: семейство ~/bin-wrapper'ов под контролем доктора.

Инцидент-класс 2026-10-07 (Claude.app): wrapper жил руками вне srouter и терялся при
перезапуске из Dock — doctor молчал. PR #404 закрыл claude-app; аудит живой машины нашёл
ТОТ ЖЕ мутант у codex: ~/bin/codex-app-proxy, ~/bin/codex-srouter — СИМЛИНКИ на
agent-orchestrator/local/toolbox/... без srouter-маркера (install считает их «чужими —
не трогаем», переезд/снос той репы убьёт их висячими симлинками, doctor не заметит).

Контракт _gui_wrappers_check() — file-evidence по всему семейству:
  ok   — каждый wrapper: regular file, читается, несёт свой srouter-маркер, executable;
  warn — перечислены конкретные проблемы (отсутствует / симлинк / dangling / без маркера /
         не исполняется) с рецептом («srouter install» / «удали и запусти srouter install»);
  unknown не существует: fs-чек всегда даёт вердикт (fail-open невозможен, «не смогли
  прочитать» — тоже проблема и попадает в warn).
"""
import os
from pathlib import Path

import claude_wrappers
import codex_wrappers
import health


def _mock_home(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / "bin").mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    return home


def _write_wrapper(home, name, marker, executable=True):
    p = home / "bin" / name
    p.write_text(f"{marker}\n#!/bin/zsh\nexec true\n", encoding="utf-8")
    p.chmod(0o755 if executable else 0o644)
    return p


def test_ok_when_all_family_managed(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    for name, _, marker in codex_wrappers.CODEX_WRAPPERS:
        _write_wrapper(home, name, marker)
    _write_wrapper(home, "claude-app", claude_wrappers.CLAUDE_APP_MARKER)

    res = health._gui_wrappers_check()

    assert res["status"] == "ok", f"все маркерed/exec/regular → ok; got {res}"


def test_warn_names_unmanaged_symlink(monkeypatch, tmp_path):
    """Живой профиль машины: codex-симлинки в чужую репо без маркера → warn с путём цели."""
    home = _mock_home(monkeypatch, tmp_path)
    target = tmp_path / "foreign-repo" / "codex-app-proxy"
    target.parent.mkdir(parents=True)
    target.write_text("#!/bin/zsh\nexec true\n", encoding="utf-8")
    (home / "bin" / "codex-app-proxy").symlink_to(target)
    for name, _, marker in codex_wrappers.CODEX_WRAPPERS:
        if name != "codex-app-proxy":
            _write_wrapper(home, name, marker)
    _write_wrapper(home, "claude-app", claude_wrappers.CLAUDE_APP_MARKER)

    res = health._gui_wrappers_check()

    assert res["status"] == "warn", f"симлинк без маркера → warn; got {res}"
    assert "codex-app-proxy" in res["detail"]
    assert "симлинк" in res["detail"].lower(), f"detail называет симлинк; got {res}"
    assert str(target) in res["detail"], f"detail показывает цель симлинка; got {res}"


def test_warn_names_dangling_symlink(monkeypatch, tmp_path):
    """Висячий симлинк (цель снесена) — warn, не ok (канон переезда репо)."""
    home = _mock_home(monkeypatch, tmp_path)
    (home / "bin" / "codex-srouter").symlink_to(tmp_path / "gone" / "codex-srouter")
    for name, _, marker in codex_wrappers.CODEX_WRAPPERS:
        if name != "codex-srouter":
            _write_wrapper(home, name, marker)
    _write_wrapper(home, "claude-app", claude_wrappers.CLAUDE_APP_MARKER)

    res = health._gui_wrappers_check()

    assert res["status"] == "warn", f"dangling симлинк → warn; got {res}"
    assert "codex-srouter" in res["detail"]


def test_warn_names_missing_wrapper(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    _write_wrapper(home, "codex-srouter", codex_wrappers.CODEX_WRAPPERS[0][2])

    res = health._gui_wrappers_check()

    assert res["status"] == "warn"
    for name in ("codex-app-proxy", "claude-app"):
        assert name in res["detail"], f"{name} отсутствует — должен быть назван; got {res}"


def test_warn_names_unmarked_and_not_executable(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    foreign = home / "bin" / "codex-srouter"
    foreign.write_text("# my own\nexec true\n", encoding="utf-8")
    foreign.chmod(0o755)
    _write_wrapper(home, "codex-app-proxy", codex_wrappers.CODEX_WRAPPERS[1][2],
                   executable=False)
    _write_wrapper(home, "claude-app", claude_wrappers.CLAUDE_APP_MARKER)

    res = health._gui_wrappers_check()

    assert res["status"] == "warn"
    assert "маркер" in res["detail"].lower(), f"unmarked назван; got {res}"
    assert "исполня" in res["detail"].lower() or "chmod" in res["detail"].lower(), \
        f"not-executable назван; got {res}"


def test_family_parity_with_sources():
    """Локальный список семейства не отстаёт от источников (канон #340 parity-гварда:
    прямой import codex_wrappers в health_codenv создал бы цикл — список локальный,
    поэтому рассинхрон ловит только тест)."""
    import health_codenv
    family = {name: marker for name, marker in health_codenv._GUI_WRAPPER_FAMILY}
    for name, _, marker in codex_wrappers.CODEX_WRAPPERS:
        assert family.get(name) == marker, f"{name} выпал/разошёлся с CODEX_WRAPPERS"
    assert family.get("claude-app") == claude_wrappers.CLAUDE_APP_MARKER, \
        "claude-app выпал/разошёлся с CLAUDE_APP_MARKER"


def test_registered_in_health_namespace_and_check_all():
    """star-import re-export (#158) + чек включён в check_all (писатель без читателя — #403)."""
    assert callable(health._gui_wrappers_check)
    import inspect
    src = inspect.getsource(health)
    assert "_gui_wrappers_check" in src, "чек вызывается в check_all"
