"""ТДД-тесты health._gui_wrappers_check: семейство ~/bin-wrapper'ов под контролем доктора.

Инцидент-класс 2026-10-07 (Claude.app): wrapper жил руками вне srouter и терялся при
перезапуске из Dock — doctor молчал. PR #404 закрыл claude-app; аудит живой машины нашёл
ТОТ ЖЕ мутант у codex: ~/bin/codex-app-proxy, ~/bin/codex-srouter — СИМЛИНКИ на
agent-orchestrator/local/toolbox/... без srouter-маркера (install считает их «чужими —
не трогаем», переезд/снос той репы убьёт их висячими симлинками, doctor не заметит).

Контракт _gui_wrappers_check() — file-evidence по всему семейству:
  ok      — каждый wrapper: regular file, читается, несёт «наш» маркер, executable;
  warn    — перечислены конкретные проблемы (симлинк / dangling / не regular file / без
            маркера / не исполняется / отсутствует при установленном app) с рецептом;
  unknown — отсутствие при НЕустановленном app (install сам откажется ставить — опционально)
            или недоступные источники чека; info-only, не driver (ревью #405).

«Наш» маркер — паритет с install (#112): текущий + state known_markers['wrappers'] +
claude legacy (CLAUDE_APP_LEGACY_MARKERS) — doctor не зовёт «чужим» то, что install
мигрирует/удаляет как своё.
"""
import json
import os
import threading
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


def _codex_marker(name):
    """Маркер codex-wrapper'а по имени (не по позиции — порядок CODEX_WRAPPERS не контракт)."""
    return {n: m for n, _, m in codex_wrappers.CODEX_WRAPPERS}[name]


def _write_wrapper(home, name, marker, executable=True):
    p = home / "bin" / name
    p.write_text(f"{marker}\n#!/bin/zsh\nexec true\n", encoding="utf-8")
    p.chmod(0o755 if executable else 0o644)
    return p


def _mock_apps(monkeypatch, tmp_path, *, codex=True, claude=True):
    """App-present гейты (ревью #405): чек вызывает те же предикаты, что install."""
    monkeypatch.setattr(codex_wrappers, "_codex_bin_path",
                        lambda: "/opt/homebrew/bin/codex" if codex else "")
    if claude:
        claude_bin = tmp_path / "Claude.app"
        claude_bin.write_text("", encoding="utf-8")
    else:
        claude_bin = tmp_path / "no" / "Claude"
    monkeypatch.setattr(claude_wrappers, "_claude_app_bin", lambda: str(claude_bin))


def test_ok_when_all_family_managed(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    for name, _, marker in codex_wrappers.CODEX_WRAPPERS:
        _write_wrapper(home, name, marker)
    _write_wrapper(home, claude_wrappers.CLAUDE_APP_WRAPPER_NAME, claude_wrappers.CLAUDE_APP_MARKER)

    res = health._gui_wrappers_check()

    assert res["status"] == "ok", f"все marked/exec/regular → ok; got {res}"


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
    _write_wrapper(home, claude_wrappers.CLAUDE_APP_WRAPPER_NAME, claude_wrappers.CLAUDE_APP_MARKER)

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
    _write_wrapper(home, claude_wrappers.CLAUDE_APP_WRAPPER_NAME, claude_wrappers.CLAUDE_APP_MARKER)

    res = health._gui_wrappers_check()

    assert res["status"] == "warn", f"dangling симлинк → warn; got {res}"
    assert "codex-srouter" in res["detail"]


def test_warn_names_missing_wrapper(monkeypatch, tmp_path):
    """app установлен, wrapper отсутствует → warn «запусти srouter install» (чинится install'ом)."""
    home = _mock_home(monkeypatch, tmp_path)
    _write_wrapper(home, "codex-srouter", _codex_marker("codex-srouter"))
    _mock_apps(monkeypatch, tmp_path)

    res = health._gui_wrappers_check()

    assert res["status"] == "warn"
    for name in ("codex-app-proxy", claude_wrappers.CLAUDE_APP_WRAPPER_NAME):
        assert name in res["detail"], f"{name} отсутствует — должен быть назван; got {res}"


def test_missing_wrapper_app_absent_is_unknown(monkeypatch, tmp_path):
    """Ревью #405: app не установлен → install сам откажется ставить wrapper («codex binary
    не найден» / «Claude.app не найден»), рецепт невыполним. Отсутствие опционально →
    unknown (info-only), не вечный driver-degraded (канон #362/#403)."""
    _mock_home(monkeypatch, tmp_path)  # bin пуст
    _mock_apps(monkeypatch, tmp_path, codex=False, claude=False)

    res = health._gui_wrappers_check()

    assert res["status"] == "unknown", f"нет app → отсутствие опционально; got {res}"
    assert "опционален" in res["detail"], f"detail объясняет опциональность; got {res}"


def test_mixed_missing_warn_dominates_optional_absence(monkeypatch, tmp_path):
    """codex есть (wrapper'ов нет → warn), Claude.app нет (claude-app отсутствует опционально):
    реальные проблемы доминируют, optional-absence остаётся в detail (не теряется)."""
    _mock_home(monkeypatch, tmp_path)  # bin пуст
    _mock_apps(monkeypatch, tmp_path, codex=True, claude=False)

    res = health._gui_wrappers_check()

    assert res["status"] == "warn", f"отсутствующий wrapper при живом app — warn; got {res}"
    assert claude_wrappers.CLAUDE_APP_WRAPPER_NAME in res["detail"], \
        f"optional-absence назван в detail; got {res}"


def test_warn_names_unmarked_and_not_executable(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    foreign = home / "bin" / "codex-srouter"
    foreign.write_text("# my own\nexec true\n", encoding="utf-8")
    foreign.chmod(0o755)
    _write_wrapper(home, "codex-app-proxy", _codex_marker("codex-app-proxy"), executable=False)
    _write_wrapper(home, claude_wrappers.CLAUDE_APP_WRAPPER_NAME, claude_wrappers.CLAUDE_APP_MARKER)
    _mock_apps(monkeypatch, tmp_path)

    res = health._gui_wrappers_check()

    assert res["status"] == "warn"
    assert "маркер" in res["detail"].lower(), f"unmarked назван; got {res}"
    assert "исполня" in res["detail"].lower() or "chmod" in res["detail"].lower(), \
        f"not-executable назван; got {res}"


def test_fifo_does_not_hang_and_warns(monkeypatch, tmp_path):
    """Ревью #405: FIFO в ~/bin — exists() True, но read_text() блокируется навсегда
    (watchdog StartInterval=20 + /health + doctor зависают разом). Гейт is_file обязан
    дать вердикт: «не regular file» → warn."""
    home = _mock_home(monkeypatch, tmp_path)
    os.mkfifo(home / "bin" / "codex-srouter")
    for name, _, marker in codex_wrappers.CODEX_WRAPPERS:
        if name != "codex-srouter":
            _write_wrapper(home, name, marker)
    _write_wrapper(home, claude_wrappers.CLAUDE_APP_WRAPPER_NAME, claude_wrappers.CLAUDE_APP_MARKER)
    _mock_apps(monkeypatch, tmp_path)

    res = {}
    t = threading.Thread(target=lambda: res.update(health._gui_wrappers_check()), daemon=True)
    t.start()
    t.join(timeout=5)

    assert res, "чек завис на FIFO (нет вердикта за 5с) — read_text без is_file-гейта"
    assert res["status"] == "warn", f"FIFO → warn «не regular file»; got {res}"
    assert "codex-srouter" in res["detail"]


def test_legacy_claude_marker_is_ours(monkeypatch, tmp_path):
    """Ревью #405: legacy-маркер claude-app (CLAUDE_APP_LEGACY_MARKERS) — НАШ: install
    мигрирует его (_is_our_content), а не «чужой, удали вручную»."""
    home = _mock_home(monkeypatch, tmp_path)
    for name, _, marker in codex_wrappers.CODEX_WRAPPERS:
        _write_wrapper(home, name, marker)
    _write_wrapper(home, claude_wrappers.CLAUDE_APP_WRAPPER_NAME,
                   claude_wrappers.CLAUDE_APP_LEGACY_MARKERS[0])

    res = health._gui_wrappers_check()

    assert res["status"] == "ok", f"legacy-маркер = наш (install мигрирует); got {res}"


def test_state_known_marker_is_ours(monkeypatch, tmp_path):
    """Ревью #405: маркер из state known_markers['wrappers'] (таблица #112) install считает
    своим (_install_one_wrapper мигрирует) — doctor не зовёт его «чужим»."""
    home = _mock_home(monkeypatch, tmp_path)
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({
        "detected_environment": {"known_markers": {"wrappers": ["# srouter: codex OLD marker"]}}
    }), encoding="utf-8")
    monkeypatch.setenv("SROUTER_STATE_PATH", str(state_file))
    for name, _, marker in codex_wrappers.CODEX_WRAPPERS:
        _write_wrapper(home, name, marker)
    _write_wrapper(home, "codex-srouter", "# srouter: codex OLD marker")
    _write_wrapper(home, claude_wrappers.CLAUDE_APP_WRAPPER_NAME, claude_wrappers.CLAUDE_APP_MARKER)

    res = health._gui_wrappers_check()

    assert res["status"] == "ok", f"маркер из state-таблицы — наш; got {res}"


def test_lstat_race_does_not_raise(monkeypatch, tmp_path):
    """Ревью #405: fs-гонка (lstat бросил OSError) не вылетает из чека — контракт check_all
    «Не бросает» (health.py); соседние чеки имеют внешний except-shell."""
    home = _mock_home(monkeypatch, tmp_path)
    for name, _, marker in codex_wrappers.CODEX_WRAPPERS:
        _write_wrapper(home, name, marker)
    _write_wrapper(home, claude_wrappers.CLAUDE_APP_WRAPPER_NAME, claude_wrappers.CLAUDE_APP_MARKER)

    def _racy(self):
        raise OSError("lstat race (pytest)")

    monkeypatch.setattr(Path, "is_symlink", _racy)

    res = health._gui_wrappers_check()  # не бросает

    assert res["status"] == "warn", f"fs-ошибка → warn-вердикт, не исключение; got {res}"


def test_registered_in_health_namespace_and_check_all():
    """star-import re-export (#158) + чек включён в check_all (писатель без читателя — #403)."""
    assert callable(health._gui_wrappers_check)
    import inspect
    src = inspect.getsource(health)
    assert "_gui_wrappers_check" in src, "чек вызывается в check_all"
