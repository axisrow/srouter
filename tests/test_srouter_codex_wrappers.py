"""ТДД-тесты srouter codex SOCKS5-wrappers + launchctl env (LaunchAgent plist) + PATH.

Codex (CLI + App) работает стабильно только через SOCKS5 (xray 10808) минуя privoxy (портит WS).
srouter install ставит ~/bin/codex + ~/bin/codex-app-proxy + LaunchAgent env-plist + ~/bin в PATH;
uninstall убирает. Канон — _install_ppp_hook/_remove_ppp_hook (best-effort, marker-gate «чужое не
трогать», строка-статус).
"""
import os
from pathlib import Path

import srouter


def _mock_home(monkeypatch, tmp_path):
    """Мок HOME → tmp/home (~/bin должен быть в tmp, не реальный ~)."""
    home = tmp_path / "home"
    home.mkdir()
    (home / "bin").mkdir()
    (home / "Library" / "LaunchAgents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: home)
    return home


def _env(tmp_path):
    """Минимальный InstallEnv: root=реальный репо (шаблоны launchagents/ оттуда)."""
    import install_lib
    return install_lib.InstallEnv(
        root=Path(__file__).resolve().parent.parent,
        prefix=tmp_path / "homebrew",
        state_path=tmp_path / "srouter.local.json",
        launchagent_dir=tmp_path / "LaunchAgents",
        python_bin="/usr/bin/python3",
        now="2026-07-04T00-00-00Z",
    )


def _markers():
    """Маркеры из CODEX_WRAPPERS: {name: marker}."""
    return {name: marker for name, _, marker in srouter.CODEX_WRAPPERS}


# ============================ _install/_remove_codex_wrappers ============================
def test_install_creates_wrappers(monkeypatch, tmp_path):
    """install ставит ~/bin/codex + ~/bin/codex-app-proxy с маркером + socks5h + executable."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    bin_dir = home / "bin"
    markers = _markers()

    note = srouter._install_codex_wrappers(env)

    assert "установ" in note.lower(), f"install должен éxito: {note}"
    for name, marker in markers.items():
        w = bin_dir / name
        assert w.exists(), f"~/bin/{name} создан"
        text = w.read_text(encoding="utf-8")
        assert marker in text, f"~/bin/{name} содержит srouter-маркер"
        assert os.access(w, os.X_OK), f"~/bin/{name} executable"
    # CLI wrapper: socks5h (DNS via proxy для GFW) + exec реального codex.
    cli_text = (bin_dir / "codex").read_text(encoding="utf-8")
    assert "socks5h://" in cli_text, "CLI использует socks5h (DNS via proxy)"
    assert "exec " in cli_text, "CLI exec'ает реальный codex"
    # App wrapper: --proxy-server (Chromium flag, env от install-plist не дублируется).
    app_text = (bin_dir / "codex-app-proxy").read_text(encoding="utf-8")
    assert "--proxy-server=socks5://" in app_text, "App передаёт Chromium --proxy-server"


def test_install_marker_gate_foreign_not_touched(monkeypatch, tmp_path):
    """Чужой ~/bin/codex (без маркера srouter) — НЕ перезаписывать."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    foreign = "# my custom codex wrapper\n#!/bin/sh\nexec /usr/local/bin/codex\n"
    (home / "bin" / "codex").write_text(foreign, encoding="utf-8")

    note = srouter._install_codex_wrappers(env)

    assert "чуж" in note.lower(), f"должен отказаться трогать чужой: {note}"
    assert (home / "bin" / "codex").read_text(encoding="utf-8") == foreign


def test_install_idempotent(monkeypatch, tmp_path):
    """Повторный install на srouter-managed wrapper — обновляет, не падает."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    srouter._install_codex_wrappers(env)
    first = (home / "bin" / "codex").read_text(encoding="utf-8")
    srouter._install_codex_wrappers(env)  # повторный
    second = (home / "bin" / "codex").read_text(encoding="utf-8")
    assert first == second, "повторный install = idempotent"


def test_remove_deletes_managed(monkeypatch, tmp_path):
    """uninstall удаляет wrappers если они srouter-managed."""
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_codex_wrappers(_env(tmp_path))
    assert (home / "bin" / "codex").exists()

    note = srouter._remove_codex_wrappers()

    assert "удалён" in note.lower()
    assert not (home / "bin" / "codex").exists()
    assert not (home / "bin" / "codex-app-proxy").exists()


def test_remove_marker_gate_foreign(monkeypatch, tmp_path):
    """Чужой wrapper (без маркера) — НЕ удалять."""
    home = _mock_home(monkeypatch, tmp_path)
    foreign = "# my custom\n#!/bin/sh\nexec codex\n"
    (home / "bin" / "codex").write_text(foreign, encoding="utf-8")

    note = srouter._remove_codex_wrappers()

    assert "чуж" in note.lower()
    assert (home / "bin" / "codex").read_text(encoding="utf-8") == foreign


# ============================ _install/_remove_launchctl_env (LaunchAgent plist) ============================
def test_install_launchctl_env_writes_plist_and_bootstraps(monkeypatch, tmp_path):
    """install пишет LaunchAgent plist с EnvironmentVariables (все proxy-ключи) + bootstrap его."""
    home = _mock_home(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(srouter, "run", lambda cmd, t: (calls.append(list(cmd)),
                                                         {"rc": 0, "out": "", "err": "", "timeout": False})[1])
    srouter._install_launchctl_env()

    plist = home / "Library" / "LaunchAgents" / srouter.CODEX_ENV_PLIST
    assert plist.exists(), "LaunchAgent plist создан"
    plist_text = plist.read_text(encoding="utf-8")
    assert srouter.CODEX_ENV_MARKER in plist_text, "plist содержит srouter-маркер"
    assert "EnvironmentVariables" in plist_text
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY"):
        assert f"<key>{key}</key>" in plist_text, f"plist содержит env-ключ {key}"
    assert "socks5h://" in plist_text, "plist содержит socks5h URL"
    # bootstrap вызван (загрузка plist в launchd).
    bootstraps = [c for c in calls if len(c) > 1 and c[1] == "bootstrap"]
    assert bootstraps, "launchctl bootstrap вызван"


def test_remove_launchctl_env_bootouts_and_unlinks(monkeypatch, tmp_path):
    """uninstall делает bootout + удаляет plist."""
    home = _mock_home(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(srouter, "run", lambda cmd, t: (calls.append(list(cmd)),
                                                         {"rc": 0, "out": "", "err": "", "timeout": False})[1])
    srouter._install_launchctl_env()  # ставим
    plist = home / "Library" / "LaunchAgents" / srouter.CODEX_ENV_PLIST
    assert plist.exists()

    srouter._remove_launchctl_env()

    assert not plist.exists(), "plist удалён"
    bootouts = [c for c in calls if len(c) > 1 and c[1] == "bootout"]
    assert bootouts, "launchctl bootout вызван"


def test_remove_launchctl_env_when_not_installed(monkeypatch, tmp_path):
    """Нечего удалять (plist нет) — мягкий статус, не ошибка."""
    _mock_home(monkeypatch, tmp_path)
    note = srouter._remove_launchctl_env()
    assert "не был" in note.lower()


# ============================ _ensure/_remove_home_bin_in_path ============================
def test_ensure_home_bin_in_path_adds(monkeypatch, tmp_path):
    """install добавляет export PATH=\"$HOME/bin:$PATH\" в ~/.zshrc если ещё нет."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    zshrc = home / ".zshrc"
    zshrc.write_text("export PATH=/usr/local/bin:$PATH\n", encoding="utf-8")

    srouter._ensure_home_bin_in_path(env)

    content = zshrc.read_text(encoding="utf-8")
    assert '$HOME/bin' in content, "PATH дополнен ~/bin"
    assert srouter.ZSHRC_PATH_MARKER in content, "маркер srouter рядом с правкой"


def test_ensure_home_bin_in_path_idempotent(monkeypatch, tmp_path):
    """Повторный install — НЕ дублирует."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    zshrc = home / ".zshrc"
    zshrc.write_text(f'export PATH="$HOME/bin:$PATH"\n{srouter.ZSHRC_PATH_MARKER}\n', encoding="utf-8")
    before = zshrc.read_text(encoding="utf-8")

    srouter._ensure_home_bin_in_path(env)

    assert zshrc.read_text(encoding="utf-8") == before, "idempotent"


def test_remove_home_bin_from_path_removes_block(monkeypatch, tmp_path):
    """uninstall убирает srouter-блок ~/bin из ~/.zshrc (симметрия install)."""
    home = _mock_home(monkeypatch, tmp_path)
    zshrc = home / ".zshrc"
    zshrc.write_text(
        f'export PATH=/usr/local/bin:$PATH\n\n{srouter.ZSHRC_PATH_MARKER}\nexport PATH="$HOME/bin:$PATH"\n',
        encoding="utf-8")

    srouter._remove_home_bin_from_path()

    content = zshrc.read_text(encoding="utf-8")
    assert srouter.ZSHRC_PATH_MARKER not in content, "маркер убран"
    assert 'export PATH="$HOME/bin:$PATH"' not in content, "srouter-строка PATH убрана"
    assert '/usr/local/bin' in content, "чужой export сохранён"


def test_remove_home_bin_when_not_modified(monkeypatch, tmp_path):
    """zshrc без srouter-маркера — не трогать."""
    home = _mock_home(monkeypatch, tmp_path)
    zshrc = home / ".zshrc"
    original = "export PATH=/usr/local/bin:$PATH\n"
    zshrc.write_text(original, encoding="utf-8")

    note = srouter._remove_home_bin_from_path()

    assert "не был" in note.lower()
    assert zshrc.read_text(encoding="utf-8") == original
