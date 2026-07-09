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
    """Минимальный InstallEnv: root=реальный репо (шаблоны launchagents/ оттуда).
    launchagent_dir = home/Library/LaunchAgents (как прод) — _install_launchctl_env пишет туда,
    _remove_launchctl_env ищет там же; путь должен совпадать."""
    home = Path.home()  # monkeypatched _mock_home
    import install_lib
    return install_lib.InstallEnv(
        root=Path(__file__).resolve().parent.parent,
        prefix=tmp_path / "homebrew",
        state_path=tmp_path / "srouter.local.json",
        launchagent_dir=home / "Library" / "LaunchAgents",
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


# ============================ _install/_remove_launchctl_env (LaunchAgent com.srouter.codenv) ============================
def _fake_runner():
    """Фейк runner (как make_privileged_runner) — собирает вызовы, всегда успех."""
    calls = []
    def runner(cmd, timeout):
        calls.append(list(cmd))
        return {"rc": 0, "out": "", "err": "", "timeout": False}
    runner.calls = calls
    return runner


def test_install_launchctl_env_writes_plist(monkeypatch, tmp_path):
    """install пишет LaunchAgent com.srouter.codenv (через _install_generic_launchagent) + bootstrap."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    runner = _fake_runner()

    note = srouter._install_launchctl_env(env, runner)

    assert "загружен" in note, f"install должен éxito: {note}"
    plist = home / "Library" / "LaunchAgents" / f"{srouter.CODEX_ENV_LABEL}.plist"
    assert plist.exists(), "plist создан"
    plist_text = plist.read_text(encoding="utf-8")
    assert srouter.CODEX_ENV_MARKER in plist_text, "plist содержит srouter-маркер"
    # Шаблон рендерит label + путь к скрипту setenv.
    assert srouter.CODEX_ENV_LABEL in plist_text
    assert "srouter-codex-env.sh" in plist_text
    # bootstrap вызван (_launchd_reload).
    assert any(len(c) > 1 and c[1] == "bootstrap" for c in runner.calls), "bootstrap вызван"


def test_install_launchctl_env_marker_gate_foreign(monkeypatch, tmp_path):
    """Чужой plist com.srouter.codenv (без маркера srouter) — НЕ перезаписывать."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    runner = _fake_runner()
    plist = home / "Library" / "LaunchAgents" / f"{srouter.CODEX_ENV_LABEL}.plist"
    plist.parent.mkdir(parents=True, exist_ok=True)
    foreign = "<?xml version='1.0'?><plist version='1.0'><dict><key>Label</key><string>other</string></dict></plist>"
    plist.write_text(foreign, encoding="utf-8")

    note = srouter._install_launchctl_env(env, runner)

    assert "чуж" in note.lower(), f"должен отказаться трогать чужой plist: {note}"
    assert plist.read_text(encoding="utf-8") == foreign, "чужой plist не перезаписан"


def test_remove_launchctl_env_bootouts_and_unlinks(monkeypatch, tmp_path):
    """uninstall делает bootout + unsetenv + удаляет plist."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    runner = _fake_runner()
    srouter._install_launchctl_env(env, runner)
    plist = home / "Library" / "LaunchAgents" / f"{srouter.CODEX_ENV_LABEL}.plist"
    assert plist.exists()

    note = srouter._remove_launchctl_env(runner)

    assert "снят" in note.lower()
    assert not plist.exists(), "plist удалён"
    assert any(len(c) > 1 and c[1] == "bootout" for c in runner.calls), "bootout вызван"
    # unsetenv для всех proxy-ключей (env ставил скрипт setenv при загрузке).
    unsetenvs = {c[2] for c in runner.calls if len(c) > 1 and c[1] == "unsetenv"}
    assert {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"} <= unsetenvs


def test_remove_launchctl_env_marker_gate_foreign(monkeypatch, tmp_path):
    """Чужой plist (без маркера) — НЕ удалять."""
    home = _mock_home(monkeypatch, tmp_path)
    runner = _fake_runner()
    plist = home / "Library" / "LaunchAgents" / f"{srouter.CODEX_ENV_LABEL}.plist"
    plist.parent.mkdir(parents=True, exist_ok=True)
    foreign = "<?xml version='1.0'?><plist version='1.0'><dict/>"
    plist.write_text(foreign, encoding="utf-8")

    note = srouter._remove_launchctl_env(runner)

    assert "чуж" in note.lower()
    assert plist.exists(), "чужой plist не удалён"


def test_remove_launchctl_env_when_not_installed(monkeypatch, tmp_path):
    """Нечего удалять (plist нет) — мягкий статус, не ошибка."""
    _mock_home(monkeypatch, tmp_path)
    note = srouter._remove_launchctl_env(_fake_runner())
    assert "не был" in note.lower()


def _list_runner(list_states):
    """runner с list-диспетчеризацией по CODEX_ENV_LABEL (canned _fake_runner list→out='' не доходит
    до fail-safe). list_states: [True/False/None,...] на каждый вызов list; None → timeout."""
    calls = []
    state = {"i": 0}

    def runner(cmd, timeout):
        calls.append(list(cmd))
        sub = cmd[1] if len(cmd) > 1 else ""
        if sub == "list":
            idx = min(state["i"], len(list_states) - 1)
            state["i"] += 1
            loaded = list_states[idx]
            if loaded is None:
                return {"rc": None, "out": "", "err": "timeout", "timeout": True}
            out = (srouter.CODEX_ENV_LABEL + "\n") if loaded else ""
            return {"rc": 0, "out": out, "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    runner.calls = calls
    return runner


def test_remove_launchctl_env_keeps_plist_when_still_loaded(monkeypatch, tmp_path):
    """Сайт C fail-safe (PR #83 cycle-3): агент ещё загружен после settle → plist ОСТАВЛЕН, нет unsetenv.

    poll живёт в install_lib → патчим install_lib._BOOTOUT_*. settle≈0 (иначе poll крутил бы 2с),
    list всегда True → state=True. Сообщение бит-в-бит: «всё ещё загружен» + «plist оставлен».
    """
    import install_lib
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_lib, "_BOOTOUT_SETTLE_MAX_WAIT", 0)
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_launchctl_env(_env(tmp_path), _fake_runner())
    plist = home / "Library" / "LaunchAgents" / f"{srouter.CODEX_ENV_LABEL}.plist"
    assert plist.exists()
    runner = _list_runner([True] * 6)  # не выгружается

    note = srouter._remove_launchctl_env(runner)

    assert "всё ещё загружен" in note, f"True → «всё ещё загружен»: {note}"
    assert "plist оставлен" in note
    assert plist.exists(), "агент ещё загружен → plist оставлен (fail-safe)"
    assert not any(len(c) > 1 and c[1] == "unsetenv" for c in runner.calls), \
        "не выгружен → env НЕ очищаем (unsetenv не вызывается)"


def test_remove_launchctl_env_keeps_plist_when_list_timeout(monkeypatch, tmp_path):
    """Сайт C: list timeout (None) → tristate-различие: «не подтверждена выгрузка», plist оставлен.

    Тест бит-в-бит различия None vs True. None короткозамыкает poll (`while state and …`).
    """
    import install_lib
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_launchctl_env(_env(tmp_path), _fake_runner())
    plist = home / "Library" / "LaunchAgents" / f"{srouter.CODEX_ENV_LABEL}.plist"
    assert plist.exists()
    runner = _list_runner([None])  # list timeout → state=None

    note = srouter._remove_launchctl_env(runner)

    assert "не подтверждена выгрузка" in note, f"None → «не подтверждена выгрузка»: {note}"
    assert "plist оставлен" in note
    assert plist.exists(), "list timeout (неизвестно) → plist оставлен (fail-safe)"
    assert not any(len(c) > 1 and c[1] == "unsetenv" for c in runner.calls)


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


def test_ensure_then_remove_no_dangling_export_new_zshrc(monkeypatch, tmp_path):
    """Regression (cycle 2): ~/.zshrc НЕ существовал → install создал → uninstall убрал блок.

    Раньше new-file путь писал export ПЕРЕД marker (инвертировано vs append) → _remove_home_bin_from_path
    (удаляет marker + следующую строку) оставлял висячий export PATH="$HOME/bin:$PATH". Чистая установка
    без .zshrc — частый случай. Теперь порядок marker→export на обоих путях.
    """
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    zshrc = home / ".zshrc"
    assert not zshrc.exists()

    srouter._ensure_home_bin_in_path(env)  # создаёт .zshrc с нуля
    assert zshrc.exists()
    srouter._remove_home_bin_from_path()   # должен убрать блок полностью

    content = zshrc.read_text(encoding="utf-8")
    assert srouter.ZSHRC_PATH_MARKER not in content, "маркер убран"
    assert 'export PATH="$HOME/bin:$PATH"' not in content, "висячий export НЕ остался (regression)"
    assert content.strip() == "", "чистая установка → пустой .zshrc после uninstall"


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


def test_remove_home_bin_keeps_foreign_home_bin_export(monkeypatch, tmp_path):
    """Regression (cycle-review): чужой `export PATH="$HOME/bin:..."` в ДРУГОМ месте файла — НЕ удалять.

    Раньше _remove_home_bin_from_path удалял ВСЕ строки `export PATH="$HOME/bin:$PATH"`, даже чужие.
    Теперь удаляет только управляемый блок (маркер + следующая строка).
    """
    home = _mock_home(monkeypatch, tmp_path)
    zshrc = home / ".zshrc"
    # Чужой export PATH="$HOME/bin:..." в начале + наш блок ниже.
    zshrc.write_text(
        'export PATH="$HOME/bin:$PATH"\n'  # ЧУЖОЙ — должен остаться
        f'# user custom\n{srouter.ZSHRC_PATH_MARKER}\nexport PATH="$HOME/bin:$PATH"\n',
        encoding="utf-8")

    srouter._remove_home_bin_from_path()

    content = zshrc.read_text(encoding="utf-8")
    assert srouter.ZSHRC_PATH_MARKER not in content, "наш маркер убран"
    # ЧУЖОЙ export в начале — остался (считаем количество: был 2, стал 1 — только чужой).
    assert content.count('export PATH="$HOME/bin:$PATH"') == 1, \
        "чужой export сохранён, наш убран"


def test_remove_home_bin_when_not_modified(monkeypatch, tmp_path):
    """zshrc без srouter-маркера — не трогать."""
    home = _mock_home(monkeypatch, tmp_path)
    zshrc = home / ".zshrc"
    original = "export PATH=/usr/local/bin:$PATH\n"
    zshrc.write_text(original, encoding="utf-8")

    note = srouter._remove_home_bin_from_path()

    assert "не был" in note.lower()
    assert zshrc.read_text(encoding="utf-8") == original
