"""ТДД-тесты srouter-managed claude-app wrapper (инцидент 2026-10-07).

Claude.app (чат + Dispatch) = Electron/Chromium: env HTTP(S)_PROXY Chromium-стек игнорирует
(эмпирия 2026-10-07: с env-прокси сокеты оставались прямыми) — нужен argv --proxy-server.
Плечо — HTTP privoxy 8118 (Claude-приложения на SOCKS5 ломаются, #127). До этого PR wrapper
жил руками в ~/bin/claude-app ВНЕ srouter → терялся при каждом перезапуске App из Dock
(дважды за день: 18:54 и повторно), doctor слеп. Контракт: install/remove по канону
codex-wrappers (marker-gate «чужое не трогать», atomic write, legacy-migration #112/#169),
template в launchagents/, прокси-URL из dashboard_common (anti-drift).
"""
import os
from pathlib import Path

import claude_wrappers
import install_lib


def _mock_home(monkeypatch, tmp_path):
    """Мок HOME → tmp/home (~/bin в tmp, не реальный ~)."""
    home = tmp_path / "home"
    home.mkdir()
    (home / "bin").mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    return home


def _env(tmp_path):
    """Минимальный InstallEnv: root=реальный репо (шаблоны launchagents/ оттуда)."""
    home = Path.home()  # monkeypatched _mock_home
    return install_lib.InstallEnv(
        root=Path(__file__).resolve().parent.parent,
        prefix=tmp_path / "homebrew",
        state_path=tmp_path / "srouter.local.json",
        launchagent_dir=home / "Library" / "LaunchAgents",
        python_bin="/usr/bin/python3",
        now="2026-10-07T00-00-00Z",
    )


def _fake_app_bin(monkeypatch, tmp_path):
    """Детерминированный «Claude.app» в tmp (машинонезависимо: реальный App может отсутствовать)."""
    fake = tmp_path / "Claude.app" / "Contents" / "MacOS" / "Claude"
    fake.parent.mkdir(parents=True)
    fake.write_text("#!/bin/true\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setattr(claude_wrappers, "_claude_app_bin", lambda: str(fake))
    return fake


def test_template_exists_with_marker_and_placeholders():
    root = Path(__file__).resolve().parent.parent
    tmpl = root / "launchagents" / claude_wrappers.CLAUDE_APP_TEMPLATE
    assert tmpl.exists(), f"template существует: {tmpl}"
    text = tmpl.read_text(encoding="utf-8")
    assert claude_wrappers.CLAUDE_APP_MARKER in text, "маркер managed-wrapper в template"
    for ph in ("__SROUTER_CLAUDE_APP_BIN__", "__SROUTER_CLAUDE_PROXY_URL__",
               "__SROUTER_CLAUDE_NO_PROXY__"):
        assert ph in text, f"placeholder {ph} в template"


def test_no_proxy_contract_loopback_and_zai():
    """NO_PROXY: loopback + z.ai (канон zai-direct-no-proxy — z.ai НЕ за прокси никогда)."""
    assert claude_wrappers.CLAUDE_NO_PROXY.startswith("localhost,127.0.0.1,::1")
    assert "z.ai" in claude_wrappers.CLAUDE_NO_PROXY
    assert ".z.ai" in claude_wrappers.CLAUDE_NO_PROXY


def test_default_app_bin_path():
    assert claude_wrappers._claude_app_bin().endswith(
        "/Applications/Claude.app/Contents/MacOS/Claude")


def test_app_bin_env_override(monkeypatch):
    monkeypatch.setenv("SROUTER_CLAUDE_APP_BIN", "/opt/Claude.app/Contents/MacOS/Claude")
    assert claude_wrappers._claude_app_bin() == "/opt/Claude.app/Contents/MacOS/Claude"


def test_install_creates_wrapper(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    _fake_app_bin(monkeypatch, tmp_path)

    note = claude_wrappers._install_claude_app_wrapper(env)

    w = home / "bin" / "claude-app"
    assert w.exists(), f"wrapper создан: {note}"
    assert "установ" in note.lower(), f"статус об успехе: {note}"
    text = w.read_text(encoding="utf-8")
    assert claude_wrappers.CLAUDE_APP_MARKER in text, "маркер managed-wrapper"
    assert os.access(w, os.X_OK), "executable"
    # ДВА механизма: env (Node-сторона) + --proxy-server (Chromium env игнорирует).
    assert "--proxy-server=" in text, "Chromium-стек: --proxy-server обязателен"
    assert "http://127.0.0.1:8118" in text, "плечо privoxy HTTP, НЕ SOCKS5 (#127)"
    assert "NO_PROXY" in text and "no_proxy" in text, "оба регистра"
    assert "--proxy-bypass-list" in text, "loopback мимо прокси"


def test_install_renders_proxy_from_source(monkeypatch, tmp_path):
    """anti-drift: прокси-URL рендерится из dashboard_common.HTTP_PROXY_URL, не хардкод (#96 канон)."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    _fake_app_bin(monkeypatch, tmp_path)
    monkeypatch.setattr(claude_wrappers, "_PROXY_URL", "http://10.9.9.9:9999")

    claude_wrappers._install_claude_app_wrapper(env)

    text = (home / "bin" / "claude-app").read_text(encoding="utf-8")
    assert "http://10.9.9.9:9999" in text, "рендер из источника"
    assert "127.0.0.1:8118" not in text, "старое значение не осталось"


def test_install_idempotent_overwrites_current_marker(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    _fake_app_bin(monkeypatch, tmp_path)
    claude_wrappers._install_claude_app_wrapper(env)
    (home / "bin" / "claude-app").write_text(
        claude_wrappers.CLAUDE_APP_MARKER + "\n# stale render\n", encoding="utf-8")

    note = claude_wrappers._install_claude_app_wrapper(env)

    assert "установ" in note.lower(), f"current-маркер → переустановка: {note}"
    assert "# stale render" not in (home / "bin" / "claude-app").read_text(encoding="utf-8")


def test_install_migrates_legacy_manual_wrapper(monkeypatch, tmp_path):
    """Существующий ручной ~/bin/claude-app (маркер первой версии «claude-app launcher») —
    наш: install МИГРИРУЕТ (перезаписывает current-маркером), а не отказывает как чужой.
    На живой машине этот файл уже стоит — отказ сломал бы adopt."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    _fake_app_bin(monkeypatch, tmp_path)
    (home / "bin" / "claude-app").write_text(
        "# srouter: claude-app launcher — явный env-прокси для Claude.app (managed).\n"
        "#!/bin/zsh\nexec true\n", encoding="utf-8")

    note = claude_wrappers._install_claude_app_wrapper(env)

    assert "установ" in note.lower(), f"legacy-маркер мигрирует: {note}"
    text = (home / "bin" / "claude-app").read_text(encoding="utf-8")
    assert claude_wrappers.CLAUDE_APP_MARKER in text, "current-маркер после миграции"
    assert "exec true" not in text, "старое тело заменено"


def test_install_marker_gate_foreign_not_touched(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    _fake_app_bin(monkeypatch, tmp_path)
    foreign = "# my own claude launcher\nexec /usr/bin/open -a Claude\n"
    (home / "bin" / "claude-app").write_text(foreign, encoding="utf-8")

    note = claude_wrappers._install_claude_app_wrapper(env)

    assert "не трогаем" in note.lower() or "чуж" in note.lower(), \
        f"unmarked → WARN, не перезаписывать: {note}"
    assert (home / "bin" / "claude-app").read_text(encoding="utf-8") == foreign


def test_install_refuses_when_app_missing(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    monkeypatch.setattr(claude_wrappers, "_claude_app_bin",
                        lambda: "/nonexistent/Claude.app/Contents/MacOS/Claude")

    note = claude_wrappers._install_claude_app_wrapper(env)

    assert "не установлен" in note.lower(), f"нет Claude.app → отказ: {note}"
    assert not (home / "bin" / "claude-app").exists()


def test_remove_ours_legacy_and_foreign(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    _fake_app_bin(monkeypatch, tmp_path)
    w = home / "bin" / "claude-app"
    # absent
    assert "не был установлен" in claude_wrappers._remove_claude_app_wrapper()
    # ours (current)
    claude_wrappers._install_claude_app_wrapper(env)
    assert "удалён" in claude_wrappers._remove_claude_app_wrapper()
    assert not w.exists()
    # legacy-marked — тоже наш
    w.write_text("# srouter: claude-app launcher — ...\nexec true\n", encoding="utf-8")
    assert "удалён" in claude_wrappers._remove_claude_app_wrapper()
    assert not w.exists()
    # foreign — не трогаем
    w.write_text("# чужой launcher\n", encoding="utf-8")
    note = claude_wrappers._remove_claude_app_wrapper()
    assert "не трогаем" in note.lower() or "чуж" in note.lower()
    assert w.exists()


def test_wired_into_install_uninstall_and_markers():
    """install/uninstall srouter_cli вызывают claude-wrapper, маркер регистрируется в
    known_markers (писатель без читателя/симметрии — класс ревью #403)."""
    import inspect
    import srouter_cli
    src = inspect.getsource(srouter_cli)
    assert "_install_claude_app_wrapper(" in src, "install вызывает claude-wrapper"
    assert "_remove_claude_app_wrapper(" in src, "uninstall снимает claude-wrapper"
    assert "CLAUDE_APP_MARKER" in src, "маркер в known_markers (migration-таблица #112)"
