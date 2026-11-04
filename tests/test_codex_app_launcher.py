"""ТДД-тесты ChatGPT.app Dock-launcher (managed) — codex_app_launcher.py.

Контракт владельца (2026-11-05): ChatGPT.app = группа Claude.app — только 10808, никогда
direct. Dock не передаёт --proxy-server; при NE-VPN primary (HitVPN/VeePN ephemeral)
scutil-снапшот пуст и Chromium уходит direct. Запуск из Dock обязан идти через
~/bin/codex-app-proxy: launcher .app-bundle в ~/Applications (скрипт с srouter-маркером,
exec codex-app-proxy) + подмена Dock-тайла (defaults export/write com.apple.dock
persistent-others + killall Dock). Uninstall обратимо возвращает исходный тайл из state.

Живой Dock и процессы в тестах НЕ мутируются: defaults/killall — fake-runner с canned
export-XML и захватом write-команд (канон mock-format-must-come-from-live-capture — формат
export-XML снят с живого `defaults export com.apple.dock -`).
"""
import inspect
import os
import plistlib
from pathlib import Path
from urllib.parse import quote

import codex_app_launcher as cal
import install_lib
import local_state


def _mock_home(monkeypatch, tmp_path):
    """Мок HOME → tmp/home: ~/Applications в tmp, не реальный ~."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    return home


def _env(tmp_path):
    return install_lib.InstallEnv(
        root=Path(__file__).resolve().parent.parent,
        prefix=tmp_path / "homebrew",
        state_path=tmp_path / "srouter.local.json",
        launchagent_dir=Path.home() / "Library" / "LaunchAgents",
        python_bin="/usr/bin/python3",
        now="2026-11-05T00-00-00Z",
    )


def _stub_app(monkeypatch, tmp_path):
    """Детерминированный «ChatGPT.app» в tmp (машинонезависимо: реальный App может
    отсутствовать). Override — SROUTER_CODEX_APP_BUNDLE (канон «больше опций»)."""
    app = tmp_path / "apps" / "ChatGPT.app"
    (app / "Contents" / "MacOS").mkdir(parents=True)
    exe = app / "Contents" / "MacOS" / "ChatGPT"
    exe.write_text("#!/bin/true\n", encoding="utf-8")
    exe.chmod(0o755)
    monkeypatch.setenv("SROUTER_CODEX_APP_BUNDLE", str(app))
    return app


def _dock_tile(app_path, *, launcher_path=None):
    """Тайл Dock в форме живого export (file:// URL, _CFURLStringType 15)."""
    target = launcher_path or app_path
    return {"GUID": "11111111",
            "tile-data": {"file-label": "ChatGPT",
                          "file-data": {"_CFURLString": f"file://{quote(str(target))}/",
                                        "_CFURLStringType": 15}}}


def _dock_export(tiles):
    return plistlib.dumps({"persistent-others": list(tiles)}, sort_keys=False).decode()


def _fake_dock_runner(export_xml, captured):
    """Fake sys_probe.run: defaults export → canned XML; defaults write / killall → capture."""
    def run(cmd, timeout=3):
        if cmd[:2] == ["/usr/bin/defaults", "export"]:
            return {"rc": 0, "out": export_xml, "err": "", "timeout": False}
        if cmd[:2] == ["/usr/bin/defaults", "write"]:
            captured["writes"].append(cmd)
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        if cmd[:1] == ["/usr/bin/killall"]:
            captured["killall"] += 1
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}
    return run


def _state_section(state_path):
    state = local_state.load_state(path=state_path)
    return (state.get("runtime") or {}).get(cal.LAUNCHER_STATE_KEY)


# ============================== install ==============================

def test_install_creates_launcher_bundle(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    app = _stub_app(monkeypatch, tmp_path)

    note = cal.install_launcher(_env(tmp_path), runner=_fake_dock_runner(
        _dock_export([_dock_tile(app)]), {"writes": [], "killall": 0}))

    bundle = home / "Applications" / "ChatGPT (srouter).app"
    script = bundle / "Contents" / "MacOS" / "ChatGPT (srouter)"
    assert script.exists(), f"launcher-скрипт создан: {note}"
    assert os.access(script, os.X_OK), "executable"
    body = script.read_text(encoding="utf-8")
    assert cal.LAUNCHER_MARKER in body, "маркер managed-launcher в скрипте"
    assert "codex-app-proxy" in body, "launcher вызывает codex-app-proxy"
    info = plistlib.loads((bundle / "Contents" / "Info.plist").read_bytes())
    assert info["CFBundleIdentifier"] == cal.LAUNCHER_BUNDLE_ID
    assert info["CFBundleExecutable"] == "ChatGPT (srouter)"
    assert "установ" in note.lower(), f"статус об успехе: {note}"


def test_install_refuses_when_no_app(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    monkeypatch.delenv("SROUTER_CODEX_APP_BUNDLE", raising=False)
    # Машинонезависимость: реальные /Applications/ChatGPT.app|Codex.app на живой машине
    # существуют — гасим дефолтные кандидаты (прецедент test_app_bin_env_override).
    monkeypatch.setattr(cal, "_APP_CANDIDATES",
                        (str(tmp_path / "nope" / "ChatGPT.app"),))

    note = cal.install_launcher(_env(tmp_path), runner=_fake_dock_runner(
        _dock_export([]), {"writes": [], "killall": 0}))

    assert "не установлен" in note.lower(), f"нет App → отказ: {note}"
    assert not (home / "Applications" / "ChatGPT (srouter).app").exists()


def test_install_marker_gate_foreign(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    _stub_app(monkeypatch, tmp_path)
    foreign_script = (home / "Applications" / "ChatGPT (srouter).app"
                      / "Contents" / "MacOS" / "ChatGPT (srouter)")
    foreign_script.parent.mkdir(parents=True)
    foreign_script.write_text("# my own launcher\nexec true\n", encoding="utf-8")

    note = cal.install_launcher(_env(tmp_path), runner=_fake_dock_runner(
        _dock_export([]), {"writes": [], "killall": 0}))

    assert "не трогаем" in note.lower() or "чуж" in note.lower(), \
        f"unmarked launcher → отказ, не adopt: {note}"
    assert foreign_script.read_text(encoding="utf-8") == "# my own launcher\nexec true\n"


def test_install_idempotent_overwrites_ours(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    _stub_app(monkeypatch, tmp_path)
    runner = _fake_dock_runner(_dock_export([]), {"writes": [], "killall": 0})
    cal.install_launcher(_env(tmp_path), runner=runner)
    script = (home / "Applications" / "ChatGPT (srouter).app"
              / "Contents" / "MacOS" / "ChatGPT (srouter)")
    script.write_text(cal.LAUNCHER_MARKER + "\n# stale render\n", encoding="utf-8")

    note = cal.install_launcher(_env(tmp_path), runner=runner)

    assert "установ" in note.lower(), f"current-маркер → переустановка: {note}"
    assert "# stale render" not in script.read_text(encoding="utf-8")


# ============================== Dock-swap ==============================

def test_dock_swap_replaces_tile_and_backs_up(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    app = _stub_app(monkeypatch, tmp_path)
    captured = {"writes": [], "killall": 0}
    runner = _fake_dock_runner(_dock_export([_dock_tile(app)]), captured)

    note = cal.install_launcher(_env(tmp_path), runner=runner)

    assert len(captured["writes"]) == 1, f"один defaults write persistent-others: {captured}"
    assert captured["killall"] == 1, "killall Dock после подмены"
    written = plistlib.loads(captured["writes"][0][-1].encode())
    launcher = home / "Applications" / "ChatGPT (srouter).app"
    tile = written["persistent-others"][0]
    assert quote(str(launcher)) in tile["tile-data"]["file-data"]["_CFURLString"], \
        f"тайл указывает на launcher: {tile}"
    section = _state_section(_env(tmp_path).state_path)
    assert section and section.get("phase") == "active", f"state phase=active: {section}"
    saved = cal._decode_tile(section["tile_b64"])
    assert saved["tile-data"]["file-data"]["_CFURLString"] == \
        f"file://{quote(str(app))}/", f"исходный тайл сохранён в state: {section}"
    assert "Dock" in note, f"note называет подмену Dock: {note}"


def test_dock_swap_preflight_state_written_before_mutation(monkeypatch, tmp_path):
    """Two-phase (канон AGENTS.md): pending-фаза + исходный тайл на диске ДО defaults write —
    crash посреди мутации оставляет backup, а не «Dock изменён, откат нигде»."""
    home = _mock_home(monkeypatch, tmp_path)
    app = _stub_app(monkeypatch, tmp_path)
    env = _env(tmp_path)
    seen = {}

    def spying_run(cmd, timeout=3):
        if cmd[:2] == ["/usr/bin/defaults", "write"]:
            seen["at_write"] = _state_section(env.state_path)
        return _fake_dock_runner(_dock_export([_dock_tile(app)]), {"writes": [], "killall": 0})(cmd, timeout)

    cal.install_launcher(env, runner=spying_run)

    assert seen.get("at_write"), "state-секция существовала на момент defaults write"
    assert seen["at_write"].get("phase") == "swapping", \
        f"preflight-фаза swapping ДО мутации: {seen['at_write']}"
    assert cal._decode_tile(seen["at_write"]["tile_b64"]), "исходный тайл в preflight-записи"


def test_dock_swap_survives_bytes_book_field(monkeypatch, tmp_path):
    """Живой тайл Dock несёт book как plist data (bytes, снято с defaults export):
    json.dump на bytes = TypeError → _save_swap False → подмена отменялась «state не
    записывается» на КАЖДОМ install (str-only мок этого не ловил, ревью #457).
    Тайл хранится byte-exact: base64(plistlib.dumps(tile)) + plistlib.loads при restore."""
    home = _mock_home(monkeypatch, tmp_path)
    app = _stub_app(monkeypatch, tmp_path)
    env = _env(tmp_path)
    tile = _dock_tile(app)
    book = b"\x62\x6f\x6f\x6b-binary-\xff\xfe"
    tile["tile-data"]["book"] = book
    captured = {"writes": [], "killall": 0}

    note = cal.install_launcher(env, runner=_fake_dock_runner(_dock_export([tile]), captured))

    assert "подменён" in note.lower(), \
        f"bytes в тайле не отменяют подмену (не «state не записывается»): {note}"
    section = _state_section(env.state_path)
    assert isinstance(section.get("tile_b64"), str), f"тайл в state как base64: {section.keys()}"
    decoded = cal._decode_tile(section["tile_b64"])
    assert decoded["tile-data"]["book"] == book, "тайл byte-exact"
    assert decoded["tile-data"]["file-data"]["_CFURLString"] == \
        tile["tile-data"]["file-data"]["_CFURLString"]
    # restore: bytes возвращаются в тайле без искажения
    launcher = home / "Applications" / "ChatGPT (srouter).app"
    captured["writes"].clear()
    cal.uninstall_launcher(env, runner=_fake_dock_runner(
        _dock_export([_dock_tile(app, launcher_path=launcher)]), captured))
    written = plistlib.loads(captured["writes"][-1][-1].encode())
    assert written["persistent-others"][0]["tile-data"]["book"] == book, \
        "restore возвращает book byte-exact"


def test_install_without_dock_tile_notes_manual_step(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    _stub_app(monkeypatch, tmp_path)
    captured = {"writes": [], "killall": 0}

    note = cal.install_launcher(_env(tmp_path), runner=_fake_dock_runner(
        _dock_export([]), captured))

    assert not captured["writes"] and not captured["killall"], \
        f"тайла нет — Dock не мутируем: {captured}"
    assert (home / "Applications" / "ChatGPT (srouter).app").exists(), \
        "launcher установлен и без тайла"
    assert "вручную" in note.lower() or "не найден" in note.lower(), \
        f"note называет ручной шаг: {note}"


def test_dock_swap_defaults_read_failure_no_mutation(monkeypatch, tmp_path):
    """defaults export не ответил → отказ без мутаций (fail-closed): подменять вслепую нельзя."""
    _mock_home(monkeypatch, tmp_path)
    _stub_app(monkeypatch, tmp_path)
    captured = {"writes": [], "killall": 0}

    def failing_run(cmd, timeout=3):
        if cmd[:2] == ["/usr/bin/defaults", "export"]:
            return {"rc": None, "out": "", "err": "timeout", "timeout": True}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    note = cal.install_launcher(_env(tmp_path), runner=failing_run)
    assert not captured["writes"] and not captured["killall"]
    assert "не прочитан" in note.lower() or "dock" in note.lower(), f"note о сбое: {note}"


# ============================== uninstall ==============================

def test_uninstall_restores_original_tile(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    app = _stub_app(monkeypatch, tmp_path)
    env = _env(tmp_path)
    captured = {"writes": [], "killall": 0}
    cal.install_launcher(env, runner=_fake_dock_runner(_dock_export([_dock_tile(app)]), captured))
    captured["writes"].clear()

    note, ok = cal.uninstall_launcher(env, runner=_fake_dock_runner(
        _dock_export([_dock_tile(app, launcher_path=home / "Applications" / "ChatGPT (srouter).app")]),
        captured))

    assert ok, f"uninstall успешен: {note}"
    assert len(captured["writes"]) == 1, f"один write при откате: {captured}"
    written = plistlib.loads(captured["writes"][0][-1].encode())
    tile = written["persistent-others"][0]
    assert tile["tile-data"]["file-data"]["_CFURLString"] == f"file://{quote(str(app))}/", \
        f"исходный тайл возвращён: {tile}"
    assert captured["killall"] >= 1, "killall Dock после отката"
    assert not (home / "Applications" / "ChatGPT (srouter).app").exists(), "launcher удалён"
    assert _state_section(env.state_path) is None, "state-секция расчищена"
    assert "возвращ" in note.lower() or "восстанов" in note.lower(), f"note об откате: {note}"


def test_uninstall_preflight_restoring_phase(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    app = _stub_app(monkeypatch, tmp_path)
    env = _env(tmp_path)
    launcher = home / "Applications" / "ChatGPT (srouter).app"
    cal.install_launcher(env, runner=_fake_dock_runner(
        _dock_export([_dock_tile(app)]), {"writes": [], "killall": 0}))
    seen = {}

    def spying_run(cmd, timeout=3):
        if cmd[:2] == ["/usr/bin/defaults", "write"] and "at_write" not in seen:
            seen["at_write"] = _state_section(env.state_path)
        return _fake_dock_runner(
            _dock_export([_dock_tile(app, launcher_path=launcher)]), {"writes": [], "killall": 0}
        )(cmd, timeout)

    cal.uninstall_launcher(env, runner=spying_run)
    assert seen.get("at_write"), "write-откат был"
    assert seen["at_write"].get("phase") == "restoring", \
        f"preflight restoring ДО мутации отката: {seen['at_write']}"
    assert cal._decode_tile(seen["at_write"]["tile_b64"]), "исходный тайл ещё в state"


def test_uninstall_without_state_backup_removes_ours(monkeypatch, tmp_path):
    """Нет backup тайла (ставили до инициализации state / секция потеряна) — launcher наш
    по маркеру → удалить, тайл честно «не возвращён» (не молчаливый успех)."""
    home = _mock_home(monkeypatch, tmp_path)
    _stub_app(monkeypatch, tmp_path)
    env = _env(tmp_path)
    cal.install_launcher(env, runner=_fake_dock_runner(
        _dock_export([]), {"writes": [], "killall": 0}))

    note, ok = cal.uninstall_launcher(env, runner=_fake_dock_runner(
        _dock_export([]), {"writes": [], "killall": 0}))

    assert ok, f"launcher удалён — успех: {note}"
    assert not (home / "Applications" / "ChatGPT (srouter).app").exists(), "launcher удалён"
    assert "не возвращ" in note.lower() or "нет сохранённого" in note.lower(), \
        f"note честно про тайл: {note}"


def test_uninstall_foreign_launcher_not_touched(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    _stub_app(monkeypatch, tmp_path)
    foreign = (home / "Applications" / "ChatGPT (srouter).app"
               / "Contents" / "MacOS" / "ChatGPT (srouter)")
    foreign.parent.mkdir(parents=True)
    foreign.write_text("# чужой launcher\nexec true\n", encoding="utf-8")

    note, ok = cal.uninstall_launcher(_env(tmp_path), runner=_fake_dock_runner(
        _dock_export([]), {"writes": [], "killall": 0}))

    assert ok, f"чужой — не наш сбой: {note}"
    assert foreign.exists(), "чужой launcher не тронут"
    assert "чуж" in note.lower() or "не трогаем" in note.lower(), f"note: {note}"


def test_uninstall_when_nothing_installed(monkeypatch, tmp_path):
    _mock_home(monkeypatch, tmp_path)
    monkeypatch.delenv("SROUTER_CODEX_APP_BUNDLE", raising=False)
    monkeypatch.setattr(cal, "_APP_CANDIDATES",
                        (str(tmp_path / "nope" / "ChatGPT.app"),))
    note, ok = cal.uninstall_launcher(_env(tmp_path), runner=_fake_dock_runner(
        _dock_export([]), {"writes": [], "killall": 0}))
    assert ok, f"no-op — не сбой: {note}"
    assert "не был установлен" in note.lower(), f"no-op честно назван: {note}"


# ============================== status (read-only) ==============================

PS_MAIN_FLAG = ("900 /Applications/ChatGPT.app/Contents/MacOS/ChatGPT "
                "--proxy-server=socks5://127.0.0.1:10808\n")
PS_MAIN_NOFLAG = "900 /Applications/ChatGPT.app/Contents/MacOS/ChatGPT\n"


def _status_runner(export_xml, captured, ps_out):
    def run(cmd, timeout=3):
        if cmd[:2] == ["/usr/bin/defaults", "export"]:
            return {"rc": 0, "out": export_xml, "err": "", "timeout": False}
        if cmd[0] == "/bin/ps":
            return {"rc": 0, "out": ps_out, "err": "", "timeout": False}
        captured["writes"].append(cmd)  # ЛЮБАЯ мутация в status — красный флаг
        return {"rc": 0, "out": "", "err": "", "timeout": False}
    return run


def _empty_snapshot():
    return {"status": "ok", "any_enabled": False, "detail": "",
            "http": {"enabled": False, "server": "", "port": None},
            "https": {"enabled": False, "server": "", "port": None},
            "socks": {"enabled": False, "server": "", "port": None},
            "pac": {"enabled": False, "url": ""}}


def test_status_read_only_and_facts(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    app = _stub_app(monkeypatch, tmp_path)
    monkeypatch.setattr(cal.system_proxy, "status", _empty_snapshot)
    captured = {"writes": [], "killall": 0}
    cal.install_launcher(_env(tmp_path), runner=_fake_dock_runner(
        _dock_export([_dock_tile(app)]), captured))
    captured["writes"].clear()  # captures install'а — status проверяем отдельно
    launcher = home / "Applications" / "ChatGPT (srouter).app"

    st = cal.status(runner=_status_runner(
        _dock_export([_dock_tile(app, launcher_path=launcher)]), captured, PS_MAIN_FLAG))

    assert not captured["writes"], f"status НЕ мутирует: {captured}"
    assert st["launcher_installed"] is True
    assert st["dock_tile_on_launcher"] is True, f"тайл на launcher: {st}"
    assert st["live_app_flag"] is True, f"--proxy-server в argv живого процесса: {st}"
    assert st["snapshot_any_enabled"] is False, f"эффективный снапшот пуст: {st}"
    assert st["status"] == "ok", f"всё на месте → ok: {st}"


def test_status_flag_absent_and_tile_off_launcher(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    app = _stub_app(monkeypatch, tmp_path)
    monkeypatch.setattr(cal.system_proxy, "status", _empty_snapshot)
    captured = {"writes": [], "killall": 0}
    cal.install_launcher(_env(tmp_path), runner=_fake_dock_runner(
        _dock_export([_dock_tile(app)]), captured))
    captured["writes"].clear()

    st = cal.status(runner=_status_runner(
        _dock_export([_dock_tile(app)]), captured, PS_MAIN_NOFLAG))

    assert st["dock_tile_on_launcher"] is False, f"тайл исходный: {st}"
    assert st["live_app_flag"] is False, f"argv без --proxy-server: {st}"
    assert st["status"] != "ok", f"не всё на месте → не ok: {st}"


def test_status_unknown_when_sources_unavailable(monkeypatch, tmp_path):
    home = _mock_home(monkeypatch, tmp_path)
    app = _stub_app(monkeypatch, tmp_path)
    monkeypatch.setattr(cal.system_proxy, "status",
                        lambda: {"status": "unknown", "any_enabled": None})
    captured = {"writes": [], "killall": 0}
    cal.install_launcher(_env(tmp_path), runner=_fake_dock_runner(
        _dock_export([_dock_tile(app)]), captured))

    st = cal.status(runner=_status_runner(
        _dock_export([_dock_tile(app, launcher_path=home / "Applications" / "ChatGPT (srouter).app")]),
        captured, ps_out=""))

    assert st["dock_tile_on_launcher"] is True
    assert st["live_app_flag"] is None, f"App не запущен → None, не False: {st}"
    assert st["snapshot_any_enabled"] is None, f"снапшот нечитаем → None: {st}"


# ============================== CLI wiring ==============================

def test_cli_wired_into_wrappers_and_uninstall():
    """`srouter wrappers codex-app install|uninstall|status` — расширение существующего
    подкомандного дерева wrappers (без новой топ-левел команды); полный uninstall зовёт
    uninstall_launcher БЕЗУСЛОВНО (ревью #457: гейт по _load_swap пропускал удаление
    launcher при install'е с незакреплённым тайлом — state-секции нет → осиротевший
    ~/Applications/*.app с exec на удалённый codex-app-proxy)."""
    import srouter_cli
    src = inspect.getsource(srouter_cli)
    assert "codex-app" in src, "subparser codex-app под wrappers"
    assert "install_launcher(" in src, "CLI вызывает install_launcher"
    assert "uninstall_launcher(" in src, "CLI uninstall вызывает uninstall_launcher"
    uninstall_src = inspect.getsource(srouter_cli._remove_optional_features)
    assert "uninstall_launcher(" in uninstall_src, "полный uninstall откатывает Dock-тайл"
    assert "_load_swap" not in uninstall_src, \
        "гейт по state-секции убран — uninstall_launcher сам обрабатывает отсутствие секции"


def test_app_flag_detector_single_source():
    """Канон detector-must-be-function (ревью #457): ps-argv детектор --proxy-server один —
    в codex_app_launcher; health_codenv переиспользует, своего regex не держит."""
    import health_codenv
    hc_src = inspect.getsource(health_codenv)
    assert "app_argv_has_proxy_flag" in hc_src, "health_codenv зовёт общий детектор"
    assert "_CODEX_APP_MAIN_RE" not in hc_src, "дубль regex в health_codenv удалён"
    assert "app_argv_has_proxy_flag" in inspect.getsource(cal.status), "status() зовёт его же"
    # поведение детектора (контракт ps-argv канона) — по обеим сторонам один:
    assert cal.app_argv_has_proxy_flag(PS_MAIN_FLAG) is True
    assert cal.app_argv_has_proxy_flag(PS_MAIN_NOFLAG) is False
    assert cal.app_argv_has_proxy_flag(
        "900 /Applications/ChatGPT.app/Contents/Resources/codex --proxy-server=x\n") is False, \
        "non-main процесс (Resources, не Contents/MacOS) не матчится"
    assert cal.app_argv_has_proxy_flag("") is False
