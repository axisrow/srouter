"""e2e-тесты srouter.cmd_install: -y/--yes минует TTY-gate (issue #106).

cmd_install падал в не-TTY среде (cron/launchd/CI/фоновый процесс) ДАЖЕ с -y: isatty()-gate
(подтверждение установки) стоял ДО проверки args.yes. -y именно для того, чтобы промпт не
требовался → TTY не требовался. Симметрично test_srouter_uninstall_cmd.py (эталон stub'а).

Покрываем gate-логику подтверждения (cmd_install:544). Конфликт-блок (cmd_install:530) НЕ трогаем —
там TTY нужен legitimately (per-компонентный выбор adopt/overwrite/skip неразрешим через -y).
"""
from pathlib import Path
from types import SimpleNamespace

import srouter


def _args(**over):
    """Минимальный args для cmd_install (как argparse отдаёт). yes=True минует _prompt_bool."""
    base = dict(state=None, prefix=None, launchagents_dir=None, python=None, yes=True)
    base.update(over)
    return SimpleNamespace(**base)


def _stub_cmd_install_internals(monkeypatch, *, apply_ok=True, tty=True):
    """Застенить все внешние сайд-эффекты cmd_install.

    apply_ok управляет возвратом apply_install. tty — есть ли терминал (минует ранний возврат
    «подтверждение требует терминал»). plan возвращается БЕЗ конфликтов (конфликт-блок :530 не
    тестируем — там TTY нужен legitimately, см. docstring модуля).

    ИНВАРИАНТ: ВСЕ хелперы после apply_install замокаются — cmd_install после успешного apply
    вызывает claude_proxy/_install_generic_launchagent/_install_ppp_hook/_install_codex_wrappers/
    _install_codex_zsh_function (issue #97)/_install_launchctl_env/_ensure_home_bin_in_path, и КАЖДЫЙ
    лезет в реальную ФС/сеть/launchd. Пропуск любого мока = тест пишет в ~/.zshrc, ~/bin, plist.
    `_install_codex_zsh_function` обязательно: без мока она падает в try/except на env.now mock'а,
    и тест проходит СЛУЧАЙНО (маскируя вызов) — хрупкость, ломающаяся при любом изменении stub'а.
    """
    monkeypatch.setattr(srouter, "_env_from_args", lambda args: SimpleNamespace(root=Path(".")))
    monkeypatch.setattr(srouter, "make_privileged_runner", lambda *a, **k: (lambda cmd, t: {"rc": 0}))
    # plan без конфликтов → блок :527 (conflicts) пустой → доходим до gate :544.
    monkeypatch.setattr(srouter, "build_plan", lambda **k: {"components": {}})
    monkeypatch.setattr(srouter, "format_plan", lambda p: "")
    monkeypatch.setattr(srouter.sys, "stdin", SimpleNamespace(isatty=lambda: tty))
    monkeypatch.setattr(srouter, "apply_install",
                        lambda **k: {"ok": apply_ok, "blocked": []})
    # best-effort хелперы после успешного apply (мокаем, чтобы не трогать реальную ФС/сеть).
    monkeypatch.setattr(srouter, "claude_proxy", SimpleNamespace(enable=lambda: {"ok": True}))
    # issue #130: git → SOCKS5 (xray 10808) через gitconfig, симметрично claude_proxy/vscode_proxy.
    monkeypatch.setattr(srouter, "git_proxy", SimpleNamespace(enable=lambda: {"ok": True, "proxy": "socks5h://127.0.0.1:10808"}))
    monkeypatch.setattr(srouter, "_install_generic_launchagent", lambda *a, **k: (True, ""))
    monkeypatch.setattr(srouter, "_install_ppp_hook", lambda *a, **k: "")
    monkeypatch.setattr(srouter, "_install_codex_wrappers", lambda env: "")
    if hasattr(srouter, "_install_codex_zsh_function"):
        # issue #97: лезет в реальный ~/.zshrc (_zshrc_path = Path.home()/.zshrc, не замокан).
        monkeypatch.setattr(srouter, "_install_codex_zsh_function", lambda env: "")
    monkeypatch.setattr(srouter, "_install_launchctl_env", lambda env, runner: "")
    monkeypatch.setattr(srouter, "_ensure_home_bin_in_path", lambda env: "")
    # issue #185: scoped SOCKS5 через VSCode http.proxy (вместо gui-SOCKS5, который ломал CC #130).
    monkeypatch.setattr(srouter, "vscode_proxy",
                        SimpleNamespace(enable=lambda: {"ok": True, "paths": []}))
    # issue #168: PF codex-изоляция (sub-anchor). Лезет в реальный pfctl/osascript — мокаем.
    if hasattr(srouter, "_install_codex_isolation"):
        monkeypatch.setattr(srouter, "_install_codex_isolation", lambda env, runner: "")
    # issue #112 Часть 4: cmd_install регистрирует known_markers в state после установки wrappers/zshrc.
    # Мокаем (как все best-effort хелперы) — иначе лезет в реальный state_path и local_state.save_state.
    if hasattr(srouter, "populate_known_markers"):
        monkeypatch.setattr(srouter, "populate_known_markers", lambda *a, **k: "")


def test_cmd_install_yes_works_without_tty(monkeypatch):
    """issue #106: не-TTY + yes=True → НЕ падает с «требует терминал», доходит до apply (rc=0)."""
    _stub_cmd_install_internals(monkeypatch, apply_ok=True, tty=False)

    rc = srouter.cmd_install(_args(yes=True))

    assert rc == 0, f"не-TTY + -y должно работать как неинтерактивный запуск, получил {rc}"


def test_cmd_install_no_tty_without_yes_fails_closed(monkeypatch, capsys):
    """issue #106 (fail-closed сохранён): не-TTY + yes=False → rc=2 с «требует терминал».

    Нельзя запускать install неинтерактивно БЕЗ явного -y — иначе _prompt_bool зависнет на EOF.
    Gate остаётся, но теперь он смотрит И isatty, И yes.
    """
    _stub_cmd_install_internals(monkeypatch, apply_ok=True, tty=False)

    rc = srouter.cmd_install(_args(yes=False))

    assert rc == 2, f"не-TTY без -y → отказ (нет ни TTY, ни подтверждения), получил {rc}"
    err = capsys.readouterr().err.lower()
    assert "терминал" in err, f"stderr объясняет: нужен TTY или -y: {err}"


# ============================ issue #110 Дефект 2 e2e: idempotent install после partial uninstall ============================
# Базовый сценарий бага #110: srouter uninstall (rc=0 «Откат завершён» — leftover скрыт) → srouter install
# сразу падает в non-TTY «обнаружены конфликты (xray, privoxy, dnsmasq)», rc=2. Причина: install видел
# stale-managed конфиги (state.managed=True, маркер пропал) как foreign → конфликт-блок non-TTY отказывал
# независимо от -y. Фикс: reclaimable (state.managed=True, маркера нет) исключён из конфликт-фильтра →
# авторазрешается с backup в apply_install. non-TTY -y проходит rc=0.
def test_cmd_install_idempotent_after_partial_uninstall(monkeypatch):
    """Дефект 1+2 интеграция: uninstall оставил stale-managed → повторный install (non-TTY, -y) rc=0.

    plan содержит reclaimable-компонент (conflict=True И reclaimable=True). До фикса cmd_install
    фильтровал конфликты без учёта reclaimable → non-TTY падал rc=2. Теперь reclaimable исключён →
    apply_install авторазрешает его (с backup), rc=0. Это и есть идемпотентность uninstall→install.
    """
    _stub_cmd_install_internals(monkeypatch, apply_ok=True, tty=False)
    # Переопределяем build_plan: компонент с conflict=True И reclaimable=True (stale-managed).
    monkeypatch.setattr(srouter, "build_plan", lambda **k: {
        "components": {
            "privoxy": {"name": "privoxy", "conflict": True, "reclaimable": True,
                        "conflicts": ["foreign_config"], "config_path": "/tmp/x", "port_owner": None},
        }
    })

    rc = srouter.cmd_install(_args(yes=True))

    assert rc == 0, ("reclaimable (stale-managed) НЕ должен блокировать non-TTY install: "
                     f"авторазрешается с backup, получил rc={rc}")


def test_cmd_install_foreign_conflict_still_blocks_non_tty(monkeypatch, capsys):
    """Дефект 2 регресс-гард: ИСТИННО foreign (reclaimable=False) → non-TTY по-прежнему rc=2.

    Фикс не должен открывать дыру: настоящий чужой конфиг (srouter никогда не ставил) остаётся
    конфликтом, требующим явного adopt/overwrite/skip. non-TTY без выбора → rc=2 (как до фикса).
    """
    _stub_cmd_install_internals(monkeypatch, apply_ok=True, tty=False)
    monkeypatch.setattr(srouter, "build_plan", lambda **k: {
        "components": {
            "privoxy": {"name": "privoxy", "conflict": True, "reclaimable": False,
                        "conflicts": ["foreign_config"], "config_path": "/tmp/x", "port_owner": None},
        }
    })

    rc = srouter.cmd_install(_args(yes=True))

    assert rc == 2, ("true-foreign (reclaimable=False) — конфликт, non-TTY без выбора → rc=2, "
                     f"получил rc={rc}")
    err = capsys.readouterr().err.lower()
    assert "конфликт" in err, "stderr объясняет: конфликт требует ручного разрешения"


# ============================ issue #189: codenv (gui-env SOCKS5) ВОССТАНОВЛЕН + VSCode scoped =====
# Эмпирика #189 (verify, lsof per-process): ChatGPT.app = Electron-оболочка над Rust-бинарником —
# ДВА независимых сетевых стека. (1) Chromium-оболочка → уважает СИСТЕМНЫЙ SOCKS (scutil) — работает.
# (2) Rust app-server (/Resources/codex, основной WS к chatgpt.com) → НЕ уважает системный SOCKS,
# берёт ТОЛЬКО env SOCKS5 → без env идёт напрямую → GFW рвёт (error_kind=TimedOut в logs_2.sqlite).
# config.toml [network] proxy_url МЁРТВ в codex 0.146. Единственный путь для Rust app-server =
# env SOCKS5 в launchd gui-домене → com.srouter.codenv LaunchAgent (_install_launchctl_env).
# codenv НЕ ломает Claude Code (#130 снят): CC CLI читает прокси из ~/.claude/settings.json
# (claude_proxy.py), НЕ из launchd gui-env → месяц коэкзиста CC+Codex это подтверждает.
# VSCode http.proxy (#185) остаётся для codex-расширения openai.chatgpt (отдельный клиент) — они
# КОМПЛЕМЕНТАРНЫ (разные клиенты/стеки), НЕ взаимоисключающи. cmd_install вызывает ОБА.
def test_cmd_install_activates_codenv_and_vscode_proxy(monkeypatch):
    """issue #189: install → _install_launchctl_env (codenv для Rust app-server) И vscode_proxy.enable()
    (scoped для расширения) — ОБА вызваны. Они покрывают разных клиентов, не конфликтуют."""
    _stub_cmd_install_internals(monkeypatch, apply_ok=True, tty=False)
    calls = {"vscode_enable": 0, "launchctl_env": 0}
    monkeypatch.setattr(srouter, "vscode_proxy",
                        SimpleNamespace(enable=lambda: (calls.__setitem__("vscode_enable", 1), {"ok": True})[1]))
    monkeypatch.setattr(srouter, "_install_launchctl_env",
                        lambda env, runner: (calls.__setitem__("launchctl_env", 1), "")[1])

    rc = srouter.cmd_install(_args(yes=True))

    assert rc == 0
    assert calls["launchctl_env"] == 1, (
        "install обязан грузить codenv LaunchAgent (gui-env SOCKS5) — без него Rust app-server "
        "ChatGPT.app идёт напрямую и GFW рвёт WS к chatgpt.com (#189)."
    )
    assert calls["vscode_enable"] == 1, (
        "install обязан активировать scoped VSCode http.proxy (#185) для codex-расширения "
        "openai.chatgpt — отдельный клиент от ChatGPT.app."
    )


# ============================ issue #130: git → SOCKS5 через gitconfig, автоматически в install =====
def test_cmd_install_enables_git_proxy(monkeypatch):
    """issue #130: install обязан вызвать git_proxy.enable() — git ходит через SOCKS5 (xray 10808)
    scoped на github.com, без ручной правки ~/.gitconfig."""
    _stub_cmd_install_internals(monkeypatch, apply_ok=True, tty=False)
    calls = {"git_enable": 0}
    monkeypatch.setattr(srouter, "git_proxy", SimpleNamespace(
        enable=lambda: (calls.__setitem__("git_enable", 1), {"ok": True, "proxy": "socks5h://127.0.0.1:10808"})[1]))

    rc = srouter.cmd_install(_args(yes=True))

    assert rc == 0
    assert calls["git_enable"] == 1, "install обязан настроить git-прокси автоматически (#130)"
