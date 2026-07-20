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
    monkeypatch.setattr(srouter, "_install_generic_launchagent", lambda *a, **k: (True, ""))
    monkeypatch.setattr(srouter, "_install_ppp_hook", lambda *a, **k: "")
    monkeypatch.setattr(srouter, "_install_codex_wrappers", lambda env: "")
    if hasattr(srouter, "_install_codex_zsh_function"):
        # issue #97: лезет в реальный ~/.zshrc (_zshrc_path = Path.home()/.zshrc, не замокан).
        monkeypatch.setattr(srouter, "_install_codex_zsh_function", lambda env: "")
    monkeypatch.setattr(srouter, "_install_launchctl_env", lambda env, runner: "")
    monkeypatch.setattr(srouter, "_ensure_home_bin_in_path", lambda env: "")


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
