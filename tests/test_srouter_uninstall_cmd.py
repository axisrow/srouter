"""e2e-тесты srouter.cmd_uninstall: проброс статуса подсистем в ненулевой rc.

cmd_uninstall агрегирует множество шагов отката. Канон privileged-boundary-fail-closed (issue #94
DEFECT A): если критичная подсистема НЕ подтвердила откат (мёртвый прокси остался в gui-домене),
uninstall обязан вернуть ненулевой rc — НЕ рапортовать полный успех. Раньше env-cleanup возвращал
только строку, конкатенировавшуюся в сообщение → fail-open (rc=0 при живом socks5 в GUI).

Покрываем СВЯЗКУ: _remove_launchctl_env → cmd_uninstall rc. Изолированный контракт {ok:bool} покрыт
в test_srouter_codex_wrappers.py; здесь — что cmd_uninstall действительно пробрасывает ok=False в rc=2.
"""
from types import SimpleNamespace

import srouter


def _args(**over):
    """Минимальный args для cmd_uninstall (как argparse отдаёт). yes=True минует _prompt_bool."""
    base = dict(state=None, prefix=None, launchagents_dir=None, python=None, yes=True)
    base.update(over)
    return SimpleNamespace(**base)


def _stub_cmd_uninstall_internals(monkeypatch, *, env_ok, leftover=None, tty=True):
    """Застенить все внешние сайд-эффекты cmd_uninstall, КРОМЕ _remove_launchctl_env.

    env_ok управляет возвратом _remove_launchctl_env (тестируемая связка). leftover (issue #110
    Дефект 1) управляет ключом leftover в apply_uninstall — частичный откат (srouter ставил, но не
    откатил) → cmd_uninstall меняет headline + rc=2. tty — есть ли терминал (минует ранний возврат
    «подтверждение требует терминал»).

    ИНВАРИАНТ: ВСЕ хелперы отката замокаются — cmd_uninstall после apply_uninstall вызывает
    _remove_active_split_route/claude_proxy.disable/_remove_ppp_hook/_remove_codex_wrappers/
    _remove_codex_zsh_function (issue #97)/_remove_home_bin_from_path, и КАЖДЫЙ лезет в реальную
    ФС/сеть/route. `_remove_codex_zsh_function` обязательно: без мока она резолвит реальный
    Path.home()/.zshrc и удаляет managed-блок — на машине разработчика с установленным srouter
    (маркер в ~/.zshrc есть) тест молча переписывает shell-конфиг. Cycle-review #108 cycle 2
    (Codex critical) — зафиксировано spy.
    """
    monkeypatch.setattr(srouter, "_env_from_args", lambda args: SimpleNamespace())
    monkeypatch.setattr(srouter, "make_privileged_runner", lambda *a, **k: (lambda cmd, t: {"rc": 0}))
    monkeypatch.setattr(srouter, "build_uninstall_plan", lambda **k: {"state_readable": True})
    monkeypatch.setattr(srouter, "format_uninstall_plan", lambda p: "")
    monkeypatch.setattr(srouter.sys, "stdin", SimpleNamespace(isatty=lambda: tty))
    monkeypatch.setattr(srouter, "apply_uninstall",
                        lambda **k: {"ok": True, "blocked": [], "leftover": leftover or []})
    monkeypatch.setattr(srouter, "_remove_active_split_route", lambda *a, **k: 0)
    monkeypatch.setattr(srouter, "claude_proxy",
                        SimpleNamespace(disable=lambda: {"ok": True}))
    monkeypatch.setattr(srouter, "_remove_ppp_hook", lambda *a, **k: "")
    monkeypatch.setattr(srouter, "_remove_codex_wrappers", lambda: "")
    if hasattr(srouter, "_remove_codex_zsh_function"):
        # issue #97: лезет в реальный ~/.zshrc (_zshrc_path = Path.home()/.zshrc, не замокан).
        monkeypatch.setattr(srouter, "_remove_codex_zsh_function", lambda: "")
    monkeypatch.setattr(srouter, "_remove_home_bin_from_path", lambda: "")
    # ЕДИНСТВЕННЫЙ варьируемый параметр: статус env-cleanup.
    monkeypatch.setattr(srouter, "_remove_launchctl_env",
                        lambda runner: {"ok": env_ok, "note": "Codex env: mock."})


def test_cmd_uninstall_returns_nonzero_when_env_not_removed(monkeypatch, capsys):
    """DEFECT A e2e: _remove_launchctl_env → ok=False (мёртвый прокси в gui) → cmd_uninstall rc=2.

    До фикса env_status был строкой и конкатенировался в сообщение → rc=0 (fail-open). Теперь
    ok=False пробрасывается в ненулевой rc: оператор видит, что uninstall НЕ завершён чисто.
    """
    _stub_cmd_uninstall_internals(monkeypatch, env_ok=False)

    rc = srouter.cmd_uninstall(_args())

    assert rc == 2, f"env не снят → ненулевой rc (fail-closed), получил {rc}"
    err = capsys.readouterr().err.lower()
    assert "env" in err and "не" in err, f"stderr объясняет причину (env не снят): {err}"


def test_cmd_uninstall_returns_zero_when_env_removed(monkeypatch):
    """DEFECT A e2e (контроль): env ok=True (всё снято) → rc=0 — валидный путь не сломан."""
    _stub_cmd_uninstall_internals(monkeypatch, env_ok=True)

    rc = srouter.cmd_uninstall(_args())

    assert rc == 0, f"env снят → rc=0, получил {rc}"


# ============================ -y/--yes минует TTY-gate (issue #106) ============================
# cmd_uninstall падал в не-TTY среде (cron/launchd/CI/фоновый процесс) ДАЖЕ с -y: isatty()-gate
# стоял ДО проверки args.yes. -y именно для того, чтобы промпт не требовался → TTY не требуется.
def test_cmd_uninstall_yes_works_without_tty(monkeypatch):
    """issue #106: не-TTY + yes=True → НЕ падает с «требует терминал», доходит до apply (rc=0)."""
    _stub_cmd_uninstall_internals(monkeypatch, env_ok=True, tty=False)

    rc = srouter.cmd_uninstall(_args(yes=True))

    assert rc == 0, f"не-TTY + -y должно работать как неинтерактивный запуск, получил {rc}"


def test_cmd_uninstall_no_tty_without_yes_fails_closed(monkeypatch, capsys):
    """issue #106 (fail-closed сохранён): не-TTY + yes=False → rc=2 с «требует терминал».

    Нельзя запускать uninstall неинтерактивно БЕЗ явного -y — иначе промпт _prompt_bool зависнет
    или прочитает EOF. Gate остаётся, но теперь он смотрит И isatty, И yes.
    """
    _stub_cmd_uninstall_internals(monkeypatch, env_ok=True, tty=False)

    rc = srouter.cmd_uninstall(_args(yes=False))

    assert rc == 2, f"не-TTY без -y → отказ (нет ни TTY, ни подтверждения), получил {rc}"
    err = capsys.readouterr().err.lower()
    assert "терминал" in err, f"stderr объясняет: нужен TTY или -y: {err}"


# ============================ issue #110 Дефект 1 e2e: leftover → partial headline + rc=2 ============================
# cmd_uninstall агрегирует apply_uninstall. До #110 apply_uninstall рапортовал ok=True БЕЗУСЛОВНО → rc=0
# «Откат завершён» даже когда srouter ставил компоненты, но не откатил их (нет backup/маркер пропал).
# Теперь apply_uninstall возвращает leftover, cmd_uninstall меняет headline + rc=2 и перечисляет leftover
# поимённо (иначе «частично» без деталей = новый обман). true-foreign НЕ попадает в leftover (см. unit-тесты).
def test_cmd_uninstall_partial_rc_when_leftover(monkeypatch, capsys):
    """Дефект 1 e2e: apply_uninstall вернул leftover → rc=2, headline «частично» + leftover поимённо.

    Сценарий: srouter ставил privoxy (state managed=True), но backup потерян / маркер пропал →
    uninstall не откатил конфиг, но не крашнулся (ok=True). cmd_uninstall ДОЛЖЕН сообщить честно:
    частично + rc=2 (не маскировать rc=0 «Откат завершён»).
    """
    _stub_cmd_uninstall_internals(
        monkeypatch, env_ok=True, tty=False,
        leftover=[{"name": "privoxy", "status": "managed — no safe backup/marker, left untouched",
                   "reason": "not restorable (no backup / marker missing)"}])

    rc = srouter.cmd_uninstall(_args(yes=True))

    assert rc == 2, "leftover (srouter ставил, не откатил) → rc=2 (частичный, fail-closed)"
    out = capsys.readouterr()
    assert "частично" in out.out.lower(), "headline «Откат выполнен частично»"
    assert "privoxy" in out.err, "leftover перечислен поимённо в stderr (детали, не обман)"


def test_cmd_uninstall_zero_rc_when_clean_rollback(monkeypatch):
    """Дефект 1 e2e (контроль): leftover=[] + env_ok=True → rc=0 «Откат завершён».

    Валидный полный откат не сломан: все компоненты restorable (откатились), env снят → честный rc=0.
    """
    _stub_cmd_uninstall_internals(monkeypatch, env_ok=True, leftover=[], tty=False)

    rc = srouter.cmd_uninstall(_args(yes=True))

    assert rc == 0, "полный откат (leftover=[], env снят) → rc=0"
