"""ТДД-тесты srouter codex SOCKS5-wrappers + launchctl env (LaunchAgent plist) + PATH.

Codex (CLI + App) работает стабильно только через SOCKS5 (xray 10808) минуя privoxy (портит WS).
srouter install ставит ~/bin/codex + ~/bin/codex-app-proxy + LaunchAgent env-plist + ~/bin в PATH;
uninstall убирает. Канон — _install_ppp_hook/_remove_ppp_hook (best-effort, marker-gate «чужое не
трогать», строка-статус).
"""
import os
from pathlib import Path

import pytest

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
    """Фейк runner (как make_privileged_runner) — собирает вызовы, успех; `print` → не загружен.

    `launchctl print <domain>/<label>` → rc=113 (service-not-found = НЕ загружен): _remove_launchctl_env
    в чистом окружении видит подтверждённую выгрузку → удаляет plist. Иначе default rc=0 читался бы как
    «жив» → C оставлял бы plist + poll крутил settle (домен-осознанная проверка, cycle-review #93).
    """
    calls = []
    def runner(cmd, timeout):
        calls.append(list(cmd))
        if len(cmd) > 1 and cmd[1] == "print":
            return {"rc": 113, "out": "", "err": "Could not find service", "timeout": False}
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

    status = srouter._remove_launchctl_env(runner)
    note = status["note"]

    assert "снят" in note.lower()
    assert not plist.exists(), "plist удалён"
    assert any(len(c) > 1 and c[1] == "bootout" for c in runner.calls), "bootout вызван"
    # unsetenv для всех proxy-ключей с gui-доменным таргетом (env ставил скрипт setenv при загрузке
    # в gui-домене; c[2] = домен gui/<uid>, c[3] = ключ — issue #94 DEFECT A).
    unsetenvs = {c[3] for c in runner.calls if len(c) > 1 and c[1] == "unsetenv"}
    assert {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"} <= unsetenvs


def test_remove_launchctl_env_marker_gate_foreign(monkeypatch, tmp_path):
    """Чужой plist (без маркера) — НЕ удалять."""
    home = _mock_home(monkeypatch, tmp_path)
    runner = _fake_runner()
    plist = home / "Library" / "LaunchAgents" / f"{srouter.CODEX_ENV_LABEL}.plist"
    plist.parent.mkdir(parents=True, exist_ok=True)
    foreign = "<?xml version='1.0'?><plist version='1.0'><dict/>"
    plist.write_text(foreign, encoding="utf-8")

    note = srouter._remove_launchctl_env(runner)["note"]

    assert "чуж" in note.lower()
    assert plist.exists(), "чужой plist не удалён"


def test_remove_launchctl_env_when_not_installed(monkeypatch, tmp_path):
    """Нечего удалять (plist нет) — мягкий статус, не ошибка."""
    _mock_home(monkeypatch, tmp_path)
    note = srouter._remove_launchctl_env(_fake_runner())["note"]
    assert "не был" in note.lower()


def _print_runner(list_states):
    """runner с `print`-диспетчеризацией (домен-осознанная проверка, cycle-review #93).

    Проверка выгрузки — `launchctl print <domain>/CODEX_ENV_LABEL`: loaded кодируется rc
    (True→rc0 / False→rc113=service-not-found / None→timeout), НЕ текстом. list_states:
    [True/False/None,...] на каждый вызов print. (canned _fake_runner print→rc113 не доходит до fail-safe.)
    """
    calls = []
    state = {"i": 0}

    def runner(cmd, timeout):
        calls.append(list(cmd))
        sub = cmd[1] if len(cmd) > 1 else ""
        if sub == "print":
            idx = min(state["i"], len(list_states) - 1)
            state["i"] += 1
            loaded = list_states[idx]
            if loaded is None:
                return {"rc": None, "out": "", "err": "timeout", "timeout": True}
            if loaded:
                return {"rc": 0, "out": f"{srouter.CODEX_ENV_LABEL} = {{ state = running }}",
                        "err": "", "timeout": False}
            return {"rc": 113, "out": "", "err": "Could not find service", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    runner.calls = calls
    return runner


def test_remove_launchctl_env_keeps_plist_when_still_loaded(monkeypatch, tmp_path):
    """Сайт C fail-safe (PR #83 cycle-3): агент ещё загружен после settle → plist ОСТАВЛЕН, нет unsetenv.

    poll живёт в install_lib → патчим install_lib._BOOTOUT_*. settle≈0 (иначе poll крутил бы 2с),
    print всегда rc0 → state=True. Сообщение бит-в-бит: «всё ещё загружен» + «plist оставлен».
    """
    import install_lib
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_lib, "_BOOTOUT_SETTLE_MAX_WAIT", 0)
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_launchctl_env(_env(tmp_path), _fake_runner())
    plist = home / "Library" / "LaunchAgents" / f"{srouter.CODEX_ENV_LABEL}.plist"
    assert plist.exists()
    runner = _print_runner([True] * 6)  # не выгружается

    note = srouter._remove_launchctl_env(runner)["note"]

    assert "всё ещё загружен" in note, f"True → «всё ещё загружен»: {note}"
    assert "plist оставлен" in note
    assert plist.exists(), "агент ещё загружен → plist оставлен (fail-safe)"
    assert not any(len(c) > 1 and c[1] == "unsetenv" for c in runner.calls), \
        "не выгружен → env НЕ очищаем (unsetenv не вызывается)"


def test_remove_launchctl_env_keeps_plist_when_print_timeout(monkeypatch, tmp_path):
    """Сайт C: print timeout (None) → tristate-различие: «не подтверждена выгрузка», plist оставлен.

    Тест бит-в-бит различия None vs True. None короткозамыкает poll (`while state and …`).
    """
    import install_lib
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_launchctl_env(_env(tmp_path), _fake_runner())
    plist = home / "Library" / "LaunchAgents" / f"{srouter.CODEX_ENV_LABEL}.plist"
    assert plist.exists()
    runner = _print_runner([None])  # print timeout → state=None

    note = srouter._remove_launchctl_env(runner)["note"]

    assert "не подтверждена выгрузка" in note, f"None → «не подтверждена выгрузка»: {note}"
    assert "plist оставлен" in note
    assert plist.exists(), "print timeout (неизвестно) → plist оставлен (fail-safe)"
    assert not any(len(c) > 1 and c[1] == "unsetenv" for c in runner.calls)


@pytest.mark.parametrize("print_result, marker", [
    # print rc=0: агент ЖИВ (bootout мог не сработать) → «всё ещё загружен».
    ({"rc": 0, "out": "com.srouter.codenv = { state = running }", "err": "", "timeout": False},
     "всё ещё загружен"),
    # print rc=112: домен gui/<uid> недоступен (не-gui контекст) → «не подтверждена выгрузка».
    ({"rc": 112, "out": "", "err": "Could not find domain", "timeout": False},
     "не подтверждена выгрузка"),
], ids=["still_alive_rc0", "domain_not_found_rc112"])
def test_remove_launchctl_env_keeps_plist_on_domain_mismatch(monkeypatch, tmp_path, print_result, marker):
    """Сайт C домен-mismatch (cycle-review #93, 2-я critical): живой агент / недоступный домен → plist ОСТАВЛЕН.

    До фикса legacy `list` без домена из не-gui контекста не видел gui-агента → False → C удалял plist
    живого. Теперь `print gui/<uid>/CODEX_ENV_LABEL`: rc=0 (жив) → True, rc=112 (домен недоступен) → None;
    оба → loaded is not False → plist оставлен, нет unsetenv.
    """
    import install_lib
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_lib, "_BOOTOUT_SETTLE_MAX_WAIT", 0)
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_launchctl_env(_env(tmp_path), _fake_runner())
    plist = home / "Library" / "LaunchAgents" / f"{srouter.CODEX_ENV_LABEL}.plist"
    assert plist.exists()

    calls = []

    def runner(cmd, timeout):
        calls.append(list(cmd))
        if len(cmd) > 1 and cmd[1] == "print":
            return dict(print_result)
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    note = srouter._remove_launchctl_env(runner)["note"]

    assert marker in note, f"ожидалось «{marker}»: {note}"
    assert "plist оставлен" in note
    assert plist.exists(), "живой агент / недоступный домен → plist оставлен (fail-safe)"
    assert not any(len(c) > 1 and c[1] == "unsetenv" for c in calls), "не выгружен → нет unsetenv"


# ============================ сайт A: gui-domain unsetenv + verify + fail-closed (issue #94 DEFECT A) ============================
# `launchctl setenv/unsetenv/getenv` оперируют «caller's context» (man launchctl). setenv делает
# LaunchAgent-скрипт, запущенный launchd ВНУТРИ gui-домена → переменные в gui-домене. uninstall бежит
# из процесса cmd_uninstall (caller-context может быть user/<uid> из SSH/cron). unsetenv без домена
# снимает НЕ в gui → gui-домен остаётся с мёртвым 127.0.0.1:10808. Граница: unsetenv gui/<uid> <key>
# (доменный таргет принимается), верифицировать getenv gui/<uid> <key> → пусто, fail-closed иначе.
# Статус пробрасывается в cmd_uninstall (раньше env_note конкатенировался в строку → fail-open).
import install_lib


def _gui_domain():
    return f"gui/{install_lib.os.getuid()}"


def _domain_aware_runner(*, unsetenv_rc=0, getenv_remaining=None, getenv_timeout=None,
                         print_loaded=False):
    """runner для gui-domain unsetenv: unsetenv/getenv по доменному таргету.

    unsetenv_rc: rc на `unsetenv gui/<uid> <key>` (0=ок, 1=сбой).
    getenv_remaining: множество ключей, которые getenv ВИДИТ после unsetenv (переменная НЕ снята —
      fail-open сценарий). Если ключ не в множестве → getenv вернёт пустой вывод (снято).
    getenv_timeout: множество ключей, на которых getenv ТАЙМАУТИТ (rc=None, timeout=True) —
      верификация не смогла спросить gui-домен. fail-closed сценарий: нельзя считать «снято».
    print_loaded: True → print rc=0 (агент жив, до bootout-poll); по умолчанию rc=113 (выгружен).
    """
    calls = []
    remaining = set(getenv_remaining or ())
    timeout_keys = set(getenv_timeout or ())

    def runner(cmd, timeout):
        calls.append(list(cmd))
        sub = cmd[1] if len(cmd) > 1 else ""
        if sub == "print":
            if print_loaded:
                return {"rc": 0, "out": f"{srouter.CODEX_ENV_LABEL} = {{ state = running }}",
                        "err": "", "timeout": False}
            return {"rc": 113, "out": "", "err": "Could not find service", "timeout": False}
        if sub == "unsetenv":
            return {"rc": unsetenv_rc, "out": "", "err": "" if unsetenv_rc == 0 else "boom",
                    "timeout": False}
        if sub == "getenv":
            key = cmd[-1]
            if key in timeout_keys:
                return {"rc": None, "out": "", "err": "timeout", "timeout": True}
            val = "socks5h://127.0.0.1:10808" if key in remaining else ""
            return {"rc": 0, "out": val, "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    runner.calls = calls
    return runner


def _unsetenv_calls(calls):
    return [c for c in calls if len(c) > 1 and c[1] == "unsetenv"]


def _getenv_calls(calls):
    return [c for c in calls if len(c) > 1 and c[1] == "getenv"]


def test_remove_launchctl_env_unsetenv_targets_gui_domain(monkeypatch, tmp_path):
    """DEFECT A: unsetenv вызывается с ЯВНЫМ доменным таргетом `gui/<uid>`, НЕ голым ключом.

    setenv-скрипт LaunchAgent кладёт переменные в gui-домен (caller-context = gui). uninstall из
    cmd_uninstall бежит в caller-context (user/<uid> из SSH/cron) — unsetenv без домена снял бы не
    там. На коде до фикса (unsetenv <key>) этот тест ПАДАЕТ: cmd[2] = ключ, нет домена.
    """
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_launchctl_env(_env(tmp_path), _fake_runner())
    runner = _domain_aware_runner()
    expected_domain = _gui_domain()

    note = srouter._remove_launchctl_env(runner)["note"]

    assert "снят" in note.lower(), f"ожидаем успех: {note}"
    calls = _unsetenv_calls(runner.calls)
    assert calls, "unsetenv вызван хотя бы раз"
    for cmd in calls:
        assert len(cmd) >= 4 and cmd[2] == expected_domain, \
            f"unsetenv таргетит gui-домен явно: ожидалось cmd[2]=={expected_domain}, получено {cmd}"


def test_remove_launchctl_env_verifies_unsetenv_via_getenv(monkeypatch, tmp_path):
    """DEFECT A: после unsetenv — верификация `getenv gui/<uid> <key>` (пусто = подтверждено снято).

    unsetenv без verify = loose-валидатор (rc игнорируется, переменная могла остаться). Граница
    валидируется строгим первоисточником: getenv gui/<uid> (тот же домен, что setenv-скрипт).
    """
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_launchctl_env(_env(tmp_path), _fake_runner())
    runner = _domain_aware_runner()  # getenv возвращает пусто для всех ключей (снято)
    expected_domain = _gui_domain()

    note = srouter._remove_launchctl_env(runner)["note"]

    assert "снят" in note.lower(), f"ожидаем успех: {note}"
    getenvs = _getenv_calls(runner.calls)
    assert getenvs, "getenv верификация вызвана"
    verified_keys = {c[-1] for c in getenvs}
    assert {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"} <= verified_keys, \
        "каждый proxy-ключ верифицирован getenv"
    for cmd in getenvs:
        assert cmd[2] == expected_domain, f"getenv таргетит gui-домен: {cmd}"


def test_remove_launchctl_env_fails_closed_when_var_not_removed(monkeypatch, tmp_path):
    """DEFECT A fail-closed: getenv показывает переменную ЖИВОЙ после unsetenv → статус НЕ «снят».

    unsetenv «отработал» (rc=0), но getenv gui/<uid> HTTP_PROXY всё ещё видит socks5h://127.0.0.1:10808
    (домен-mismatch / launchd не снял). Без верификации cmd_uninstall вернул бы success → мёртвый
    прокси в gui. Теперь: статус сигнализирует проблему, cmd_uninstall пробрасывает в rc≠0.
    """
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_launchctl_env(_env(tmp_path), _fake_runner())
    runner = _domain_aware_runner(getenv_remaining={"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                                                    "http_proxy", "https_proxy", "all_proxy",
                                                    "NO_PROXY", "no_proxy"})

    status = srouter._remove_launchctl_env(runner)
    note = status["note"]

    assert status["ok"] is False, f"переменная осталась в gui → fail-closed (ok=False): {note}"
    assert "gui" in note.lower() and "остались" in note.lower(), \
        f"статус сигнализирует проблему (env не снят в gui): {note}"


def test_remove_launchctl_env_fails_closed_when_getenv_timeout(monkeypatch, tmp_path):
    """DEFECT A fail-closed верификации: getenv ТАЙМАУТИТ → НЕ считать «снято», ok=False.

    Внутренний цикл-review #94: первоначальный фикс считал пустой out = «снято» всегда. Но getenv
    при timeout/OSError (rc=None) возвращает пустой out — это НЕ «переменной нет», а «не смогли
    спросить». Считать это «снято» = fail-open (переменная могла остаться в gui). Канон: сбой
    верификации → unverifiable → fail-closed (ok=False). На коде без этого фикса тест ПАДАЕТ.
    """
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_launchctl_env(_env(tmp_path), _fake_runner())
    runner = _domain_aware_runner(getenv_timeout={"HTTP_PROXY"})  # getenv не ответил

    status = srouter._remove_launchctl_env(runner)

    assert status["ok"] is False, f"getenv timeout → unverifiable → fail-closed: {status['note']}"
    assert "подтверждено" in status["note"].lower() or "не" in status["note"].lower(), \
        f"статус отличает unverifiable от снято: {status['note']}"


def test_remove_launchctl_env_returns_structured_status_ok(monkeypatch, tmp_path):
    """DEFECT A: _remove_launchctl_env возвращает структурированный статус {ok:bool} для cmd_uninstall.

    Раньше возвращалась только строка-статус → cmd_uninstall конкатенировал в сообщение → fail-open
    (env не снят, но rc=0). Теперь ok=False пробрасывается в ненулевой rc cmd_uninstall.
    """
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_launchctl_env(_env(tmp_path), _fake_runner())
    runner = _domain_aware_runner()  # getenv → пусто (всё снято)

    status = srouter._remove_launchctl_env(runner)

    assert isinstance(status, dict), "статус — структурированный dict {ok:bool, note:str}"
    assert status.get("ok") is True


def test_remove_launchctl_env_returns_structured_status_not_ok(monkeypatch, tmp_path):
    """DEFECT A: переменная не снята → status.ok is False (cmd_uninstall пробрасывает в rc≠0)."""
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_launchctl_env(_env(tmp_path), _fake_runner())
    runner = _domain_aware_runner(getenv_remaining={"HTTP_PROXY"})

    status = srouter._remove_launchctl_env(runner)

    assert isinstance(status, dict)
    assert status.get("ok") is False


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
