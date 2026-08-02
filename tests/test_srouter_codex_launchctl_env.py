"""Общие test-cases srouter codex SOCKS5-wrappers + launchctl env + PATH.

Codex (CLI + App) работает стабильно только через SOCKS5 (xray 10808) минуя privoxy (портит WS).
srouter install ставит ~/bin/codex-srouter + ~/bin/codex-app-proxy + LaunchAgent env-plist + ~/bin в PATH;
uninstall убирает. Канон — _install_ppp_hook/_remove_ppp_hook (best-effort, marker-gate «чужое не
трогать», строка-статус).

Issue #251: subprocess.run(...) на реальный wrapper-скрипт использует timeout=30/45 (не 10/15) — под
pytest-xdist -n 8 несколько десятков таких вызовов исполняются одновременно (каждый сам по себе
спавнит readlink/stat/grep/env), и CPU-contention на 10-ядерной машине не укладывается в 10-15с
(эмпирически подтверждено: TimeoutExpired ровно на границе timeout, воспроизводится с чистым PATH без
реального ~/bin — т.е. дело не в гонке за общий каталог, а в тесном таймауте под параллельной нагрузкой).
"""
import os
import signal
import subprocess
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
    """Минимальный InstallEnv: root = tmp-копия репо (реальные шаблоны launchagents/ копируются).
    launchagent_dir = home/Library/LaunchAgents (как прод) — _install_launchctl_env пишет туда,
    _remove_launchctl_env ищет там же; путь должен совпадать.

    Issue #250: root НЕ указывает на сам чекаут репозитория — сам чекаут может лежать внутри
    AO-worktree (`.ao/data/worktrees/...`), а guard `_install_launchctl_env` такой путь отвергает.
    Тесты «нормальной установки» должны моделировать КАНОНИЧЕСКИЙ root (как прод ~/Projects/srouter),
    а не зависеть от того, где физически лежит чекаут прогона. Worktree-путь проверяется отдельно
    (_worktree_env ниже) — намеренно, а не случайно."""
    import shutil
    home = Path.home()  # monkeypatched _mock_home
    import install_lib
    root = tmp_path / "srouter-root"
    root.mkdir(exist_ok=True)
    repo_agents = Path(__file__).resolve().parent.parent / "launchagents"
    if not (root / "launchagents").exists():
        shutil.copytree(repo_agents, root / "launchagents")
    return install_lib.InstallEnv(
        root=root,
        prefix=tmp_path / "homebrew",
        state_path=tmp_path / "srouter.local.json",
        launchagent_dir=home / "Library" / "LaunchAgents",
        python_bin="/usr/bin/python3",
        now="2026-07-04T00-00-00Z",
    )


def _markers():
    """Маркеры из CODEX_WRAPPERS: {name: marker}."""
    return {name: marker for name, _, marker in srouter.CODEX_WRAPPERS}


def _cli_wrapper_name():
    """Имя CLI-wrapper'а в ~/bin (первая запись CODEX_WRAPPERS) — единый источник правды."""
    return srouter.CODEX_WRAPPERS[0][0]


def _cli_wrapper_path():
    """Путь к CLI-wrapper в ~/bin (для тестов — через канон _codex_wrapper_path)."""
    return srouter._codex_wrapper_path(_cli_wrapper_name())


# ============================ _install/_remove_launchctl_env (LaunchAgent com.srouter.codenv) ============================
def _fake_runner():
    """Фейк runner (как make_privileged_runner) — собирает вызовы, успех; `print` → не загружен.

    `launchctl print <domain>/<label>` → rc=113 (service-not-found = НЕ загружен): _remove_launchctl_env
    в чистом окружении видит подтверждённую выгрузку → удаляет plist. Иначе default rc=0 читался бы как
    «жив» → C оставлял бы plist + poll крутил settle (домен-осознанная проверка, cycle-review #93).

    `launchctl print gui/<uid>` (БЕЗ label — issue #191 env-верификация через health._read_gui_proxy_env)
    отдаётся отдельно: пустой блок environment={} (verifiable=True, keys={}) — «всё снято», раз
    unsetenv (через asuser, issue #191) должен был реально снять переменные в честном сценарии.
    """
    calls = []
    def runner(cmd, timeout):
        calls.append(list(cmd))
        if len(cmd) > 1 and cmd[1] == "print":
            target = cmd[2] if len(cmd) > 2 else ""
            # голый домен gui/<uid> (issue #191 env-верификация через health._read_gui_proxy_env) —
            # без "/CODEX_ENV_LABEL" суффикса → пустой блок environment (всё снято, unsetenv сработал).
            if target and srouter.CODEX_ENV_LABEL not in target:
                return {"rc": 0, "out": "environment = {\n}\n", "err": "", "timeout": False}
            # <domain>/<label> — agent-статус: НЕ загружен.
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


def test_install_launchctl_env_warn_uses_print_not_broken_getenv_domain_arg(monkeypatch, tmp_path):
    """issue #191: WARN о чужом GUI-прокси должен реально видеть gui-домен, а не молчать всегда.

    Старый код (`getenv gui/<uid> HTTP_PROXY`) эмпирически игнорирует домен-аргумент (Usage: getenv
    <key> — ровно один позиционный аргумент, второй молча отбрасывается) → val ВСЕГДА пуст → WARN
    никогда не срабатывает, даже если в gui реально висит чужой (не-srouter) прокси. На честной модели
    (print gui/<uid> реально видит чужой прокси) старый код это пропускает — RED. Фикс должен
    переиспользовать health._read_gui_proxy_env (print-based, единственный домен-осознанный источник).
    """
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    calls = []
    foreign_proxy = "http://10.0.0.5:3128"

    def runner(cmd, timeout):
        calls.append(list(cmd))
        sub = cmd[1] if len(cmd) > 1 else ""
        if sub == "print":
            target = cmd[2] if len(cmd) > 2 else ""
            if target and srouter.CODEX_ENV_LABEL not in target:
                # честный gui-домен: реальный чужой HTTP_PROXY уже висит там.
                return {"rc": 0,
                        "out": f"environment = {{\n\t\tHTTP_PROXY => {foreign_proxy}\n}}\n",
                        "err": "", "timeout": False}
            return {"rc": 113, "out": "", "err": "Could not find service", "timeout": False}
        if sub == "getenv":
            # РЕАЛЬНОЕ launchctl: домен-аргумент молча игнорируется, второй arg отброшен → пусто.
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    note = srouter._install_launchctl_env(env, runner)

    assert "ВНИМАНИЕ" in note and foreign_proxy in note, (
        f"чужой прокси реально висит в gui-домене (эмпирика #191: print его видит, "
        f"getenv gui/<uid> KEY — нет) — WARN должен сработать: {note}"
    )


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
    # unsetenv для всех proxy-ключей через `launchctl asuser <uid> launchctl unsetenv KEY` (issue #191:
    # голый `unsetenv gui/<uid> KEY` эмпирически молча игнорирует домен — asuser реально исполняет
    # команду в bootstrap-контексте gui-пользователя, man launchctl).
    unsetenvs = {c[5] for c in runner.calls
                 if len(c) > 5 and c[1] == "asuser" and c[4] == "unsetenv"}
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

    poll живёт в install_plist → патчим install_plist._BOOTOUT_*. settle≈0 (иначе poll крутил бы 2с),
    print всегда rc0 → state=True. Сообщение бит-в-бит: «всё ещё загружен» + «plist оставлен».
    """
    import install_plist
    monkeypatch.setattr(install_plist, "_BOOTOUT_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_plist, "_BOOTOUT_SETTLE_MAX_WAIT", 0)
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
    import install_plist
    monkeypatch.setattr(install_plist, "_BOOTOUT_POLL_INTERVAL", 0)
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
    import install_plist
    monkeypatch.setattr(install_plist, "_BOOTOUT_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_plist, "_BOOTOUT_SETTLE_MAX_WAIT", 0)
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


# ============================ сайт A: gui-domain unsetenv + verify + fail-closed (issue #94 DEFECT A,
# переписано issue #191 — см. ниже) ============================
# `launchctl setenv/unsetenv/getenv` оперируют «caller's context» (man launchctl). setenv делает
# LaunchAgent-скрипт, запущенный launchd ВНУТРИ gui-домена → переменные в gui-домене. uninstall бежит
# из процесса cmd_uninstall (caller-context может быть user/<uid> из SSH/cron). Изначальный фикс #94
# предполагал, что `unsetenv gui/<uid> <key>` / `getenv gui/<uid> <key>` честно принимают домен —
# ОПРОВЕРГНУТО эмпирически (issue #191, 2026-07-28): `Usage: launchctl getenv <key>` — ровно ОДИН
# позиционный аргумент; вызов с двумя трактует первый как имя переменной, второй молча игнорируется.
# Рабочий домен-осознанный путь — `launchctl asuser <uid> launchctl unsetenv <key>` (man: asuser
# исполняет команду в bootstrap-контексте target-пользователя) + верификация через
# `launchctl print gui/<uid>` (health._read_gui_proxy_env, единственный источник правды о gui-домене).
# Статус пробрасывается в cmd_uninstall (раньше env_note конкатенировался в строку → fail-open).
import install_lib


def _gui_domain():
    return f"gui/{install_lib.os.getuid()}"


# ============================ issue #191: getenv/unsetenv С доменным аргументом молча не работают ============
# Эмпирически подтверждено на реальной машине (не гипотеза): `launchctl getenv <arg1> <arg2>` — Usage
# ровно ОДИН позиционный аргумент ("Usage: launchctl getenv <key>", rc=64 без него). При вызове
# `getenv gui/501 HTTP_PROXY` launchctl берёт ПЕРВЫЙ аргумент ("gui/501") как имя переменной, ВТОРОЙ
# ("HTTP_PROXY") молча игнорируется — доказано напрямую: `setenv gui/501 marker_value_xyz` +
# `getenv gui/501` вернул "marker_value_xyz". Тот же паттерн — `unsetenv gui/501 HTTP_PROXY` unset'ит
# несуществующую переменную "gui/501", реальный HTTP_PROXY в gui-домене остаётся нетронутым. Старый
# _remove_launchctl_env верил rc=0 + пустому getenv-выводу как «снято» — ложноположительно ВСЕГДА
# (пустой вывод получается из-за игнорируемого домена, а не из-за реального снятия). Рабочий путь:
# `launchctl asuser <uid> launchctl unsetenv <key>` (man: bootstrap-контекст target-пользователя) +
# верификация `launchctl print gui/<uid>` (блок `environment = {...}`, как health._read_gui_proxy_env).
def _real_launchctl_runner(gui_env, *, print_missing_service=True, print_timeout=False,
                           asuser_works=True):
    """Честная модель РЕАЛЬНОГО launchctl (эмпирически проверено 2026-07-28, не гипотеза):

    - gui_env: dict, представляющий истинное состояние переменных в gui-домене (единственный
      источник правды — читается только через `print gui/<uid>` в блоке environment={...}).
    - `getenv <arg1> [arg2]` / голый `unsetenv <arg1> [arg2]`: игнорирует arg2 полностью, трактует
      arg1 как имя переменной; такой переменной в этой модели никогда нет → ВСЕГДА rc=0 + пустой out,
      независимо от gui_env — НЕ меняет gui_env.
    - `asuser <uid> launchctl unsetenv <key>`: рабочий путь (man launchctl — bootstrap-контекст
      target-пользователя) — реально удаляет <key> из gui_env, если asuser_works=True.
    - `print gui/<uid>`: единственная команда, реально читающая gui_env → рендерит блок environment.
      print_timeout=True → timeout (fail-closed сценарий верификации).
    """
    calls = []

    def runner(cmd, timeout):
        calls.append(list(cmd))
        sub = cmd[1] if len(cmd) > 1 else ""
        if sub == "print":
            if print_timeout:
                return {"rc": None, "out": "", "err": "timeout", "timeout": True}
            if print_missing_service and len(cmd) > 2 and "com.srouter.codenv" in cmd[2]:
                return {"rc": 113, "out": "", "err": "Could not find service", "timeout": False}
            lines = ["environment = {"]
            for k, v in gui_env.items():
                lines.append(f"\t\t{k} => {v}")
            lines.append("}")
            return {"rc": 0, "out": "\n".join(lines), "err": "", "timeout": False}
        if sub == "asuser" and len(cmd) >= 6 and cmd[4] == "unsetenv":
            if asuser_works:
                gui_env.pop(cmd[5], None)
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        if sub in ("getenv", "unsetenv"):
            # РЕАЛЬНОЕ launchctl: arg2 (реальный ключ) молча игнорируется — gui_env НЕ меняется,
            # getenv не видит реальный ключ (спросили про несуществующую "gui/<uid>"-переменную).
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    runner.calls = calls
    return runner


def test_remove_launchctl_env_unsetenv_via_asuser_succeeds_on_real_model(monkeypatch, tmp_path):
    """GREEN (issue #191): на честной модели `asuser <uid> launchctl unsetenv <key>` реально снимает
    переменные из gui-домена (эмпирически рабочий путь) — код рапортует успех и удаляет plist."""
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_launchctl_env(_env(tmp_path), _fake_runner())
    gui_env = {"HTTP_PROXY": "socks5h://127.0.0.1:10808", "HTTPS_PROXY": "socks5h://127.0.0.1:10808"}
    runner = _real_launchctl_runner(gui_env)

    status = srouter._remove_launchctl_env(runner)

    assert status["ok"] is True, f"asuser реально снял переменные — ожидаем успех: {status['note']}"
    assert "снят" in status["note"].lower()
    plist = home / "Library" / "LaunchAgents" / f"{srouter.CODEX_ENV_LABEL}.plist"
    assert not plist.exists(), "plist удалён после подтверждённого снятия"


def test_remove_launchctl_env_asuser_targets_real_key_not_domain_string(monkeypatch, tmp_path):
    """issue #191: unsetenv-вызов — `launchctl asuser <uid> launchctl unsetenv <key>`, где <key> —
    реальное имя переменной (HTTP_PROXY/…), а НЕ строка домена (в отличие от опровергнутого
    `unsetenv gui/<uid> <key>`, где launchctl видит только первый позиционный аргумент)."""
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_launchctl_env(_env(tmp_path), _fake_runner())
    runner = _real_launchctl_runner({})
    uid = str(install_lib.os.getuid())

    srouter._remove_launchctl_env(runner)

    asuser_calls = [c for c in runner.calls if len(c) > 1 and c[1] == "asuser"]
    assert asuser_calls, "asuser вызван хотя бы раз"
    keys = {c[5] for c in asuser_calls if len(c) > 5 and c[2] == uid and c[4] == "unsetenv"}
    assert {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"} <= keys, \
        f"каждый proxy-ключ снимается через asuser <uid> launchctl unsetenv <key>: {asuser_calls}"


def test_remove_launchctl_env_verifies_via_print_gui_domain(monkeypatch, tmp_path):
    """issue #191: верификация снятия идёт через `launchctl print gui/<uid>` (health._read_gui_proxy_env),
    НЕ через `getenv gui/<uid> <key>` (опровергнуто — молча игнорирует домен)."""
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_launchctl_env(_env(tmp_path), _fake_runner())
    runner = _real_launchctl_runner({"HTTP_PROXY": "socks5h://127.0.0.1:10808"})
    expected_domain = _gui_domain()

    srouter._remove_launchctl_env(runner)

    print_calls = [c for c in runner.calls
                   if len(c) > 2 and c[1] == "print" and c[2] == expected_domain]
    assert print_calls, f"print {expected_domain} (без label) вызван для верификации env: {runner.calls}"
    getenv_calls = [c for c in runner.calls if len(c) > 1 and c[1] == "getenv"]
    assert not getenv_calls, "getenv БОЛЬШЕ не используется для верификации (опровергнутый путь #191)"


def test_remove_launchctl_env_fails_closed_when_asuser_leaves_leftover(monkeypatch, tmp_path):
    """issue #191 fail-closed: asuser unsetenv не снял ключ (asuser_works=False — симулирует любой сбой
    рабочего пути) → print gui/<uid> реально видит переменную → status.ok is False."""
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_launchctl_env(_env(tmp_path), _fake_runner())
    runner = _real_launchctl_runner({"HTTP_PROXY": "socks5h://127.0.0.1:10808"}, asuser_works=False)

    status = srouter._remove_launchctl_env(runner)

    assert status["ok"] is False, f"переменная реально осталась в gui → fail-closed: {status['note']}"
    assert "gui" in status["note"].lower() and "остались" in status["note"].lower()
    plist = home / "Library" / "LaunchAgents" / f"{srouter.CODEX_ENV_LABEL}.plist"
    assert plist.exists(), "plist оставлен как контроль (env не подтверждённо снят)"


def test_remove_launchctl_env_fails_closed_when_print_verification_times_out(monkeypatch, tmp_path):
    """issue #191 fail-closed верификации: `print gui/<uid>` таймаутит → НЕ считать «снято».

    Канон verify-dont-guess: сбой верификации ≠ подтверждённый успех. Пустой результат печати из-за
    timeout — это «не смогли спросить», а не «переменной нет» (симметрично getenv-fail-closed из #94,
    но теперь bound к print, реальному домен-осознанному источнику).
    """
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_launchctl_env(_env(tmp_path), _fake_runner())
    runner = _real_launchctl_runner({}, print_timeout=True)

    status = srouter._remove_launchctl_env(runner)

    assert status["ok"] is False, f"print timeout → unverifiable → fail-closed: {status['note']}"
    plist = home / "Library" / "LaunchAgents" / f"{srouter.CODEX_ENV_LABEL}.plist"
    assert plist.exists(), "plist оставлен — верификация не подтвердила снятие"


def test_remove_launchctl_env_returns_structured_status_ok_real_model(monkeypatch, tmp_path):
    """_remove_launchctl_env возвращает {ok: True} на честной модели, где asuser реально снял env."""
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_launchctl_env(_env(tmp_path), _fake_runner())
    runner = _real_launchctl_runner({"HTTP_PROXY": "socks5h://127.0.0.1:10808"})

    status = srouter._remove_launchctl_env(runner)

    assert isinstance(status, dict)
    assert status.get("ok") is True


def test_remove_launchctl_env_returns_structured_status_not_ok_real_model(monkeypatch, tmp_path):
    """_remove_launchctl_env возвращает {ok: False} когда переменная реально осталась в gui-домене."""
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_launchctl_env(_env(tmp_path), _fake_runner())
    runner = _real_launchctl_runner({"HTTP_PROXY": "socks5h://127.0.0.1:10808"}, asuser_works=False)

    status = srouter._remove_launchctl_env(runner)

    assert isinstance(status, dict)
    assert status.get("ok") is False


# ============================ z.ai в launchctl-gui NO_PROXY (issue #195) ============================
# z.ai доступен напрямую (мимо SOCKS5/xray/VPS) — не за GFW. moonbridge (Codex.app helper,
# ~/.codex/moon-bridge/, слушает 127.0.0.1:38440) как клиент ходит к api.z.ai, унаследовав gui-env.
# Codex→moonbridge = loopback (уже в NO_PROXY); moonbridge→api.z.ai = внешний хост → нужен z.ai
# в launchctl-gui NO_PROXY, иначе moonbridge идёт SOCKS5→xray→VPS и ДОХНЕТ при мёртвом VPS (#194).
# Канон: zai-direct-no-proxy, srouter-critical-infra-24-7 (VPS-смерть не должна валить z.ai).
# ОБА варианта z.ai,.z.ai: z.ai = точное совпадение хоста, .z.ai = любой поддомен (*.z.ai).
def test_codex_no_proxy_includes_zai():
    """CODEX_NO_PROXY (единый источник launchctl-gui NO_PROXY) содержит z.ai И .z.ai.

    Без .z.ai — поддомены api.z.ai/api-coding.z.ai НЕ матчатся NO_PROXY (curl-семантика:
    'z.ai' без точки = только точный хост, '.z.ai' = wildcard поддоменов). Покрытие и корня,
    и поддоменов нужно moonbridge'у (ходит к api.z.ai/api/coding/paas/...).
    """
    np = srouter.CODEX_NO_PROXY
    hosts = {h.strip().lower() for h in np.split(",") if h.strip()}
    assert "z.ai" in hosts, f"CODEX_NO_PROXY должен содержать 'z.ai' (точный хост): {np}"
    assert ".z.ai" in hosts, f"CODEX_NO_PROXY должен содержать '.z.ai' (поддомены): {np}"


def test_codex_no_proxy_preserves_loopback():
    """z.ai добавляется К loopback, не заменяет его: localhost/127.0.0.1/::1 остаются.

    Loopback нужен Codex→moonbridge (слушает на 127.0.0.1), z.ai — moonbridge→api.z.ai. Оба класса
    хостов обязательны в одном NO_PROXY."""
    np = srouter.CODEX_NO_PROXY
    hosts = {h.strip().lower() for h in np.split(",") if h.strip()}
    for lb in ("localhost", "127.0.0.1", "::1"):
        assert lb in hosts, f"loopback '{lb}' сохранён в CODEX_NO_PROXY: {np}"


def test_codenv_env_script_calls_direct_first():
    """#197: srouter-codex-env.sh вычисляет NO_PROXY динамически через direct_first.no_proxy_string()
    (честный TLS-test candidate-доменов), не статичным литералом.

    Скрипт НЕ рендерится через плейсхолдеры при install (запускается in-place из env.root/
    launchagents/, как health.py у watchdog) — сам резолвит ROOT_DIR, вызывает Python-модуль
    direct_first. Единый источник правды теперь direct_first.no_proxy_string() (не строковый
    литерал, дублирующий CODEX_NO_PROXY, issue #195 root — drift между двумя копиями)."""
    script = Path(__file__).resolve().parent.parent / "launchagents" / "srouter-codex-env.sh"
    text = script.read_text(encoding="utf-8")
    assert "launchctl setenv NO_PROXY" in text, "скрипт выставляет NO_PROXY в gui-домен"
    assert "direct_first" in text, "скрипт вызывает direct_first (не хардкодит NO_PROXY литералом)"
    assert "no_proxy_string" in text


def test_codenv_env_script_sets_proxy_before_blocking_probe():
    """#197 cycle-review (Codex critical): PROXY-переменные (launchctl setenv HTTP_PROXY ...) ДОЛЖНЫ
    выставляться ДО блокирующего direct_first.no_proxy_string() probe.

    Boot-race: no_proxy_string() делает serial curl per-domain (до MAX_CANDIDATE_DOMAINS x max_time
    ≈ сотни секунд worst-case). При RunAtLoad на буте launchctl-env пуст; если PROXY-переменные
    ставятся ПОСЛЕ probe, GUI-процессы (Codex.app/ChatGPT.app), стартующие в окне probe, унаследуют
    ОТСУТСТВИЕ SOCKS-прокси → прямой egress под GFW (утечка реального IP + недоступность vendor).
    launchctl setenv не ретроактивен → уже запущенные процессы не чинятся при последующем setenv.

    Инвариант (канон fail-closed-proxy-down, srouter-critical-infra-24-7): PROXY-переменные попадают
    в launchctl-env НЕМЕДЛЕННО, окно без них минимально. Единственный сетевой вызов (probe) не должен
    задерживать установку PROXY — он нужен только для NO_PROXY (логически независим от PROXY-vars)."""
    script = Path(__file__).resolve().parent.parent / "launchagents" / "srouter-codex-env.sh"
    # Только строки кода (без комментариев) — иначе якоря цепляются за текст docstring-комментария.
    code_lines = [ln for ln in script.read_text(encoding="utf-8").splitlines()
                  if not ln.lstrip().startswith("#")]

    def _first_line(substr):
        for i, ln in enumerate(code_lines):
            if substr in ln:
                return i
        return -1

    # Установка PROXY-переменных: цикл `for key in HTTP_PROXY ...; do launchctl setenv "$key" ...`.
    proxy_setenv_line = _first_line('launchctl setenv "$key"')
    assert proxy_setenv_line != -1, "скрипт должен выставлять PROXY-переменные через launchctl setenv"
    # Блокирующий probe = присвоение NO_PROXY из вызова no_proxy_string() (serial curl).
    probe_line = _first_line("no_proxy_string")
    assert probe_line != -1, "скрипт вызывает direct_first.no_proxy_string() для динамического NO_PROXY"
    assert proxy_setenv_line < probe_line, (
        "PROXY-переменные (launchctl setenv HTTP_PROXY) ДОЛЖНЫ выставляться ДО блокирующего "
        "direct_first.no_proxy_string() probe — иначе GUI-процессы в окне probe при загрузке "
        "унаследуют отсутствие прокси → прямой egress под GFW (Codex critical #197 cycle-review). "
        f"proxy_setenv@code-line{proxy_setenv_line} должен быть < probe@code-line{probe_line}"
    )


def test_codenv_env_script_fallback_contains_zai_direct():
    """srouter-codex-env.sh fallback (Python/detect недоступен) содержит z.ai,.z.ai — regression-гвард
    #195: даже при сбое Python NO_PROXY не должен потерять z.ai (канон srouter-critical-infra-24-7,
    zai-direct-no-proxy — z.ai всегда direct, независимо от готовности Python-слоя)."""
    script = Path(__file__).resolve().parent.parent / "launchagents" / "srouter-codex-env.sh"
    text = script.read_text(encoding="utf-8")
    import re
    # Fallback-присвоение внутри if [ -z "$NO_PROXY" ]; then NO_PROXY="..."; fi
    m = re.search(r'NO_PROXY="([^"]*z\.ai[^"]*)"', text)
    assert m, f"fallback NO_PROXY литерал с z.ai не найден в скрипте: {text!r}"
    hosts = {h.strip().lower() for h in m.group(1).split(",") if h.strip()}
    assert "z.ai" in hosts and ".z.ai" in hosts, \
        f"fallback NO_PROXY содержит z.ai,.z.ai (регресс-гвард #195): {m.group(1)}"
    for lb in ("localhost", "127.0.0.1", "::1"):
        assert lb in hosts, f"fallback NO_PROXY сохраняет loopback '{lb}': {m.group(1)}"


def test_codenv_env_script_resolves_root_dir_without_placeholders():
    """Скрипт НЕ содержит нерендеренных плейсхолдеров __SROUTER_*__ — исключает класс багов
    «placeholder не отрендерен → error 5» (PR #189 регрессия). Сам резолвит ROOT_DIR."""
    script = Path(__file__).resolve().parent.parent / "launchagents" / "srouter-codex-env.sh"
    text = script.read_text(encoding="utf-8")
    assert "__SROUTER_" not in text, "скрипт не должен содержать нерендеренные плейсхолдеры"
    assert "ROOT_DIR=" in text


def test_codenv_plist_comment_mentions_zai():
    """com.srouter.codenv.plist комментарий описывает реальный NO_PROXY (z.ai,.z.ai).

    Документация в plist = контракт для оператора; устаревший комментарий вводит в заблуждение
    (как #165 — parity требует sync docs со значением)."""
    plist = Path(__file__).resolve().parent.parent / "launchagents" / "com.srouter.codenv.plist"
    text = plist.read_text(encoding="utf-8")
    assert "z.ai" in text, f"plist комментарий описывает z.ai в NO_PROXY: {plist.name}"


# ============ issue #250: guard — LaunchAgent НЕ ставится с путём в эфемерный AO-worktree =========
#
# Инцидент 2026-07-30: `com.srouter.codenv` указывал на
# `~/.ao/data/worktrees/srouter/srouter-117/launchagents/srouter-codex-env.sh`. Worktree стёрт →
# /bin/sh не находит скрипт → exit 127 при каждом из 1419 запусков, Codex молча без SOCKS5.
# Корень: `_install_launchctl_env` рендерит plist из `env.root`; install, запущенный ИЗ AO-worktree,
# сажает мину замедленного действия — эфемерный каталог как цель ПОСТОЯННОГО LaunchAgent.
# Канон ao-worktree-vs-main-worktree-confusion.

def _worktree_env(tmp_path, home):
    """InstallEnv с root ВНУТРИ .ao/data/worktrees/ — реальные шаблоны копируются туда."""
    import shutil
    import install_lib
    root = home / ".ao" / "data" / "worktrees" / "srouter" / "srouter-117"
    root.mkdir(parents=True)
    repo = Path(__file__).resolve().parent.parent
    shutil.copytree(repo / "launchagents", root / "launchagents")
    return install_lib.InstallEnv(
        root=root,
        prefix=tmp_path / "homebrew",
        state_path=tmp_path / "srouter.local.json",
        launchagent_dir=home / "Library" / "LaunchAgents",
        python_bin="/usr/bin/python3",
        now="2026-07-04T00-00-00Z",
    )


def test_install_launchctl_env_refuses_ao_worktree_root(monkeypatch, tmp_path):
    """install из AO-worktree → LaunchAgent НЕ ставится (fail-closed), plist не создан.

    Мина: worktree эфемерен, LaunchAgent постоянен. Молчаливая установка = отложенный exit 127
    (issue #250). Лучше явный отказ при install, чем 1419 падений в тишине после удаления worktree.
    """
    home = _mock_home(monkeypatch, tmp_path)
    env = _worktree_env(tmp_path, home)
    runner = _fake_runner()

    note = srouter._install_launchctl_env(env, runner)

    plist = home / "Library" / "LaunchAgents" / f"{srouter.CODEX_ENV_LABEL}.plist"
    assert not plist.exists(), f"plist с worktree-путём НЕ должен создаваться; note={note}"
    assert "worktree" in note.lower(), f"note объясняет причину отказа; got {note}"
    assert not any(len(c) > 1 and c[1] == "bootstrap" for c in runner.calls), \
        "bootstrap не вызывается — job не загружаем вовсе"


def test_install_launchctl_env_allows_canonical_root(monkeypatch, tmp_path):
    """Регресс-гард: канонический root (не worktree) по-прежнему ставится — guard не ломает норму."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    runner = _fake_runner()

    note = srouter._install_launchctl_env(env, runner)

    assert "загружен" in note, f"канонический root ставится как раньше: {note}"
    assert (home / "Library" / "LaunchAgents" / f"{srouter.CODEX_ENV_LABEL}.plist").exists()
