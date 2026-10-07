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
    # Шаблон рендерит label + путь к скрипту residual-чистки.
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


def test_codenv_env_script_no_unrendered_placeholders():
    """Скрипт НЕ содержит нерендеренных плейсхолдеров __SROUTER_*__ — исключает класс багов
    «placeholder не отрендерен → error 5» (PR #189 регрессия). Запускается in-place из env.root."""
    script = Path(__file__).resolve().parent.parent / "launchagents" / "srouter-codex-env.sh"
    text = script.read_text(encoding="utf-8")
    assert "__SROUTER_" not in text, "скрипт не должен содержать нерендеренные плейсхолдеры"


def test_codenv_plist_comment_describes_cleanup_role():
    """com.srouter.codenv.plist комментарий описывает РЕАЛЬНУЮ роль скрипта (residual-чистка,
    контракт строгого whitelist 2026-10-07), а не устаревший посев прокси. Документация в
    plist = контракт для оператора; устаревший комментарий вводит в заблуждение (как #165)."""
    plist = Path(__file__).resolve().parent.parent / "launchagents" / "com.srouter.codenv.plist"
    text = plist.read_text(encoding="utf-8")
    assert "unsetenv" in text.lower(), (
        f"plist комментарий описывает residual-чистку (unsetenv), не посев: {plist.name}"
    )
    assert "8118" not in text and "10808" not in text, (
        f"plist комментарий не описывает посев прокси-плеч (контракт: ambient-прокси не сеется): "
        f"{plist.name}"
    )


# ============ issue #340 → контракт 2026-10-07: УСТАРЕЛО, оставлено как история ============
# БАННЕР ОПИСЫВАЕТ СНЯТЫЙ КОНТРАКТ: «терминальное privoxy-плечо» (посев scheme-ключей в
# gui-домен) отменён контрактом маршрутизации 2026-10-07 — ambient env-прокси не сеется ни в
# один слой, codenv-агент теперь ТОЛЬКО residual-чистка. Эмпирика #340 сохраняет ценность:
# 1. requests (vendored pip) и reqwest (Codex Rust app-server) выбирают scheme-ключ
#    (HTTPS_PROXY) ПРЕДПОЧТИТЕЛЬНЕЕ ALL_PROXY (reqwest src/proxy.rs get_from_environment:
#    «Overwritten by the more specific HTTP_PROXY»; requests.utils.select_proxy: scheme → all).
#    Следствия: (а) удаление одного только ALL_PROXY из gui-домена pip НЕ чинит —
#    HTTPS_PROXY=socks5h сам по себе даёт тот же TypeError PoolKey; (б) ALL_PROXY в gui-домене
#    избыточен для reqwest-потребителя.
# 2. Живая эмпирика (2026-09-05, ps eww app-server PID): текущий Rust app-server ChatGPT.app
#    (`codex app-server`) спавнится ChatGPT.app с САНИТИЗОВАННЫМ env БЕЗ прокси-переменных —
#    launchctl gui-домен до него не доходит. CLI-codex wrapper'ы ставят socks5h:10808 себе
#    точечно (privoxy рвёт WS #120) — не тронуты.
# Текущее решение: scheme-ключи НЕ ставятся, чистятся ВСЕ 8 ключей (scheme+all+NO_PROXY, оба
# регистра — CODEX_LAUNCHCTL_UNSET_KEYS): setenv не ретроактивен, residual старых посевов иначе
# живёт в gui-домене вечно. Живой контракт — tests/test_codex_env_contract.py.
def test_codenv_env_script_unsets_all_proxy_residual():
    """Контракт 2026-10-07: скрипт каждый прогон снимает ВСЕ прокси-ключи gui-домена
    (scheme+all, оба регистра).

    launchctl setenv не ретроактивен и не снимает то, чего не ставит: старые версии скрипта
    сеяли socks5h ALL_PROXY/all_proxy (#331/#340) и privoxy 8118 scheme-ключи (#340) — без
    цикла unsetenv residual жил бы в gui-домене вечно. Поведенческий контракт (никаких setenv,
    все шесть unsetenv) — tests/test_codex_env_contract.py; здесь — content-гвард списка ключей."""
    script = Path(__file__).resolve().parent.parent / "launchagents" / "srouter-codex-env.sh"
    code = "\n".join(ln for ln in script.read_text(encoding="utf-8").splitlines()
                     if not ln.lstrip().startswith("#"))
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        assert key in code, f"ключ {key} отсутствует в residual-чистке; код: {code}"


def test_codex_launchctl_unset_keys_include_all_proxy():
    """#340 → контракт 2026-10-07: UNSET-список покрывает все шесть прокси-ключей scheme+all
    (residual старых установок снимается при uninstall и в periodic-чистке агента)."""
    unset_keys = set(srouter.CODEX_LAUNCHCTL_UNSET_KEYS)
    six_proxy_keys = {"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
                      "ALL_PROXY", "all_proxy"}
    assert six_proxy_keys <= unset_keys, \
        f"все шесть прокси-ключей обязаны сниматься (residual старых установок): {unset_keys}"


def test_remove_launchctl_env_unset_keys_follow_unset_list(monkeypatch, tmp_path):
    """uninstall итерирует CODEX_LAUNCHCTL_UNSET_KEYS (включая ALL_PROXY/all_proxy)."""
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_launchctl_env(_env(tmp_path), _fake_runner())
    runner = _real_launchctl_runner({})

    srouter._remove_launchctl_env(runner)

    keys = {c[5] for c in runner.calls
            if len(c) > 5 and c[1] == "asuser" and c[4] == "unsetenv"}
    assert set(srouter.CODEX_LAUNCHCTL_UNSET_KEYS) <= keys, \
        f"uninstall снимает все ключи UNSET-списка (включая ALL_PROXY/all_proxy): {keys}"


def test_codenv_env_script_propagates_launchctl_failures():
    """#340 (Codex cycle-review): сбой setenv/unsetenv → ненулевой exit скрипта, не маскировка.

    LaunchAgent job-check читает last exit code: скрипт, «проглотивший» сбой launchctl (rc=0
    при провале unsetenv residual / setenv proxy), выглядит здоровым, пока gui-домен остаётся
    с pip-ломающим плечом или без прокси вовсе. Канон: fail-closed + noisy-log-better-than-no-log
    (детерминированный сигнал в exit code лучше молчаливого rc=0)."""
    script = Path(__file__).resolve().parent.parent / "launchagents" / "srouter-codex-env.sh"
    code = "\n".join(ln for ln in script.read_text(encoding="utf-8").splitlines()
                     if not ln.lstrip().startswith("#"))
    assert "FAIL=0" in code and "FAIL=1" in code, "скрипт накапливает статус сбоев launchctl"
    assert "exit" in code, "скрипт отдаёт накопленный статус в exit code"
    # Каждый launchctl вызов в коде гейтится `|| FAIL=1` — ни одного «голого» вызова.
    bare = [ln for ln in code.splitlines()
            if ln.strip().startswith("launchctl ") and "FAIL=1" not in ln]
    assert not bare, f"launchctl-вызовы без `|| FAIL=1`: {bare}"


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


def test_install_launchctl_env_guard_resolves_relative_worktree_path(monkeypatch, tmp_path):
    """Относительный root внутри worktree тоже отвергается (guard резолвит, не сверяет строку).

    Cycle-review PR #262 (Codex): guard звал resolve() ТОЛЬКО для существующего файла, иначе сверял
    сырую строку. Относительный путь '.ao/data/worktrees/...' не содержит ведущего '/' → маркер
    '/.ao/data/worktrees/' не совпадал → мина проходила молча. False negative на ровном месте.
    """
    import shutil
    import install_lib
    home = _mock_home(monkeypatch, tmp_path)
    abs_root = home / ".ao" / "data" / "worktrees" / "srouter" / "srouter-117"
    abs_root.mkdir(parents=True)
    shutil.copytree(Path(__file__).resolve().parent.parent / "launchagents", abs_root / "launchagents")
    monkeypatch.chdir(home)
    env = install_lib.InstallEnv(
        root=Path(os.path.relpath(abs_root, home)),  # ОТНОСИТЕЛЬНЫЙ путь — без ведущего '/'
        prefix=tmp_path / "homebrew",
        state_path=tmp_path / "srouter.local.json",
        launchagent_dir=home / "Library" / "LaunchAgents",
        python_bin="/usr/bin/python3",
        now="2026-07-04T00-00-00Z",
    )

    note = srouter._install_launchctl_env(env, _fake_runner())

    assert "worktree" in note.lower(), f"относительный worktree-путь тоже мина; got {note}"
    assert not (home / "Library" / "LaunchAgents" / f"{srouter.CODEX_ENV_LABEL}.plist").exists()


def test_install_launchctl_env_guard_no_false_positive_on_dotdot_escape(monkeypatch, tmp_path):
    """Путь, ТЕКСТОВО содержащий маркер, но резолвящийся ЗА worktree → установка разрешена.

    Cycle-review PR #262 (Codex): '<...>/.ao/data/worktrees/../canonical' содержит маркер как
    подстроку, хотя '..' выводит реальный путь наружу. Подстрочная сверка давала ложный отказ —
    канон loose-validator (сверяем резолвнутый путь, не написание строки)."""
    import shutil
    import install_lib
    home = _mock_home(monkeypatch, tmp_path)
    canonical = home / ".ao" / "data" / "canonical-srouter"
    canonical.mkdir(parents=True)
    shutil.copytree(Path(__file__).resolve().parent.parent / "launchagents", canonical / "launchagents")
    # Написание содержит '/.ao/data/worktrees/', но '..' резолвится в canonical-srouter.
    tricky = home / ".ao" / "data" / "worktrees" / ".." / "canonical-srouter"
    env = install_lib.InstallEnv(
        root=tricky,
        prefix=tmp_path / "homebrew",
        state_path=tmp_path / "srouter.local.json",
        launchagent_dir=home / "Library" / "LaunchAgents",
        python_bin="/usr/bin/python3",
        now="2026-07-04T00-00-00Z",
    )

    note = srouter._install_launchctl_env(env, _fake_runner())

    # Проверяем ИМЕННО guard по его собственной формулировке отказа: он не должен сработать на
    # пути, резолвящемся за пределы worktree. Сверять по подстроке "worktree" во ВСЁМ note нельзя —
    # сам путь её содержит и попадает в текст любой другой ошибки (то же ловушка loose-validator,
    # от которой guard и лечили: решение по резолвнутому пути, а не по написанию строки).
    assert "эфемерный AO-worktree" not in note, f"guard НЕ должен отвергать путь вне worktree; got {note}"
