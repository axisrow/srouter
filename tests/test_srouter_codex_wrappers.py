"""ТДД-тесты srouter codex SOCKS5-wrappers + launchctl env (LaunchAgent plist) + PATH.

Codex (CLI + App) работает стабильно только через SOCKS5 (xray 10808) минуя privoxy (портит WS).
srouter install ставит ~/bin/codex-srouter + ~/bin/codex-app-proxy + LaunchAgent env-plist + ~/bin в PATH;
uninstall убирает. Канон — _install_ppp_hook/_remove_ppp_hook (best-effort, marker-gate «чужое не
трогать», строка-статус).
"""
import os
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


def _cli_wrapper_name():
    """Имя CLI-wrapper'а в ~/bin (первая запись CODEX_WRAPPERS) — единый источник правды."""
    return srouter.CODEX_WRAPPERS[0][0]


def _cli_wrapper_path():
    """Путь к CLI-wrapper в ~/bin (для тестов — через канон _codex_wrapper_path)."""
    return srouter._codex_wrapper_path(_cli_wrapper_name())


# ============================ _install/_remove_codex_wrappers ============================
def test_install_creates_wrappers(monkeypatch, tmp_path):
    """install ставит ~/bin/codex-srouter + ~/bin/codex-app-proxy с маркером + socks5h + executable.

    Issue #169: CLI-wrapper переименован codex → codex-srouter — убрать коллизию неймспейса
    (wrapper и real binary оба звались codex). Имя берётся из CODEX_WRAPPERS (единый источник)."""
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
    # Issue #169 — rename: CLI-wrapper файл называется codex-srouter, НЕ codex (коллизия с real binary).
    assert _cli_wrapper_name() == "codex-srouter", "CLI-wrapper переименован в codex-srouter (#169)"
    assert (bin_dir / "codex-srouter").exists(), "wrapper под именем codex-srouter"
    assert not (bin_dir / "codex").exists(), "старого ~/bin/codex НЕТ (rename, коллизия устранена)"
    # CLI wrapper: socks5h (DNS via proxy для GFW) + env -u санирует унаследованный прокси
    # (от ~/.claude/settings.json env) + exec реального codex. Issue #96: без очистки privoxy
    # из окружения Codex идёт через 8118 → privoxy режёт WS → "Falling back to HTTPS".
    cli_text = (bin_dir / "codex-srouter").read_text(encoding="utf-8")
    assert "socks5h://" in cli_text, "CLI использует socks5h (DNS via proxy)"
    assert "exec " in cli_text, "CLI exec'ает реальный codex"
    # env -u для всех 8 прокси-переменных (верхний/нижний регистр + ALL_PROXY + NO_PROXY).
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                "http_proxy", "https_proxy", "all_proxy",
                "NO_PROXY", "no_proxy"):
        assert f"-u {var}" in cli_text, f"CLI очищает унаследованную {var} через env -u (#96)"
    # НИ ОДНОГО упоминания privoxy/8118 — launcher не должен тащить HTTP-прокси.
    assert "8118" not in cli_text, "CLI launcher не содержит privoxy-порт (#96)"
    assert "127.0.0.1:10808" in cli_text, "CLI指向 xray SOCKS5 10808"
    # App wrapper: --proxy-server (Chromium flag, env от install-plist не дублируется).
    app_text = (bin_dir / "codex-app-proxy").read_text(encoding="utf-8")
    assert "--proxy-server=socks5://" in app_text, "App передаёт Chromium --proxy-server"


def test_install_marker_gate_foreign_not_touched(monkeypatch, tmp_path):
    """Чужой ~/bin/codex-srouter (без маркера srouter) — НЕ перезаписывать (unmarked → WARN, #112 Часть 4)."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    foreign = "# my custom codex wrapper\n#!/bin/sh\nexec /usr/local/bin/codex\n"
    (home / "bin" / "codex-srouter").write_text(foreign, encoding="utf-8")

    note = srouter._install_codex_wrappers(env)

    # #112 Часть 4: unmarked wrapper (нет current, нет legacy) → WARN «без srouter-маркера — не трогаем».
    # Формулировка migration-aware (отличает unmarked от чисто-foreign для оператора), семантика та же.
    assert "не трогаем" in note.lower() or "чуж" in note.lower(), \
        f"unmarked/foreign wrapper → WARN, не перезаписывать: {note}"
    assert (home / "bin" / "codex-srouter").read_text(encoding="utf-8") == foreign


def test_cli_launcher_renders_configured_proxy(monkeypatch, tmp_path):
    """Launcher рендерит __SROUTER_CODEX_PROXY_URL__/__SROUTER_CODEX_NO_PROXY__ из модульных
    констант, а не хардкодит 10808. Меняем источник — меняется launcher (#96, anti-drift)."""
    _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    monkeypatch.setattr(srouter, "_CODEX_PROXY_URL", "socks5h://127.0.0.1:99999")
    monkeypatch.setattr(srouter, "CODEX_NO_PROXY", "localhost,internal")

    srouter._install_codex_wrappers(env)
    cli_text = (Path.home() / "bin" / _cli_wrapper_name()).read_text(encoding="utf-8")

    assert "127.0.0.1:99999" in cli_text, "launcher использует отрендеренный _CODEX_PROXY_URL"
    assert "internal" in cli_text, "launcher использует отрендеренный CODEX_NO_PROXY"
    assert "10808" not in cli_text, "launcher НЕ хардкодит 10808 литералом"


def _install_with_fake_codex(monkeypatch, tmp_path, fake_bin):
    """Общий хелпер интеграционных тестов launcher'а. monkeypatch _codex_bin_path → fake_bin как
    install-time GATE (есть ли codex вообще), и делает fake_bin достижимым как `codex` в PATH
    вызывающего — wrapper с #144 runtime-резолвит binary по PATH минуя себя, путь НЕ вшивается.
    Копия fake_bin → tmp_path/fakebin/codex, fakebin добавлен в PATH через monkeypatch.setenv
    (наследуется env={**os.environ, ...}). Возвращает путь к wrapper."""
    _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    monkeypatch.setattr(srouter, "_codex_bin_path", lambda: str(fake_bin))
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    # Копия под именем codex — wrapper ищет именно `codex` в PATH.
    (fakebin / "codex").write_text(fake_bin.read_text(encoding="utf-8"), encoding="utf-8")
    (fakebin / "codex").chmod(0o755)
    # ~/bin ПЕРЕД fakebin: проверяем, что wrapper пропускает себя и берёт fakebin/codex (антирекурсия).
    monkeypatch.setenv("PATH", f"{Path.home() / 'bin'}:{fakebin}:/usr/bin:/bin")
    srouter._install_codex_wrappers(env)
    return Path.home() / "bin" / _cli_wrapper_name()


def test_cli_launcher_clears_inherited_privoxy_env(monkeypatch, tmp_path):
    """Интеграционный (#96 core): запуск ~/bin/codex-srouter с унаследованным privoxy-окружением →
    дочерний codex видит SOCKS5, privoxy (8118) отсутствует. Доказывает env -u работает.

    Fake-codex дампит своё окружение в JSON — проверяем значения 8 переменных.
    """
    import json
    import subprocess
    out_file = tmp_path / "child-env.json"
    fake_bin = tmp_path / "fake-codex"
    fake_bin.write_text(
        "#!/bin/sh\n"
        f"python3 -c \"import json,os; "
        f"json.dump(dict((k,os.environ.get(k,'')) for k in "
        f"['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy',"
        f"'NO_PROXY','no_proxy']), open('$OUT','w'))\"\n",
        encoding="utf-8")
    fake_bin.chmod(0o755)
    wrapper = _install_with_fake_codex(monkeypatch, tmp_path, fake_bin)
    # Наследуем privoxy-окружение (как от ~/.claude/settings.json env).
    inherited = {
        "HTTP_PROXY": "http://127.0.0.1:8118", "HTTPS_PROXY": "http://127.0.0.1:8118",
        "ALL_PROXY": "http://127.0.0.1:8118",
        "http_proxy": "http://127.0.0.1:8118", "https_proxy": "http://127.0.0.1:8118",
        "all_proxy": "http://127.0.0.1:8118",
        "NO_PROXY": "localhost,127.0.0.1,::1,z.ai", "no_proxy": "localhost,127.0.0.1,::1,z.ai",
        "OUT": str(out_file),
    }
    subprocess.run([str(wrapper), "arg1"], env={**os.environ, **inherited},
                   check=True, timeout=10)
    child = json.loads(out_file.read_text(encoding="utf-8"))
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
              "http_proxy", "https_proxy", "all_proxy"):
        assert child[k] == "socks5h://127.0.0.1:10808", \
            f"{k} = SOCKS5 в дочернем процессе (не унаследованный privoxy): {child[k]}"
        assert "8118" not in child[k], f"{k} не содержит privoxy-порт"
    assert "z.ai" not in child["NO_PROXY"], "NO_PROXY очищен от чужих z.ai-исключений"


def test_cli_launcher_forwards_argv_verbatim(monkeypatch, tmp_path):
    """argv доходит до codex-бинаря как есть: пробелы, кавычки, glob-символы, ведущие дефисы."""
    import subprocess
    argv_file = tmp_path / "argv.txt"
    fake_bin = tmp_path / "fake-codex"
    fake_bin.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$@\" > {argv_file}\n", encoding="utf-8")
    fake_bin.chmod(0o755)
    wrapper = _install_with_fake_codex(monkeypatch, tmp_path, fake_bin)
    args = ["--flag", "with space", "with'quote", "*.glob", "--", "-leading-dash"]
    subprocess.run([str(wrapper), *args], env={**os.environ, "OUT": "x"},
                   check=True, timeout=10)
    forwarded = argv_file.read_text(encoding="utf-8").splitlines()
    assert forwarded == args, f"argv проброшен verbatim: {forwarded}"


def test_cli_launcher_propagates_exit_status(monkeypatch, tmp_path):
    """exec пробрасывает exit-код реального codex (например 23) — без потерь."""
    import subprocess
    fake_bin = tmp_path / "fake-codex"
    fake_bin.write_text("#!/bin/sh\nexit 23\n", encoding="utf-8")
    fake_bin.chmod(0o755)
    wrapper = _install_with_fake_codex(monkeypatch, tmp_path, fake_bin)
    rc = subprocess.run([str(wrapper)], env={**os.environ, "OUT": "x"}).returncode
    assert rc == 23, f"launcher возвращает реальный exit-код: {rc}"


def test_install_idempotent(monkeypatch, tmp_path):
    """Повторный install на srouter-managed wrapper — обновляет, не падает."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    srouter._install_codex_wrappers(env)
    first = (home / "bin" / _cli_wrapper_name()).read_text(encoding="utf-8")
    srouter._install_codex_wrappers(env)  # повторный
    second = (home / "bin" / _cli_wrapper_name()).read_text(encoding="utf-8")
    assert first == second, "повторный install = idempotent"


def test_remove_deletes_managed(monkeypatch, tmp_path):
    """uninstall удаляет wrappers если они srouter-managed."""
    home = _mock_home(monkeypatch, tmp_path)
    srouter._install_codex_wrappers(_env(tmp_path))
    assert (home / "bin" / _cli_wrapper_name()).exists()

    note = srouter._remove_codex_wrappers()

    assert "удалён" in note.lower()
    assert not (home / "bin" / _cli_wrapper_name()).exists()
    assert not (home / "bin" / "codex-app-proxy").exists()


def test_remove_marker_gate_foreign(monkeypatch, tmp_path):
    """Чужой wrapper (без маркера) — НЕ удалять."""
    home = _mock_home(monkeypatch, tmp_path)
    foreign = "# my custom\n#!/bin/sh\nexec codex\n"
    (home / "bin" / _cli_wrapper_name()).write_text(foreign, encoding="utf-8")

    note = srouter._remove_codex_wrappers()

    assert "чуж" in note.lower()
    assert (home / "bin" / _cli_wrapper_name()).read_text(encoding="utf-8") == foreign


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


# ============================ _install/_remove_codex_zsh_function (issue #96) ============================
# Shell-функция codex() в ~/.zshrc вызывает ~/bin/codex-srouter по абсолютному пути — тогда порядок brew в
# PATH не важен (функция всегда бьёт binary). Без неё wrapper #83 проигрывает /opt/homebrew/bin/codex.
def test_codex_function_installed_in_zshrc(monkeypatch, tmp_path):
    """install добавляет managed-блок codex() с парными маркерами, вызывающий ~/bin/codex-srouter.

    Issue #169: функция зовёт переименованный wrapper ~/bin/codex-srouter (имя codex освобождено
    под real binary — коллизия неймспейса устранена)."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    zshrc = home / ".zshrc"
    zshrc.write_text("export PATH=/usr/local/bin:$PATH\n", encoding="utf-8")

    note = srouter._install_codex_zsh_function(env)

    assert "установ" in note.lower() or "добав" in note.lower(), f"install должен éxito: {note}"
    content = zshrc.read_text(encoding="utf-8")
    assert srouter.ZSHRC_CODEX_FUNC_MARKER_BEGIN in content, "begin-маркер присутствует"
    assert srouter.ZSHRC_CODEX_FUNC_MARKER_END in content, "end-маркер присутствует"
    assert 'function codex' in content, "определение function codex"
    assert '"$HOME/bin/codex-srouter" "$@"' in content, "вызов по абсолютному пути ~/bin/codex-srouter (#169)"
    # guard: не перекрывает молча, если рядом уже есть определение
    assert '${+aliases[codex]}' in content and '${+functions[codex]}' in content
    # чужой export сохранён
    assert '/usr/local/bin' in content


def test_codex_function_install_idempotent(monkeypatch, tmp_path):
    """Повторный install оставляет ровно один managed-блок."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    zshrc = home / ".zshrc"
    zshrc.write_text("export FOO=1\n", encoding="utf-8")

    srouter._install_codex_zsh_function(env)
    srouter._install_codex_zsh_function(env)

    content = zshrc.read_text(encoding="utf-8")
    assert content.count(srouter.ZSHRC_CODEX_FUNC_MARKER_BEGIN) == 1, "один begin-маркер"
    assert content.count(srouter.ZSHRC_CODEX_FUNC_MARKER_END) == 1, "один end-маркер"
    assert content.count('function codex') == 1, "одно определение функции"
    assert 'export FOO=1' in content, "чужой контент сохранён"


def test_codex_function_preserves_foreign_alias(monkeypatch, tmp_path):
    """Fail-closed: чужой `alias codex=…` без srouter-маркера → блок НЕ добавлен, alias неизменён."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    zshrc = home / ".zshrc"
    zshrc.write_text("alias codex='/usr/local/bin/my-codex'\n", encoding="utf-8")
    before = zshrc.read_text(encoding="utf-8")

    note = srouter._install_codex_zsh_function(env)

    assert "чуж" in note.lower() or "конфликт" in note.lower() or "не добав" in note.lower(), \
        f"должен отказаться перекрывать чужой alias: {note}"
    assert zshrc.read_text(encoding="utf-8") == before, "чужой alias не изменён"
    assert srouter.ZSHRC_CODEX_FUNC_MARKER_BEGIN not in zshrc.read_text(encoding="utf-8"), \
        "managed-блок не добавлен при конфликте"


def test_codex_function_preserves_foreign_function(monkeypatch, tmp_path):
    """Fail-closed: чужая `function codex {}` → блок НЕ добавлен."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    zshrc = home / ".zshrc"
    zshrc.write_text("function codex { /usr/local/bin/my-codex \"$@\"; }\n", encoding="utf-8")
    before = zshrc.read_text(encoding="utf-8")

    note = srouter._install_codex_zsh_function(env)

    assert any(w in note.lower() for w in ("чуж", "конфликт", "не добав")), \
        f"должен отказаться перекрывать чужую функцию: {note}"
    assert zshrc.read_text(encoding="utf-8") == before
    assert srouter.ZSHRC_CODEX_FUNC_MARKER_BEGIN not in zshrc.read_text(encoding="utf-8")


def test_codex_function_uninstall_removes_only_managed_block(monkeypatch, tmp_path):
    """uninstall удаляет ТОЛЬКО парный begin…end блок, чужой контент (включая export PATH) сохранён."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    zshrc = home / ".zshrc"
    zshrc.write_text(
        'export PATH=/usr/local/bin:$PATH\n'
        '# user comment\n', encoding="utf-8")
    srouter._install_codex_zsh_function(env)
    assert srouter.ZSHRC_CODEX_FUNC_MARKER_BEGIN in zshrc.read_text(encoding="utf-8")

    note = srouter._remove_codex_zsh_function()

    assert "удал" in note.lower() or "снят" in note.lower() or "убран" in note.lower(), f"{note}"
    content = zshrc.read_text(encoding="utf-8")
    assert srouter.ZSHRC_CODEX_FUNC_MARKER_BEGIN not in content, "begin убран"
    assert srouter.ZSHRC_CODEX_FUNC_MARKER_END not in content, "end убран"
    assert 'function codex' not in content, "определение функции убрано"
    assert '/usr/local/bin' in content, "чужой export сохранён"
    assert '# user comment' in content, "чужой комментарий сохранён"


def test_codex_function_uninstall_when_not_installed(monkeypatch, tmp_path):
    """zshrc без managed-блока — мягкий статус, не ошибка, чужое не трогать."""
    home = _mock_home(monkeypatch, tmp_path)
    zshrc = home / ".zshrc"
    original = "alias codex=/usr/local/bin/codex\n"
    zshrc.write_text(original, encoding="utf-8")

    note = srouter._remove_codex_zsh_function()

    assert "не был" in note.lower(), f"{note}"
    assert zshrc.read_text(encoding="utf-8") == original


def test_codex_function_malformed_marker_fails_closed(monkeypatch, tmp_path):
    """Непарный маркер (есть begin, нет end) → uninstall НЕ удаляет широко (fail-closed, safe-noop)."""
    home = _mock_home(monkeypatch, tmp_path)
    zshrc = home / ".zshrc"
    # Только begin-маркер без end (повреждённое состояние) + чужой контент после.
    broken = (
        f'{srouter.ZSHRC_CODEX_FUNC_MARKER_BEGIN}\n'
        'function codex { "$HOME/bin/codex-srouter" "$@"; }\n'
        'export PATH=/usr/local/bin:$PATH\n'  # НЕТ end-маркера
    )
    zshrc.write_text(broken, encoding="utf-8")

    note = srouter._remove_codex_zsh_function()

    content = zshrc.read_text(encoding="utf-8")
    # Не должен молча удалить чужой export, оставив begin висеть. Безопасный исход — отказ/noop.
    assert "не был" in note.lower() or "поврежд" in note.lower() or "не пар" in note.lower(), \
        f"непарный маркер → safe-noop/отказ, не широкое удаление: {note}"


def test_codex_function_beats_brew_in_path(monkeypatch, tmp_path):
    """КЛЮЧЕВОЙ (#96, PATH ≠ evidence): даже если /opt/homebrew/bin/codex ПЕРВЫЙ в PATH,
    функция codex() перехватывает вызов и доходит до ~/bin/codex-srouter (managed-launcher).

    Реальный zsh: source .zshrc с функцией, whence -w codex = function, вызов доходит до fake
    launcher через $HOME/bin/codex (не до brew-бинаря). Доказывает победу функции над PATH-порядком.

    Требует реальный zsh в окружении (макOS — есть по умолчанию; Linux CI — убедиться, что zsh
    установлен, иначе тест skip'нется и регрессию PATH-победы функции пропустит).
    """
    import shutil
    import subprocess
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    # brew-codex ПЕРВЫМ в PATH (как в проде через /etc/paths.d/homebrew). #144: wrapper runtime-резолвит
    # его по PATH минуя себя, выставляя SOCKS5 → fake-codex пишет 'managed' ТОЛЬКО если HTTP_PROXY=socks5h
    # (т.е. вызов прошёл через wrapper). Без функции zsh взял бы brew-binary напрямую, БЕЗ SOCKS5 env →
    # 'direct'. Так мы отличаем «через wrapper» от «прямой binary» — это и есть доказательство победы
    # функции над PATH-порядком при runtime-резолве (#144).
    result_file = tmp_path / "result.txt"
    brew_dir = tmp_path / "brewbin"
    brew_dir.mkdir()
    (brew_dir / "codex").write_text(
        f"#!/bin/sh\n"
        f'if [ "$HTTP_PROXY" = "socks5h://127.0.0.1:10808" ]; then '
        f'printf managed > {result_file}; else printf direct > {result_file}; fi\n',
        encoding="utf-8")
    (brew_dir / "codex").chmod(0o755)
    monkeypatch.setattr(srouter, "_codex_bin_path", lambda: str(brew_dir / "codex"))
    srouter._install_codex_wrappers(env)
    srouter._install_codex_zsh_function(env)
    zsh = shutil.which("zsh")
    if not zsh:
        import pytest
        pytest.skip("zsh недоступен — runtime-тест функции требует zsh")
    rc = subprocess.run(
        [zsh, "-c",
         f'source {home}/.zshrc; '
         f'whence -w codex; '
         f'codex --sentinel'],
        env={**os.environ,
             "PATH": f"{brew_dir}:{home}/bin:/usr/bin:/bin",
             "HOME": str(home)},
        capture_output=True, text=True, timeout=15)
    whence = rc.stdout.splitlines()[0] if rc.stdout.strip() else ""
    assert "function" in whence, f"codex должен быть функцией (не brew-binary): {whence!r}"
    assert result_file.exists(), f"вызов дошёл до codex (через функцию): stderr={rc.stderr!r}"
    assert result_file.read_text(encoding="utf-8") == "managed", \
        "вызов прошёл через wrapper (SOCKS5 выставлен) — функция перехватила, brew-binary не позван напрямую"


# ============================ issue #112 Часть 4: marker-migration (РЕШЕНИЕ 2, вариант A) ============================
# Wrappers сейчас marker-gate: текущий маркер есть → переустановить; нет → «чужой, не трогаем». При смене
# версии маркера (v1→v2) старый «свой» wrapper = «чужой» → не обновляется (залипает). Фикс: state-based
# known_markers table — install мигрирует old→current, WARN на unmarked (не adopt молча, канон fail-closed).
def _write_known_markers_state(env, surface, markers):
    """Записать detected_environment.known_markers[surface] = markers в state srouter.local.json."""
    import json
    state_path = env.state_path
    state = {}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except ValueError:
            state = {}
    detected = state.setdefault("detected_environment", {})
    table = detected.setdefault("known_markers", {})
    table[surface] = markers
    state_path.write_text(json.dumps(state), encoding="utf-8")


def test_install_upgrades_old_marker_wrapper(monkeypatch, tmp_path):
    """Часть 4: wrapper со СТАРЫМ (legacy) маркером из known_markers → install обновляет до current.

    Сценарий смены версии маркера: wrapper был установлен с old marker "# srouter-codex-wrapper-v0".
    state.known_markers.wrappers знает old+current → install распознаёт old как «свой» → перезаписывает
    с current-маркером. До #112: old ≠ current → «чужой, не трогаем» → wrapper залипал на старой версии.
    """
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    bin_dir = home / "bin"
    bin_dir.mkdir(exist_ok=True)
    current = _markers()[_cli_wrapper_name()]
    legacy = "# srouter-codex-wrapper-v0 (managed)"
    # Wrapper с LEGACY-маркером (как после смены версии маркера).
    (bin_dir / _cli_wrapper_name()).write_text(f"{legacy}\n#!/bin/sh\nexec old-codex\n", encoding="utf-8")
    # state знает old+current как наши (migration table).
    _write_known_markers_state(env, "wrappers", [current, legacy])

    note = srouter._install_codex_wrappers(env)

    wrapper_text = (bin_dir / _cli_wrapper_name()).read_text(encoding="utf-8")
    assert current in wrapper_text, "wrapper обновлён до current-маркера (миграция)"
    assert legacy not in wrapper_text, "old legacy-маркер заменён"
    assert "установ" in note.lower() or "обнов" in note.lower() or "миграц" in note.lower(), \
        f"note сообщает об обновлении/миграции: {note}"


def test_install_warns_on_unmarked_wrapper(monkeypatch, tmp_path):
    """Часть 4: wrapper БЕЗ маркера (не current, не legacy) → WARN, не adopt молча (fail-closed).

    Unmarked wrapper — не наш (нет ни current, ни legacy маркера). Канон «никогда молча не adopt»:
    WARN + не перезаписывать. Оператор удаляет вручную, если это его старый wrapper. Отличие от
    чисто-foreign: явный WARN-статус «без srouter-маркера» (migration-aware формулировка).
    """
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    bin_dir = home / "bin"
    bin_dir.mkdir(exist_ok=True)
    current = _markers()[_cli_wrapper_name()]
    legacy = "# srouter-codex-wrapper-v0 (managed)"
    # Unmarked wrapper (нет current, нет legacy маркера — произвольный чужой контент).
    unmarked = "#!/bin/sh\nexec /usr/local/bin/codex\n# user custom\n"
    (bin_dir / _cli_wrapper_name()).write_text(unmarked, encoding="utf-8")
    # state знает только current+legacy (unmarked не входит).
    _write_known_markers_state(env, "wrappers", [current, legacy])

    note = srouter._install_codex_wrappers(env)

    assert "не трогаем" in note.lower() or "чуж" in note.lower() or "маркер" in note.lower(), \
        f"unmarked wrapper → WARN, не adopt: {note}"
    assert (bin_dir / _cli_wrapper_name()).read_text(encoding="utf-8") == unmarked, "unmarked wrapper НЕ перезаписан"


def test_install_upgrades_old_marker_wrapper_without_state_uses_current_only(monkeypatch, tmp_path):
    """Часть 4 граница: НЕТ known_markers в state → wrapper с unknown-старым-маркером = unmarked (WARN).

    Без migration-table install не знает о legacy-маркерах → использует только current. Unknown-маркер
    = unmarked → WARN. Это безопасный fallback: migration требует явной регистрации legacy в state
    (через populate_known_markers при install с новой версией). Не угадываем legacy вслепую.
    """
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    bin_dir = home / "bin"
    bin_dir.mkdir(exist_ok=True)
    # НЕТ state known_markers (env.state_path не существует или пустой).
    unknown_old = "# srouter-codex-wrapper-unknown (managed)"
    (bin_dir / _cli_wrapper_name()).write_text(f"{unknown_old}\n#!/bin/sh\nexec codex\n", encoding="utf-8")

    note = srouter._install_codex_wrappers(env)

    assert "не трогаем" in note.lower() or "чуж" in note.lower() or "маркер" in note.lower(), \
        f"unknown old-маркер без state-migration-table → WARN (не угадываем legacy): {note}"


# ============================ issue #169: rename codex → codex-srouter (migration старого ~/bin/codex) ============================
# Rename убирает коллизию неймспейса (wrapper и real binary оба звались codex → natural-рекурсия #150/#144).
# После rename wrapper файл = codex-srouter; real binary так и зовётся codex. Старый ~/bin/codex от прежней
# установки (до rename) остаётся на диске → MUST мигрировать: srouter-managed (по маркеру) → удалить (устарел),
# чужой (без маркера) → НЕ трогать (канон provenance issue-112-hybrid-uninstall, «чужое не трогаем»).
def _legacy_marker():
    """Маркер wrapper'а до rename — 'codex CLI wrapper (managed)' (имя файла было codex, маркер тот же).
    Маркер НЕ менялся при rename (он идентифицирует «srouter-managed wrapper», не имя файла)."""
    return srouter.CODEX_WRAPPERS[0][2]


def test_install_removes_legacy_managed_codex_wrapper(monkeypatch, tmp_path):
    """#169 migration: старый ~/bin/codex со srouter-маркером → install УДАЛЯЕТ (устарел, заменён на codex-srouter).

    Сценарий upgrade: пользователь ставил srouter до rename → ~/bin/codex несёт наш маркер (он «наш»).
    После rename install обязан убрать устаревший ~/bin/codex (иначе коллизия неймспейса остаётся: два
    wrapper'а, один под старым именем, один под новым). Без миграции old ~/bin/codex залипал бы и продолжал
    перехватывать вызовы codex в не-zsh контекстах (foreign точка входа)."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    bin_dir = home / "bin"
    bin_dir.mkdir(exist_ok=True)
    legacy = _legacy_marker()
    # Старый ~/bin/codex от прежней установки (до rename) — несёт наш маркер → «наш».
    (bin_dir / "codex").write_text(f"{legacy}\n#!/bin/sh\nexec /usr/bin/env codex\n", encoding="utf-8")

    note = srouter._install_codex_wrappers(env)

    assert (bin_dir / "codex-srouter").exists(), "новый wrapper codex-srouter установлен"
    assert not (bin_dir / "codex").exists(), \
        f"устаревший srouter-managed ~/bin/codex удалён (migration rename #169): {note}"
    assert "миграц" in note.lower() or "удалён" in note.lower() or "обнов" in note.lower(), \
        f"note сообщает о миграции устаревшего codex: {note}"


def test_install_preserves_foreign_legacy_codex_wrapper(monkeypatch, tmp_path):
    """#169 migration fail-closed: старый ~/bin/codex БЕЗ srouter-маркера (чужой) → НЕ трогать.

    Канон provenance (#112): «чужое не трогаем». Чужой ~/bin/codex (пользовательский wrapper/скрипт без
    нашего маркера) — не наш, rename не должен его удалять. Только WARN оператору. Это симметрично
    marker-gate install/remove: маркер — единственный доказательство «наш»."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    bin_dir = home / "bin"
    bin_dir.mkdir(exist_ok=True)
    foreign_codex = "#!/bin/sh\n# my own codex launcher\nexec /usr/local/bin/codex \"$@\"\n"
    (bin_dir / "codex").write_text(foreign_codex, encoding="utf-8")

    note = srouter._install_codex_wrappers(env)

    assert (bin_dir / "codex-srouter").exists(), "новый wrapper установлен"
    assert (bin_dir / "codex").read_text(encoding="utf-8") == foreign_codex, \
        f"чужой ~/bin/codex НЕ трогаем (fail-closed provenance): {note}"
    assert "не трогаем" in note.lower() or "чуж" in note.lower() or "codex" in note.lower(), \
        f"note WARN о чужом ~/bin/codex: {note}"


def test_install_rename_idempotent_after_migration(monkeypatch, tmp_path):
    """#169 idempotency: повторный install после миграции не падает, не дублирует, не трогает уже-чистое состояние.

    Первый install мигрирует (старый codex удалён, codex-srouter поставлен). Второй install — codex уже
    нет (нечего мигрировать), codex-srouter уже на месте (idempotent install). Результат идентичен первому."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    bin_dir = home / "bin"
    bin_dir.mkdir(exist_ok=True)
    legacy = _legacy_marker()
    (bin_dir / "codex").write_text(f"{legacy}\n#!/bin/sh\nexec codex\n", encoding="utf-8")

    srouter._install_codex_wrappers(env)  # миграция
    assert not (bin_dir / "codex").exists() and (bin_dir / "codex-srouter").exists()
    after_migration = (bin_dir / "codex-srouter").read_text(encoding="utf-8")

    srouter._install_codex_wrappers(env)  # повторный — idempotent
    assert not (bin_dir / "codex").exists(), "после миграции старого codex по-прежнему нет"
    assert (bin_dir / "codex-srouter").read_text(encoding="utf-8") == after_migration, \
        "повторный install = idempotent (codex-srouter не изменился)"


def test_install_keeps_legacy_when_new_wrapper_not_installed(monkeypatch, tmp_path):
    """cycle-review FIX A (codex+claude critical): migration ТРАНЗАКЦИОННА. Если новый codex-srouter НЕ
    установлен (codex binary не найден → WARN) — устаревший managed ~/bin/codex ДОЛЖЕН ОСТАТЬСЯ.

    Без транзакционности: migration безусловно удалял legacy, даже когда замена не встала → пользователь
    терял работающий wrapper без замены (молча, install рапортовал частичный успех). Корневой инвариант:
    миграция разрешена ТОЛЬКО после подтверждения, что новый codex-srouter установлен и валиден.
    """
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    bin_dir = home / "bin"
    bin_dir.mkdir(exist_ok=True)
    legacy = _legacy_marker()
    legacy_content = f"{legacy}\n#!/bin/sh\nexec codex\n"
    (bin_dir / "codex").write_text(legacy_content, encoding="utf-8")
    # codex binary НЕ найден → install нового codex-srouter WARN'ется и не ставится.
    monkeypatch.setattr(srouter, "_codex_bin_path", lambda: "")

    note = srouter._install_codex_wrappers(env)

    assert not (bin_dir / "codex-srouter").exists(), "новый wrapper не установлен (codex bin missing)"
    assert (bin_dir / "codex").exists(), \
        f"legacy managed ~/bin/codex СОХРАНЁН (migration отменена — замена не встала): {note}"
    assert (bin_dir / "codex").read_text(encoding="utf-8") == legacy_content, "legacy не изменён"


def test_install_zsh_function_updates_stale_legacy_path(monkeypatch, tmp_path):
    """cycle-review FIX B (codex critical): существующий managed zsh-блок со СТАРЫМ путём ~/bin/codex
    (от установки до rename) → install ОБНОВЛЯЕТ его на ~/bin/codex-srouter.

    Regression upgrade-path: _install_codex_zsh_function short-circuit'ил на голом маркере
    (ZSHRC_CODEX_FUNC_MARKER_BEGIN в content → «idempotent»). Но блок звал ~/bin/codex, который
    migration удалил → функция вела в удалённый файл → `codex` в интерактивном шелле ломался, притом
    install рапортил успех. Фикс: если managed-блок зовёт устаревший путь — обновить его.
    """
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    bin_dir = home / "bin"
    bin_dir.mkdir(exist_ok=True)
    zshrc = home / ".zshrc"
    # Существующая установка (до rename): managed zsh-блок зовёт СТАРЫЙ ~/bin/codex.
    stale_block = (
        f"{srouter.ZSHRC_CODEX_FUNC_MARKER_BEGIN}\n"
        'if (( ! ${+aliases[codex]} && ! ${+functions[codex]} )); then\n'
        '  function codex {\n'
        '    "$HOME/bin/codex" "$@"\n'   # СТАРЫЙ путь
        '  }\n'
        "fi\n"
        f"{srouter.ZSHRC_CODEX_FUNC_MARKER_END}"
    )
    zshrc.write_text(stale_block, encoding="utf-8")

    note = srouter._install_codex_zsh_function(env)

    content = zshrc.read_text(encoding="utf-8")
    assert '"$HOME/bin/codex-srouter" "$@"' in content, \
        f"stale zsh-блок обновлён на codex-srouter: {note}"
    assert content.count('"$HOME/bin/codex" "$@"') == 0, \
        "старый путь ~/bin/codex в zsh-функции полностью убран"


def test_install_zsh_function_idempotent_when_already_renamed(monkeypatch, tmp_path):
    """cycle-review FIX B граница: если managed-блок уже зовёт codex-srouter (fresh install / повторный) —
    short-circuit «idempotent» корректен (обновлять нечего). Не ломает нормальный idempotent install."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    zshrc = home / ".zshrc"
    zshrc.write_text(srouter._CODEX_FUNC_BLOCK, encoding="utf-8")
    before = zshrc.read_text(encoding="utf-8")

    note = srouter._install_codex_zsh_function(env)

    assert "idempotent" in note.lower(), f"уже renam'нутый блок — idempotent: {note}"
    assert zshrc.read_text(encoding="utf-8") == before, "блок не изменён (уже актуален)"


def test_remove_also_cleans_legacy_managed_codex_wrapper(monkeypatch, tmp_path):
    """#169 uninstall cleanup: remove удаляет codex-srouter И подчищает устаревший srouter-managed ~/bin/codex.

    Сценарий: пользователь не перезапускал install после rename → ~/bin/codex (srouter-managed) остался.
    Uninstall обязан убрать ВСЁ srouter-managed (старое имя в т.ч.), иначе leftover даёт «призрак» wrapper'а
    после деинсталляции. Чужой ~/bin/codex при remove — НЕ трогаем (fail-closed, как install)."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    bin_dir = home / "bin"
    bin_dir.mkdir(exist_ok=True)
    legacy = _legacy_marker()
    # Установлено: новый codex-srouter (install) + устаревший srouter-managed ~/bin/codex (до rename).
    srouter._install_codex_wrappers(env)
    (bin_dir / "codex").write_text(f"{legacy}\n#!/bin/sh\nexec codex\n", encoding="utf-8")
    assert (bin_dir / "codex").exists() and (bin_dir / "codex-srouter").exists()

    note = srouter._remove_codex_wrappers()

    assert not (bin_dir / "codex-srouter").exists(), "codex-srouter удалён"
    assert not (bin_dir / "codex").exists(), \
        f"устаревший srouter-managed ~/bin/codex тоже удалён при uninstall (leftover cleanup): {note}"


def test_remove_keeps_foreign_legacy_codex_wrapper(monkeypatch, tmp_path):
    """#169 uninstall fail-closed: чужой ~/bin/codex (без маркера) — НЕ удалять при uninstall (как install)."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    bin_dir = home / "bin"
    bin_dir.mkdir(exist_ok=True)
    srouter._install_codex_wrappers(env)
    foreign_codex = "#!/bin/sh\n# user codex\nexec /usr/local/bin/codex \"$@\"\n"
    (bin_dir / "codex").write_text(foreign_codex, encoding="utf-8")

    note = srouter._remove_codex_wrappers()

    assert not (bin_dir / "codex-srouter").exists(), "наш codex-srouter удалён"
    assert (bin_dir / "codex").read_text(encoding="utf-8") == foreign_codex, \
        f"чужой ~/bin/codex НЕ удалён (fail-closed provenance): {note}"


# ============================ issue #150: cycle-guard через versioned env-сентинель ============================
# 3-я находка cycle-review PR #146 (воспроизведено rc=124). ДЫРА: точечные identity-чеки антирекурсии
# (realpath/inode/srouter-маркер) не замыкаются на foreign-wrapper БЕЗ маркера, делающий рекурсивный вызов
# managed wrapper'а. Managed находит foreign (нет маркера → «реальный codex») → exec'ает → foreign резолвит
# managed обратно → exec'ает managed → бесконечный цикл → rc=124 (timeout).
#
# ФИКС: cycle-state инвариант через versioned env-сентинель SROUTER_CODEX_WRAPPER_V1=<pid>:<hop>.
# При повторном входе managed wrapper в рекурсивную цепочку — обрыв с fail-loud диагностикой
# (exit 126, не 124). Покрывает ТРИ класса рекурсии: exec-цикл (PID-match), fork-цикл (hop-ceiling),
# и отличает от легитимного descendant (hop < ceiling). НЕ PATH-санitизация (отвергнута в issue #150:
# blast radius на 24/7-инфре — tools теряют ~/bin).
#
# Issue #169 (rename codex→codex-srouter) СДВИГАЕТ threat-model: managed wrapper больше не зовётся `codex`,
# значит foreign-wrapper с `exec codex "$@"` / `codex "$@"` НЕ находит managed (находит себя → foreign↔foreign
# цикл). ДО rename managed звался codex и был первым в PATH → foreign неизбежно попадал в managed → cycle-guard
# обрывал (rc=126). После rename этот ЕСТЕСТВЕННЫЙ путь устранён структурно (в этом и цель rename из epic #166),
# НО как следствие cycle-guard больше НЕ ловит foreign↔foreign self-cycle (см. test_cycle_guard_foreign_self_cycle_documented_limitation):
# foreign-wrapper, делающий рекурсивный `codex`-вызов, циклит сам с собой без повторного входа managed →
# sentinel никогда не ceiling'ится. Это availability-класс через ЧУЖОЙ wrapper в собственном PATH под контролем
# того же UID — #150 ЯВНО выводит его за scope best-effort слоя (нужен active malice / сломанный чужой wrapper
# в уже контролируемом PATH; честная fail-closed граница = PF kill-switch, #168, отдельный слой).
#
# Coverage cycle-guard ПОСЛЕ rename (#169): ловит повторный вход MANAGED codex-srouter (PID-match + hop-ceiling).
# Тесты ниже моделируют foreign, целенаправленно зовущий managed codex-srouter по имени — cycle-guard обрывает.
# Ограничение (foreign↔foreign по имени codex) — отдельный тест-документация ниже, НЕ rc=126 (вне scope).


def _install_cycle_guard_wrapper(monkeypatch, tmp_path):
    """Install managed wrapper (подход A, без вшитого binary) для cycle-guard тестов.

    _codex_bin_path → found (install-gate проходит), путь не вшивается (#144). Возвращает путь к wrapper."""
    _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    monkeypatch.setattr(srouter, "_codex_bin_path", lambda: str(tmp_path / "any-codex"))
    srouter._install_codex_wrappers(env)
    return Path.home() / "bin" / _cli_wrapper_name()


def test_foreign_wrapper_recursion_cycle_breaks_not_timeout(monkeypatch, tmp_path):
    """#150 core (красный→зелёный), адаптированный под rename #169: foreign-wrapper БЕЗ srouter-маркера,
    целенаправленно резолвящий ИМЯ managed wrapper'а (codex-srouter), вызывает цикл managed→foreign→managed.

    До rename managed wrapper звался codex → foreign `exec codex "$@"` неизбежно попадал в managed (он
    первый в PATH) → цикл. Rename (#169) структурно убирает ЭТОТ естественный путь: foreign `exec codex`
    теперь находит себя (foreign↔foreign, вне srouter). Но cycle-guard #153 обязан работать и когда
    foreign целенаправленно зовёт managed по новому имени codex-srouter — повторный вход managed обрывается
    fail-loud (exit 126, не 124). Доказывает, что rename не сломал cycle-guard.

    Сценарий: managed codex-srouter runtime-резолвит `codex` → foreign codex (без маркера → «реальный») →
    foreign `exec codex-srouter "$@"` (новое имя managed) → повторный вход managed → cycle-guard обрыв.
    """
    import subprocess
    called = tmp_path / "called.txt"
    # Реальный codex (должен НЕ запуститься в цикле — иначе цикл не оборван, просто дошёл до него).
    real_codex = tmp_path / "realdir" / "codex"
    real_codex.parent.mkdir(parents=True)
    real_codex.write_text(f"#!/bin/sh\nprintf 'real' > {called}\n", encoding="utf-8")
    real_codex.chmod(0o755)
    wrapper = _install_cycle_guard_wrapper(monkeypatch, tmp_path)
    # foreignbin/codex — ЧУЖОЙ wrapper БЕЗ srouter-маркера. Резолвит managed по новому имени codex-srouter
    # (после rename #169 foreign `exec codex` попадал бы в себя → foreign↔foreign; здесь моделируем
    # целенаправленный вызов managed, чтобы проверить cycle-guard на повторном входе managed codex-srouter).
    managed_name = _cli_wrapper_name()
    foreignbin = tmp_path / "foreignbin"
    foreignbin.mkdir()
    (foreignbin / "codex").write_text(f"#!/bin/sh\nexec {managed_name} \"$@\"\n", encoding="utf-8")
    (foreignbin / "codex").chmod(0o755)
    # ~/bin (managed codex-srouter) → foreignbin (foreign codex → зовёт codex-srouter) → realdir (real codex).
    try:
        proc = subprocess.run(
            [str(wrapper), "x"],
            env={**os.environ, "PATH": f"{Path.home() / 'bin'}:{foreignbin}:{tmp_path / 'realdir'}:/usr/bin:/bin"},
            capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        pytest.fail("foreign-wrapper (зовущий managed codex-srouter) вызвал бесконечную рекурсию "
                    "managed→foreign→managed (rc=124 timeout) — cycle-guard не замыкается (#150/#153)")
    # Цикл ОБОРВАН: не timeout. Fail-loud — понятный exit-код (не 0, не 124).
    assert proc.returncode != 0, f"cycle должен обрываться fail-loud (ненулевой exit), не успех: rc={proc.returncode}"
    assert proc.returncode != 124, "cycle-guard обязан дать диагностику, не молчаливый 124-timeout"


def test_cycle_guard_pid_scoped_not_blocking_descendant(monkeypatch, tmp_path):
    """#150 PID-scoped инвариант (cycle-review PR #153): сентинель НЕ контаминирует дерево real Codex.

    Булево-сентинель (=1) наследовался бы всему дереву процесса real Codex → блокировал каждый
    descendant-вызов managed wrapper (agent/tool spawning worker) ложным exit 126, несмотря на то, что
    это ЛЕГИТИМНЫЙ второй вход, а не цикл. Это регрессия nested-agent/orchestration (Codex confidence 0.99).

    Реальный Codex при spawn worker'а делает fork()+exec() — НОВЫЙ PID, не exec() (тот же PID). Сентинель
    хранит PID первого managed-входа ($$): exec сохраняет PID (цикл managed→foreign→managed → match →
    обрыв), fork даёт новый PID (descendant → no match → легитимный вход, переписывает сентинель своим
    PID). Этот тест моделирует descendant через fork (background subshell `(...)&` = новый процесс).
    """
    import subprocess
    import time
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    monkeypatch.setattr(srouter, "_codex_bin_path", lambda: str(tmp_path / "any-codex"))
    srouter._install_codex_wrappers(env)
    wrapper = home / "bin" / _cli_wrapper_name()
    child_marker = tmp_path / "child_ran.txt"
    real_codex_dir = tmp_path / "realdir"
    real_codex_dir.mkdir()
    # parent real-codex: fork'ает descendant (НОВЫЙ PID через background subshell), ждёт, exit 0.
    # descendant зовёт managed wrapper как agent spawning worker.
    (real_codex_dir / "codex").write_text(
        "#!/bin/sh\n"
        f'if [ "$1" = "--child" ]; then printf ok > {child_marker}; exit 0; fi\n'
        f'("{wrapper}" --child) &\n'
        f'wait\n'
        f'exit 0\n', encoding="utf-8")
    (real_codex_dir / "codex").chmod(0o755)
    caller_path = f"{home / 'bin'}:{real_codex_dir}:/usr/bin:/bin"
    proc = subprocess.run([str(wrapper)],
                          env={**os.environ, "PATH": caller_path},
                          capture_output=True, text=True, timeout=15)
    time.sleep(0.3)  # descendant background может дописывать маркер
    assert child_marker.exists() and child_marker.read_text(encoding="utf-8") == "ok", \
        (f"descendant codex (fork, новый PID) заблокирован ложным sentinel — regression nested-agent: "
         f"parent rc={proc.returncode}, stderr={proc.stderr!r}")


def test_cycle_guard_fork_foreign_bounded_not_process_bomb(monkeypatch, tmp_path):
    """#150 hop-counter инвариант (cycle-review PR #153 round-2), адаптированный под rename #169: fork'ающий
    foreign-wrapper, целенаправленно зовущий managed codex-srouter, обходит PID-scoped guard, но обязан
    bounded-обрываться, не накапливая процессы.

    Foreign БЕЗ exec (`codex-srouter "$@"`) форкает вызов managed codex-srouter — каждый re-entry
    получает новый PID → PID-check пропускает → без hop-ceiling это fork-bomb до per-user process limit
    (process-table exhaustion, DoS на 24/7-инфре, Codex confidence 0.98). Легитимный descendant завершается
    (real codex работает и выходит), fork-foreign — НЕТ (каждый уровень порождает следующий без лимита).

    Hop-счётчик в sentinel (<pid>:<hop>): каждый fork-re-entry инкрементирует унаследованный hop; при
    hop > CEILING → обрыв rc=126. Отличает бесконтрольную fork-рекурсию (foreign) от bounded-вложенности
    легитимного descendant (которая «выдыхается» сама — процессы завершаются).
    """
    import subprocess
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    monkeypatch.setattr(srouter, "_codex_bin_path", lambda: str(tmp_path / "any-codex"))
    srouter._install_codex_wrappers(env)
    wrapper = home / "bin" / _cli_wrapper_name()
    real_codex = tmp_path / "realdir" / "codex"
    real_codex.parent.mkdir(parents=True)
    real_codex.write_text("#!/bin/sh\nprintf real > /dev/null\n", encoding="utf-8")
    real_codex.chmod(0o755)
    # foreign БЕЗ exec: форкает managed codex-srouter (новое имя, #169) и ждёт. Каждый уровень порождает
    # следующий — не завершается. До rename foreign звал `codex` (= managed первым в PATH); теперь зовёт имя.
    managed_name = _cli_wrapper_name()
    foreignbin = tmp_path / "foreignbin"
    foreignbin.mkdir()
    (foreignbin / "codex").write_text(f'#!/bin/sh\n{managed_name} "$@"; exit $?\n', encoding="utf-8")
    (foreignbin / "codex").chmod(0o755)
    caller_path = f"{home / 'bin'}:{foreignbin}:{tmp_path / 'realdir'}:/usr/bin:/bin"
    proc = subprocess.run([str(wrapper), "x"],
                          env={**os.environ, "PATH": caller_path},
                          capture_output=True, text=True, timeout=15)
    assert proc.returncode == 126, \
        (f"fork-foreign должен bounded-обрываться rc=126 (hop-ceiling), не fork-bomb: "
         f"получено rc={proc.returncode}, stderr={proc.stderr[:200]!r}")


def test_cycle_guard_foreign_self_cycle_documented_limitation(monkeypatch, tmp_path):
    """cycle-review FIX C (codex critical #2, confidence 0.97): ДОКУМЕНТИРОВАННОЕ ОГРАНИЧЕНИЕ coverage после
    rename #169. foreign-wrapper, делающий рекурсивный `codex "$@"`-вызов (НЕ зовущий managed codex-srouter),
# циклит сам с собой (foreign↔foreign) БЕЗ повторного входа managed → cycle-guard #153 НЕ обрывает.

    ДО rename: managed wrapper звался codex (первый в PATH) → foreign `codex "$@"` попадал в managed →
    cycle-guard обрывал rc=126 (тест test_cycle_guard_fork_foreign_bounded_not_process_bomb на старом имени).
    ПОСЛЕ rename: managed = codex-srouter → foreign `codex "$@"` находит себя → self-cycle без managed в
    цепочке → sentinel никогда не ceiling'ится. Это регрессия COVERAGE (srouter перестал покрывать класс),
    обнаруженная Codex и ранее скрытая адаптацией тестов под новое имя.

    ПОЧЕМУ НЕ ЧИНИТСЯ здесь (решение пользователя, канон #150): foreign↔foreign self-cycle — availability-класс
    через ЧУЖОЙ wrapper в собственном PATH под контролем того же UID. #150 ЯВНО выводит этот класс за scope
    best-effort слоя (нужен active malice / сломанный чужой wrapper в уже контролируемом PATH; PATH-санitизация
    отвергнута — blast radius на 24/7-инфре). Честная fail-closed граница = PF kill-switch (#168, отдельный слой).
    Тест фиксирует ограничение как осознанный контракт: foreign↔foreign НЕ обрывается (timeout/hang), и это
    задокументировано, а не скрыто.
    """
    import subprocess
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    monkeypatch.setattr(srouter, "_codex_bin_path", lambda: str(tmp_path / "any-codex"))
    srouter._install_codex_wrappers(env)
    wrapper = home / "bin" / _cli_wrapper_name()
    real_codex = tmp_path / "realdir" / "codex"
    real_codex.parent.mkdir(parents=True)
    real_codex.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    real_codex.chmod(0o755)
    # foreign БЕЗ exec: зовёт `codex` (НЕ codex-srouter) → резолвит себя → foreign↔foreign self-cycle.
    foreignbin = tmp_path / "foreignbin"
    foreignbin.mkdir()
    (foreignbin / "codex").write_text('#!/bin/sh\ncodex "$@"; exit $?\n', encoding="utf-8")
    (foreignbin / "codex").chmod(0o755)
    caller_path = f"{home / 'bin'}:{foreignbin}:{tmp_path / 'realdir'}:/usr/bin:/bin"
    # ДОКУМЕНТИРОВАННОЕ ограничение: foreign↔foreign self-cycle НЕ обрывается cycle-guard → fork-bomb,
    # который subprocess убивает по timeout (TimeoutExpired) — это и есть сигнал «ограничение не устранено».
    # cycle-guard обрывил бы с rc=126; timeout/ненулевой rc = ограничение подтверждено (вне scope #150).
    timed_out = False
    rc = None
    try:
        proc = subprocess.run([str(wrapper), "x"],
                              env={**os.environ, "PATH": caller_path},
                              capture_output=True, text=True, timeout=6)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
    assert timed_out or rc != 126, \
        (f"foreign↔foreign self-cycle вне scope (#150); если стал обрываться rc=126 (без timeout) — coverage "
         f"расширилась, обнови тест-документацию: rc={rc}, timed_out={timed_out}")


def test_cycle_guard_non_numeric_hop_resets_not_crash(monkeypatch, tmp_path):
    """#150 robustness (cycle-review PR #153 round-3 minor): аномальное/манипулированное значение sentinel
    (non-numeric hop) не должно ронять wrapper арифметической ошибкой — reset в 0, продолжаем штатно.

    Сценарий: env намеренно установлен в 'garbage' (нет ':' или non-numeric hop). Natural-пути сюда не
    доходят (wrapper всегда пишет <pid>:<int>), но fail-loud-семантика обязана держаться и на аномалиях:
    arith-ошибка в sh дала бы непредсказуемый exit. Guard `case` сбрасывает non-numeric → 0 → штатный вход.
    """
    import subprocess
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    monkeypatch.setattr(srouter, "_codex_bin_path", lambda: str(tmp_path / "any-codex"))
    srouter._install_codex_wrappers(env)
    wrapper = home / "bin" / _cli_wrapper_name()
    real_codex = tmp_path / "realdir" / "codex"; real_codex.parent.mkdir(parents=True)
    real_codex.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    real_codex.chmod(0o755)
    caller_path = f"{home / 'bin'}:{tmp_path / 'realdir'}:/usr/bin:/bin"
    # env с аномальным sentinel (non-numeric hop) — wrapper обязан reset'нуть и продолжить, не крашнуться.
    proc = subprocess.run([str(wrapper), "x"],
                          env={**os.environ, "PATH": caller_path,
                               "SROUTER_CODEX_WRAPPER_V1": "99999:not-a-number"},
                          capture_output=True, text=True, timeout=10)
    assert proc.returncode == 0, \
        f"non-numeric hop должен reset'нуться → штатный запуск (не arith-краш): rc={proc.returncode}, stderr={proc.stderr!r}"


def test_cycle_guard_runs_real_codex_on_single_pass(monkeypatch, tmp_path):
    """#150 шаг 3: на ОДНОКРАТНОМ нормальном входе (нет цикла) cycle-guard НЕ срабатывает — real Codex
    запускается, аргументы доходят. Сентинель guard'ит только повторный вход, не первый.

    Foreign-wrapper отсутствует → managed резолвит реальный codex → exec'ает (сентинель ставится, но
    повторного входа managed нет) → real codex работает штатно.
    """
    import subprocess
    called = tmp_path / "called.txt"
    real_codex = tmp_path / "realdir" / "codex"
    real_codex.parent.mkdir(parents=True)
    real_codex.write_text(f"#!/bin/sh\nprintf '%s' \"$1\" > {called}\n", encoding="utf-8")
    real_codex.chmod(0o755)
    wrapper = _install_cycle_guard_wrapper(monkeypatch, tmp_path)

    proc = subprocess.run(
        [str(wrapper), "hello-arg"],
        env={**os.environ, "PATH": f"{Path.home() / 'bin'}:{tmp_path / 'realdir'}:/usr/bin:/bin"},
        capture_output=True, text=True, timeout=10)

    assert proc.returncode == 0, f"однократный запуск — успех: {proc.stderr!r}"
    assert called.exists() and called.read_text(encoding="utf-8") == "hello-arg", \
        "real Codex запущен, argv проброшен (cycle-guard не мешает штатному вызову)"


def test_cycle_guard_preserves_caller_path(monkeypatch, tmp_path):
    """#150 шаг 3 (отказ от PATH-санitизации обоснован): cycle-guard НЕ режет PATH дочернего codex.
    Сентинель — это env-ФЛАГ (SROUTER_CODEX_WRAPPER_V1), не модификация PATH. Дочерний codex видит
    исходный PATH вызывающего целиком (включая ~/bin) — tools/агенты ничего не теряют (blast radius
    PATH-санitизации из issue #150 здесь отсутствует).
    """
    import subprocess
    import json
    out_file = tmp_path / "child-path.json"
    real_codex = tmp_path / "realdir" / "codex"
    real_codex.parent.mkdir(parents=True)
    real_codex.write_text(
        f"#!/bin/sh\npython3 -c \"import json,os; json.dump(os.environ.get('PATH',''), open('{out_file}','w'))\"\n",
        encoding="utf-8")
    real_codex.chmod(0o755)
    wrapper = _install_cycle_guard_wrapper(monkeypatch, tmp_path)
    caller_path = f"{Path.home() / 'bin'}:{tmp_path / 'realdir'}:/usr/bin:/bin"

    subprocess.run([str(wrapper), "x"],
                   env={**os.environ, "PATH": caller_path},
                   check=True, timeout=10)
    child_path = json.loads(out_file.read_text(encoding="utf-8"))
    assert child_path == caller_path, \
        f"PATH дочернего codex сохранён целиком (сентинель не PATH-санitизация): {child_path!r} != {caller_path!r}"


def test_cycle_guard_uses_versioned_sentinel_env(monkeypatch, tmp_path):
    """#150 шаг 4 (инвариант): отрендеренный managed wrapper использует versioned env-сентинель
    SROUTER_CODEX_WRAPPER_V1 (с суффиксом версии), а не голый SROUTER_CODEX_WRAPPER — чтобы не
    столкнуться со случайной пользовательской переменной без версии. Версия позволяет сменить сентинель
    при изменении формата без конфликта.
    """
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    monkeypatch.setattr(srouter, "_codex_bin_path", lambda: str(tmp_path / "any-codex"))
    srouter._install_codex_wrappers(env)
    cli_text = (home / "bin" / _cli_wrapper_name()).read_text(encoding="utf-8")

    assert "SROUTER_CODEX_WRAPPER_V1" in cli_text, \
        "wrapper использует versioned сентинель SROUTER_CODEX_WRAPPER_V1 (#150)"


# ============================ issue #144: wrapper runtime-резолвит binary (подход A) ============================
# ДЫРА: srouter.py _codex_bin_path() хардкодил ОДИН codex-binary в __SROUTER_CODEX_BIN__; >1 binary на
# диске или caller с другим PATH → второй codex идёт напрямую, fail-closed нарушен.
#
# ФИКС (A): wrapper НЕ хардкодит binary, а runtime-резолвит его по PATH ВЫЗЫВАЮЩЕЙ оболочки, МИНУЯ
# сам себя (антирекурсия). Один wrapper ловит любую версию codex, оказавшуюся в PATH caller'а.
# Это best-effort layer (не fail-closed): честный kill-switch = PF (isolate_firewall.py, отдельная граница).


def test_wrapper_does_not_hardcode_bin_placeholder(monkeypatch, tmp_path):
    """#144(A): отрендеренный wrapper НЕ содержит литерального __SROUTER_CODEX_BIN__ и НЕ вшивает
    абсолютный путь найденного binary. Binary резолвится в runtime по PATH, а не вшит в install-time."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    # Даже когда codex найден, путь НЕ должен попасть в wrapper.
    fake_bin = tmp_path / "realcodex"
    fake_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_bin.chmod(0o755)
    monkeypatch.setattr(srouter, "_codex_bin_path", lambda: str(fake_bin))

    srouter._install_codex_wrappers(env)
    cli_text = (home / "bin" / _cli_wrapper_name()).read_text(encoding="utf-8")

    assert "__SROUTER_CODEX_BIN__" not in cli_text, "плейсхолдер должен быть заменён runtime-резолвом"
    assert str(fake_bin) not in cli_text, "абсолютный путь binary НЕ вшит (#144 runtime-резолв)"
    assert "/opt/homebrew/bin/codex" not in cli_text, "хардкод homebrew-пути отсутствует"


def _install_with_path_resolving_wrapper(monkeypatch, tmp_path):
    """Install wrapper БЕЗ вшитого binary (подход A): _codex_bin_path возвращает found (чтобы install
    не упал на «binary не найден»), но путь не используется в рендере. Возвращает путь к wrapper."""
    _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    # Наличие codex нужно install'у как gate (WARN если совсем нет), но путь не вшивается.
    monkeypatch.setattr(srouter, "_codex_bin_path", lambda: str(tmp_path / "any-codex"))
    srouter._install_codex_wrappers(env)
    return Path.home() / "bin" / _cli_wrapper_name()


def test_wrapper_runtime_resolves_codex_from_caller_path(monkeypatch, tmp_path):
    """#144(A) core: wrapper в runtime находит codex из PATH ВЫЗЫВАЮЩЕЙ оболочки (минуя себя) и exec'ает
    именно его. Смена binary в PATH НЕ требует reinstall wrapper'а — runtime всегда берёт текущий.

    Fake codex пишет маркер своего пути → проверяем, что exec'нут именно тот codex, что первым в PATH.
    """
    called = tmp_path / "called-codex.txt"
    codex_dir = tmp_path / "codexbin"
    codex_dir.mkdir()
    real_codex = codex_dir / "codex"
    real_codex.write_text(f"#!/bin/sh\nprintf '%s' 'real-codex' > {called}\n", encoding="utf-8")
    real_codex.chmod(0o755)
    wrapper = _install_with_path_resolving_wrapper(monkeypatch, tmp_path)

    subprocess.run([str(wrapper), "x"],
                    env={**os.environ, "PATH": f"{Path.home() / 'bin'}:{codex_dir}:/usr/bin:/bin"},
                    check=True, timeout=10)
    assert called.exists(), "wrapper runtime-резолвнул и exec'нул codex из PATH"
    assert called.read_text(encoding="utf-8") == "real-codex", "exec'нут именно codex из PATH caller'а"


def test_wrapper_skips_itself_no_recursion(monkeypatch, tmp_path):
    """#144(A) антирекурсия: wrapper НЕ находит сам себя как реальный binary. ~/bin/codex = wrapper,
    он первый в PATH → wrapper обязан его ПРОПУСТИТЬ и взять следующий codex, иначе бесконечный цикл."""
    called = tmp_path / "called.txt"
    real_codex = tmp_path / "other" / "codex"
    real_codex.parent.mkdir(parents=True)
    real_codex.write_text(f"#!/bin/sh\nprintf 'real' > {called}\n", encoding="utf-8")
    real_codex.chmod(0o755)
    wrapper = _install_with_path_resolving_wrapper(monkeypatch, tmp_path)

    # ~/bin ПЕРВЫМ в PATH (там wrapper), затем каталог с реальным codex. Без skip-self — рекурсия/timeout.
    subprocess.run([str(wrapper), "x"],
                    env={**os.environ, "PATH": f"{Path.home() / 'bin'}:{tmp_path / 'other'}:/usr/bin:/bin"},
                    check=True, timeout=10)
    assert called.exists() and called.read_text(encoding="utf-8") == "real", \
        "wrapper пропустил себя (антирекурсия) и взял следующий codex из PATH"


def test_wrapper_skips_itself_hardlink_no_recursion(monkeypatch, tmp_path):
    """#144(A) антирекурсия — hardlink-случай (корневой инвариант «wrapper не exec'нет сам себя»).

    Hardlink-копия wrapper'а в другой PATH-директории: тот же inode, но ДРУГОЙ realpath.
    Сравнение только по realpath (пути) НЕ распознаёт hardlink как себя → бесконечная рекурсия.
    Антирекурсия обязана ловить и hardlink (inode+device совпадают), не только symlink (realpath).

    Без фикса: wrapper берёт hardlink как «реальный codex» → exec'ает копию себя → снова → timeout.
    """
    import subprocess
    called = tmp_path / "called.txt"
    real_codex = tmp_path / "realdir" / "codex"
    real_codex.parent.mkdir(parents=True)
    real_codex.write_text(f"#!/bin/sh\nprintf 'real' > {called}\n", encoding="utf-8")
    real_codex.chmod(0o755)
    wrapper = _install_with_path_resolving_wrapper(monkeypatch, tmp_path)
    # hardbin/codex — HARDLINK на wrapper (тот же inode, другой путь). os.link создаёт hardlink.
    hardbin = tmp_path / "hardbin"
    hardbin.mkdir()
    os.link(str(wrapper), str(hardbin / "codex"))
    assert os.stat(wrapper).st_ino == os.stat(hardbin / "codex").st_ino, "precondition: hardlink = тот же inode"
    # hardbin ПЕРВЫМ (минуя wrapper в ~/bin), затем realdir. Без hardlink-aware skip → рекурсия/timeout.
    try:
        subprocess.run([str(wrapper), "x"],
                        env={**os.environ, "PATH": f"{Path.home() / 'bin'}:{hardbin}:{tmp_path / 'realdir'}:/usr/bin:/bin"},
                        check=True, timeout=10)
    except subprocess.TimeoutExpired:
        pytest.fail("hardlink-копия wrapper'а в PATH вызвала рекурсию (антирекурсия не ловит hardlink)")
    assert called.exists() and called.read_text(encoding="utf-8") == "real", \
        "wrapper пропустил hardlink-копию себя (inode-aware антирекурсия) и взял реальный codex"


def test_wrapper_skips_other_managed_copy_no_recursion(monkeypatch, tmp_path):
    """#144(A) антирекурсия — корневой инвариант: wrapper НЕ exec'нит ДРУГУЮ управляемую srouter-копию.

    Две НЕЗАВИСИМЫЕ копии managed wrapper'а в PATH (разные inode, разные realpath — например текущая
    ~/bin/codex + stale-копия из прежней установки/миграции). inode/realpath их различают → копия A
    принимает B за «реальный codex» и exec'ает её; B принимает A → бесконечный ping-pong через exec
    → зависание. Управляемый wrapper отличим от реального codex ТОЛЬКО по srouter-маркеру в содержимом,
    не по пути/inode. Антирекурсия обязана skip'ать любого кандидата, несущего srouter-маркер wrapper'а.
    """
    import subprocess
    called = tmp_path / "called.txt"
    real_codex = tmp_path / "realdir" / "codex"
    real_codex.parent.mkdir(parents=True)
    real_codex.write_text(f"#!/bin/sh\nprintf 'real' > {called}\n", encoding="utf-8")
    real_codex.chmod(0o755)
    wrapper = _install_with_path_resolving_wrapper(monkeypatch, tmp_path)
    # stalebin/codex — ВТОРАЯ независимая копия managed wrapper'а (другой путь, другой inode).
    stalebin = tmp_path / "stalebin"
    stalebin.mkdir()
    (stalebin / "codex").write_text(wrapper.read_text(encoding="utf-8"), encoding="utf-8")
    (stalebin / "codex").chmod(0o755)
    assert os.stat(wrapper).st_ino != os.stat(stalebin / "codex").st_ino, "precondition: разные inode (не hardlink)"
    # ~/bin (копия A) → stalebin (копия B) → realdir. Без marker-aware skip → A↔B рекурсия/timeout.
    try:
        subprocess.run([str(wrapper), "x"],
                        env={**os.environ, "PATH": f"{Path.home() / 'bin'}:{stalebin}:{tmp_path / 'realdir'}:/usr/bin:/bin"},
                        check=True, timeout=10)
    except subprocess.TimeoutExpired:
        pytest.fail("две управляемые копии wrapper'а в PATH вызвали ping-pong рекурсию "
                    "(антирекурсия не распознаёт srouter-маркер у другой копии)")
    assert called.exists() and called.read_text(encoding="utf-8") == "real", \
        "wrapper пропустил ДРУГУЮ managed-копию (по srouter-маркеру) и взял реальный codex"


def test_wrapper_picks_second_codex_when_two_binaries(monkeypatch, tmp_path):
    """#144 корень дыры: на диске ДВА разных codex-binary. Caller с PATH, ведущим ко второму, должен
    попасть в него через wrapper (а не в вшитый-единственный, как раньше).

    Две директории, в каждой свой codex (пишут разные маркеры). Wrapper runtime берёт тот, что в PATH
    вызывающего — независимо от того, что нашёл _codex_bin_path в install-time.
    """
    first_called = tmp_path / "first.txt"
    second_called = tmp_path / "second.txt"
    d1 = tmp_path / "d1"
    d2 = tmp_path / "d2"
    d1.mkdir(); d2.mkdir()
    (d1 / "codex").write_text(f"#!/bin/sh\nprintf 'first' > {first_called}\n", encoding="utf-8")
    (d1 / "codex").chmod(0o755)
    (d2 / "codex").write_text(f"#!/bin/sh\nprintf 'second' > {second_called}\n", encoding="utf-8")
    (d2 / "codex").chmod(0o755)
    # install-time нашёл d1/codex (раньше вшло бы в __SROUTER_CODEX_BIN__ и d2 был бы проигнорирован).
    monkeypatch.setattr(srouter, "_codex_bin_path", lambda: str(d1 / "codex"))
    _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    srouter._install_codex_wrappers(env)
    wrapper = Path.home() / "bin" / _cli_wrapper_name()

    # Caller с PATH, где d2 ПЕРВЫМ (минуя wrapper в ~/bin): wrapper должен взять d2/codex.
    subprocess.run([str(wrapper), "x"],
                    env={**os.environ, "PATH": f"{Path.home() / 'bin'}:{d2}:{d1}:/usr/bin:/bin"},
                    check=True, timeout=10)
    assert second_called.exists() and second_called.read_text(encoding="utf-8") == "second", \
        "caller с PATH→d2 дошёл до d2/codex через runtime-резолв (не до вшитого d1)"
    assert not first_called.exists(), "вшитый install-time codex НЕ выиграл у PATH caller'а"


def test_wrapper_runtime_resolves_after_binary_change(monkeypatch, tmp_path):
    """#144 подводный камень «незаметная смена binary после brew upgrade»: runtime-резолв берёт ТЕКУЩИЙ
    codex из PATH. Сменился binary в том же пути — wrapper сам подхватывает новый, reinstall не нужен."""
    marker = tmp_path / "marker.txt"
    bin_slot = tmp_path / "slot"
    bin_slot.mkdir()
    wrapper = _install_with_path_resolving_wrapper(monkeypatch, tmp_path)

    # Версия 1 по пути slot/codex.
    (bin_slot / "codex").write_text(f"#!/bin/sh\nprintf 'v1' > {marker}\n", encoding="utf-8")
    (bin_slot / "codex").chmod(0o755)
    subprocess.run([str(wrapper), "x"],
                    env={**os.environ, "PATH": f"{Path.home() / 'bin'}:{bin_slot}:/usr/bin:/bin"},
                    check=True, timeout=10)
    assert marker.read_text(encoding="utf-8") == "v1"

    # brew upgrade: тот же путь, другой binary. БЕЗ reinstall wrapper'а.
    (bin_slot / "codex").write_text(f"#!/bin/sh\nprintf 'v2' > {marker}\n", encoding="utf-8")
    (bin_slot / "codex").chmod(0o755)
    subprocess.run([str(wrapper), "x"],
                    env={**os.environ, "PATH": f"{Path.home() / 'bin'}:{bin_slot}:/usr/bin:/bin"},
                    check=True, timeout=10)
    assert marker.read_text(encoding="utf-8") == "v2", "runtime-резолв подхватил обновлённый binary"


def test_install_warns_about_uncovered_entry_points(monkeypatch, tmp_path):
    """#144 подход A — best-effort, НЕ fail-closed. install обязан ЧЕСТНО предупредить оператора, что
    wrapper НЕ покрывает: прямой абсолютный путь /opt/.../codex, node .../codex.js, exec.LookPath с
    другим PATH. PF kill-switch — единственная настоящая граница (отдельная, здесь не трогаем)."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    fake_bin = tmp_path / "codex"
    fake_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_bin.chmod(0o755)
    monkeypatch.setattr(srouter, "_codex_bin_path", lambda: str(fake_bin))

    note = srouter._install_codex_wrappers(env)

    low = note.lower()
    assert ("best-effort" in low or "best effort" in low), \
        f"install честно маркирует wrapper как best-effort (не fail-closed): {note}"
    # Подсветка необёрнутых точек входа (хоть бы общим WARN «прямой вызов/абсолютный путь не покрыт»).
    assert ("абсолют" in low or "напрям" in low or "не покрыт" in low
            or "не перехват" in low or "не обёрнут" in low), \
        f"install WARN про необёрнутые точки входа: {note}"
