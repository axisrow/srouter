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
    констант, а не хардкодит 10808. Меняем источник — меняется launcher (#96, anti-drift).

    CLI-wrapper рендерит CODEX_NO_PROXY_LOOPBACK (loopback-only, БЕЗ z.ai — санитизация #96),
    НЕ CODEX_NO_PROXY (z.ai релевантен только launchctl-gui moonbridge)."""
    _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    monkeypatch.setattr(srouter, "_CODEX_PROXY_URL", "socks5h://127.0.0.1:99999")
    monkeypatch.setattr(srouter, "CODEX_NO_PROXY_LOOPBACK", "localhost,internal")

    srouter._install_codex_wrappers(env)
    cli_text = (Path.home() / "bin" / _cli_wrapper_name()).read_text(encoding="utf-8")

    assert "127.0.0.1:99999" in cli_text, "launcher использует отрендеренный _CODEX_PROXY_URL"
    assert "internal" in cli_text, "launcher использует отрендеренный CODEX_NO_PROXY_LOOPBACK"
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
    import subprocess
    out_file = tmp_path / "child-env.txt"
    fake_bin = tmp_path / "fake-codex"
    # #252 perf: python3-спавн (42.5мс) заменён на чистый /bin/sh (4.8мс) — предмет теста ENV-var
    # проброс до дочернего процесса, не поведение Python. Простой KEY=value построчный дамп.
    keys = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy",
            "NO_PROXY", "no_proxy")
    dump_lines = "\n".join(f'printf \'{k}=%s\\n\' "${k}"' for k in keys)
    fake_bin.write_text(f"#!/bin/sh\n{{ {dump_lines}; }} > \"$OUT\"\n", encoding="utf-8")
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
                   check=True, timeout=30)
    child = dict(
        line.split("=", 1) for line in out_file.read_text(encoding="utf-8").splitlines() if "=" in line
    )
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
                   check=True, timeout=30)
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
                    check=True, timeout=30)
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
                    check=True, timeout=30)
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
                        check=True, timeout=30)
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
                        check=True, timeout=30)
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
                    check=True, timeout=30)
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
                    check=True, timeout=30)
    assert marker.read_text(encoding="utf-8") == "v1"

    # brew upgrade: тот же путь, другой binary. БЕЗ reinstall wrapper'а.
    (bin_slot / "codex").write_text(f"#!/bin/sh\nprintf 'v2' > {marker}\n", encoding="utf-8")
    (bin_slot / "codex").chmod(0o755)
    subprocess.run([str(wrapper), "x"],
                    env={**os.environ, "PATH": f"{Path.home() / 'bin'}:{bin_slot}:/usr/bin:/bin"},
                    check=True, timeout=30)
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


def test_cli_wrapper_loopback_only_no_zai():
    """CLI-wrapper (~/bin/codex-srouter) рендерит CODEX_NO_PROXY_LOOPBACK — БЕЗ z.ai.

    Две разные границы: launchctl-gui (moonbridge→api.z.ai напрямую) vs CLI-codex (managed SOCKS5).
    CLI-codex идёт через xray→VPS — z.ai в его NO_PROXY ломал бы #96 (санитизация унаследованного
    privoxy-окружения: NO_PROXY должен быть loopback-only). Regression-гвард против слияния
    CODEX_NO_PROXY (z.ai) и CODEX_NO_PROXY_LOOPBACK обратно в одну константу (канон
    route-scope-not-shared-validator — общая константа для разных границ = гарантированная утечка)."""
    assert "z.ai" not in srouter.CODEX_NO_PROXY_LOOPBACK, \
        f"CLI-wrapper NO_PROXY loopback-only, БЕЗ z.ai: {srouter.CODEX_NO_PROXY_LOOPBACK}"
    assert "z.ai" in srouter.CODEX_NO_PROXY, \
        f"launchctl-gui NO_PROXY содержит z.ai (moonbridge): {srouter.CODEX_NO_PROXY}"
