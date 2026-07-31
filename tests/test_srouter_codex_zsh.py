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

import codex_wrappers
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
    # precondition (cycle-3 root fix): zsh-функция codex-srouter создаётся только при валидном target.
    srouter._install_codex_wrappers(env)
    assert (home / "bin" / "codex-srouter").exists()

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
    srouter._install_codex_wrappers(env)  # precondition: валидный target (cycle-3 root fix)

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
    srouter._install_codex_wrappers(env)  # precondition: валидный target (cycle-3 root fix)
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
    monkeypatch.setattr(codex_wrappers, "_codex_bin_path", lambda: str(brew_dir / "codex"))
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
        capture_output=True, text=True, timeout=45)
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
    monkeypatch.setattr(codex_wrappers, "_codex_bin_path", lambda: "")

    note = srouter._install_codex_wrappers(env)

    assert not (bin_dir / "codex-srouter").exists(), "новый wrapper не установлен (codex bin missing)"
    assert (bin_dir / "codex").exists(), \
        f"legacy managed ~/bin/codex СОХРАНЁН (migration отменена — замена не встала): {note}"
    assert (bin_dir / "codex").read_text(encoding="utf-8") == legacy_content, "legacy не изменён"


def test_codex_bin_path_rejects_managed_legacy_wrapper(monkeypatch, tmp_path):
    """cycle-review cycle-4 FIX #1 (codex critical 0.99): _codex_bin_path ОТВЕРГАЕТ любой кандидат с
    managed-маркером (не только codex-srouter), как wrapper template делает marker-skip. Иначе legacy
    managed ~/bin/codex (первый в PATH) misclassify как real binary → install проходит → migration удаляет
    legacy без независимого real codex → новый codex-srouter exit 127 (runtime-resolve не находит real).

    Memory issue-144-wrapper-runtime-resolve: wrapper ≠ binary, runtime-resolve. install-time gate тоже
    обязан различать managed-wrapper от real binary — по маркеру, не по пути (маркер = единственный признак)."""
    home = _mock_home(monkeypatch, tmp_path)
    bin_dir = home / "bin"
    marker = srouter.CODEX_WRAPPERS[0][2]
    # legacy managed codex в ~/bin (первый в PATH), НЕТ независимого real codex.
    (bin_dir / "codex").write_text(f"{marker}\n#!/bin/sh\nexec /hardcoded/old/codex\n", encoding="utf-8")
    (bin_dir / "codex").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")

    resolved = srouter._codex_bin_path()

    assert resolved != str(bin_dir / "codex"), \
        f"managed legacy wrapper НЕ принят за real binary (маркер → reject): resolved={resolved}"


def test_install_no_delete_legacy_when_only_managed_codex_in_path(monkeypatch, tmp_path):
    """cycle-review cycle-4 FIX #1 (интеграционный): legacy managed ~/bin/codex — ЕДИНСТВЕННЫЙ codex в PATH
    (нет независимого real binary). Install НЕ должен мигрировать (удалять) legacy: новый codex-srouter
    создастся, но runtime-resolve не найдёт real codex → exit 127. Migration разрешена только когда resolver
    нашёл НЕЗАВИСИМЫЙ real codex (без managed-маркера).

    Примечание: _codex_bin_path мокаем → '' (моделируем «нет независимого real codex»; в реальном окружении
    /opt/homebrew/bin/codex может существовать и thenбы пройти — здесь изолируем именно этот класс)."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    bin_dir = home / "bin"
    bin_dir.mkdir(exist_ok=True)
    marker = srouter.CODEX_WRAPPERS[0][2]
    legacy_content = f"{marker}\n#!/bin/sh\nexec /hardcoded/old/codex\n"
    (bin_dir / "codex").write_text(legacy_content, encoding="utf-8")
    (bin_dir / "codex").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")  # legacy единственный codex в PATH
    monkeypatch.setattr(codex_wrappers, "_codex_bin_path", lambda: "")  # НЕТ независимого real codex

    note = srouter._install_codex_wrappers(env)

    # legacy СОХРАНЁН (нет независимого real codex → codex-srouter не встал → migration отменена).
    assert (bin_dir / "codex").exists(), \
        f"legacy preserved — нет независимого real codex (resolver отверг managed): {note}"
    assert (bin_dir / "codex").read_text(encoding="utf-8") == legacy_content


def test_install_idempotent_current_block_validates_target(monkeypatch, tmp_path):
    """cycle-review cycle-4 FIX #2 (codex critical 0.99): existing current block (зовёт codex-srouter) при
    target-missing НЕ рапортует чистый успех. Строка codex-srouter проверяется ПОСЛЕ ordered_pair и
    target-gate — иначе predсуществующий блок ведёт в никуда (target удалён), а install говорит ОК."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    zshrc = home / ".zshrc"
    # managed current block (зовёт codex-srouter), но target НЕ установлен.
    zshrc.write_text(srouter._CODEX_FUNC_BLOCK, encoding="utf-8")
    assert not (home / "bin" / "codex-srouter").exists()

    note = srouter._install_codex_zsh_function(env)

    low = note.lower()
    # НЕ чистый «idempotent» успех — note сигнализирует проблему target. (Слово «idempotent» может быть в
    # диагностике «не рапортую idempotent вслепую» — поэтому проверяем отсутствие чистого успеха-маркера.)
    assert "уже в ~/.zshrc (idempotent)" not in note, \
        f"current block при target-missing НЕ чистый idempotent-успех: {note}"
    assert "не установлен" in low or "не валиден" in low, \
        f"note сигнализирует невалидный target: {note}"


def test_remove_codex_zsh_function_reversed_markers_safe_noop(monkeypatch, tmp_path):
    """cycle-review cycle-4 FIX #3 (claude+codex critical 0.99): uninstall с реверснутыми маркерами (END
    перед BEGIN, count==1 каждый) — SAFE NO-OP, НЕ corruption. Иначе start>end → slice overlap → дублирование
    контента, рапорт «убрана». Замкнутый инвариант: ordered-pair parser общий для install И remove."""
    home = _mock_home(monkeypatch, tmp_path)
    zshrc = home / ".zshrc"
    reversed_block = (
        f"{srouter.ZSHRC_CODEX_FUNC_MARKER_END}\n"      # END первым (реверс)
        "export UNIQUE=line1\n"
        "export UNIQUE2=line2\n"
        f"{srouter.ZSHRC_CODEX_FUNC_MARKER_BEGIN}\n"    # BEGIN вторым
    )
    zshrc.write_text(reversed_block, encoding="utf-8")

    note = srouter._remove_codex_zsh_function()

    content = zshrc.read_text(encoding="utf-8")
    assert content == reversed_block, \
        f"reversed markers → byte-for-byte safe no-op (НЕ corruption): {note}"
    assert content.count("export UNIQUE=line1") == 1, "контент НЕ дублирован"


def test_remove_codex_zsh_function_tight_trailing_fail_closed(monkeypatch, tmp_path):
    """cycle-review cycle-2 FIX (codex critical 0.99): uninstall с tight-trailing (контент glued к END-маркеру
    без newline) — SAFE NO-OP, НЕ активирует закомментированную команду.

    END-маркер — shell-комментарий (# ...). Glued-суффикс (ENDecho ACTIVATED) инертен — часть комментария.
    Без line-boundary инварианта remove_managed_block срезал бы блок по байтам END, оставив
    'echo ACTIVATED' standalone исполняемой строкой → uninstall активировал бы закомментированную команду
    при следующем старте шелла (fail-open, потенциально деструктивно). Теперь line-boundary invariant
    (централизованный в marker_block.find_managed_block) считает tight-trailing malformed → None →
    _remove_codex_zsh_function видит block is None → отказ, .zshrc byte-for-byte нетронут."""
    home = _mock_home(monkeypatch, tmp_path)
    zshrc = home / ".zshrc"
    # END-маркер + glued команда без newline (команда инертна — часть комментария END'а).
    malformed_block = (
        f"{srouter.ZSHRC_CODEX_FUNC_MARKER_BEGIN}\n"
        'if (( ! ${+aliases[codex]} )); then\n'
        '  function codex {\n'
        '    "$HOME/bin/codex-srouter" "$@"\n'
        '  }\n'
        "fi\n"
        f"{srouter.ZSHRC_CODEX_FUNC_MARKER_END}echo DESTRUCTIVE_COMMAND\n"
    )
    zshrc.write_text(malformed_block, encoding="utf-8")

    note = srouter._remove_codex_zsh_function()

    content = zshrc.read_text(encoding="utf-8")
    assert content == malformed_block, \
        f"tight-trailing malformed boundary → byte-for-byte safe no-op (НЕ активирует glued команду): {note}"
    # Glued команда осталась инертной (часть END-комментария), НЕ стала standalone исполняемой строкой.
    assert content.count("echo DESTRUCTIVE_COMMAND") == 1
    # Ни одна строка не равна чистой исполняемой команде (она всё ещё glued к маркеру в той же строке).
    assert "echo DESTRUCTIVE_COMMAND" not in content.split("\n"), \
        "glued команда НЕ активирована (осталась частью комментария END-маркера)"


@pytest.mark.parametrize("malformed_kind", ["suffix_after_begin", "prefix_before_end"])
def test_remove_codex_zsh_function_partial_line_marker_fail_closed(monkeypatch, tmp_path, malformed_kind):
    """cycle-review cycle-3 FIX (codex critical 0.99): partial-line markers (suffix-after-BEGIN /
    prefix-before-END) → SAFE NO-OP, НЕ удаляют intervening чужой контент (data-loss).

    Cycle-2 line-boundary FIX был односторонним (char-before-BEGIN + char-after-END) — пропускал
    маркер с trailing-суффиксом (BEGIN + \" example\") и leading-префиксом (\"echo user \" + END),
    хотя маркер НЕ занимал всю строку. remove_managed_block тогда удалял intervening user-контент
    и рапортил успех → silent data-loss без backup. Whole-line matching (cycle-3) замыкает все 4
    стороны: find_managed_block возвращает None → _remove_codex_zsh_function отказ, .zshrc
    byte-for-byte нетронут."""
    home = _mock_home(monkeypatch, tmp_path)
    zshrc = home / ".zshrc"
    B = srouter.ZSHRC_CODEX_FUNC_MARKER_BEGIN
    E = srouter.ZSHRC_CODEX_FUNC_MARKER_END
    user_lines = "export USER_LINE_1=keep\nexport USER_LINE_2=keep\n"
    if malformed_kind == "suffix_after_begin":
        # BEGIN + trailing suffix on same line → marker not whole-line.
        malformed = f"{B} example suffix\n{user_lines}{E}\n"
    else:  # prefix_before_end
        # leading prefix + END on same line → marker not whole-line.
        malformed = f"{B}\n{user_lines}echo user prefix {E}\n"
    zshrc.write_text(malformed, encoding="utf-8")

    note = srouter._remove_codex_zsh_function()

    content = zshrc.read_text(encoding="utf-8")
    assert content == malformed, \
        f"partial-line marker ({malformed_kind}) → byte-for-byte safe no-op (НЕ data-loss): {note}"
    # Intervening user-контент сохранён (не удалён).
    assert content.count("USER_LINE_1=keep") == 1, "чужой контент НЕ удалён (no data-loss)"
    assert content.count("USER_LINE_2=keep") == 1


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
    # Новый codex-srouter установлен (как делает cmd_install перед zsh-func) — target валиден → миграция разрешена.
    srouter._install_codex_wrappers(env)
    assert (bin_dir / "codex-srouter").exists(), "precondition: codex-srouter установлен (target валиден)"

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


def test_install_zsh_function_no_migration_when_new_wrapper_missing(monkeypatch, tmp_path):
    """cycle-review cycle-2 FIX #1 (codex critical 0.99 — transactional coherence): если новый codex-srouter
    НЕ установлен (codex binary не найден → wrapper не встал) — stale zsh-блок НЕ мигрируется на codex-srouter.

    Иначе inconsistency: FIX A сохраняет legacy ~/bin/codex (рабочий), но FIX B перенаправляет zsh-функцию на
    codex-srouter (которого нет) → `codex` в интерактивном шелле зовёт несуществующий файл, притом рабочий
    legacy стоит. Корневой инвариант: zsh-migration согласована с wrapper-install — мигрируем zsh ТОЛЬКО если
    новый codex-srouter установлен и валиден (is_file + executable + current-маркер)."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    bin_dir = home / "bin"
    bin_dir.mkdir(exist_ok=True)
    zshrc = home / ".zshrc"
    stale_block = (
        f"{srouter.ZSHRC_CODEX_FUNC_MARKER_BEGIN}\n"
        'if (( ! ${+aliases[codex]} && ! ${+functions[codex]} )); then\n'
        '  function codex {\n'
        '    "$HOME/bin/codex" "$@"\n'   # СТАРЫЙ путь — РАБОЧИЙ (legacy preserved FIX A)
        '  }\n'
        "fi\n"
        f"{srouter.ZSHRC_CODEX_FUNC_MARKER_END}"
    )
    zshrc.write_text(stale_block, encoding="utf-8")
    # Новый codex-srouter НЕ установлен (нет файла) → мигрировать zsh нельзя.
    assert not (bin_dir / "codex-srouter").exists()

    note = srouter._install_codex_zsh_function(env)

    content = zshrc.read_text(encoding="utf-8")
    assert '"$HOME/bin/codex" "$@"' in content, \
        f"zsh-блок НЕ мигрирован — остался звать рабочий legacy ~/bin/codex (new wrapper missing): {note}"
    assert '"$HOME/bin/codex-srouter" "$@"' not in content, \
        "zsh НЕ перенаправлен на несуществующий codex-srouter (transactional coherence)"


def test_install_zsh_function_migration_reports_write_failure(monkeypatch, tmp_path):
    """cycle-review cycle-2 FIX #1b (codex): результат _write_text_atomic проверяется. Если atomic-write
    упал → note сообщает об отказе, не рапортует успех (иначе оператор думает что zsh обновлён, а файл не записан)."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    zshrc = home / ".zshrc"
    stale_block = (
        f"{srouter.ZSHRC_CODEX_FUNC_MARKER_BEGIN}\n"
        '  function codex {\n    "$HOME/bin/codex" "$@"\n  }\n'
        f"{srouter.ZSHRC_CODEX_FUNC_MARKER_END}"
    )
    zshrc.write_text(stale_block, encoding="utf-8")
    # _write_text_atomic падает (имитация отказа записи).
    # Патчим модуль-владелец codex_wrappers (#228): именно оттуда _install_codex_zsh_function
    # резолвит эти имена. Через srouter (re-export) патч бы не подействовал.
    monkeypatch.setattr(codex_wrappers, "_write_text_atomic", lambda path, text: False)
    # Нужен валидный новый codex-srouter, чтобы миграция вообще пыталась выполниться.
    monkeypatch.setattr(codex_wrappers, "_codex_zsh_target_installed", lambda: True)

    note = srouter._install_codex_zsh_function(env)

    assert "не" in note.lower() or "отказ" in note.lower() or "не обнов" in note.lower() or "сбой" in note.lower(), \
        f"write-failure → note сообщает об отказе, не успех: {note}"


def test_install_zsh_function_malformed_markers_not_rewritten(monkeypatch, tmp_path):
    """cycle-review cycle-2 FIX #1c (codex): malformed markers (дублированный/непарный BEGIN/END) → НЕ
    переписываем span (можно задеть чужой контент). Требуем ровно одну упорядоченную пару, target внутри неё."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    zshrc = home / ".zshrc"
    # ДВА BEGIN-маркера (повреждённое состояние) — index() взял бы первый, span мог бы задеть чужой контент.
    malformed = (
        f"{srouter.ZSHRC_CODEX_FUNC_MARKER_BEGIN}\n"
        '  function codex {\n    "$HOME/bin/codex" "$@"\n  }\n'
        f"{srouter.ZSHRC_CODEX_FUNC_MARKER_BEGIN}\n"   # второй BEGIN
        '  function codex {\n    "$HOME/bin/codex" "$@"\n  }\n'
        f"{srouter.ZSHRC_CODEX_FUNC_MARKER_END}\n"
    )
    zshrc.write_text(malformed, encoding="utf-8")

    note = srouter._install_codex_zsh_function(env)

    content = zshrc.read_text(encoding="utf-8")
    assert content == malformed, \
        f"malformed (двойной BEGIN) → НЕ переписываем, оставляем как есть (fail-closed): {note}"


def test_install_zsh_function_no_create_when_new_wrapper_missing(monkeypatch, tmp_path):
    """cycle-review cycle-3 FIX #1-root (codex critical 0.99 — unified target gate): fresh-create path.
    Если новый codex-srouter НЕ установлен И zshrc не имеет managed-блока → НЕ создавать zsh-функцию
    (иначе она shadow'ит сохранённый legacy ~/bin/codex, зовёт несуществующий codex-srouter = та же
    FIX A/B inconsistency, через fresh-create путь, не migration). Замкнутый инвариант: zsh-функция
    (codex-srouter) создаётся/мигрируется/принимается ТОЛЬКО если _codex_zsh_target_installed() во ВСЕХ путях."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    zshrc = home / ".zshrc"
    zshrc.write_text("export FOO=1\n")  # нет managed zsh блока; codex-srouter НЕ установлен
    assert not (home / "bin" / "codex-srouter").exists()

    note = srouter._install_codex_zsh_function(env)

    content = zshrc.read_text(encoding="utf-8")
    assert srouter._CODEX_FUNC_BLOCK not in content, \
        f"fresh-create zsh-функция НЕ добавлена (target missing → не shadow'им legacy): {note}"
    assert '"$HOME/bin/codex-srouter"' not in content, "zsh НЕ указывает на отсутствующий codex-srouter"


def test_install_zsh_function_no_append_when_new_wrapper_missing(monkeypatch, tmp_path):
    """cycle-review cycle-3 FIX #1-root: append path (zshrc есть, без managed-блока, без foreign codex-def) —
    тоже не добавляем _CODEX_FUNC_BLOCK если target не установлен. Покрывает третий путь функции."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    zshrc = home / ".zshrc"
    zshrc.write_text("export PATH=/usr/local/bin:$PATH\n# user comment\n")
    assert not (home / "bin" / "codex-srouter").exists()

    note = srouter._install_codex_zsh_function(env)

    content = zshrc.read_text(encoding="utf-8")
    assert srouter._CODEX_FUNC_BLOCK not in content, \
        f"append zsh-функции НЕ выполнен (target missing): {note}"


def test_install_zsh_function_reversed_markers_not_rewritten(monkeypatch, tmp_path):
    """cycle-review cycle-3 FIX #2-root (codex critical 0.99 — ordered marker pair): реверснутые маркеры
    (END перед BEGIN, begins==1/ends==1 проходят) → НЕ переписываем. Иначе start>end → content[start:end]
    пустой → реконструкция ДУБЛИРУЕТ контент .zshrc (рапорт успеха). Замкнутый инвариант: требуем ровно одну
    УПОРЯДОЧЕННУЮ пару (begin_index < end_index), target внутри неё."""
    home = _mock_home(monkeypatch, tmp_path)
    env = _env(tmp_path)
    bin_dir = home / "bin"
    bin_dir.mkdir(exist_ok=True)
    zshrc = home / ".zshrc"
    reversed_block = (
        f"{srouter.ZSHRC_CODEX_FUNC_MARKER_END}\n"      # END ПЕРВЫМ (реверс)
        "export FOO=bar\n"
        '  function codex {\n    "$HOME/bin/codex" "$@"\n  }\n'
        f"{srouter.ZSHRC_CODEX_FUNC_MARKER_BEGIN}\n"    # BEGIN вторым
    )
    zshrc.write_text(reversed_block, encoding="utf-8")
    # codex-srouter валиден (чтобы миграция пыталась выполниться) — но реверс маркеров должен её заблокировать.
    srouter._install_codex_wrappers(env)
    assert (bin_dir / "codex-srouter").exists()

    note = srouter._install_codex_zsh_function(env)

    content = zshrc.read_text(encoding="utf-8")
    assert content == reversed_block, \
        f"реверснутые маркеры → НЕ переписываем (start>end corruption): {note}"
    assert content.count("export FOO=bar") == 1, "контент НЕ дублирован (ordered-pair guard)"


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
