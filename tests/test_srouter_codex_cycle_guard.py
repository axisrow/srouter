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
            capture_output=True, text=True, timeout=30)
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
    # Codex-review PR #253: этот процесс форкает descendant — на timeout нужно убить ВСЮ группу процессов
    # (start_new_session=True + killpg), иначе descendant переживает kill прямого child (orphan-риск,
    # см. process-group containment в fork_foreign_bounded ниже).
    proc = _run_wrapper_containerized([str(wrapper)], env={**os.environ, "PATH": caller_path}, timeout=45)
    time.sleep(0.3)  # descendant background может дописывать маркер
    assert child_marker.exists() and child_marker.read_text(encoding="utf-8") == "ok", \
        (f"descendant codex (fork, новый PID) заблокирован ложным sentinel — regression nested-agent: "
         f"parent rc={proc.returncode}, stderr={proc.stderr!r}")


def _run_wrapper_containerized(cmd, *, env, timeout):
    """subprocess.run с process-group containment (Codex-review PR #253 critical finding).

    Тесты в этом блоке намеренно моделируют fork-рекурсивные/fork-порождающие сценарии wrapper'а.
    Голый subprocess.run(timeout=...) на TimeoutExpired убивает ТОЛЬКО прямого child — форкнутые
    descendants (уже запущенные до истечения timeout) переживают kill и продолжают исполняться как
    orphans (задокументированный инцидент здесь же: 1134+ orphan-процессов от идентичного паттерна,
    см. test_cycle_guard_foreign_self_cycle_documented_limitation). Увеличение timeout (issue #251,
    таймаут-раса под xdist) БЕЗ containment расширяло бы окно, в котором сломанный hop-ceiling мог бы
    наплодить orphans, прежде чем тест вообще завершится. start_new_session=True сажает процесс в
    свою process group (setsid); при TimeoutExpired killpg(pgid, SIGKILL) гарантированно убивает всё
    дерево (родителя и уже запущенных потомков), а не только прямого child.
    """
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, start_new_session=True)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = proc.communicate()
        raise subprocess.TimeoutExpired(cmd, timeout, output=out, stderr=err)
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


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

    Codex-review PR #253 (critical, confidence 0.99): если hop-ceiling когда-нибудь регрессирует (ровно
    баг, который этот тест обязан ловить), голый subprocess.run(timeout=...) на TimeoutExpired убивает
    только прямого child — уже наплодившиеся descendants переживают и продолжают форкать (см. containment
    в _run_wrapper_containerized выше). Используем её вместо голого subprocess.run.
    """
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
    proc = _run_wrapper_containerized([str(wrapper), "x"],
                                       env={**os.environ, "PATH": caller_path}, timeout=45)
    assert proc.returncode == 126, \
        (f"fork-foreign должен bounded-обрываться rc=126 (hop-ceiling), не fork-bomb: "
         f"получено rc={proc.returncode}, stderr={proc.stderr[:200]!r}")


def test_cycle_guard_foreign_self_cycle_documented_limitation():
    """cycle-review cycle-2 FIX #2 (codex critical 0.99 — uncontained process-exhaustion test): STATIC
    контракт-тест ДОКУМЕНТИРОВАННОГО ограничения coverage cycle-guard после rename #169.

    Предыдущая версия запускала РЕАЛЬНЫЙ fork-bomb (foreign `codex "$@"` → self-cycle) под subprocess timeout —
    но timeout убивает только direct child, descendants выживают и продолжают плодиться (1134+ orphan-процессов
    за один прогон, дестабилизируя CI/машину — сами воспроизводили availability-атаку, которую декларируем вне
    scope). Codex confidence 0.99: replace with static/bounded contract test.

    Этот тест проверяет ограничение ПО СТРУКТУРЕ wrapper template, без запуска fork-bomb:
      1. cycle-guard sentinel (SROUTER_CODEX_WRAPPER_V1) проверяется ТОЛЬКО в managed wrapper (grep по маркеру).
      2. runtime-resolve НЕ distinguishes foreign-wrapper (без маркера) от real codex — кандидат принимается
         как «реальный codex», если не несёт srouter-маркер (grep: marker-skip единственный фильтр).
    → foreign-wrapper `codex "$@"` резолвится в себя (после rename managed = codex-srouter, не в `codex`-PATH),
      циклит без re-entry managed → sentinel не ceiling'ится. Это и есть ограничение, доказанное статически.

    ПОЧЕМУ НЕ ЧИНИТСЯ (решение пользователя, канон #150): foreign↔foreign self-cycle — availability-класс через
    ЧУЖОЙ wrapper в собственном PATH под контролем того же UID; #150 ЯВНО выводит за scope best-effort слоя
    (PATH-санitизация отвергнута — blast radius на 24/7-инфре). Честная fail-closed = PF kill-switch (#168)."""
    template = (Path(__file__).resolve().parent.parent / "launchagents" / "srouter-codex-cli-wrapper.sh"
                ).read_text(encoding="utf-8")
    # (1) cycle-guard sentinel проверяется только в managed wrapper (маркер srouter присутствует в template).
    managed_marker = "# srouter: codex CLI wrapper (managed)"
    assert managed_marker in template, "template — managed wrapper (несёт srouter-маркер)"
    assert "SROUTER_CODEX_WRAPPER_V1" in template, "cycle-guard sentinel присутствует в managed wrapper"
    # (2) runtime-resolve skip'ает кандидата ТОЛЬКО по srouter-маркеру; foreign (без маркера) = «реальный codex».
    # Это структурно означает: foreign-wrapper, делающий рекурсивный codex-вызов, не отличим от real binary →
    # если он первый в `codex`-PATH (managed = codex-srouter, не codex), циклит сам с собой без re-entry managed.
    assert "grep -q 'srouter: codex CLI wrapper'" in template, \
        "runtime-resolve distinguish'ит managed-копию только по srouter-маркеру (foreign = «real codex»)"
    # Контракт: ограничение задокументировано в framing-комментарии теста (см. блок #150 выше). Если cycle-guard
    # когда-нибудь покроет foreign↔foreign — добавится второй distinguishment (помимо marker-skip), и этот
    # static-инвариант изменится → тест напомнит обновить документацию.


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
                          capture_output=True, text=True, timeout=30)
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
        capture_output=True, text=True, timeout=30)

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
    out_file = tmp_path / "child-path.txt"
    real_codex = tmp_path / "realdir" / "codex"
    real_codex.parent.mkdir(parents=True)
    # #252 perf: python3-спавн заменён на /bin/sh — предмет теста PATH-строка, не Python-поведение.
    real_codex.write_text(
        f"#!/bin/sh\nprintf '%s' \"$PATH\" > {out_file}\n",
        encoding="utf-8")
    real_codex.chmod(0o755)
    wrapper = _install_cycle_guard_wrapper(monkeypatch, tmp_path)
    caller_path = f"{Path.home() / 'bin'}:{tmp_path / 'realdir'}:/usr/bin:/bin"

    subprocess.run([str(wrapper), "x"],
                   env={**os.environ, "PATH": caller_path},
                   check=True, timeout=30)
    child_path = out_file.read_text(encoding="utf-8")
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
