"""Двухпроцессный harness для _mutation_lock regression-теста (issue #282).

Запускается как standalone процесс subprocess-ом из test_git_proxy_architectural.py
(role + workdir через argv, HOME через env). Доказывает, что _mutation_lock даёт
НАСТОЯЩЕЕ cross-process взаимоисключение (fcntl.flock), а не process-local примитив
(threading.Lock / threading.Lock-based mutex), который прошёл бы in-process harness, но не
защитил бы реальный сценарий issue #234 (CLI-процесс vs dashboard-поток — РАЗНЫЕ процессы).

Роли:
  holder — входит в _mutation_lock, сигналит `holder_entered` СТРОГО ПОСЛЕ входа в
           защищённое тело (после реального flock), держит лок до появления маркера
           `release`, затем выходит. rc=0 при успехе.
  waiter  — сигналит `waiter_started`, затем `waiter_attempting` ПЕРЕД блокирующим входом
           в _mutation_lock. Если вход произошёл ДО `release` (holder ещё держит лок) —
           значит лок НЕ cross-process (сломан): сигналит `waiter_entered_too_early` и
           завершается rc=2. Если дождался входа ПОСЛЕ `release` — нормальный сериализованный
           вход: сигналит rc=0.
  probe   — детерминированный LOCK_EX|LOCK_NB-пробер канонического lockfile (argv[3]='locked'|'free'):
            'locked' обязан получить EWOULDBLOCK (flock удержан holder'ом), 'free' — приобрести.
            rc=0 при совпадении ожидания, ненулевой иначе. Это авторитетный ответ ОС, замена
            wall-clock-absence-проверки (cycle-review #283, Codex round 2).

Маркеры — файлы в workdir (argv[2]). Env-флаг SR_BROKEN_LOCK=1 подменяет _mutation_lock
на process-local threading.Lock — негативный контроль: harness ОБЯЗАН детектировать такой
лок как `entered_too_early` (иначе он был бы false-green на настоящем flock).

Propagated exceptions: любой BaseException из _mutation_lock/критической секции ловится и
превращается в rc!=0 (+ результат пишется в *.result), чтобы тест видел сбой процесса как
отказ, а не как молчаливое прохождение.
"""
import contextlib
import errno
import fcntl
import os
import sys
import threading
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

def _write(path: Path, text: str) -> None:
    path.write_text(text)


def _wait_for(path: Path, timeout: float, poll: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(poll)
    return False


def _make_lock():
    """Возвращает lock-фабрику (_mutation_lock) — настоящую или намеренно сломанную."""
    if os.environ.get("SR_BROKEN_LOCK") == "1":
        # Негативный контроль: process-local threading.Lock НЕ сериализует между процессами
        # (у каждого процесса свой объект). Такой лок прошёл бы in-process harness, но не
        # защитил бы cross-process сценарий issue #234.
        _process_local = threading.Lock()

        @contextlib.contextmanager
        def _cm():
            with _process_local:
                yield True

        return _cm
    # Ленивый импорт: root-модуль виден только после sys.path.insert выше; при standalone
    # запуске (subprocess, без pytest) conftest не выполняется, поэтому импортируем здесь.
    import git_proxy

    return git_proxy._mutation_lock


def _holder(workdir: Path) -> int:
    try:
        lock_factory = _make_lock()
        with lock_factory() as acquired:
            if not acquired:
                _write(workdir / "holder.result", "no-lock")
                return 3
            # Вход в защищённое тело ПОСЛЕ реального flock — сигналим только теперь.
            _write(workdir / "holder_entered", "1")
            if not _wait_for(workdir / "release", timeout=30):
                _write(workdir / "holder.result", "timeout-waiting-release")
                return 4
            _write(workdir / "holder.result", "ok")
        return 0
    except BaseException as exc:  # noqa: BLE001 — симметрично _waiter: propagated exception = rc!=0
        _write(workdir / "holder.result", f"exception:{type(exc).__name__}:{exc}")
        return 5


def _waiter(workdir: Path) -> int:
    _write(workdir / "waiter_started", "1")
    lock_factory = _make_lock()
    _write(workdir / "waiter_attempting", "1")  # на пороге блокирующего входа
    try:
        with lock_factory() as acquired:
            if not acquired:
                _write(workdir / "waiter.result", "no-lock")
                return 3
            # ВОШЛИ в критическую секцию. Если holder ЕЩЁ держит лок (release не написан) —
            # значит лок НЕ cross-process (сломан). Если release уже написан — нормальный
            # сериализованный вход после освобождения holder'а.
            if not (workdir / "release").exists():
                _write(workdir / "waiter_entered_too_early", "1")
                _write(workdir / "waiter.result", "entered-before-release")
                return 2
            _write(workdir / "waiter.result", "ok")
        return 0
    except BaseException as exc:  # noqa: BLE001 — propagated exception = сбой процесса (rc!=0)
        _write(workdir / "waiter.result", f"exception:{type(exc).__name__}:{exc}")
        return 5


def _probe(workdir: Path, expect: str) -> int:
    """Детерминированный cross-process probe (cycle-review #283, Codex round 2).

    Открывает канонический lockfile `_mutation_lock` (git_proxy._MUTATION_LOCKFILE — единый
    источник правды, не дублируем имя) и пытается LOCK_EX|LOCK_NB:
      - expect='locked' (holder внутри _mutation_lock): обязан получить EWOULDBLOCK — flock удержан
        другим процессом. rc=0 при EWOULDBLOCK, rc=3 если лок НЕ удержан (сломан/process-local).
      - expect='free' (holder вышел): обязан приобрести лок. rc=0 при приобретении, rc=2 если занят.

    Это авторитетный ответ ОС без тайминговых окон — замена wall-clock-absence-проверки, которая
    могла false-green на сломанном локе, задерживающем yield дольше окна (канон
    wall-clock-assert-is-not-the-invariant).
    """
    import git_proxy

    lock_p = Path.home() / git_proxy._MUTATION_LOCKFILE
    try:
        fd = os.open(lock_p, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError as exc:
        _write(workdir / "probe.result", f"open-failed:{exc}")
        return 6
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno == errno.EWOULDBLOCK:
                # flock удержан другим процессом.
                if expect == "locked":
                    _write(workdir / "probe.result", "blocked-as-expected")
                    return 0
                _write(workdir / "probe.result", "blocked-unexpectedly")
                return 2
            _write(workdir / "probe.result", f"flock-error:{exc.errno}")
            return 7
        else:
            # flock приобретён (никто не держит).
            if expect == "free":
                _write(workdir / "probe.result", "acquired-as-expected")
                return 0
            _write(workdir / "probe.result", "acquired-unexpectedly")
            return 3
    finally:
        os.close(fd)


def main() -> None:
    role = sys.argv[1]
    workdir = Path(sys.argv[2])
    if role == "holder":
        sys.exit(_holder(workdir))
    elif role == "waiter":
        sys.exit(_waiter(workdir))
    elif role == "probe":
        sys.exit(_probe(workdir, sys.argv[3]))
    sys.exit(10)


if __name__ == "__main__":
    main()
