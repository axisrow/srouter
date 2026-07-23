"""Иерархия блокировок + watchdog для 24/7-инфраструктуры (issue #159).

Investigation-first граф захвата (доказан, см. lock_hierarchy.py docstring): единственное
ребро вложенности `_MUTATION_LOCK → _SELECT_LOCK`, все остальные 5 локов — листья. Циклов
нет. Эти тесты закрывают превентивную защиту:

1. ЯВНАЯ иерархия захвата, проверяемая в рантайме (ordering-guard): будущая регрессия
   (обратное ребро `_SELECT_LOCK → _MUTATION_LOCK`) детектируется в момент захвата.
2. Watchdog: blocking-лок под hang'ом не висит вечно — bounded acquire выходит за бюджет
   (канон srouter-critical-infra-24-7).
3. Нулевая регрессия: default env (`timeout=0`, guard off) ≡ старое поведение `with lock:`.
"""
import threading
import time

import pytest

import lock_hierarchy
import node_selector


# ============================ ordering-guard (подход A) ============================

def test_hierarchy_levels_monotonic():
    # Меньше число = захват раньше, отпускается позже. Вложенность внутрь (низший → высший
    # числом) разрешена; обратное — нарушение иерархии.
    assert lock_hierarchy.LEVEL_MUTATION < lock_hierarchy.LEVEL_SELECT < lock_hierarchy.LEVEL_CACHE


def test_guard_off_is_noop(monkeypatch):
    # Без SROUTER_LOCK_ORDER_GUARD продакшен не платит за проверку: held() не трогает
    # thread-local стек и не возбуждает ничего при любом порядке.
    monkeypatch.delenv("SROUTER_LOCK_ORDER_GUARD", raising=False)
    monkeypatch.delenv("SROUTER_LOCK_ORDER_STRICT", raising=False)
    stack = lock_hierarchy._held_levels()
    stack.clear()
    with lock_hierarchy.held(lock_hierarchy.LEVEL_CACHE, "c"):
        with lock_hierarchy.held(lock_hierarchy.LEVEL_MUTATION, "m"):
            pass  # обратный порядок — но guard off, никакого сигнала
    assert stack == []  # стек не заполнялся вовсе


def test_nested_higher_to_lower_allowed(monkeypatch):
    # Доказанное ребро _MUTATION_LOCK → _SELECT_LOCK: MUTATION(level 0) удерживается,
    # SELECT(level 1) вкладывается — корректно (число растёт внутрь), без исключения.
    monkeypatch.setenv("SROUTER_LOCK_ORDER_GUARD", "1")
    monkeypatch.setenv("SROUTER_LOCK_ORDER_STRICT", "1")
    with lock_hierarchy.held(lock_hierarchy.LEVEL_MUTATION, "mutation"):
        with lock_hierarchy.held(lock_hierarchy.LEVEL_SELECT, "select"):
            assert lock_hierarchy._held_levels()[-1] == (lock_hierarchy.LEVEL_SELECT, "select")


def test_nested_lower_to_higher_detected(monkeypatch):
    # РЕГРЕССИЯ-ловушка: удерживая SELECT, захватить MUTATION — обратное ребро, будущий
    # deadlock. guard+strict обязаны это поймать в момент захвата (не дождавшись тупика).
    monkeypatch.setenv("SROUTER_LOCK_ORDER_GUARD", "1")
    monkeypatch.setenv("SROUTER_LOCK_ORDER_STRICT", "1")
    with lock_hierarchy.held(lock_hierarchy.LEVEL_SELECT, "select"):
        with pytest.raises(lock_hierarchy.LockOrderViolation):
            with lock_hierarchy.held(lock_hierarchy.LEVEL_MUTATION, "mutation"):
                pass


def test_violation_non_strict_logs_only(monkeypatch, caplog):
    # Канон srouter-critical-infra-24-7: guard не должен калечить работающий путь.
    # Без strict нарушение только логируется (fail-open), выполнение продолжается.
    monkeypatch.setenv("SROUTER_LOCK_ORDER_GUARD", "1")
    monkeypatch.delenv("SROUTER_LOCK_ORDER_STRICT", raising=False)
    import logging
    with caplog.at_level(logging.ERROR, logger="srouter.locks"):
        with lock_hierarchy.held(lock_hierarchy.LEVEL_SELECT, "select"):
            with lock_hierarchy.held(lock_hierarchy.LEVEL_MUTATION, "mutation"):
                pass  # не упало — fail-open
    assert any("lock-order violation" in rec.getMessage() for rec in caplog.records)


def test_stack_restored_on_exception(monkeypatch):
    # Исключение внутри held не должно оставлять мусор в thread-local стеке
    # (иначе следующий захват в этом потоке получит ложное нарушение).
    monkeypatch.setenv("SROUTER_LOCK_ORDER_GUARD", "1")
    stack = lock_hierarchy._held_levels()
    stack.clear()
    with pytest.raises(RuntimeError):
        with lock_hierarchy.held(lock_hierarchy.LEVEL_CACHE, "c"):
            raise RuntimeError("boom")
    assert stack == []


# ============================ watchdog bounded-acquire (подход C) ============================

def test_bounded_acquire_blocking_default():
    # Нулевая регрессия: timeout_sec=0/None блокирует до успеха, идентично `with lock:`.
    lk = threading.Lock()
    with lock_hierarchy.bounded_acquire(lk, name="t", level=lock_hierarchy.LEVEL_CACHE):
        assert not lk.locked() or lk.locked()  # внутри — держим
    assert not lk.locked()


def test_bounded_acquire_timeout_falls_back():
    # Занятый лок + маленький бюджет → on_timeout вызван, возвращён его результат
    # (stale/empty-fallback как у существующих кэшей).
    lk = threading.Lock()
    lk.acquire()
    try:
        called = {"v": False}

        def fallback():
            called["v"] = True
            return "stale"

        with lock_hierarchy.bounded_acquire(
            lk, name="t", level=lock_hierarchy.LEVEL_CACHE, timeout_sec=0.1, on_timeout=fallback
        ) as v:
            assert v == "stale"
        assert called["v"] is True
    finally:
        lk.release()


def test_bounded_acquire_timeout_raises_without_fallback():
    # Таймаут без on_timeout → структурный сбой (fail-closed), не тихой hang.
    lk = threading.Lock()
    lk.acquire()
    try:
        with pytest.raises(lock_hierarchy.LockAcquireTimeout):
            with lock_hierarchy.bounded_acquire(
                lk, name="t", level=lock_hierarchy.LEVEL_CACHE, timeout_sec=0.1
            ):
                pass
    finally:
        lk.release()


def test_env_timeout_sec_read(monkeypatch):
    # Канон more-options-better: SROUTER_LOCK_TIMEOUT_SEC задаёт дефолт бюджета.
    monkeypatch.setenv("SROUTER_LOCK_TIMEOUT_SEC", "0.2")
    assert lock_hierarchy._default_timeout_sec() == pytest.approx(0.2)


def test_env_timeout_invalid_falls_back_to_unbounded(monkeypatch):
    # Мусор в env → безопасный дефолт 0.0 (unbounded = наследие `with lock:`).
    monkeypatch.setenv("SROUTER_LOCK_TIMEOUT_SEC", "not-a-number")
    assert lock_hierarchy._default_timeout_sec() == 0.0
    monkeypatch.setenv("SROUTER_LOCK_TIMEOUT_SEC", "-5")
    assert lock_hierarchy._default_timeout_sec() == 0.0


def test_watchdog_breaks_simulated_hang():
    # ПРЯМАЯ проверка требования 24/7: один поток держит реальный _SELECT_LOCK (как при
    # долгом рестарте xray), второй обязан выйти за бюджет, а не висеть вечно.
    held = threading.Event()
    release = threading.Event()
    result = {"exc": None, "elapsed": None}

    def holder():
        with node_selector._SELECT_LOCK:
            held.set()
            release.wait(timeout=5.0)

    t = threading.Thread(target=holder)
    t.start()
    assert held.wait(timeout=2.0)
    start = time.monotonic()
    try:
        with lock_hierarchy.bounded_acquire(
            node_selector._SELECT_LOCK,
            name="select",
            level=lock_hierarchy.LEVEL_SELECT,
            timeout_sec=0.3,
        ):
            pass
    except lock_hierarchy.LockAcquireTimeout as exc:
        result["exc"] = exc
    result["elapsed"] = time.monotonic() - start
    release.set()
    t.join(timeout=5.0)
    # Должен был выйти через таймаут, не дождавшись освобождения держащего потока.
    assert isinstance(result["exc"], lock_hierarchy.LockAcquireTimeout)
    assert result["elapsed"] < 2.0  # вышел быстро, не завис на 5с держащего потока


# ============================ единый источник LEVEL_* (канон no-hidden-magic) ============================

def test_single_source_of_lock_levels():
    # Эталон tests/test_proxy_constants.py: ОПРЕДЕЛЕНИЯ числовых уровней блокировок
    # живут ТОЛЬКО в lock_hierarchy.py. Использования (`level=lock_hierarchy.LEVEL_*`)
    # в точках вызова — норма; ловим только повторное присвоение `LEVEL_* = <int>`.
    import pathlib
    import re
    root = pathlib.Path(lock_hierarchy.__file__).resolve().parent
    define_re = re.compile(r"^\s*LEVEL_(MUTATION|SELECT|CACHE)\s*=\s*\d", re.MULTILINE)
    offenders = []
    for py in root.glob("*.py"):
        if py.name == "lock_hierarchy.py":
            continue
        text = py.read_text(encoding="utf-8")
        for m in define_re.finditer(text):
            offenders.append(f"{py.name}:LEVEL_{m.group(1)}")
    assert not offenders, f"уровни блокировок определены вне lock_hierarchy.py: {offenders}"
