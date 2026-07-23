"""Явная иерархия захвата блокировок + watchdog-таймаут для 24/7-инфраструктуры.

issue #159 — аудит 6 threading.Lock в srouter без явной иерархии захвата.

========================= ГРАФ ЗАХВАТА (investigation-first) =========================

Построен по коду (канон verify-dont-guess — не догадка). В проекте ровно 6 threading.Lock:

  MUTATION  dashboard._MUTATION_LOCK   — non-blocking acquire в before_request (dashboard.py),
                                          держится весь POST-handler; занято → 409. Off вне POST.
  SELECT    node_selector._SELECT_LOCK — select_node → _select_node_locked (рестарт xray +
                                          route-sync под локом).
  CACHE     dashboard._lock            — status-кэш gather_status (dict-only внутри).
          dashboard_geo._geo_lock      — geo IP-кэш (curl ВНЕ лока).
          dashboard_nodes._nodes_lock  — snapshot-кэш (dict-only внутри).
          dashboard_hotroutes._lock    — hot-routes probe-кэш (dict/set-only внутри).

Единственное ребро вложенности «держа A, берётся B»:

        _MUTATION_LOCK  ──►  _SELECT_LOCK        (api_node_select → node_selector.select_node)

Все 5 остальных локов — ЛИСТЬЯ: внутри их `with`-блоков только dict/set-доступ, внешние
вызовы (curl, probes, subprocess) вынесены за пределы лока; _SELECT_LOCK внутри зовёт
только local_state.*/gen_xray_config/subprocess — ни один не берёт threading.Lock.

==> ГРАФ АЦИКЛИЧЕН (DAG). DEADLOCK-ЦИКЛОВ НЕТ.

Почему обратное ребро _SELECT_LOCK → _MUTATION_LOCK возникнуть не может (инвариант):
  - импорт dashboard в node_selector запрещён каноном (node_selector.py:26);
  - select_node имеет единственный call-site (api_node_select), уже под _MUTATION_LOCK.

Регрессии, которые сломали бы инвариант (и станут детектироваться ordering-guard):
  - вызов gather_status()/probe_* внутри POST-handler (ребро MUTATION→CACHE);
  - второй threading.Lock в local_state/gen_xray_config, взятый внутри _SELECT_LOCK;
  - _MUTATION_LOCK.acquire(blocking=True) вместо blocking=False (не цикл, но hang-риск).

========================= ИЕРАРХИЯ (подход A) =========================

  LEVEL_MUTATION=0  >  LEVEL_SELECT=1  >  LEVEL_CACHE=2

Меньше число = захват раньше, отпускается позже. Вложенность «наружу внутрь» (число
растёт) разрешена; обратное — нарушение иерархии (потенциальный тупик). Кэш-локи на одном
уровне: между собой не вкладываются, поэтому конфликтовать не могут.

ordering-guard (held()) по умолчанию OFF (SROUTER_LOCK_ORDER_GUARD=1 чтобы включить):
продакшен не платит за проверку, у которой сегодня 0 нарушений. Нарушение в не-strict
режиме только логируется (fail-open, канон srouter-critical-infra-24-7 — не калечим
работающий путь); в strict (SROUTER_LOCK_ORDER_STRICT=1) — RuntimeError (для CI/тестов).

========================= WATCHDOG (подход C) =========================

bounded_acquire() — bounded `acquire(timeout=t)`: hang держащего кода не вешает 24/7-инфру
намертво, за бюджет выходит через on_timeout (stale/empty-fallback) или LockAcquireTimeout.
Default SROUTER_LOCK_TIMEOUT_SEC=0 (unbounded) — поведение идентично старому `with lock:`,
нулевая регрессия. _MUTATION_LOCK НЕ оборачивается (уже non-blocking 409).

Каноны: no-hidden-magic (явные уровни, единый источник), more-options-better (env-опции),
srouter-critical-infra-24-7 (guard/watchdog не вносят новую точку сбоя в работающий путь),
verify-dont-guess (граф доказан до кода).
"""
from __future__ import annotations

import contextlib
import logging
import os
import threading

_log = logging.getLogger("srouter.locks")

# --- Явная иерархия захвата (меньше число = захват раньше, отпускается позже) ---
LEVEL_MUTATION = 0
LEVEL_SELECT = 1
LEVEL_CACHE = 2

# Thread-local стек уровней удерживаемых блокировок. Запись только при включенном guard
# (по умолчанию off — нулевая цена для продакшена).
_tlocal = threading.local()


def _held_levels():
    """Стек (level, name) удерживаемых в текущем потоке блокировок (guard-only)."""
    stack = getattr(_tlocal, "levels", None)
    if stack is None:
        stack = []
        _tlocal.levels = stack
    return stack


# --- env-опции (канон more-options-better, эталон install_lib.py:121) ---
def _guard_enabled():
    """runtime ordering-guard. off по умолчанию: продакшен не платит за проверку,
    у которой сегодня 0 нарушений. on (SROUTER_LOCK_ORDER_GUARD=1) — превентивно/CI."""
    return os.environ.get("SROUTER_LOCK_ORDER_GUARD", "") == "1"


def _strict_mode():
    """off (по умолчанию): нарушение порядка → warning в лог, выполнение продолжается
    (fail-open, не калечим 24/7). on (SROUTER_LOCK_ORDER_STRICT=1): → RuntimeError."""
    return os.environ.get("SROUTER_LOCK_ORDER_STRICT", "") == "1"


def _default_timeout_sec():
    """Ограниченный бюджет захвата для watchdog. 0 = неограниченно (наследие blocking
    `with lock:`, нулевая регрессия). Мусор/отрицательное → 0.0 (безопасный дефолт)."""
    raw = os.environ.get("SROUTER_LOCK_TIMEOUT_SEC", "0")
    try:
        v = float(raw)
    except (TypeError, ValueError):
        return 0.0
    return v if v > 0 else 0.0


class LockOrderViolation(RuntimeError):
    """Нарушение иерархии захвата (только в strict-режиме, SROUTER_LOCK_ORDER_STRICT=1)."""


class LockAcquireTimeout(RuntimeError):
    """watchdog: блокировка не захвачена за бюджет SROUTER_LOCK_TIMEOUT_SEC / timeout_sec."""


@contextlib.contextmanager
def held(level, name):
    """ordering-guard-контекст: вызывается ПОСЛЕ успешного захвата сырого Lock.

    Кладёт (level, name) в thread-local стек, проверяет монотонность порядка
    (вложенный уровень >= внешнего — захват «внутрь» разрешён), снимает в finally.
    Дешёвый no-op, если guard выключен (продакшен по умолчанию).
    """
    if not _guard_enabled():
        yield
        return
    stack = _held_levels()
    if stack and level < stack[-1][0]:
        # Нарушение: захватил уровень ВЫШЕ (меньше число), удерживая нижний — будущий тупик.
        msg = (
            f"lock-order violation: acquiring {name}(level={level}) while holding "
            f"{stack[-1][1]}(level={stack[-1][0]}); hierarchy MUTATION<SELECT<CACHE"
        )
        _log.error(msg)
        if _strict_mode():
            raise LockOrderViolation(msg)
    stack.append((level, name))
    try:
        yield
    finally:
        stack.pop()


@contextlib.contextmanager
def bounded_acquire(lock, *, name, level, timeout_sec=None, on_timeout=None):
    """Ограниченный захват блокировки + ordering-guard-аннотация.

    - timeout_sec > 0: bounded acquire; не получилось за бюджет → on_timeout() (если задан)
      или raise LockAcquireTimeout. timeout_sec == 0/None → блокирующее поведение,
      идентичное `with lock:` (нулевая регрессия семантики существующих локов).
    - on_timeout: вызывается БЕЗ захвата лока; его результат выдаётся как value контекста
      (stale/empty-fallback). Не используется для точек, где таймаут = структурный сбой.
    - ordering-guard (held) срабатывает только при SROUTER_LOCK_ORDER_GUARD=1.

    Это каноническая обёртка для всех кэш-локов и _SELECT_LOCK.
    _MUTATION_LOCK НЕ оборачивается (уже non-blocking 409, трогать запрещено каноном).
    """
    t = timeout_sec if timeout_sec is not None else _default_timeout_sec()
    if t and t > 0:
        ok = lock.acquire(timeout=t)
    else:
        # blocking=True: возвращает None (старые Python) или True — трактуем как успех.
        ok = lock.acquire(blocking=True)
        if ok is None:
            ok = True
    if not ok:
        if on_timeout is not None:
            # Контекст «провалился» без захвата: отдаём fallback, release не зовём.
            yield on_timeout()
            return
        raise LockAcquireTimeout(f"{name}: acquire timed out after {t}s")
    try:
        with held(level, name):
            yield
    finally:
        lock.release()
