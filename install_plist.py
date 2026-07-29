#!/usr/bin/env python3
"""LaunchAgent plist-генерация и launchd-управление (issue #229, экстракция из install_lib.py).

Рендер/запись plist из шаблонов, tristate-проверка загрузки launchd-агента, bootout/bootstrap с
poll-ожиданием (issue #84/#93 контракты). Потребители: install_config.py (apply_install/build_plan
делегируют сюда LaunchAgent-часть), install_cleanup.py (unload при uninstall), srouter.py/health.py
(через install_lib-фасад).
"""
from __future__ import annotations

import os
import time
import xml.parsers.expat
from html import escape
from pathlib import Path

import plistlib

from sys_probe import run

LAUNCHCTL = "/bin/launchctl"

LAUNCHAGENT_LABEL = "com.srouter.dashboard"
LAUNCHAGENT_FILE = f"{LAUNCHAGENT_LABEL}.plist"
LAUNCHAGENT_MARKER = "srouter-managed-launchagent-v1"

# Надёжная перезагрузка launchd-агента: bootout асинхронен, домен gui/<uid>/<label> освобождается
# не сразу → `bootstrap` подряд падает `Bootstrap failed: 5: Input/output error`. Поэтому после
# bootout poll-ждём выгрузки, а bootstrap ретраим. Константы — уровня модуля, чтобы тесты могли
# занулить интервалы (мгновенные тесты без реального launchd). Канон: всегда-тдд.
_BOOTOUT_SETTLE_MAX_WAIT = 2.0   # суммарный потолок ожидания выгрузки после bootout (сек)
_BOOTOUT_POLL_INTERVAL = 0.5     # шаг poll «демон выгрузился?» (сек); 0.5 = 4 вызова вместо 10 при потолке 2.0
_BOOTSTRAP_MAX_RETRIES = 3       # попыток bootstrap, если домен ещё занят
_BOOTSTRAP_RETRY_DELAY = 0.5     # пауза между попытками bootstrap (сек)


def _has_launchagent_marker(path):
    return LAUNCHAGENT_MARKER in _read_head(path)


def _read_head(path, limit=4096):
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")[:limit]
    except OSError:
        return ""


def _launchd_domain():
    return f"gui/{os.getuid()}"


def _launchagent_template_path(env):
    return env.root / "launchagents" / LAUNCHAGENT_FILE


def _render_launchagent_plist(env):
    """Рендерим LaunchAgent из шаблона: абсолютные пути и только loopback dashboard.py."""
    template = _launchagent_template_path(env).read_text(encoding="utf-8")
    replacements = {
        "__SROUTER_LAUNCHAGENT_MARKER__": LAUNCHAGENT_MARKER,
        "__SROUTER_LAUNCHAGENT_LABEL__": LAUNCHAGENT_LABEL,
        "__SROUTER_PYTHON_BIN__": env.python_bin,
        "__SROUTER_DASHBOARD_PATH__": str(env.root / "dashboard.py"),
        "__SROUTER_ROOT_DIR__": str(env.root),
        "__SROUTER_LOG_OUT__": str(env.log_out),
        "__SROUTER_LOG_ERR__": str(env.log_err),
    }
    for key, value in replacements.items():
        template = template.replace(key, escape(str(value)))
    return template


def _write_launchagent(env):
    try:
        rendered = _render_launchagent_plist(env)
    except OSError:
        return False
    return _write_text_atomic(env.launchagent_path(), rendered)


def _write_text_atomic(path, text):
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(path)
        return True
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False


_LAUNCHCTL_SERVICE_NOT_FOUND = 113  # `launchctl print <domain>/<label>` rc: сервиса НЕТ в этом домене


def _launchd_is_loaded(label, *, domain=None, runner=run):
    """Загружен ли launchd-агент в КОНКРЕТНОМ домене — по `launchctl print <domain>/<label>`.

    Единственный источник правды для «агент загружен» — факт о launchd, живёт в plist-модуле (канон слоёв:
    CLI — тонкий слой над install_config/install_plist). Домен-осознанно НАМЕРЕННО: legacy `launchctl list`
    без домена инспектирует bootstrap-домен ВЫЗЫВАЮЩЕГО процесса (из SSH/launchd/cron — user/<uid> или
    system), НЕ gui/<uid>. Тогда gui-агент не виден в list → ложный False → удаление plist живого агента
    (fail-open, cycle-review #93). `print <domain>/<label>` спрашивает про ТОТ ЖЕ таргет, что и bootout
    в _launchd_unload — граница герметична, домен-mismatch невозможен.

    tristate по rc `launchctl print` (семантика по первоисточнику, проверена на реальном launchctl):
      rc == 0   -> сервис есть в домене                       -> True  (загружен)
      rc == 113 -> service-not-found (ЕДИНСТВЕННЫЙ путь к False) -> False (подтверждённо выгружен)
      иначе (rc 112 «домен не найден» / timeout / rc=None launch-failure / любой другой rc)
                -> состояние НЕИЗВЕСТНО                        -> None  (fail-safe: не трогать plist)

    domain по умолчанию gui/<uid> (_launchd_domain) — все текущие таргеты там. runner — чтобы ВСЕ
    launchctl-вызовы шли через одну точку: в тестах фейк, иначе poll-loop дёргал бы реальный launchctl.
    """
    domain = domain or _launchd_domain()
    r = runner([LAUNCHCTL, "print", f"{domain}/{label}"], 5)
    if r.get("rc") == 0:
        return True
    if not r.get("timeout") and r.get("rc") == _LAUNCHCTL_SERVICE_NOT_FOUND:
        return False  # 113 — ЕДИНСТВЕННЫЙ достоверный «выгружен»
    return None       # 112 / timeout / rc=None launch-failure / прочий rc — неизвестно (fail-safe)


def _launchd_unload(domain, label, *, runner=run):
    """Bootout launchd-агента → poll-wait до фактической выгрузки → tristate-статус.

    Единственный контракт «выгрузить с подтверждением» (issue #84). bootout асинхронен — launchd
    освобождает gui/<uid>/<label> с задержкой (~2с), пока _launchd_is_loaded ещё возвращает True.
    Любой потребитель ОБЯЗАН дождаться реальной выгрузки, прежде чем действовать на результат
    (unlink plist / unsetenv / re-bootstrap). Это тот самый poll, один раз. Не бросает.

    Возвращает {"state": tristate} — состояние launchd ПОСЛЕ settle-окна (тот же словарь, что
    _launchd_is_loaded):
      state is False -> подтверждённо выгружен (можно unlink / unsetenv / продолжать)
      state is True  -> ещё загружен после settle (fail-safe: оставить plist)
      state is None  -> неизвестно (list/print сбой или timeout) (fail-safe: оставить plist)

    bootout rc игнорируем: «уже выгружен» — не ошибка. bootout и проверка выгрузки идут по ОДНОМУ
    таргету domain/label (герметичность, cycle-review #93). runner маршрутизирует ВСЕ launchctl-вызовы
    (bootout + print) через одну точку — для тестов. Возврат — dict (не голый tristate) по конвенции
    репо (dict-возвраты у _launchd_reload/_unload_launchagent) и ради forward-совместимости.
    """
    def is_loaded():
        return _launchd_is_loaded(label, domain=domain, runner=runner)

    # 1. bootout (игнорируем rc — уже выгружен = не ошибка).
    runner([LAUNCHCTL, "bootout", f"{domain}/{label}"], 10)

    # 2. poll-wait: ждём, пока launchd РЕАЛЬНО выгрузит агента. Время по часам (не накоплением
    # interval) — иначе при interval=0 (тесты) цикл стал бы бесконечным. `while state and …`:
    # True truthy → крутим; None (list-timeout) falsy → выходим сразу, tristate проходит насквозь
    # (НЕ `while state is not False` — иначе полные settle-2с на каждом таймауте + провокация True).
    deadline = time.monotonic() + _BOOTOUT_SETTLE_MAX_WAIT
    state = is_loaded()
    while state and time.monotonic() < deadline:
        time.sleep(_BOOTOUT_POLL_INTERVAL)
        state = is_loaded()
    return {"state": state}


def _launchd_reload(domain, plist, label, *, runner=run):
    """Перезагрузить launchd-агента надёжно: bootout → poll-wait выгрузки → bootstrap(retry).

    Решает гонку «Bootstrap failed: 5: Input/output error»: launchd не успевает освободить слот
    домена между bootout и bootstrap. Поэтому после bootout ждём фактической выгрузки (через
    _launchd_is_loaded), а bootstrap ретраим с паузой. Возвращает {ok: bool, last_err: str}, не бросает.

    runner — функция cmd/timeout → dict (как _install_launchagent принимает; по умолчанию sys_probe.run).
             ВСЕ launchctl-вызовы (bootout, print, bootstrap) идут через него — единая точка для тестов.
    """

    def is_loaded():
        return _launchd_is_loaded(label, domain=domain, runner=runner)

    # 1-2. bootout + poll реальной выгрузки (общий контракт _launchd_unload). state СОЗНАТЕЛЬНО
    # игнорируем: reload всегда re-bootstrap'ит, даже если выгрузка не подтверждена — bootstrap-retry
    # ниже сам покроет занятость домена. Поведение идентично прежнему (bootout всегда → bootstrap).
    _launchd_unload(domain, label, runner=runner)

    # 3. bootstrap с retry: домен может быть ещё занят.
    last_err = ""
    for _ in range(_BOOTSTRAP_MAX_RETRIES):
        b = runner([LAUNCHCTL, "bootstrap", domain, str(plist)], 15)
        if b.get("timeout"):
            # launchctl может таймаутить, но агента всё-таки поднять (медленный диск) — проверим.
            last_err = "timeout"
        elif b.get("rc") == 0:
            return {"ok": True, "last_err": ""}
        else:
            last_err = b.get("err") or b.get("out") or "bootstrap failed"
        # soft-success: bootstrap вернул ненулевой rc/timeout, но агент всё-таки поднялся.
        if is_loaded():
            return {"ok": True, "last_err": ""}
        time.sleep(_BOOTSTRAP_RETRY_DELAY)
    return {"ok": False, "last_err": last_err}


def _install_launchagent(env, runner):
    plist_path = env.launchagent_path()
    if plist_path.exists() and not _has_launchagent_marker(plist_path):
        return False, "launchagent_foreign"
    if not _write_launchagent(env):
        return False, "launchagent_write_failed"

    domain = _launchd_domain()
    # Надёжная перезагрузка: bootout → poll-wait → bootstrap(retry). Решает гонку занятого домена.
    res = _launchd_reload(domain, plist_path, LAUNCHAGENT_LABEL, runner=runner)
    if res["ok"]:
        return True, ""
    # Fallback для старого launchd без bootstrap/bootout: load -w.
    fallback = runner([LAUNCHCTL, "load", "-w", str(plist_path)], 15)
    if fallback.get("timeout") or fallback.get("rc") != 0:
        return False, "launchagent_load_failed"
    return True, ""


# ============================ обобщённый рендер/загрузка plists (watchdog/isolate/...) ============================
def _render_generic_launchagent(env, *, template_name, label, marker, script_path):
    """Рендерить произвольный LaunchAgent из шаблона launchagents/<template_name>.

    Обобщение _render_launchagent_plist: разные label/marker/script (health.py, isolate_firewall.py,
    и т.д.). Подставляет __SROUTER_<LABEL>_LABEL__, __SROUTER_<X>_MARKER__, __SROUTER_<X>_PATH__,
    плюс общие PYTHON_BIN/ROOT_DIR/LOG_*. escape — как в dashboard.
    """
    template = (env.root / "launchagents" / template_name).read_text(encoding="utf-8")
    # Префикс для плейсхолдеров LABEL/MARKER/PATH — из label (напр. com.srouter.watchdog → WATCHDOG).
    # Из label надёжнее, чем из marker (marker может иметь -v1 суффикс → WATCHDOG_V1 ≠ WATCHDOG).
    prefix = label.rsplit(".", 1)[-1].upper()  # com.srouter.watchdog → WATCHDOG
    replacements = {
        f"__SROUTER_{prefix}_LABEL__": label,
        f"__SROUTER_{prefix}_MARKER__": marker,
        f"__SROUTER_{prefix}_PATH__": str(script_path),
        "__SROUTER_PYTHON_BIN__": env.python_bin,
        "__SROUTER_ROOT_DIR__": str(env.root),
        "__SROUTER_LOG_OUT__": str(env.log_out),
        "__SROUTER_LOG_ERR__": str(env.log_err),
    }
    for key, value in replacements.items():
        template = template.replace(key, escape(str(value)))
    return template


def _install_generic_launchagent(env, runner, *, template_name, label, marker, script_path):
    """Рендер + загрузка произвольного LaunchAgent (watchdog/isolate/...). Возвращает (ok, err).

    Симметрично _install_launchagent, но с заданным label/marker/script. Путь plist =
    launchagent_dir/<label>.plist. bootout (ignore) → bootstrap (fallback load -w). main ruleset НЕ
    трогается (anchor com.apple/* уже в /etc/pf.conf — но это LaunchAgent, не PF; просто под-anchor).
    """
    plist_path = env.launchagent_dir / f"{label}.plist"
    # Если чужой plist без нашего маркера — не трогаем.
    if plist_path.exists():
        try:
            existing = plist_path.read_text(encoding="utf-8")
            if marker not in existing:
                return False, f"{label}_foreign"
        except OSError:
            return False, f"{label}_read_failed"
    try:
        rendered = _render_generic_launchagent(env, template_name=template_name, label=label,
                                               marker=marker, script_path=script_path)
    except OSError as exc:
        return False, f"{label}_template_failed: {exc}"
    if not _write_text_atomic(plist_path, rendered):
        return False, f"{label}_write_failed"

    domain = _launchd_domain()
    # Надёжная перезагрузка: bootout → poll-wait → bootstrap(retry). Решает гонку занятого домена.
    res = _launchd_reload(domain, plist_path, label, runner=runner)
    if res["ok"]:
        return True, ""
    # Fallback для старого launchd без bootstrap/bootout: load -w.
    fallback = runner([LAUNCHCTL, "load", "-w", str(plist_path)], 15)
    if fallback.get("timeout") or fallback.get("rc") != 0:
        return False, f"{label}_load_failed"
    return True, ""


def _unload_launchagent(item, runner):
    plist_path = item.get("plist_path") or ""
    if not item.get("removable") or not plist_path:
        return {"ok": True, "changed": False}
    domain = _launchd_domain()
    expected_label = item.get("label") or LAUNCHAGENT_LABEL
    # identity-связка plist↔label ДО выгрузки (issue #94 DEFECT B). label и plist_path берутся из
    # state-item НЕЗАВИСИМО — при state-drift (label агента X, path агента Y) или marker-preserving
    # подмене Label внутри plist: bootout по item.label (X) → rc 113 (не найден = «выгружен») → unlink
    # удалил бы plist_path ЖИВОГО агента Y. Строгий первоисточник — сам plist: plistlib.load + требуем
    # Label==item.label==path-derived (имя файла). Любой mismatch → fail-closed, plist не трогаем.
    # Проверка ДО bootout: не удалять даже контроль живого агента, если identity не подтверждена.
    path = Path(plist_path)
    path_label = path.stem  # com.srouter.dashboard.plist → com.srouter.dashboard
    try:
        data = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException, ValueError,
            xml.parsers.expat.ExpatError):
        # Битый/чужой plist: OSError (нет файла/доступ), InvalidFileException/ValueError (plistlib
        # не распознал формат), ExpatError (битый XML — НЕ подкласс ValueError, отдельная иерархия
        # xml.parsers.expat). Любая невалидность → identity не верифицируема → fail-closed.
        return {"ok": False, "blocked": "launchagent_identity_mismatch"}
    plist_label = data.get("Label") if isinstance(data, dict) else None
    if plist_label != expected_label or path_label != expected_label:
        # Три арбитра (item.label / Label-в-plist / имя-файла) должны совпасть. Mismatch = аномалия
        # (state-drift / подмена файла) → НЕ unlink, окно выгрузки тоже не открываем. Fail-closed.
        return {"ok": False, "blocked": "launchagent_identity_mismatch"}
    # bootout + poll реальной выгрузки по ВАЛИДИРОВАННОМУ label (общий контракт, issue #84). unlink
    # ТОЛЬКО при подтверждённой выгрузке (state is False): живой StartInterval-агент иначе
    # пере-применял бы мёртвый конфиг.
    state = _launchd_unload(domain, expected_label, runner=runner)["state"]
    if state is not False:
        # ещё загружен (True) ИЛИ неизвестно/list-timeout (None): НЕ unlink. Fail-safe: оставить plist.
        return {"ok": False, "blocked": "launchagent_unload_failed"}
    try:
        path.unlink(missing_ok=True)
    except OSError:
        return {"ok": False, "blocked": "launchagent_remove_failed"}
    return {"ok": True, "changed": True}
