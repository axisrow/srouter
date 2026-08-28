"""Health-пробы для codenv (launchd gui-env SOCKS5), Desktop App proxy, ChatGPT.app, VSCode, gh/git.

Извлечено из health.py (issue #158 — разбиение крупного файла на модули по обязанностям).
health.py остаётся тонким фасадом: `from health_codenv import *` ре-экспортирует все публичные
имена (канон star-import-reexport-contract) — существующие `health.<name>` и monkeypatch на
`health` module продолжают работать без изменений.
"""
from pathlib import Path
import logging
import os
import time
from urllib.parse import urlparse

import sys_probe
import system_proxy_control
from install_lib import _LAUNCHCTL_SERVICE_NOT_FOUND, _launchd_domain, _launchd_is_loaded
from health_constants import PRIVOXY_PORT, XRAY_PORT

import health as _health_facade  # noqa: E402 — резолвит intra/inter-module вызовы через health для monkeypatch (канон #158)

_log = logging.getLogger("srouter.health")

# star-import re-export (канон star-import-reexport-contract) — см. health_probes.py докстринг __all__.
__all__ = [
    "LAUNCHCTL_PROXY_KEYS", "_read_proxy_sources", "_codenv_managed", "_desktop_proxy_check",
    "_CODENV_LABEL", "_CODENV_MARKER", "_CODENV_SOCKS_URL", "_read_gui_proxy_env",
    "_AO_WORKTREE_MARK", "_in_ao_worktree",
    "_CODENV_STDERR_TAIL_BYTES", "_codenv_default_stderr_path", "_codenv_stderr_tail",
    "_codenv_plist_is_managed", "_codenv_job_state", "_CODENV_RELOAD_SETTLE_WAIT",
    "_codenv_unloaded_is_persistent", "_codenv_job_check",
    "_codex_app_proxy_check", "_app_pids_route", "_codex_app_chromium_proxy_check",
]

# Абсолютные пути: launchd/GUI PATH их не содержит (канон проекта).
LSOF = "/usr/sbin/lsof"
PS = "/bin/ps"
LAUNCHCTL = "/bin/launchctl"

# ============================ #134: Desktop App proxy (launchctl getenv) ============================

# launchctl держит ТРИ прокси-ключа; Desktop App наследует все. Инцидент #127: SOCKS5 сидел в
# HTTP_PROXY (не HTTPS_PROXY) → doctor (читая только HTTPS_PROXY) сказал ✅. Обходим все три,
# НЕ угадывая selector приложения (он у Claude/Node/Electron разный) — показываем «как есть».
# NOTE: не то же что CODEX_LAUNCHCTL_ENV в srouter.py — там (key, SOCKS5-value)-пары для Codex
# install; здесь — диагностика Claude Desktop, другая семантика.
LAUNCHCTL_PROXY_KEYS = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY")


def _read_proxy_sources():
    """Читает Desktop App прокси (launchctl gui-домен) + CLI прокси (settings.json) — #134.

    Desktop App видит launchd gui-домен, в отличие от CLI (settings.json). launchctl держит ТРИ
    ключа (LAUNCHCTL_PROXY_KEYS); инцидент #127 — SOCKS5 в HTTP_PROXY. Не угадываем приоритет
    приложения — собираем все найденные «как есть», классификацию делает _desktop_proxy_check.
    cli_proxy (settings.json HTTPS_PROXY) нужен для детекта расхождения CLI vs Desktop (issue #134 п.2) —
    один клиент может работать, другой быть сломан, а без сравнения doctor молчит (#127-класс инцидент).

    cycle-review PR #219 round 2 (Codex, confidence 0.96): голый `launchctl getenv KEY` читает
    caller-context домен, НЕ gui/<uid> (issue #191 — тот же класс). Из SSH/cron/AO-shell это может
    быть НЕ gui-домен → _desktop_proxy_check сверял бы SOCKS5-значение с _CODENV_SOCKS_URL по
    значению из НЕПРАВИЛЬНОГО домена. Делегируем в _read_gui_proxy_env() (`launchctl print gui/<uid>`,
    тот же domain-aware источник, что уже использует _codenv_managed) — единый домен для всей
    codenv-trust цепочки. verifiable=False (timeout/unknown domain) → desktop_keys пуст (fail-closed:
    не выдумываем значения из caller-context, лучше unknown, чем ложный ok/info).

    Возвращает {desktop_keys: {KEY: value}, cli_proxy: str}. Не бросает (fail-soft: import claude_proxy
    — local, сохраняет fail-soft границу health).
    """
    gui = _health_facade._read_gui_proxy_env(keys_filter=LAUNCHCTL_PROXY_KEYS)
    desktop_keys = gui.get("keys") or {} if gui.get("verifiable") else {}
    try:
        import claude_proxy
        data = claude_proxy._load()
        env = data.get("env", {}) if isinstance(data, dict) else {}
        cli_proxy = env.get("HTTPS_PROXY", "") or os.environ.get("HTTPS_PROXY", "")
    except ImportError as exc:
        _log.debug("claude_proxy недоступен: %s — cli_proxy пуст", exc)
        cli_proxy = ""
    return {"desktop_keys": desktop_keys, "cli_proxy": cli_proxy}


def _codenv_managed(runner=None):
    """codenv LaunchAgent srouter-managed? Маркер в plist (provenance) И реально loaded в launchd.

    Архитектурный конфликт #189/#127: codenv ставит SOCKS5 в gui-домен (нужно ChatGPT.app Rust
    app-server), но тот же SOCKS5 ломает Claude Desktop App (#127). _desktop_proxy_check отличает
    «наш codenv» (намеренный tradeoff → info, не driver-шум) от «чужой корпоративный SOCKS5» (→ down).

    issue #192: маркер на диске один — НЕДОСТАТОЧЕН. Stale-plist сценарий: codenv когда-то стоял,
    потом bootout БЕЗ удаления plist (маркер остаётся навсегда), пользователь ставит ЧУЖОЙ SOCKS5
    вручную — маркер-only читал бы это как managed=True → info, молча маскируя инцидент #127.
    managed = маркер В plist (provenance) AND job РЕАЛЬНО загружен в launchd (install_lib.
    _launchd_is_loaded — домен-осознанный `launchctl print`, rc=0 loaded/113 not-found/иначе
    unknown fail-safe). Только оба условия дают True; unknown (None) НЕ трактуется как loaded —
    не выдумываем managed без доказательства (та же fail-safe семантика, что и сам _launchd_is_loaded).

    runner: опциональный (cmd, timeout) -> {rc, out, err, timeout} для _launchd_is_loaded — по
    умолчанию sys_probe.run (as-is для health.py doctor-чеков), инъекция для тестов.
    Ошибка чтения plist/отсутствие → False (fail-safe: трактуем как чужой → down, не глушим #127).
    """
    try:
        plist = Path.home() / "Library" / "LaunchAgents" / f"{_CODENV_LABEL}.plist"
        has_marker = plist.exists() and _CODENV_MARKER in plist.read_text(encoding="utf-8")
    except (OSError, ValueError):
        # OSError — нет файла/прав; ValueError — UnicodeDecodeError на бинарном/повреждённом plist
        # (codenv plist обычно XML, но может быть binary plutil-convert или битым). НЕ Exception —
        # иначе маскирует баги (канон systemexit-breaks-except-exception-fallback). Fail-safe False.
        return False
    if not has_marker:
        return False
    run = runner if runner is not None else sys_probe.run
    loaded = _launchd_is_loaded(_CODENV_LABEL, domain=_launchd_domain(), runner=run)
    return loaded is True


def _desktop_proxy_check():
    """Прокси Desktop App (launchctl getenv) — SOCKS5 в любом ключе → down (#127/#134).

    Не угадываем selector приложения (у Claude/Node/Electron разные). Для Claude SOCKS5 ломается
    везде (#127 fiasco), HTTP работает. SOCKS5 в любом launchctl-ключе — либо уже ломает, либо
    мина (вспыхнет при смене конфига) → down. Scheme-классификация через urlparse (эталон #127,
    не подстрока — иначе http://socks.example.com даст ложный down). detail перечисляет все
    найденные ключи «как есть».

    issue #189 codenv-aware: SOCKS5 от srouter-managed codenv (для ChatGPT.app Rust app-server) —
    намеренный tradeoff (лечит ChatGPT.app #189, ломает Claude Desktop App #127). doctor показывает
    факт в detail, но НЕ роняет вердикт (status="info") — иначе нормальная установка с codenv вечно
    degraded (шум, как PR #135 для PF). Чужой SOCKS5 (не codenv) → по-прежнему down (#127-инцидент).

    Расхождение settings.json (CLI) vs launchctl HTTPS_PROXY (Desktop) → warn (issue #134 п.2):
    один клиент может работать, другой сломан, а без этого сравнения doctor молчит (#127-класс).
    down (уже сломанный SOCKS5) важнее warn (потенциальное расхождение) — проверяется первым.
    """
    src = _health_facade._read_proxy_sources()
    keys = src["desktop_keys"]
    cli_proxy = src.get("cli_proxy", "")
    if not keys:
        return {"status": "unknown",
                "detail": "launchctl proxy не задан — Desktop App идёт напрямую (ok для NO_PROXY-доменов, не защищён PF для остальных)"}
    # SOCKS-scheme в ЛЮБОМ ключе → down (Claude Code/Desktop App через SOCKS не умеют, #127).
    # urlparse по scheme, не подстрока — канон loose-validator (см. _tunnel_target_up в health_probes.py:
    # bad-code/upstream-error парсится структурно, не подстрокой).
    socks_keys = {k: v for k, v in keys.items()
                  if urlparse(v).scheme.lower() in {"socks", "socks5", "socks5h"}}
    if socks_keys:
        bad = ", ".join(f"{k}={v}" for k, v in socks_keys.items())
        # issue #189: srouter-managed codenv SOCKS5 — намеренный (лечит ChatGPT.app). info, не driver-шум.
        # cycle-review PR #219 (Codex, confidence 0.93): _codenv_managed()=True доказывает только,
        # что job com.srouter.codenv ЗАГРУЖЕН — НЕ то, что именно он записал ЭТИ SOCKS5-значения.
        # Кто-то другой может параллельно прописать чужой SOCKS5 в тот же launchctl gui-домен ключ,
        # пока codenv тоже загружен — тот же класс инцидента #127. Сверяем КАЖДОЕ найденное SOCKS5-
        # значение с каноническим codenv endpoint (_CODENV_SOCKS_URL) — только полное совпадение
        # всех ключей даёт info; любое расхождение — down (не глушим потенциально чужой SOCKS5).
        if _health_facade._codenv_managed() and all(v == _CODENV_SOCKS_URL for v in socks_keys.values()):
            return {"status": "info",
                    "detail": (f"SOCKS5 в launchctl ({bad}) = srouter codenv (#189 для ChatGPT.app Rust "
                               f"app-server). Claude Desktop App ломается на SOCKS5 (#127), но CC CLI "
                               f"через ~/.claude/settings.json не затронут. Намеренный tradeoff.")}
        return {"status": "down",
                "detail": f"SOCKS5 в launchctl ({bad}) — Desktop App UnsupportedProxyProtocol (#127)"}
    # Расхождение CLI (settings.json) vs Desktop (launchctl HTTPS_PROXY) — оба заданы и различны.
    desktop_https = keys.get("HTTPS_PROXY", "")
    if cli_proxy and desktop_https and cli_proxy != desktop_https:
        return {"status": "warn",
                "detail": f"CLI={cli_proxy}, Desktop={desktop_https} — расхождение прокси "
                          f"(один клиент может работать, другой — нет)"}
    # Только HTTP-прокси, без расхождения → ok, перечисляем все найденные ключи.
    found = ", ".join(f"{k}={v}" for k, v in keys.items())
    return {"status": "ok", "detail": f"Desktop App proxy (launchctl): {found}"}


# ============================ #189: ChatGPT.app Rust app-server proxy (launchctl gui-env) =========

# codenv LaunchAgent label/marker — ДУБЛИРОВАНЫ из codex_wrappers.py (CODEX_ENV_LABEL/MARKER :74-75).
# health.py НЕ импортирует codex_wrappers (тот сам импортирует health — вышел бы цикл; плюс CLI-слой
# тащит argparse/apply_install). Парity-гвард: при смене маркера в codex_wrappers.py — обновить тут.
# Указатель на srouter.py устарел: PR #258 (a177c6f) перенёс определения в codex_wrappers.py,
# srouter.py их только реэкспортирует (cycle-review PR #262).
_CODENV_LABEL = "com.srouter.codenv"
_CODENV_MARKER = "srouter-managed-codex-env-v1"

# Канонический codenv SOCKS5-endpoint — тот же литерал, что dashboard_common.SOCKS_PROXY_URL /
# srouter.py._CODEX_PROXY_URL. cycle-review PR #219 (Codex, confidence 0.93): _codenv_managed()=True
# доказывает только «job зарегистрирован», НЕ что именно он записал ЭТО SOCKS5-значение — сверка
# со значением обязательна, иначе чужой SOCKS5 в том же launchctl-ключе маскируется под codenv (#127).
_CODENV_SOCKS_URL = f"socks5h://127.0.0.1:{XRAY_PORT}"


def _read_gui_proxy_env(runner=None, *, keys_filter=LAUNCHCTL_PROXY_KEYS):
    """Прокси в launchd GUI-домене (где codenv ставит SOCKS5) — через `launchctl print gui/<uid>`.

    launchctl getenv читает ТОЛЬКО caller-context (`Usage: getenv <key>` — НЕ принимает домен), молча
    игнорируя домен-аргумент → из SSH/cron/AO-shell даёт НЕ gui, а из GUI-терминала совпадает случайно.
    codenv-факт = факт о GUI-домене (видит ChatGPT.app launchd-process), не о терминале doctor'а →
    единственный домен-осознанный источник = `launchctl print gui/<uid>` блок `environment = {...}`.
    Эмпирически подтверждено (issue #191): unsetenv gui/<uid> KEY тоже игнорирует домен — arg1
    трактуется как имя переменной, arg2 (реальный ключ) молча отбрасывается.

    runner: опциональный (cmd, timeout) -> {rc, out, err, timeout} — для переиспользования вызывающим
    кодом с собственным инъектируемым runner (srouter._remove_launchctl_env, issue #191). По умолчанию
    sys_probe.run (as-is для health.py doctor-чеков).

    Возвращает {keys: {KEY: value}, verifiable: bool}. timeout → verifiable=False (fail-closed: не
    различимо «пусто» vs «не смогли спросить», не выдумываем false-down). keys_filter ограничивает
    парсинг нужными env-ключами (по умолчанию LAUNCHCTL_PROXY_KEYS — HTTPS_PROXY/HTTP_PROXY/ALL_PROXY).
    """
    run = runner if runner is not None else sys_probe.run
    domain = f"gui/{os.getuid()}"
    lc = run([LAUNCHCTL, "print", domain], 3)
    if lc.get("timeout"):
        return {"keys": {}, "verifiable": False}  # fail-closed
    keys = {}
    in_env = False
    found_block = False  # блок environment найден? Иначе out без блока (несуществующий домен/иной
                        # формат) → НЕ верим, не выдумываем false-down «codenv снят» (fail-closed).
    for line in (lc.get("out") or "").splitlines():
        stripped = line.strip()
        if stripped == "environment = {":
            in_env = True
            found_block = True
            continue
        if in_env:
            # конец блока — строка из одного '}' (отступ launchctl print).
            if stripped == "}":
                break
            # формат: '\t\tKEY => value' (как отдаёт launchctl print).
            if " => " in stripped:
                k, _, v = stripped.partition(" => ")
                k = k.strip()
                if k in keys_filter and v.strip():
                    keys[k] = v.strip()
    if not found_block:
        # out без блока environment (несуществующий домен: launchctl print gui/<bad> отдаёт rc=0 +
        # 'Bad request. Could not find domain'). Не различимо «домен недоступен» от «codenv снят»
        # → unknown (fail-closed), НЕ false-down.
        return {"keys": {}, "verifiable": False}
    return {"keys": keys, "verifiable": True}


# ============================ #250: состояние codenv launchd-job (первоисточник) =================
#
# Инцидент 2026-07-30: job загружен, plist с диска удалён, ProgramArguments указывает в стёртый
# AO-worktree → exit 127 при КАЖДОМ из 1419 запусков (RunAtLoad + StartInterval=300), Codex молча
# без SOCKS5. doctor молчал: _codenv_managed читал АРТЕФАКТ (plist-файл + маркер), а не СОСТОЯНИЕ
# job'а. Первоисточник — `launchctl print gui/<uid>/<label>`: path / state / runs / last exit code /
# arguments. Канон verify-dont-guess (probe-semantics-from-primary-source).

# Эфемерный каталог AO-worktree. Постоянный LaunchAgent, указывающий туда, — всегда мина: worktree
# удаляется, job остаётся и падает. Тот же литерал — в guard установки (codex_wrappers).
_AO_WORKTREE_MARK = "/.ao/data/worktrees/"


def _in_ao_worktree(path):
    """Путь ведёт внутрь эфемерного AO-worktree? Единая точка для guard установки и детектора.

    cycle-review round 2 (Codex, critical): сравнение было регистрозависимым. Эмпирически на APFS
    по умолчанию `.AO/data/worktrees` и `.ao/data/worktrees` — ОДИН каталог (`Path.samefile` →
    True), но `resolve()` сохраняет исходное написание, поэтому подстрочная сверка промахивалась:
    install через альтернативное написание молча зашивал эфемерный путь в постоянный LaunchAgent
    (та самая мина issue #250), а детектор его не подсвечивал. Сверяем casefold'ом — решение по
    свойствам ФС, а не по написанию строки (канон loose-validator-recurring-leak).

    resolve(strict=False) нормализует '..' и делает путь абсолютным ДАЖЕ для несуществующего файла,
    поэтому вердикт не зависит ни от факта существования, ни от регистра, ни от '..'-сегментов.

    НЕ бросает ни на каком входе — контракт, а не почти-контракт (cycle-review round 2, /review):
    `Path(path)` кидает TypeError на None/int/bytes РАНЬШЕ, чем отработает except вокруг resolve().
    Оба текущих вызывающих защищены, но это ОБЩИЙ предикат двух подсистем, и исключение отсюда
    ушло бы в check_all — fail-open по всему стеку. Нераспознанный вход → False: «не доказано, что
    worktree». Для guard'а это fail-open-сторона, поэтому оба вызывающих обязаны давать реальный
    путь (Path/str), а не полагаться на этот fallback.
    """
    try:
        resolved = Path(path).resolve(strict=False)
    except (OSError, ValueError, RuntimeError):
        # Путь есть, но ОС/парсер его не осилили — решаем по сырой строке (ниже, регистронезависимо).
        return _AO_WORKTREE_MARK in str(path).casefold()
    except TypeError:
        _log.debug("_in_ao_worktree: не путь (%s) — не worktree", type(path).__name__)
        return False
    # Точное совпадение написания — worktree без вопросов (быстрый путь, большинство случаев).
    if _AO_WORKTREE_MARK in str(resolved):
        return True
    # Иначе написание отличается регистром. Регистр решает НЕ строка, а сама ФС (cycle-review
    # round 3, Codex): macOS поддерживает case-sensitive APFS, где '.AO' и '.ao' — РАЗНЫЕ каталоги,
    # и безусловный casefold объявил бы канонический '/.AO/...'-чекаут эфемерным worktree →
    # guard отказал бы в установке, doctor нарисовал бы ложный down на здоровой машине (канон #135).
    # Спрашиваем первоисточник: тот же ли это физически каталог, что канонический AO-worktrees-корень.
    if _AO_WORKTREE_MARK not in str(resolved).casefold():
        return False
    # Ищем предка, чьё написание заканчивается worktrees-маркером, и спрашиваем ФС: он ли это.
    canonical = Path.home() / ".ao" / "data" / "worktrees"
    for ancestor in resolved.parents:
        if not f"{ancestor}/".casefold().endswith(_AO_WORKTREE_MARK):
            continue
        try:
            # Оба существуют и это ОДИН каталог → просто иначе записан (case-insensitive том).
            return ancestor.samefile(canonical)
        except OSError:
            # Одного из каталогов нет / нет прав → ФС не опровергла совпадение. Fail-closed:
            # для guard'а «не доказано, что другой» безопаснее трактовать как worktree — цена
            # ошибки здесь отказ в установке, а не молча зашитая мина (issue #250).
            return True
    return False


# Хвост stderr codenv-скрипта: там причина падения прописана буквально ('No such file or directory'
# с полным путём). Канон noisy-log-better-than-no-log — detail без причины бесполезен оператору.
_CODENV_STDERR_TAIL_BYTES = 2048


def _codenv_default_stderr_path():
    """Дефолтный StandardErrorPath codenv — из того же генератора, что рендерит шаблон.

    cycle-review round 2 (/review): дефолт был захардкожен как '/tmp/codenv.err' (взят из текста
    инцидента), тогда как шаблон подставляет `__SROUTER_LOG_ERR__` → InstallEnv.log_err
    (~/Library/Logs/...). Мёртвый дефолт: когда `launchctl print` не отдал 'stderr path', читался
    несуществующий файл и причина падения молча терялась из detail — канон
    config-contract-is-the-generator (путь берём у генератора, не переписываем его руками).
    """
    try:
        import install_config
        # from_env(), НЕ InstallEnv(): реальный CLI строит env именно так, и именно его log_err
        # рендерится в plist. InstallEnv() дал бы дефолты класса, игнорируя SROUTER_LOG_DIR —
        # при кастомном log-dir doctor читал бы ЧУЖОЙ лог и молча терял причину падения
        # (cycle-review round 3, Codex; каноны more-options-better + config-contract-is-the-generator).
        return str(install_config.InstallEnv.from_env().log_err)
    except (ImportError, OSError, ValueError, TypeError, AttributeError) as exc:
        _log.debug("install_config недоступен (%s) — дефолт stderr codenv неизвестен", exc)
        return ""


def _codenv_stderr_tail(path=None, *, limit=_CODENV_STDERR_TAIL_BYTES):
    """Хвост stderr-лога codenv (по умолчанию StandardErrorPath из шаблона). Не бросает → ''."""
    try:
        target = path or _codenv_default_stderr_path()
        if not target:
            return ""
        data = Path(target).read_bytes()[-limit:]
        return data.decode("utf-8", errors="replace").strip()
    except (OSError, ValueError):
        # Нет файла / нет прав / битый путь — отсутствие лога не должно ронять чек (fail-soft).
        return ""


def _codenv_plist_is_managed():
    """srouter-managed codenv plist лежит на диске? (только provenance, БЕЗ launchd-состояния.)

    Доказательство «установка была»: маркер в plist. Отличает «codenv не ставили» (опционален —
    молчим) от «ставили, а job мёртв» (авария #250). Провенанс-часть _codenv_managed, вынесенная
    отдельно: тому нужны И маркер, И loaded — здесь как раз случай «маркер есть, loaded нет».
    Ошибка чтения/битый plist → False (fail-safe: не выдумываем установку без доказательства).
    """
    try:
        plist = Path.home() / "Library" / "LaunchAgents" / f"{_CODENV_LABEL}.plist"
        return plist.exists() and _CODENV_MARKER in plist.read_text(encoding="utf-8")
    except (OSError, ValueError):
        # OSError — нет файла/прав; ValueError — UnicodeDecodeError на бинарном/битом plist
        # (та же граница, что в _codenv_managed: один файл не должен ронять doctor).
        return False


def _codenv_job_state(runner=None):
    """Состояние launchd-job com.srouter.codenv по `launchctl print gui/<uid>/<label>`.

    Первоисточник, не артефакт: plist-файл на диске может быть удалён, пока job живёт в памяти
    launchd (осиротевший job) — и наоборот. Разбираем реальный формат launchctl print (проверен на
    живой машине, `com.srouter.dashboard`): табулированные `key = value` + блок `arguments = { ... }`
    со строками-аргументами по одной на строку.

    Возвращает dict, НЕ бросает:
      loaded: True (rc=0, вывод распознан) / False (rc=113 service-not-found) / None (unknown)
      path: str — plist-путь, как его помнит launchd ('' если поля нет)
      state: str — 'running' / 'not running' / 'spawn scheduled' / ''
      runs: int|None, last_exit_code: int|None — None = поля НЕТ (нет данных), НЕ 0
      arguments: list[str] — ProgramArguments как их видит launchd
      stderr_path: str — StandardErrorPath (для хвоста причины)

    last_exit_code=None НАМЕРЕННО не подменяется нулём: 0 = «доказанно завершился успешно»,
    None = «нет данных». Подмена вернула бы fail-open (молчание при неизвестном состоянии).
    """
    empty = {"loaded": None, "path": "", "state": "", "runs": None, "last_exit_code": None,
             "arguments": [], "stderr_path": ""}
    run = runner if runner is not None else sys_probe.run
    try:
        r = run([LAUNCHCTL, "print", f"{_launchd_domain()}/{_CODENV_LABEL}"], 5)
    except (OSError, ValueError, TypeError) as exc:
        # runner — инъекция; сбой запуска launchctl не должен ронять doctor (fail-soft граница).
        _log.debug("launchctl print codenv не выполнен: %s", exc)
        return empty
    # cycle-review PR #262 (Codex): try охватывал только ВЫЗОВ, а разбор результата был снаружи —
    # runner, вернувший не-словарь (None/строка), ронял `.get` → AttributeError сквозь весь
    # check_all (общий doctor/watchdog путь → fail-open по всему стеку). Валидируем форму ответа.
    if not isinstance(r, dict):
        _log.debug("launchctl print codenv: runner вернул %s, не словарь", type(r).__name__)
        return empty
    # rc-семантика ОБЯЗАНА совпадать с install_plist._launchd_is_loaded (rc=0 загружен / rc=113
    # not-found — единственный достоверный False / иначе unknown fail-safe). Мы не вызываем его
    # напрямую: он отдаёт голый tristate, а нам нужен САМ вывод того же `launchctl print` для
    # разбора state/runs/last exit code/arguments — вызов _launchd_is_loaded означал бы ВТОРОЙ
    # идентичный subprocess за прогон doctor'а. Парity-гвард (как _CODENV_LABEL ниже): при смене
    # tristate-контракта в install_plist — обновить здесь; тест-гвард на совпадение семантики —
    # tests/test_health_codenv_job.py::test_codenv_job_state_rc_semantics_match_launchd_is_loaded.
    if r.get("timeout"):
        return empty  # unknown, НЕ false-down (probe-канон)
    rc = r.get("rc")
    if rc == _LAUNCHCTL_SERVICE_NOT_FOUND:
        return {**empty, "loaded": False}  # 113 — единственный достоверный «не загружен»
    if rc != 0:
        return empty
    out = r.get("out") or ""
    st = {**empty, "loaded": None}
    in_args = False
    args = []
    # Глубина вложенности. cycle-review PR #262: парсер строил `key = value` ПЛОСКО, срезая отступы,
    # а реальный `launchctl print` содержит вложенные блоки (`resource coalition = {`,
    # `jetsam coalition = {`, `event triggers = {`) со СВОИМИ `state`/`runs`/`last exit code`. Они
    # идут ПОСЛЕ top-level полей и затирали их: на живом `com.srouter.dashboard` истинное
    # `state = spawn scheduled` читалось как `active` (state коалиции, к job'у отношения не имеет).
    # Критично вдвойне — `state` служит гейтом loaded=True: обрывок, заканчивающийся внутри
    # coalition-блока, выдал бы себя за полноценно загруженный job (fail-open).
    # Берём ТОЛЬКО поля первого уровня (depth == 1: внутри `gui/<uid>/<label> = {`).
    depth = 0
    for line in out.splitlines():
        stripped = line.strip()
        if in_args:
            if stripped == "}":
                in_args = False
                depth -= 1
                continue
            if stripped:
                args.append(stripped)
            continue
        if stripped == "}":
            depth -= 1
            # cycle-review round 2 (/review): на закрывающей скобке top-level блока depth падал в 0,
            # и СЛЕДУЮЩИЙ блок-сосед снова входил на depth==1 → его `state`/`last exit code`
            # читались как поля нашего job'а (утечка 99 вместо 0). Живой `launchctl print` отдаёт
            # один top-level блок, так что случай недостижим из настоящего вывода — но парсер
            # первоисточника обязан быть строг: после закрытия своего блока читать больше нечего.
            if depth <= 0:
                break
            continue
        if stripped.endswith("= {"):
            depth += 1
            # `arguments = {` парсим как список строк-аргументов; прочие блоки просто пропускаем.
            if stripped == "arguments = {" and depth == 2:
                in_args = True
            continue
        if depth != 1:
            continue  # вложенный блок (coalition/triggers) — его поля НЕ про наш job
        key, sep, value = stripped.partition(" = ")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if key == "path":
            st["path"] = value
        elif key == "state":
            st["state"] = value
        elif key == "stderr path":
            st["stderr_path"] = value
        elif key in ("runs", "last exit code"):
            field = "runs" if key == "runs" else "last_exit_code"
            try:
                st[field] = int(value)
            except ValueError:
                # launchctl печатает 'last exit code = (never exited)' и подобное — не число,
                # значит данных нет. None, не выдуманный 0 (fail-closed).
                st[field] = None
    st["arguments"] = args
    # rc=0 сам по себе НЕ доказывает загруженный job: `launchctl print gui/<bad>/<label>` отдаёт
    # rc=0 + 'Bad request.' Требуем узнаваемый вывод — иначе unknown (не выдумываем ни down, ни ok
    # из мусора; тот же fail-closed, что found_block в _read_gui_proxy_env).
    #
    # cycle-review PR #262 (Codex): прежнее условие принимало ЛЮБОЕ одно поле, включая одинокий
    # `path`. Усечённый вывод (только path) давал loaded=True → все проверки падений пропускались
    # → «здоров». Неполный первоисточник — это «не смогли спросить», а не «спросили, всё хорошо».
    # `state` обязателен: это поле launchd печатает для КАЖДОГО реально загруженного job'а, и
    # именно оно отличает живую запись от обрывка вывода.
    if st["state"]:
        st["loaded"] = True
    return st


# Пауза перед перепроверкой «job выгружен». Окно reload в install_plist — до ~3.5с
# (_BOOTOUT_SETTLE_MAX_WAIT 2.0 + 3 x _BOOTSTRAP_RETRY_DELAY 0.5). Ждём с запасом, но не настолько,
# чтобы затормозить doctor: перепроверка происходит ТОЛЬКО в редкой ветке «managed plist + rc=113».
_CODENV_RELOAD_SETTLE_WAIT = 4.0


def _codenv_unloaded_is_persistent(runner=None, *, wait=_CODENV_RELOAD_SETTLE_WAIT):
    """«Выгружен» — устойчивое состояние, а не окно reload? Перепроверка после паузы.

    cycle-review round 3 (Codex): единичный снимок rc=113 не отличает мёртвый codenv от штатной
    переустановки — install_plist._launchd_reload делает bootout → poll → bootstrap, и в этом окне
    plist уже на диске, а job'а ещё нет. Ложный down там шумел бы на ЗДОРОВОЙ машине (канон #135)
    и мог бы дёрнуть watchdog ложным recovery.

    True только если job ПОВТОРНО не найден (rc=113) после паузы, перекрывающей окно reload.
    Любой другой исход (job появился / launchctl недоступен / таймаут) → False: не эскалируем
    в down без подтверждения (fail-safe, та же семантика, что и у остального детектора).
    """
    time.sleep(wait)
    st = _codenv_job_state(runner=runner)
    return st["loaded"] is False


def _codenv_job_check(runner=None, *, wait=_CODENV_RELOAD_SETTLE_WAIT):
    """codenv LaunchAgent реально ЖИВ? По состоянию job'а, не по наличию plist-файла (issue #250).

    Исходы (ТДД issue #250):
      down    — job загружен, но: last exit code != 0 (падает; runs подсвечивает флап) ИЛИ plist
                на диске отсутствует (осиротевший job переживает удаление своего plist) ИЛИ
                ProgramArguments указывает на несуществующий файл ИЛИ путь внутри AO-worktree
                (эфемерный каталог как цель постоянного LaunchAgent — всегда мина установки).
      ok      — job загружен, exit ДОКАЗАННО 0, скрипт на месте: канон #135 — здоровый codenv
                НЕ шумит. Именно ok, а не info: подтверждённо здоров ≠ «не смогли проверить».
                (Исторически PR #262 выбрал ok ещё и потому, что _print_report красил ЛЮБОЙ
                info-чек жёлтым; тот баг рендера исправлен — ok читается первым, PR #296.)
      unknown — job не загружен (codenv опционален — не авария), launchctl недоступен/таймаут,
                вывод не распознан ИЛИ exit-код неизвестен. Никогда не бросает (probe-канон).

    down обязан быть DRIVER: 1419 падений в тишине — ровно то, что этот чек закрывает
    (noisy-log-better-than-no-log). Без codenv Codex после ребута идёт напрямую за GFW —
    утечка реального IP (fail-closed-proxy-down).
    """
    st = _codenv_job_state(runner=runner)
    if st["loaded"] is not True:
        if st["loaded"] is False:
            # cycle-review round 2 (Codex, critical): rc=113 БЕЗУСЛОВНО давал «опционален» → info.
            # Но srouter-managed plist на диске ДОКАЗЫВАЕТ, что установка была: значит это не «не
            # ставили», а «поставили, и job выгружен/не забутстрапился». Зеркало осиротевшего job'а
            # (там job без plist, тут plist без job'а) — и ровно тот класс, что ловит issue #250:
            # codenv сконфигурирован, но мёртв → после ребута Codex молча без SOCKS5.
            # Provenance-граница (#112): ЧУЖОЙ plist без маркера — не наша установка, молчим.
            # Окно reload — НЕ авария (cycle-review round 3, Codex): install пишет plist, затем
            # bootout → poll → bootstrap (install_plist._launchd_reload), и МЕЖДУ ними состояние
            # ровно «managed plist есть, rc=113». Окно до ~3.5с, а watchdog бежит раз в ~20с и
            # /health дёргается в любой момент → штатная переустановка давала бы degraded/503 и
            # ложное recovery-уведомление. Uninstall имеет такое же окно (bootout→unlink).
            # Down — только для УСТОЙЧИВОГО состояния: перепроверяем после короткой паузы.
            if _codenv_plist_is_managed() and _codenv_unloaded_is_persistent(runner=runner, wait=wait):
                return {"status": "down",
                        "detail": (f"codenv установлен, но НЕ загружен: srouter-managed plist на диске "
                                   f"({Path.home() / 'Library' / 'LaunchAgents' / f'{_CODENV_LABEL}.plist'}), "
                                   f"а job в launchd отсутствует — bootstrap не прошёл или job выгружен. "
                                   f"Codex останется без SOCKS5 после ребута → прямой трафик за GFW. "
                                   f"Лечение: srouter install (codenv) — перезагрузит LaunchAgent")}
            return {"status": "unknown",
                    "detail": f"codenv LaunchAgent {_CODENV_LABEL} не загружен в launchd "
                              f"(опционален — нужен только для ChatGPT.app Rust app-server, #189)"}
        return {"status": "unknown",
                "detail": f"состояние {_CODENV_LABEL} не определено (launchctl print недоступен/таймаут)"}
    facts = f"state={st['state'] or '?'}, runs={st['runs'] if st['runs'] is not None else '?'}"
    # 1. Падает. Хвост stderr — причина буквально ('No such file or directory' + полный путь).
    exit_code = st["last_exit_code"]
    if exit_code is not None and exit_code != 0:
        tail = _health_facade._codenv_stderr_tail(st["stderr_path"] or None)
        cause = f" Причина (stderr): {tail[-300:]}" if tail else ""
        flap = " ФЛАП (падает при каждом запуске)" if (st["runs"] or 0) > 5 else ""
        return {"status": "down",
                "detail": (f"codenv падает: last exit code = {exit_code} ({facts}).{flap} "
                           f"Codex останется без SOCKS5 после ребута → прямой трафик за GFW."
                           f"{cause} Лечение: srouter install (codenv)")}
    # 2. Осиротевший job: живёт в launchd, plist с диска удалён (bootout его не снял).
    plist = Path.home() / "Library" / "LaunchAgents" / f"{_CODENV_LABEL}.plist"
    if not plist.exists():
        return {"status": "down",
                "detail": (f"осиротевший codenv job: загружен в launchd ({facts}), но plist на диске "
                           f"отсутствует ({plist}) — переустановка его не заменит. "
                           f"Лечение: launchctl bootout {_launchd_domain()}/{_CODENV_LABEL}, "
                           f"затем srouter install")}
    # 3. ProgramArguments → эфемерный worktree / несуществующий файл (корень exit 127).
    script = st["arguments"][-1] if st["arguments"] else ""
    if script:
        # _in_ao_worktree — та же единая точка, что и в guard установки (codex_wrappers):
        # resolve('..'/относительных) + casefold. Guard и детектор ОБЯЗАНЫ видеть worktree
        # одинаково, иначе одна сторона молчит там, где другая бьёт тревогу.
        if _in_ao_worktree(script):
            return {"status": "down",
                    "detail": (f"codenv указывает в эфемерный AO-worktree: {script} ({facts}). "
                               f"Worktree удаляется — job останется и начнёт падать с exit 127 "
                               f"(мина установки, issue #250). Лечение: srouter install из "
                               f"канонического репозитория")}
        if not Path(script).exists():
            return {"status": "down",
                    "detail": (f"codenv ProgramArguments указывает на несуществующий файл: {script} "
                               f"({facts}) — следующий запуск даст exit 127, Codex без SOCKS5. "
                               f"Лечение: srouter install (codenv)")}
    # 4. Здоров — но только если exit-код ДОКАЗАННО 0. cycle-review PR #262 (Codex): `None` («нет
    # данных»: launchctl не напечатал поле или напечатал '(never exited)') раньше проваливался сюда,
    # и detail ЛГАЛ «last exit code = 0» — «не смогли проверить» выдавалось за «проверили, здоров».
    # Ровно тот fail-open, который докстринг _codenv_job_state обещал исключить.
    if exit_code is None:
        return {"status": "unknown",
                "detail": (f"codenv загружен ({facts}), но launchctl не сообщил last exit code — "
                           f"здоровье не подтверждено (job мог ни разу не завершиться). "
                           f"Проверить вручную: launchctl print {_launchd_domain()}/{_CODENV_LABEL}")}
    return {"status": "ok",
            "detail": f"codenv LaunchAgent загружен и здоров ({facts}, last exit code = 0): {script or plist}"}


def _codex_app_proxy_check():
    """ChatGPT.app (ЛЮБОЙ из двух независимых сетевых стеков) без прокси → down DRIVER (issue #189, #189-follow-up).

    Эмпирика (verify, lsof per-process): ChatGPT.app = Electron/Chromium-обёртка + отдельный Rust
    app-server бинарник — ДВА независимых сетевых стека:
      (а) Rust app-server (/Applications/ChatGPT.app/.../codex, basename "codex") — основной WS к
          wss://chatgpt.com. НЕ уважает системный SOCKS (Rust reqwest без SystemConfiguration), берёт
          ТОЛЬКО env SOCKS5 из launchd gui-домена (codenv LaunchAgent).
      (б) Chromium network-service helper (comm — полный путь ВНУТРИ .app/-бандла, например
          ".../Codex Framework.framework/Versions/<ver>/Helpers/Codex (Service).app/Contents/MacOS/
          Codex (Service)", basename ≠ "codex") — Chromium-подпроцесс UI/telemetry. Читает системные
          прокси-настройки по-своему (не всегда через launchctl gui-env напрямую) и может течь мимо
          прокси НЕЗАВИСИМО от Rust-стека.
    Живая эмпирика (эта сессия, воспроизведено дважды включая после Cmd+Q restart): lsof по PID
    Chromium network-service helper показал ~37 TCP-сокетов в SYN_SENT, ВСЕ напрямую (192.168.1.x /
    китайский мобильный IPv6), НИ ОДИН не шёл через 127.0.0.1:10808/8118 — при этом launchctl getenv
    в тот же момент показывал корректный socks5h://127.0.0.1:10808. Это ровно симптом UI
    net::ERR_CONNECTION_TIMED_OUT (GFW режет прямой путь): Chromium-стек течёт мимо прокси
    НЕЗАВИСИМО от того, что Rust-стек (или его отсутствие) может быть исправен.

    Регрессия до фикса: детект App-PID требовал `_is_codex_binary_comm(comm) AND _is_codex_app_comm(comm)`
    — basename-условие (_is_codex_binary_comm) матчит ТОЛЬКО "codex"/"codex-<arch>-apple-darwin", что
    отсекает Chromium helper целиком (basename "Codex (Service)" ≠ "codex"). Если на машине Rust
    app-server не запущен отдельным процессом (или ещё не стартовал), единственный процесс ChatGPT.app
    в ps — этот helper → AND-условие давало app_pids=[] → ложный status="unknown" "App не запущен",
    хотя стек явно активен и течёт мимо прокси (verify-dont-guess: проверено эмпирически regex'ами
    на реальных comm-строках, не гипотеза).

    Решение: убрали _is_codex_binary_comm из ЭТОГО детект-пути — App-PID матчится ТОЛЬКО по
    _is_codex_app_comm (path-сегмент /ChatGPT.app/ или /Codex.app/, канон health_codex.py). Это НЕ
    расширяет TUI/CLI-чек _codex_proxy_probe (там basename-условие остаётся — он различает CLI-codex
    от прочих процессов вне .app-бандла, где path-сегмент неприменим).
    Trade-off осознан: путь /ChatGPT.app/ содержит МНОГО helper-типов (GPU-process, storage-service,
    crashpad и т.п.), не все из них обязаны использовать прокси (например GPU-process рисует UI
    локально). Различить подтип надёжно без ps args (comm не отдаёт --type=/--utility-sub-type=)
    нельзя — а расширять сам `ps` вызов на args ради одного chatgpt-специфичного чека не оправдано.
    Поэтому НЕ репортим down по самому факту наличия helper-процесса — down/warn ставится ТОЛЬКО
    когда lsof РЕАЛЬНО показывает non-proxied external сокет у хотя бы одного App-related PID
    (см. _app_pids_route) — то же правило, что уже было для Rust-стека. GPU/storage helper без
    сетевой активности просто не даст external-сокетов → не заматчится ни в один из трёх сетов
    (external/socks/privoxy) → чек остаётся unknown/idle для него, false-positive не возникает.

    Чек: (1) App-related PID активны (ps по _is_codex_app_comm, ЛЮБОЙ helper внутри .app/-бандла);
    (2) gui-env через _read_gui_proxy_env; (3) реальный runtime-маршрут через _app_pids_route (lsof).
      status="down"    — App активен, gui-env пуст (codenv не загружен) — DRIVER;
      status="warn"    — App активен, gui-env только HTTP (privoxy рвёт WS #120) — DRIVER;
      status="ok"      — App активен, gui-env SOCKS5 (codenv работает) — DRIVER;
      status="unknown" — App не запущен ИЛИ gui-env не верифицируем — info-only (fail-closed).
    App-PID здесь, НЕ в _codex_proxy_probe (TUI-чек исключил App-PID, чтобы не давать ложный mixed/down
    на нерелевантном PID — баг «❌ на VSCode PID 56748»).
    """
    # 1. App-related процессы активны? Матч ТОЛЬКО по path-сегменту .app/ (_is_codex_app_comm) —
    # НЕ требуем basename=="codex" здесь: Chromium network-service helper (basename ≠ "codex") тоже
    # App-related и тоже может течь мимо прокси (см. докстринг выше, регрессия #189-follow-up).
    r = sys_probe.run([PS, "-axo", "pid=,comm="], timeout=3)
    if r.get("timeout"):
        return {"status": "unknown", "source": "n/a", "detail": "timeout ps"}
    app_pids = []
    app_kinds = {}
    for line in (r.get("out") or "").splitlines():
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        pid_s, comm = parts[0].strip(), parts[1].strip()
        kind = _health_facade._codex_app_process_kind(comm)
        if pid_s.isdigit() and kind:
            app_pids.append(pid_s)
            app_kinds[pid_s] = kind
    if not app_pids:
        return {"status": "unknown", "source": "n/a",
                "detail": "ChatGPT.app/Codex.app не запущен — Rust app-server не активен"}

    # 2. gui-env (codenv).
    gui = _health_facade._read_gui_proxy_env()
    if not gui.get("verifiable"):
        return {"status": "unknown", "source": "n/a",
                "detail": f"launchctl gui-env не отвечает — ручная проверка: "
                          f"launchctl getenv gui/$(id -u) HTTPS_PROXY (App PID {','.join(app_pids)})"}
    keys = gui.get("keys") or {}
    pid_hint = f"PID {','.join(app_pids)}"
    rust_pids = [p for p in app_pids if app_kinds.get(p) == "rust"]

    if not keys:
        if not rust_pids:
            # codex-review (PR #314): gui-env пуст, но живы только Chromium/generic-helper PID —
            # Rust app-server НЕ запущен. codenv нужен только Rust'у (Chromium берёт прокси из
            # системного SOCKS, см. _codex_app_chromium_proxy_check) — не приписываем Rust'у.
            # Статус остаётся down (App-related процесс без launchd-прокси — по-прежнему сигнал,
            # не unknown), но detail честно называет причину непричастности codenv.
            return {"status": "down", "source": "gui-env",
                    "detail": (f"ChatGPT.app: Rust app-server не запущен (только non-rust "
                               f"App-процессы, {pid_hint}), gui-env codenv пуст — codenv нужен только "
                               f"Rust app-server, для текущих процессов неприменим. Если Chromium "
                               f"network-service течёт мимо прокси — см. отдельный system-proxy check.")}
        return {"status": "down", "source": "gui-env",
                "detail": (f"ChatGPT.app Rust app-server без прокси: launchctl gui-env пуст — codenv "
                           f"не загружен/битый ({pid_hint}). WS к chatgpt.com рвётся (GFW). "
                           f"Восстановить: srouter install (codenv)")}
    socks_keys = {k: v for k, v in keys.items()
                  if urlparse(v).scheme.lower() in {"socks", "socks5", "socks5h"}}
    if socks_keys:
        found = ", ".join(f"{k}={v}" for k, v in socks_keys.items())
        # cycle-review #190 round 2: ok требует POSITIVE SOCKS5 evidence (route['socks']). gui-env SOCKS5
        # ≠ live-маршрут App-PID: setenv не ретроактивен (stale App direct), либо App выбрал privoxy 8118,
        # либо idle/нет ESTABLISHED, либо lsof сбой (rc≠0) — всё это НЕ ok (false-ok, round-1/2 finding).
        route = _app_pids_route(app_pids, app_kinds=app_kinds)
        if route.get("external"):
            ext = ",".join(sorted(route["external"]))
            external_by_kind = route.get("external_by_kind") or {}
            chromium_ext = sorted(external_by_kind.get("chromium", set()))
            rust_ext = sorted(external_by_kind.get("rust", set()))
            if rust_ext:
                # Rust app-server (/Resources/codex) сам держит external-сокет — только этот случай
                # реально "STALE App" (setenv не ретроактивен).
                return {"status": "down", "source": "runtime",
                        "detail": (f"ChatGPT.app Rust app-server НАПРЯМУЮ (gui-env SOCKS5 есть, но App PID "
                                   f"{ext} "
                                   f"держит external-сокеты) — STALE App: запущен ДО codenv, setenv не ретроактивен. "
                                   f"Полностью перезапусти ChatGPT.app (Cmd+Q из Dock, не закрыть окно). "
                                   f"codenv gui-env: {found}")}
            if chromium_ext:
                return {"status": "down", "source": "runtime",
                        "detail": (f"ChatGPT.app Chromium helper НАПРЯМУЮ (PID {','.join(chromium_ext)} "
                                   f"держит external-сокеты; gui-env SOCKS5 есть) — App запущен без "
                                   f"Chromium --proxy-server. Запусти через ~/bin/codex-app-proxy. "
                                   f"codenv gui-env: {found}")}
            # Ни rust, ни chromium — leak идёт от другого .app-helper (generic-kind, см.
            # _codex_app_process_kind docstring). Не приписываем Rust/Chromium, чтобы не врать
            # диагнозом на процесс, который к их стекам не относится.
            return {"status": "down", "source": "runtime",
                    "detail": (f"ChatGPT.app helper НАПРЯМУЮ (PID {ext} держит external-сокеты; "
                               f"gui-env SOCKS5 есть) — процесс внутри .app-бандла течёт мимо прокси. "
                               f"Полностью перезапусти ChatGPT.app (Cmd+Q из Dock, не закрыть окно). "
                               f"codenv gui-env: {found}")}
        if route.get("privoxy"):
            pv = ",".join(sorted(route["privoxy"]))
            return {"status": "warn", "source": "runtime",
                    "detail": (f"ChatGPT.app Rust app-server через privoxy 8118 (PID {pv}), не SOCKS5 — "
                               f"long-lived WS порвётся (#120). STALE App: перезапусти ChatGPT.app (Cmd+Q). "
                               f"codenv gui-env: {found}")}
        if not route.get("verifiable") or not route.get("socks"):
            # lsof timeout/rc≠0 ИЛИ нет positive SOCKS5-сокета (idle/нет ESTABLISHED к 10808) —
            # не можем доказать ok → unknown (fail-closed). gui-env SOCKS5 недостаточен.
            return {"status": "unknown", "source": "runtime",
                    "detail": (f"App-PID runtime-маршрут не подтверждён SOCKS5 (gui-env SOCKS5: {found}, "
                               f"{pid_hint}, lsof socks={','.join(sorted(route.get('socks', set()))) or 'нет'}). "
                               f"Ручная проверка: lsof -nP -p {','.join(app_pids)}")}
        return {"status": "ok", "source": "runtime",
                "detail": (f"ChatGPT.app Rust app-server через SOCKS5 (lsof PID {','.join(sorted(route['socks']))} "
                           f"-> 10808, codenv gui-env: {found})")}
    # gui-env задан, но без SOCKS5 (только HTTP/privoxy) → warn (long-lived WS порвётся #120).
    found = ", ".join(f"{k}={v}" for k, v in keys.items())
    return {"status": "warn", "source": "gui-env",
            "detail": (f"ChatGPT.app Rust app-server через HTTP прокси без SOCKS5 ({found}, {pid_hint}) — "
                       f"privoxy рвёт long-lived WS (#120). codenv должен ставить SOCKS5")}


def _app_pids_route(app_pids, *, app_kinds=None):
    """Runtime-маршрут App-PID по lsof-сокетам (как _codex_proxy_probe, но для App-PID).

    cycle-review #190 round 1/2: _codex_app_proxy_check не может полагаться только на gui-env (setenv
    не ретроактивен → stale App). lsof по App-PID классифицирует РЕАЛЬНЫЙ маршрут: external-ESTABLISHED
    (direct) / SOCKS5 10808 / privoxy 8118 (рвёт WS #120). ok требует positive SOCKS5 (round 2).
    Возвращает {external, socks, privoxy: set(pids), external_by_kind, verifiable: bool}. timeout ИЛИ rc≠0 → verifiable=False
    (сбой lsof ≠ доказательство маршрута → fail-closed unknown, не ok).
    """
    lr = sys_probe.run([LSOF, "-nP", "-p", ",".join(app_pids)], timeout=3)
    if lr.get("timeout") or lr.get("rc") not in (0, None):
        return {"external": set(), "socks": set(), "privoxy": set(),
                "external_by_kind": {}, "verifiable": False}
    external, socks, privoxy = set(), set(), set()
    external_by_kind = {}
    for line in (lr.get("out") or "").splitlines():
        if "TCP" not in line or "ESTABLISHED" not in line:
            continue
        fields = line.split()
        pid = fields[1] if len(fields) > 1 else ""
        if f"->127.0.0.1:{XRAY_PORT}" in line:
            socks.add(pid)
        elif f"->127.0.0.1:{PRIVOXY_PORT}" in line:
            privoxy.add(pid)  # HTTP-прокси рвёт long-lived WS (#120)
        elif "->127.0.0.1:" not in line:
            external.add(pid)  # external ESTABLISHED — direct, без localhost-прокси
            kind = (app_kinds or {}).get(pid)
            if kind:
                external_by_kind.setdefault(kind, set()).add(pid)
    return {"external": external, "socks": socks, "privoxy": privoxy,
            "external_by_kind": external_by_kind, "verifiable": True}


# Chromium network-service подпроцесс ChatGPT.app/Codex.app — единственный сетевой стек
# внутри Chromium-оболочки: --utility-sub-type=network.mojom.NetworkService (Chromium contract,
# см. канон Chromium services). GPU-process/storage-service/renderer НЕ делают внешних запросов
# по протоколу HTTP(S) — только NetworkService реально держит сокеты к chatgpt.com.
_NETWORK_SERVICE_MARK = "--utility-sub-type=network.mojom.NetworkService"


def _codex_app_chromium_proxy_check():
    """ChatGPT.app Chromium NetworkService без прокси → down DRIVER (обычный запуск из Dock).

    Живая регрессия (issue-обсуждение 2026-08-28): у Wi-Fi endpoint был сохранён верно
    (127.0.0.1:10808), но SOCKS-канал был ВЫКЛЮЧЕН. Rust app-server (см. _codex_app_proxy_check)
    уже шёл через launchd-env (codenv) и был здоров — но Chromium NetworkService подпроцесс
    читает СИСТЕМНЫЙ macOS SOCKS активного network service, а не launchd gui-env, и уходил
    напрямую. Старый doctor не видел системный SOCKS вообще и советовал `~/bin/codex-app-proxy`
    (ручной wrapper с `--proxy-server`) — не тот контракт: обычный запуск из Dock ДОЛЖЕН работать
    сам по себе, чинить нужно системный SOCKS, а не подменять способ запуска приложения.

    Чек:
      1. Chromium NetworkService процесс(ы) ChatGPT/Codex.app активны? (ps, matched по
         `_NETWORK_SERVICE_MARK` в comm/args-строке И path-сегменту .app/, см. _is_codex_app_comm).
         Нет процесса → unknown (info-only, GPU/storage/renderer helper без NetworkService не
         матчится — верно unknown, не down, канон fail-closed).
      2. Реальный runtime-маршрут (lsof): external ESTABLISHED → мимо прокси; socks к
         127.0.0.1:XRAY_PORT → доказанный прокси-путь.
      3. Если маршрут доказанно external — смотрим `system_proxy_control.status()`:
         SOCKS-канал активного network service выключен/не тот endpoint → это и есть причина,
         detail называет ИМЕННО её и предлагает `srouter system-proxy repair` (не "перезапусти
         App" — перезапуск НЕ чинит выключенный системный SOCKS, живая регрессия это подтвердила;
         не `codex-app-proxy` — обычный Dock-запуск должен работать сам).

      status="ok"      — NetworkService активен, lsof доказывает SOCKS-маршрут;
      status="down"    — NetworkService активен, lsof доказывает external (прямой) маршрут;
      status="unknown" — NetworkService не активен ИЛИ маршрут не доказан (idle/lsof-сбой).
    """
    r = sys_probe.run([PS, "-axo", "pid=,args="], timeout=3)
    if r.get("timeout"):
        return {"status": "unknown", "source": "n/a", "detail": "timeout ps"}
    network_pids = []
    for line in (r.get("out") or "").splitlines():
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        pid_s, rest = parts[0].strip(), parts[1].strip()
        if not pid_s.isdigit():
            continue
        if _NETWORK_SERVICE_MARK not in rest:
            continue
        if not _health_facade._is_codex_app_comm(rest):
            continue
        network_pids.append(pid_s)
    if not network_pids:
        return {"status": "unknown", "source": "n/a",
                "detail": "ChatGPT.app/Codex.app Chromium network-service не активен"}

    route = _app_pids_route(network_pids)
    if not route.get("verifiable"):
        return {"status": "unknown", "source": "runtime",
                "detail": f"lsof не подтвердил маршрут (PID {','.join(network_pids)})"}
    # codex-review (PR #314): external проверяем ПЕРВЫМ. Два NetworkService PID одновременно
    # (перезапуск/апдейт App) — один может держать SOCKS5, другой течь external напрямую; наличие
    # ЛЮБОГО socks-сокета раньше маскировало реальный direct-leak другого PID (false-ok на mixed).
    if not route.get("external"):
        if route.get("socks"):
            return {"status": "ok", "source": "runtime",
                    "detail": (f"ChatGPT.app Chromium network-service через SOCKS5 "
                               f"(lsof PID {','.join(sorted(route['socks']))} -> {XRAY_PORT})")}
        return {"status": "unknown", "source": "runtime",
                "detail": f"ChatGPT.app Chromium network-service активен, но нет доказанного маршрута "
                          f"(idle, PID {','.join(network_pids)})"}

    ext = ",".join(sorted(route["external"]))
    sys_status = system_proxy_control.status()
    if sys_status.get("status") == "ok" and not sys_status.get("target"):
        socks = sys_status.get("socks") or {}
        service = sys_status.get("service", "")
        return {"status": "down", "source": "system-proxy",
                "detail": (f"ChatGPT.app Chromium network-service идёт напрямую (PID {ext}) — "
                           f"системный SOCKS-прокси {service} выключен/настроен неверно "
                           f"(enabled={socks.get('enabled')}, {socks.get('server')}:{socks.get('port')}). "
                           f"Почини: srouter system-proxy repair")}
    if sys_status.get("status") != "ok":
        # codex-review (adversarial-review, PR #314): status() сам не смог проверить системный SOCKS
        # (unknown — нет default route/networksetup не читается) — НЕ заявляем "настроен корректно"
        # (мы этого не знаем), не прячем совет по фиксу.
        return {"status": "down", "source": "runtime",
                "detail": (f"ChatGPT.app Chromium network-service идёт напрямую (PID {ext}); системный "
                           f"SOCKS не удалось проверить ({sys_status.get('detail', 'unknown')}). "
                           f"Проверь: srouter system-proxy status / repair")}
    return {"status": "down", "source": "runtime",
            "detail": (f"ChatGPT.app Chromium network-service идёт напрямую (PID {ext}), хотя "
                       f"системный SOCKS настроен корректно — проверь вручную: "
                       f"lsof -nP -p {','.join(network_pids)}")}
