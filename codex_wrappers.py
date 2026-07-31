"""Codex wrappers, launchctl-env и PATH/zsh-интеграция (вынесено из srouter.py, #228).

Экстракция без редизайна: тела функций перенесены байт-в-байт, публичные имена
и семантика сохранены. srouter.py переэкспортирует всё отсюда для обратной
совместимости с тестами и потребителями.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import health
import local_state
import marker_block
from install_lib import (
    BREW,
    LAUNCHCTL,
    _install_generic_launchagent,
    _launchd_domain,
    _launchd_unload,
    _write_text_atomic,
    load_known_markers,
)

# Codex (CLI + App) работает стабильно только через SOCKS5 (xray 10808) минуя privoxy (портит WS).
# srouter install ставит ~/bin/codex + ~/bin/codex-app-proxy + launchctl env (через LaunchAgent
# plist, переживает ребут) + ~/bin в PATH; uninstall убирает. Канон — _install_ppp_hook
# (best-effort, marker-gate, строка-статус).
# URL SOCKS5 — из dashboard_common (SOCKS_PROXY_URL), единый источник правды для xray-порта.
# except BaseException (не Exception): dashboard_common raise SystemExit при отсутствии
# srouter_config.py, а SystemExit не ловится Exception — fallback должен сработать и для него.
try:
    from dashboard_common import SOCKS_PROXY_URL as _CODEX_PROXY_URL
except BaseException:
    _CODEX_PROXY_URL = "socks5h://127.0.0.1:10808"
# NO_PROXY для launchctl-gui env: loopback (Codex→moonbridge на loopback и локальные сервисы)
# + z.ai,.z.ai (moonbridge→api.z.ai — внешний хост, доступен напрямую мимо SOCKS5/xray/VPS).
# z.ai НЕ за GFW: при мёртвом VPS (#194) moonbridge-клиент обязан достучаться к api.z.ai напрямую,
# иначе codex ломается. ОБА варианта: z.ai = точный хост, .z.ai = поддомены (api.z.ai и др.).
# Канон: zai-direct-no-proxy, srouter-critical-infra-24-7 (VPS-смерть не валит z.ai-трафик).
CODEX_NO_PROXY = "localhost,127.0.0.1,::1,z.ai,.z.ai"
# NO_PROXY для CLI-wrapper (~/bin/codex-srouter) — ТОЛЬКО loopback, БЕЗ z.ai. CLI-codex идёт через
# SOCKS5 (managed путь, xray→VPS) — его NO_PROXY = санитизация унаследованного privoxy-окружения
# (#96 core), НЕ provider-direct. z.ai-прямой-доступ релевантен moonbridge (GUI launchctl-gui выше),
# а не CLI-codex. Две разные границы = две константы (канон route-scope-not-shared-validator).
CODEX_NO_PROXY_LOOPBACK = "localhost,127.0.0.1,::1"
# (env-key, value) — единый список для install/setenv и uninstall/unsetenv (синхронны всегда).
# Значение нужно только для setenv (launchctl-gui); unsetenv итерирует по ключам.
CODEX_LAUNCHCTL_ENV = tuple((k, _CODEX_PROXY_URL) for k in
                            ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                             "http_proxy", "https_proxy", "all_proxy")) \
                      + (("NO_PROXY", CODEX_NO_PROXY), ("no_proxy", CODEX_NO_PROXY))
# Wrappers: (name, template, marker). Цикл в install/remove — не два явных вызова.
# Issue #169: CLI-wrapper переименован codex → codex-srouter — убрать коллизию неймспейса (wrapper и
# real binary оба звались codex → natural-рекурсия #150/#144, foreign-wrapper резолвит codex=wrapper).
# После rename wrapper файл = codex-srouter, real binary так и зовётся codex → wrapper больше не
# находит себя по имени при runtime-резолве, коллизия устранена СТРУКТУРНО. Маркер НЕ менялся при rename
# (идентифицирует «srouter-managed wrapper», не имя файла) — migration старого ~/bin/codex по этому маркеру.
CODEX_WRAPPERS = (
    ("codex-srouter", "srouter-codex-cli-wrapper.sh", "# srouter: codex CLI wrapper (managed)"),
    ("codex-app-proxy", "srouter-codex-app-proxy-wrapper.sh", "# srouter: codex-app-proxy wrapper (managed)"),
)
# Имя CLI-wrapper'а (первая запись CODEX_WRAPPERS) — единый источник правды для rename-migration.
CODEX_CLI_WRAPPER_NAME = CODEX_WRAPPERS[0][0]
# Старое имя CLI-wrapper'а до rename (#169). Migration: srouter-managed ~/bin/codex (по маркеру) → удалить
# при install/remove; чужой (без маркера) — не трогать (канон provenance issue-112-hybrid-uninstall).
CODEX_CLI_WRAPPER_LEGACY_NAME = "codex"
# LaunchAgent для глобального env: launchctl setenv SOCKS5 в GUI-домен (переживает ребут).
# Label = com.srouter.codenv → prefix CODENV для плейсхолдеров __SROUTER_CODENV_*__ в шаблоне plist.
CODEX_ENV_LABEL = "com.srouter.codenv"
CODEX_ENV_MARKER = "srouter-managed-codex-env-v1"
ZSHRC_PATH_MARKER = "# srouter: ~/bin в PATH для codex wrapper"
# Shell-функция codex() в ~/.zshrc (issue #96): вызывает ~/bin/codex-srouter по абсолютному пути, чтобы
# порядок brew в PATH был не важен (функция всегда бьёт binary). Без неё wrapper #83 проигрывает
# /opt/homebrew/bin/codex. Парные маркеры для marker-gate install/remove (как ZSHRC_PATH_MARKER).
# Issue #169: функция зовёт ПЕРЕИМЕНОВАННЫЙ wrapper ~/bin/codex-srouter (имя codex освобождено под real
# binary — коллизия неймспейса устранена). Функция по-прежнему зовётся codex() в интерактивном шелле,
# чтобы пользовательский habit `codex …` работал — только внутри она ведёт на codex-srouter.
ZSHRC_CODEX_FUNC_MARKER_BEGIN = "# >>> srouter-managed-codex-function-v1 >>>"
ZSHRC_CODEX_FUNC_MARKER_END = "# <<< srouter-managed-codex-function-v1 <<<"
# function codex { … }, не голый codex() — существующий alias может помешать парсингу определения.
# guard `! $+aliases[codex] && ! $+functions[codex]` — не перекрываем молча чужое определение.
# Без exec внутри (заменит интерактивный шелл). Абсолютный путь "$HOME/bin/codex-srouter" (#169 rename).
_CODEX_FUNC_BLOCK = (
    f"{ZSHRC_CODEX_FUNC_MARKER_BEGIN}\n"
    'if (( ! ${+aliases[codex]} && ! ${+functions[codex]} )); then\n'
    '  function codex {\n'
    '    "$HOME/bin/codex-srouter" "$@"\n'
    '  }\n'
    "fi\n"
    f"{ZSHRC_CODEX_FUNC_MARKER_END}"
)


def _codex_wrapper_path(name: str) -> Path:
    """Путь к wrapper в ~/bin (вычисляется динамически — дружелюбно к мокам Path.home в тестах)."""
    return Path.home() / "bin" / name


def _zshrc_path() -> Path:
    """Путь к ~/.zshrc (динамически, для моков Path.home в тестах)."""
    return Path.home() / ".zshrc"


def _looks_like_managed_codex_wrapper(path: str) -> bool:
    """Файл path — наш managed codex-wrapper (несёт srouter-маркер)? Маркер — единственный признак
    «managed wrapper», НЕ путь/имя (memory issue-144: wrapper ≠ binary). cycle-review cycle-4 FIX #1:
    install-time resolver обязан различать managed-wrapper от real binary по маркеру — иначе legacy
    ~/bin/codex (managed) misclassify как real binary → migration удаляет его без независимого real codex
    → новый codex-srouter exit 127. Тот же marker-skip, что wrapper template делает в runtime-резолве.

    #176: marker-in-content classification централизован в marker_block.is_managed_artifact."""
    return marker_block.is_managed_artifact(path, CODEX_WRAPPERS[0][2])


def _codex_bin_path() -> str:
    """Абсолютный путь к реальному codex binary (не наш wrapper) — install-time GATE: отвечает только
    на вопрос «есть ли на диске независимый real codex» (если нет → WARN, wrapper не ставится). ПУТЬ сюда НЕ
    вшивается: с #144 CLI-wrapper runtime-резолвит codex по PATH вызывающего минуя себя (подход A),
    так что >1 binary на диске и смена binary после brew upgrade покрыты без reinstall.
    shutil.which минуя наш wrapper (codex-srouter после #169), fallback на homebrew-пути (Apple Silicon / Intel).
    '' если не найден. cycle-review cycle-4 FIX #1: отвергаем ЛЮБОЙ кандидат с managed-маркером (не только
    codex-srouter) — legacy ~/bin/codex (managed) НЕ считается real binary, иначе migration удалила бы его
    без независимого real codex. Примечание #169: real binary зовётся codex (имя освобождено от wrapper'а)."""
    found = shutil.which("codex")
    if found and not _looks_like_managed_codex_wrapper(found):
        return found
    for cand in (str(Path(BREW).parent / "codex"), "/opt/homebrew/bin/codex", "/usr/local/bin/codex"):
        if Path(cand).exists() and not _looks_like_managed_codex_wrapper(cand):
            return cand
    return ""  # не найден — _install_one_wrapper покажет WARN


def _install_one_wrapper(env, wrapper_path: Path, template_name: str, marker: str) -> str:
    """Поставить один wrapper. Marker-gate + marker-migration + atomic write + chmod +x.

    issue #112 Часть 4 (РЕШЕНИЕ 2): при существующем wrapper'е различаем ТРИ случая:
      - current-маркер есть → переустановить (idempotent, обновить рендер).
      - legacy-маркер из known_markers → МИГРИРОВАТЬ (перезаписать с current-маркером). Смена версии
        маркера: старый «свой» распознаётся через state-таблицу, иначе залипал бы на старой версии.
      - unmarked (нет ни current, ни legacy) → WARN, НЕ adopt молча (канон fail-closed, чужое не трогаем).
    """
    try:
        if wrapper_path.exists():
            content = wrapper_path.read_text(encoding="utf-8")
            if marker in content:
                pass  # наш current — переустановим (idempotent).
            else:
                # Marker-migration: проверить legacy-маркеры из known_markers (state-based, #112 ч.4).
                known = load_known_markers(env.state_path, "wrappers", [marker])
                legacy_hits = [m for m in known if m != marker and m in content]
                if not legacy_hits:
                    # Unmarked wrapper — не наш (нет current, нет legacy). WARN, не adopt.
                    return (f"Codex {wrapper_path.name}: существует без srouter-маркера — не трогаем "
                            f"(удали вручную, если это твой старый wrapper).")
                # legacy-маркер найден → мигрируем (продолжаем к рендеру, atomic write обновит файл).
        codex_bin = _codex_bin_path()
        if not codex_bin:
            return f"Codex {wrapper_path.name}: codex binary не найден — wrapper не установлен (установи codex)."
        template = (env.root / "launchagents" / template_name).read_text(encoding="utf-8")
        # Рендер плейсхолдеров из единого источника правды, не хардкод литералов. CLI-wrapper
        # (srouter-codex-cli-wrapper.sh) использует _CODEX_PROXY_URL + CODEX_NO_PROXY_LOOPBACK
        # (loopback-only, БЕЗ z.ai — это санитизация #96, не provider-direct; z.ai релевантен только
        # launchctl-gui CODEX_NO_PROXY для moonbridge). Реальный codex он РАНТАЙМ-резолвит по PATH
        # минуя себя (#144, подход A), абсолютный путь НЕ вшивается. App-wrapper плейсхолдеров прокси
        # не содержит (.replace на отсутствующей подстроке — no-op).
        rendered = (template
                    .replace("__SROUTER_CODEX_PROXY_URL__", _CODEX_PROXY_URL)
                    .replace("__SROUTER_CODEX_NO_PROXY__", CODEX_NO_PROXY_LOOPBACK))
        wrapper_path.parent.mkdir(parents=True, exist_ok=True)
        if not _write_text_atomic(wrapper_path, rendered):
            return f"Codex {wrapper_path.name}: не записан (ошибка atomic write)."
        wrapper_path.chmod(0o755)
        # CLI-wrapper: best-effort layer (#144). Не fail-closed — честная граница = PF kill-switch.
        if wrapper_path.name == CODEX_CLI_WRAPPER_NAME:
            return (f"Codex {wrapper_path.name}: установлен ({wrapper_path} — SOCKS5 минуя privoxy). "
                    f"Best-effort (НЕ fail-closed): runtime-резолвит codex по PATH вызывающего. "
                    f"НЕ перехватывает прямой абсолютный путь к binary, `node codex.js` и вызов с "
                    f"другим PATH — настоящая fail-closed граница = PF kill-switch (isolate_firewall.py).")
        return f"Codex {wrapper_path.name}: установлен ({wrapper_path} — SOCKS5 минуя privoxy)."
    except (OSError, ValueError, TypeError) as exc:
        # Файловые операции + PATH-манипуляции → OSError, ValueError, TypeError
        return f"Codex {wrapper_path.name}: не установлен ({str(exc)[:80]})."


def _install_codex_wrappers(env) -> str:
    """Поставить ~/bin/codex-srouter + ~/bin/codex-app-proxy. Best-effort, цикл по CODEX_WRAPPERS.

    Issue #169 rename-migration: перед установкой нового codex-srouter подчищаем устаревший
    srouter-managed ~/bin/codex от прежней установки (до rename) — иначе коллизия неймспейса
    остаётся (два wrapper'а: старый codex + новый codex-srouter). Чужой ~/bin/codex (без маркера)
    — не трогаем (fail-closed provenance, #112).

    cycle-review FIX A (транзакционность): migration legacy ~/bin/codex → удаление разрешено ТОЛЬКО
    если новый codex-srouter установлен и валиден (несёт current-маркер, executable). Если install
    нового упал (codex binary не найден / write-fail / foreign codex-srouter без маркера) — legacy
    СОХРАНЯЕТСЯ, иначе пользователь терял работающий wrapper без замены (молчаливый частичный успех)."""
    parts = [_install_one_wrapper(env, _codex_wrapper_path(name), tmpl, marker)
             for name, tmpl, marker in CODEX_WRAPPERS]
    cli_marker = CODEX_WRAPPERS[0][2]
    # Транзакционность: новый codex-srouter должен стоять И быть нашим (current-маркер + executable).
    # Иначе миграция отменилась бы (удаление legacy без замены = потеря wrapper'а).
    # _codex_zsh_target_installed() — единый критерий валидности target (общий с _install_codex_zsh_function,
    # cycle-review cycle-2 FIX #1): одно определение «target валиден» → нет рассинхрона между
    # legacy-preservation (здесь) и zsh-migration (там).
    if _codex_zsh_target_installed():
        migration_note = _migrate_legacy_codex_cli_wrapper(cli_marker, action="install")
        if migration_note:
            parts.append(migration_note)
    else:
        legacy = _codex_wrapper_path(CODEX_CLI_WRAPPER_LEGACY_NAME)
        if legacy.exists():
            parts.append(
                f"Codex {CODEX_CLI_WRAPPER_LEGACY_NAME}: миграция отложена — новый "
                f"{CODEX_CLI_WRAPPER_NAME} не установлен/не валиден (сохранил устаревший wrapper, #169).")
    return "\n".join(parts)


def _migrate_legacy_codex_cli_wrapper(marker: str, *, action: str) -> str:
    """Rename-migration старого ~/bin/codex (#169). Возвращает note-строку (пусто = нечего делать).

    install: srouter-managed ~/bin/codex (по маркеру) → УДАЛИТЬ (устарел, заменён на codex-srouter);
             чужой (без маркера) → WARN «не трогаем» (fail-closed provenance #112, как marker-gate).
    remove:  srouter-managed ~/bin/codex → удалить (leftover cleanup, симметрия install);
             чужой → пусто (remove молча не трогает чужое, WARN только в install-контексте).

    Маркер НЕ менялся при rename (идентифицирует «srouter-managed wrapper», не имя файла) → один и тот же
    маркер валиден и для codex-srouter, и для устаревшего codex. Это и есть признак «наш»."""
    legacy = _codex_wrapper_path(CODEX_CLI_WRAPPER_LEGACY_NAME)
    try:
        if not legacy.exists():
            return ""
        content = legacy.read_text(encoding="utf-8")
        if marker in content:
            # srouter-managed устаревший wrapper → удалить (rename-cleanup).
            legacy.unlink()
            return (f"Codex {CODEX_CLI_WRAPPER_LEGACY_NAME}: мигрирован → удалён устаревший "
                    f"wrapper (заменён на {CODEX_CLI_WRAPPER_NAME}, #169).")
        # Чужой ~/bin/codex без маркера — не наш. install WARN'ует оператору, remove молча пропускает.
        if action == "install":
            return (f"Codex {CODEX_CLI_WRAPPER_LEGACY_NAME}: существует чужой ~/bin/{CODEX_CLI_WRAPPER_LEGACY_NAME} "
                    f"без srouter-маркера — не трогаем (замени на codex-srouter или удали вручную).")
        return ""
    except (OSError, ValueError, TypeError) as exc:
        # Файловые операции → OSError, ValueError, TypeError
        return (f"Codex {CODEX_CLI_WRAPPER_LEGACY_NAME}: миграция не выполнена ({str(exc)[:60]}).")


def _remove_one_wrapper(wrapper_path: Path, marker: str) -> str:
    """Удалить один wrapper (если srouter-managed). Marker-gate обязательный."""
    try:
        if not wrapper_path.exists():
            return f"Codex {wrapper_path.name}: не был установлен."
        if marker not in wrapper_path.read_text(encoding="utf-8"):
            return f"Codex {wrapper_path.name}: чужой {wrapper_path} — не трогаем."
        wrapper_path.unlink()
        return f"Codex {wrapper_path.name}: удалён."
    except (OSError, ValueError, TypeError) as exc:
        # Файловые операции → OSError, ValueError, TypeError
        return f"Codex {wrapper_path.name}: не удалён ({str(exc)[:60]})."


def _remove_codex_wrappers() -> str:
    """Удалить wrappers (если srouter-managed). Цикл по CODEX_WRAPPERS, единый разделитель с install.

    Issue #169 rename-migration: также подчищаем устаревший srouter-managed ~/bin/codex от прежней
    установки (до rename) — leftover иначе даёт «призрак» wrapper'а после деинсталляции. Чужой
    ~/bin/codex (без маркера) — не трогаем (fail-closed provenance #112)."""
    parts = [_remove_one_wrapper(_codex_wrapper_path(name), marker)
             for name, _, marker in CODEX_WRAPPERS]
    cli_marker = CODEX_WRAPPERS[0][2]
    migration_note = _migrate_legacy_codex_cli_wrapper(cli_marker, action="remove")
    if migration_note:
        parts.append(migration_note)
    return "\n".join(parts)


def _install_launchctl_env(env, runner) -> str:
    """Глобальный SOCKS5 env через LaunchAgent (RunAtLoad + launchctl setenv). Переживает ребут.

    launchctl setenv кладёт переменные в GUI-домен launchd → все GUI-приложения их видят. Но setenv
    сам по себе не переживает ребут — LaunchAgent com.srouter.codenv (RunAtLoad + StartInterval=300)
    вызывает скрипт srouter-codex-env.sh, который делает setenv при загрузке и каждые 5мин.
    Эмпирически: Claude.app/ChatGPT.app на System Settings SOCKS, global env их не ломает.

    Через _install_generic_launchagent (как watchdog): marker-gate + atomic write + _launchd_reload
    (bootout→poll→bootstrap-retry, решает гонку занятого домена — PR #80).
    """
    try:
        # Предупредить, если в GUI-домене уже есть ЧУЖОЙ прокси (корпоративный/ручной) — setenv
        # скрипта его перезапишет без восстановления. Не блокируем, но WARN в статусе.
        # issue #191 (эмпирически подтверждено): `getenv gui/<uid> HTTP_PROXY` МОЛЧА игнорирует домен
        # (Usage: getenv <key> — ровно один позиционный аргумент, второй отбрасывается) → val ВСЕГДА
        # пуст, WARN никогда не срабатывал. Единственный домен-осознанный источник — `launchctl print
        # gui/<uid>` (health._read_gui_proxy_env, тот же паттерн, что doctor-чеки #189).
        warn = ""
        gui = health._read_gui_proxy_env(runner, keys_filter=("HTTP_PROXY",))
        val = gui.get("keys", {}).get("HTTP_PROXY", "")
        if val and "127.0.0.1:10808" not in val:
            warn = f" ВНИМАНИЕ: существующий GUI HTTP_PROXY={val[:40]} будет перезаписан (backup не делается)."
        ok, err = _install_generic_launchagent(
            env, runner,
            template_name="com.srouter.codenv.plist",
            label=CODEX_ENV_LABEL,
            marker=CODEX_ENV_MARKER,
            script_path=env.root / "launchagents" / "srouter-codex-env.sh",
        )
        if ok:
            return (f"Codex env: LaunchAgent {CODEX_ENV_LABEL} загружен (SOCKS5 в GUI-домен, "
                    f"переживает ребут).{warn}")
        if err.endswith("_foreign"):
            return f"Codex env: чужой LaunchAgent {CODEX_ENV_LABEL} — не трогаем."
        return f"Codex env: не установлен ({err})."
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        # LaunchAgent операции + subprocess → OSError, subprocess исключения
        return f"Codex env: не установлен ({str(exc)[:80]})."


def _remove_launchctl_env(runner) -> dict:
    """Выгрузить LaunchAgent env + снять переменные из GUI-домена + удалить plist.

    Возвращает {ok: bool, note: str}. ok=False пробрасывается в ненулевой rc cmd_uninstall — это
    и есть fail-closed (раньше возвращалась только строка → конкатенировалась в сообщение → fail-open).

    Порядок важен: bootout ПЕРЕД unlink. Если bootout не сработал, а агент всё ещё загружен
    (_launchd_is_loaded), НЕ удаляем plist — иначе StartInterval-агент останется в памяти и будет
    пере-применять мёртвый socks5 env каждые 5 мин (утечка нерабочего прокси в GUI-домен).

    env-cleanup — ВНУТРИ gui-домена явно (issue #94 DEFECT A, переписано issue #191). `launchctl
    setenv/unsetenv/getenv` оперируют «caller's context» (man launchctl): setenv делает LaunchAgent-
    скрипт, запущенный launchd В gui-домене → переменные в gui. uninstall бежит из процесса
    cmd_uninstall (caller-context может быть user/<uid> из SSH/cron). unsetenv без домена снял бы НЕ
    в gui → gui-домен остался бы с мёртвым 127.0.0.1:10808. Изначальный фикс #94 предполагал, что
    домен принимается голым аргументом (`unsetenv gui/<uid> <key>` / `getenv gui/<uid> <key>`) —
    ОПРОВЕРГНУТО эмпирически (issue #191): эти вызовы молча игнорируют домен-аргумент (Usage:
    getenv <key> — ровно один позиционный аргумент). Рабочий путь: `launchctl asuser <uid> launchctl
    unsetenv <key>` (man: исполняет в bootstrap-контексте target-пользователя — реально gui), затем
    верификация `launchctl print gui/<uid>` блок environment={...} (строгий первоисточник, НЕ getenv).
    Любой ключ, оставшийся в gui-домене → ok=False (fail-closed).
    """
    try:
        plist_path = Path.home() / "Library" / "LaunchAgents" / f"{CODEX_ENV_LABEL}.plist"
        if not plist_path.exists():
            return {"ok": True, "note": "Codex env: не был установлен."}
        if CODEX_ENV_MARKER not in plist_path.read_text(encoding="utf-8"):
            return {"ok": True, "note": f"Codex env: чужой LaunchAgent {CODEX_ENV_LABEL} — не трогаем."}
        # bootout + poll реальной выгрузки — единый контракт _launchd_unload (issue #84). bootout
        # асинхронен: без poll _launchd_is_loaded вернёт True в окне → ложный «ещё загружен» → plist
        # оставлен + StartInterval-агент пере-применяет мёртвый env. tristate проходит насквозь.
        loaded = _launchd_unload(_launchd_domain(), CODEX_ENV_LABEL, runner=runner)["state"]
        # None = unknown (launchctl list timeout) — fail-safe: НЕ удаляем plist (оставить контроль).
        # True = агент реально ещё загружен после settle — тоже не удаляем.
        if loaded is not False:
            note = (f"Codex env: LaunchAgent {CODEX_ENV_LABEL} "
                    f"{'не подтверждена выгрузка' if loaded is None else 'всё ещё загружен'} "
                    f"после bootout — plist оставлен (не удалять контроль). "
                    f"Проверь: launchctl list | grep {CODEX_ENV_LABEL}")
            # Агент потенциально жив в gui-домене → env активен. ok=False: cmd_uninstall не должен
            # рапортовать полный успех, пока env-прокси не подтверждённо снят (fail-closed).
            return {"ok": False, "note": note}
        # Снять переменные ИЗ gui-домена явно и верифицировать.
        #
        # issue #191 (эмпирически подтверждено на реальной машине, не гипотеза): `launchctl unsetenv/
        # getenv gui/<uid> KEY` МОЛЧА не работают — `Usage: launchctl getenv <key>` принимает РОВНО
        # один позиционный аргумент; вызов с двумя ("gui/<uid>", "KEY") трактует ПЕРВЫЙ как имя
        # переменной, ВТОРОЙ молча игнорируется (доказано: `setenv gui/501 X` + `getenv gui/501` → X).
        # То же для unsetenv — реальный ключ в gui-домене не снимается, rc=0 без эффекта.
        #
        # Рабочий домен-осознанный путь (эмпирика + man launchctl asuser): `launchctl asuser <uid>
        # launchctl unsetenv KEY` — asuser выполняет команду "in as similar an execution context as
        # possible to that of the target user's bootstrap" (man), то есть РЕАЛЬНО внутри gui-домена,
        # независимо от caller-context процесса cmd_uninstall (SSH/cron/AO-shell). Верификация —
        # `launchctl print gui/<uid>` блок `environment = {...}` (единственный домен-осознанный
        # источник чтения, тот же паттерн, что health._read_gui_proxy_env для doctor-чеков #189).
        uid = os.getuid()
        all_keys = tuple(key for key, _ in CODEX_LAUNCHCTL_ENV)
        for key in all_keys:
            runner([LAUNCHCTL, "asuser", str(uid), LAUNCHCTL, "unsetenv", key], 5)
        gui = health._read_gui_proxy_env(runner, keys_filter=all_keys)
        if not gui.get("verifiable"):
            # print gui/<uid> не смог спросить (timeout / домен недоступен) → состояние НЕверифицируемо.
            # fail-closed (канон): НЕ рапортуем «снято», ok=False — оператор должен проверить вручную.
            # Plist оставлен как контроль. Отличие от leftover: переменные МОГУТ быть сняты, но мы не знаем.
            return {"ok": False,
                    "note": (f"Codex env: НЕ подтверждено снятие — launchctl print gui/{uid} не ответил "
                             f"(таймаут/домен недоступен). Проверь: launchctl print gui/{uid}. "
                             f"Plist оставлен.")}
        leftover = [k for k in all_keys if k in gui["keys"]]
        if leftover:
            # Переменная осталась ЖИВОЙ в gui-домене → мёртвый 127.0.0.1:10808 утечёт в GUI-приложения.
            # НЕ удаляем plist (контроль), ok=False → cmd_uninstall вернёт ненулевой rc (fail-closed).
            return {"ok": False,
                    "note": (f"Codex env: НЕ снят — переменные остались в gui-домене ({', '.join(leftover)}). "
                             f"Проверь: launchctl print gui/{uid} | "
                             f"launchctl asuser {uid} launchctl unsetenv {leftover[0]}. Plist оставлен.")}
        plist_path.unlink()
        return {"ok": True,
                "note": f"Codex env: снят (LaunchAgent {CODEX_ENV_LABEL} выгружен, env очищен, plist удалён)."}
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        # LaunchAgent + файловые операции + subprocess → OSError, subprocess исключения
        return {"ok": False, "note": f"Codex env: не снят ({str(exc)[:80]})."}


def _ensure_home_bin_in_path(env) -> str:
    """Добавить ~/bin в PATH через ~/.zshrc (marker-gate + backup через install_lib._backup + atomic write).

    CLI wrapper требует ~/bin раньше системного codex в PATH.
    """
    try:
        from install_lib import _backup
        zshrc = _zshrc_path()
        block = f'\n{ZSHRC_PATH_MARKER}\nexport PATH="$HOME/bin:$PATH"\n'
        if not zshrc.exists():
            # Тот же порядок, что и append (marker → export), чтобы _remove_home_bin_from_path
            # (удаляет marker + следующую строку) корректно убирал блок. Не export→marker (иначе
            # uninstall оставит висячий export).
            _write_text_atomic(zshrc, f'{ZSHRC_PATH_MARKER}\nexport PATH="$HOME/bin:$PATH"\n')
            return "PATH: создан ~/.zshrc с ~/bin (новый терминал подхватит codex wrapper)."
        content = zshrc.read_text(encoding="utf-8")
        if ZSHRC_PATH_MARKER in content or '$HOME/bin' in content or "${HOME}/bin" in content:
            return "PATH: ~/bin уже в ~/.zshrc (idempotent)."
        _backup(zshrc, env)  # timestamped backup через каноничный helper
        _write_text_atomic(zshrc, content + block)
        return "PATH: ~/bin добавлен в ~/.zshrc (backup: .zshrc.srouter-backup-*)."
    except (OSError, ValueError, TypeError) as exc:
        # Файловые операции → OSError, ValueError, TypeError
        return f"PATH: не изменён ({str(exc)[:80]})."


def _remove_home_bin_from_path() -> str:
    """Убрать srouter-блок ~/bin из ~/.zshrc (симметрично _ensure_home_bin_in_path). Marker-gate.

    Удаляет ТОЛЬКО наш управляемый блок: маркер + следующую за ним строку export. Чужой
    `export PATH="$HOME/bin:$PATH"` в другом месте файла — НЕ трогаем (правило «чужое не трогать»).
    """
    try:
        zshrc = _zshrc_path()
        if not zshrc.exists():
            return "PATH: не был изменён."
        lines = zshrc.read_text(encoding="utf-8").splitlines()
        if ZSHRC_PATH_MARKER not in lines:
            return "PATH: не был изменён."
        # Найти индекс маркера, удалить его + следующую строку (наш export PATH).
        out = []
        i = 0
        while i < len(lines):
            if lines[i] == ZSHRC_PATH_MARKER:
                # Пропустить маркер и следующую строку (управляемый блок). Если следующая не наш
                # export — всё равно пропускаем (мы её сами добавили после маркера при install).
                i += 2
                continue
            out.append(lines[i])
            i += 1
        _write_text_atomic(zshrc, "\n".join(out).rstrip() + "\n")
        return "PATH: ~/bin убран из ~/.zshrc."
    except (OSError, ValueError, TypeError) as exc:
        # Файловые операции → OSError, ValueError, TypeError
        return f"PATH: не убран ({str(exc)[:80]})."


def _codex_zsh_target_installed() -> bool:
    """Установлен ли новый codex-srouter И валиден (is_file + executable + current-маркер)?

    cycle-review cycle-2 FIX #1 (transactional coherence): zsh-migration stale-блока codex→codex-srouter
    согласовывается с wrapper-install — мигрируем zsh только если target реально стоит. Иначе FIX A
    сохранит рабочий legacy ~/bin/codex, а FIX B перенаправит zsh на codex-srouter (которого нет) →
    inconsistency (`codex` зовёт несуществующий файл, притом рабочий legacy стоит). Те же критерии, что
    new_installed_ok в _install_codex_wrappers — единый источник правды валидности target.

    #176: тело (is_file + X_OK + marker в содержимом) централизовано в marker_block.validate_target_installed."""
    try:
        wrapper = _codex_wrapper_path(CODEX_CLI_WRAPPER_NAME)
        return marker_block.validate_target_installed(wrapper, CODEX_WRAPPERS[0][2])
    except OSError:
        return False


def _install_codex_zsh_function(env) -> str:
    """Добавить shell-функцию codex() в ~/.zshrc (issue #96).

    Функция вызывает ~/bin/codex-srouter по АБСОЛЮТНОМУ пути — порядок brew в PATH не важен (функция
    всегда бьёт binary). Без неё wrapper #83 проигрывает /opt/homebrew/bin/codex → Codex идёт через privoxy
    (наследует HTTP_PROXY от ~/.claude/settings.json env) → режёт WS → "Falling back to HTTPS".

    Issue #169: функция зовёт переименованный wrapper ~/bin/codex-srouter (внутри _CODEX_FUNC_BLOCK).
    Сама функция по-прежнему зовётся codex() в интерактивном шелле — пользовательский habit `codex …`
    сохранён, только внутри ведёт на codex-srouter (имя codex освобождено под real binary).

    Marker-gate (парные begin/end) + backup через install_lib._backup + atomic write — тот же
    канон, что _ensure_home_bin_in_path. Fail-closed: чужой alias codex/function codex без нашего
    маркера → НЕ добавляем блок (не перекрываем молча).

    #176: ordered-pair marker-parsing централизован в marker_block.find_managed_block (единственный
    источник инварианта «ровно одна упорядоченная пара» — замыкает cycle-3/cycle-4 класс дыр разом).
    Никакого count/find/ordered_pair вне marker_block: здесь только find → block, inspect span, replace.
    """
    try:
        from install_lib import _backup
        zshrc = _zshrc_path()
        content = zshrc.read_text(encoding="utf-8") if zshrc.exists() else ""
        # Idempotent ИЛИ migration stale-блока (cycle-review FIX B). Managed-блок уже на месте —
        # но он может быть от установки ДО rename (#169) и звать устаревший ~/bin/codex. Только по
        # голому маркеру short-circuit'ить нельзя: zsh-функция осталась бы звать удалённый legacy
        # wrapper → `codex` в интерактивном шелле ломался, притом install рапортил успех.
        # Различаем: блок зовёт текущий codex-srouter → idempotent; зовёт устаревший codex → обновляем.
        block = marker_block.find_managed_block(content,
                                                ZSHRC_CODEX_FUNC_MARKER_BEGIN,
                                                ZSHRC_CODEX_FUNC_MARKER_END)
        any_marker = (ZSHRC_CODEX_FUNC_MARKER_BEGIN in content
                      or ZSHRC_CODEX_FUNC_MARKER_END in content)
        if any_marker and block is None:
            # Маркеры присутствуют, но не образуют ровно одну упорядоченную пару → fail-closed
            # (реверснутые/дублированные: count для диагностического сообщения, решение = отказ).
            begins = content.count(ZSHRC_CODEX_FUNC_MARKER_BEGIN)
            ends = content.count(ZSHRC_CODEX_FUNC_MARKER_END)
            return ("Codex функция: повреждённый managed-маркер в ~/.zshrc "
                    f"(begin={begins}, end={ends}) — не обновляю (проверь вручную).")
        if block is not None:
            # Инспектируем target-строку ТОЛЬКО внутри валидированного span (cycle-4 FIX #2:
            # строка по всему content не должна обходить инвариант — берём span_text из find_managed_block).
            span = block.span_text
            if '"$HOME/bin/codex-srouter" "$@"' in span:
                # cycle-review cycle-4 FIX #2: current-блок принимаем «idempotent» ТОЛЬКО после target-gate.
                # Иначе предсуществующий блок (target удалён) ведёт в никуда, а install рапортует ОК.
                if not _codex_zsh_target_installed():
                    return ("Codex функция: managed-блок зовёт codex-srouter, но target не установлен/не валиден — "
                            "проверь ~/bin/codex-srouter (блок не трогаю, не рапортую idempotent вслепую).")
                return "Codex функция: уже в ~/.zshrc (idempotent)."
            if '"$HOME/bin/codex" "$@"' in span:
                # cycle-review cycle-3 FIX #1-root (unified target gate): мигрируем stale-блок codex → codex-srouter
                # ТОЛЬКО если новый codex-srouter установлен и валиден. Иначе FIX A сохранит legacy ~/bin/codex
                # (рабочий), а zsh перенаправится на codex-srouter (которого нет) → inconsistency.
                if not _codex_zsh_target_installed():
                    return ("Codex функция: новый codex-srouter не установлен/не валиден — "
                            "stale zsh-блок НЕ мигрирую (оставляя ~/bin/codex, рабочий). "
                            "Запусти srouter install после установки codex binary.")
                _backup(zshrc, env)  # timestamped backup перед правкой managed-блока
                updated_block = span.replace('"$HOME/bin/codex" "$@"',
                                             '"$HOME/bin/codex-srouter" "$@"')
                new_content = marker_block.replace_managed_block(content, block, updated_block)
                # проверяем результат atomic-write, не рапортуем успех молча (cycle-2 FIX #1b).
                if not _write_text_atomic(zshrc, new_content):
                    return "Codex функция: не обновлена (ошибка atomic write ~/.zshrc)."
                return ("Codex функция: обновлён путь в managed-блоке (codex → codex-srouter, rename #169). "
                        "Backup: .zshrc.srouter-backup-*. "
                        "ВНИМАНИЕ: существующие терминалы/codex-процессы не получат новое окружение — "
                        "перезапусти их (exec zsh -l, затем закрыть/открыть TUI).")
            # Managed-маркер есть, но target-строка не распознана (модифицированный блок) — не трогаем (fail-closed).
            return "Codex функция: уже в ~/.zshrc (idempotent)."
        # block is None AND not any_marker → fresh-create/append path. cycle-review cycle-3 FIX #1-root
        # (unified target gate): zsh-функция (codex-srouter) создаётся ТОЛЬКО если target установлен и
        # валиден. Иначе она shadow'ит сохранённый legacy ~/bin/codex (FIX A) и зовёт несуществующий
        # codex-srouter — та же inconsistency через fresh-create.
        # Замкнутый инвариант: _codex_zsh_target_installed() — единый gate ДЛЯ ВСЕХ путей (migration/create/append).
        if not _codex_zsh_target_installed():
            return ("Codex функция: новый codex-srouter не установлен/не валиден — "
                    "zsh-функция не добавляется (иначе shadow'нет рабочий ~/bin/codex, зовя несуществующий target). "
                    "Запусти srouter install после установки codex binary.")
        # Fail-closed: чужое определение codex (alias или function) без нашего маркера — не трогаем.
        # `alias codex=` или `codex()` или `function codex`/`codex ()`. Ищем как определение,
        # не как упоминание в комментарии (требуем синтаксис присваивания/определения).
        has_foreign = bool(re.search(r'(^|\n)\s*(alias\s+codex\s*=|function\s+codex\b|codex\s*\(\s*\)\s*\{)',
                                    content))
        if has_foreign:
            return ("Codex функция: обнаружен чужой alias/function codex в ~/.zshrc — "
                    "не добавляю (конфликт). ~/bin/codex-srouter доступен как явная точка входа.")
        if not zshrc.exists():
            _write_text_atomic(zshrc, _CODEX_FUNC_BLOCK + "\n")
            return ("Codex функция: создан ~/.zshrc с codex() → ~/bin/codex-srouter (новый терминал подхватит). "
                    "ВНИМАНИЕ: существующие терминалы/codex-процессы не получат новое окружение — "
                    "перезапусти их (exec zsh -l в каждом, затем закрыть/открыть TUI).")
        _backup(zshrc, env)  # timestamped backup, каноничный helper
        _write_text_atomic(zshrc, content.rstrip() + "\n\n" + _CODEX_FUNC_BLOCK + "\n")
        return ("Codex функция: добавлена в ~/.zshrc (codex → ~/bin/codex-srouter по абс. пути, "
                "бьёт brew в PATH). Backup: .zshrc.srouter-backup-*. "
                "ВНИМАНИЕ: существующие терминалы/codex-процессы не получат новое окружение — "
                "перезапусти их (exec zsh -l, затем закрыть/открыть TUI); иначе старая TUI пойдёт "
                "через privoxy 8118 и порвёт long-lived WS (#120).")
    except (OSError, ValueError, TypeError) as exc:
        # Файловые операции → OSError, ValueError, TypeError
        return f"Codex функция: не добавлена ({str(exc)[:80]})."


def _remove_codex_zsh_function() -> str:
    """Убрать managed-блок codex() из ~/.zshrc (симметрично _install_codex_zsh_function).

    Удаляет ТОЛЬКО парный begin…end блок (включая function-определение внутри). Чужой контент
    (export PATH, комментарии, чужой alias/function codex — если появился позже) НЕ трогаем.
    Если маркеры непарные (повреждённое состояние) — fail-closed: отказ, не широкое удаление.

    #176: ordered-pair marker-parsing + newline-cleanup централизованы в marker_block
    (find_managed_block → block; remove_managed_block → slice + rstrip "\n", byte-for-byte как прежде).
    """
    try:
        zshrc = _zshrc_path()
        if not zshrc.exists():
            return "Codex функция: не была изменена."
        content = zshrc.read_text(encoding="utf-8")
        if ZSHRC_CODEX_FUNC_MARKER_BEGIN not in content and ZSHRC_CODEX_FUNC_MARKER_END not in content:
            return "Codex функция: не была изменена."
        # cycle-review cycle-4 FIX #3: тот же ordered-pair инвариант, что в install (cycle-3). Ровно одна
        # УПОРЯДОЧЕННАЯ пара (begin перед end). Реверснутые/дублированные → safe no-op, НЕ corruption
        # (иначе start>end → slice overlap → дублирование контента .zshrc, рапорт «убрана»).
        # Замкнут в marker_block.find_managed_block (None = повреждено/непарно).
        block = marker_block.find_managed_block(content,
                                                ZSHRC_CODEX_FUNC_MARKER_BEGIN,
                                                ZSHRC_CODEX_FUNC_MARKER_END)
        if block is None:
            begins = content.count(ZSHRC_CODEX_FUNC_MARKER_BEGIN)
            ends = content.count(ZSHRC_CODEX_FUNC_MARKER_END)
            return ("Codex функция: не удалена — повреждённый маркер "
                    f"(begin={begins}, end={ends}), проверь ~/.zshrc вручную.")
        # remove_managed_block: slice блока + зачистка окружающих \n (мы добавляли \n\n перед блоком при install).
        new_content = marker_block.remove_managed_block(content, block)
        # проверяем результат atomic-write, не рапортуем успех молча (cycle-4 симметрия с install).
        if not _write_text_atomic(zshrc, new_content):
            return "Codex функция: не убрана (ошибка atomic write ~/.zshrc)."
        return "Codex функция: убрана из ~/.zshrc."
    except (OSError, ValueError, TypeError) as exc:
        # Файловые операции → OSError, ValueError, TypeError
        return f"Codex функция: не убрана ({str(exc)[:80]})."


def _install_codex_isolation(env, runner) -> str:
    """Best-effort: provisioning _srouter_codex (uid 503) + включить PF codex-изоляцию.

    PF kill-switch — настоящая fail-closed граница codex (epic #166, issue #168/#186): блокирует
    прямой выход UID 503 в ядре, разрешает только loopback SOCKS5 10808. Правила (user 503) матчат
    трафик ТОЛЬКО когда системный пользователь с этим UID существует → provisioning создаёт его
    ДО загрузки правил (UID готов к моменту apply → правила активны сразу, без окна «валидны но
    не матчат»). Best-effort (как остальные codex-шаги) — сбой provisioning НЕ валит install.
    Known-limitation (follow-up): запуск codex под uid 503 (sudo -u в wrapper) — отдельный PR.
    """
    try:
        import isolate_firewall
        state_path = getattr(env, "state_path", None) if env is not None else None
        # 1) Provisioning UID 503 ДО enable (канон fail-closed: правила активны сразу после загрузки).
        prov = isolate_firewall.provision_codex_user()
        prov_note = "" if prov.get("ok") else f" provisioning не удался ({prov.get('err', 'unknown')});"
        # 2) Переиспользуем существующий token из lease (как CLI enable-codex, isolate_firewall.py:534),
        #    иначе re-install каждый раз зовёт pfctl -E → копит leaked enable-ref'ы (cycle-review cycle 1).
        lease = local_state.load_active_codex_isolate(path=state_path) or {}
        r = isolate_firewall.enable_codex_isolation(token=lease.get("token"))
        if r.get("ok"):
            local_state.save_active_codex_isolate({"token": r.get("token"), "applied_at": None}, path=state_path)
            return ("Codex PF-изоляция: sub-anchor загружен + _srouter_codex (uid 503) создан "
                    f"(kill-switch активен).{prov_note} "
                    "Запуск codex под uid 503 (sudo -u) — follow-up.")
        return f"Codex PF-изоляция: не включена ({r.get('err', 'unknown')}).{prov_note}"
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        # isolate_firewall subprocess + state операции → OSError, subprocess исключения
        return f"Codex PF-изоляция: сбой ({str(exc)[:80]})."


def _remove_codex_isolation(env, runner) -> str:
    """Best-effort: снять codex-изоляцию при uninstall (flush sub-anchor + release token) +
    deprovision _srouter_codex (uid 503). Идемпотентно.

    state очищается ТОЛЬКО при подтверждённом disable (r.ok) — иначе leaked pfctl -E enable-ref
    остаётся захваченным, но token стёрт → release невозможен без pfctl -d (cycle-review cycle 1,
    канон fail-closed-proxy-down: state обязан отражать реальность). Deprovision пользователя —
    ПОСЛЕ успешного disable+clear (правила сняты → субъект правила больше не нужен; симметрия
    state-lifecycle: не трогаем пользователя при незавершённом disable, repeatable).
    """
    try:
        import isolate_firewall
        state_path = getattr(env, "state_path", None) if env is not None else None
        lease = local_state.load_active_codex_isolate(path=state_path) or {}
        r = isolate_firewall.disable_codex_isolation(token=lease.get("token"))
        if r.get("ok"):
            local_state.clear_active_codex_isolate(path=state_path)
            deprov = isolate_firewall.deprovision_codex_user()  # best-effort, идемпотентно
            deprov_note = "" if deprov.get("ok") else f" пользователь не удалён ({deprov.get('err', '')});"
            return f"Codex PF-изоляция: снята.{deprov_note}"
        return f"Codex PF-изоляция: частично ({r.get('err', '')})."  # state сохранён — retry возможен
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        # isolate_firewall subprocess + state операции → OSError, subprocess исключения
        return f"Codex PF-изоляция: не снята ({str(exc)[:80]})."
