"""Codex SOCKS5 wrappers и launchctl env управление.

Codex (CLI + App) работает стабильно только через SOCKS5 (xray 10808) минуя privoxy (портит WS).
srouter install ставит ~/bin/codex + ~/bin/codex-app-proxy + launchctl env (через LaunchAgent
plist, переживает ребут) + ~/bin в PATH; uninstall убирает.

Вынесено из srouter.py для issue #228 (refactor эпик #158).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from install_lib import (
    BREW,
    InstallEnv,
    _install_generic_launchagent,
    _launchd_is_loaded,
    _launchd_unload,
    _write_text_atomic,
    load_known_markers,
)
import marker_block  # централизованный marker-парсер (#176)

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
    """
    try:
        import health
        # Предупредить, если в GUI-домене уже есть ЧУЖОЙ прокси.
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
        return f"Codex env: не установлен ({str(exc)[:80]})."


def _remove_launchctl_env(runner) -> dict:
    """Удалить LaunchAgent + launchctl unsetenv. Возвращает словарь с ключами ok: bool, msg: str.

    Idempotent: отсутствие plist/переменных = успех. unload делаем через _launchd_unload (check loaded)."""
    result = {"ok": True, "msg": "", "steps": []}
    try:
        plist_path = Path.home() / "Library" / "LaunchAgents" / f"{CODEX_ENV_LABEL}.plist"
        # Удалить plist (если srouter-managed).
        if plist_path.exists():
            content = plist_path.read_text(encoding="utf-8")
            if CODEX_ENV_MARKER in content:
                # unload через _launchd_unload (только если loaded).
                if _launchd_is_loaded(CODEX_ENV_LABEL, domain="user"):
                    unloaded, unload_msg = _launchd_unload("user", CODEX_ENV_LABEL)
                    result["steps"].append(unload_msg)
                    if not unloaded:
                        result["ok"] = False
                        result["msg"] = unload_msg
                        return result
                plist_path.unlink()
                result["steps"].append(f"Codex env: plist {CODEX_ENV_LABEL}.plist удалён.")
            else:
                result["steps"].append(f"Codex env: чужой plist {CODEX_ENV_LABEL}.plist — не трогаем.")
        else:
            result["steps"].append(f"Codex env: plist {CODEX_ENV_LABEL}.plist не был установлен.")

        # Удалить переменные через launchctl unsetenv.
        for key, _ in CODEX_LAUNCHCTL_ENV:
            unset_cmd = f"launchctl unsetenv {key}"
            r = runner(unset_cmd.split(), 10)
            # unsetenv silent-fail: если переменной нет, rc=0, out=''.
            if r.get("timeout") or (r.get("rc") not in (0, None) and "not found" not in (r.get("err") or "").lower()):
                result["ok"] = False
                result["msg"] = f"Codex env: launchctl unsetenv не сработал ({(r.get('err') or '')[:60]})."
                return result
        result["steps"].append("Codex env: launchctl unsetenv выполнен.")
        result["msg"] = "\n".join(result["steps"])
        return result
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        result["ok"] = False
        result["msg"] = f"Codex env: не удалён ({str(exc)[:60]})."
        return result


def _ensure_home_bin_in_path(env) -> str:
    """Добавить ~/bin в PATH через ~/.zshrc (маркер ZSHRC_PATH_MARKER). Idempotent."""
    try:
        zshrc = _zshrc_path()
        if not zshrc.exists():
            # Создать ~/.zshrc, если не было (fallback для новых систем).
            zshrc.parent.mkdir(parents=True, exist_ok=True)
            zshrc.write_text("", encoding="utf-8")
        content = zshrc.read_text(encoding="utf-8")
        if ZSHRC_PATH_MARKER in content:
            return "PATH ~/bin: уже есть в ~/.zshrc."
        # Добавить в конец ~/.zshrc (export PATH="$HOME/bin:$PATH").
        block = f"\n{ZSHRC_PATH_MARKER}\nexport PATH=\"$HOME/bin:$PATH\"\n"
        _write_text_atomic(zshrc, content + block)
        return "PATH ~/bin: добавлен в ~/.zshrc."
    except (OSError, ValueError, TypeError) as exc:
        return f"PATH ~/bin: не добавлен ({str(exc)[:60]})."


def _remove_home_bin_from_path() -> str:
    """Удалить ~/bin из PATH (удалить блок ZSHRC_PATH_MARKER из ~/.zshrc). Marker-gate."""
    try:
        zshrc = _zshrc_path()
        if not zshrc.exists():
            return "PATH ~/bin: ~/.zshrc нет — нечего удалять."
        content = zshrc.read_text(encoding="utf-8")
        if ZSHRC_PATH_MARKER not in content:
            return "PATH ~/bin: не был добавлен в ~/.zshrc."
        # Удалить строки блока по маркеру.
        lines = content.splitlines()
        in_block = False
        new_lines = []
        for line in lines:
            if ZSHRC_PATH_MARKER in line:
                in_block = True
                continue
            if in_block and line.strip().startswith("export PATH"):
                continue  # пропустить строку export внутри блока
            if in_block and line.strip() and not line.strip().startswith("#"):
                in_block = False  # конец блока
            new_lines.append(line)
        _write_text_atomic(zshrc, "\n".join(new_lines))
        return "PATH ~/bin: удалён из ~/.zshrc."
    except (OSError, ValueError, TypeError) as exc:
        return f"PATH ~/bin: не удалён ({str(exc)[:60]})."


def _codex_zsh_target_installed() -> bool:
    """Установлен ли целевой wrapper ~/bin/codex-srouter (маркер + executable)?

    Единый критерий валидности target (shared между _install_codex_wrappers и _install_codex_zsh_function,
    cycle-review cycle-2 FIX #1): одно определение «target валиден» → нет рассинхрона между legacy-preservation
    и zsh-migration."""
    target = _codex_wrapper_path(CODEX_CLI_WRAPPER_NAME)
    if not target.exists():
        return False
    content = target.read_text(encoding="utf-8")
    return CODEX_WRAPPERS[0][2] in content and bool(target.stat().st_mode & 0o111)


def _install_codex_zsh_function(env) -> str:
    """Установить shell-функцию codex() в ~/.zshrc (абсолютный путь к codex-srouter).

    Marker-gate: не трогаем чужое определение. Если target не установлен (#228 rename-migration),
    WARN — функция не работает без wrapper'а. Idempotent: текущий маркер → переустановить (блок целиком)."""
    try:
        zshrc = _zshrc_path()
        if not zshrc.exists():
            # Создать ~/.zshrc, если не было.
            zshrc.parent.mkdir(parents=True, exist_ok=True)
            zshrc.write_text("", encoding="utf-8")
        content = zshrc.read_text(encoding="utf-8")
        # Проверить target (cycle-review cycle-2 FIX #1): функция не работает без валидного wrapper'а.
        if not _codex_zsh_target_installed():
            return (f"Codex zsh-функция: целевой wrapper {CODEX_CLI_WRAPPER_NAME} не установлен/не валиден — "
                    f"функция не будет работать. Установи codex.")
        # Проверить существующее определение (guard от перекрытия чужого).
        if "aliases[codex]" in content or "functions[codex]" in content:
            # Проверить наш маркер — если есть, переустановить (idempotent).
            if ZSHRC_CODEX_FUNC_MARKER_BEGIN in content:
                # Удалить старый блок (будет заменён на новый).
                block = marker_block.find_managed_block(content, ZSHRC_CODEX_FUNC_MARKER_BEGIN, ZSHRC_CODEX_FUNC_MARKER_END)
                if block:
                    content = marker_block.remove_managed_block(content, block)
            else:
                # Чужое определение — не трогаем (fail-closed).
                return (f"Codex zsh-функция: существует чужое определение codex alias/function — "
                        f"не трогаем (удали вручную, если хочешь использовать srouter-managed функцию).")
        # Добавить блок в конец ~/.zshrc.
        _write_text_atomic(zshrc, content.rstrip() + "\n" + _CODEX_FUNC_BLOCK + "\n")
        return f"Codex zsh-функция: установлена (codex() → {CODEX_CLI_WRAPPER_NAME})."
    except (OSError, ValueError, TypeError) as exc:
        return f"Codex zsh-функция: не установлена ({str(exc)[:60]})."


def _remove_codex_zsh_function() -> str:
    """Удалить shell-функцию codex() из ~/.zshrc (marker-gate). Idempotent."""
    try:
        zshrc = _zshrc_path()
        if not zshrc.exists():
            return "Codex zsh-функция: ~/.zshrc нет — нечего удалять."
        content = zshrc.read_text(encoding="utf-8")
        if ZSHRC_CODEX_FUNC_MARKER_BEGIN not in content:
            return "Codex zsh-функция: не была установлена."
        # Удалить блок по маркерам (marker_block.remove_managed_block).
        block = marker_block.find_managed_block(content, ZSHRC_CODEX_FUNC_MARKER_BEGIN, ZSHRC_CODEX_FUNC_MARKER_END)
        if block:
            new_content = marker_block.remove_managed_block(content, block)
        else:
            new_content = content  # блок не найден, ничего не удаляем
        _write_text_atomic(zshrc, new_content)
        return "Codex zsh-функция: удалена."
    except (OSError, ValueError, TypeError) as exc:
        return f"Codex zsh-функция: не удалена ({str(exc)[:60]})."


def _install_codex_isolation(env, runner) -> str:
    """Полная изоляция Codex через wrappers + launchctl env + zsh function + PATH.

    Вызывает все компоненты и собирает результаты в одну строку (разделитель \n).
    Best-effort: частичный успех = WARN, не fail (кроме критичных ошибок, типа код)."""
    parts = [
        _install_codex_wrappers(env),
        _install_launchctl_env(env, runner),
        _ensure_home_bin_in_path(env),
        _install_codex_zsh_function(env),
    ]
    return "\n".join(parts)


def _remove_codex_isolation(env, runner) -> str:
    """Полное удаление изоляции Codex (wrappers + env + zsh + PATH).

    Вызывает все компоненты удаления и собирает результаты. _remove_launchctl_env возвращает
    dict (ok, msg, steps), остальные — строки."""
    results = [
        _remove_codex_wrappers(),
        _remove_codex_zsh_function(),
        _remove_home_bin_from_path(),
    ]
    # _remove_launchctl_env возвращает dict.
    env_result = _remove_launchctl_env(runner)
    results.append(env_result["msg"])
    return "\n".join(results)
