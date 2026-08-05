"""User-side оркестрация защищённого Privoxy (issue #158, декомпозиция privoxy_system.py;
issue #287 — tree-copy redesign install-механизма).

Выполняется в ОСНОВНОМ процессе srouter (CLI/dashboard) — НЕ копируется в
/Library/PrivilegedHelperTools и не исполняется через sudo. В отличие от helper-дерева
(privoxy_system.py + privoxy_helper_fs.py/privoxy_helper_launchd.py/privoxy_helper_config.py:
protect_as_root/unprotect_as_root/control_as_root/helper_main и все транзитивные примитивы),
этот модуль читает/пишет local_state и вызывает root-helper через `sudo <helper_path> ...`
как subprocess — не импортом.

Архитектурный инвариант (каноны root-helper-stdlib-only, helper-stdlib-only-no-dashboard-common,
обновлены #287): helper-дерево (entrypoint privoxy_system.py + HELPER_TREE_MODULES) копируется
_install_helper'ом НИЖЕ ЦЕЛИКОМ, каждый файл — с собственным digest-pinning
(_read_helper_tree_pinned/_stage_helper_tree/_digest_fd_nofollow в privoxy_system.py) —
ФИЗИЧЕСКИ обязано оставаться в дереве, иначе ModuleNotFoundError под sudo (helper исполняется
изолированно, только stdlib в каждом файле дерева). Этот модуль, наоборот, безопасно
импортирует local_state — он не копируется никуда.

Facade-lookup (канон moving-caller-inverts-mock-ownership, тот же паттерн что
local_state_traffic_guard.py и др.): все функции здесь резолвят и helper-side примитивы
(protection_present/_port_open/_result/_now/DEFAULT_LAYOUT/...), и друг друга ЧЕРЕЗ фасад
`import privoxy_system`, `privoxy_system.status(...)` — а не прямым локальным именем. Тесты патчат
`privoxy_system.status`/`privoxy_system.protect`/`privoxy_system.DEFAULT_LAYOUT` и т.п.; если бы
`protect()` вызывал `status(...)` локальным именем внутри этого файла, патч на фасаде превратился
бы в тихий no-op (caller и callee оба переехали одновременно). Цикла импорта нет: `import
privoxy_system` только регистрирует модуль, атрибуты читаются в момент вызова функции — к тому
времени privoxy_system.py (helper payload) уже полностью инициализирован, а сам этот модуль
импортируется из privoxy_system.py в самом низу файла (после определения helper-side).
"""
import json
import os
import pwd
import shutil
import sys
import tempfile
from pathlib import Path

import privoxy_system


def status(*, runner=None, layout=None):
    """Read-only статус доступен без sudo."""
    if layout is None:
        layout = privoxy_system.DEFAULT_LAYOUT
    if runner is None:
        from sys_probe import run as runner
    result = runner([privoxy_system.LAUNCHCTL, "print",
                     privoxy_system._launchd_target(privoxy_system.SYSTEM_DOMAIN, privoxy_system.SYSTEM_LABEL)], 5)
    output = result.get("out") or ""
    loaded = result.get("rc") == 0 and bool(output.strip())
    pid = None
    raw_pid = privoxy_system._launchd_field(output, "pid") if loaded else None
    try:
        pid = int(raw_pid) if raw_pid is not None else None
    except ValueError:
        pid = None
    owner = ""
    if pid:
        ps = runner([privoxy_system.PS, "-o", "user=", "-p", str(pid)], 3)
        owner = (ps.get("out") or "").strip()
    user_shadow = runner(
        [privoxy_system.LAUNCHCTL, "print",
         privoxy_system._launchd_target(f"gui/{os.getuid()}", privoxy_system.USER_LABEL)], 5
    )
    protected_assets = (
        layout.config_dir.parent,
        layout.config_dir,
        layout.config_path,
        layout.runtime_dir,
        layout.binary_path,
        layout.launchdaemon_path,
        layout.helper_path,
        layout.helper_modules_dir,  # #287: writable modules-директория = code-execution vector
        layout.sudoers_path,
    )
    return {
        "protected": privoxy_system.protection_present(layout),
        "loaded": loaded,
        "pid": pid,
        "owner": owner,
        "state": privoxy_system._launchd_field(output, "state") if loaded else None,
        "port_up": privoxy_system._port_open(),
        "config_writable": os.access(layout.config_path, os.W_OK) if layout.config_path.exists() else None,
        "binary_writable": os.access(layout.binary_path, os.W_OK) if layout.binary_path.exists() else None,
        "assets_writable": any(path.exists() and os.access(path, os.W_OK)
                               for path in protected_assets),
        "user_shadow_loaded": user_shadow.get("rc") == 0 and bool((user_shadow.get("out") or "").strip()),
        "error": "" if loaded else (result.get("err") or "not loaded")[:240],
    }


def state_protected(state_path):
    try:
        import local_state
        state = local_state.load_state(path=state_path)
    except (OSError, ValueError, TypeError, ImportError):
        return False
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    entry = detected.get("privoxy") if isinstance(detected.get("privoxy"), dict) else {}
    protection = entry.get("protection") if isinstance(entry.get("protection"), dict) else {}
    return protection.get("service_scope") == "system" and protection.get("label") == privoxy_system.SYSTEM_LABEL


def _write_pending(state_path, previous):
    import local_state
    state, readable = local_state.load_state_checked(path=state_path)
    if not readable:
        return False
    runtime = state.get("runtime") if isinstance(state.get("runtime"), dict) else {}
    runtime["privoxy_protection_pending"] = {
        "action": "protect",
        "started_at": privoxy_system._now(),
        "previous": previous,
    }
    state["runtime"] = runtime
    return local_state.save_state(state, path=state_path) is not None


def _write_unprotect_pending(state_path):
    import local_state
    state, readable = local_state.load_state_checked(path=state_path)
    if not readable:
        return False
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    current = detected.get("privoxy") if isinstance(detected.get("privoxy"), dict) else {}
    runtime = state.get("runtime") if isinstance(state.get("runtime"), dict) else {}
    runtime["privoxy_protection_pending"] = {
        "action": "unprotect",
        "started_at": privoxy_system._now(),
        "previous": current,
    }
    state["runtime"] = runtime
    return local_state.save_state(state, path=state_path) is not None


def _mark_failed(state_path, error):
    import local_state
    state, readable = local_state.load_state_checked(path=state_path)
    if not readable:
        return
    runtime = state.get("runtime") if isinstance(state.get("runtime"), dict) else {}
    pending = runtime.get("privoxy_protection_pending")
    if isinstance(pending, dict):
        pending["failed_at"] = privoxy_system._now()
        pending["error"] = error
    runtime["last_error"] = error
    state["runtime"] = runtime
    local_state.save_state(state, path=state_path)


def _promote_state(state_path, *, backup_dir, layout=None):
    if layout is None:
        layout = privoxy_system.DEFAULT_LAYOUT
    import local_state
    state, readable = local_state.load_state_checked(path=state_path)
    if not readable:
        return False
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    previous = detected.get("privoxy") if isinstance(detected.get("privoxy"), dict) else {}
    runtime = state.get("runtime") if isinstance(state.get("runtime"), dict) else {}
    pending = runtime.get("privoxy_protection_pending")
    if isinstance(pending, dict) and isinstance(pending.get("previous"), dict):
        previous = pending["previous"]
    detected["privoxy"] = {
        "config_path": str(layout.config_path),
        "port": privoxy_system._PRIVOXY_PORT,
        "service": "protected-system",
        "management": {"mode": "managed", "managed": True, "provenance": "protected"},
        "protection": {
            "version": privoxy_system.PROTECTION_VERSION,
            "mode": "strict",
            "service_scope": "system",
            "label": privoxy_system.SYSTEM_LABEL,
            "backup_dir": backup_dir,
            "previous": previous,
            "activated_at": privoxy_system._now(),
        },
    }
    detected["last_checked_at"] = privoxy_system._now()
    state["detected_environment"] = detected
    runtime.pop("privoxy_protection_pending", None)
    runtime["last_apply"] = privoxy_system._now()
    runtime["last_error"] = None
    state["runtime"] = runtime
    return local_state.save_state(state, path=state_path) is not None


def _restore_state_after_unprotect(state_path):
    import local_state
    state, readable = local_state.load_state_checked(path=state_path)
    if not readable:
        return False
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    entry = detected.get("privoxy") if isinstance(detected.get("privoxy"), dict) else {}
    protection = entry.get("protection") if isinstance(entry.get("protection"), dict) else {}
    previous = protection.get("previous") if isinstance(protection.get("previous"), dict) else None
    detected["privoxy"] = previous
    detected["last_checked_at"] = privoxy_system._now()
    state["detected_environment"] = detected
    runtime = state.get("runtime") if isinstance(state.get("runtime"), dict) else {}
    runtime.pop("privoxy_protection_pending", None)
    runtime["last_apply"] = privoxy_system._now()
    runtime["last_error"] = None
    state["runtime"] = runtime
    return local_state.save_state(state, path=state_path) is not None


def _parse_helper_output(result):
    for line in reversed((result.get("out") or "").splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and "ok" in value:
            return value
    return privoxy_system._result(False, error=(result.get("err") or result.get("out") or "helper_failed")[:240])


def _sudo_reset(runner):
    return runner([privoxy_system.SUDO, "-k"], 5)


def _install_helper(runner, layout=None):
    """Установка root-owned helper-ДЕРЕВА через fd-pinning + per-file post-install digest
    (issue #287, tree-copy redesign — заменяет прежний однофайловый install #148 variant 3).

    Прежний код (single-file) проверял marker на __file__ и звал `sudo install __file__ dst` —
    /usr/bin/install ПОВТОРНО открывал тот же pathname под sudo (TOCTOU: атакующий подменял
    файл во время password-prompt). Фикс #148: honest-read через O_NOFOLLOW → staged temp →
    `sudo install staged dst` (staged, не __file__) → post-install digest-check.

    Tree-copy (#287) расширяет ТОТ ЖЕ паттерн на N файлов (entrypoint + HELPER_TREE_MODULES),
    сохраняя все инварианты #148 на КАЖДЫЙ файл, плюс атомарность публикации ВСЕГО дерева:

    (1) _read_helper_tree_pinned читает entrypoint+модули из Path(__file__).parent ОДНИМ
        fd на файл (O_NOFOLLOW) — marker (только в entrypoint) и per-file digest на bytes
        того же fd, TOCTOU-окна между проверкой и использованием нет ни для одного файла.
    (2) _stage_helper_tree пишет все N файлов в staged root (user-owned в окне — см. (5)).
    (3) Установка в ПРОМЕЖУТОЧНЫЕ *.new-пути (не финальные) через N раздельных `sudo install`:
        entrypoint → helper_path.new, каждый модуль → helper_modules_dir.new/<name>. Финальные
        пути НЕ трогаются на этом шаге — работающий (если есть) helper остаётся нетронутым,
        пока новое дерево не полностью проверено.
    (4) post-install digest-check КАЖДОГО установленного *.new-файла против expected-digest
        честно прочитанных bytes (шаг 1). ЛЮБОЕ расхождение → fail-closed: cleanup всех *.new
        путей, ни один частично установленный/подменённый файл не публикуется как финальный.
    (5) ТОЛЬКО если ВСЕ digest сошлись — публикация: один `sudo mv -f` modules.new →
        helper_modules_dir (atomic rename заменяет старую директорию модулей целиком), затем
        один `sudo mv -f` helper_path.new → helper_path (atomic rename файла). Между этими
        двумя rename есть короткое окно, где entrypoint и modules могут временно не совпадать
        по версии при аварийном обрыве процесса ровно между ними — это НЕ security-регрессия
        (оба rename делает тот же доверенный root-процесс install, не attacker-controlled шаг;
        следующий protect() переустановит дерево заново с нуля). Атака была бы возможна только
        если бы attacker мог вклиниться МЕЖДУ digest-check и install — но post-install digest
        проверяет уже установленный *.new-файл, а не kernel-level промежуточное состояние.

    ВАЖНО (#148 variant 3, унаследовано): staged создаётся в user-процессе `protect()` (НЕ
    root) → mkstemp/mkdtemp дают user-owned объекты, staged user-owned/writable в окне
    [staging .. sudo install]. Подмена ЛЮБОГО файла в этом окне ловится post-install digest
    (шаг 4) — install копирует staged байт-в-байт в root-owned *.new, digest *.new сравнивается
    с digest честно прочитанного оригинала. Race-тесты
    test_install_helper_fail_closed_when_staged_substituted_after_mkstemp (single-file
    наследие) и test_install_helper_fail_closed_when_staged_tree_file_substituted_after_stage
    (#287, multi-file) фиксируют инвариант.
    """
    if layout is None:
        layout = privoxy_system.DEFAULT_LAYOUT
    # (1) marker (entrypoint) + per-file expected-digest на bytes зафиксированных fd.
    tree = privoxy_system._read_helper_tree_pinned()
    if tree is None:
        return privoxy_system._result(False, error="helper_source_marker_missing")
    # foreign-helper guard: helper_path — target (root-owned), path-based допустимо,
    # но читаем через O_NOFOLLOW для консистентности.
    if layout.helper_path.exists() and not privoxy_system._helper_tree_has_marker_fd(layout.helper_path):
        return privoxy_system._result(False, error="foreign_privileged_helper")
    parent = runner([privoxy_system.SUDO, privoxy_system.MKDIR, "-p", str(layout.helper_path.parent)], 30)
    if parent.get("rc") != 0:
        return privoxy_system._result(False, error=(parent.get("err") or "helper_parent_failed")[:240])
    # (2): зафиксированные digest-проверенные bytes всего дерева в staged root.
    staged_root = privoxy_system._stage_helper_tree(tree)
    if staged_root is None:
        return privoxy_system._result(False, error="helper_stage_failed")

    entry_name = next(name for name in tree if name not in privoxy_system.HELPER_TREE_MODULES)
    modules_new = layout.helper_modules_dir.with_name(f"{layout.helper_modules_dir.name}.new")
    entry_new = layout.helper_path.with_name(f"{layout.helper_path.name}.new")
    new_paths_to_cleanup = [entry_new, modules_new]
    try:
        # (3) установка в ПРОМЕЖУТОЧНЫЕ *.new-пути — финальные пути не трогаются, пока
        # дерево не проверено целиком (см. (5) про атомарную публикацию).
        # Сносим остатки прерванного прошлого прогона ДО mkdir: `mkdir -p` молча успешен на
        # существующей директории, а install перезаписывает лишь файлы текущего дерева. Любой
        # посторонний файл в .modules.new пережил бы install и въехал внутрь опубликованного
        # root-owned дерева (публикация — rename директории целиком), не попав ни под один
        # digest-чек. Дерево пинится целиком → стартуем всегда с чистого листа.
        _cleanup_new_paths(runner, new_paths_to_cleanup)
        # `install -d -m 0755 -o root -g wheel`, а НЕ `mkdir -p`: mkdir не задаёт режим и отдаёт
        # его ambient umask root'а. Это единственная директория, из которой helper_main делает
        # sys.path.insert + import под sudo, причём БЕЗ повторной digest-проверки в runtime
        # (digest-pinning закрывает только момент install) — writable modules dir = arbitrary
        # root code execution уже после того, как все fd-pinning/digest-чеки прошли.
        # install -d ставит режим атомарно при создании, без окна mkdir→chmod.
        mkdir_new = runner(
            [privoxy_system.SUDO, privoxy_system.INSTALL, "-d", "-o", "root", "-g", "wheel",
             "-m", "0755", str(modules_new)],
            30,
        )
        if mkdir_new.get("rc") != 0:
            return privoxy_system._result(False, error=(mkdir_new.get("err") or "helper_modules_new_mkdir_failed")[:240])
        installed_digests = {}
        for name, (_, expected_digest) in tree.items():
            is_entry = name == entry_name
            source = staged_root / name if is_entry else staged_root / "modules" / name
            target = entry_new if is_entry else modules_new / name
            mode = "0755" if is_entry else "0644"
            installed = runner(
                [privoxy_system.SUDO, privoxy_system.INSTALL, "-o", "root", "-g", "wheel", "-m", mode,
                 str(source), str(target)],
                30,
            )
            if installed.get("rc") != 0:
                _cleanup_new_paths(runner, new_paths_to_cleanup)
                return privoxy_system._result(False, error=(installed.get("err") or "helper_install_failed")[:240])
            # (4) post-install digest-check ЭТОГО файла — до перехода к следующему, чтобы не
            # тратить время на install остальных файлов дерева при первом же расхождении.
            installed_digest = privoxy_system._digest_fd_nofollow(target)
            if installed_digest is None or installed_digest != expected_digest:
                _cleanup_new_paths(runner, new_paths_to_cleanup)
                return privoxy_system._result(False, error="helper_digest_mismatch")
            installed_digests[name] = installed_digest

        # (5) все digest сошлись — атомарная публикация: modules first (rename заменяет
        # старую директорию целиком), затем entrypoint (rename заменяет старый файл).
        publish_modules = runner([privoxy_system.SUDO, "/bin/mv", "-f", str(modules_new), str(layout.helper_modules_dir)], 30)
        if publish_modules.get("rc") != 0:
            _cleanup_new_paths(runner, new_paths_to_cleanup)
            return privoxy_system._result(False, error=(publish_modules.get("err") or "helper_modules_publish_failed")[:240])
        publish_entry = runner([privoxy_system.SUDO, "/bin/mv", "-f", str(entry_new), str(layout.helper_path)], 30)
        if publish_entry.get("rc") != 0:
            _cleanup_new_paths(runner, [entry_new])
            return privoxy_system._result(False, error=(publish_entry.get("err") or "helper_entry_publish_failed")[:240])
        return privoxy_system._result(True)
    finally:
        try:
            shutil.rmtree(staged_root, ignore_errors=True)
        except OSError:
            pass


def _cleanup_new_paths(runner, paths):
    """Best-effort удаление промежуточных *.new-путей (fail-closed cleanup, tree install)."""
    for path in paths:
        try:
            runner([privoxy_system.SUDO, "/bin/rm", "-rf", "--", str(path)], 15)
        except Exception:  # noqa: BLE001 — cleanup не должен маскировать основную ошибку.
            pass


def _remove_via_runner(runner, path):
    """Best-effort удаление скомпрометированного helper (fail-closed cleanup)."""
    try:
        runner([privoxy_system.SUDO, "/bin/rm", "-f", "--", str(path)], 15)
    except Exception:  # noqa: BLE001 — cleanup не должен маскировать основную ошибку.
        pass


def _rollback_protection(runner, layout=None):
    if layout is None:
        layout = privoxy_system.DEFAULT_LAYOUT
    privoxy_system._sudo_reset(runner)
    rollback = runner([privoxy_system.SUDO, str(layout.helper_path), "unprotect", "--restore"], 90)
    privoxy_system._sudo_reset(runner)
    return privoxy_system._parse_helper_output(rollback)


def protect(*, state_path, prefix="/opt/homebrew", runner=None, require_tty=True,
            layout=None, debug=None):
    if layout is None:
        layout = privoxy_system.DEFAULT_LAYOUT
    if runner is None:
        from sys_probe import run as runner
    if require_tty and not sys.stdin.isatty():
        return privoxy_system._result(False, error="interactive_terminal_required")
    # #152: уровень privoxy-логирования. По умолчанию (None) — из SROUTER_PRIVOXY_DEBUG (privacy:
    # 0 если env не задан). Явный аргумент переопределяет env (для тестов/programmatic-call).
    if debug is None:
        debug = privoxy_system._privoxy_debug_from_env()
    current = privoxy_system.status(runner=runner, layout=layout)
    secure = (
        current["protected"]
        and current["loaded"]
        and current["port_up"]
        and current["owner"] == "nobody"
        and current["config_writable"] is False
        and current["binary_writable"] is False
        and current["assets_writable"] is False
        and not current["user_shadow_loaded"]
    )
    if secure:
        if not privoxy_system.state_protected(state_path):
            manifest = privoxy_system._load_manifest(layout) or {}
            if not privoxy_system._promote_state(state_path, backup_dir=manifest.get("backup_dir", ""), layout=layout):
                return privoxy_system._result(False, error="state_repair_failed", status=current)
            return privoxy_system._result(True, changed=True, repaired_state=True, status=current)
        return privoxy_system._result(True, changed=False, status=current)

    import local_state
    state, readable = local_state.load_state_checked(path=state_path)
    if not readable:
        return privoxy_system._result(False, error="state_unreadable")
    detected = state.get("detected_environment") if isinstance(state.get("detected_environment"), dict) else {}
    previous = detected.get("privoxy") if isinstance(detected.get("privoxy"), dict) else {}
    if not privoxy_system._write_pending(state_path, previous):
        return privoxy_system._result(False, error="pending_state_write_failed")

    staged_dir = Path(tempfile.mkdtemp(prefix="srouter-privoxy-protect-", dir="/private/tmp"))
    staged_config = staged_dir / "config"
    try:
        os.chmod(staged_dir, 0o700)
        staged_config.write_text(privoxy_system.protected_config_text(layout, debug=debug), encoding="utf-8")
        os.chmod(staged_config, 0o600)
        privoxy_system._sudo_reset(runner)
        installed = privoxy_system._install_helper(runner, layout)
        if not installed["ok"]:
            privoxy_system._mark_failed(state_path, installed["error"])
            return installed
        invoked = runner(
            [privoxy_system.SUDO, str(layout.helper_path), "protect",
             "--username", pwd.getpwuid(os.getuid()).pw_name,
             "--uid", str(os.getuid()),
             "--prefix", str(prefix),
             "--config", str(staged_config),
             "--debug", str(debug)],
            120,
        )
        outcome = privoxy_system._parse_helper_output(invoked)
        privoxy_system._sudo_reset(runner)
        if not outcome["ok"]:
            privoxy_system._mark_failed(state_path, outcome["error"])
            return outcome

        no_cache = runner([privoxy_system.SUDO, "-n", str(layout.helper_path), "status"], 10)
        if no_cache.get("rc") == 0:
            detail = privoxy_system._rollback_protection(runner, layout)
            error = "sudo_without_fresh_authorization"
            if not detail.get("ok"):
                error += f"; rollback_failed:{detail.get('error')}"
            privoxy_system._mark_failed(state_path, error)
            return privoxy_system._result(False, error=error)

        current = privoxy_system.status(runner=runner, layout=layout)
        if not (current["protected"] and current["loaded"] and current["port_up"]
                and current["owner"] == "nobody" and current["config_writable"] is False
                and current["binary_writable"] is False and current["assets_writable"] is False
                and not current["user_shadow_loaded"]):
            rollback_result = privoxy_system._rollback_protection(runner, layout)
            error = "post_protect_verification_failed"
            if not rollback_result.get("ok"):
                error += f"; rollback_failed:{rollback_result.get('error')}"
            privoxy_system._mark_failed(state_path, error)
            return privoxy_system._result(False, error=error, status=current)
        if not privoxy_system._promote_state(state_path, backup_dir=outcome.get("backup_dir", ""), layout=layout):
            # Файлы/служба уже применены, но active-state не зафиксирован — это не success.
            # Откатываем той же whitelisted root-операцией и оставляем pending с причиной.
            rollback_result = privoxy_system._rollback_protection(runner, layout)
            privoxy_system._mark_failed(state_path, "state_promote_failed")
            return privoxy_system._result(
                False,
                error=("state_promote_failed" if rollback_result.get("ok")
                       else f"state_promote_failed; rollback_failed:{rollback_result.get('error')}"),
                status=current,
            )
        return privoxy_system._result(True, changed=True, status=current, backup_dir=outcome.get("backup_dir", ""))
    finally:
        shutil.rmtree(staged_dir, ignore_errors=True)


def control(action, *, runner=None, require_tty=True, layout=None):
    if layout is None:
        layout = privoxy_system.DEFAULT_LAYOUT
    if action not in {"start", "stop", "restart"}:
        return privoxy_system._result(False, error="action_not_allowed")
    if runner is None:
        from sys_probe import run as runner
    if require_tty and not sys.stdin.isatty():
        return privoxy_system._result(False, error="interactive_terminal_required")
    if not privoxy_system.protection_present(layout):
        return privoxy_system._result(False, error="protected_service_not_installed")
    privoxy_system._sudo_reset(runner)
    invoked = runner([privoxy_system.SUDO, str(layout.helper_path), action], 90)
    privoxy_system._sudo_reset(runner)
    outcome = privoxy_system._parse_helper_output(invoked)
    outcome["status"] = privoxy_system.status(runner=runner, layout=layout)
    return outcome


def unprotect(*, state_path, restore=True, runner=None, require_tty=True, layout=None):
    if layout is None:
        layout = privoxy_system.DEFAULT_LAYOUT
    if runner is None:
        from sys_probe import run as runner
    if require_tty and not sys.stdin.isatty():
        return privoxy_system._result(False, error="interactive_terminal_required")
    if not privoxy_system.protection_present(layout):
        return privoxy_system._result(True, changed=False)
    if not privoxy_system._write_unprotect_pending(state_path):
        return privoxy_system._result(False, error="pending_state_write_failed")
    privoxy_system._sudo_reset(runner)
    cmd = [privoxy_system.SUDO, str(layout.helper_path), "unprotect"]
    if restore:
        cmd.append("--restore")
    invoked = runner(cmd, 90)
    outcome = privoxy_system._parse_helper_output(invoked)
    privoxy_system._sudo_reset(runner)
    if not outcome["ok"]:
        privoxy_system._mark_failed(state_path, outcome["error"])
        return outcome
    if not privoxy_system._restore_state_after_unprotect(state_path):
        return privoxy_system._result(False, error="state_restore_failed")
    return privoxy_system._result(True, changed=True, restored=outcome.get("restored", False))
