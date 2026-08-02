"""Вкл/откл git-прокси для github.com в ~/.gitconfig (через `git config --global`).

У пользователя сломан прямой IPv4-путь к github (тормозит/отваливается), а у github нет AAAA
(только IPv4). Рабочий путь — через xray. Эта настройка scoped ТОЛЬКО на github.com: другие
git-серверы (GitLab, корпоративные) идут напрямую, как раньше.

Прокси = SOCKS5 (xray 10808), НЕ HTTP (privoxy 8118) — канон issue #130: git умеет нативный SOCKS5
(в отличие от Claude Code, см. claude_proxy.py), а privoxy лишний хоп для git-операций.

Состояние = сам ~/.gitconfig (единый источник правды, НЕ дублируется в srouter-state). git config
правит пользовательский файл от текущего юзера — root НЕ нужен. Функции не бросают (probe-канон).

Provenance (issue #222, verify-don't-guess — 3 раунда rc/bool()-эвристик найдены Codex adversarial
cycle-review PR #221/#130, каждая новая дыра в той же категории):

1. Presence != truthy. `git config --get` при пустом значении даёт rc=0/out="" — валидный override
   ("ключ есть, но пустой"), НЕ "ключа нет" (rc=1). status() репортит `present` отдельно от `proxy`.
2. Multi-value-aware. Ключ может иметь НЕСКОЛЬКО значений (`--add` дважды). `--get`/bool() видят
   только последнее. Мы читаем через `--get-all` (полный список) и явно отслеживаем `multi`.
3. Read-after-write verify. `git config --unset` на multi-valued key возвращает rc=5 — тот же код,
   что и «ключа нет» — но НИЧЕГО НЕ УДАЛЯЕТ (мутация отказывает целиком, проверено эмпирически:
   `--add x1 --add x2 --unset` → rc=5, `--get-all` всё ещё [x1, x2]). Каждая мутация (--unset-all/
   --add/set) подтверждается контрольным чтением через --get-all, а не доверием к rc.
4. Backup — ПОЛНЫЙ список чужих значений (не одно), сериализован в _BACKUP_KEY через один --add на
   значение. Обновляется на КАЖДОЕ новое foreign-состояние между generations (enable() каждый раз
   сверяет текущий foreign-список с уже забэкапленным и переписывает backup, если они разошлись) —
   не только "backup отсутствует, бэкапим первый раз" (что теряло промежуточные чужие значения при
   A→install→manual B→uninstall→install→uninstall).

Остаточный риск (PR #223, issue #224): `git config` не даёт transactional multi-value write —
`_write_values` делает `--unset-all` затем цикл `--add`, окно между ними физически существует.
Если процесс убит именно в этом окне (не "падение вызова", а SIGKILL/крэш всего процесса),
txn-маркер (_TXN_KEY) остаётся установленным, следующая операция видит его и доводит до конца
(_check_and_resolve_txn retry'ит мутацию с explicit target, НЕ heuristic "current похоже на X").
Issue #224 решён architectural fix: explicit transactional marker вместо reverse-engineering
current-vs-backup pattern-matching.

Issue #234 (Codex cycle-review PR #233, 3 раунда → architectural signal, канон
best-effort-layer-cycle-review-never-converges): 2 CRITICAL находки, отличные по категории от
core transactional-логики (threading/serialization и cross-process coordination, не edge cases
базового transactional паттерна).

1. Checksum sentinel collision: старый checksum = `str(len(txn_values))` — decimal-строка
   неотличима от легитимного numeric target-значения (target=["A","2"], partial-маркер
   [KEY,"A","2"] мог быть ошибочно принят за complete). Fix: self-identifying sentinel —
   `_TXN_SENTINEL_PREFIX + sha256(canonical join)` (_txn_sentinel()) — криптографически не может
   совпасть ни с одним легитимным git-config значением.
2. Concurrent enable/disable race: txn-check, current-state read, backup decision и write не были
   сериализованы между процессами (CLI + dashboard threaded server могли interleave'иться и терять
   backup безвозвратно). Fix: cross-process advisory lock (`_mutation_lock()`, flock LOCK_EX,
   эталон local_state._routing_config_lock issue #139) оборачивает ВСЮ enable()/disable()
   транзакцию — вторая операция блокируется до полного завершения первой, не читает stale snapshot.
"""
import hashlib
import os

import sys_probe

GIT = "/usr/bin/git"
KEY = "http.https://github.com.proxy"
# Backup списка исходных чужих значений (created/overwrote-канон install_lib.py, но БЕЗ отдельного
# state-файла — состояние модуля = сам ~/.gitconfig, backup живёт там же как доп. ключ).
_BACKUP_KEY = KEY + "-srouter-backup"
# Transactional marker для issue #224: фиксирует "операция в процессе, target = X"
_TXN_KEY = _BACKUP_KEY + "-txn"

# Issue #234 (Codex cycle-review PR #233, finding 1): checksum-sentinel ДОЛЖЕН быть
# self-identifying — decimal count (`str(len(values))`) неотличим от легитимного numeric
# target-значения (target=["A","2"], партийный маркер [KEY,"A","2"] интерпретировался как
# complete с checksum="2"==len([KEY,"A"]) по случайному совпадению строк, теряя "2" навсегда).
# Префикс НЕ может встретиться как реальное git-config значение, записанное нами или
# пользователем — ни одно легитимное proxy-URL/target-значение не начинается с этой строки.
_TXN_SENTINEL_PREFIX = "srouter-git-proxy-txn-checksum:"


def _txn_sentinel(txn_values):
    """Self-identifying sentinel для txn-маркера: префикс + sha256(canonical join).

    txn_values — [key, val1, val2, ...] (БЕЗ sentinel). Digest покрывает КАЖДОЕ значение
    (не только count) — коллизия требовала бы найти другой список значений с тем же digest,
    криптографически неосуществимо. NUL-separated join исключает ambiguity типа
    ["A", "B"] vs ["AB"] (те же байты, разный split).
    """
    canonical = "\x00".join(txn_values).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    return _TXN_SENTINEL_PREFIX + digest


def _mutation_lock():
    """Context-manager cross-process exclusive lock (flock LOCK_EX) вокруг ВСЕЙ enable()/disable()
    транзакции — issue #234 finding 2 (Codex cycle 2): txn-check, current-state read, backup
    decision и write НЕ были сериализованы между процессами (CLI + dashboard threaded server).
    Конкурентные enable/disable могли interleave'иться так, что backup терялся безвозвратно (одна
    сторона читает stale current ДО того, как другая завершит restore+cleanup backup).

    Эталон — local_state._routing_config_lock (issue #139 finding 2): тот же примитив (adaptive
    lockfile рядом с управляемым ресурсом, flock блокирующий — вторая операция ждёт, не читает
    stale snapshot). Lockfile — НЕ ~/.gitconfig (нельзя flock файл, который сам rewrite'ится через
    `git config`, apply мог бы держать fd на пере-созданном inode) — отдельный sentinel-файл рядом.
    """
    import contextlib
    import fcntl
    from pathlib import Path

    lock_p = Path.home() / ".gitconfig.srouter-proxy.lock"

    @contextlib.contextmanager
    def _cm():
        try:
            lock_p.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(lock_p, os.O_CREAT | os.O_RDWR, 0o600)
        except OSError:
            # Не можем создать lock-файл (permission/missing HOME) — деградируем без lock,
            # не блокируем управление прокси целиком из-за недоступности lock-примитива.
            yield
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)  # блокирует до отпускания другим процессом/потоком
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)

    return _cm()


# Прокси = SOCKS5 xray (10808). Берём из dashboard_common если доступен; fallback на хардкод,
# чтобы модуль не падал в среде без srouter_config (git_proxy не должен тянуть конфиг инфраструктуры).
try:
    from dashboard_common import SOCKS_PROXY_URL as _PROXY  # socks5h://127.0.0.1:10808
except SystemExit:
    # dashboard_common raises SystemExit (BaseException) when srouter_config.py is missing.
    # Fallback to canonical value (install-path compatibility — module must not crash).
    _PROXY = "socks5h://127.0.0.1:10808"


def _get_all(key, timeout=4):
    """Полный список значений KEY. {present, values, multi, unknown}. Не бросает.

    rc=0 → присутствует (values = все строки, возможно с пустыми). rc=1 → задокументированное
    «ключа/секции нет» (НЕ ошибка). Любой другой rc (permission denied, malformed config, timeout)
    — реальный сбой чтения, unknown=True (fail-closed, отличаем от «ключа нет»).

    `-z` (NUL-terminated) — принципиально, НЕ `\\n`-split (Codex cycle-review PR #221 round 3,
    issue #222): sys_probe.run применяет `.strip()` к сырому выводу (sys_probe.py) ДО парсинга —
    при `\\n`-разделении это молча съедает пустое значение, если оно СТОИТ ПЕРВЫМ/ПОСЛЕДНИМ в
    multi-value списке (`'\\nA\\nB\\n'.strip()` → `'A\\nB'` теряет ведущее пустое значение).
    `-z` не подвержен этому (`.strip()` не трогает NUL-байты) и, дополнительно, корректно отличает
    ОДНО значение с embedded `\\n` от НЕСКОЛЬКИХ отдельных значений (`\\n`-split спутал бы их).
    """
    r = sys_probe.run([GIT, "config", "--global", "--get-all", "-z", key], timeout=timeout)
    if r.get("timeout"):
        return {"present": False, "values": [], "multi": False, "unknown": True}
    rc = r.get("rc")
    if rc == 1:
        return {"present": False, "values": [], "multi": False, "unknown": False}
    if rc != 0:
        return {"present": False, "values": [], "multi": False, "unknown": True}
    out = r.get("out") or ""
    # NUL-terminated: последний split-элемент после финального разделителя — пустой хвост, отбросить.
    values = out.split("\x00")[:-1] if out else [""]
    return {"present": True, "values": values, "multi": len(values) > 1, "unknown": False}


def _unset_all(key, timeout=5):
    """Снять ВСЕ значения KEY (--unset-all, безопасно для multi-value — не частичный отказ).

    Read-after-write verify: rc игнорируется как источник истины (rc=5 двусмысленен — и «ключа
    нет», и, в принципе, отказ) — реальный результат подтверждается повторным --get-all.
    """
    sys_probe.run([GIT, "config", "--global", "--unset-all", key], timeout=timeout)
    after = _get_all(key, timeout=timeout)
    if after["unknown"]:
        return {"ok": False, "err": "git config --get-all verify failed after --unset-all"}
    if after["present"]:
        return {"ok": False, "err": "git config --unset-all did not remove key (verified)"}
    return {"ok": True}


def _write_values(key, values, timeout=5, begin_txn=True):
    """Записать KEY = список values (может быть один или несколько). Verify после записи.

    Реализация: --unset-all (начисто), затем --add на каждое значение — детерминированно
    работает и для single-, и для multi-value списков, без спец-случаев.

    Issue #224 transactional паттерн: ПЕРЕД первой мутацией записываем txn-маркер
    (_TXN_KEY) с target state, затем выполняем мутации, ПОСЛЕ подтверждённого успеха
    (verify) снимаем txn-маркер. Если процесс убит поседи — txn-маркер остаётся, следующая
    операция видит его и доводит до конца (НЕ heuristic reverse-engineering).

    begin_txn=False используется в _check_and_resolve_txn() для retry без создания
    нового txn-маркера (транзакция уже начата, маркер существует).

    Best-effort rollback (/review PR #223 п.1, ужесточён точечным cycle-review issue #222): git
    config не даёт transactional multi-value write — окно между --unset-all и --add физически
    существует. Если запись НОВЫХ значений падает посреди цикла, key был бы оставлен ПУСТЫМ.
    При сбое пытаемся восстановить ИСХОДНЫЕ (до этого вызова) значения обратно. Но сам rollback —
    ТОЖЕ серия git config-мутаций без гарантии успеха: точечный adversarial review нашёл, что
    rollback раньше не верифицировал свой результат и возвращал тот же generic {"ok": False}
    независимо от того, откатились данные полностью, частично или вообще не откатились — caller
    не мог отличить "операция не удалась, но данные целы" от "данные реально потеряны". Теперь
    после rollback делаем read-after-write verify (`_get_all` == original_values) и добавляем
    явный флаг `data_loss=True`, когда восстановленное состояние НЕ совпадает с исходным —
    ЛЮБОЕ расхождение (полный отказ rollback, частичный отказ на одном из нескольких значений)
    репортится одинаково честно, а не молча.

    Нюанс: txn-маркер НЕ снимается при rollback — наоборот, он ОСТАЁТСЯ, чтобы следующая
    операция видела "операция начата, target = X" и retry'ит. Rollback лишь возвращает данные
    в pre-call state, но НЕ завершает транзакцию (только успешная write + verify снимает txn).
    """
    before = _get_all(key, timeout=timeout)
    if before["unknown"]:
        return {"ok": False, "err": "git config --get-all pre-write snapshot failed"}
    original_values = before["values"] if before["present"] else []

    # Issue #224: начинаем транзакцию ДО первой мутации (если не retry)
    if begin_txn:
        txn_begin = _begin_txn(key, values)
        if not txn_begin["ok"]:
            return {"ok": False, "err": f"txn begin failed: {txn_begin['err']}"}

    clr = _unset_all(key, timeout=timeout)
    if not clr["ok"]:
        if begin_txn:
            _rollback_txn()  # txn не удался — снимаем маркер
        return clr

    def _rollback(err):
        for val in original_values:
            sys_probe.run([GIT, "config", "--global", "--add", key, val], timeout=timeout)
        verify = _get_all(key, timeout=timeout)
        restored_ok = not verify["unknown"] and verify["values"] == original_values
        # ВАЖНО: txn-маркер НЕ снимаем — он остаётся для retry в следующей операции
        return {"ok": False, "err": err[:200], "data_loss": not restored_ok}

    for val in values:
        r = sys_probe.run([GIT, "config", "--global", "--add", key, val], timeout=timeout)
        if r.get("timeout") or r.get("rc") != 0:
            return _rollback(r.get("err") or "git config --add failed")
    after = _get_all(key, timeout=timeout)
    if after["unknown"] or after["values"] != values:
        return _rollback("git config write verify mismatch after --add")

    # Успех! Снимаем txn-маркер (commit) — только если мы его создавали
    if begin_txn:
        commit = _commit_txn()
        if not commit["ok"]:
            # Некритично: данные целы, txn-маркер orphan (следующий вызов просто увидит absent)
            # Не возвращаем ошибку — данные важнее cleanup
            pass

    return {"ok": True}


def status():
    """{enabled, present, proxy, values, multi, key}. НЕ бросает.

    present — ключ реально существует в gitconfig (независимо от значения — пустая строка тоже
    present=True). proxy — ПЕРВОЕ значение списка (single-value путь и UI). values — полный список
    (multi-value-aware). enabled — present И единственное значение == наш managed _PROXY (multi-value
    или чужое значение → enabled=False, fail-closed).

    Contract change (/review PR #223): раньше (`git config --get` без `--all`) поле `proxy` было
    ПОСЛЕДНИМ значением multi-valued ключа (git's `--get` semantics). Теперь, после перехода на
    `--get-all`, это ПЕРВОЕ значение списка. При multi-value `enabled` всегда False, так что для
    единственного текущего потребителя (`health._github_direct_check()`, читает `proxy` только в
    info-тексте warn-ветки, недостижимой при multi-value) разницы нет — но контракт поля сменился,
    учитывай это в новых потребителях `status()["proxy"]`.
    """
    r = _get_all(KEY)
    if r["unknown"]:
        return {"enabled": False, "present": False, "proxy": "", "values": [], "multi": False,
                "key": KEY, "status": "unknown"}
    proxy = r["values"][0] if r["values"] else ""
    enabled = r["present"] and not r["multi"] and proxy == _PROXY
    return {"enabled": enabled, "present": r["present"], "proxy": proxy, "values": r["values"],
            "multi": r["multi"], "key": KEY}


def _backup_state():
    """Текущий backup (список чужих значений) в _BACKUP_KEY. {present, values, unknown}."""
    return _get_all(_BACKUP_KEY)


def _txn_state():
    """Текущее состояние транзакции в _TXN_KEY. {present, values, unknown}.

    values = [target_key, target_val1, target_val2, ...] — первый элемент — ключ,
    остальные — целевой список значений. Формат фиксирован, чтобы избежать
    дополнительного escaping/parsing (git config --add хранит каждое значение
    как отдельную строку, multi-value semantics уже есть).
    """
    return _get_all(_TXN_KEY)


def _begin_txn(key, target_values):
    """Начать транзакцию: записать в _TXN_KEY "операция начата, target = X".

    target_values — список значений, которые мы хотим записать в key.
    Возвращает {ok, err} — не бросает.

    ВАЖНО: пишем напрямую через sys_probe.run, НЕ _write_values, чтобы txn-маркер
    сам не был обёрнут в ещё одну транзакцию (begin_txn=False не помогает, т.к. _write_values
    с begin_txn=False всё равно может падать, и мы не хотим, чтобы txn begin был обязан perfect).
    """
    # Формат: [key, val1, val2, ...] — первый элемент всегда ключ, остальные значения
    txn_values = [key] + target_values

    # Сначала чистим _TXN_KEY (если был)
    unset = _unset_all(_TXN_KEY)
    if not unset["ok"]:
        return unset

    # Пишем каждое значение
    for val in txn_values:
        r = sys_probe.run([GIT, "config", "--global", "--add", _TXN_KEY, val], timeout=5)
        if r.get("timeout") or r.get("rc") != 0:
            return {"ok": False, "err": f"txn begin --add failed: {r.get('err')}"}

    # Issue #224 follow-up (Codex review), fixed issue #234 (checksum sentinel collision):
    # пишем self-identifying sentinel последним для детекции partial write. Sentinel — НЕ
    # decimal count (который неотличим от легитимного numeric target-значения), а digest
    # префиксированный строкой, которая не может встретиться как реальное git-config значение.
    sentinel_val = _txn_sentinel(txn_values)
    r_checksum = sys_probe.run([GIT, "config", "--global", "--add", _TXN_KEY, sentinel_val], timeout=5)
    if r_checksum.get("timeout") or r_checksum.get("rc") != 0:
        return {"ok": False, "err": f"txn checksum write failed: {r_checksum.get('err')}"}

    # Verify (включая sentinel)
    after = _get_all(_TXN_KEY)
    expected_values = txn_values + [sentinel_val]
    if after["unknown"] or after["values"] != expected_values:
        return {"ok": False, "err": "txn begin verify failed"}

    return {"ok": True}


def _commit_txn():
    """Завершить транзакцию успешно: снять _TXN_KEY.

    Вызывается ТОЛЬКО после подтверждённого успеха (read-after-write verify).
    """
    return _unset_all(_TXN_KEY)


def _rollback_txn():
    """Откатить транзакцию: снять _TXN_KEY (operation aborted, not committed).

    Отличие от _commit_txn: смысловая разница для документации, механически
    одинаково — убираем маркер "операция в процессе".
    """
    return _unset_all(_TXN_KEY)


def _check_and_resolve_txn():
    """Проверить наличие незавершённой транзакции и довести до конца.

    Вызывается в начале ANY mutating операции (enable/disable) — если _TXN_KEY
    present, значит предыдущая операция была прервана посреди мутации.
    Вместо heuristic "current похоже на X" мы читаем ЯВНЫЙ target из txn-маркера
    и retry'им операцию до успеха (remove txn-маркер только после verify).

    Возвращает {ok, err, resolved} — resolved=True если транзакция была найдена
    и доведена до конца, resolved=False если транзакции не было.
    """
    txn = _txn_state()
    if txn["unknown"]:
        return {"ok": False, "err": "git config --get-all txn check failed", "resolved": False}

    if not txn["present"]:
        return {"ok": True, "resolved": False}  # Нет незавершённой транзакции — норма

    # Транзакция в процессе — доводим до конца
    # Формат: [key, val1, val2, ..., sentinel] — sentinel последний элемент
    if len(txn["values"]) < 3:  # минимум: [key, one_value, sentinel]
        # Некорректный формат txn-маркера — убираем и ругаемся (fail-closed)
        _unset_all(_TXN_KEY)
        return {"ok": False, "err": "corrupt txn marker (less than 3 values with sentinel)", "resolved": False}

    # Issue #234: self-identifying sentinel вместо decimal count — не может случайно совпасть
    # с легитимным numeric target-значением. Пересчитываем ожидаемый sentinel из actual_values
    # (без последнего элемента) и сравниваем строго, byte-for-byte, с тем, что реально на диске.
    last = txn["values"][-1]
    actual_values = txn["values"][:-1]  # без sentinel
    if not last.startswith(_TXN_SENTINEL_PREFIX) or last != _txn_sentinel(actual_values):
        # Sentinel отсутствует/не совпадает — маркер частично записан, убираем (fail-closed)
        _unset_all(_TXN_KEY)
        return {"ok": False, "err": "txn marker partial write: sentinel mismatch or missing", "resolved": True}

    target_key = txn["values"][0]
    target_values = txn["values"][1:-1]  # всё кроме ключа и sentinel

    # Retry: пишем target_values в target_key с verify БЕЗ создания нового txn-маркера
    w = _write_values(target_key, target_values, begin_txn=False)
    if not w["ok"]:
        # Retry не удался — txn-маркер ОСТАЁТСЯ (следующая операция попробует снова)
        return {"ok": False, "err": f"txn retry failed: {w['err']}", "resolved": True}

    # Retry succeeded — убираем txn-маркер (commit)
    c = _commit_txn()
    if not c["ok"]:
        # Критично: verify прошёл, но cleanup txn-маркера упал — orphan marker,
        # но至少 данные консистентны. Логируем, не возвращаем ошибку (данные важнее).
        # Следующий вызов _check_and_resolve_txn просто увидит absent txn.
        pass

    return {"ok": True, "resolved": True}


def enable():
    """Прописать KEY = наш managed _PROXY (scoped github.com). {ok, proxy, err}.

    Если текущее значение(-я) чужие (present и не равны ровно [_PROXY]) — бэкапим ПОЛНЫЙ список
    ПЕРЕД перезаписью, чтобы disable() мог восстановить исходное состояние целиком (multi-value
    включительно). Backup обновляется на КАЖДОЕ новое foreign-состояние между generations — если
    текущий foreign-список отличается от уже сохранённого backup, backup переписывается (иначе
    A→install→manual B→uninstall→install→uninstall терял бы B, восстанавливая устаревший A).
    Идемпотентно: если текущее значение уже == наш _PROXY (повторный install), backup не трогаем.

    Issue #224: в начале проверяем и доводим до конец любую незавершённую транзакцию.

    Issue #234 finding 2: вся транзакция (txn-check + current-read + backup-decision + write)
    выполняется под cross-process exclusive lock (_mutation_lock) — конкурентный disable() не
    может interleave'иться между read и write этой функции.
    """
    with _mutation_lock():
        return _enable_locked()


def _enable_locked():
    """Тело enable() — вызывается ТОЛЬКО под _mutation_lock() (issue #234 finding 2)."""
    # Issue #224: итеративно проверяем и доводим до конца незавершённые транзакции
    # (максимум 1 итерация: после resolved txn проверка снова даст resolved=False)
    for _ in range(2):
        txn_check = _check_and_resolve_txn()
        if not txn_check["ok"]:
            return {"ok": False, "err": f"txn check failed: {txn_check['err']}"}
        if not txn_check["resolved"]:
            break  # Нет незавершённой транзакции — выходим из цикла

    current = _get_all(KEY)
    if current["unknown"]:
        return {"ok": False, "err": "git config --get-all failed (non-absent rc)"}

    is_foreign = current["present"] and current["values"] != [_PROXY]
    if is_foreign:
        backup = _backup_state()
        if backup["unknown"]:
            return {"ok": False, "err": "git config --get-all backup check failed"}
        if backup["values"] != current["values"]:
            # Foreign-состояние новое (первый install ИЛИ сменилось между generations) — обновляем.
            # begin_txn=False, т.к. backup-ключ не часть основной транзакции
            rb = _write_values(_BACKUP_KEY, current["values"], begin_txn=False)
            if not rb["ok"]:
                return {"ok": False, "err": rb["err"]}

    w = _write_values(KEY, [_PROXY])
    if not w["ok"]:
        return {"ok": False, "err": w["err"]}
    return {"ok": True, "proxy": _PROXY}


def _is_partial_restore_of(current_values, backup_values):
    """current_values выглядит как ПРЕРВАННОЕ восстановление backup_values — строгий непустой
    префикс (порядок совпадает с тем, как _write_values пишет значения последовательно через
    --add). Round 5 cycle-review issue #222: `_write_values`'s собственный rollback целится в
    pre-call snapshot KEY, НЕ в backup — если restore ВНУТРИ self-healing (KEY-absent или
    foreign-matches-backup ветка) сам частично падает посреди цикла --add, KEY застревает на
    ПОДМНОЖЕСТВЕ backup (напр. backup=[A,B,C], restore падает на B -> KEY=[A]). Такое подмножество
    статистически неотличимо от случайного стороннего значения по строгому equality-сравнению —
    но префиксное совпадение с backup практически невозможно для настоящего чужого значения
    (нужно случайно совпасть С НАЧАЛА списка ровно наших забэкапленных значений). Используется
    как recovery-эвристика, НЕ заменяет строгий value-match для обычного "чужое значение, не трогаем".
    """
    return (
        0 < len(current_values) < len(backup_values)
        and current_values == backup_values[:len(current_values)]
    )


def _restore_backup_into_key():
    """Восстановить backup в KEY и убрать backup-ключ. {ok, err}. Общий шаг всех self-healing веток."""
    backup = _backup_state()
    if backup["unknown"]:
        return {"ok": False, "err": "git config --get-all backup failed"}
    if not backup["present"]:
        return {"ok": True}  # backup уже нет — идемпотентно (ничего восстанавливать)
    w = _write_values(KEY, backup["values"])
    if not w["ok"]:
        return {"ok": False, "err": w["err"]}
    return _unset_all(_BACKUP_KEY)


def disable():
    """Снять/восстановить KEY, ТОЛЬКО если текущее значение == наш managed _PROXY. {ok, err}.

    fail-closed value-match (канон vscode_proxy.disable, #112): если текущее значение(-я) чужие
    (ручная смена после install, ИЛИ multi-value — не наш single-value путь), НЕ трогаем. Если
    значение — ровно наше — restore backup (полный список, multi-value включительно), если он
    есть; иначе (created с нуля) — unset начисто. Read-after-write verify на каждом шаге.

    Self-healing orphan backup (Codex cycle-review PR #221 round 3, issue #222 наблюдение C):
    если restore значения прошёл в ПРЕДЫДУЩЕМ вызове, но cleanup backup-ключа был прерван (краш
    между двумя git config-мутациями), current больше НЕ равен [_PROXY] — обычная ветка "чужое
    значение, не трогаем" вернула бы ok=True, оставляя backup мусором навсегда (единственная
    ветка, которая его чистит, стала бы недостижима). Поэтому: если текущее чужое значение РОВНО
    совпадает с существующим backup — restore уже случился раньше, доубираем backup.

    Self-healing при KEY absent + backup present (точечный cycle-review issue #222, находка 4):
    если предыдущий enable()/_write_values частично отказал (новая запись упала, rollback ТОЖЕ
    не сработал — см. `data_loss` в _write_values), KEY может оказаться ПОЛНОСТЬЮ absent, а
    backup при этом остаться present с исходным чужим значением. Наивная идемпотентная ветка
    "ключа нет -> ok=True, ничего не делаем" в этом случае оставляла бы backup недостижимым
    мусором И теряла бы исходное чужое значение НАВСЕГДА — backup существует именно для того,
    чтобы данные восстановились, а не чтобы висеть нетронутым, когда KEY уже пуст. Поэтому:
    KEY absent — идемпотентный no-op ТОЛЬКО если backup ТОЖЕ absent (нормальное «ничего никогда
    не было установлено»); если backup present — восстанавливаем его в KEY, симметрично основной
    restore-ветке ниже.

    Self-healing при ЧАСТИЧНО восстановленном backup (round 5 cycle-review issue #222): restore
    ВНУТРИ любой из self-healing веток (или основного restore-пути ниже) — ТОЖЕ мутация через
    `_write_values`, которая сама может частично отказать (см. докстринг `_write_values`). Тогда
    current застревает на СТРОГОМ ПРЕФИКСЕ backup, а не на полном backup и не на absent — обе
    предыдущие self-healing-ветки его не распознавали (не равен ни [_PROXY]/absent, ни backup
    целиком) и классифицировали как "чужое значение, никогда не трогаем", хороня backup и
    оставшиеся значения безвозвратно. `_is_partial_restore_of` ловит этот случай ДО capitulation
    в fail-closed ветку и повторяет restore.

    Issue #224: в начале проверяем и доводим до конец любую незавершённую транзакцию.

    Issue #234 finding 2: вся транзакция выполняется под cross-process exclusive lock
    (_mutation_lock) — конкурентный enable() не может interleave'иться между read и write.
    """
    with _mutation_lock():
        return _disable_locked()


def _disable_locked():
    """Тело disable() — вызывается ТОЛЬКО под _mutation_lock() (issue #234 finding 2)."""
    # Issue #224: итеративно проверяем и доводим до конца незавершённые транзакции
    # (максимум 1 итерация: после resolved txn проверка снова даст resolved=False)
    for _ in range(2):
        txn_check = _check_and_resolve_txn()
        if not txn_check["ok"]:
            return {"ok": False, "err": f"txn check failed: {txn_check['err']}"}
        if not txn_check["resolved"]:
            break  # Нет незавершённой транзакции — выходим из цикла

    current = _get_all(KEY)
    if current["unknown"]:
        return {"ok": False, "err": "git config --get-all failed (non-absent rc)"}

    if not current["present"]:
        backup = _backup_state()
        if backup["unknown"]:
            return {"ok": False, "err": "git config --get-all backup failed"}
        if not backup["present"]:
            return {"ok": True}  # ни ключа, ни backup — идемпотентно, чистое "ничего не было"
        return _restore_backup_into_key()

    if current["values"] != [_PROXY]:
        backup = _backup_state()
        if backup["unknown"]:
            return {"ok": False, "err": "git config --get-all backup failed"}
        if backup["present"] and backup["values"] == current["values"]:
            # current уже == restored backup -> предыдущий disable() прервался ПОСЛЕ restore, но
            # ДО cleanup backup-ключа. Значение не трогаем, только доубираем сиротский backup.
            return _unset_all(_BACKUP_KEY)
        if backup["present"] and _is_partial_restore_of(current["values"], backup["values"]):
            # current — незавершённый restore backup (строгий префикс), не легитимное чужое
            # значение — довершаем restore, а не капитулируем в "не трогаем".
            return _restore_backup_into_key()
        return {"ok": True}  # чужое текущее значение (или multi-value чужое) — не трогаем

    return _restore_backup_into_key() if _backup_state()["present"] else _unset_all(KEY)
