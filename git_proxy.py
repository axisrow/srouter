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

Остаточный риск (/review PR #223 п.1): `git config` не даёт transactional multi-value write —
`_write_values` делает `--unset-all` затем цикл `--add`, окно между ними физически существует.
Если процесс убит именно в этом окне (не просто "падение вызова", а SIGKILL/крэш всего процесса),
`_write_values` best-effort rollback (см. докстринг) не успевает отработать — тогда backup (если
уже обновлён) остаётся источником восстановления при следующем вызове. Окно на порядки уже, чем
раньше (единственная git config-мутация, не произвольный кусок Python-кода), и every write verified
read-after-write — но полная атомарность потребовала бы file-level tmp+replace (канон
vscode_proxy._save/install_lib._backup), что для этого объёма риска признано избыточным.
"""
import sys_probe

GIT = "/usr/bin/git"
KEY = "http.https://github.com.proxy"
# Backup списка исходных чужих значений (created/overwrote-канон install_lib.py, но БЕЗ отдельного
# state-файла — состояние модуля = сам ~/.gitconfig, backup живёт там же как доп. ключ).
_BACKUP_KEY = KEY + "-srouter-backup"

# Прокси = SOCKS5 xray (10808). Берём из dashboard_common если доступен; fallback на хардкод,
# чтобы модуль не падал в среде без srouter_config (git_proxy не должен тянуть конфиг инфраструктуры).
try:
    from dashboard_common import SOCKS_PROXY_URL as _PROXY  # socks5h://127.0.0.1:10808
except Exception:
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


def _write_values(key, values, timeout=5):
    """Записать KEY = список values (может быть один или несколько). Verify после записи.

    Реализация: --unset-all (начисто), затем --add на каждое значение — детерминированно
    работает и для single-, и для multi-value списков, без спец-случаев.

    Best-effort rollback (/review PR #223 п.1): git config не даёт transactional multi-value
    write — окно между --unset-all и --add физически существует. Если запись НОВЫХ значений
    падает посреди цикла, key был бы оставлен ПУСТЫМ (не просто "не обновлён", а активно
    искажён — данные потеряны из ~/.gitconfig ДАЖЕ если backup их где-то хранит). Поэтому при
    сбое пытаемся восстановить ИСХОДНЫЕ (до этого вызова) значения обратно, прежде чем вернуть
    ошибку — снижает окно потери данных до единственного узкого best-effort шага вместо
    "новые значения не записались, старые тоже потеряны".
    """
    before = _get_all(key, timeout=timeout)
    if before["unknown"]:
        return {"ok": False, "err": "git config --get-all pre-write snapshot failed"}
    original_values = before["values"] if before["present"] else None

    clr = _unset_all(key, timeout=timeout)
    if not clr["ok"]:
        return clr

    def _rollback(err):
        if original_values is not None:
            for val in original_values:
                sys_probe.run([GIT, "config", "--global", "--add", key, val], timeout=timeout)
        return {"ok": False, "err": err[:200]}

    for val in values:
        r = sys_probe.run([GIT, "config", "--global", "--add", key, val], timeout=timeout)
        if r.get("timeout") or r.get("rc") != 0:
            return _rollback(r.get("err") or "git config --add failed")
    after = _get_all(key, timeout=timeout)
    if after["unknown"] or after["values"] != values:
        return _rollback("git config write verify mismatch after --add")
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


def enable():
    """Прописать KEY = наш managed _PROXY (scoped github.com). {ok, proxy, err}.

    Если текущее значение(-я) чужие (present и не равны ровно [_PROXY]) — бэкапим ПОЛНЫЙ список
    ПЕРЕД перезаписью, чтобы disable() мог восстановить исходное состояние целиком (multi-value
    включительно). Backup обновляется на КАЖДОЕ новое foreign-состояние между generations — если
    текущий foreign-список отличается от уже сохранённого backup, backup переписывается (иначе
    A→install→manual B→uninstall→install→uninstall терял бы B, восстанавливая устаревший A).
    Идемпотентно: если текущее значение уже == наш _PROXY (повторный install), backup не трогаем.
    """
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
            rb = _write_values(_BACKUP_KEY, current["values"])
            if not rb["ok"]:
                return {"ok": False, "err": rb["err"]}

    w = _write_values(KEY, [_PROXY])
    if not w["ok"]:
        return {"ok": False, "err": w["err"]}
    return {"ok": True, "proxy": _PROXY}


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
    """
    current = _get_all(KEY)
    if current["unknown"]:
        return {"ok": False, "err": "git config --get-all failed (non-absent rc)"}
    if not current["present"]:
        return {"ok": True}  # ключа уже нет — идемпотентно

    if current["values"] != [_PROXY]:
        backup = _backup_state()
        if backup["unknown"]:
            return {"ok": False, "err": "git config --get-all backup failed"}
        if backup["present"] and backup["values"] == current["values"]:
            # current уже == restored backup -> предыдущий disable() прервался ПОСЛЕ restore, но
            # ДО cleanup backup-ключа. Значение не трогаем, только доубираем сиротский backup.
            return _unset_all(_BACKUP_KEY)
        return {"ok": True}  # чужое текущее значение (или multi-value чужое) — не трогаем

    backup = _backup_state()
    if backup["unknown"]:
        return {"ok": False, "err": "git config --get-all backup failed"}

    if backup["present"]:
        w = _write_values(KEY, backup["values"])
        if not w["ok"]:
            return {"ok": False, "err": w["err"]}
        c = _unset_all(_BACKUP_KEY)
        if not c["ok"]:
            return {"ok": False, "err": c["err"]}
        return {"ok": True}

    return _unset_all(KEY)
