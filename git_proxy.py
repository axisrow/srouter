"""Вкл/откл git-прокси для github.com в ~/.gitconfig (через `git config --global`).

У пользователя сломан прямой IPv4-путь к github (тормозит/отваливается), а у github нет AAAA
(только IPv4). Рабочий путь — через xray. Эта настройка scoped ТОЛЬКО на github.com: другие
git-серверы (GitLab, корпоративные) идут напрямую, как раньше.

Прокси = SOCKS5 (xray 10808), НЕ HTTP (privoxy 8118) — канон issue #130: git умеет нативный SOCKS5
(в отличие от Claude Code, см. claude_proxy.py), а privoxy лишний хоп для git-операций.

Состояние = сам ~/.gitconfig (единый источник правды, НЕ дублируется в srouter-state). git config
правит пользовательский файл от текущего юзера — root НЕ нужен. Функции не бросают (probe-канон).

Provenance (created/overwrote-канон install_lib.py, issue #112): если у ключа было чужое значение
ДО enable(), оно бэкапится в KEY + "-srouter-backup" (тот же ~/.gitconfig, не отдельный state-файл)
и восстанавливается при disable(). disable() снимает/восстанавливает ТОЛЬКО если ТЕКУЩЕЕ значение
== наш managed _PROXY (fail-closed value-match, канон vscode_proxy.disable) — ручная смена прокси
после install не трогается.
"""
import sys_probe

GIT = "/usr/bin/git"
KEY = "http.https://github.com.proxy"
# Backup исходного чужого значения (created/overwrote-канон install_lib.py, но БЕЗ отдельного
# state-файла — состояние модуля = сам ~/.gitconfig, backup живёт там же как доп. ключ).
_BACKUP_KEY = KEY + "-srouter-backup"

# Прокси = SOCKS5 xray (10808). Берём из dashboard_common если доступен; fallback на хардкод,
# чтобы модуль не падал в среде без srouter_config (git_proxy не должен тянуть конфиг инфраструктуры).
try:
    from dashboard_common import SOCKS_PROXY_URL as _PROXY  # socks5h://127.0.0.1:10808
except Exception:
    _PROXY = "socks5h://127.0.0.1:10808"


def _get(key, timeout=4):
    """git config --get KEY → {rc, out}. Не бросает."""
    return sys_probe.run([GIT, "config", "--global", "--get", key], timeout=timeout)


def status():
    """{enabled: bool, proxy: str, key, scoped}. НЕ бросает.

    rc=1 + пустой out — задокументированное «ключа нет» (НЕ ошибка). Любой другой ненулевой rc
    (permission denied, malformed config, git отсутствует) — реальный сбой чтения, status="unknown".
    Codex cycle-review PR #221 round 2: раньше любой non-timeout rc маскировался под enabled=False,
    и disable() врал ok=True без реальной попытки очистки.
    """
    r = _get(KEY)
    if r.get("timeout"):
        return {"enabled": False, "proxy": "", "key": KEY, "status": "unknown"}
    rc = r.get("rc")
    if rc not in (0, 1):
        return {"enabled": False, "proxy": "", "key": KEY, "status": "unknown"}
    out = (r.get("out") or "").strip()
    return {"enabled": bool(out), "proxy": out, "key": KEY}


def enable():
    """Прописать KEY = прокси (scoped github.com). {ok, proxy, err}.

    Если текущее значение чужое (не наш _PROXY и не пусто) — бэкапим его в _BACKUP_KEY ПЕРЕД
    перезаписью (created/overwrote-канон), чтобы disable() мог восстановить исходный прокси.
    Идемпотентно: повторный enable() (backup уже сохранён) не перезаписывает backup нашим же
    значением — иначе следующий disable() «восстановил» бы _PROXY вместо исходного чужого.
    """
    current = status()
    if current.get("status") != "unknown" and current.get("enabled") and current.get("proxy") != _PROXY:
        # чужое значение стоит — бэкапим, только если backup ещё не установлен (idempotent install).
        backup = _get(_BACKUP_KEY)
        backup_rc = backup.get("rc")
        if not backup.get("timeout") and backup_rc == 1:  # backup отсутствует → первый install
            rb = sys_probe.run([GIT, "config", "--global", _BACKUP_KEY, current["proxy"]], timeout=5)
            if rb.get("timeout") or rb.get("rc") != 0:
                return {"ok": False, "err": (rb.get("err") or "git config backup failed")[:200]}
    r = sys_probe.run([GIT, "config", "--global", KEY, _PROXY], timeout=5)
    if r.get("timeout") or r.get("rc") != 0:
        return {"ok": False, "err": (r.get("err") or "git config failed")[:200]}
    return {"ok": True, "proxy": _PROXY}


def disable():
    """Снять/восстановить KEY, ТОЛЬКО если текущее значение == наш managed _PROXY. {ok, err}.

    fail-closed provenance (канон vscode_proxy.disable, #112): value-match по ТЕКУЩЕМУ значению —
    если пользователь вручную сменил прокси после install, текущее значение чужое, не трогаем.
    Если значение — наше, и есть backup исходного чужого значения — restore backup (round-trip
    без потери данных, Codex cycle-review PR #221 round 2). Иначе (created с нуля) — --unset.
    """
    current = status()
    if current.get("status") == "unknown":
        return {"ok": False, "err": "git config --get failed (non-absent rc)"}
    if not current.get("enabled"):
        return {"ok": True}  # ключа уже нет — идемпотентно
    if current.get("proxy") != _PROXY:
        return {"ok": True}  # чужое ТЕКУЩЕЕ значение — не трогаем (fail-closed provenance)

    backup = _get(_BACKUP_KEY)
    if backup.get("timeout"):
        return {"ok": False, "err": "git config --get backup timeout"}
    backup_val = (backup.get("out") or "").strip() if backup.get("rc") == 0 else ""

    if backup_val:
        rb = sys_probe.run([GIT, "config", "--global", KEY, backup_val], timeout=5)
        if rb.get("timeout") or rb.get("rc") != 0:
            return {"ok": False, "err": (rb.get("err") or "git config restore failed")[:200]}
        ru = sys_probe.run([GIT, "config", "--global", "--unset", _BACKUP_KEY], timeout=5)
        if ru.get("timeout") or ru.get("rc") not in (0, 5):
            return {"ok": False, "err": (ru.get("err") or "git config backup cleanup failed")[:200]}
        return {"ok": True}

    r = sys_probe.run([GIT, "config", "--global", "--unset", KEY], timeout=5)
    rc = r.get("rc")
    # rc=0 (снят) или rc=5 (раздел/ключ отсутствует — гонка между status() и unset) — оба успех.
    if r.get("timeout") or rc not in (0, 5):
        return {"ok": False, "err": (r.get("err") or "git config --unset failed")[:200]}
    return {"ok": True}
