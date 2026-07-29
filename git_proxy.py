"""Вкл/откл git-прокси для github.com в ~/.gitconfig (через `git config --global`).

У пользователя сломан прямой IPv4-путь к github (тормозит/отваливается), а у github нет AAAA
(только IPv4). Рабочий путь — через xray. Эта настройка scoped ТОЛЬКО на github.com: другие
git-серверы (GitLab, корпоративные) идут напрямую, как раньше.

Прокси = SOCKS5 (xray 10808), НЕ HTTP (privoxy 8118) — канон issue #130: git умеет нативный SOCKS5
(в отличие от Claude Code, см. claude_proxy.py), а privoxy лишний хоп для git-операций.

Состояние = сам ~/.gitconfig (единый источник правды, НЕ дублируется в srouter-state). git config
правит пользовательский файл от текущего юзера — root НЕ нужен. Функции не бросают (probe-канон).

Provenance (fail-closed value-match, канон vscode_proxy.disable, #112): disable() снимает KEY
ТОЛЬКО если текущее значение == наш managed _PROXY — ручную смену прокси после install не трогает.
enable() перезаписывает существующее значение безусловно (install = «одна команда, всё настроено»,
issue #130). НЕТ backup/restore исходного чужого значения при uninstall — сложная provenance-модель
(empty-value-aware, multi-value-aware, read-after-write verify) вынесена в issue #222 как отдельная
задача; здесь только узкий фикс «не стирать чужое ПОСЛЕ install» без полного round-trip восстановления.
"""
import sys_probe

GIT = "/usr/bin/git"
KEY = "http.https://github.com.proxy"

# Прокси = SOCKS5 xray (10808). Берём из dashboard_common если доступен; fallback на хардкод,
# чтобы модуль не падал в среде без srouter_config (git_proxy не должен тянуть конфиг инфраструктуры).
try:
    from dashboard_common import SOCKS_PROXY_URL as _PROXY  # socks5h://127.0.0.1:10808
except Exception:
    _PROXY = "socks5h://127.0.0.1:10808"


def status():
    """{enabled: bool, proxy: str, key, scoped}. НЕ бросает.

    rc=1 + пустой out — задокументированное «ключа нет» (НЕ ошибка). Любой другой ненулевой rc
    (permission denied, malformed config, git отсутствует) — реальный сбой чтения, status="unknown".
    Codex cycle-review PR #221 round 2: раньше любой non-timeout rc маскировался под enabled=False,
    и disable() врал ok=True без реальной попытки очистки.
    """
    r = sys_probe.run([GIT, "config", "--global", "--get", KEY], timeout=4)
    if r.get("timeout"):
        return {"enabled": False, "proxy": "", "key": KEY, "status": "unknown"}
    rc = r.get("rc")
    if rc not in (0, 1):
        return {"enabled": False, "proxy": "", "key": KEY, "status": "unknown"}
    out = (r.get("out") or "").strip()
    return {"enabled": bool(out), "proxy": out, "key": KEY}


def enable():
    """Прописать KEY = прокси (scoped github.com). {ok, proxy, err}. Перезаписывает безусловно."""
    r = sys_probe.run([GIT, "config", "--global", KEY, _PROXY], timeout=5)
    if r.get("timeout") or r.get("rc") != 0:
        return {"ok": False, "err": (r.get("err") or "git config failed")[:200]}
    return {"ok": True, "proxy": _PROXY}


def disable():
    """Снять KEY, ТОЛЬКО если текущее значение == наш managed _PROXY. {ok, err}. Идемпотентно.

    fail-closed provenance (канон vscode_proxy.disable, #112): value-match по ТЕКУЩЕМУ значению —
    если пользователь вручную сменил прокси после install, текущее значение чужое, не трогаем.
    НЕ восстанавливает исходное чужое значение, стоявшее ДО install (backup/restore — issue #222).
    """
    current = status()
    if current.get("status") == "unknown":
        return {"ok": False, "err": "git config --get failed (non-absent rc)"}
    if not current.get("enabled"):
        return {"ok": True}  # ключа уже нет — идемпотентно
    if current.get("proxy") != _PROXY:
        return {"ok": True}  # чужое ТЕКУЩЕЕ значение — не трогаем (fail-closed provenance)
    r = sys_probe.run([GIT, "config", "--global", "--unset", KEY], timeout=5)
    rc = r.get("rc")
    # rc=0 (снят) или rc=5 (раздел/ключ отсутствует — гонка между status() и unset) — оба успех.
    if r.get("timeout") or rc not in (0, 5):
        return {"ok": False, "err": (r.get("err") or "git config --unset failed")[:200]}
    return {"ok": True}
