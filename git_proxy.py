"""Вкл/откл git-прокси для github.com в ~/.gitconfig (через `git config --global`).

У пользователя сломан прямой IPv4-путь к github (тормозит/отваливается), а у github нет AAAA
(только IPv4). Рабочий путь — через privoxy (8118). Эта настройка scoped ТОЛЬКО на github.com:
другие git-серверы (GitLab, корпоративные) идут напрямую, как раньше.

Состояние = сам ~/.gitconfig (единый источник правды, НЕ дублируется в srouter-state). git config
правит пользовательский файл от текущего юзера — root НЕ нужен. Функции не бросают (probe-канон).
"""
import sys_probe

GIT = "/usr/bin/git"
KEY = "http.https://github.com.proxy"

# Прокси = privoxy (8118). Берём из dashboard_common если доступен; fallback на хардкод,
# чтобы модуль не падал в среде без srouter_config (git_proxy не должен тянуть конфиг инфраструктуры).
try:
    from dashboard_common import HTTP_PROXY_URL as _PROXY  # http://127.0.0.1:8118
except Exception:
    _PROXY = "http://127.0.0.1:8118"


def status():
    """{enabled: bool, proxy: str, key, scoped}. НЕ бросает.

    `git config --global --get KEY` возвращает rc=1 + пустой out если ключа нет — это НЕ ошибка.
    """
    r = sys_probe.run([GIT, "config", "--global", "--get", KEY], timeout=4)
    if r.get("timeout"):
        return {"enabled": False, "proxy": "", "key": KEY, "status": "unknown"}
    out = (r.get("out") or "").strip()
    return {"enabled": bool(out), "proxy": out, "key": KEY}


def enable():
    """Прописать KEY = прокси (scoped github.com). {ok, proxy, err}."""
    r = sys_probe.run([GIT, "config", "--global", KEY, _PROXY], timeout=5)
    if r.get("timeout") or r.get("rc") != 0:
        return {"ok": False, "err": (r.get("err") or "git config failed")[:200]}
    return {"ok": True, "proxy": _PROXY}


def disable():
    """Снять KEY (--unset). {ok, err}. Идемпотентно: rc=5 (ключа не было) — успех."""
    r = sys_probe.run([GIT, "config", "--global", "--unset", KEY], timeout=5)
    rc = r.get("rc")
    # rc=0 (снят) или rc=5 (раздел/ключ отсутствует) — оба успех. timeout/др. rc — ошибка.
    if r.get("timeout") or rc not in (0, 5):
        return {"ok": False, "err": (r.get("err") or "git config --unset failed")[:200]}
    return {"ok": True}
