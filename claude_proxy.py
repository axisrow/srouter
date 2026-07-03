"""Вкл/откл HTTPS_PROXY для Claude Code в ~/.claude/settings.json.

После включения PF-изоляции Anthropic-доменов Claude Code CLI не может работать напрямую
(PF режет api.anthropic.com / platform.claude.com на 160.79.104.10). CLI обязан ходить через
прокси privoxy (8118) — иначе логин/API не работают. settings.json → env.HTTPS_PROXY подхватывается
Claude Code/node автоматически при запуске (подтверждено: HTTPS_PROXY=... claude работает).

Это ЧУЖОЙ конфиг (как ~/.gitconfig для git-proxy) — правим JSON read-modify-write (не строками),
сохраняя все существующие env/permissions/hooks. Atomic-запись через tmp+replace. Не бросает.
"""
import json
from pathlib import Path

# Прокси = privoxy (8118). Берём из dashboard_common если доступен; fallback на хардкод,
# чтобы модуль не падал в среде без srouter_config (как git_proxy).
try:
    from dashboard_common import HTTP_PROXY_URL as _PROXY  # http://127.0.0.1:8118
except Exception:
    _PROXY = "http://127.0.0.1:8118"

SETTINGS = Path.home() / ".claude" / "settings.json"
# Claude Code/node уважают HTTPS_PROXY; HTTP_PROXY добавляем для полноты (HTTP-эндпоинты).
ENV_KEYS = ("HTTPS_PROXY", "HTTP_PROXY")


def _load():
    """Прочитать settings.json. Missing/non-JSON → {}. Не бросает."""
    try:
        return json.loads(SETTINGS.read_text(encoding="utf-8")) if SETTINGS.exists() else {}
    except Exception:
        return {}


def _save(data):
    """Atomic-запись settings.json. {ok, err}. tmp+replace — не теряем данные при сбое."""
    try:
        SETTINGS.parent.mkdir(parents=True, exist_ok=True)
        tmp = SETTINGS.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        tmp.replace(SETTINGS)
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "err": str(exc)[:200]}


def status():
    """{enabled: bool, proxy: str}. enabled = env.HTTPS_PROXY == наш прокси. Не бросает."""
    data = _load()
    env = data.get("env") if isinstance(data, dict) else None
    if not isinstance(env, dict):
        return {"enabled": False, "proxy": ""}
    val = env.get("HTTPS_PROXY", "")
    return {"enabled": val == _PROXY, "proxy": val}


def enable():
    """Прописать env.HTTPS_PROXY = env.HTTP_PROXY = прокси. {ok, err}.

    Не трогает другие env-ключи (TRAVELPAYOUTS_TOKEN, IS_DEMO и т.д.) — read-modify-write.
    """
    data = _load()
    if not isinstance(data, dict):
        data = {}
    env = data.get("env")
    if not isinstance(env, dict):
        env = {}
        data["env"] = env
    for k in ENV_KEYS:
        env[k] = _PROXY
    return _save(data)


def disable():
    """Удалить env.HTTPS_PROXY/HTTP_PROXY. {ok, err}. Идемпотентно (уже чисто — успех)."""
    data = _load()
    env = data.get("env") if isinstance(data, dict) else None
    if isinstance(env, dict):
        changed = False
        for k in ENV_KEYS:
            if k in env:
                del env[k]
                changed = True
        if changed:
            return _save(data)
    return {"ok": True}  # уже чисто или файла нет — успех
