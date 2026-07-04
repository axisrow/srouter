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
from urllib.parse import urlparse

# Прокси = privoxy (8118). Берём из dashboard_common если доступен; fallback на хардкод,
# чтобы модуль не падал в среде без srouter_config (как git_proxy).
try:
    from dashboard_common import HTTP_PROXY_URL as _PROXY  # http://127.0.0.1:8118
except Exception:
    _PROXY = "http://127.0.0.1:8118"

SETTINGS = Path.home() / ".claude" / "settings.json"
# Claude Code/node уважают HTTPS_PROXY; HTTP_PROXY добавляем для полноты (HTTP-эндпоинты).
ENV_KEYS = ("HTTPS_PROXY", "HTTP_PROXY")
# NO_PROXY (оба регистра) — хосты из ANTHROPIC_BASE_URL идут напрямую, мимо privoxy.
# Сторонний провайдер (z.ai/glm/любой) на внешнем хостинге — прокси-туннель ему не нужен (лишний хоп).
# NO_PROXY следует за HTTPS_PROXY (ставится в enable, убирается в disable) — в установке srouter они
# семантически связаны: прокси без NO_PROXY ломает доступ к провайдеру, NO_PROXY без прокси бессмысленен.
NO_PROXY_KEYS = ("NO_PROXY", "no_proxy")


def _base_url_hosts(data):
    """Хост для NO_PROXY из env.ANTHROPIC_BASE_URL. Пустая строка если URL нет.

    Возвращает хост (напр. 'api.z.ai') — без parent-доменного suffix. Раньше добавлялся '.z.ai'
    для поддоменов, но parts[-2:] ломается на country-TLD ('api.x.co.uk' → '.co.uk' обходит прокси
    для ВСЕХ .co.uk). Provider = один хост, suffix не нужен. IP/localhost тоже без suffix.
    Если ANTHROPIC_BASE_URL нет (CC на дефолтном api.anthropic.com) → '', NO_PROXY не ставим (gate).
    """
    env = data.get("env") if isinstance(data, dict) else None
    base = env.get("ANTHROPIC_BASE_URL", "") if isinstance(env, dict) else ""
    return (urlparse(base).hostname or "").lower()


def _merge_no_proxy(existing, add):
    """Объединить NO_PROXY-строки без дублей, сохраняя порядок и регистр существующих хостов.

    existing — как есть (чужой регистр не нормализуем). add — provider-хосты (уже lower).
    Дедуп через lowercase set, но в вывод — оригинальный регистр.
    """
    seen, out = set(), []
    for raw in f"{existing},{add}".split(","):
        h = raw.strip()
        if h and h.lower() not in seen:
            seen.add(h.lower())
            out.append(h)
    return ",".join(out)


def _strip_no_proxy(existing, remove):
    """Убрать хосты из NO_PROXY (set-diff), вернуть строку. Чужие хосты сохраняются."""
    rm = {h.strip().lower() for h in remove.split(",") if h.strip()}
    items = [h.strip() for h in existing.split(",") if h.strip() and h.strip().lower() not in rm]
    return ",".join(items)


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
    """Состояние прокси CC: {enabled, proxy, provider_direct, no_proxy}. Не бросает.

    provider_direct = хост ANTHROPIC_BASE_URL реально в NO_PROXY (провайдер идёт напрямую).
    Это сырой state компонента, НЕ probe — runtime-вердикт для doctor/gather_status делает
    health._claude_proxy_probe() с каноничным {status}.
    """
    data = _load()
    env = data.get("env") if isinstance(data, dict) else None
    if not isinstance(env, dict):
        return {"enabled": False, "proxy": "", "provider_direct": False, "no_proxy": ""}
    val = env.get("HTTPS_PROXY", "")
    no_proxy = env.get("NO_PROXY", "") or env.get("no_proxy", "")
    hosts = _base_url_hosts(data)
    # set-intersection (не substring) — 'z.ai' in 'api.z.ai' = True это substring-ложка.
    host_set = {h for h in hosts.split(",") if h}
    np_set = {h.strip().lower() for h in no_proxy.split(",") if h.strip()}
    provider_direct = bool(host_set & np_set)
    return {"enabled": val == _PROXY, "proxy": val, "provider_direct": provider_direct, "no_proxy": no_proxy}


def enable():
    """Прописать env.HTTPS_PROXY/HTTP_PROXY = прокси + NO_PROXY (provider-direct). {ok, err}.

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
    hosts = _base_url_hosts(data)
    if hosts:
        # Синхронизировать оба регистра: если один пуст, инициализировать из другого (иначе merge
        # каждой variant независимо создаст рассинхрон — NO_PROXY без corp.local, no_proxy с ним).
        existing = env.get("NO_PROXY", "") or env.get("no_proxy", "")
        for k in NO_PROXY_KEYS:
            env[k] = _merge_no_proxy(existing, hosts)
    return _save(data)


def disable():
    """Удалить env.HTTPS_PROXY/HTTP_PROXY + provider-хосты из NO_PROXY. {ok, err}. Идемпотентно."""
    data = _load()
    env = data.get("env") if isinstance(data, dict) else None
    if isinstance(env, dict):
        changed = False
        for k in ENV_KEYS:
            if k in env:
                del env[k]
                changed = True
        hosts = _base_url_hosts(data)
        if hosts:
            for k in NO_PROXY_KEYS:
                if k in env:
                    stripped = _strip_no_proxy(env[k], hosts)
                    if stripped:
                        env[k] = stripped
                    else:
                        del env[k]  # стали пустыми — убрать ключ целиком
                    changed = True
        if changed:
            return _save(data)
    return {"ok": True}  # уже чисто или файла нет — успех
