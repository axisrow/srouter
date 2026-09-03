"""Вкл/откл HTTPS_PROXY для Claude Code в ~/.claude/settings.json.

После включения PF-изоляции Anthropic-доменов Claude Code CLI не может работать напрямую
(PF режет api.anthropic.com / platform.claude.com на 160.79.104.10). CLI обязан ходить через
прокси — иначе логин/API не работают. settings.json → env.HTTPS_PROXY подхватывается Claude Code
при запуске. Для Claude Code используем HTTP bridge privoxy 8118. SOCKS listener xray 10808
остаётся для клиентов, которые действительно поддерживают SOCKS, но не записывается в
HTTP_PROXY/HTTPS_PROXY Claude Code (#127).

Это ЧУЖОЙ конфиг (как ~/.gitconfig для git-proxy) — правим JSON read-modify-write (не строками),
сохраняя все существующие env/permissions/hooks. Atomic-запись через tmp+replace. Не бросает.

Issue #307 (foreign/force/provenance, канон privileged-boundary-fail-closed): чужое значение
HTTPS_PROXY (корпоративная политика, ручная настройка) — ОТДЕЛЬНОЕ состояние `foreign` в
status(), enable() на него отказывает ЯВНО (conflict), перезапись — только force=True с
backup'ом чужого значения в sidecar-файл (прецедент #112 provenance). disable() удаляет
proxy-ключи ТОЛЬКО когда их значение == наш managed прокси (value-match), чужое не трогает,
и восстанавливает backup после force-перезаписи. Классификация состояний — общий слой
proxy_config_contract (канон third-module-breaks-reexport-cycle).
"""
import json
from pathlib import Path
from urllib.parse import urlparse

import proxy_config_contract as _contract

# Прокси Claude Code = HTTP bridge privoxy 8118. Не заменять на SOCKS по одному lsof/exit-code:
# black-box proof — реальный Claude Code должен получить ожидаемый API 401 (#127).
try:
    from dashboard_common import HTTP_PROXY_URL as _PROXY  # http://127.0.0.1:8118
except SystemExit:
    # dashboard_common raises SystemExit (BaseException) when srouter_config.py is missing.
    # Fallback to canonical value (install-path compatibility — module must not crash).
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
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        # File read errors or JSON parsing failures: OSError on I/O errors,
        # JSONDecodeError on malformed JSON, ValueError/TypeError on type issues.
        # Fallback: empty dict (no proxy configured).
        return {}


def _save(data):
    """Atomic-запись settings.json. {ok, err}. tmp+replace — не теряем данные при сбое."""
    try:
        SETTINGS.parent.mkdir(parents=True, exist_ok=True)
        tmp = SETTINGS.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        tmp.replace(SETTINGS)
        return {"ok": True}
    except (OSError, TypeError, ValueError) as exc:
        # File write errors: OSError on I/O failures, TypeError on invalid data types,
        # ValueError on JSON encoding failures. Return structured error (truncated).
        return {"ok": False, "err": str(exc)[:200]}


def status():
    """Состояние прокси CC: {enabled, proxy, state, provider_direct, no_proxy}. Не бросает.

    state (issue #307) — absent/managed-on/foreign: чужое значение HTTPS_PROXY/HTTP_PROXY
    это НЕ «не настроено», а отдельное состояние foreign — иначе клик «Включить» на панели
    выглядит безопасным, а уничтожил бы чужую настройку.
    provider_direct = хост ANTHROPIC_BASE_URL реально в NO_PROXY (провайдер идёт напрямую).
    Это сырой state компонента, НЕ probe — runtime-вердикт для doctor/gather_status делает
    health._claude_proxy_probe() с каноничным {status}.
    """
    data = _load()
    env = data.get("env") if isinstance(data, dict) else None
    if not isinstance(env, dict):
        return {"enabled": False, "proxy": "", "state": _contract.ABSENT,
                "provider_direct": False, "no_proxy": ""}
    val = env.get("HTTPS_PROXY", "")
    no_proxy = env.get("NO_PROXY", "") or env.get("no_proxy", "")
    hosts = _base_url_hosts(data)
    # set-intersection (не substring) — 'z.ai' in 'api.z.ai' = True это substring-ложка.
    host_set = {h for h in hosts.split(",") if h}
    np_set = {h.strip().lower() for h in no_proxy.split(",") if h.strip()}
    provider_direct = bool(host_set & np_set)
    state = _contract.aggregate(
        _contract.classify(k in env, env.get(k, ""), _PROXY) for k in ENV_KEYS)
    return {"enabled": val == _PROXY, "proxy": val, "state": state,
            "provider_direct": provider_direct, "no_proxy": no_proxy}


def _backup_path():
    """Sidecar-backup чужих значений, перезаписанных force-enable (прецедент #112 provenance).
    Живёт рядом с settings.json; disable() восстанавливает из него и удаляет."""
    return SETTINGS.parent / (SETTINGS.name + ".srouter-proxy-backup.json")


def _read_backup():
    """Прочитать sidecar-backup. None если нет/битый. Не бросает."""
    try:
        p = _backup_path()
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        return None


def enable(force=False):
    """Прописать env.HTTPS_PROXY/HTTP_PROXY = прокси + NO_PROXY (provider-direct). {ok, err}.

    Не трогает другие env-ключи (TRAVELPAYOUTS_TOKEN, IS_DEMO и т.д.) — read-modify-write.

    Issue #307: если текущее значение proxy-ключей ЧУЖОЕ (не наш managed прокси) — отказ
    без мутации {ok: False, conflict: True, state}; перезапись только force=True, при этом
    чужие значения сохраняются в sidecar-backup (disable() потом их восстановит). На
    absent/managed-on enable идемпотентен, force не нужен.
    """
    scheme = urlparse(_PROXY).scheme.lower()
    if scheme not in {"http", "https"}:
        return {"ok": False, "err": f"unsupported proxy scheme for Claude Code: {scheme or 'missing'}"}

    data = _load()
    if not isinstance(data, dict):
        data = {}
    env = data.get("env")
    if not isinstance(env, dict):
        env = {}
        data["env"] = env

    state = _contract.aggregate(
        _contract.classify(k in env, env.get(k, ""), _PROXY) for k in ENV_KEYS)
    if _contract.needs_force(state) and not force:
        return _contract.conflict_result(state)

    if force and _contract.needs_force(state):
        # Provenance: сохранить ЧУЖИЕ значения перед перезаписью (только сами proxy-ключи).
        foreign = {k: env[k] for k in ENV_KEYS if k in env and env[k] != _PROXY}
        if foreign:
            # _save() пишет строго SETTINGS; backup — отдельная атомарная запись тем же паттерном.
            try:
                _backup_path().parent.mkdir(parents=True, exist_ok=True)
                tmp = _backup_path().with_suffix(".json.tmp")
                tmp.write_text(json.dumps({"env": foreign}, indent=2, ensure_ascii=False) + "\n",
                               encoding="utf-8")
                tmp.replace(_backup_path())
            except (OSError, TypeError, ValueError) as exc:
                return {"ok": False, "err": f"backup foreign value failed: {str(exc)[:150]}"}

    for k in ENV_KEYS:
        env[k] = _PROXY
    hosts = _base_url_hosts(data)
    if hosts:
        # Merge обе variant (NO_PROXY + no_proxy) + provider-хосты. Если брать только одну variant
        # (NO_PROXY or no_proxy), при рассинхронных значениях вторая теряется (a.com vs b.com).
        # Union обеих → provider-хост добавляется к полному множеству, обе variant синхронны.
        existing = _merge_no_proxy(env.get("NO_PROXY", ""), env.get("no_proxy", ""))
        for k in NO_PROXY_KEYS:
            env[k] = _merge_no_proxy(existing, hosts)
    return _save(data)


def disable():
    """Удалить env.HTTPS_PROXY/HTTP_PROXY + provider-хосты из NO_PROXY. {ok, err}. Идемпотентно.

    Issue #307 (value-match provenance, #112): удаляем proxy-ключ ТОЛЬКО когда его значение ==
    наш managed прокси; чужое (корпоративный/ручной) не трогаем. Если force-enable раньше
    перезаписал чужое значение — восстанавливаем его из sidecar-backup и backup потребляем.
    NO_PROXY связан с НАШИМ прокси — стрипаем provider-хосты только когда сняли наш ключ.
    """
    data = _load()
    env = data.get("env") if isinstance(data, dict) else None
    if isinstance(env, dict):
        changed = False
        managed_removed = False
        for k in ENV_KEYS:
            if k in env and env[k] == _PROXY:
                del env[k]
                changed = True
                managed_removed = True
        if managed_removed:
            backup = _read_backup()
            if isinstance(backup, dict) and isinstance(backup.get("env"), dict):
                for k, v in backup["env"].items():
                    if k in ENV_KEYS and v != _PROXY:
                        env[k] = v
                try:
                    _backup_path().unlink()
                except OSError:
                    pass
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
