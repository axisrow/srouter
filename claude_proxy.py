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
# Issue #331: launchctl gui-домен (srouter-codex-env.sh) ставит ALL_PROXY/all_proxy =
# socks5h://127.0.0.1:10808 во ВСЕ GUI-процессы — в сессиях Claude Code это протекает в
# pip/requests: urllib.request.getproxies_environment() подхватывает all_proxy, requests
# select_proxy маппит 'all' на ВСЕ схемы → путь SOCKSProxyManager → TypeError
# PoolKey key_proxy_ssl_context (при shadowing urllib3 поверх vendored). Для CC единственное
# плечо = privoxy 8118, поэтому enable() НЕЙТРАЛИЗУЕТ all_proxy пустой строкой (не ставит
# SOCKS!) — канон #199 «снять env-прокси ОБА регистра»: нейтрализация там, где задумана.
# Чужое НЕпустое значение — FOREIGN (канон #307), перезапись только force с backup.
NEUTRAL_PROXY_KEYS = ("ALL_PROXY", "all_proxy")
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
        # Issue #307 round 2 (Codex cycle-review PR #328 finding 3): ошибка чтения/парсинга —
        # None («неизвестно»), НЕ {}: раньше битый JSON схлопывался в пустой конфиг и enable
        # молча перезаписывал ВЕСЬ чужой settings.json. Missing-файл — {} (легитимный путь
        # «настроить с нуля»). Валидный JSON не-object проходит как есть — вызывающий
        # откажет (чужой документ, не наш словарь).
        return None


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

    state (issue #307) — absent/managed-on/foreign/unknown: чужое значение HTTPS_PROXY/HTTP_PROXY
    это НЕ «не настроено», а отдельное состояние foreign; нечитаемый/битый/не-object JSON —
    unknown (Codex cycle-review PR #328 finding 3), а не «не настроено».
    provider_direct = хост ANTHROPIC_BASE_URL реально в NO_PROXY (провайдер идёт напрямую).
    Это сырой state компонента, НЕ probe — runtime-вердикт для doctor/gather_status делает
    health._claude_proxy_probe() с каноничным {status}.
    """
    data = _load()
    env = data.get("env") if isinstance(data, dict) else None
    if not isinstance(env, dict):
        unknown = data is None or not isinstance(data, dict)
        return {"enabled": False, "proxy": "",
                "state": _contract.UNKNOWN if unknown else _contract.ABSENT,
                "provider_direct": False, "no_proxy": "", "socks_neutralized": False}
    val = env.get("HTTPS_PROXY", "")
    no_proxy = env.get("NO_PROXY", "") or env.get("no_proxy", "")
    hosts = _base_url_hosts(data)
    # set-intersection (не substring) — 'z.ai' in 'api.z.ai' = True это substring-ложка.
    host_set = {h for h in hosts.split(",") if h}
    np_set = {h.strip().lower() for h in no_proxy.split(",") if h.strip()}
    provider_direct = bool(host_set & np_set)
    state = _contract.aggregate(
        _contract.classify(k in env, env.get(k, ""), _PROXY) for k in ENV_KEYS)
    # Issue #331: SOCKS-плечо нейтрализовано = оба neutral-ключа присутствуют с пустой строкой
    # (строгая форма: частичная нейтрализация — не нейтрализация, all_proxy без ALL_PROXY
    # всё ещё протекает в lower-first-стеки).
    socks_neutralized = all(k in env and env[k] == "" for k in NEUTRAL_PROXY_KEYS)
    return {"enabled": val == _PROXY, "proxy": val, "state": state,
            "provider_direct": provider_direct, "no_proxy": no_proxy,
            "socks_neutralized": socks_neutralized}


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

    Issue #307 round 2 (Codex cycle-review PR #328): нечитаемый/битый/не-object settings.json —
    честный отказ БЕЗ перезаписи файла (finding 3); state перечитывается с диска непосредственно
    перед записью — значение, появившееся в гонке между gate и save, не затирается (finding 4).
    """
    scheme = urlparse(_PROXY).scheme.lower()
    if scheme not in {"http", "https"}:
        return {"ok": False, "err": f"unsupported proxy scheme for Claude Code: {scheme or 'missing'}"}

    data = _load()
    if not isinstance(data, dict):
        return {"ok": False, "err": "settings.json нечитаем/битый/не JSON-object — "
                                    "перезапись чужого файла запрещена (issue #307)"}
    env = data.get("env")
    if not isinstance(env, dict):
        env = {}
        data["env"] = env

    state = _contract.aggregate(
        _contract.classify(k in env, env.get(k, ""), _PROXY) for k in ENV_KEYS)
    if _contract.needs_force(state) and not force:
        return _contract.conflict_result(state)

    # Issue #331: чужое НЕпустое all_proxy/ALL_PROXY — FOREIGN (канон #307), тот же контракт,
    # что у ENV_KEYS: отказ без мутации, перезапись только force с backup. Пустая строка —
    # НАША нейтрализация (managed value = ""), не foreign (classify тут не применим: он считает
    # present-пустую строку FOREIGN — presence != truthy #222, а для neutral-ключей пустота
    # ровно то значение, которое мы сами и ставим).
    foreign_neutral = {k: env[k] for k in NEUTRAL_PROXY_KEYS if k in env and env[k] != ""}
    if foreign_neutral and not force:
        return {"ok": False, "conflict": True, "state": state,
                "err": f"чужое непустое {','.join(sorted(foreign_neutral))} — перезапись только force (issue #307/#331)"}

    if force and (_contract.needs_force(state) or foreign_neutral):
        # Provenance: сохранить ЧУЖИЕ значения перед перезаписью (только сами proxy-ключи).
        foreign = {k: env[k] for k in ENV_KEYS if k in env and env[k] != _PROXY}
        foreign.update(foreign_neutral)
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

    # TOCTOU re-check (finding 4): снапшот proxy-ключей, на котором принято решение.
    # Presence отдельно от значения (AO review round 3): absent и JSON-null — РАЗНЫЕ
    # состояния (classify считает present-любое-значение foreign); иначе конкурентная
    # вставка HTTPS_PROXY: null после gate сравнялась бы с absent и была бы затёрта.
    decision_snapshot = {k: (k in env, env.get(k)) for k in ENV_KEYS + NEUTRAL_PROXY_KEYS}

    for k in ENV_KEYS:
        env[k] = _PROXY
    for k in NEUTRAL_PROXY_KEYS:
        env[k] = ""
    hosts = _base_url_hosts(data)
    if hosts:
        # Merge обе variant (NO_PROXY + no_proxy) + provider-хосты. Если брать только одну variant
        # (NO_PROXY or no_proxy), при рассинхронных значениях вторая теряется (a.com vs b.com).
        # Union обеих → provider-хост добавляется к полному множеству, обе variant синхронны.
        existing = _merge_no_proxy(env.get("NO_PROXY", ""), env.get("no_proxy", ""))
        for k in NO_PROXY_KEYS:
            env[k] = _merge_no_proxy(existing, hosts)

    # Re-read непосредственно перед записью: если proxy-ключи на диске изменились с момента
    # решения — решение устарело, отказываем (чужое значение, появившееся в гонке, не тронуто).
    fresh = _load()
    if not isinstance(fresh, dict):
        return {"ok": False, "err": "settings.json стал нечитаем во время операции — отказ (issue #307)"}
    fresh_env = fresh.get("env") if isinstance(fresh.get("env"), dict) else {}
    if {k: (k in fresh_env, fresh_env.get(k)) for k in ENV_KEYS + NEUTRAL_PROXY_KEYS} != decision_snapshot:
        return {"ok": False, "conflict": True, "state": state,
                "err": "settings.json изменился во время операции — повторите (issue #307)"}
    return _save(data)


def disable():
    """Удалить env.HTTPS_PROXY/HTTP_PROXY + provider-хосты из NO_PROXY. {ok, err}. Идемпотентно.

    Issue #307 (value-match provenance, #112): удаляем proxy-ключ ТОЛЬКО когда его значение ==
    наш managed прокси; чужое (корпоративный/ручной) не трогаем. Если force-enable раньше
    перезаписал чужое значение — восстанавливаем его из sidecar-backup и backup потребляем.
    NO_PROXY связан с НАШИМ прокси — стрипаем provider-хосты только когда сняли наш ключ.

    Issue #307 round 2 (Codex finding 2/3): нечитаемый/битый settings.json — отказ без мутации
    (не «успех»); sidecar-backup удаляется ТОЛЬКО после подтверждённой записи восстановленного
    значения — при упавшей _save() backup остаётся единственной копией чужого значения.
    """
    data = _load()
    if data is None:
        return {"ok": False, "err": "settings.json нечитаем/битый — отказ без мутации (issue #307)"}
    if not isinstance(data, dict):
        return {"ok": False, "err": "settings.json не JSON-object — отказ без мутации (issue #307)"}
    env = data.get("env") if isinstance(data, dict) else None
    if isinstance(env, dict):
        changed = False
        managed_removed = False
        for k in ENV_KEYS:
            if k in env and env[k] == _PROXY:
                del env[k]
                changed = True
                managed_removed = True
        # Issue #331: нейтрализация — наше пустое значение, снимаем как managed (value-match:
        # ТОЛЬКО пустую строку; чужое непустое all_proxy не трогаем — provenance #112/#307).
        # managed_removed НЕ поднимаем: NO_PROXY-strip/backup-restore связаны с proxy-ключами,
        # а не с нейтрализацией all_proxy.
        for k in NEUTRAL_PROXY_KEYS:
            if k in env and env[k] == "":
                del env[k]
                changed = True
        backup_consumed = False
        if managed_removed:
            backup = _read_backup()
            if isinstance(backup, dict) and isinstance(backup.get("env"), dict):
                for k, v in backup["env"].items():
                    if k in ENV_KEYS and v != _PROXY:
                        env[k] = v
                # Finding 2: backup удаляем ТОЛЬКО после подтверждённой записи (ниже) —
                # при упавшей _save() он остаётся единственной копией чужого значения.
                backup_consumed = True
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
            r = _save(data)
            if r["ok"] and backup_consumed:
                try:
                    _backup_path().unlink()
                except OSError as exc:
                    # Данные уже восстановлены в settings.json; сиротский backup не теря
                    # данных, но честно репортим, что cleanup не удался.
                    return {"ok": True, "err": f"backup cleanup failed: {str(exc)[:120]}"}
            return r
    return {"ok": True}  # уже чисто или файла нет — успех
