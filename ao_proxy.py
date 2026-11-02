"""Синхронизация scmProxyUrl AO-демона (Agent Orchestrator) с прокси-конфигурацией srouter.

Зачем (issue #436): десктоп-демон AO ходит в GitHub/GitLab напрямую и ловит RST-штормы
флапающего прямого канала. У AO есть штатная ручка scmProxyUrl (применяется к SCM-клиентам
демона hot, без рестарта — agent-orchestrator#155), но дефолт «empty → env-прокси» не работает:
.app стартует с чистым env. Управляющий слой — srouter, по пер-тул pathMatch'у
(git_proxy/go_proxy/vscode_proxy).

API AO сверено с OpenAPI демона (агрегировано в бинарнике; живой GET подтверждает):
  чтение — GET  /api/v1/settings            → SettingsResponse.scmProxyUrl (строка);
  запись — PATCH /api/v1/settings/scm-proxy, тело {"url": "<url>"} — схема
           UpdateScmProxyURLRequest (поле url, НЕ scmProxyUrl; пустая строка = прямой канал).
Обнаружение демона — ~/.ao/running.json {"pid", "port"} (тот же файл, что читает ao CLI).

Значение по контракту srouter:
  - туннель → socks5h://127.0.0.1:10808 (канон SCM-класса: git_proxy/codex ходят в xray
    SOCKS5h — remote-DNS мимо GFW и без лишнего privoxy-хопа; пример из OpenAPI AO совпадает);
  - «напрямую» → пустая строка. В srouter «напрямую» для SCM-хостов — это github-direct
    split (`srouter routing github-direct on`): пользователь выразил «SCM мимо туннеля» —
    демон посылается по тому же прямому пути (acceptance #436 «режим напрямую очищает
    scmProxyUrl»). Состав split читается из live xray-config (local_state.github_direct_status).

Запись идемпотентна: GET первым — значение уже верное → PATCH нет (нулевой шум в БД демона);
после PATCH — read-back verify (канон go_proxy). Демон не запущен (нет running.json / порт
закрыт) → тихий skip {ok: True, skipped: not_running} — применится при следующей смене
конфига. Sync НИКОГДА не бросает (fire-and-forget из CLI/dashboard-хвостов мутаций).

Env-override (more-options-better, канон SROUTER_VSCODE_SETTINGS):
  SROUTER_AO_BASE_URL      — прямой URL демона (мимо running.json; дев-старты, тесты);
  SROUTER_AO_RUNNING_JSON  — другой путь до running.json.

Проксирует ТОЛЬКО SCM-клиентов демона (GitHub/GitLab); LLM-провайдеры демона ручкой не
затрагиваются — NO_PROXY-исключения на стороне AO не нужны (by design, issue #436).

Это dashboard-модуль, НЕ root-helper (там свой stdlib-only паритет — shared-код не тащить).
"""
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

# Единый источник правды по портам прокси — dashboard_common (issue #155). except SystemExit
# (НЕ BaseException): без srouter_config.py модуль обязан импортироваться (install-путь),
# а не падать (канон git_proxy/vscode_proxy/proxy_effective).
try:
    from dashboard_common import SOCKS_PROXY_URL as _PROXY
except SystemExit:  # pragma: no cover
    _PROXY = "socks5h://127.0.0.1:10808"
PROXY = _PROXY  # контракт для тестов/health

SETTINGS_PATH = "/api/v1/settings"
SCM_PROXY_PATH = "/api/v1/settings/scm-proxy"
DEFAULT_RUNNING_JSON = Path.home() / ".ao" / "running.json"
TIMEOUT = 3


def _daemon_base_url(running_json=None):
    """URL демона из running.json: http://127.0.0.1:<port>. None = демона нет/файл битый.

    SROUTER_AO_BASE_URL сильнее файла (дев-старты демона на нестандартном порту).
    pid не проверяем: мёртвый pid с файлом на месте даёт connection refused на HTTP —
    тот же тихий skip, отдельная liveness-проба не нужна.
    """
    override = os.environ.get("SROUTER_AO_BASE_URL", "").strip()
    if override:
        return override.rstrip("/")
    path = Path(running_json) if running_json else _running_json_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        port = int(data["port"])
        if not 1 <= port <= 65535:
            return None
        return f"http://127.0.0.1:{port}"
    except (OSError, ValueError, TypeError, KeyError):
        return None


def _running_json_path():
    override = os.environ.get("SROUTER_AO_RUNNING_JSON", "").strip()
    return Path(override) if override else DEFAULT_RUNNING_JSON


def _request(method, url, *, body=None, timeout=TIMEOUT):
    """Один HTTP-вызов к демону. {status: int|None, data: dict|None, err: str}.

    err="connection_refused" — демон не слушает порт (класс «не запущен»).
    Не бросает: urllib.error/OSеrror/JSON-мусор — все схлопываются в err.
    """
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            try:
                parsed = json.loads(raw) if raw else {}
            except (ValueError, UnicodeDecodeError):
                parsed = None
            return {"status": resp.status, "data": parsed, "err": ""}
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "data": None, "err": f"http_{exc.code}"}
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", None)
        refused = isinstance(reason, ConnectionRefusedError) or "Refused" in str(reason or "")
        return {"status": None, "data": None,
                "err": "connection_refused" if refused else str(reason or exc)}
    except OSError as exc:
        return {"status": None, "data": None, "err": str(exc)[:150] or exc.__class__.__name__}


def _current_scm_proxy(base, timeout):
    """Текущее scmProxyUrl демона. (value|None, err): value None при любой ошибке чтения."""
    r = _request("GET", base + SETTINGS_PATH, timeout=timeout)
    if r["err"]:
        return None, r["err"]
    data = r["data"] if isinstance(r["data"], dict) else {}
    return str(data.get("scmProxyUrl") or ""), ""


def desired_url(github_status=None):
    """Желаемое scmProxyUrl по контракту srouter. Чистая функция (статус — параметр).

    github-direct split в direct («SCM-хосты напрямую») → ""; иначе socks5h-туннель.
    Неизвестный/нечитаемый статус (ok=False) — туннель: прокси-контракт srouter дефолтен,
    а тихая очистка отрезала бы демон от туннеля на фоне читаемого конфига.
    """
    st = github_status if github_status is not None else _github_direct_status()
    if isinstance(st, dict) and st.get("ok") and st.get("split") and st.get("direct"):
        return ""
    return PROXY


def _github_direct_status():
    """Состав github-direct split из live xray-config. Не бросает; lazy import — фасад
    local_state тяжёлый и тянет xray-константы (цикл ao_proxy ⇄ local_state не нужен)."""
    try:
        import local_state
        return local_state.github_direct_status()
    except Exception:  # noqa: BLE001 — sync не имеет права падать из-за чтения статуса
        return {"ok": False, "err": "github_direct_status_failed"}


def sync(*, base_url=None, running_json=None, timeout=TIMEOUT, github_status=None):
    """Держать scmProxyUrl демона равным desired_url(). Идемпотентно, не бросает.

    {ok, url, changed?|skipped?|err?}
      changed=True   — PATCH применён и подтверждён read-back;
      changed=False  — значение уже верное (запись не нужна);
      skipped        — "not_running": демона нет — тихий skip (issue #436);
      ok=False       — демон ответил ошибкой (API/verify) — честный err, не тихо.
    """
    desired = desired_url(github_status)
    result = {"ok": True, "url": desired}
    base = base_url or _daemon_base_url(running_json)
    if not base:
        result["skipped"] = "not_running"
        return result

    current, err = _current_scm_proxy(base, timeout)
    if err == "connection_refused":
        result["skipped"] = "not_running"
        return result
    if not err and current == desired:
        result["changed"] = False
        return result

    r = _request("PATCH", base + SCM_PROXY_PATH, body={"url": desired}, timeout=timeout)
    if r["err"] == "connection_refused":
        result["skipped"] = "not_running"
        return result
    if r["err"] or r["status"] != 200:
        result["ok"] = False
        result["err"] = f"patch failed: {r['err'] or r['status']}"
        return result

    current, err = _current_scm_proxy(base, timeout)
    if err or current != desired:
        result["ok"] = False
        result["err"] = f"read-back verify failed: {err or f'scmProxyUrl={current!r}'}"
    else:
        result["changed"] = True
    return result


def disable(*, base_url=None, running_json=None, timeout=TIMEOUT):
    """Снять НАШЕ значение scmProxyUrl (== PROXY) — uninstall-путь (канон git_proxy.disable).

    Value-match provenance (#112): чужое/пустое значение не трогаем — демон мог быть
    настроен вручную на корпоративный прокси. Демон не запущен → тихий skip: после
    установки srouter заново первый же sync запишет актуальное значение. Не бросает.
    """
    base = base_url or _daemon_base_url(running_json)
    if not base:
        return {"ok": True, "skipped": "not_running"}
    current, err = _current_scm_proxy(base, timeout)
    if err == "connection_refused":
        return {"ok": True, "skipped": "not_running"}
    if err:
        return {"ok": False, "err": f"read failed: {err}"}
    if current != PROXY:
        return {"ok": True, "changed": False, "url": current}
    r = _request("PATCH", base + SCM_PROXY_PATH, body={"url": ""}, timeout=timeout)
    if r["err"] == "connection_refused":
        return {"ok": True, "skipped": "not_running"}
    if r["err"] or r["status"] != 200:
        return {"ok": False, "err": f"patch failed: {r['err'] or r['status']}"}
    return {"ok": True, "changed": True}
