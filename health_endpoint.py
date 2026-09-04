"""Health-пробы для ANTHROPIC_BASE_URL endpoint: override-детект, xray-sync, runtime env живого CC.

Извлечено из health.py (issue #158 — разбиение крупного файла на модули по обязанностям).
health.py остаётся тонким фасадом: `from health_endpoint import *` ре-экспортирует все публичные
имена (канон star-import-reexport-contract) — существующие `health.<name>` и monkeypatch на
`health` module продолжают работать без изменений.
"""
import logging
import os
import re
from urllib.parse import urlparse

import local_state
import sys_probe

import health as _health_facade  # noqa: E402 — резолвит intra/inter-module вызовы через health для monkeypatch (канон #158)

_log = logging.getLogger("srouter.health")

# star-import re-export (канон star-import-reexport-contract) — см. health_probes.py докстринг __all__.
__all__ = [
    "_read_endpoint_config", "_endpoint_override_check", "_host_in_no_proxy",
    "_endpoint_direct_override", "_pids_env_readable", "_override_runtime_leak_pids",
    "_endpoint_xray_sync_check", "_read_runtime_endpoint_config", "_runtime_model_override_check",
    "_ENDPOINT_SYNC_STATE_PATH", "_ENDPOINT_SYNC_XRAY_PATH",
]

# Абсолютные пути: launchd/GUI PATH их не содержит (канон проекта).
PS = "/bin/ps"
LAUNCHCTL = "/bin/launchctl"

# ============================ #129: endpoint-override detection ============================

_DEFAULT_ANTHROPIC_HOST = "api.anthropic.com"


def _read_endpoint_config():
    """Читает ANTHROPIC_BASE_URL + NO_PROXY из всех источников (#129).

    Источники (по приоритету): shell env → ~/.claude/settings.json env → launchctl getenv.
    Managed/local/project settings scopes (Claude Code docs) — НЕ покрыты: srouter не имеет доступа
    к этим scope'ам из Doctor. Если ни один источник не задан → source="default" (предполагаем
    стандартный api.anthropic.com).
    Возвращает {base_url, no_proxy, source}. Не бросает.
    """
    import claude_proxy
    # settings.json env
    data = claude_proxy._load()
    env = data.get("env", {}) if isinstance(data, dict) else {}
    # launchctl getenv (gui-домен) — фолбэк если shell/settings пусты.
    lc_base = sys_probe.run(["/bin/launchctl", "getenv", "ANTHROPIC_BASE_URL"], timeout=3)
    lc_base_val = (lc_base.get("out") or "").strip() if not lc_base.get("timeout") else ""
    lc_noproxy = sys_probe.run(["/bin/launchctl", "getenv", "NO_PROXY"], timeout=3)
    lc_noproxy_val = (lc_noproxy.get("out") or "").strip() if not lc_noproxy.get("timeout") else ""
    base = os.environ.get("ANTHROPIC_BASE_URL", "") or env.get("ANTHROPIC_BASE_URL", "") or lc_base_val
    no_proxy = os.environ.get("NO_PROXY", "") or env.get("NO_PROXY", "") or lc_noproxy_val
    no_proxy += "," + (os.environ.get("no_proxy", "") or env.get("no_proxy", ""))
    source = ("shell" if os.environ.get("ANTHROPIC_BASE_URL")
              else "settings.json" if env.get("ANTHROPIC_BASE_URL")
              else "launchctl" if lc_base_val
              else "default")
    return {"base_url": base, "no_proxy": no_proxy, "source": source}


def _host_in_no_proxy(host, no_proxy):
    """hostname входит в NO_PROXY (exact или subdomain, НЕ substring)? Семантика #129.

    Не substring — lookalike-атака (evil-z.ai при NO_PROXY=z.ai) не проходит (канон #131 C2).
    Чистая функция: вынесена, чтобы _endpoint_override_check и _endpoint_direct_override (#329)
    разделили ОДНО определение членства (не два расходящихся парсера).
    """
    return any(
        h.strip() and (host == h.strip() or host.endswith("." + h.strip()))
        for h in no_proxy.split(",")
    )


def _endpoint_direct_override():
    """«CC ходит к endpoint напрямую BY DESIGN»? (#329, канон zai-direct-no-proxy).

    overridden=True только когда ANTHROPIC_BASE_URL задан, hostname != api.anthropic.com
    (exact, урок #131 lookalike) И hostname входит в NO_PROXY (direct-first) — тогда прямые
    соединения CC к endpoint намеренны и lsof-классификация «external = утечка» ложна.
    Владелец семантики NO_PROXY — этот модуль (канон route-scope-not-shared-validator):
    _claude_proxy_probe переиспользует через health-фасад, не дублирует парсинг.
    Возвращает {overridden: bool, base_url: str, host: str}; не бросает (_read_endpoint_config
    сам fail-soft).
    """
    cfg = _health_facade._read_endpoint_config()
    base = cfg["base_url"]
    host = (urlparse(base).hostname or "").lower().rstrip(".") if base else ""
    if not host or host == _DEFAULT_ANTHROPIC_HOST:
        return {"overridden": False, "base_url": base, "host": host}
    return {"overridden": _host_in_no_proxy(host, cfg["no_proxy"]),
            "base_url": base, "host": host}


def _override_runtime_leak_pids(external_pids, rt, readable, override_host):
    """#337: какие external-PID доказуемо утекают ПРИ активном override-гейте?

    Гейт #329 схлопывал ВСЕ external в unknown «проба неприменима», но прямое соединение
    намеренно только у PID, чей runtime env СОДЕРЖИТ override. Чистая функция (обе ветки
    тестируемы, канон detector-must-be-function-not-constant): PID утекает, когда
      - env читается (pid в `readable`, критерий _pids_env_readable из #335), И
      - его ANTHROPIC_BASE_URL НЕ на override-хосте (пустой/нестандартный = CC идёт на
        стандартный или чужой endpoint напрямую — это утечка, класс дивергенции #143).
    PID с env на override-хосте — by design; нечитаемый — атрибуция невозможна. Оба не утечка.
    rt — результат _read_runtime_endpoint_config (per_pid с ANTHROPIC_*); override_host —
    hostname файлового override. Никогда не бросает; возвращает подмножество external_pids.
    """
    leaks = set()
    for pid in external_pids:
        if pid not in readable:
            continue
        base = rt.get("per_pid", {}).get(pid, {}).get("ANTHROPIC_BASE_URL", "")
        host = (urlparse(base).hostname or "").lower().rstrip(".") if base else ""
        if host != (override_host or ""):
            leaks.add(pid)
    return leaks


def _endpoint_override_check():
    """Детектит ANTHROPIC_BASE_URL override + NO_PROXY masking (#129).

    Если hostname BASE_URL = api.anthropic.com (exact match) → ok (стандартный).
    Иначе → info (WARN). Если домен в NO_PROXY → info «CC ходит напрямую».
    Урок #127: doctor был слеп к endpoint-override → ложный SOCKS5-тест.
    cycle-review #131 C2: exact hostname match (не substring — lookalike-атака).
    """
    cfg = _health_facade._read_endpoint_config()
    base = cfg["base_url"]
    if not base:
        return {"status": "ok", "detail": f"стандартный endpoint ({_DEFAULT_ANTHROPIC_HOST})"}
    host = (urlparse(base).hostname or "").lower().rstrip(".")
    if host == _DEFAULT_ANTHROPIC_HOST:
        return {"status": "ok", "detail": f"стандартный endpoint ({_DEFAULT_ANTHROPIC_HOST})"}
    if _host_in_no_proxy(host, cfg["no_proxy"]):
        return {"status": "info",
                "detail": f"endpoint override: {base} (в NO_PROXY → CC ходит напрямую, "
                          f"прокси/туннель-проверки нерелевантны)"}
    return {"status": "info", "detail": f"endpoint override: {base} (нестандартный endpoint)"}


# ============================ #200: рассинхрон endpoint local.json ↔ xray config ============================
# Doctor видит РЕАЛЬНЫЙ endpoint (из рабочего xray config), не placeholder из local.json. Когда
# active_node.endpoint_host — test-IP 203.0.113.x (RFC 5737), а рабочий xray config держит реальный
# VPS-address — это рассинхрон источника правды: local.json (canonical) врёт, xray — правда. Канон
# verify-dont-guess (показываем реальный, не placeholder), srouter-is-configurator (local.json=canonical).
# Чек info-only (как endpoint-override): картина для диагностики + подсказка `srouter sync`, не сбой стека.
# Path-константы module-level — чтобы тесты могли перенаправить в tmp через monkeypatch (канон #155/#165).
_ENDPOINT_SYNC_STATE_PATH = None  # None → local_state default (рядом с модулем)
_ENDPOINT_SYNC_XRAY_PATH = local_state.XRAY_CONFIG_PATH


def _endpoint_xray_sync_check(state_path=None, xray_config_path=None):
    """Детектит рассинхрон endpoint_host (local.json) ↔ address (рабочий xray config) — #200.

    Возвращает {status, detail}:
      ok   — endpoint активного узла (canonical state) == address из xray (синхрон);
      warn — рассинхрон: local.json — placeholder test-IP, а xray держит реальный address. detail
             показывает РЕАЛЬНЫЙ endpoint (из xray) и подсказку `srouter sync` (импорт в local.json);
      warn — рабочий xray config СУЩЕСТВУЕТ, но битый (unreadable) или без outbound tag=active
             (no_active) — НЕ fresh install, это аномалия конфига, требующая внимания;
      info — нет xray config вовсе (absent, fresh install) / нет активного узла (apply не настроен).
    Канон: local.json = canonical источник, но рабочий xray — runtime-истина. apply-защита (#200
    в install_lib) блокирует перезапись рабочего config placeholder'ом; doctor показывает картину.
    Не бросает (probe-канон: compare_endpoint_with_xray сам fail-soft).
    """
    sp = state_path or _health_facade._ENDPOINT_SYNC_STATE_PATH
    xp = xray_config_path or _health_facade._ENDPOINT_SYNC_XRAY_PATH
    cmp = local_state.compare_endpoint_with_xray(state_path=sp, xray_config_path=xp)
    local, xray, placeholder, xray_status = cmp["local"], cmp["xray"], cmp["placeholder"], cmp["xray_status"]
    # нет активного узла в local.json → endpoint не настроен через srouter; sync-чек неприменим
    # (даже если рабочий xray есть — apply не использует local.json без узла). info, не warn.
    if not local:
        return {"status": "info",
                "detail": "нет активного узла / endpoint_host в local.json (sync-чек неприменим)"}
    # #200 regression: read_xray_active_address кладёт address="" И для absent (файла нет), И для
    # unreadable (файл есть, но битый), И для no_active (файл есть, валиден, но без tag=active) —
    # `if not xray:` раньше схлопывал все три в одно сообщение "fresh install", маскируя реальную
    # аномалию (config СУЩЕСТВУЕТ, просто не тот). xray_status различает их (canonical источник —
    # local_state_xray.read_xray_active_address докстринг) — разветвляем по нему, не по пустой строке.
    if xray_status == "absent":
        # файла вообще нет → local.json единственный источник (fresh install), дрейфа нет.
        return {"status": "info",
                "detail": f"endpoint {local}: рабочий xray config отсутствует (fresh install) — "
                          f"sync-чек неприменим, local.json — единственный источник"}
    if xray_status == "unreadable":
        return {"status": "warn",
                "detail": f"endpoint {local}: рабочий xray config существует, но повреждён/не "
                          f"парсится — apply может fail-closed, проверь конфиг xray"}
    if xray_status == "no_active":
        return {"status": "warn",
                "detail": f"endpoint {local}: рабочий xray config существует, но без outbound "
                          f"tag=active (возможно сгенерирован не через gen_xray_config, или "
                          f"устаревшим форматом); endpoint из local.json ({local}) не подтверждён "
                          f"— сверь runtime вручную"}
    if cmp["synced"]:
        return {"status": "ok",
                "detail": f"endpoint синхронизирован: local.json == xray == {local}"}
    # рассинхрон: показываем РЕАЛЬНЫЙ endpoint из xray (не placeholder), warn + подсказка sync
    if placeholder:
        return {"status": "warn",
                "detail": (f"рассинхрон: local.json endpoint_host={local} (placeholder TEST-NET), "
                           f"рабочий xray config держит РЕАЛЬНЫЙ address={xray}. "
                           f"Doctor/apply видят реальный ({xray}). Запусти `srouter sync` "
                           f"(импорт address из xray в local.json) или проверь active_node.")}
    # оба реальных, но разные — detect-only, без авто-sync (выбор пользователя)
    return {"status": "warn",
            "detail": (f"рассинхрон: local.json endpoint_host={local}, рабочий xray={xray} "
                       f"(оба реальные). `srouter sync` НЕ применит — реши вручную, какой правдив.")}


# ============================ #143: runtime env живого CC-процесса (ps eww) ============================
# Сценарий #143: CC запустился с ANTHROPIC_BASE_URL / ANTHROPIC_DEFAULT_*_MODEL override; затем
# пользователь сбросил settings.json/shell/launchctl на стандартные, а ЖИВОЙ процесс сохранил env.
# Doctor читает файлы (_read_endpoint_config, #129) → видит «стандартный endpoint», а CC реально
# ходит на подменённый сервер. Файлы слепы к runtime-override — нужно env ЖИВОГО процесса.
# На macOS `ps eww -p <pid>` читает env процесса ТОГО ЖЕ UID (эмпирически подтверждено: живой CC
# отдаёт ANTHROPIC_BASE_URL=api.z.ai + ANTHROPIC_DEFAULT_*_MODEL=glm-*). Чужой/системный UID →
# пустой вывод (fail-soft). НЕ противоречит докстрингу _codex_proxy_probe: там env
# чужого codex-процесса не читается → lsof-классификация; здесь — same-UID CC.

# Regex извлекает ANTHROPIC_* vars из вывода `ps eww`. Env разделяется ПРОБЕЛОМ (не \012); [^ ]*
# обрезает значение до следующего пробела. Ключи — только ANTHROPIC_* (наш trust boundary).
_RUNTIME_ENV_RE = re.compile(r"(ANTHROPIC_[A-Z_]+)=([^ ]*)")
# Каждая строка процесса в `ps eww` начинается с PID-цифр (`^[0-9]+ `); заголовок отбрасывается.
# Per-PID секционирование (см. _read_runtime_endpoint_config) — не слить env разных процессов.
_PID_LINE_RE = re.compile(r"^\s*(\d+)\s")
# Токен env в выводе `ps eww`: ALL_CAPS_NAME=значение (граница — пробел/начало строки). Отличает
# «ps напечатал env» от строки команды без окружения (чужой UID/sandbox): CLI-аргументы вида
# --flag=value или пути в нижнем регистре не матчатся (#329).
_GENERIC_ENV_TOKEN_RE = re.compile(r"(?:^|\s)([A-Z][A-Z0-9_]{1,})=")


def _read_runtime_endpoint_config():
    """Читает env ЖИВОГО CC-процесса через `ps eww` (#143), per-PID.

    Возвращает {per_pid, pids, readable}:
      - readable=False, pids=[]   — CC не запущен (ps -axo пуст) ИЛИ ps-timeout;
      - readable=False, pids=[..] — CC запущен, но ps eww пуст/timeout/нет ANTHROPIC_* (чужой
        UID/sandbox — PID сохранены для forensics в detail чека);
      - readable=True, per_pid={pid: {KEY: value}} — env прочитан ПО PID'ам.
    per_pid: {pid: {ANTHROPIC_*: value}} для каждого CC PID (включая секреты — doctor доверяет
    тому же UID; фильтрацию секретов делает чек, НЕ эта функция). Per-PID, не merged — иначе
    dict(findall) перезаписал бы дубликаты ключей и ОДИН override-процесс маскировался бы
    standard-процессом (cycle-review Codex: false-negative ровно в сценарии #143 — несколько
    живых CC-сессий штатны). Один ps eww батчем; вывод секционируется по строкам `^[0-9]+ `.
    """
    pids = _health_facade._claude_code_pids()
    if not pids:
        return {"per_pid": {}, "pids": [], "readable": False}
    # Один ps eww на ВСЕ PID батчем (запятая, как lsof в _claude_proxy_probe). ps eww отдаёт
    # каждую строку процесса с PID в начале — секционируем per-PID, не одним dict().
    r = sys_probe.run([PS, "eww", "-p", ",".join(pids)], timeout=3)
    if r.get("timeout") or not (r.get("out") or "").strip():
        return {"per_pid": {}, "pids": pids, "readable": False}
    per_pid = {}
    cur_pid, cur_lines = "", []
    for line in (r["out"] or "").splitlines():
        m = _PID_LINE_RE.match(line)
        if m:  # новая строка процесса — фиксируем предыдущую
            if cur_pid:
                per_pid[cur_pid] = dict(_RUNTIME_ENV_RE.findall("\n".join(cur_lines)))
            cur_pid, cur_lines = m.group(1), [line]
        elif cur_pid:
            cur_lines.append(line)  # продолжение env того же PID (маловероятно, но устойчиво)
    if cur_pid:
        per_pid[cur_pid] = dict(_RUNTIME_ENV_RE.findall("\n".join(cur_lines)))
    # НИ у одного PID нет ANTHROPIC_* (мусор/неполный env/чужой контекст) — evidence нет → НЕ
    # readable. Иначе чек дал бы ложный ok «стандартный endpoint» без proof (verify-dont-guess).
    if not any(per_pid.values()):
        return {"per_pid": {}, "pids": pids, "readable": False}
    return {"per_pid": per_pid, "pids": pids, "readable": True}


def _pids_env_readable(pids):
    """Какие из PID отдают env через `ps eww` (same-UID)? (#329 «Дополнительно»).

    Возвращает set PID-строк — подмножество pids, чьи секции в выводе `ps eww` содержат хотя бы
    один ALL_CAPS= токен (см. _GENERIC_ENV_TOKEN_RE). Чужой UID/sandbox → строки без env или
    процесса нет в выводе → НЕ читается; пустой вывод/timeout/пустой список → пустое set.
    Критерий «читается», не «имеет HTTPS_PROXY»: отсутствие переменной в читаемом env — само
    по себе диагноз (процесс без прокси-конфига); нечитаемость же делает проверку неприменимой.
    Секционирование — тот же канон _PID_LINE_RE, что в _read_runtime_endpoint_config.
    """
    if not pids:
        return set()
    r = sys_probe.run([PS, "eww", "-p", ",".join(pids)], timeout=3)
    if r.get("timeout"):
        return set()
    readable = set()
    cur_pid = ""
    for line in (r.get("out") or "").splitlines():
        m = _PID_LINE_RE.match(line)
        if m:
            cur_pid = m.group(1)
        if cur_pid and _GENERIC_ENV_TOKEN_RE.search(line):
            readable.add(cur_pid)
    return readable


def _runtime_model_override_check():
    """Детектит env-override ЖИВОГО CC и расхождение runtime vs файлов doctor (#143).

    Возвращает {status, detail}. status:
      - "unknown" — CC не запущен / env не читается (fail-soft; info-only, как _claude_proxy_probe idle);
      - "ok"      — ВСЕ CC PID'ы на api.anthropic.com, без model-substitution, без расхождения с файлами;
      - "info"    — ХОТЯ БЫ ОДИН CC PID с override/substitution/расхождением.
    Per-PID агрегация: ЛЮБОЙ override-PID = unsafe runtime (стандартный процесс его НЕ маскирует —
    cycle-review Codex false-negative fix). Сигналы per-PID (накапливаются в detail):
      (a) runtime base_url override на нестандартный хост;
      (b) ANTHROPIC_DEFAULT_* присутствуют → slot-mapping модели подменён (даже при чистом base_url);
      (c) stale-process: runtime override есть, а файлы doctor ЧИСТЫ → ровно сценарий #143
          (живой CC держит override после сброса настроек);
      (d) runtime != files (PID и файлы на разных нестандартных endpoint'ах).
    Канон info-only: НЕ driver (как _endpoint_override_check) — картина для диагностики (#143 п.1+4).
    Security: detail выводит ТОЛЬКО base_url и ANTHROPIC_DEFAULT_* — никогда ANTHROPIC_API_KEY /
    ANTHROPIC_AUTH_TOKEN (doctor доверяет тому же UID, но логи/terminal не должны содержать секреты).
    """
    rt = _health_facade._read_runtime_endpoint_config()
    if not rt["readable"]:
        detail = ("Claude Code не запущен" if not rt["pids"]
                  else f"env живого CC не читается (PID {','.join(rt['pids'])}) — возможно чужой UID/sandbox")
        return {"status": "unknown", "detail": detail}

    cfg = _health_facade._read_endpoint_config()  # что видит doctor по файлам/сессии
    files_base = cfg["base_url"]
    files_host = (urlparse(files_base).hostname or "").lower().rstrip(".")
    files_clean = (not files_base) or files_host == _DEFAULT_ANTHROPIC_HOST

    signals = []
    ok_pids = []
    unreadable_pids = []  # PID без распарсенного env (per-process sandbox/permission/partial ps).
    for pid in rt["pids"]:
        env = rt["per_pid"].get(pid, {})
        if not env:
            # этого PID env не прочитан. Override-сигналов по нему нет, но и evidence «standard» тоже
            # нет — override-PID мог быть им (Codex c2: standard-PID не должен маскировать). Не ok.
            unreadable_pids.append(pid)
            continue
        runtime_base = env.get("ANTHROPIC_BASE_URL", "")
        runtime_host = (urlparse(runtime_base).hostname or "").lower().rstrip(".")
        model_keys = {k: v for k, v in env.items() if k.startswith("ANTHROPIC_DEFAULT_")}
        runtime_overridden = bool(runtime_base and runtime_host != _DEFAULT_ANTHROPIC_HOST)
        pid_signals = []
        if runtime_overridden:
            pid_signals.append(f"runtime endpoint: {runtime_base}")
        if model_keys:
            pairs = ", ".join(f"{k}={v}" for k, v in sorted(model_keys.items()))
            pid_signals.append(f"model substitution: {pairs}")
        if runtime_overridden and files_clean:
            pid_signals.append("stale process (override после сброса настроек, runtime != files)")
        if runtime_base and files_base and runtime_base != files_base:
            pid_signals.append(f"runtime != files ({runtime_base} vs {files_base})")
        if pid_signals:
            signals.append(f"PID {pid}: " + "; ".join(pid_signals))
        else:
            ok_pids.append(pid)

    pid_list = ",".join(rt["pids"])
    # Override приоритетнее (info). Но если override не найден и ХОТЯ БЫ ОДИН PID без evidence →
    # unknown: override-PID мог быть непрочитанным, а standard-PID его бы маскировал ложным ok
    # (verify-dont-guess: нет evidence для PID = не ok, Codex c2 false-negative fix). ok — только
    # когда ВСЕ PID прочитаны и standard.
    if not signals:
        if unreadable_pids:
            return {"status": "unknown",
                    "detail": (f"env не прочитан для PID {','.join(unreadable_pids)} "
                               f"(sandbox/права/partial ps) — override-PID мог быть непрочитанным; "
                               f"остальные standard: PID {','.join(ok_pids)}")}
        return {"status": "ok",
                "detail": f"runtime: стандартный endpoint, без model-substitution (PID {pid_list})"}
    detail = f"runtime override (PID {pid_list}): " + " | ".join(signals)
    extras = []
    if ok_pids:
        extras.append(f"остальные standard: PID {','.join(ok_pids)}")
    if unreadable_pids:
        extras.append(f"env не прочитан: PID {','.join(unreadable_pids)}")
    if extras:
        detail += " (" + "; ".join(extras) + ")"
    return {"status": "info", "detail": detail}
