"""Health-пробы для dev-workflow: VSCode/Cursor scoped SOCKS5 (codex-расширение), gh/git direct.

Извлечено из health.py (issue #158 — разбиение крупного файла на модули по обязанностям).
health.py остаётся тонким фасадом: `from health_devworkflow import *` ре-экспортирует все публичные
имена (канон star-import-reexport-contract) — существующие `health.<name>` и monkeypatch на
`health` module продолжают работать без изменений.
"""
from pathlib import Path
import logging
from urllib.parse import urlparse

import git_proxy  # git github-proxy: managed SOCKS5 xray в ~/.gitconfig (#130, инцидент 2026-10-10)

_log = logging.getLogger("srouter.health")

# star-import re-export (канон star-import-reexport-contract) — см. health_probes.py докстринг __all__.
__all__ = ["_vscode_proxy_check", "GH_DIRECT_HINT", "_github_direct_check",
           "_git_proxy_route_check"]

# ============================ #185: scoped SOCKS5 для codex через VSCode http.proxy ============================


def _vscode_proxy_check():
    """Scoped SOCKS5 для codex-расширения openai.chatgpt через VSCode `http.proxy` (#185).

    Расширение openai.chatgpt запускает свой codex-binary (мимо wrapper), наследует HTTP_PROXY=privoxy
    из ~/.claude/settings.json → privoxy рвёт WS (#96/#120). Scoped-фикс: VSCode http.proxy=socks5h://10808
    → расширение строит HTTP_PROXY/HTTPS_PROXY В ENV codex-процессА (verify из extension.js), CC не трогает.
    Чек читает user-settings.json (Code+Cursor) и сверяет http.proxy.

    Возвращает {status, detail}:
      ok      — ВСЕ настроенные (present+proxy) settings.json содержат socks5h://10808 (#309: чек
                проверяет все редакторы, не возвращается на первом совпавшем);
      unknown — ни одного settings.json нет (редактор не установлен) — info-only (как desktop-proxy);
      down    — http.proxy есть, но НЕ socks5 хотя бы у одного редактора — даже при верном втором
                (#309: ранний ok перекрывал сломанного; privoxy/HTTP рвёт WS #120, или чужой
                корпоративный) — driver.
    Чек ВСЕГДА info-only (как endpoint-override): VSCode может быть не установлен, srouter-stack от этого
    не падает. ok/down — картина scoped-маршрута codex для диагностики, не driver агрегированного вердикта.
    """
    try:
        import vscode_proxy
    except ImportError as exc:
        _log.debug("vscode_proxy недоступен: %s — check пропущен", exc)
        return {"status": "unknown", "detail": "vscode_proxy недоступен — check пропущен"}
    st = vscode_proxy.status()
    paths = st.get("paths") or {}
    present = {p: info for p, info in paths.items() if info.get("present")}
    if not present:
        return {"status": "unknown",
                "detail": "VSCode/Cursor user-settings не найдены — редактор не установлен (scoped http.proxy неприменим)"}
    # #309 (1.2): проверяем ВСЕ present-редакторы, не возвращаемся на первом совпавшем —
    # ранний ok перекрывал сломанного редактора (сценарий #120: Code=socks5 + Cursor=privoxy-http
    # давал ok, сломанный даже не попадал в detail; down-ветка была недостижима при хоть одном
    # верном — канон detector-must-be-function-not-constant).
    socks_ok = [p for p, info in present.items()
                if urlparse(info.get("proxy", "")).scheme.lower() in {"socks", "socks5", "socks5h"}]
    # http.proxy задан, но НЕ socks5 хотя бы у одного → down (privoxy/HTTP рвёт WS, или чужой прокси
    # мимо xray). Сломанный редактор не «перекрывается» верным — все перечисляются.
    bad = [(p, info["proxy"]) for p, info in present.items()
           if info.get("proxy") and p not in socks_ok]
    if bad:
        bad_str = ", ".join(f"{Path(p).parent.parent.name}={proxy}" for p, proxy in bad)
        ok_names = ", ".join(Path(p).parent.parent.name for p in socks_ok)  # 'Code' / 'Cursor'
        ok_note = f"; верные: {ok_names}" if socks_ok else ""
        return {"status": "down",
                "detail": f"VSCode http.proxy НЕ SOCKS5 ({bad_str}){ok_note} — codex рвёт WS через privoxy/чужой (#120)"}
    if socks_ok:
        names = ", ".join(Path(p).parent.parent.name for p in socks_ok)  # 'Code' / 'Cursor'
        return {"status": "ok", "detail": f"VSCode http.proxy=SOCKS5 10808 ({names}) — codex расширения гонит через xray (#185)"}
    # Файлы есть, http.proxy не задан совсем → unknown (scoped не настроен, но не сломан — info-only).
    return {"status": "unknown",
            "detail": "VSCode http.proxy не задан — codex расширения наследует privoxy из env (рвёт WS #120), scoped не активирован"}


# ============================ #199: gh/git VPS-независимый dev-workflow ============================

# Подсказка-текст для VPS-независимого gh/git — единый литерал, чтобы doctor и README говорили
# одно (канон — единый источник правды). РАЗДЕЛЯЕТ стеки: gh (Go, env-прокси) и git (git-config
# scoped proxy) — это РАЗНЫЕ источники прокси, им нужны РАЗНЫЕ команды (cycle-1 FIX Codex critical).
#
# Эмпирика (verify 2026-07-27): github TCP напрямую открыт (GFW не режет TCP); gh Go-стек обходит
# GFW TLS. НО прокси-источников два:
#   1. env: srouter ставит И uppercase (HTTP_PROXY), И lowercase (http_proxy) — Go httpproxy
#      fallback читает оба регистра. Снимать надо ВСЕ: HTTP_PROXY/http_proxy, HTTPS_PROXY/https_proxy,
#      ALL_PROXY/all_proxy, NO_PROXY/no_proxy.
#   2. git-config: `http.https://github.com.proxy` (git_proxy.enable, SOCKS5 xray 10808 — #130) —
#      env -u его НЕ трогает (verify: `git config --get-urlmatch` после env -u всё ещё показывает
#      прокси активным). Снимается `git -c http.https://github.com.proxy= <cmd>` (переопределение
#      на лету, пустое).
# gh repo clone делегирует внутреннему git → scoped git-config применяется к clone (не чистый gh-путь).
GH_DIRECT_HINT = (
    "gh (Go-стек) и git-over-https — РАЗНЫЕ стеки прокси, разные команды (verify 2026-07-27):\n"
    "  • gh: `env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY -u http_proxy -u https_proxy "
    "-u all_proxy -u no_proxy gh ...` — снять env-прокси ОБА регистра (Go fallback на lowercase).\n"
    "  • git over https: env -u НЕ трогает scoped git-config `http.https://github.com.proxy` → "
    "`git -c http.https://github.com.proxy= fetch|pull|push` (пустое значение перекрывает config).\n"
    "  • gh repo clone делегирует git → scoped config применяется; clone VPS-независим ТОЛЬКО через "
    "`git -c http.https://github.com.proxy=` (или `gh api`, или ssh:22 — github SSH открыт напрямую).\n"
    "github TCP напрямую открыт; gh Go-стек обходит GFW TLS (curl/git LibreSSL — нет). VPS-независимо (#199)."
)


def _github_direct_check():
    """Подсказка VPS-независимого dev-workflow для gh/git (issue #199). info-only ВСЕГДА.

    2026-09-30 багфикс: раньше чек читал ТОЛЬКО git_proxy.status() (scoped urlmatch-ключ) и на
    живой машине рапортовал «git github-proxy выключен — github идёт напрямую» (ok), пока
    бесхозный глобальный http.proxy=8118 реально проксировал git через privoxy, а локальные
    override'ы репо наоборот глушили глобальное. Теперь вердикт строится на
    git_proxy.effective_proxy() — композер ВСЕХ слоёв по приоритету git (local urlmatch >
    global urlmatch > global generic http.proxy/https.proxy > env): warn для ЛЮБОГО активного
    слоя с именем слоя и источника, ok только когда эффективно direct. Канон
    detector-must-be-function-not-constant: вердикт по эффективному значению, не по одному слою.

    Диагноз #199 (verify, эмпирически): github доступен напрямую через gh — Go HTTP/TLS-стек gh
    обходит GFW TLS-блокировку (в отличие от curl/git на LibreSSL + системном resolver). git
    через прокси зависит от VPS: мёртвый VPS = git timeout. Подсказка РАЗДЕЛЯЕТ стеки (cycle-1
    FIX): gh → снять env-прокси (оба регистра) через `env -u`; git-over-https → env -u НЕ трогает
    git-config, нужен `git -c http.https://github.com.proxy=`.

    Предикт = статичный git-config (verify-don't-guess — не догадки о таймаутах, а проверяемый
    факт конфигурации). Чек info-only ВСЕГДА (как endpoint-override): git-proxy-настройка — это
    scoped-конфиг, не сбой стека; warn/ok/unknown НЕ роняют агрегированный вердикт — это картина
    для диагностики dev-workflow, не driver. Канон: verify-don't-guess, srouter-critical-infra-24-7
    (dev-workflow не должен зависеть от VPS — github-операции переживают смерть VPS).

    Возвращает {status, detail}:
      ok      — эффективный прокси пуст (direct или осознанный пустой local override);
      warn    — эффективный прокси ЕСТЬ → подсказка по конкретному слою (managed socks =
                зависимость от VPS; global-generic = бесхозный слой вне управления; env =
                переменная окружения; local-urlmatch = локальный override задаёт прокси;
                foreign = посторонний прокси, #309);
      unknown — effective_proxy unknown/ошибка/мусор (git config timeout/недоступен).
    Не бросает (probe-канон).
    """
    try:
        import git_proxy
        eff = git_proxy.effective_proxy()
    except (ImportError, RuntimeError, OSError, ValueError) as exc:
        # ImportError — модуль недоступен; RuntimeError/OSError/ValueError — сбой effective_proxy() (fail-soft).
        _log.debug("git_proxy недоступен/сбой: %s — check пропущен", exc)
        return {"status": "unknown", "detail": "git_proxy недоступен — check пропущен"}
    # isinstance ДО .get: git_proxy.status может вернуть None/не-dict (мусор) — .get упал бы
    # (probe-канон: чек не бросает). git_proxy.status при timeout отдаёт {status:"unknown"} — это
    # НЕ «git-proxy выключен» (enabled=False без status — другое; ниже разделяем).
    if not isinstance(eff, dict) or not eff.get("layer") or eff.get("layer") == "unknown":
        return {"status": "unknown",
                "detail": "git config недоступен (timeout/мусор) — github-direct check пропущен"}
    layer = eff.get("layer")
    proxy = eff.get("proxy") or ""
    # Осознанный direct: ни один слой не задан ИЛИ пустой локальный override (direct В ЭТОМ репо).
    if layer == "direct" or (layer == "local-urlmatch" and not proxy):
        return {"status": "ok",
                "detail": "git github-proxy выключен — github идёт напрямую (VPS-независимо). "
                          "Если gh/git timeout через прокси: " + GH_DIRECT_HINT}
    if layer == "local-urlmatch":
        return {"status": "warn",
                "detail": f"git→github идёт через ЛОКАЛЬНЫЙ override .git/config этого репо ({proxy}) — "
                          f"глобальное управление обойдено; снять: git config --local --unset "
                          f"http.https://github.com.proxy. " + GH_DIRECT_HINT}
    if layer == "global-urlmatch" and eff.get("state") == "foreign":
        return {"status": "warn",
                "detail": f"git github-proxy указывает на ЧУЖОЙ прокси ({proxy or '?'}) — "
                          f"git ходит через постороннего посредника, НЕ srouter-стек. Если это не "
                          f"осознанная настройка — снять: git config --global --unset "
                          f"http.https://github.com.proxy. "
                          + GH_DIRECT_HINT}
    if layer == "global-urlmatch":
        return {"status": "warn",
                "detail": f"git github-proxy ВКЛЮЧЁН ({proxy or 'xray SOCKS5 10808'}) → "
                          f"git pull/push зависит от VPS. " + GH_DIRECT_HINT}
    if layer == "global-generic":
        return {"status": "warn",
                "detail": f"git→github идёт через БЕСХОЗНЫЙ глобальный слой ({proxy}; {eff.get('detail')}) "
                          f"— общий прокси для ВСЕХ хостов, вне управления srouter. Управление: "
                          f"srouter git-proxy status / disable --full. " + GH_DIRECT_HINT}
    # env — последний слой лестницы
    return {"status": "warn",
            "detail": f"git→github идёт через ENV-прокси ({proxy}; {eff.get('detail')}) — снимается "
                      f"env -u. " + GH_DIRECT_HINT}


# ============================ инцидент 2026-10-10: самовольное переключение git-маршрута ============================


def _git_proxy_route_check():
    """git→github обязан ездить managed SOCKS5 xray; env-fallthrough/foreign/direct — down (driver).

    Инцидент 2026-10-10: глобальный urlmatch-ключ http.https://github.com.proxy исчез из
    ~/.gitconfig, env HTTPS_PROXY=http://127.0.0.1:8118 молча перехватил git → push поехал через
    privoxy и умер вместе с ним. `gh/git direct` (_github_direct_check) — info-only «подсказка» и
    на переключение не краснеет; этот чек — driver (канон fail-closed: git-push без туннеля мёртв —
    GFW режет LibreSSL-TLS, verify #199). Источник правды — git_proxy.effective_proxy (лестница
    слоёв). Fail-soft: не бросает.
    """
    eff = git_proxy.effective_proxy()
    if not isinstance(eff, dict):
        return {"status": "unknown", "detail": "git-proxy: effective_proxy вернул не-dict"}
    layer, proxy = eff.get("layer"), eff.get("proxy", "")
    if layer == "unknown":
        return {"status": "unknown",
                "detail": f"git-proxy: {eff.get('detail') or 'конфиг нечитаем'}"}
    if layer == "env":
        return {"status": "down",
                "detail": (f"git→github уехал в env-слой ({proxy}) — мимо xray-туннеля: ключ "
                           f"{git_proxy.KEY} отсутствует/сбит, а env HTTPS_PROXY перехватывает "
                           f"маршрут. push умрёт вместе с privoxy. "
                           f"Чинить: srouter git-proxy enable")}
    if layer == "direct":
        return {"status": "down",
                "detail": ("git→github идёт НАПРЯМУЮ (ни ключа, ни env) — GFW режет TLS, "
                           "push умрёт. Чинить: srouter git-proxy enable")}
    if proxy == git_proxy._PROXY:
        return {"status": "ok",
                "detail": f"git→github через managed {git_proxy._PROXY} (слой {layer})"}
    return {"status": "down",
            "detail": (f"git→github через ЧУЖОЙ proxy {proxy or '(пусто)'} (слой {layer}) — "
                       f"самовольное переключение. "
                       f"Чинить: srouter git-proxy enable --force")}
