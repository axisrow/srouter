"""Health-пробы для dev-workflow: VSCode/Cursor scoped SOCKS5 (codex-расширение), gh/git direct.

Извлечено из health.py (issue #158 — разбиение крупного файла на модули по обязанностям).
health.py остаётся тонким фасадом: `from health_devworkflow import *` ре-экспортирует все публичные
имена (канон star-import-reexport-contract) — существующие `health.<name>` и monkeypatch на
`health` module продолжают работать без изменений.
"""
from pathlib import Path
import logging
from urllib.parse import urlparse

import health as _health_facade  # noqa: E402 — резолвит intra-module вызовы через health для monkeypatch (канон #158)

_log = logging.getLogger("srouter.health")

# star-import re-export (канон star-import-reexport-contract) — см. health_probes.py докстринг __all__.
__all__ = ["_vscode_proxy_check", "GH_DIRECT_HINT", "_github_direct_check"]

# ============================ #185: scoped SOCKS5 для codex через VSCode http.proxy ============================


def _vscode_proxy_check():
    """Scoped SOCKS5 для codex-расширения openai.chatgpt через VSCode `http.proxy` (#185).

    Расширение openai.chatgpt запускает свой codex-binary (мимо wrapper), наследует HTTP_PROXY=privoxy
    из ~/.claude/settings.json → privoxy рвёт WS (#96/#120). Scoped-фикс: VSCode http.proxy=socks5h://10808
    → расширение строит HTTP_PROXY/HTTPS_PROXY В ENV codex-процессА (verify из extension.js), CC не трогает.
    Чек читает user-settings.json (Code+Cursor) и сверяет http.proxy.

    Возвращает {status, detail}:
      ok      — хотя бы один существующий settings.json содержит http.proxy == socks5h://10808;
      unknown — ни одного settings.json нет (редактор не установлен) — info-only (как desktop-proxy);
      down    — http.proxy есть, но НЕ socks5 (privoxy/HTTP рвёт WS #120, или чужой корпоративный) — driver.
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
    # Хотя бы один с правильным SOCKS5 → ok (пользователь может пользоваться любым редактором).
    socks_ok = [p for p, info in present.items()
                if urlparse(info.get("proxy", "")).scheme.lower() in {"socks", "socks5", "socks5h"}]
    if socks_ok:
        names = ", ".join(Path(p).parent.parent.name for p in socks_ok)  # 'Code' / 'Cursor'
        return {"status": "ok", "detail": f"VSCode http.proxy=SOCKS5 10808 ({names}) — codex расширения гонит через xray (#185)"}
    # http.proxy задан, но НЕ socks5 → down (privoxy/HTTP рвёт WS, или чужой прокси мимо xray).
    bad = ", ".join(f"{Path(p).parent.parent.name}={info['proxy']}" for p, info in present.items() if info.get("proxy"))
    if bad:
        return {"status": "down",
                "detail": f"VSCode http.proxy НЕ SOCKS5 ({bad}) — codex рвёт WS через privoxy/чужой (#120)"}
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

    Диагноз #199 (verify, эмпирически): github доступен напрямую через gh — Go HTTP/TLS-стек gh
    обходит GFW TLS-блокировку (в отличие от curl/git на LibreSSL + системном resolver). Но если в
    ~/.gitconfig включён scoped git-прокси `http.https://github.com.proxy → privoxy 8118` (git_proxy),
    то git pull/push идёт ЧЕРЕЗ прокси → зависит от VPS: мёртвый VPS = git timeout (выглядело как
    «флап gh»). Подсказка РАЗДЕЛЯЕТ стеки (cycle-1 FIX): gh → снять env-прокси (оба регистра) через
    `env -u`; git-over-https → env -u НЕ трогает git-config, нужен `git -c http.https://github.com.proxy=`.

    Предикт = статичный git-config (verify-don't-guess — не догадки о таймаутах, а проверяемый
    факт конфигурации). Чек info-only ВСЕГДА (как endpoint-override): git-proxy-настройка — это
    scoped-конфиг, не сбой стека; warn/ok/unknown НЕ роняют агрегированный вердикт — это картина
    для диагностики dev-workflow, не driver. Канон: verify-don't-guess, srouter-critical-infra-24-7
    (dev-workflow не должен зависеть от VPS — github-операции переживают смерть VPS).

    Возвращает {status, detail}:
      ok      — git-config github-proxy выключен (github уже идёт напрямую);
      warn    — git-config ВКЛЮЧЁН (scoped github → privoxy) → git зависит от VPS, подсказка env -u;
      unknown — git_proxy.status unknown/ошибка (git config timeout/недоступен).
    Не бросает (probe-канон).
    """
    try:
        import git_proxy
        st = git_proxy.status()
    except (ImportError, RuntimeError, OSError, ValueError) as exc:
        # ImportError — модуль недоступен; RuntimeError/OSError/ValueError — сбой status() (fail-soft).
        _log.debug("git_proxy недоступен/сбой: %s — check пропущен", exc)
        return {"status": "unknown", "detail": "git_proxy недоступен — check пропущен"}
    # isinstance ДО .get: git_proxy.status может вернуть None/не-dict (мусор) — .get упал бы
    # (probe-канон: чек не бросает). git_proxy.status при timeout отдаёт {status:"unknown"} — это
    # НЕ «git-proxy выключен» (enabled=False без status — другое; ниже разделяем).
    if not isinstance(st, dict) or st.get("status") == "unknown":
        return {"status": "unknown",
                "detail": "git config недоступен (timeout) — github-direct check пропущен"}
    enabled = bool(st.get("enabled"))
    if not enabled:
        return {"status": "ok",
                "detail": "git github-proxy выключен — github идёт напрямую (VPS-независимо). "
                          "Если gh/git timeout через прокси: " + GH_DIRECT_HINT}
    return {"status": "warn",
            "detail": f"git github-proxy ВКЛЮЧЁН ({st.get('proxy') or 'xray SOCKS5 10808'}) → "
                      f"git pull/push зависит от VPS. " + GH_DIRECT_HINT}
