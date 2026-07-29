"""ТДД-тесты health._github_direct_check: doctor подсказывает VPS-независимый dev-workflow
для gh/git (issue #199).

Диагноз #199 (verify, эмпирически 2026-07-27): github TCP напрямую открыт (GFW не режет TCP-слой),
gh Go-стек обходит GFW TLS-блокировку → `gh api user` через `env -u HTTP_PROXY -u HTTPS_PROXY -u
ALL_PROXY` работает. Но git-прокси scoped на github.com → xray SOCKS5 10808 ВКЛЮЧЁН (git_proxy,
канон #130) → git pull/push зависит от VPS (мёртвый VPS = timeout). Подсказка носит образовательный
характер: для VPS-независимости gh/git запускать с `env -u`.

Чек ВСЕГДА info-only (как endpoint-override): git-proxy-настройка — это scoped-конфиг, не сбой
стека; ни ok/warn/unknown не роняют агрегированный вердикт. Это картина для диагностики dev-workflow,
не driver. Канон: verify-don't-guess (статичный предикат git-config, не догадки о таймаутах),
srouter-critical-infra-24-7 (dev-workflow не должен зависеть от VPS).

Возвращает {status, detail}:
  status="ok"      — git-config github-proxy выключен (github уже идёт напрямую);
  status="warn"    — git-config ВКЛЮЧЁН → git зависит от VPS, подсказка env -u;
  status="unknown" — git_proxy.status unknown (git config timeout/ошибка).
"""
import git_proxy
import health


# ============================ _github_direct_check: предикаты по git_proxy.status ============================

def test_ok_when_gitconfig_github_proxy_disabled(monkeypatch):
    """git-config github-proxy ВЫКЛЮЧЕН → ok (github уже идёт напрямую, VPS-независимо)."""
    monkeypatch.setattr(git_proxy, "status",
                        lambda: {"enabled": False, "proxy": "", "key": "http.https://github.com.proxy"})
    res = health._github_direct_check()
    assert res["status"] == "ok"
    assert "напрямую" in res["detail"].lower() or "direct" in res["detail"].lower(), res["detail"]


def test_warn_when_gitconfig_github_proxy_enabled(monkeypatch):
    """git-config github-proxy ВКЛЮЧЕН (scoped github → xray SOCKS5) → warn + подсказка env -u.

    Главный сигнал подсказки: git-операции scoped на xray SOCKS5 → зависят от VPS. env -u снимает
    зависимость (gh Go-стек обходит GFW TLS напрямую).
    """
    monkeypatch.setattr(git_proxy, "status",
                        lambda: {"enabled": True, "proxy": "socks5h://127.0.0.1:10808",
                                 "key": "http.https://github.com.proxy"})
    res = health._github_direct_check()
    assert res["status"] == "warn"
    detail = res["detail"].lower()
    assert "env -u" in detail, "подсказка обязана назвать точную команду env -u"
    assert "github" in detail


def test_warn_detail_mentions_gh_go_stack_and_vps_independence(monkeypatch):
    """Подсказка объясняет ПОЧЕМУ env -u работает: gh Go-стек + VPS-независимость (#199 суть)."""
    monkeypatch.setattr(git_proxy, "status",
                        lambda: {"enabled": True, "proxy": "socks5h://127.0.0.1:10808",
                                 "key": "http.https://github.com.proxy"})
    res = health._github_direct_check()
    detail = res["detail"].lower()
    # Канон verify-don't-guess: подсказка называет эмпирически проверенный механизм, не догадку.
    assert "gh" in detail
    assert "vps" in detail or "напрямую" in detail


def test_hint_distinguishes_gh_env_vs_git_config_stack(monkeypatch):
    """#199 cycle-1 FIX (Codex critical): gh и git — РАЗНЫЕ стеки прокси, разные команды.

    gh (Go) читает env-прокси (HTTP_PROXY/http_proxy — оба регистра, Go httpproxy fallback).
    git-over-https читает git-config `http.https://github.com.proxy` — env -u его НЕ трогает
    (verify: `git config --get-urlmatch` после env -u всё ещё показывает прокси активным).
    Значит подсказка НЕ может обещать одну команду `env -u` для обоих:
      - для gh: env -u должен снимать И uppercase, И lowercase (http_proxy/https_proxy/all_proxy);
      - для git-over-https: нужен `git -c http.https://github.com.proxy=` (переопределение config).
    Без `git -c` подсказка лживо обещает VPS-независимость git, оставляя его на прокси — ровно
    тот сбой, который PR должен переживать. Тест кодирует РАЗДЕЛЕНИЕ стеков, не одну команду.
    """
    monkeypatch.setattr(git_proxy, "status",
                        lambda: {"enabled": True, "proxy": "socks5h://127.0.0.1:10808",
                                 "key": "http.https://github.com.proxy"})
    res = health._github_direct_check()
    detail = res["detail"].lower()
    # gh-путь: env -u должен снимать lowercase env тоже (Go fallback на http_proxy/https_proxy).
    assert "http_proxy" in detail, "env -u обязан снимать lowercase http_proxy (Go httpproxy fallback)"
    # git-путь: env -u НЕ трогает git-config → нужен git -c (переопределение scoped proxy).
    assert "git -c" in detail, "git-over-https: env -u не трогает git-config → нужен git -c ...proxy="


def test_hint_does_not_promise_gh_repo_clone_is_proxy_free(monkeypatch):
    """#199 cycle-1 FIX: gh repo clone делегирует внутреннему git → scoped git-config применяется.

    Codex: клонирование через gh не использует Go-транспорт gh для самого fetch — gh зовёт git,
    который читает http.https://github.com.proxy. Подсказка не должна описывать gh repo clone как
    VPS-независимый путь только на gh-стеке.
    """
    monkeypatch.setattr(git_proxy, "status",
                        lambda: {"enabled": True, "proxy": "socks5h://127.0.0.1:10808",
                                 "key": "http.https://github.com.proxy"})
    res = health._github_direct_check()
    # Если hint упоминает clone/gh repo clone, он обязан сопровождать git -c (иначе ложь).
    detail = res["detail"].lower()
    if "clone" in detail or "gh repo" in detail:
        assert "git -c" in detail, "clone через gh делегирует git → нужен git -c для scoped proxy"


def test_unknown_when_git_proxy_status_unknown(monkeypatch):
    """git_proxy.status unknown (git config timeout) → unknown (info-only, не роняет)."""
    monkeypatch.setattr(git_proxy, "status",
                        lambda: {"enabled": False, "proxy": "", "key": "http.https://github.com.proxy",
                                 "status": "unknown"})
    res = health._github_direct_check()
    assert res["status"] == "unknown"


def test_unknown_when_git_proxy_raises(monkeypatch):
    """git_proxy.status бросает → unknown (probe-канон: чек не бросает)."""
    def _raise():
        raise RuntimeError("git exploded")
    monkeypatch.setattr(git_proxy, "status", _raise)
    res = health._github_direct_check()
    assert res["status"] == "unknown"


def test_never_raises(monkeypatch):
    """Любой возврат git_proxy.status (даже мусор) → чек возвращает status-строку, не бросает."""
    for garbage in [{}, None, {"enabled": "maybe"}, {"weird": True}]:
        monkeypatch.setattr(git_proxy, "status", lambda g=garbage: g)
        res = health._github_direct_check()
        assert res["status"] in ("ok", "warn", "unknown"), f"мусор {garbage!r} дал {res}"


# ============================ check_all: info-only интеграция (не driver) ============================

def test_check_all_has_github_direct_check(monkeypatch):
    """check_all содержит gh/git-direct чек (виден в doctor)."""
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(git_proxy, "status",
                        lambda: {"enabled": True, "proxy": "socks5h://127.0.0.1:10808",
                                 "key": "http.https://github.com.proxy"})
    result = health.check_all()
    names = [c["name"] for c in result["checks"]]
    assert any("github" in n.lower() or "gh" in n.lower() for n in names), names


def test_check_all_github_direct_is_info_only_never_driver(monkeypatch):
    """warn git-proxy-enabled НЕ роняет вердикт — info-only (как endpoint-override).

    Даже когда github-direct чек warn (git-config прокси включён), при живом стеке вердикт
    остаётся ok: это образовательная подсказка dev-workflow, не сбой инфраструктуры.
    """
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(git_proxy, "status",
                        lambda: {"enabled": True, "proxy": "socks5h://127.0.0.1:10808",
                                 "key": "http.https://github.com.proxy"})
    result = health.check_all()
    assert result["status"] == "ok", "info-only чек не должен ронять вердикт"
    gh_checks = [c for c in result["checks"] if "github" in c["name"].lower() or "gh" in c["name"].lower()]
    assert gh_checks, "чек должен присутствовать"
    assert all(c.get("info") for c in gh_checks), "gh/git-direct чек ВСЕГДА info-only"


def test_check_all_github_direct_info_only_when_disabled(monkeypatch):
    """ok git-proxy-disabled тоже info-only (картина, не driver) — симметрия с warn."""
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(git_proxy, "status",
                        lambda: {"enabled": False, "proxy": "", "key": "http.https://github.com.proxy"})
    result = health.check_all()
    assert result["status"] == "ok"
    gh_checks = [c for c in result["checks"] if "github" in c["name"].lower() or "gh" in c["name"].lower()]
    assert gh_checks
    assert all(c.get("info") for c in gh_checks)


# ============================ helper (копия из test_health.py — все чеки up) ============================

def _all_up_monkey(monkeypatch, *, probe_status="ok", probe_detail="runtime: коннект"):
    """Мокирует ВСЕ driver-чеки в up + active_node пустой — изолирует github-direct чек.

    Не мокает github-direct (тестируемый чек) — его мокает каждый тест через git_proxy.status.
    """
    import local_state
    monkeypatch.setattr(health, "_port_up", lambda port: True)
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200", False))
    monkeypatch.setattr(health, "_upstream_vps_reachable",
                        lambda node=None: {"status": "ok", "detail": "VPS reachable"})
    monkeypatch.setattr(health, "_claude_proxy_probe",
                        lambda: {"status": probe_status, "detail": probe_detail})
    monkeypatch.setattr(health, "_codex_proxy_probe",
                        lambda: {"status": probe_status, "detail": probe_detail})
    monkeypatch.setattr(health, "_codex_app_proxy_check",
                        lambda: {"status": probe_status, "detail": probe_detail})
    monkeypatch.setattr(health, "_desktop_proxy_check",
                        lambda: {"status": "unknown", "detail": "launchctl пустой"})
    monkeypatch.setattr(local_state, "active_node", lambda path=None: {})
