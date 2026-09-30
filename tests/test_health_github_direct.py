"""ТДД-тесты health._github_direct_check: doctor показывает ЭФФЕКТИВНЫЙ git-прокси для github.

История: чек (issue #199) читал только scoped-ключ http.https://github.com.proxy через
git_proxy.status() и рапортовал «github идёт напрямую», пока бесхозный глобальный
http.proxy=8118 реально проксировал git, а локальные override'ы репо наоборот выключали
(живой факт машины 2026-09-30). С 2026-09-30 чек читает git_proxy.effective_proxy() —
композер всех слоёв (local urlmatch > global urlmatch > global generic > env), канон
detector-must-be-function-not-constant: вердикт по эффективному значению, не по одному слою.

Чек ВСЕГДА info-only (как endpoint-override): git-proxy-настройка — это конфиг, не сбой
стека; ни ok/warn/unknown не роняют агрегированный вердикт. Канон: verify-don't-guess,
srouter-critical-infra-24-7 (dev-workflow не должен зависеть от VPS).

Моки сидят на git_proxy.effective_proxy (НЕ status): переезд caller'а = перенос моков
(канон moving-caller-inverts-mock-ownership — иначе моки обесцениваются тихо).

Возвращает {status, detail}:
  status="ok"      — эффективный прокси отсутствует (github идёт напрямую);
  status="warn"    — эффективный прокси есть → подсказка по конкретному слою;
  status="unknown" — effective_proxy unknown/ошибка (git config timeout/мусор).
"""
import git_proxy
import health

# Реальный тестируемый чек — канонический _all_up_monkey его мокает, тесты check_all ниже
# восстанавливают поверх (паттерн _REAL_NETWORK_INTERFACE_UP из test_health.py, #271).
_REAL_GITHUB_DIRECT_CHECK = health._github_direct_check


# ============================ _github_direct_check: предикаты по effective_proxy ============================

def test_ok_when_effective_direct(monkeypatch):
    """Эффективно direct (ничего не задано) → ok (github идёт напрямую, VPS-независимо)."""
    monkeypatch.setattr(git_proxy, "effective_proxy",
                        lambda repo=None: {"proxy": "", "layer": "direct", "detail": ""})
    res = health._github_direct_check()
    assert res["status"] == "ok"
    assert "напрямую" in res["detail"].lower() or "direct" in res["detail"].lower(), res["detail"]


def test_warn_when_managed_proxy_on(monkeypatch):
    """managed urlmatch → xray SOCKS5 → git зависит от VPS → warn + подсказка."""
    monkeypatch.setattr(git_proxy, "effective_proxy",
                        lambda repo=None: {"proxy": "socks5h://127.0.0.1:10808",
                                           "layer": "global-urlmatch", "detail": "managed-on"})
    res = health._github_direct_check()
    assert res["status"] == "warn"
    detail = res["detail"].lower()
    assert "env -u" in detail, "подсказка обязана назвать точную команду env -u"
    assert "github" in detail


def test_warn_detail_mentions_gh_go_stack_and_vps_independence(monkeypatch):
    monkeypatch.setattr(git_proxy, "effective_proxy",
                        lambda repo=None: {"proxy": "socks5h://127.0.0.1:10808",
                                           "layer": "global-urlmatch", "detail": "managed-on"})
    res = health._github_direct_check()
    detail = res["detail"].lower()
    assert "gh" in detail
    assert "vps" in detail or "напрямую" in detail


def test_hint_distinguishes_gh_env_vs_git_config_stack(monkeypatch):
    """gh (env, Go-стек) и git (git-config) — разные стеки; подсказка называет обе команды."""
    monkeypatch.setattr(git_proxy, "effective_proxy",
                        lambda repo=None: {"proxy": "socks5h://127.0.0.1:10808",
                                           "layer": "global-urlmatch", "detail": "managed-on"})
    res = health._github_direct_check()
    detail = res["detail"].lower()
    assert "http_proxy" in detail, "env -u обязан снимать lowercase http_proxy (Go httpproxy fallback)"
    assert "git -c" in detail, "git-over-https: env -u не трогает git-config → нужен git -c ...proxy="


def test_foreign_proxy_is_not_ok_not_off(monkeypatch):
    """foreign urlmatch — посторонний прокси: НЕ ok, имя прокси названо."""
    monkeypatch.setattr(git_proxy, "effective_proxy",
                        lambda repo=None: {"proxy": "http://corp-proxy.example.com:8080",
                                           "layer": "global-urlmatch", "state": "foreign",
                                           "detail": "foreign"})
    res = health._github_direct_check()
    assert res["status"] != "ok", f"foreign прокси прочитан как «выключен»: {res}"
    assert res["status"] in ("warn", "down")
    detail = res["detail"].lower()
    assert "чужой" in detail or "foreign" in detail or "посторонн" in detail, res["detail"]
    assert "corp-proxy.example.com" in res["detail"], "detail обязан назвать фактический прокси"


def test_stray_global_generic_is_not_ok(monkeypatch):
    """КРАСНЫЙ на живой баг 2026-09-30: urlmatch absent, но бесхозный глобальный
    http.proxy/https.proxy=8118 реально проксирует git. Чек обязан НЕ говорить «идёт напрямую»
    и назвать слой (global-generic) + значение — раньше печатал ok «git github-proxy выключен»."""
    monkeypatch.setattr(git_proxy, "effective_proxy",
                        lambda repo=None: {"proxy": "http://127.0.0.1:8118",
                                           "layer": "global-generic",
                                           "detail": "https.proxy=http://127.0.0.1:8118"})
    res = health._github_direct_check()
    assert res["status"] != "ok", f"бесхозный 8118 прочитан как «напрямую»: {res}"
    detail = res["detail"].lower()
    assert "8118" in detail, "detail обязан назвать фактический прокси-URL"
    assert "git-proxy" in detail, "hint обязан вести в srouter git-proxy (управление слоем)"


def test_env_layer_is_not_ok(monkeypatch):
    """env-слой (HTTPS_PROXY) тоже активный прокси → warn с именем переменной."""
    monkeypatch.setattr(git_proxy, "effective_proxy",
                        lambda repo=None: {"proxy": "http://wprp.example:3128",
                                           "layer": "env", "detail": "HTTPS_PROXY"})
    res = health._github_direct_check()
    assert res["status"] == "warn"
    assert "env" in res["detail"].lower() or "proxy" in res["detail"].lower()
    assert "wprp.example" in res["detail"]


def test_local_urlmatch_direct_is_ok(monkeypatch):
    """Пустой local override = осознанный direct В ЭТОМ репо → ok (эффективно напрямую)."""
    monkeypatch.setattr(git_proxy, "effective_proxy",
                        lambda repo=None: {"proxy": "", "layer": "local-urlmatch",
                                           "detail": "local .git/config override"})
    res = health._github_direct_check()
    assert res["status"] == "ok"


def test_unknown_when_effective_unknown(monkeypatch):
    monkeypatch.setattr(git_proxy, "effective_proxy",
                        lambda repo=None: {"proxy": "", "layer": "unknown", "detail": "timeout"})
    res = health._github_direct_check()
    assert res["status"] == "unknown"


def test_unknown_when_effective_proxy_raises(monkeypatch):
    def _raise():
        raise RuntimeError("git exploded")
    monkeypatch.setattr(git_proxy, "effective_proxy", _raise)
    res = health._github_direct_check()
    assert res["status"] == "unknown"


def test_never_raises(monkeypatch):
    """Любой возврат git_proxy.effective_proxy (даже мусор) → status-строка, не бросает."""
    for garbage in [{}, None, {"proxy": "x"}, {"weird": True}]:
        monkeypatch.setattr(git_proxy, "effective_proxy", lambda g=garbage, repo=None: g)
        res = health._github_direct_check()
        assert res["status"] in ("ok", "warn", "unknown"), f"мусор {garbage!r} дал {res}"


# ============================ check_all: info-only интеграция (не driver) ============================

def test_check_all_has_github_direct_check(monkeypatch):
    """check_all содержит gh/git-direct чек (виден в doctor)."""
    from test_health import _all_up_monkey  # rootdir-insertion pytest: tests/ в sys.path
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_github_direct_check", _REAL_GITHUB_DIRECT_CHECK)
    monkeypatch.setattr(git_proxy, "effective_proxy",
                        lambda repo=None: {"proxy": "socks5h://127.0.0.1:10808",
                                           "layer": "global-urlmatch", "detail": "managed-on"})
    result = health.check_all()
    names = [c["name"] for c in result["checks"]]
    assert any("github" in n.lower() or "gh" in n.lower() for n in names), names


def test_check_all_github_direct_is_info_only_never_driver(monkeypatch):
    """warn (прокси включён) НЕ роняет вердикт — info-only (как endpoint-override)."""
    from test_health import _all_up_monkey  # rootdir-insertion pytest: tests/ в sys.path
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_github_direct_check", _REAL_GITHUB_DIRECT_CHECK)
    monkeypatch.setattr(git_proxy, "effective_proxy",
                        lambda repo=None: {"proxy": "socks5h://127.0.0.1:10808",
                                           "layer": "global-urlmatch", "detail": "managed-on"})
    result = health.check_all()
    assert result["status"] == "ok", "info-only чек не должен ронять вердикт"
    gh_checks = [c for c in result["checks"] if "github" in c["name"].lower() or "gh" in c["name"].lower()]
    assert gh_checks, "чек должен присутствовать"
    assert all(c.get("info") for c in gh_checks), "gh/git-direct чек ВСЕГДА info-only"


def test_check_all_github_direct_info_only_when_disabled(monkeypatch):
    """ok (direct) тоже info-only (картина, не driver) — симметрия с warn."""
    from test_health import _all_up_monkey  # rootdir-insertion pytest: tests/ в sys.path
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_github_direct_check", _REAL_GITHUB_DIRECT_CHECK)
    monkeypatch.setattr(git_proxy, "effective_proxy",
                        lambda repo=None: {"proxy": "", "layer": "direct", "detail": ""})
    result = health.check_all()
    assert result["status"] == "ok"
    gh_checks = [c for c in result["checks"] if "github" in c["name"].lower() or "gh" in c["name"].lower()]
    assert gh_checks
    assert all(c.get("info") for c in gh_checks)


# Локальная копия _all_up_monkey удалена (issue #331): параллельная копия канона перестала
# синхронизироваться — не мокала новые machine-dependent probes check_all, из-за чего эти
# check_all-тесты зависели от живой машины (немоканный probe = недетерминированный вердикт,
# канон unmocked-probe / гвард test_machine_state_mock_guard.py). Тесты используют канонический
# helper из test_health.py + восстанавливают РЕАЛЬНЫЙ _github_direct_check поверх его мока.
