"""ТДД-тесты _proxy_env_consistency (issue #331): doctor видит протечку SOCKS-плеча в env.

launchctl gui-домен (srouter-codex-env.sh) ставит ALL_PROXY/all_proxy=socks5h://...:10808 во
ВСЕ GUI-процессы. Если settings.json (claude_proxy.enable) при этом не нейтрализует all_proxy
пустой строкой, сессии Claude Code наследуют ОБА плеча — pip/requests через select_proxy
маппят 'all' на все схемы → SOCKSProxyManager → TypeError PoolKey key_proxy_ssl_context.
Doctor обязан это видеть и давать готовый сниппет, а не «причины нет» (канон noisy-log).

Немоканный probe = недетерминированный вердикт на dev-машине (канон unmocked-probe) —
поэтому в этих тестах claude_proxy.status и os.environ мокаются явно.
"""
import sys

import claude_proxy
import pytest

import health


def _managed_status(*, neutralized=False, state="managed-on", enabled=True):
    return {"enabled": enabled, "proxy": "http://127.0.0.1:8118" if enabled else "",
            "state": state, "provider_direct": True,
            "no_proxy": "localhost,127.0.0.1,::1,api.z.ai",
            "socks_neutralized": neutralized}


def _scrub_proxy_env(monkeypatch):
    """Канон ambient-env-poisons-env-parameterized-stubs: тест параметризован env — чистим
    ВСЕ 8 proxy-ключей до сценария, ставим нужные явно."""
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        monkeypatch.delenv(key, raising=False)


def _mock_status(monkeypatch, status):
    monkeypatch.setattr(claude_proxy, "status", lambda: status)


def test_warn_when_managed_and_not_neutralized(monkeypatch):
    """CC-прокси managed-on, нейтрализации нет, в живом env есть ALL_PROXY=socks5h → warn."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("ALL_PROXY", "socks5h://127.0.0.1:10808")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8118")
    _mock_status(monkeypatch, _managed_status(neutralized=False))
    r = health._proxy_env_consistency()
    assert r["status"] == "warn"
    assert "ALL_PROXY" in r["detail"], "detail называет ключ-виновник"
    assert "socks5h://127.0.0.1:10808" in r["detail"], "detail показывает живое значение (noisy-log)"
    assert "export ALL_PROXY=" in r["detail"], "готовый сниппет для разового снятия"


def test_warn_even_when_live_env_clean(monkeypatch):
    """Протечка определяется settings-инвариантом (managed-on ⇒ neutralized), а не тем, что
    doctor запущен из контекста без ALL_PROXY: следующая CC-сессия всё равно унаследует
    launchctl-SOCKS. Warn обязан быть и при чистом живом env."""
    _scrub_proxy_env(monkeypatch)
    _mock_status(monkeypatch, _managed_status(neutralized=False))
    r = health._proxy_env_consistency()
    assert r["status"] == "warn"


def test_ok_when_neutralized(monkeypatch):
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("ALL_PROXY", "socks5h://127.0.0.1:10808")  # launchctl-слой ещё стоит — это ок
    _mock_status(monkeypatch, _managed_status(neutralized=True))
    assert health._proxy_env_consistency()["status"] == "ok"


def test_ok_when_cc_proxy_disabled(monkeypatch):
    """CC-прокси выключен → нейтрализация не требуется (disable снимает её же)."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("ALL_PROXY", "socks5h://127.0.0.1:10808")
    _mock_status(monkeypatch, _managed_status(enabled=False, neutralized=False))
    assert health._proxy_env_consistency()["status"] == "ok"


def test_unknown_when_settings_unreadable(monkeypatch):
    """Битый settings.json (state unknown, #307) — не угадываем (verify-dont-guess)."""
    _scrub_proxy_env(monkeypatch)
    _mock_status(monkeypatch, _managed_status(state="unknown", enabled=False))
    assert health._proxy_env_consistency()["status"] == "unknown"


def test_unknown_when_foreign_proxy(monkeypatch):
    """Чужой HTTPS_PROXY (#307) — env вне контракта srouter, не warn'им чужую настройку."""
    _scrub_proxy_env(monkeypatch)
    _mock_status(monkeypatch, _managed_status(state="foreign", enabled=False))
    assert health._proxy_env_consistency()["status"] == "unknown"


def test_fail_soft_when_claude_proxy_import_broken(monkeypatch):
    """claude_proxy недоступен (InstallEnv-путь) — fail-soft unknown, не исключение."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setitem(sys.modules, "claude_proxy", None)  # import → ImportError
    r = health._proxy_env_consistency()
    assert r["status"] == "unknown"
    assert "claude_proxy" in r["detail"]


# ============================ wiring в check_all ============================

def test_check_all_warn_is_driver_degraded(monkeypatch):
    """warn (протечка) → ok=False, БЕЗ info-флага → driver: вердикт degraded (pip-класс сломан)."""
    from test_health import _all_up_monkey  # rootdir-insertion pytest: tests/ в sys.path
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_proxy_env_consistency",
                        lambda: {"status": "warn", "detail": "протечка"})
    result = health.check_all()
    pe = [c for c in result["checks"] if "proxy-env" in c["name"]][0]
    assert pe["ok"] is False
    assert "info" not in pe, "warn — driver, не info"
    assert result["status"] == "degraded"


def test_check_all_unknown_is_info_only(monkeypatch):
    """unknown (settings нечитаем/чужой прокси) — info-only, не роняет вердикт."""
    from test_health import _all_up_monkey  # rootdir-insertion pytest: tests/ в sys.path
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_proxy_env_consistency",
                        lambda: {"status": "unknown", "detail": "не определить"})
    result = health.check_all()
    pe = [c for c in result["checks"] if "proxy-env" in c["name"]][0]
    assert pe.get("info") is True
    assert result["status"] == "ok"


def test_check_all_ok_when_env_consistent(monkeypatch):
    from test_health import _all_up_monkey  # rootdir-insertion pytest: tests/ в sys.path
    _all_up_monkey(monkeypatch)
    result = health.check_all()
    pe = [c for c in result["checks"] if "proxy-env" in c["name"]][0]
    assert pe["ok"] is True
    assert result["status"] == "ok"
