"""ТДД-тесты _no_proxy_direct_check: NO_PROXY (settings.json env) с напрямую недоступным хостом.

Инцидент 2026-10-01 (agy login): '.googleapis.com' в env NO_PROXY → процессы, запущенные из
CC-сессий, ходили на oauth2.googleapis.com мимо privoxy напрямую и умирали по GFW
(dial tcp i/o timeout). Doctor обязан это видеть как warn с хостом и путём фикса, а не молчать
(канон noisy-log-better-than-no-log).

Немоканный probe = недетерминированный вердикт на dev-машине (канон unmocked-probe) —
claude_proxy.* и sys_probe.direct_probe мокаются явно на уровне модульных ссылок (как
test_health_proxy_env.py / direct_first.py).
"""
import sys

import claude_proxy
import pytest
import sys_probe

import health
from health_probes import GFW_CONTROL_DOMAIN


# Инцидентный NO_PROXY (реальный env-блок на момент инцидента): loopback + z.ai + provider
# (by design direct) + два посторонних google-хоста.
INCIDENT_NO_PROXY = "localhost,127.0.0.1,::1,z.ai,.z.ai,storage.googleapis.com,.googleapis.com,api.z.ai"


def _status(**over):
    st = {"enabled": True, "proxy": "http://127.0.0.1:8118", "state": "managed-on",
          "provider_direct": True, "no_proxy": "localhost,127.0.0.1,::1,api.z.ai",
          "socks_neutralized": True}
    st.update(over)
    return st


def _mock_claude_proxy(monkeypatch, status, provider_host="api.z.ai"):
    """Симметрия реальности: env-блок из _load() несёт ту же NO_PROXY, что и status()
    (status читает её оттуда же); тесты рассинхрона переопределяют _load отдельно."""
    monkeypatch.setattr(claude_proxy, "status", lambda: status)
    monkeypatch.setattr(claude_proxy, "_load", lambda: {
        "env": {"ANTHROPIC_BASE_URL": f"https://{provider_host}/",
                "NO_PROXY": status.get("no_proxy", "")}})
    monkeypatch.setattr(claude_proxy, "_base_url_hosts", lambda data: provider_host)


def _mock_direct_probe(monkeypatch, results=None, default=None):
    """results: {host: {"reachable","kind"}}; default — для не перечисленных (контроль и прочие).
    Возвращает список фактических вызовов (host, connect_timeout, max_time)."""
    results = results or {}
    calls = []

    def _fake(host, *, connect_timeout=4, max_time=8):
        calls.append((host, connect_timeout, max_time))
        r = results.get(host, default if default is not None else {"reachable": True, "kind": "ok"})
        return dict(r)

    monkeypatch.setattr(sys_probe, "direct_probe", _fake)
    return calls


def test_warn_when_no_proxy_host_times_out_directly(monkeypatch):
    """ДЫРА (инцидент 2026-10-01): .googleapis.com в NO_PROXY таймаутит напрямую при живом
    контроле → warn, detail называет хост и путь фикса (settings.json env.NO_PROXY)."""
    _mock_claude_proxy(monkeypatch, _status(no_proxy=INCIDENT_NO_PROXY))
    calls = _mock_direct_probe(monkeypatch, results={
        "googleapis.com": {"reachable": False, "kind": "timeout"},
    })
    r = health._no_proxy_direct_check()
    assert r["status"] == "warn"
    assert "googleapis.com" in r["detail"], "detail называет хост-виновник"
    assert "settings.json" in r["detail"], "detail указывает путь фикса"
    assert calls, "прямая проба фактически выполнялась"


def test_ok_when_candidate_reachable(monkeypatch):
    """Посторонний хост честно доступен напрямую → ok (NO_PROXY правомерен, не наш случай)."""
    _mock_claude_proxy(monkeypatch, _status(no_proxy="localhost,z.ai,example.com"))
    _mock_direct_probe(monkeypatch, default={"reachable": True, "kind": "ok"})
    assert health._no_proxy_direct_check()["status"] == "ok"


def test_ok_when_upstream_error_5xx(monkeypatch):
    """5xx напрямую = сервер ОТВЕТИЛ, прямой канал жив → не warn (upstream-error ≠ блокировка)."""
    _mock_claude_proxy(monkeypatch, _status(no_proxy="localhost,z.ai,example.com"))
    _mock_direct_probe(monkeypatch, default={"reachable": True, "kind": "upstream-error"})
    assert health._no_proxy_direct_check()["status"] == "ok"


def test_warn_when_connection_failed_dead_path(monkeypatch):
    """connection-failed (живой формат инцидента: GFW RST / refused, а не только timeout) —
    прямой путь мёртв при живом контроле → warn. Инвариант «путь мёртв», не «GFW банит»
    (канон mock-format-must-come-from-live-capture: реальный захват googleapis.com дал
    connection-failed, сочинённый мок с timeout один консервировал бы дыру)."""
    _mock_claude_proxy(monkeypatch, _status(no_proxy="localhost,z.ai,example.com"))
    _mock_direct_probe(monkeypatch, results={
        "example.com": {"reachable": False, "kind": "connection-failed"},
    })
    r = health._no_proxy_direct_check()
    assert r["status"] == "warn"
    assert "example.com" in r["detail"] and "connection-failed" in r["detail"]


def test_unknown_when_control_unreachable(monkeypatch):
    """Контрольный домен сам недоступен напрямую → прямой сети нет, тест неприменим → unknown
    (parity _gfw_domain_check: без контроля «всё режется» = не GFW, первичная причина выше)."""
    _mock_claude_proxy(monkeypatch, _status(no_proxy="localhost,z.ai,example.com"))
    _mock_direct_probe(monkeypatch, default={"reachable": False, "kind": "timeout"})
    r = health._no_proxy_direct_check()
    assert r["status"] == "unknown"
    assert "контроль" in r["detail"]


def test_ok_when_proxy_disabled_zero_probes(monkeypatch):
    """CC-прокси выключен → NO_PROXY не действует, проверять нечего; 0 сетевых вызовов."""
    _mock_claude_proxy(monkeypatch, _status(enabled=False, no_proxy=INCIDENT_NO_PROXY))
    calls = _mock_direct_probe(monkeypatch)
    r = health._no_proxy_direct_check()
    assert r["status"] == "ok"
    assert calls == [], "выключенный прокси — ни одного curl"


@pytest.mark.parametrize("state", ["foreign", "unknown"])
def test_unknown_when_foreign_or_unreadable_settings(monkeypatch, state):
    """Чужой HTTPS_PROXY / битый settings.json (#307) — вне контракта srouter → unknown."""
    _mock_claude_proxy(monkeypatch, _status(state=state, no_proxy=INCIDENT_NO_PROXY))
    _mock_direct_probe(monkeypatch)
    assert health._no_proxy_direct_check()["status"] == "unknown"


def test_loopback_builtin_provider_ignored(monkeypatch):
    """loopback/BUILTIN z.ai/provider-хост — by design direct, не пробуются; посторонние — да."""
    _mock_claude_proxy(monkeypatch, _status(no_proxy=INCIDENT_NO_PROXY))
    # все reachable: google-хосты «честно прямые» — предмет теста ФИЛЬТР, не вердикт
    calls = _mock_direct_probe(monkeypatch, default={"reachable": True, "kind": "ok"})
    r = health._no_proxy_direct_check()
    assert r["status"] == "ok"
    probed = {h for h, _, _ in calls} - {GFW_CONTROL_DOMAIN}  # контроль легитимно пробуется
    assert "localhost" not in probed and "127.0.0.1" not in probed and "::1" not in probed
    assert "z.ai" not in probed and "api.z.ai" not in probed, "BUILTIN/provider не пробуются"
    assert "storage.googleapis.com" in probed, "посторонний хост пробуется"
    assert "googleapis.com" in probed, "ведущая точка срезается, хост пробуется"


def test_zero_network_when_no_candidates(monkeypatch):
    """Чистый NO_PROXY (только loopback+z.ai+provider) → ни контроля, ни кандидатов: 0 curl."""
    _mock_claude_proxy(monkeypatch, _status(no_proxy="localhost,127.0.0.1,::1,z.ai,.z.ai,api.z.ai"))
    calls = _mock_direct_probe(monkeypatch)
    r = health._no_proxy_direct_check()
    assert r["status"] == "ok"
    assert calls == [], "чистый конфиг — ноль сетевых вызовов"


def test_fail_soft_when_claude_proxy_import_broken(monkeypatch):
    """claude_proxy недоступен (InstallEnv-путь) — fail-soft unknown, не исключение."""
    monkeypatch.setitem(sys.modules, "claude_proxy", None)  # import → ImportError
    r = health._no_proxy_direct_check()
    assert r["status"] == "unknown"
    assert "claude_proxy" in r["detail"]


def test_ip_literals_skipped(monkeypatch):
    """IP-литералы (LAN/VPS-адреса в NO_PROXY) — не кандидаты: HTTP-проба по bare-IP без SNI
    даёт ложный connection-failed (review #392 finding 1). Loopback покрывается тем же."""
    _mock_claude_proxy(monkeypatch, _status(
        no_proxy="localhost,127.0.0.1,::1,192.168.1.10,85.136.181.198,example.com"))
    calls = _mock_direct_probe(monkeypatch, default={"reachable": True, "kind": "ok"})
    r = health._no_proxy_direct_check()
    probed = {h for h, _, _ in calls}
    assert "192.168.1.10" not in probed and "85.136.181.198" not in probed
    assert "example.com" in probed, "домены по-прежнему пробуются"
    assert r["status"] == "ok", "IP в NO_PROXY не дают ложный warn (проба только example.com)"


def test_both_no_proxy_variants_merged(monkeypatch):
    """Рассинхронные NO_PROXY/no_proxy в settings.json: хост из затенённой variant (её видит
    curl-стек детей) тоже проверяется — merge обеих variant, как enable() (review #392 finding 2)."""
    _mock_claude_proxy(monkeypatch, _status(no_proxy="localhost,z.ai,visible.example.com"))
    # _load (мок в _mock_claude_proxy) отдаёт env только с no_proxy-key — расширяем рассинхроном:
    monkeypatch.setattr(claude_proxy, "_load", lambda: {
        "env": {"ANTHROPIC_BASE_URL": "https://api.z.ai/",
                "NO_PROXY": "hidden.example.com"}})
    _mock_direct_probe(monkeypatch, results={
        "hidden.example.com": {"reachable": False, "kind": "timeout"},
        GFW_CONTROL_DOMAIN: {"reachable": True, "kind": "ok"},
    }, default={"reachable": True, "kind": "ok"})
    r = health._no_proxy_direct_check()
    assert r["status"] == "warn", "хост из NO_PROXY-variant, скрытой от status(), не ускользает"
    assert "hidden.example.com" in r["detail"]


def test_leading_dot_dedupe(monkeypatch):
    """.example.com и example.com — один и тот же probe-хост: дедуп, один вызов (+ контроль)."""
    _mock_claude_proxy(monkeypatch, _status(no_proxy="localhost,z.ai,.example.com,example.com"))
    calls = _mock_direct_probe(monkeypatch, default={"reachable": True, "kind": "ok"})
    health._no_proxy_direct_check()
    candidate_calls = [h for h, _, _ in calls if h == "example.com"]
    assert len(candidate_calls) == 1, "дубль с ведущей точкой не пробуется дважды"


def test_candidate_cap_truncated(monkeypatch):
    """Больше NO_PROXY_MAX_CANDIDATES посторонних хостов → срез до 5, усечение видно в detail."""
    hosts = ",".join(f"h{i}.example.com" for i in range(7))
    _mock_claude_proxy(monkeypatch, _status(no_proxy=f"localhost,z.ai,{hosts}"))
    calls = _mock_direct_probe(monkeypatch, results={
        GFW_CONTROL_DOMAIN: {"reachable": True, "kind": "ok"},  # прямая сеть есть
    }, default={"reachable": False, "kind": "timeout"})
    r = health._no_proxy_direct_check()
    assert r["status"] == "warn"
    candidate_calls = [h for h, _, _ in calls if h != GFW_CONTROL_DOMAIN]
    assert len(candidate_calls) == 5, "кап 5 кандидатов"
    assert "5" in r["detail"] or "усеч" in r["detail"], "усечение упомянуто в detail"


# ============================ wiring в check_all ============================

def test_check_all_warn_is_driver_degraded(monkeypatch):
    """warn (хост в NO_PROXY умирает напрямую) → ok=False БЕЗ info → driver: вердикт degraded."""
    from test_health import _all_up_monkey, _mock_doctor_only_checks  # rootdir-insertion pytest
    _all_up_monkey(monkeypatch)
    _mock_doctor_only_checks(monkeypatch)
    monkeypatch.setattr(health, "_no_proxy_direct_check",
                        lambda: {"status": "warn", "detail": "googleapis.com напрямую недоступен"})
    result = health.check_all(active_claude=True)
    npd = [c for c in result["checks"] if "NO_PROXY direct-reachable" in c["name"]][0]
    assert npd["ok"] is False
    assert "info" not in npd, "warn — driver, не info"
    assert result["status"] == "degraded"


def test_check_all_unknown_is_info_only(monkeypatch):
    """unknown (нет прямой сети/битый settings) — info-only, не роняет вердикт."""
    from test_health import _all_up_monkey, _mock_doctor_only_checks
    _all_up_monkey(monkeypatch)
    _mock_doctor_only_checks(monkeypatch)
    monkeypatch.setattr(health, "_no_proxy_direct_check",
                        lambda: {"status": "unknown", "detail": "не определить"})
    result = health.check_all(active_claude=True)
    npd = [c for c in result["checks"] if "NO_PROXY direct-reachable" in c["name"]][0]
    assert npd.get("info") is True
    assert result["status"] == "ok"


def test_check_absent_in_light_health(monkeypatch):
    """Регресс-гвард: лёгкий check_all() (без active_claude, /health + watchdog ~20с) НЕ делает
    per-host прямые curl (канон gate-is-for-arbitrary-path / srouter-critical-infra-24-7)."""
    from test_health import _all_up_monkey
    _all_up_monkey(monkeypatch)

    def _boom():
        raise AssertionError("лёгкий путь не должен звать NO_PROXY direct-check")

    monkeypatch.setattr(health, "_no_proxy_direct_check", _boom)
    result = health.check_all()  # БЕЗ active_claude — лёгкий путь
    names = " ".join(c["name"] for c in result["checks"])
    assert "NO_PROXY direct-reachable" not in names
