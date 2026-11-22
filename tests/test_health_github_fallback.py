"""#456: github-фоллбек-вердикт при GFW-окнах — матрица direct ok/мёртв × socks ok/мёртв.

Инцидент 2026-11-05: direct TLS github мёртв, ретрай socks5h умер в ту же минуту, через минуты
тот же путь — 200 за 2.6s. Окна флапают: из одной неудачи нельзя выводить «socks тоже мёртв».
`_github_fallback_check` проверяет ОБА пути явно и отдаёт готовую команду ретрая.

Моки на владельце-фасаде (канон moving-caller-inverts-mock-ownership): чек резолвит
_direct_domain_probe/_github_socks_probe через health — патчим health.*, не health_probes.
На этом уровне мокаем готовые dict'и проб, не run() (канон sys-probe-run-never-raises-oserror:
run не бросает OSError — структуры dict).
"""
import pytest

import sys_probe
import health
import health_probes


DIRECT_OK = {"reachable": True, "kind": "ok"}
DIRECT_DEAD = {"reachable": False, "kind": "timeout"}
SOCKS_OK = {"reachable": True, "kind": "ok"}
SOCKS_DEAD = {"reachable": False, "kind": "connection-failed"}
SPLIT_UNKNOWN = {"status": "unknown", "detail": "mock: разделение github-direct не выполнено"}
SPLIT_ON = {"status": "info", "direct": True, "detail": "github ходит напрямую (режим on)"}


@pytest.fixture(autouse=True)
def _github_direct_split_unknown(monkeypatch):
    """Режим github-direct — с фасада, не из живого xray-конфига dev-машины (там он бывает on).
    По умолчанию «разделение не выполнено» = github в managed → туннель; on-тесты переопределяют."""
    monkeypatch.setattr(health, "_github_direct_split_check", lambda *a, **kw: dict(SPLIT_UNKNOWN))


def _mock_paths(monkeypatch, direct, socks):
    monkeypatch.setattr(health, "_direct_domain_probe", lambda host: dict(direct))
    monkeypatch.setattr(health, "_github_socks_probe", lambda host: dict(socks))


# ==================== матрица вердиктов: direct × socks5h ====================

def test_matrix_direct_ok_socks_ok_is_ok(monkeypatch):
    """Оба живы → ok: git работай напрямую (живой путь помечен рабочим)."""
    _mock_paths(monkeypatch, DIRECT_OK, SOCKS_OK)
    v = health_probes._github_fallback_check()
    assert v["status"] == "ok"
    assert "напрямую" in v["detail"]
    assert not v.get("retry_cmd"), "живой direct не требует команды ретрая"


def test_matrix_direct_ok_socks_dead_is_ok_with_tunnel_note(monkeypatch):
    """direct жив при мёртвом socks5h → ok (путь рабочий) + пометка о деградации туннеля."""
    _mock_paths(monkeypatch, DIRECT_OK, SOCKS_DEAD)
    v = health_probes._github_fallback_check()
    assert v["status"] == "ok"
    assert "connection-failed" in v["detail"], "kind мёртвого socks попадает в detail"
    assert "напрямую" in v["detail"]


def test_matrix_direct_dead_socks_ok_warns_with_retry_cmd(monkeypatch):
    """Ядро #456: direct мёртв (окно), socks5h жив → warn + готовая команда ретрая."""
    _mock_paths(monkeypatch, DIRECT_DEAD, SOCKS_OK)
    v = health_probes._github_fallback_check()
    assert v["status"] == "warn"
    assert "timeout" in v["detail"], "kind мёртвого direct попадает в detail"
    cmd = v.get("retry_cmd") or ""
    # urlmatch-ключ, не generic http.proxy: generic перекрыт managed-ключом
    # http.https://github.com.proxy (git config --get-urlmatch вернул 10808 при -c http.proxy=…11081).
    assert cmd.startswith("git -c http.https://github.com.proxy=socks5h://127.0.0.1:10808"), \
        "готовая команда ретрая тем же путём, что валидирован, и не перекрыта urlmatch-ключом"
    assert "clone|push|fetch" in cmd
    assert "окн" in v["detail"], "совет мгновенного ретрая: окна флапают, ретраи дёшевы"


def test_matrix_direct_dead_socks_dead_is_down(monkeypatch):
    """Оба мёртвы → down: окно накрыло оба; ретрай дёшев — окна короткие."""
    _mock_paths(monkeypatch, DIRECT_DEAD, SOCKS_DEAD)
    v = health_probes._github_fallback_check()
    assert v["status"] == "down"
    assert "timeout" in v["detail"] and "connection-failed" in v["detail"], \
        "kind обоих путей в detail — диагноз без повторных проб"
    assert v.get("retry_cmd"), "команда ретрая остаётся при себе — окна короткие"


# ==================== github-direct on: socks5h 10808 для github — тот же direct ====================
# Инцидент 2026-11-22: режим on (правило _srouter_github → direct стоит выше managed) — «socks5h»-
# проба через 10808 шла тем же direct. Чек писал «оба пути мёртвы — подожди 5–10 мин», пока туннель
# (probe 11081 на тот же узел) отдавал 6/6, и советовал ретрай через тот же мёртвый direct.

def test_github_direct_on_dead_direct_points_to_off_not_wait(monkeypatch):
    """on + direct мёртв → фоллбек = вернуть github в туннель, туннель мёртвым не объявлять."""
    monkeypatch.setattr(health, "_github_direct_split_check", lambda *a, **kw: dict(SPLIT_ON))
    socks_calls = []
    monkeypatch.setattr(health, "_direct_domain_probe", lambda host: dict(DIRECT_DEAD))
    monkeypatch.setattr(health, "_github_socks_probe",
                        lambda host: socks_calls.append(host) or dict(SOCKS_DEAD))
    v = health_probes._github_fallback_check()
    assert not socks_calls, "в режиме on socks-проба — повторный прогон того же direct (до 8 с впустую)"
    assert v["status"] == "down", "рабочего пути для git сейчас нет"
    assert v.get("retry_cmd") == "srouter github-direct off", "в режиме on ретрай через 10808 = тот же direct"
    assert "оба пути мёртвы" not in v["detail"], "туннель не проверялся — не объявлять его мёртвым"
    assert "github-direct on" in v["detail"]


def test_github_direct_on_live_direct_is_ok_without_second_path_claim(monkeypatch):
    """on + direct жив → ok, но без «оба пути живы»: 10808 для github в режиме on — не второй путь."""
    monkeypatch.setattr(health, "_github_direct_split_check", lambda *a, **kw: dict(SPLIT_ON))
    _mock_paths(monkeypatch, DIRECT_OK, SOCKS_OK)
    v = health_probes._github_fallback_check()
    assert v["status"] == "ok"
    assert not v.get("retry_cmd")
    assert "оба пути живы" not in v["detail"]
    assert "github-direct on" in v["detail"]


def test_matrix_garbage_probes_is_unknown(monkeypatch):
    """Мусор от проб (не dict) → unknown, не падение (probe-канон)."""
    monkeypatch.setattr(health, "_direct_domain_probe", lambda host: None)
    monkeypatch.setattr(health, "_github_socks_probe", lambda host: "мусор")
    v = health_probes._github_fallback_check()
    assert v["status"] == "unknown"


def test_both_probes_target_same_github_host(monkeypatch):
    """Обе пробы ходят на ОДИН хост: путь пробы = путь git-ретрая (иначе вердикт лживый)."""
    seen = []
    monkeypatch.setattr(health, "_direct_domain_probe", lambda host: (seen.append(("d", host)) or DIRECT_OK))
    monkeypatch.setattr(health, "_github_socks_probe", lambda host: (seen.append(("s", host)) or SOCKS_OK))
    health_probes._github_fallback_check()
    hosts = [h for _, h in seen]
    assert seen and hosts.count(hosts[0]) == len(seen), "обе пробы — один домен"
    assert hosts[0] == "github.com"


# ==================== _github_socks_probe: обёртка socks-пробы ====================

def test_socks_probe_uses_socks5h_xray_and_clean_env(monkeypatch):
    """Проба идёт через socks5h://127.0.0.1:10808 (-x) с env БЕЗ proxy-переменных.

    Регресс-гварды #456: (1) дверь пробы = дверь git-ретрая (socks5h xray, НЕ privoxy 8118);
    (2) ambient NO_PROXY иначе заставил бы curl с -x обойти прокси (канон #197/#252 —
    _default_manager bound method, патч module-level sys_probe.run не перехватывает).
    """
    captured = {}

    def _fake_run(cmd, timeout, env=None):
        captured["cmd"] = cmd
        captured["env"] = env
        return {"rc": 0, "out": "301", "err": "", "timeout": False}

    monkeypatch.setattr(sys_probe._default_manager, "run", _fake_run)
    r = health_probes._github_socks_probe("github.com")
    cmd = captured["cmd"]
    x = cmd.index("-x")
    assert cmd[x + 1] == "socks5h://127.0.0.1:10808", "проба валидирует ровно socks-путь ретрая"
    assert any(a.startswith("https://github.com/") for a in cmd)
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        assert key not in (captured["env"] or {}), f"ambient {key} должен быть снят"
    assert r == {"reachable": True, "kind": "ok"}


def test_socks_probe_timeout_is_dead(monkeypatch):
    """socks-путь мёртв (timeout) → reachable=False, kind=timeout — как direct_probe."""
    monkeypatch.setattr(sys_probe._default_manager, "run",
                        lambda cmd, timeout, env=None: {"rc": None, "out": "", "err": "", "timeout": True})
    r = health_probes._github_socks_probe("github.com")
    assert r == {"reachable": False, "kind": "timeout"}


def test_socks_probe_5xx_reachable_but_upstream_error(monkeypatch):
    """5xx через socks = путь доставил (сервер ответил) → reachable, kind=upstream-error."""
    monkeypatch.setattr(sys_probe._default_manager, "run",
                        lambda cmd, timeout, env=None: {"rc": 0, "out": "503", "err": "", "timeout": False})
    r = health_probes._github_socks_probe("github.com")
    assert r == {"reachable": True, "kind": "upstream-error"}
