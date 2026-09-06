"""Реестр потребителей прокси: единая нормализованная картина «настроен / физически».

Мотивация: прокси настраивается независимо в 5+ местах (системный macOS, ~/.gitconfig,
~/.claude/settings.json, VSCode settings.json, launchctl setenv), и ни одно из них не знает
про остальные. Пользователь не мог ответить, что включено и работает ли оно.

Ключевое требование — ДВЕ НЕЗАВИСИМЫЕ ОСИ: configured (что записано в родном конфиге) и
runtime (идёт ли трафик на самом деле). Ни одна по отдельности на вопрос не отвечает:
эмпирически наблюдалось и «настроен, но узел мёртв», и «дашборд думает, что выключено».

Формы status() у трёх модулей РАЗНЫЕ (разведано по коду) — реестр обязан их свести:
  git_proxy   : ключ "status" есть ТОЛЬКО в unknown-ветке
  vscode_proxy: "paths" — dict в status() и list в enable()
  claude_proxy: нет ни present, ни status, ни paths
Общее ядро всех трёх — только {enabled, proxy}.
"""
import proxy_registry


def _spec(reg, consumer_id):
    return next(c for c in reg["consumers"] if c["id"] == consumer_id)


def test_every_consumer_has_both_axes(monkeypatch):
    """Каждая строка обязана нести configured И runtime — это суть панели.
    #302: плюс явный класс evidence и process-alive ось running."""
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    reg = proxy_registry.overview(probe=False)
    assert reg["consumers"], "реестр не может быть пустым"
    for c in reg["consumers"]:
        assert set(("id", "title", "configured", "runtime", "proxy", "detail", "manageable",
                    "evidence", "running")) <= set(c), c
        assert c["configured"] in (True, False, None)
        assert c["runtime"] in ("ok", "down", "warn", "unknown", "mixed", "n/a")
        assert c["evidence"] in ("physical", "active-probe", "config-only"), c
        assert c["running"] in (True, False, None), c


def test_git_unknown_branch_without_status_key_is_not_read_as_configured(monkeypatch):
    """git_proxy.status() в unknown-ветке отдаёт status='unknown'; enabled=False там НЕ означает
    «выключено» — git config не ответил. Путать эти два случая нельзя (fail-closed)."""
    monkeypatch.setattr(proxy_registry.git_proxy, "status",
                        lambda: {"enabled": False, "present": False, "proxy": "", "values": [],
                                 "multi": False, "key": "k", "status": "unknown"})
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    git = _spec(proxy_registry.overview(probe=False), "git")
    assert git["configured"] is None      # неизвестно, а не «нет»
    assert git["runtime"] == "unknown"


def test_git_normal_branch_without_status_key_still_parses(monkeypatch):
    """Нормальная ветка git_proxy.status() ключа 'status' НЕ содержит — .get() обязателен."""
    monkeypatch.setattr(proxy_registry.git_proxy, "status",
                        lambda: {"enabled": True, "present": True,
                                 "proxy": "socks5h://127.0.0.1:10808",
                                 "values": ["socks5h://127.0.0.1:10808"], "multi": False, "key": "k"})
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    git = _spec(proxy_registry.overview(probe=False), "git")
    assert git["configured"] is True
    assert git["proxy"] == "socks5h://127.0.0.1:10808"


def test_vscode_paths_dict_shape_does_not_leak_into_registry(monkeypatch):
    """vscode_proxy.status()['paths'] — dict; реестр не обязан его тащить, но и падать не должен."""
    monkeypatch.setattr(proxy_registry.vscode_proxy, "status",
                        lambda: {"enabled": True, "proxy": "socks5h://127.0.0.1:10808",
                                 "paths": {"/a/settings.json": {"present": True, "proxy": "x"}}})
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    vs = _spec(proxy_registry.overview(probe=False), "vscode")
    assert vs["configured"] is True


def test_broken_consumer_never_breaks_the_whole_overview(monkeypatch):
    """Один упавший status() не имеет права уронить всю панель (канон fail-soft)."""
    def boom():
        raise RuntimeError("git config сломался")
    monkeypatch.setattr(proxy_registry.git_proxy, "status", boom)
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    reg = proxy_registry.overview(probe=False)
    git = _spec(reg, "git")
    assert git["configured"] is None
    assert git["runtime"] == "unknown"
    assert len(reg["consumers"]) > 1        # остальные строки на месте


def test_probe_false_skips_the_expensive_measurement(monkeypatch):
    """Открытие страницы должно быть лёгким: парный curl только по явному запросу."""
    called = []
    monkeypatch.setattr(proxy_registry, "_effective", lambda: called.append(1) or {"status": "ok"})
    proxy_registry.overview(probe=False)
    assert called == []
    proxy_registry.overview(probe=True)
    assert called == [1]


def test_mismatch_configured_but_not_working_is_surfaced(monkeypatch):
    """ГЛАВНАЯ строка панели: настроен ✓ + физически ✕. Ради неё всё и делается."""
    monkeypatch.setattr(proxy_registry.git_proxy, "status",
                        lambda: {"enabled": True, "present": True, "proxy": "socks5h://x", "values": ["socks5h://x"], "multi": False, "key": "k"})
    monkeypatch.setattr(proxy_registry, "_health_call",
                        lambda fn: {"status": "down", "detail": "туннель мёртв"})
    monkeypatch.setattr(proxy_registry, "_effective",
                        lambda: {"status": "down", "verdict": "proxy-broken", "works": False})
    reg = proxy_registry.overview(probe=True)
    git = _spec(reg, "git")
    assert git["configured"] is True and git["runtime"] == "down"
    assert any("git" in w for w in reg["warnings"]), reg["warnings"]


def test_stack_reports_privoxy_and_xray(monkeypatch):
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    reg = proxy_registry.overview(probe=False)
    assert set(("privoxy", "xray")) <= set(reg["stack"])


def test_system_proxy_row_is_read_only(monkeypatch):
    """Системный прокси показываем, но управлять им не предлагаем."""
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    sysrow = _spec(proxy_registry.overview(probe=False), "system")
    assert sysrow["manageable"] is False


def test_apply_rejects_unknown_consumer_id():
    """Вайтлист id перед мутацией (канон: роуты валидируют по вайтлисту)."""
    res = proxy_registry.apply(["../../etc/passwd"], action="enable")
    assert res["ok"] is False
    assert res["results"] == [] or all(not r["ok"] for r in res["results"])


def test_apply_rejects_unknown_action():
    res = proxy_registry.apply(["git"], action="destroy")
    assert res["ok"] is False


def test_apply_skips_unmanageable_consumers():
    """system/codex/desktop не имеют write-пути — честный отказ, не молчаливый успех."""
    res = proxy_registry.apply(["system"], action="enable")
    assert res["ok"] is False
    assert res["results"][0]["ok"] is False


def test_not_configured_consumer_does_not_claim_working_proxy(monkeypatch):
    """Если потребитель НЕ настроен на прокси, его runtime не может быть 'ok'.

    Наблюдалось вживую: health._github_direct_check() отдаёт status='ok' со смыслом
    «git корректно ходит НАПРЯМУЮ» — это здоровье git'а, а не доказательство работы прокси.
    В панели «настроен=нет / физически=ok» читалось бы как «прокси работает», что ложь.
    Прокси-путь не задействован -> честное n/a.
    """
    monkeypatch.setattr(proxy_registry.git_proxy, "status",
                        lambda: {"enabled": False, "present": False, "proxy": "",
                                 "values": [], "multi": False, "key": "k"})
    monkeypatch.setattr(proxy_registry, "_health_call",
                        lambda fn: {"status": "ok", "detail": "git идёт напрямую"})
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    git = _spec(proxy_registry.overview(probe=True), "git")
    assert git["configured"] is False
    assert git["runtime"] == "n/a", "не настроен -> прокси-путь не задействован"


def test_not_configured_but_leaking_still_reports_down(monkeypatch):
    """Обратная сторона: 'не настроен' НЕ повод скрывать доказанную утечку/поломку.
    #302: инвариант держится для physical-потребителя (claude) — config-only/active-probe
    строки при configured=False честно уходят в n/a (прокси-путь не задействован)."""
    monkeypatch.setattr(proxy_registry.claude_proxy, "status",
                        lambda: {"enabled": False, "proxy": ""})
    monkeypatch.setattr(proxy_registry, "_health_call",
                        lambda fn: {"status": "down", "detail": "идёт мимо прокси"})
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    row = _spec(proxy_registry.overview(probe=True), "claude")
    assert row["runtime"] == "down"


def test_broken_status_fn_forces_unknown_runtime_even_if_health_fn_succeeds(monkeypatch):
    """ДЫРА (cycle-review PR #299, claim C): упавший status_fn -> configured=None должен
    ЧЕСТНО занулять runtime в 'unknown', даже если health_fn независимо отработал и вернул
    'ok'/'down' — иначе панель покажет «не проверяли, настроен ли» + «физически ok/down»,
    хотя мы вообще не знаем, задействован ли прокси-путь этого потребителя. Существующий
    guard (`if ... and runtime == "n/a"`) ловит только n/a-случай, но не общий."""
    def boom():
        raise RuntimeError("git config сломался")
    monkeypatch.setattr(proxy_registry.git_proxy, "status", boom)
    monkeypatch.setattr(proxy_registry, "_health_call",
                        lambda fn: {"status": "ok", "detail": "git идёт напрямую"})
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    git = _spec(proxy_registry.overview(probe=True), "git")
    assert git["configured"] is None
    assert git["runtime"] == "unknown", (
        f"status_fn упал -> мы не знаем, настроен ли потребитель, значит runtime тоже "
        f"честный unknown, а не значение здоровой (но независимой) health-пробы: {git}"
    )


# ==================== issue #307: state passthrough + force ====================

def test_row_passes_foreign_state_through_to_panel(monkeypatch):
    """ДЫРА #307: foreign обязан дойти до панели как отдельное состояние — иначе клик
    «Включить» выглядит безопасным, хотя уничтожит чужую настройку."""
    monkeypatch.setattr(proxy_registry.git_proxy, "status",
                        lambda: {"enabled": False, "proxy": "https://corp:8443", "state": "foreign"})
    git = _spec(proxy_registry.overview(probe=False), "git")
    assert git["state"] == "foreign"


def test_apply_enable_forwards_force_to_consumer(monkeypatch):
    """force — явный параметр API-контракта: реестр обязан донести его до enable_fn."""
    seen = {}

    def _fake_enable(force=False):
        seen["force"] = force
        return {"ok": True}

    monkeypatch.setattr(proxy_registry.git_proxy, "enable", _fake_enable)
    r = proxy_registry.apply(["git"], action="enable", force=True)
    assert r["ok"] is True
    assert seen["force"] is True


def test_apply_enable_default_force_false(monkeypatch):
    seen = {}

    def _fake_enable(force=False):
        seen["force"] = force
        return {"ok": True}

    monkeypatch.setattr(proxy_registry.git_proxy, "enable", _fake_enable)
    proxy_registry.apply(["git"], action="enable")
    assert seen["force"] is False


def test_apply_passes_conflict_flag_through(monkeypatch):
    """conflict — не рядовая ошибка: панель отличает её для confirm-диалога force."""
    monkeypatch.setattr(proxy_registry.git_proxy, "enable",
                        lambda force=False: {"ok": False, "conflict": True, "state": "foreign",
                                             "err": "foreign value"})
    r = proxy_registry.apply(["git"], action="enable")
    assert r["ok"] is False
    assert r["results"][0]["conflict"] is True


# ==================== issue #302: трёхуровневая ось configured/running/verified ====================

def test_config_only_consumers_never_claim_runtime_ok(monkeypatch):
    """ДЫРА #302 (эмпирика design-анализа): конфиг-пробы vscode/desktop НЕ являются
    доказательством физической работы — их health_fn читает settings.json/launchctl,
    т.е. тот же класс артефакта, что ось configured. Даже когда проба отдаёт ok,
    runtime обязан быть честным 'n/a' (noisy-log-better-than-no-log: ложный ok хуже
    отсутствия ответа)."""
    monkeypatch.setattr(proxy_registry.vscode_proxy, "status",
                        lambda: {"enabled": True, "proxy": "socks5h://127.0.0.1:10808",
                                 "paths": {"/a/settings.json": {"present": True, "proxy": "socks5h://127.0.0.1:10808"}}})
    monkeypatch.setattr(proxy_registry, "_health_call",
                        lambda fn: {"status": "ok", "detail": "якобы физически ok"})
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    reg = proxy_registry.overview(probe=True)
    for cid in ("vscode", "desktop"):
        row = _spec(reg, cid)
        assert row["evidence"] == "config-only", row
        assert row["runtime"] == "n/a", (
            f"{cid}: конфиг-проба не доказывает трафик — runtime обязан быть n/a, "
            f"получено {row['runtime']}")


def test_running_reflects_process_alive_gated(monkeypatch):
    """running — process-alive ось (#302): заполняется ТОЛЬКО когда есть с чем сравнивать
    (гейт по образцу #337), и не выдумывается для потребителей без процесса (git/system)."""
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    monkeypatch.setattr(proxy_registry, "_process_running",
                        lambda cid: {"claude": True, "desktop": True, "vscode": False}.get(cid))
    reg = proxy_registry.overview(probe=True)
    assert _spec(reg, "claude")["running"] is True
    assert _spec(reg, "desktop")["running"] is True
    assert _spec(reg, "vscode")["running"] is False
    assert _spec(reg, "git")["running"] is None


def test_running_not_measured_without_probe(monkeypatch):
    """probe=False — открытие страницы лёгкое: running не измеряется (None), не выдумывается."""
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    monkeypatch.setattr(proxy_registry, "_process_running",
                        lambda cid: (_ for _ in ()).throw(AssertionError("ps не должен зваться без probe")))
    reg = proxy_registry.overview(probe=False)
    assert _spec(reg, "desktop")["running"] is None


def test_git_active_probe_only_when_configured(monkeypatch):
    """git (#302): физический замер возможен только АКТИВНЫЙ (процесс <2с, пассивный lsof
    промахивается — эмпирика design-анализа). runtime идёт из активной пробы; когда
    configured=False/None, прокси-путь git не задействован — проба не зовётся вовсе."""
    monkeypatch.setattr(proxy_registry.git_proxy, "status",
                        lambda: {"enabled": False, "present": False, "proxy": "",
                                 "values": [], "multi": False, "key": "k"})
    monkeypatch.setattr(proxy_registry, "_git_verified",
                        lambda: (_ for _ in ()).throw(AssertionError("проба не должна зваться при configured=False")))
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    git = _spec(proxy_registry.overview(probe=True), "git")
    assert git["evidence"] == "active-probe"
    assert git["runtime"] == "n/a"


def test_git_verified_probe_failure_explains_unknown(monkeypatch):
    """Code-review #347: unknown от упавшей активной пробы обязан нести причину в detail —
    «unknown из ниоткуда» нечитаем (noisy-log-better-than-no-log)."""
    monkeypatch.setattr(proxy_registry.git_proxy, "status",
                        lambda: {"enabled": True, "present": True, "proxy": "http://127.0.0.1:8118",
                                 "values": [], "multi": False, "key": "k"})

    def boom():
        raise RuntimeError("git сломан")
    monkeypatch.setattr(proxy_registry, "_git_verified", boom)
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    git = _spec(proxy_registry.overview(probe=True), "git")
    assert git["runtime"] == "unknown"
    assert "не удалась" in git["detail"], git


def test_git_verified_probe_result_becomes_runtime(monkeypatch):
    """configured=True + probe=True: активный ls-remote стеком самого git — настоящий
    per-потребительский физический замер; его вердикт и есть runtime."""
    monkeypatch.setattr(proxy_registry.git_proxy, "status",
                        lambda: {"enabled": True, "present": True,
                                 "proxy": "http://127.0.0.1:8118",
                                 "values": ["http://127.0.0.1:8118"], "multi": False, "key": "k"})
    monkeypatch.setattr(proxy_registry, "_git_verified",
                        lambda: {"status": "down", "detail": "туннель мёртв"})
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    reg = proxy_registry.overview(probe=True)
    git = _spec(reg, "git")
    assert git["runtime"] == "down"
    # главный сценарий панели работает и для git: настроен + не идёт = предупреждение
    assert any("git" in w for w in reg["warnings"]), reg["warnings"]


def test_git_without_probe_runtime_is_na(monkeypatch):
    """Без явного запроса активной пробы НЕТ (секунды через GFW) — git runtime 'n/a',
    а не выдуманный 'unknown' от конфиг-пробы."""
    monkeypatch.setattr(proxy_registry.git_proxy, "status",
                        lambda: {"enabled": True, "present": True, "proxy": "http://127.0.0.1:8118",
                                 "values": [], "multi": False, "key": "k"})
    monkeypatch.setattr(proxy_registry, "_git_verified",
                        lambda: (_ for _ in ()).throw(AssertionError("активная проба только по probe=True")))
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    git = _spec(proxy_registry.overview(probe=False), "git")
    assert git["runtime"] == "n/a"


# ==================== issue #303: атомарный apply + rollback при partial failure ====================

class _Spy:
    """Шпион мутации: считает вызовы; возвращает result или бросает exc."""

    def __init__(self, exc=None, result=None):
        self.calls = []
        self._exc = exc
        self._result = result

    def __call__(self, *args, **kwargs):
        self.calls.append(1)
        if self._exc is not None:
            raise self._exc
        return self._result if self._result is not None else {"ok": True}


def _spy(exc=None, result=None):
    return _Spy(exc=exc, result=result)


def test_apply_stops_on_first_failure(monkeypatch):
    """ДЫРА #303: после первой ошибки apply НЕ продолжает — не расширяет частично
    изменённое состояние (fail-closed: частично применённый прокси хуже явного отказа)."""
    ok_enable = _spy()
    boom = _spy(exc=RuntimeError("settings.json read-only"))
    vscode_enable = _spy()
    monkeypatch.setattr(proxy_registry.git_proxy, "enable", ok_enable)
    monkeypatch.setattr(proxy_registry.claude_proxy, "enable", boom)
    monkeypatch.setattr(proxy_registry.vscode_proxy, "enable", vscode_enable)
    r = proxy_registry.apply(action="enable")
    assert ok_enable.calls == [1]
    assert boom.calls == [1]
    assert vscode_enable.calls == [], "после первой ошибки оставшиеся потребители не мутируются"
    assert r["ok"] is False
    assert r["failed"]["id"] == "claude"
    assert r["applied"] == ["git"]
    assert r["unattempted"] == ["vscode"]


def test_apply_rolls_back_applied_consumers(monkeypatch):
    """ДЫРА #303: успешные до сбоя мутации откатываются компенсирующим действием —
    пользователь не остаётся в частично применённом состоянии без явного сигнала."""
    monkeypatch.setattr(proxy_registry.git_proxy, "enable", lambda force=False: {"ok": True})
    monkeypatch.setattr(proxy_registry.claude_proxy, "enable",
                        lambda force=False: {"ok": False, "err": "disk full"})
    git_disable = _spy(result={"ok": True})
    monkeypatch.setattr(proxy_registry.git_proxy, "disable", git_disable)
    r = proxy_registry.apply(action="enable")
    assert git_disable.calls == [1], "успешно применённый git обязан быть откачен"
    assert r["rolled_back"] == ["git"]
    assert r["partial"] is True
    assert r["ok"] is False


def test_apply_rollback_failure_is_reported_loudly(monkeypatch):
    """Откат сам может упасть — это НЕ может быть тихим: rollback_errors обязателен."""
    monkeypatch.setattr(proxy_registry.git_proxy, "enable", lambda force=False: {"ok": True})
    monkeypatch.setattr(proxy_registry.claude_proxy, "enable",
                        lambda force=False: (_ for _ in ()).throw(RuntimeError("boom")))
    def broken_disable():
        raise RuntimeError("git config unwritable")
    monkeypatch.setattr(proxy_registry.git_proxy, "disable", broken_disable)
    r = proxy_registry.apply(action="enable")
    assert r["rolled_back"] == []
    assert r["rollback_errors"] == [{"id": "git", "err": "git config unwritable"}]
    assert r["ok"] is False


def test_apply_disable_rollback_restores_via_enable_force(monkeypatch):
    """Откат disable — enable(force=True): восстанавливаем СОБСТВЕННОЕ только что снятое
    значение; conflict-гейт не имеет права заблокировать восстановление."""
    monkeypatch.setattr(proxy_registry.git_proxy, "disable", lambda: {"ok": True})
    monkeypatch.setattr(proxy_registry.claude_proxy, "disable",
                        lambda: {"ok": False, "err": "boom"})
    seen = {}
    def fake_enable(force=False):
        seen["force"] = force
        return {"ok": True}
    monkeypatch.setattr(proxy_registry.git_proxy, "enable", fake_enable)
    r = proxy_registry.apply(action="disable")
    assert seen["force"] is True
    assert r["rolled_back"] == ["git"]


def test_apply_full_success_reports_no_partial(monkeypatch):
    monkeypatch.setattr(proxy_registry.git_proxy, "enable", lambda force=False: {"ok": True})
    monkeypatch.setattr(proxy_registry.claude_proxy, "enable", lambda force=False: {"ok": True})
    monkeypatch.setattr(proxy_registry.vscode_proxy, "enable", lambda force=False: {"ok": True})
    r = proxy_registry.apply(action="enable")
    assert r["ok"] is True
    assert r["partial"] is False
    assert r["rolled_back"] == [] and r["rollback_errors"] == []
    assert r["applied"] == ["git", "claude", "vscode"]
    assert r["unattempted"] == []


def test_apply_conflict_aborts_and_rolls_back(monkeypatch):
    """conflict = неудавшаяся мутация: apply останавливается, ранее применённое откатывается."""
    monkeypatch.setattr(proxy_registry.git_proxy, "enable", lambda force=False: {"ok": True})
    monkeypatch.setattr(proxy_registry.claude_proxy, "enable",
                        lambda force=False: {"ok": False, "conflict": True, "state": "foreign",
                                             "err": "foreign value"})
    git_disable = _spy(result={"ok": True})
    monkeypatch.setattr(proxy_registry.git_proxy, "disable", git_disable)
    r = proxy_registry.apply(action="enable")
    assert git_disable.calls == [1]
    assert r["failed"]["id"] == "claude"
    assert r["rolled_back"] == ["git"]
    assert r["ok"] is False
