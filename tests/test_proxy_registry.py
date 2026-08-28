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
    """Каждая строка обязана нести configured И runtime — это суть панели."""
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    reg = proxy_registry.overview(probe=False)
    assert reg["consumers"], "реестр не может быть пустым"
    for c in reg["consumers"]:
        assert set(("id", "title", "configured", "runtime", "proxy", "detail", "manageable")) <= set(c), c
        assert c["configured"] in (True, False, None)
        assert c["runtime"] in ("ok", "down", "warn", "unknown", "mixed", "n/a")


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
    """Обратная сторона: 'не настроен' НЕ повод скрывать доказанную утечку/поломку."""
    monkeypatch.setattr(proxy_registry.git_proxy, "status",
                        lambda: {"enabled": False, "present": False, "proxy": "",
                                 "values": [], "multi": False, "key": "k"})
    monkeypatch.setattr(proxy_registry, "_health_call",
                        lambda fn: {"status": "down", "detail": "идёт мимо прокси"})
    monkeypatch.setattr(proxy_registry, "_effective", lambda: {"status": "ok"})
    git = _spec(proxy_registry.overview(probe=True), "git")
    assert git["runtime"] == "down"


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
