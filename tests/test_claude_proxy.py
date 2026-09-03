"""ТДД-тесты claude_proxy: round-trip enable/disable/status на tmp-файле (не реальный settings.json).

Проверяет контракт: enable/disable не теряют другие env-ключи, идемпотентны, fail-soft.
"""
import json

import claude_proxy
from dashboard_common import HTTP_PROXY_URL


EXPECTED_CLAUDE_PROXY = "http://127.0.0.1:8118"


def _setup(monkeypatch, tmp_path):
    """Перенаправить claude_proxy.SETTINGS на tmp-файл (не трогаем реальный ~/.claude/settings.json)."""
    settings = tmp_path / "settings.json"
    monkeypatch.setattr(claude_proxy, "SETTINGS", settings)
    return settings


def test_status_off_when_no_file(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)  # файла нет
    s = claude_proxy.status()
    assert s["enabled"] is False
    assert s["proxy"] == ""


def test_enable_creates_env_and_status_on(monkeypatch, tmp_path):
    settings = _setup(monkeypatch, tmp_path)
    r = claude_proxy.enable()
    assert r["ok"] is True
    data = json.loads(settings.read_text())
    assert data["env"]["HTTPS_PROXY"] == EXPECTED_CLAUDE_PROXY
    assert data["env"]["HTTP_PROXY"] == EXPECTED_CLAUDE_PROXY
    s = claude_proxy.status()
    assert s["enabled"] is True
    assert s["proxy"] == EXPECTED_CLAUDE_PROXY


def test_default_proxy_is_supported_http_bridge():
    """Regression #127: контракт фиксируется независимо от изменяемой `_PROXY`."""
    assert HTTP_PROXY_URL == EXPECTED_CLAUDE_PROXY
    assert claude_proxy._PROXY == EXPECTED_CLAUDE_PROXY


def test_enable_rejects_socks_without_mutating_settings(monkeypatch, tmp_path):
    """Даже будущая ошибочная смена константы не должна записать SOCKS в чужой settings.json."""
    settings = _setup(monkeypatch, tmp_path)
    original = {"env": {"EXISTING_KEY": "keep-me"}, "model": "opus"}
    settings.write_text(json.dumps(original))
    monkeypatch.setattr(claude_proxy, "_PROXY", "socks5h://127.0.0.1:10808")

    result = claude_proxy.enable()

    assert result["ok"] is False
    assert "unsupported proxy scheme" in result["err"]
    assert json.loads(settings.read_text()) == original
    assert claude_proxy.status()["enabled"] is False


def test_enable_overwrites_stale_socks5_from_previous_experiments(monkeypatch, tmp_path):
    """Regression issue #130: settings.json с мусором от экспериментов (SOCKS5 fiasco #127) —
    HTTPS_PROXY=socks5h://... — install-путь (force=True) ДОЛЖЕН уметь перезаписать на HTTP.

    Issue #307: без force такой ключ теперь ЧУЖОЕ значение (state=foreign, enable отказывает);
    перезапись — осознанный force с backup. Модуль не отличает «наш старый мусор» от
    корпоративной настройки — решение принимает вызывающий (CLI install зовёт с force).
    """
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {
        "HTTPS_PROXY": "socks5h://127.0.0.1:10808",
        "HTTP_PROXY": "socks5h://127.0.0.1:10808",
        "KEEP": "yes",
    }}))

    r = claude_proxy.enable(force=True)

    assert r["ok"] is True
    data = json.loads(settings.read_text())
    assert data["env"]["HTTPS_PROXY"] == EXPECTED_CLAUDE_PROXY, "SOCKS5-мусор перезаписан на HTTP"
    assert data["env"]["KEEP"] == "yes"
    # Provenance #307: чужое значение забэкаплено, не потеряно.
    backup = json.loads(claude_proxy._backup_path().read_text())
    assert backup["env"]["HTTPS_PROXY"] == "socks5h://127.0.0.1:10808"
    assert data["env"]["HTTP_PROXY"] == EXPECTED_CLAUDE_PROXY, "SOCKS5-мусор перезаписан на HTTP"
    assert data["env"]["KEEP"] == "yes"
    s = claude_proxy.status()
    assert s["enabled"] is True
    assert s["proxy"] == EXPECTED_CLAUDE_PROXY


def test_enable_preserves_existing_env(monkeypatch, tmp_path):
    """enable НЕ должен терять другие env-ключи (TRAVELPAYOUTS_TOKEN, IS_DEMO и т.д.)."""
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {"EXISTING_KEY": "keep-me"}, "model": "opus"}))
    claude_proxy.enable()
    data = json.loads(settings.read_text())
    assert data["env"]["EXISTING_KEY"] == "keep-me"  # существующий ключ сохранён
    assert data["env"]["HTTPS_PROXY"] == EXPECTED_CLAUDE_PROXY  # proxy добавлен
    assert data["model"] == "opus"  # другие секции не тронуты


def test_disable_removes_proxy_keys(monkeypatch, tmp_path):
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {"HTTPS_PROXY": "http://127.0.0.1:8118",
                                            "HTTP_PROXY": "http://127.0.0.1:8118",
                                            "KEEP": "yes"}}))
    r = claude_proxy.disable()
    assert r["ok"] is True
    data = json.loads(settings.read_text())
    assert "HTTPS_PROXY" not in data["env"]
    assert "HTTP_PROXY" not in data["env"]
    assert data["env"]["KEEP"] == "yes"  # другие ключи не задеты


def test_disable_idempotent(monkeypatch, tmp_path):
    """Повторный disable (ключей уже нет) → ok, не ломает."""
    _setup(monkeypatch, tmp_path)
    r1 = claude_proxy.disable()
    r2 = claude_proxy.disable()
    assert r1["ok"] is True
    assert r2["ok"] is True  # идемпотентно


def test_round_trip_enable_disable_status(monkeypatch, tmp_path):
    """Полный цикл: off → enable → on → disable → off."""
    _setup(monkeypatch, tmp_path)
    assert claude_proxy.status()["enabled"] is False
    assert claude_proxy.enable()["ok"] is True
    assert claude_proxy.status()["enabled"] is True
    assert claude_proxy.disable()["ok"] is True
    assert claude_proxy.status()["enabled"] is False


def test_enable_handles_broken_json(monkeypatch, tmp_path):
    """settings.json битый → enable создаёт свежий env (fail-soft)."""
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text("{ not valid json")
    r = claude_proxy.enable()
    assert r["ok"] is True  # не падает на битом файле
    data = json.loads(settings.read_text())  # результат — валидный JSON
    assert data["env"]["HTTPS_PROXY"] == EXPECTED_CLAUDE_PROXY


# ============================ NO_PROXY для z.ai (glm идёт напрямую, мимо privoxy) ============================
def test_enable_adds_zai_no_proxy_from_anthropic_base_url(monkeypatch, tmp_path):
    """enable ставит NO_PROXY с хостом из ANTHROPIC_BASE_URL — чтобы glm/z.ai шёл напрямую.

    Без этого z.ai (через privoxy → xray → VPS) = лишний хоп. NO_PROXY = только хост (без suffix —
    parent-доменная эвристика ломалась на country-TLD вроде .co.uk).
    """
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic"}}))
    claude_proxy.enable()
    data = json.loads(settings.read_text())
    no_proxy = data["env"].get("NO_PROXY", "")
    assert "api.z.ai" in no_proxy, "NO_PROXY содержит хост из ANTHROPIC_BASE_URL"
    assert data["env"].get("no_proxy", "") == no_proxy, "оба регистра NO_PROXY/no_proxy синхронны"


def test_enable_preserves_existing_no_proxy(monkeypatch, tmp_path):
    """enable НЕ затирает чужой NO_PROXY — merge ( corp.local сохраняется, z.ai добавляется)."""
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {
        "ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic",
        "NO_PROXY": "corp.local,10.0.0.1",
    }}))
    claude_proxy.enable()
    data = json.loads(settings.read_text())
    no_proxy = data["env"]["NO_PROXY"]
    assert "corp.local" in no_proxy, "чужой NO_PROXY-хост сохранён (merge, не затёр)"
    assert "10.0.0.1" in no_proxy, "чужой NO_PROXY-IP сохранён"
    assert "api.z.ai" in no_proxy, "z.ai-хост добавлен"


def test_enable_skips_no_proxy_when_no_base_url(monkeypatch, tmp_path):
    """Без ANTHROPIC_BASE_URL (CC на дефолтном api.anthropic.com) → NO_PROXY не ставим (gate)."""
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {"EXISTING": "keep"}}))
    claude_proxy.enable()
    data = json.loads(settings.read_text())
    assert "NO_PROXY" not in data["env"], "без ANTHROPIC_BASE_URL NO_PROXY не добавляется"
    assert data["env"]["EXISTING"] == "keep"


def test_disable_removes_only_zai_hosts(monkeypatch, tmp_path):
    """disable убирает только z.ai-хосты из NO_PROXY, чужие (corp.local) сохраняет."""
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {
        "ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic",
        "HTTPS_PROXY": "http://127.0.0.1:8118",
        "NO_PROXY": "corp.local,api.z.ai",
    }}))
    claude_proxy.disable()
    data = json.loads(settings.read_text())
    no_proxy = data["env"].get("NO_PROXY", "")
    assert "api.z.ai" not in no_proxy, "provider-хост убран"
    assert "corp.local" in no_proxy, "чужой хост сохранён"


def test_disable_idempotent_no_proxy(monkeypatch, tmp_path):
    """Повторный disable (NO_PROXY уже без z.ai) → ok, не падает, чужое не трогает."""
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {
        "ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic",
        "NO_PROXY": "corp.local",  # z.ai уже убран
    }}))
    r = claude_proxy.disable()
    assert r["ok"] is True
    data = json.loads(settings.read_text())
    assert data["env"]["NO_PROXY"] == "corp.local", "чужой NO_PROXY не изменён"


def test_status_reports_provider_direct(monkeypatch, tmp_path):
    """status() отдаёт provider_direct=True когда хост ANTHROPIC_BASE_URL в NO_PROXY, False иначе."""
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {
        "ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic",
        "HTTPS_PROXY": EXPECTED_CLAUDE_PROXY,
        "NO_PROXY": "api.z.ai",
    }}))
    s = claude_proxy.status()
    assert s["enabled"] is True
    assert s["provider_direct"] is True, "хост провайдера в NO_PROXY → provider_direct=True"
    assert "z.ai" in s.get("no_proxy", "")


def test_enable_merges_divergent_no_proxy_variants(monkeypatch, tmp_path):
    """Regression (cycle 2): рассинхронные NO_PROXY/no_proxy — enable сохраняет хосты из ОБОИХ.

    Раньше enable брал `NO_PROXY or no_proxy` (только одну variant) → при NO_PROXY=a.com,
    no_proxy=b.com вторая терялась. Теперь merge обеих → provider-хост добавляется к полному множеству.
    """
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {
        "ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic",
        "NO_PROXY": "a.com",
        "no_proxy": "b.com",
    }}))
    claude_proxy.enable()
    data = json.loads(settings.read_text())
    # Оба ключа синхронны и содержат хосты из обеих variant + provider.
    for k in ("NO_PROXY", "no_proxy"):
        np = data["env"][k]
        assert "a.com" in np, f"{k}: a.com (из NO_PROXY) сохранён"
        assert "b.com" in np, f"{k}: b.com (из no_proxy) сохранён"
        assert "api.z.ai" in np, f"{k}: provider-хост добавлен"


# ==================== issue #307: foreign state + force-gate + provenance ====================

def test_status_reports_foreign_state_not_configured_false(monkeypatch, tmp_path):
    """ДЫРА #307 (ложный configured=false): чужое HTTPS_PROXY рапортуется как отдельное
    состояние foreign, а не неотличимо от «не настроено»."""
    settings = _setup(monkeypatch, tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({"env": {"HTTPS_PROXY": "http://corp-proxy:3128"}}))
    s = claude_proxy.status()
    assert s["state"] == "foreign"
    assert s["enabled"] is False
    assert s["proxy"] == "http://corp-proxy:3128"


def test_status_states_absent_and_managed_on(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    assert claude_proxy.status()["state"] == "absent"
    claude_proxy.enable()
    assert claude_proxy.status()["state"] == "managed-on"


def test_enable_on_foreign_fails_closed_without_mutation(monkeypatch, tmp_path):
    """ДЫРА #307 (перезапись чужого): enable() на чужое значение обязан отказать ЯВНО
    (conflict) и НЕ трогать settings.json (канон privileged-boundary-fail-closed)."""
    settings = _setup(monkeypatch, tmp_path)
    original = {"env": {"HTTPS_PROXY": "http://corp-proxy:3128", "KEEP": "x"}}
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps(original))

    r = claude_proxy.enable()

    assert r["ok"] is False
    assert r["conflict"] is True
    assert r["state"] == "foreign"
    assert json.loads(settings.read_text()) == original, "чужое значение не тронуто"


def test_enable_force_overwrites_and_backs_up_foreign_value(monkeypatch, tmp_path):
    """force — осознанная перезапись: чужое значение сохраняется в sidecar-backup
    (прецедент #112 provenance), не исчезает безвозвратно."""
    settings = _setup(monkeypatch, tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({"env": {"HTTPS_PROXY": "http://corp-proxy:3128"}}))

    r = claude_proxy.enable(force=True)

    assert r["ok"] is True
    data = json.loads(settings.read_text())
    assert data["env"]["HTTPS_PROXY"] == EXPECTED_CLAUDE_PROXY
    backup = claude_proxy._backup_path()
    assert backup.exists()
    saved = json.loads(backup.read_text())
    assert saved["env"]["HTTPS_PROXY"] == "http://corp-proxy:3128"


def test_enable_without_force_is_idempotent_on_managed_on(monkeypatch, tmp_path):
    """Повторный enable на своём значении — обычный ok, force не нужен."""
    _setup(monkeypatch, tmp_path)
    assert claude_proxy.enable()["ok"] is True
    assert claude_proxy.enable()["ok"] is True
    assert claude_proxy.enable(force=True)["ok"] is True


def test_disable_on_foreign_value_does_not_delete_it(monkeypatch, tmp_path):
    """ДЫРА #307 (удаление чужого при disable): сегодня disable() безусловно удаляет
    env.HTTPS_PROXY/HTTP_PROXY даже когда там чужое значение."""
    settings = _setup(monkeypatch, tmp_path)
    original = {"env": {"HTTPS_PROXY": "http://corp-proxy:3128",
                        "HTTP_PROXY": "http://corp-proxy:3128",
                        "OTHER": "keep"}}
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps(original))

    r = claude_proxy.disable()

    assert r["ok"] is True
    assert json.loads(settings.read_text()) == original, "чужой прокси-ключ не должен удаляться"


def test_disable_after_force_restores_backed_up_foreign_value(monkeypatch, tmp_path):
    """Provenance-цикл: force-enable перезаписал чужое -> disable() восстанавливает ЧУЖОЕ
    значение из backup (а не просто удаляет наш ключ)."""
    settings = _setup(monkeypatch, tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({"env": {"HTTPS_PROXY": "http://corp-proxy:3128"}}))
    assert claude_proxy.enable(force=True)["ok"] is True

    assert claude_proxy.disable()["ok"] is True

    data = json.loads(settings.read_text())
    assert data["env"]["HTTPS_PROXY"] == "http://corp-proxy:3128"
    assert not claude_proxy._backup_path().exists(), "backup потреблён, не висит сиротой"


def test_disable_without_backup_removes_managed_key(monkeypatch, tmp_path):
    """Обычный цикл (наше значение с нуля): disable удаляет ключ, как и раньше."""
    settings = _setup(monkeypatch, tmp_path)
    claude_proxy.enable()
    assert claude_proxy.disable()["ok"] is True
    data = json.loads(settings.read_text())
    assert "HTTPS_PROXY" not in data["env"] and "HTTP_PROXY" not in data["env"]


def test_disable_strips_no_proxy_only_when_managed(monkeypatch, tmp_path):
    """NO_PROXY связан с НАШИМ прокси: при чужом HTTPS_PROXY его трогать нельзя."""
    settings = _setup(monkeypatch, tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({"env": {
        "ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic",
        "HTTPS_PROXY": "http://corp-proxy:3128",
        "NO_PROXY": "api.z.ai,other.internal",
    }}))

    claude_proxy.disable()

    env = json.loads(settings.read_text())["env"]
    assert env["NO_PROXY"] == "api.z.ai,other.internal", "чужой NO_PROXY не тронут"
