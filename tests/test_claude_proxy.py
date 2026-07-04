"""ТДД-тесты claude_proxy: round-trip enable/disable/status на tmp-файле (не реальный settings.json).

Проверяет контракт: enable/disable не теряют другие env-ключи, идемпотентны, fail-soft.
"""
import json

import claude_proxy


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
    assert data["env"]["HTTPS_PROXY"] == claude_proxy._PROXY
    assert data["env"]["HTTP_PROXY"] == claude_proxy._PROXY
    s = claude_proxy.status()
    assert s["enabled"] is True
    assert s["proxy"] == claude_proxy._PROXY


def test_enable_preserves_existing_env(monkeypatch, tmp_path):
    """enable НЕ должен терять другие env-ключи (TRAVELPAYOUTS_TOKEN, IS_DEMO и т.д.)."""
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {"EXISTING_KEY": "keep-me"}, "model": "opus"}))
    claude_proxy.enable()
    data = json.loads(settings.read_text())
    assert data["env"]["EXISTING_KEY"] == "keep-me"  # существующий ключ сохранён
    assert data["env"]["HTTPS_PROXY"] == claude_proxy._PROXY  # proxy добавлен
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
    assert data["env"]["HTTPS_PROXY"] == claude_proxy._PROXY


# ============================ NO_PROXY для z.ai (glm идёт напрямую, мимо privoxy) ============================
def test_enable_adds_zai_no_proxy_from_anthropic_base_url(monkeypatch, tmp_path):
    """enable ставит NO_PROXY с хостами из ANTHROPIC_BASE_URL — чтобы glm/z.ai шёл напрямую.

    Без этого z.ai (через privoxy → xray → VPS) = лишний хоп. NO_PROXY = хост + parent-домен (.z.ai).
    """
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic"}}))
    claude_proxy.enable()
    data = json.loads(settings.read_text())
    no_proxy = data["env"].get("NO_PROXY", "")
    assert "api.z.ai" in no_proxy, "NO_PROXY содержит хост из ANTHROPIC_BASE_URL"
    assert ".z.ai" in no_proxy, "NO_PROXY содержит parent-домен (.z.ai суффикс-матч)"
    assert data["env"].get("no_proxy", "") == no_proxy, "оба регистра NO_PROXY/no_proxy"


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
        "NO_PROXY": "corp.local,api.z.ai,.z.ai",
    }}))
    claude_proxy.disable()
    data = json.loads(settings.read_text())
    no_proxy = data["env"].get("NO_PROXY", "")
    assert "api.z.ai" not in no_proxy, "z.ai-хост убран"
    assert ".z.ai" not in no_proxy, "z.ai-суффикс убран"
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
        "HTTPS_PROXY": claude_proxy._PROXY,
        "NO_PROXY": "api.z.ai,.z.ai",
    }}))
    s = claude_proxy.status()
    assert s["enabled"] is True
    assert s["provider_direct"] is True, "хост провайдера в NO_PROXY → provider_direct=True"
    assert "z.ai" in s.get("no_proxy", "")

