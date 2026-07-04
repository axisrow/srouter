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
