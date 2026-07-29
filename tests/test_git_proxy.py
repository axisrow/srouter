"""ТДД-тесты git_proxy: канон issue #130 — git-прокси = SOCKS5 (xray 10808), не HTTP (privoxy 8118).

git умеет нативный SOCKS5 (в отличие от Claude Code, см. claude_proxy.py). Единая таблица #130:
Claude Code → HTTP (privoxy 8118), Codex/git → SOCKS5 (xray 10808). git_proxy раньше использовал
HTTP_PROXY_URL (унаследовано от общего "any client → privoxy" паттерна до разделения #130) — это
несоответствие каноничной таблице, git должен ходить через SOCKS5 как Codex.
"""
import git_proxy
from dashboard_common import SOCKS_PROXY_URL

EXPECTED_GIT_PROXY = "socks5h://127.0.0.1:10808"


def test_default_proxy_is_socks5_xray():
    """Regression #130: git-прокси обязан быть SOCKS5 (xray 10808), НЕ HTTP (privoxy 8118)."""
    assert SOCKS_PROXY_URL == EXPECTED_GIT_PROXY
    assert git_proxy._PROXY == EXPECTED_GIT_PROXY


def test_enable_writes_socks5_url(monkeypatch):
    """enable() прописывает SOCKS5 URL в git config (не HTTP)."""
    calls = []

    def _fake_run(cmd, **_kwargs):
        calls.append(cmd)
        return {"rc": 0, "out": "", "err": ""}

    monkeypatch.setattr(git_proxy.sys_probe, "run", _fake_run)

    r = git_proxy.enable()

    assert r["ok"] is True
    assert r["proxy"] == EXPECTED_GIT_PROXY
    assert calls[-1] == [git_proxy.GIT, "config", "--global", git_proxy.KEY, EXPECTED_GIT_PROXY]


def test_disable_unsets_key(monkeypatch):
    """disable() снимает git-config ключ (--unset), когда там наш managed-прокси. rc=0 → ok."""
    calls = []

    def _fake_run(cmd, **_kwargs):
        calls.append(cmd)
        if "--get" in cmd:
            return {"rc": 0, "out": EXPECTED_GIT_PROXY, "err": ""}
        return {"rc": 0, "out": "", "err": ""}

    monkeypatch.setattr(git_proxy.sys_probe, "run", _fake_run)

    r = git_proxy.disable()

    assert r["ok"] is True
    assert calls[-1] == [git_proxy.GIT, "config", "--global", "--unset", git_proxy.KEY]


def test_disable_idempotent_when_key_absent(monkeypatch):
    """disable() идемпотентен: rc=5 (ключа/раздела не было) — тоже успех, не ошибка."""
    monkeypatch.setattr(git_proxy.sys_probe, "run", lambda cmd, **k: {"rc": 5, "out": "", "err": ""})

    r = git_proxy.disable()

    assert r["ok"] is True


def test_disable_preserves_foreign_value(monkeypatch):
    """Regression (Codex cycle-review PR #221): disable() НЕ должен трогать чужой/ручной прокси.

    fail-closed provenance (канон vscode_proxy.disable — #112): снимать ключ можно только если
    текущее значение == наш managed _PROXY. Корпоративный/ручной прокси (например
    https://corp.example:8443) — НЕ наш, install→uninstall не должен его стирать.
    """
    store = {git_proxy.KEY: "https://corp.example:8443"}

    def _fake_run(cmd, **_kwargs):
        if "--get" in cmd:
            val = store.get(git_proxy.KEY, "")
            return {"rc": 0 if val else 1, "out": val, "err": ""}
        if "--unset" in cmd:
            had = git_proxy.KEY in store
            store.pop(git_proxy.KEY, None)
            return {"rc": 0 if had else 5, "out": "", "err": ""}
        store[git_proxy.KEY] = cmd[-1]
        return {"rc": 0, "out": "", "err": ""}

    monkeypatch.setattr(git_proxy.sys_probe, "run", _fake_run)

    r = git_proxy.disable()

    assert r["ok"] is True
    assert store.get(git_proxy.KEY) == "https://corp.example:8443", "чужое значение не тронуто"


def test_disable_removes_own_managed_value(monkeypatch):
    """disable() снимает ключ, когда значение == наш managed _PROXY (обычный srouter-путь)."""
    store = {git_proxy.KEY: EXPECTED_GIT_PROXY}

    def _fake_run(cmd, **_kwargs):
        if "--get" in cmd:
            val = store.get(git_proxy.KEY, "")
            return {"rc": 0 if val else 1, "out": val, "err": ""}
        if "--unset" in cmd:
            had = git_proxy.KEY in store
            store.pop(git_proxy.KEY, None)
            return {"rc": 0 if had else 5, "out": "", "err": ""}
        store[git_proxy.KEY] = cmd[-1]
        return {"rc": 0, "out": "", "err": ""}

    monkeypatch.setattr(git_proxy.sys_probe, "run", _fake_run)

    r = git_proxy.disable()

    assert r["ok"] is True
    assert git_proxy.KEY not in store, "наш managed прокси снят"


def test_round_trip_enable_disable_status(monkeypatch):
    """Полный цикл install→uninstall: enable ставит SOCKS5, disable снимает, status отражает оба."""
    store = {}

    def _fake_run(cmd, **_kwargs):
        if "--get" in cmd:
            val = store.get(git_proxy.KEY, "")
            return {"rc": 0 if val else 1, "out": val, "err": ""}
        if "--unset" in cmd:
            had = git_proxy.KEY in store
            store.pop(git_proxy.KEY, None)
            return {"rc": 0 if had else 5, "out": "", "err": ""}
        # set: [GIT, config, --global, KEY, VALUE]
        store[git_proxy.KEY] = cmd[-1]
        return {"rc": 0, "out": "", "err": ""}

    monkeypatch.setattr(git_proxy.sys_probe, "run", _fake_run)

    assert git_proxy.status()["enabled"] is False
    assert git_proxy.enable()["ok"] is True
    assert git_proxy.status()["enabled"] is True
    assert git_proxy.status()["proxy"] == EXPECTED_GIT_PROXY
    assert git_proxy.disable()["ok"] is True
    assert git_proxy.status()["enabled"] is False
