"""ТДД-тесты git_proxy: канон issue #130 — git-прокси = SOCKS5 (xray 10808), не HTTP (privoxy 8118).

git умеет нативный SOCKS5 (в отличие от Claude Code, см. claude_proxy.py). Единая таблица #130:
Claude Code → HTTP (privoxy 8118), Codex/git → SOCKS5 (xray 10808). git_proxy раньше использовал
HTTP_PROXY_URL (унаследовано от общего "any client → privoxy" паттерна до разделения #130) — это
несоответствие каноничной таблице, git должен ходить через SOCKS5 как Codex.

Provenance (Codex cycle-review PR #221): disable() снимает KEY ТОЛЬКО если текущее значение ==
наш managed _PROXY (fail-closed value-match, канон vscode_proxy.disable, #112) — ручную смену
прокси ПОСЛЕ install не трогает. enable() перезаписывает безусловно (install = «одна команда,
всё настроено», issue #130). Backup/restore исходного значения ДО install — вынесено в issue #222
(полная provenance-модель: empty-value-aware, multi-value-aware, read-after-write verify — слишком
большой scope для узкого фикса «не стирать чужое»).
"""
import git_proxy
from dashboard_common import SOCKS_PROXY_URL

EXPECTED_GIT_PROXY = "socks5h://127.0.0.1:10808"


def _fake_git(store):
    """Общий fake git-config store: --get/--unset/set по KEY-подобным аргументам. Как реальный git."""
    def _run(cmd, **_kwargs):
        if "--get" in cmd:
            key = cmd[-1]
            val = store.get(key, "")
            return {"rc": 0 if val else 1, "out": val, "err": ""}
        if "--unset" in cmd:
            key = cmd[-1]
            had = key in store
            store.pop(key, None)
            return {"rc": 0 if had else 5, "out": "", "err": ""}
        # set: [GIT, config, --global, KEY, VALUE]
        key, val = cmd[-2], cmd[-1]
        store[key] = val
        return {"rc": 0, "out": "", "err": ""}
    return _run


def test_default_proxy_is_socks5_xray():
    """Regression #130: git-прокси обязан быть SOCKS5 (xray 10808), НЕ HTTP (privoxy 8118)."""
    assert SOCKS_PROXY_URL == EXPECTED_GIT_PROXY
    assert git_proxy._PROXY == EXPECTED_GIT_PROXY


def test_enable_writes_socks5_url(monkeypatch):
    """enable() прописывает SOCKS5 URL в git config (не HTTP)."""
    store = {}
    monkeypatch.setattr(git_proxy.sys_probe, "run", _fake_git(store))

    r = git_proxy.enable()

    assert r["ok"] is True
    assert r["proxy"] == EXPECTED_GIT_PROXY
    assert store[git_proxy.KEY] == EXPECTED_GIT_PROXY


def test_enable_overwrites_existing_value(monkeypatch):
    """enable() перезаписывает существующее значение безусловно (install = «одна команда, всё
    настроено», issue #130) — независимо от того, что там было раньше."""
    store = {git_proxy.KEY: "https://corp.example:8443"}
    monkeypatch.setattr(git_proxy.sys_probe, "run", _fake_git(store))

    r = git_proxy.enable()

    assert r["ok"] is True
    assert store[git_proxy.KEY] == EXPECTED_GIT_PROXY


def test_disable_unsets_key(monkeypatch):
    """disable() снимает git-config ключ, когда там наш managed-прокси."""
    store = {git_proxy.KEY: EXPECTED_GIT_PROXY}
    monkeypatch.setattr(git_proxy.sys_probe, "run", _fake_git(store))

    r = git_proxy.disable()

    assert r["ok"] is True
    assert git_proxy.KEY not in store


def test_disable_idempotent_when_key_absent(monkeypatch):
    """disable() идемпотентен: ключа нет — успех, ничего не делает."""
    store = {}
    monkeypatch.setattr(git_proxy.sys_probe, "run", _fake_git(store))

    r = git_proxy.disable()

    assert r["ok"] is True


def test_disable_preserves_foreign_value(monkeypatch):
    """Regression (Codex cycle-review PR #221): disable() НЕ должен трогать чужой/ручной прокси,
    если ТЕКУЩЕЕ значение не равно нашему managed _PROXY (fail-closed value-match, канон #112)."""
    store = {git_proxy.KEY: "https://corp.example:8443"}
    monkeypatch.setattr(git_proxy.sys_probe, "run", _fake_git(store))

    r = git_proxy.disable()

    assert r["ok"] is True
    assert store.get(git_proxy.KEY) == "https://corp.example:8443", "чужое значение не тронуто"


def test_disable_removes_own_managed_value(monkeypatch):
    """disable() снимает ключ, когда значение == наш managed _PROXY (обычный srouter-путь)."""
    store = {git_proxy.KEY: EXPECTED_GIT_PROXY}
    monkeypatch.setattr(git_proxy.sys_probe, "run", _fake_git(store))

    r = git_proxy.disable()

    assert r["ok"] is True
    assert git_proxy.KEY not in store, "наш managed прокси снят"


def test_round_trip_enable_disable_status(monkeypatch):
    """Полный цикл install→uninstall: enable ставит SOCKS5, disable снимает, status отражает оба."""
    store = {}
    monkeypatch.setattr(git_proxy.sys_probe, "run", _fake_git(store))

    assert git_proxy.status()["enabled"] is False
    assert git_proxy.enable()["ok"] is True
    assert git_proxy.status()["enabled"] is True
    assert git_proxy.status()["proxy"] == EXPECTED_GIT_PROXY
    assert git_proxy.disable()["ok"] is True
    assert git_proxy.status()["enabled"] is False


# ============================ Codex cycle-review PR #221: status() rc handling ============================

def test_status_reports_unknown_on_nonzero_non_absent_rc(monkeypatch):
    """Regression (Codex cycle-review PR #221, confidence 0.99): status() должен различать rc=1
    (ключа нет, задокументированное поведение git config --get) от других ненулевых rc (реальная
    ошибка — permission denied, malformed config, отсутствующий git). Раньше любой rc с пустым out
    → enabled=False, маскируя реальный сбой как "прокси выключен" — disable() затем врал ok=True
    без проверки.
    """
    monkeypatch.setattr(git_proxy.sys_probe, "run",
                        lambda cmd, **k: {"rc": 128, "out": "", "err": "fatal: bad config"})

    s = git_proxy.status()

    assert s["status"] == "unknown", "rc=128 (реальная ошибка) — unknown, НЕ enabled=False"


def test_status_enabled_false_on_documented_absent_rc1(monkeypatch):
    """Контроль: rc=1 + пустой out — задокументированное «ключа нет», enabled=False (не unknown)."""
    monkeypatch.setattr(git_proxy.sys_probe, "run",
                        lambda cmd, **k: {"rc": 1, "out": "", "err": ""})

    s = git_proxy.status()

    assert s.get("status") != "unknown"
    assert s["enabled"] is False


def test_disable_fails_closed_when_status_unknown(monkeypatch):
    """disable() при status()==unknown (реальная ошибка git config) возвращает ok=False —
    НЕ маскирует сбой как успешную очистку (cmd_uninstall полагается на ok для fail-closed rc)."""
    monkeypatch.setattr(git_proxy.sys_probe, "run",
                        lambda cmd, **k: {"rc": 128, "out": "", "err": "fatal: bad config"})

    r = git_proxy.disable()

    assert r["ok"] is False
