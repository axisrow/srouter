"""ТДД tests: health_devworkflow._git_proxy_route_check — git→github обязан ездить managed SOCKS5.

Инцидент 2026-10-10: глобальный urlmatch-ключ http.https://github.com.proxy исчез из
~/.gitconfig, env HTTPS_PROXY=http://127.0.0.1:8118 молча перехватил git → push поехал через
privoxy и умер вместе с ним. `gh/git direct` — info-only («подсказка») и на самовольное
переключение не краснеет. Новый чек — driver: env-fallthrough / чужой ключ / direct = down.
Источник правды — git_proxy.effective_proxy (лестница слоёв, канон single-source).
"""
import git_proxy
import health
import health_devworkflow
from types import SimpleNamespace  # noqa: F401 — унификация с соседними тест-файлами


def _eff(layer, proxy, detail="mock"):
    return {"proxy": proxy, "layer": layer, "detail": detail}


def _mock_eff(monkeypatch, eff):
    monkeypatch.setattr(health_devworkflow.git_proxy, "effective_proxy", lambda **kw: eff)


def test_git_route_ok_when_managed_socks(monkeypatch):
    """Managed socks-ключ на urlmatch-слое → ok."""
    _mock_eff(monkeypatch, _eff("global-urlmatch", git_proxy._PROXY))
    r = health._git_proxy_route_check()
    assert r["status"] == "ok"
    assert git_proxy._PROXY in r["detail"]


def test_git_route_down_on_env_fallthrough(monkeypatch):
    """КРАСНЫЙ (живой инцидент 2026-10-10): ключа нет, env HTTPS_PROXY=8118 перехватил git
    → down с подсказкой починки. Раньше чека не было — переключение было невидимо."""
    _mock_eff(monkeypatch, _eff("env", "http://127.0.0.1:8118"))
    r = health._git_proxy_route_check()
    assert r["status"] == "down"
    assert "env" in r["detail"]
    assert "8118" in r["detail"]
    assert "srouter git-proxy enable" in r["detail"]


def test_git_route_down_on_foreign_key(monkeypatch):
    """Чужое значение на urlmatch-слое (не наш socks) → down «самовольное переключение»."""
    _mock_eff(monkeypatch, _eff("global-urlmatch", "http://10.0.0.5:3128"))
    r = health._git_proxy_route_check()
    assert r["status"] == "down"
    assert "10.0.0.5" in r["detail"]


def test_git_route_down_when_direct(monkeypatch):
    """Ни ключа, ни env → direct: GFW режет TLS к github, push умрёт → down."""
    _mock_eff(monkeypatch, _eff("direct", ""))
    r = health._git_proxy_route_check()
    assert r["status"] == "down"
    assert "НАПРЯМУЮ" in r["detail"]


def test_git_route_unknown_fail_soft(monkeypatch):
    """Нечитаемый конфиг → unknown (fail-soft, не выдумываем direct)."""
    _mock_eff(monkeypatch, _eff("unknown", "", "конфиг нечитаем"))
    r = health._git_proxy_route_check()
    assert r["status"] == "unknown"
