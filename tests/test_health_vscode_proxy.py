"""ТДД-тесты health._vscode_proxy_check: doctor видит scoped SOCKS5 через VSCode http.proxy (#185).

Контракт _vscode_proxy_check() → {status, detail}:
  status="ok"      — хотя бы один существующий settings.json содержит http.proxy == socks5h://10808;
  status="unknown" — ни одного settings.json нет (редактор не установлен) — info-only (как desktop-proxy);
  status="down"    — http.proxy есть, но НЕ socks5 (privoxy/HTTP рвёт WS #120) — driver;
  status="warn"    — один редактор ok, другой foreign/отсутствует — картина, info-only.

Info-only ВСЕГДА (как endpoint-override / desktop-proxy-unknown): VSCode может быть не установлен,
srouter-stack от этого не падает. Чек — диагностика scoped-маршрута codex, НЕ driver.
"""
import health


def _patch_paths(monkeypatch, paths):
    """Перенаправить vscode_proxy.SETTINGS_PATHS на tmp-список."""
    import vscode_proxy
    monkeypatch.setattr(vscode_proxy, "SETTINGS_PATHS", tuple(paths))


def test_vscode_check_unknown_when_no_editor(monkeypatch):
    """Ни одного settings.json → unknown (редактор не установлен), info-only."""
    _patch_paths(monkeypatch, [])  # нет редакторов
    res = health._vscode_proxy_check()
    assert res["status"] == "unknown"
    assert "не установлен" in res["detail"] or "нет" in res["detail"].lower()


def test_vscode_check_ok_when_socks5_present(monkeypatch, tmp_path):
    """settings.json с http.proxy=socks5h://10808 → ok."""
    p = tmp_path / "Code.json"
    p.write_text('{"http.proxy": "socks5h://127.0.0.1:10808"}', encoding="utf-8")
    _patch_paths(monkeypatch, [p])
    res = health._vscode_proxy_check()
    assert res["status"] == "ok"
    assert "10808" in res["detail"] or "socks" in res["detail"].lower()


def test_vscode_check_down_when_http_privoxy(monkeypatch, tmp_path):
    """http.proxy=http://127.0.0.1:8118 (privoxy) → down: рвёт WS #120, driver."""
    p = tmp_path / "Code.json"
    p.write_text('{"http.proxy": "http://127.0.0.1:8118"}', encoding="utf-8")
    _patch_paths(monkeypatch, [p])
    res = health._vscode_proxy_check()
    assert res["status"] == "down"
    assert "8118" in res["detail"] or "http" in res["detail"].lower()


def test_vscode_check_down_when_foreign_proxy(monkeypatch, tmp_path):
    """Чужой http.proxy (корпоративный) → down: не SOCKS5, codex пойдёт не через xray."""
    p = tmp_path / "Code.json"
    p.write_text('{"http.proxy": "http://corp.internal:3128"}', encoding="utf-8")
    _patch_paths(monkeypatch, [p])
    res = health._vscode_proxy_check()
    assert res["status"] == "down"


def test_vscode_check_registered_info_only(monkeypatch):
    """Чек регистрируется в check_all как info-only (не driver — VSCode может отсутствовать)."""
    _patch_paths(monkeypatch, [])  # unknown → info
    # #252 perf: без мока _tunnel_up бьёт реальным curl к api.anthropic.com через прокси (~1s,
    # cProfile). Предмет теста — только vscode-proxy wiring, не туннель.
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200", False))
    result = health.check_all()
    names = [c["name"] for c in result["checks"]]
    assert any("vscode" in n.lower() and "proxy" in n.lower() for n in names), (
        f"check_all должен включать vscode-proxy чек, есть: {names}"
    )
    vs = [c for c in result["checks"] if "vscode" in c["name"].lower()][0]
    assert vs.get("info") is True, "vscode-proxy чек — info-only (редактор может быть не установлен)"
