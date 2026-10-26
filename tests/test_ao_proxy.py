"""ТДД-тесты ao_proxy: scmProxyUrl AO-демона синхронен с эффективной прокси-конфигурацией.

Контракт (issue #436): PATCH /api/v1/settings/scm-proxy {"url": ...} (сверено с OpenAPI AO —
схема UpdateScmProxyURLRequest, поле url, НЕ scmProxyUrl; чтение — GET /api/v1/settings →
.scmProxyUrl). Значение по контракту srouter: socks5h-туннель (канон git_proxy — SCM-класс),
режим «напрямую» (github-direct split в direct) → пустая строка. Демон не запущен — тихий skip.

Тесты гоняют СОБСТВЕННЫЙ loopback HTTP-заглушку (http.server в потоке) — живой прокси-стек
и живой AO-демон не трогаются: base_url передаётся явно, running.json — в tmp.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import ao_proxy


EXPECTED_PROXY = "socks5h://127.0.0.1:10808"
SETTINGS_PATH = "/api/v1/settings"
SCM_PROXY_PATH = "/api/v1/settings/scm-proxy"


class _StubAO(BaseHTTPRequestHandler):
    """Мини-двойник AO settings API: живой захват PATCH-тел (канон mock-format)."""

    def log_message(self, *args):  # тишина в pytest-выводе
        pass

    def _reply(self, code, payload):
        raw = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == SETTINGS_PATH:
            self._reply(200, {"scmProxyUrl": self.server.scm_proxy_url})
        else:
            self._reply(404, {"error": "not_found"})

    def do_PATCH(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        self.server.patch_calls.append(body)
        if self.server.fail_patch:
            self._reply(self.server.fail_patch, {"error": "boom"})
            return
        self.server.scm_proxy_url = body.get("url", "")
        self._reply(200, {"scmProxyUrl": self.server.scm_proxy_url})


def _start_stub(*, scm_proxy_url="", fail_patch=0):
    server = HTTPServer(("127.0.0.1", 0), _StubAO)
    server.scm_proxy_url = scm_proxy_url
    server.patch_calls = []
    server.fail_patch = fail_patch
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_desired_url_tunnel_by_default(monkeypatch):
    assert ao_proxy.desired_url(github_status={"ok": True, "split": False, "direct": False}) \
        == EXPECTED_PROXY
    assert ao_proxy.desired_url(github_status={"ok": False, "err": "config_unreadable"}) \
        == EXPECTED_PROXY
    # github_status=None → статус читается из live-конфига; в тестах не зависим от машины
    # (на этой машине github-direct может быть включён — канон ambient/machine-dependent).
    monkeypatch.setattr(ao_proxy, "_github_direct_status",
                        lambda: {"ok": True, "split": False, "direct": False})
    assert ao_proxy.desired_url() == EXPECTED_PROXY


def test_desired_url_empty_in_direct_mode():
    # «напрямую» = github-direct split переключён на direct — SCM-хосты мимо туннеля
    assert ao_proxy.desired_url(github_status={"ok": True, "split": True, "direct": True}) == ""


def test_sync_patches_daemon_and_is_idempotent():
    server = _start_stub(scm_proxy_url="")
    try:
        r = ao_proxy.sync(base_url=f"http://127.0.0.1:{server.server_address[1]}",
                          github_status={"ok": True, "split": False, "direct": False})
        assert r["ok"] is True and r.get("changed") is True and r["url"] == EXPECTED_PROXY
        # Тело PATCH — по схеме UpdateScmProxyURLRequest: ключ url (НЕ scmProxyUrl).
        assert server.patch_calls == [{"url": EXPECTED_PROXY}]
        # Повторная синхронизация: значение уже верное — записи нет (идемпотентность).
        r2 = ao_proxy.sync(base_url=f"http://127.0.0.1:{server.server_address[1]}",
                           github_status={"ok": True, "split": False, "direct": False})
        assert r2["ok"] is True and r2.get("changed") is False
        assert len(server.patch_calls) == 1
    finally:
        server.shutdown()


def test_sync_clears_url_in_direct_mode():
    server = _start_stub(scm_proxy_url=EXPECTED_PROXY)
    try:
        r = ao_proxy.sync(base_url=f"http://127.0.0.1:{server.server_address[1]}",
                          github_status={"ok": True, "split": True, "direct": True})
        assert r["ok"] is True and r.get("changed") is True and r["url"] == ""
        assert server.patch_calls == [{"url": ""}]
        assert server.scm_proxy_url == ""
    finally:
        server.shutdown()


def test_sync_silent_skip_when_daemon_down():
    # Порт гарантированно никого не слушает: подняли сервер и сразу закрыли.
    server = _start_stub()
    port = server.server_address[1]
    server.shutdown()
    server.server_close()
    r = ao_proxy.sync(base_url=f"http://127.0.0.1:{port}",
                      github_status={"ok": True, "split": False, "direct": False})
    assert r["ok"] is True
    assert r.get("skipped") == "not_running"


def test_sync_silent_skip_when_running_json_missing(tmp_path):
    r = ao_proxy.sync(running_json=tmp_path / "absent.json",
                      github_status={"ok": True, "split": False, "direct": False})
    assert r["ok"] is True
    assert r.get("skipped") == "not_running"


# Настоящий discovery захватывается ДО autouse-гварда conftest (_block_ao_daemon_http
# глушит ao_proxy._daemon_base_url на время каждого теста) — этот тест проверяет его сам.
_REAL_DAEMON_BASE_URL = ao_proxy._daemon_base_url


def test_daemon_port_from_running_json(tmp_path, monkeypatch):
    monkeypatch.setattr(ao_proxy, "_daemon_base_url", _REAL_DAEMON_BASE_URL)
    running = tmp_path / "running.json"
    running.write_text(json.dumps({"pid": 123, "port": 3456}), encoding="utf-8")
    assert ao_proxy._daemon_base_url(running_json=running) == "http://127.0.0.1:3456"
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert ao_proxy._daemon_base_url(running_json=broken) is None


def test_sync_reports_api_error():
    server = _start_stub(fail_patch=500)
    try:
        r = ao_proxy.sync(base_url=f"http://127.0.0.1:{server.server_address[1]}",
                          github_status={"ok": True, "split": False, "direct": False})
        assert r["ok"] is False
        assert "500" in (r.get("err") or "")
    finally:
        server.shutdown()


# ==================== disable(): снять НАШЕ значение (uninstall-путь, value-match #112) ====================

def test_disable_clears_owned_value():
    server = _start_stub(scm_proxy_url=EXPECTED_PROXY)
    try:
        r = ao_proxy.disable(base_url=f"http://127.0.0.1:{server.server_address[1]}")
        assert r["ok"] is True and r.get("changed") is True
        assert server.patch_calls == [{"url": ""}]
        assert server.scm_proxy_url == ""
    finally:
        server.shutdown()


def test_disable_leaves_foreign_value_alone():
    # чужой корпоративный прокси — НЕ трогаем (fail-closed provenance, канон #112)
    foreign = "http://corp-proxy.example:3128"
    server = _start_stub(scm_proxy_url=foreign)
    try:
        r = ao_proxy.disable(base_url=f"http://127.0.0.1:{server.server_address[1]}")
        assert r["ok"] is True and r.get("changed") is False
        assert server.patch_calls == []
        assert server.scm_proxy_url == foreign
    finally:
        server.shutdown()


def test_disable_silent_skip_when_daemon_down():
    server = _start_stub()
    port = server.server_address[1]
    server.shutdown()
    server.server_close()
    r = ao_proxy.disable(base_url=f"http://127.0.0.1:{port}")
    assert r["ok"] is True
    assert r.get("skipped") == "not_running"


# ==================== хвост cmd_routing: смена маршрута дёргает синк (issue #436) ====================

def test_routing_add_domain_syncs_ao(tmp_path, monkeypatch):
    from types import SimpleNamespace

    import local_state
    import srouter_cli

    calls = []
    monkeypatch.setattr(srouter_cli.ao_proxy, "sync",
                        lambda *a, **k: calls.append(k) or {"ok": True, "changed": False})
    monkeypatch.setattr(local_state, "routing_apply",
                        lambda *a, **k: {"ok": True, "changed": True, "err": ""})

    args = SimpleNamespace(routing_subcommand="add-domain", host="example.com",
                           ips=None, adopt=True, xray_config=str(tmp_path / "c.json"),
                           state=str(tmp_path / "s.json"), outbound=None)
    assert srouter_cli.cmd_routing(args) == 0
    assert len(calls) == 1
