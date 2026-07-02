"""Тесты traffic_shape: mocked, БЕЗ реальных pf/dnctl/root вызовов.

Проверяем: domain->IP резолв, argv команд (список + абсолютные пути + только
validated IP/rate), security (scoped IPv6 / non-canonical / спецсимволы rate ->
reject, sys_probe.run НЕ зван), -128 cancel, функции не бросают.
"""
import socket

import sys_probe
import traffic_shape


# ============================ helpers ============================
def _spy_run(calls, rc=0, out="", err="", timed_out=False):
    """Фейковый sys_probe.run: пишет argv в calls, возвращает dashboard-style dict.

    Параметр `timeout` (секунды) реального sys_probe.run — не то же самое, что
    булев флаг `timeout` в результате: их разводим, иначе timeout=60 сек ломает ok.
    """
    def fake_run(cmd_list, timeout=None):
        calls.append(cmd_list)
        return {"rc": rc, "out": out, "err": err, "timeout": timed_out}
    return fake_run


def _spy_apply_run(calls, token="5"):
    """Фейк для apply_throttle: `pfctl -E` возвращает 'Token : <N>', остальное ok.

    apply делает два privileged-вызова: enable (-E, ловим токен из out) и
    настройку shaping. Различаем по вхождению '-E' в applescript-тексте.
    """
    def fake_run(cmd_list, timeout=None):
        calls.append(cmd_list)
        script = cmd_list[2] if len(cmd_list) >= 3 else ""
        if "-E" in script:
            return {"rc": 0, "out": f"Token : {token}", "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}
    return fake_run


# ============================ валидация IP-литерала ============================
def test_ip_literal_accepts_canonical():
    assert traffic_shape._ip_literal("203.0.113.10") is True
    assert traffic_shape._ip_literal("2001:db8::1") is True


def test_ip_literal_rejects_scoped_ipv6():
    # fe80::1%en0 — zone-id обходить границу shell не должен.
    assert traffic_shape._ip_literal("fe80::1%en0") is False


def test_ip_literal_rejects_non_canonical_and_injection():
    assert traffic_shape._ip_literal("203.0.113.010") is False        # non-canonical
    assert traffic_shape._ip_literal("2001:DB8::1") is False           # альт. написание
    assert traffic_shape._ip_literal("203.0.113.10;touch x") is False  # инъекция
    assert traffic_shape._ip_literal("") is False
    assert traffic_shape._ip_literal(None) is False


# ============================ валидация rate ============================
def test_valid_rate_accepts_positive_int():
    assert traffic_shape._valid_rate(512) == "512Kbit/s"
    assert traffic_shape._valid_rate("1000") == "1000Kbit/s"


def test_valid_rate_rejects_non_numeric_and_specials():
    assert traffic_shape._valid_rate("512; touch x") is None
    assert traffic_shape._valid_rate("512Kbit/s") is None   # уже строка с юнитом — не число
    assert traffic_shape._valid_rate("abc") is None
    assert traffic_shape._valid_rate(0) is None             # неположительное
    assert traffic_shape._valid_rate(-5) is None
    assert traffic_shape._valid_rate(None) is None
    assert traffic_shape._valid_rate(1.5) is None           # только целое


# ============================ domain -> IP резолв ============================
def test_resolve_domain_ip_ok(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")
    assert traffic_shape.resolve_domain_ip("example.com") == "203.0.113.10"


def test_resolve_domain_ip_rejects_bad_domain(monkeypatch):
    # shell-небезопасный domain не должен даже дойти до gethostbyname.
    def boom(_h):
        raise AssertionError("gethostbyname не должен вызываться для невалидного домена")
    monkeypatch.setattr(socket, "gethostbyname", boom)
    assert traffic_shape.resolve_domain_ip("bad;touch x.com") == ""
    assert traffic_shape.resolve_domain_ip("") == ""
    assert traffic_shape.resolve_domain_ip(None) == ""


def test_resolve_domain_ip_rejects_non_canonical_result(monkeypatch):
    # Даже если резолвер вернул scoped/non-canonical — режем на _ip_literal.
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "fe80::1%en0")
    assert traffic_shape.resolve_domain_ip("example.com") == ""


def test_resolve_domain_ip_resolver_failure(monkeypatch):
    def boom(_h):
        raise socket.gaierror("no such host")
    monkeypatch.setattr(socket, "gethostbyname", boom)
    assert traffic_shape.resolve_domain_ip("example.com") == ""


# ============================ apply_throttle: argv ============================
def test_apply_throttle_builds_validated_argv(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(traffic_shape, "MAIN_CONF_PATH", str(tmp_path / "srouter_pf.conf"))
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")
    # apply двухшаговый: -E отдаёт 'Token : 5', затем настройка shaping.
    monkeypatch.setattr(sys_probe, "run", _spy_apply_run(calls))

    res = traffic_shape.apply_throttle("example.com", 512)

    assert res["ok"] is True
    assert res["cancelled"] is False
    # Токен pf enable-ref распарсен из 'Token : 5' и возвращён вызывающему.
    assert res["token"] == "5"
    # Все вызовы — список argv, первый элемент абсолютный путь до osascript.
    assert calls, "sys_probe.run должен быть вызван"
    for cmd in calls:
        assert isinstance(cmd, list)
        assert cmd[0] == traffic_shape.OSASCRIPT
        assert cmd[1] == "-e"
    # В applescript-тексте фигурируют абсолютные пути бинарей + validated IP + rate.
    joined = " ".join(cmd[2] for cmd in calls)
    assert traffic_shape.DNCTL in joined
    assert traffic_shape.PFCTL in joined
    assert "203.0.113.10" in joined
    assert "512Kbit/s" in joined
    assert traffic_shape.ANCHOR in joined
    # Никакого сырого domain в командах.
    assert "example.com" not in joined


def test_apply_throttle_installs_anchor_reference_in_main_ruleset(monkeypatch, tmp_path):
    # Баг #1: без dummynet-anchor/anchor ссылки в main ruleset pf не вычисляет
    # наш anchor и throttle не enforce-ится. Проверяем, что модуль ставит ссылку.
    calls = []
    conf = tmp_path / "srouter_pf.conf"
    monkeypatch.setattr(traffic_shape, "MAIN_CONF_PATH", str(conf))
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")
    monkeypatch.setattr(sys_probe, "run", _spy_apply_run(calls))

    res = traffic_shape.apply_throttle("example.com", 512)

    assert res["ok"] is True
    # main-ruleset файл содержит ОБЕ ссылки на наш anchor (dummynet + filter).
    written = conf.read_text()
    assert f'dummynet-anchor "{traffic_shape.ANCHOR}"' in written
    assert f'anchor "{traffic_shape.ANCHOR}"' in written
    # И этот main-ruleset реально грузится через pfctl -f <path>.
    joined = " ".join(cmd[2] for cmd in calls)
    assert f"{traffic_shape.PFCTL} -f {conf}" in joined


def test_apply_throttle_fail_closed_without_token(monkeypatch):
    # Баг #2 fail-closed: если pfctl -E не вернул 'Token : N' — reject,
    # shaping не настраивается (иначе enable-ref утечёт без возможности освободить).
    calls = []
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")

    def no_token_run(cmd_list, timeout=None):
        calls.append(cmd_list)
        return {"rc": 0, "out": "pf enabled", "err": "", "timeout": False}  # без Token

    monkeypatch.setattr(sys_probe, "run", no_token_run)

    res = traffic_shape.apply_throttle("example.com", 512)

    assert res["ok"] is False
    assert res.get("token") in (None, "")
    # После неудачного -E больше ничего privileged не запускаем (только сам -E).
    assert len(calls) == 1, "fail-closed: shaping не строится без токена"


# ============================ apply_throttle: security reject ============================
def test_apply_throttle_rejects_bad_rate_without_running(monkeypatch):
    calls = []
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")
    monkeypatch.setattr(sys_probe, "run", _spy_run(calls))

    res = traffic_shape.apply_throttle("example.com", "512; touch x")

    assert res["ok"] is False
    assert calls == [], "при невалидном rate команда не строится и run НЕ зван"


def test_apply_throttle_rejects_scoped_ip_without_running(monkeypatch):
    calls = []
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "fe80::1%en0")
    monkeypatch.setattr(sys_probe, "run", _spy_run(calls))

    res = traffic_shape.apply_throttle("example.com", 512)

    assert res["ok"] is False
    assert calls == [], "scoped IPv6 -> reject, run НЕ зван"


def test_apply_throttle_rejects_bad_domain_without_running(monkeypatch):
    calls = []
    monkeypatch.setattr(sys_probe, "run", _spy_run(calls))

    res = traffic_shape.apply_throttle("bad;touch x.com", 512)

    assert res["ok"] is False
    assert calls == [], "shell-небезопасный domain -> reject, run НЕ зван"


# ============================ -128 cancel ============================
def test_apply_throttle_cancel_maps_to_cancelled(monkeypatch):
    calls = []
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")
    monkeypatch.setattr(sys_probe, "run", _spy_run(calls, rc=-128, err="User canceled. (-128)"))

    res = traffic_shape.apply_throttle("example.com", 512)

    assert res["cancelled"] is True
    assert res["ok"] is False


# ============================ clear_throttle ============================
def test_clear_throttle_builds_validated_argv(monkeypatch):
    calls = []
    monkeypatch.setattr(sys_probe, "run", _spy_run(calls, rc=0))

    res = traffic_shape.clear_throttle()

    assert res["ok"] is True
    assert calls, "clear должен вызывать sys_probe.run"
    joined = " ".join(cmd[2] for cmd in calls)
    assert traffic_shape.ANCHOR in joined
    for cmd in calls:
        assert cmd[0] == traffic_shape.OSASCRIPT


def test_clear_throttle_releases_enable_token(monkeypatch):
    # Баг #2: clear с токеном должен вызвать pfctl -X <token> для декремента
    # pf enable-reference-count (иначе pf остаётся включён системно).
    calls = []
    monkeypatch.setattr(sys_probe, "run", _spy_run(calls, rc=0))

    res = traffic_shape.clear_throttle(token="5")

    assert res["ok"] is True
    joined = " ".join(cmd[2] for cmd in calls)
    assert f"{traffic_shape.PFCTL} -X 5" in joined


def test_clear_throttle_rejects_non_numeric_token(monkeypatch):
    # Токен интерполируется в shell -> только цифры. Мусорный токен -> не в команде.
    calls = []
    monkeypatch.setattr(sys_probe, "run", _spy_run(calls, rc=0))

    res = traffic_shape.clear_throttle(token="5; rm -rf /")

    joined = " ".join(cmd[2] for cmd in calls)
    assert "rm -rf" not in joined
    assert "-X" not in joined  # невалидный токен не превращается в -X


def test_clear_throttle_without_token_still_flushes(monkeypatch):
    # Без токена clear всё равно чистит anchor+pipe (best-effort), но не зовёт -X.
    calls = []
    monkeypatch.setattr(sys_probe, "run", _spy_run(calls, rc=0))

    res = traffic_shape.clear_throttle()

    assert res["ok"] is True
    joined = " ".join(cmd[2] for cmd in calls)
    assert traffic_shape.ANCHOR in joined
    assert "-X" not in joined


def test_clear_throttle_cancel(monkeypatch):
    calls = []
    monkeypatch.setattr(sys_probe, "run", _spy_run(calls, rc=-128, err="User canceled. (-128)"))
    res = traffic_shape.clear_throttle()
    assert res["cancelled"] is True
    assert res["ok"] is False


# ============================ функции не бросают ============================
def test_functions_never_raise(monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(sys_probe, "run", boom)
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")

    # Ни один из вызовов не должен пробросить исключение наружу.
    r1 = traffic_shape.apply_throttle("example.com", 512)
    r2 = traffic_shape.clear_throttle()
    assert r1["ok"] is False
    assert r2["ok"] is False
