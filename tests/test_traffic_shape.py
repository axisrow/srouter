"""Тесты traffic_shape: mocked, БЕЗ реальных pf/dnctl/root вызовов.

Проверяем: domain->IP резолв, argv команд (список + абсолютные пути + только
validated IP/rate), архитектуру под-anchor com.apple/srouter_throttle (без замены
main ruleset), fail-fast `&&`, token lifecycle с rollback, clear attempt-all
(`|| rc=1`), security (scoped IPv6 / non-canonical / спецсимволы rate -> reject,
sys_probe.run НЕ зван), -128 cancel, функции не бросают.
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


def _apply_ok_run(calls, token="5"):
    """Фейк успешного apply: единственная osascript-инвокация возвращает 'Token : N'.

    apply теперь делает ОДИН privileged-вызов (одна цепочка `&&`). Токен pf
    печатает `pfctl -E` в объединённый stdout — фейк отдаёт его в out.
    """
    def fake_run(cmd_list, timeout=None):
        calls.append(cmd_list)
        return {"rc": 0, "out": f"Token : {token}", "err": "", "timeout": False}
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


# ============================ архитектура: под-anchor com.apple/* ============================
def test_anchor_is_under_com_apple():
    # Баг 3: под-anchor com.apple/* УЖЕ evaluated /etc/pf.conf — main ruleset не трогаем.
    assert traffic_shape.ANCHOR == "com.apple/srouter_throttle"


def test_apply_throttle_single_invocation_fail_fast(monkeypatch):
    # Баг 1: одна osascript-инвокация (один пароль), команды через `&&` (fail-fast),
    # НЕ `;`-склейка (маскирует частичный сбой). Баг 3: НЕТ замены main ruleset.
    calls = []
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")
    monkeypatch.setattr(sys_probe, "run", _apply_ok_run(calls))

    res = traffic_shape.apply_throttle("example.com", 512)

    assert res["ok"] is True
    assert len(calls) == 1, "apply — одна privileged-инвокация (один пароль-промпт)"
    script = calls[0][2]
    assert "&&" in script, "fail-fast через &&"
    # `;`-склейки команд быть не должно (маскирует частичные сбои).
    assert ";" not in script
    # Баг 3: НЕТ управления main ruleset — ни pfctl -f <путь>, ни временного файла.
    assert not hasattr(traffic_shape, "MAIN_CONF_PATH")
    assert "pfctl -f /" not in script and "-f /tmp" not in script
    # Правила грузятся в под-anchor через stdin (`-f -`), не через файл.
    # (кавычки anchor-имени экранированы для applescript -> сверяем экранированную форму).
    assert f'-a \\"{traffic_shape.ANCHOR}\\" -f -' in script


def test_apply_throttle_builds_validated_argv(monkeypatch):
    calls = []
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")
    monkeypatch.setattr(sys_probe, "run", _apply_ok_run(calls))

    res = traffic_shape.apply_throttle("example.com", 512)

    assert res["ok"] is True
    assert res["cancelled"] is False
    # Токен pf enable-ref распарсен из 'Token : 5' и возвращён вызывающему.
    assert res["token"] == "5"
    # Единственный вызов — список argv с абсолютным osascript.
    assert calls, "sys_probe.run должен быть вызван"
    for cmd in calls:
        assert isinstance(cmd, list)
        assert cmd[0] == traffic_shape.OSASCRIPT
        assert cmd[1] == "-e"
    joined = calls[0][2]
    assert traffic_shape.DNCTL in joined
    assert traffic_shape.PFCTL in joined
    assert "203.0.113.10" in joined
    assert "512Kbit/s" in joined
    assert traffic_shape.ANCHOR in joined
    # Никакого сырого domain в командах.
    assert "example.com" not in joined


# ============================ token lifecycle (баг 2) ============================
def test_apply_throttle_rollback_on_post_enable_failure(monkeypatch):
    # Баг 2: -E успел (в out есть 'Token : 5'), но последующая команда упала (rc!=0).
    # Токен ОБЯЗАН вернуться + запуститься best-effort rollback (clear -> pfctl -X 5).
    calls = []
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")

    def fail_after_enable(cmd_list, timeout=None):
        calls.append(cmd_list)
        # apply-инвокация падает, но токен уже напечатан в out; rollback (clear) — ok.
        if len(calls) == 1:
            return {"rc": 1, "out": "Token : 5\npfctl: some error", "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(sys_probe, "run", fail_after_enable)

    res = traffic_shape.apply_throttle("example.com", 512)

    assert res["ok"] is False
    assert res["token"] == "5", "токен не теряется при сбое после -E"
    assert "rollback" in res, "best-effort rollback приложен к ответу"
    assert len(calls) == 2, "второй вызов — rollback (только в failure-path)"
    rollback_script = calls[1][2]
    assert f"{traffic_shape.PFCTL} -X 5" in rollback_script, "rollback освобождает enable-ref"


def test_apply_throttle_no_token_no_rollback(monkeypatch):
    # Сбой ДО -E (out без 'Token') -> token:None, rollback НЕ зван.
    calls = []
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")
    monkeypatch.setattr(sys_probe, "run", _spy_run(calls, rc=1, out="pf: permission denied"))

    res = traffic_shape.apply_throttle("example.com", 512)

    assert res["ok"] is False
    assert res.get("token") is None
    assert "rollback" not in res
    assert len(calls) == 1, "без токена rollback не запускается"


def test_apply_throttle_exception_preserves_token(monkeypatch):
    # Широкий except (defensive): -E успел (token распарсен), но rollback бросил
    # исключение -> apply не бросает наружу И не теряет токен (token:"9").
    state = {"n": 0}
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")

    def enable_then_boom(cmd_list, timeout=None):
        state["n"] += 1
        if state["n"] == 1:
            return {"rc": 1, "out": "Token : 9", "err": "", "timeout": False}  # apply упал, токен есть
        raise RuntimeError("kaboom во время rollback")

    monkeypatch.setattr(sys_probe, "run", enable_then_boom)
    res = traffic_shape.apply_throttle("example.com", 512)
    assert res["ok"] is False
    assert res.get("token") == "9", "токен сохранён даже при исключении в rollback"


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
    # Отмена пароля до появления токена: -128, out пустой.
    monkeypatch.setattr(sys_probe, "run", _spy_run(calls, rc=-128, err="User canceled. (-128)"))

    res = traffic_shape.apply_throttle("example.com", 512)

    assert res["cancelled"] is True
    assert res["ok"] is False
    assert res.get("token") is None
    assert "rollback" not in res, "нет токена — нечего откатывать"


# ============================ clear_throttle ============================
def test_clear_throttle_attempt_all_pattern(monkeypatch):
    # Баг 1 (clear): attempt-all — ВСЕ шаги в одной shell-строке через `|| rc=1`,
    # rc отражает любой сбой; `&&` тут НЕ подходит (маскирует остаток cleanup).
    calls = []
    monkeypatch.setattr(sys_probe, "run", _spy_run(calls, rc=0))

    res = traffic_shape.clear_throttle(token="5")

    assert res["ok"] is True
    assert len(calls) == 1, "clear — одна privileged-инвокация"
    script = calls[0][2]
    assert "|| rc=1" in script, "attempt-all: каждый шаг с || rc=1"
    assert "exit $rc" in script, "честный rc в конце"
    assert traffic_shape.ANCHOR in script
    assert f"{traffic_shape.PFCTL} -X 5" in script


def test_clear_throttle_builds_validated_argv(monkeypatch):
    calls = []
    monkeypatch.setattr(sys_probe, "run", _spy_run(calls, rc=0))

    res = traffic_shape.clear_throttle()

    assert res["ok"] is True
    assert calls, "clear должен вызывать sys_probe.run"
    joined = calls[0][2]
    assert traffic_shape.ANCHOR in joined
    for cmd in calls:
        assert cmd[0] == traffic_shape.OSASCRIPT


def test_clear_throttle_releases_enable_token(monkeypatch):
    # Баг 2: clear с токеном должен вызвать pfctl -X <token> для декремента
    # pf enable-reference-count (иначе pf остаётся включён системно).
    calls = []
    monkeypatch.setattr(sys_probe, "run", _spy_run(calls, rc=0))

    res = traffic_shape.clear_throttle(token="5")

    assert res["ok"] is True
    joined = calls[0][2]
    assert f"{traffic_shape.PFCTL} -X 5" in joined


def test_clear_throttle_rejects_non_numeric_token(monkeypatch):
    # Токен интерполируется в shell -> только цифры. Мусорный токен -> не в команде.
    calls = []
    monkeypatch.setattr(sys_probe, "run", _spy_run(calls, rc=0))

    res = traffic_shape.clear_throttle(token="5; rm -rf /")

    joined = calls[0][2]
    assert "rm -rf" not in joined
    assert "-X" not in joined  # невалидный токен не превращается в -X


def test_clear_throttle_without_token_still_flushes(monkeypatch):
    # Без токена clear всё равно чистит anchor+pipe (attempt-all), но не зовёт -X.
    calls = []
    monkeypatch.setattr(sys_probe, "run", _spy_run(calls, rc=0))

    res = traffic_shape.clear_throttle()

    assert res["ok"] is True
    joined = calls[0][2]
    assert traffic_shape.ANCHOR in joined
    assert "-X" not in joined


def test_clear_throttle_cancel(monkeypatch):
    calls = []
    monkeypatch.setattr(sys_probe, "run", _spy_run(calls, rc=-128, err="User canceled. (-128)"))
    res = traffic_shape.clear_throttle()
    assert res["cancelled"] is True
    assert res["ok"] is False


# ============================ applescript-экранирование ============================
def test_applescript_escaping_of_quotes_and_backslashes(monkeypatch):
    # anchor-имя содержит `/` и кавычки в shell-строке; внутри `do shell script "..."`
    # кавычки/бэкслэши обязаны быть экранированы (канон _applescript_text).
    calls = []
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")
    monkeypatch.setattr(sys_probe, "run", _apply_ok_run(calls))

    traffic_shape.apply_throttle("example.com", 512)

    # applescript-текст (весь argv[2]) обрамлён `do shell script "..."`; внутренние
    # кавычки из `-a "com.apple/..."` должны прийти как \" (экранированные).
    script = calls[0][2]
    assert script.startswith('do shell script "')
    assert '\\"' in script, "внутренние кавычки экранированы для applescript"


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
