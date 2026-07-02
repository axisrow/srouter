"""Тесты traffic_shape: mocked, БЕЗ реальных pf/dnctl/root вызовов.

Проверяем: domain->IP резолв, argv команд (список + абсолютные пути + только
validated IP/rate), архитектуру под-anchor com.apple/srouter_throttle (без замены
main ruleset), fail-fast `&&`, token lifecycle с rollback, clear attempt-all
(`|| rc=1`), security (scoped IPv6 / non-canonical / спецсимволы rate -> reject,
sys_probe.run НЕ зван), -128 cancel, функции не бросают.

РЕАЛЬНАЯ семантика osascript (issue #61, доказано экспериментом): при rc != 0
любой команды цепочки `do shell script` ОТБРАСЫВАЕТ stdout (out == ""), error
message (-> err) аккумулирует только stderr цепочки. Моки failure-путей обязаны
кодировать именно это (out="", токен только в err) — мок с токеном в out при
rc != 0 кодирует невозможное состояние и пропускает регрессию зелёной.
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
    # Баг 1: одна osascript-инвокация (один пароль). Fail-fast: сбой самого -E
    # обрывает цепочку через `|| exit $?` (токен не создан — утечки нет), остальные
    # шаги соединены `&&`. Баг 3: НЕТ замены main ruleset.
    calls = []
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")
    monkeypatch.setattr(sys_probe, "run", _apply_ok_run(calls))

    res = traffic_shape.apply_throttle("example.com", 512)

    assert res["ok"] is True
    assert len(calls) == 1, "apply — одна privileged-инвокация (один пароль-промпт)"
    script = calls[0][2]
    # fail-fast самого -E: упал — выходим с его rc, токена нет, утечки нет.
    assert f"t=$({traffic_shape.PFCTL} -E 2>&1) || exit $?" in script
    # config и загрузка anchor — fail-fast связка (сбой dnctl не даёт грузить правила).
    assert "&&" in script, "fail-fast через && между config и загрузкой anchor"
    # Баг 3: НЕТ управления main ruleset — ни pfctl -f <путь>, ни временного файла.
    assert not hasattr(traffic_shape, "MAIN_CONF_PATH")
    assert "pfctl -f /" not in script and "-f /tmp" not in script
    # Правила грузятся в под-anchor через stdin (`-f -`), не через файл.
    # (кавычки anchor-имени экранированы для applescript -> сверяем экранированную форму).
    assert f'-a \\"{traffic_shape.ANCHOR}\\" -f -' in script


def test_apply_throttle_duplicates_token_to_stderr(monkeypatch):
    # Issue #61 фикс 1: реальный osascript при rc != 0 отбрасывает stdout, поэтому
    # токен обязан дублироваться в stderr СРАЗУ после -E — иначе при сбое
    # dnctl/pfctl -a токен потерян и rollback мёртв.
    calls = []
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")
    monkeypatch.setattr(sys_probe, "run", _apply_ok_run(calls))

    traffic_shape.apply_throttle("example.com", 512)

    script = calls[0][2]
    # Экранированные для applescript формы: `\n` -> `\\n`, `"` -> `\"`.
    dup = "printf '%s\\\\n' \\\"$t\\\""              # stdout — success-путь
    dup_err = "printf '%s\\\\n' \\\"$t\\\" 1>&2"     # stderr — переживает сбой цепочки
    # Ровно два printf-дубля: stdout (префикс dup_err — потому count, не `in`).
    assert script.count(dup) == 2, "токен печатается и в stdout, и в stderr"
    assert dup_err in script, "токен дублируется в stderr (failure-путь)"
    # Дубли идут ДО config/загрузки anchor — до первого возможного сбоя после -E.
    assert script.index(dup_err) < script.index("config"), "stderr-дубль до dnctl config"


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


# ============================ владение dummynet pipe (issue #61 фикс 2) ============================
def test_pipe_num_is_nonstandard_high():
    # PIPE_NUM — глобальный id dummynet (НЕ скоупится pf-anchor'ом). Низкие id
    # (1-10) типичны для чужого шейпинга (Network Link Conditioner и т.п.) —
    # наш id обязан быть нестандартно высоким, чтобы не столкнуться.
    assert traffic_shape.PIPE_NUM == 4127
    assert traffic_shape.PIPE_NUM not in range(1, 11)


def test_apply_throttle_pipe_busy_check_runs_first(monkeypatch):
    # Fail-closed владение: ПЕРВАЯ команда privileged-цепочки — проверка, что pipe
    # ещё не существует (dnctl-чтение требует root => проверка внутри цепочки).
    # Существует -> маркер в stderr + exit 71 ДО pfctl -E (токен не создаётся)
    # и ДО dnctl config (чужой pipe не перезаписывается).
    calls = []
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")
    monkeypatch.setattr(sys_probe, "run", _apply_ok_run(calls))

    traffic_shape.apply_throttle("example.com", 512)

    script = calls[0][2]
    busy_check = (
        f"if {traffic_shape.DNCTL} pipe show {traffic_shape.PIPE_NUM} >/dev/null 2>&1; "
        f"then echo {traffic_shape.PIPE_BUSY_MARKER} 1>&2; exit 71; fi"
    )
    assert busy_check in script, "проверка занятости pipe — первой командой цепочки"
    assert script.index("pipe show") < script.index("t=$("), "проверка ДО pfctl -E"
    assert script.index("pipe show") < script.index("config"), "проверка ДО dnctl config"


def test_apply_throttle_rejects_busy_pipe(monkeypatch):
    # Pipe уже существует (чужой шейпинг): exit 71, маркер в stderr-аккумуляторе.
    # ok:false + понятная ошибка, БЕЗ config, БЕЗ rollback (токен не создавался).
    calls = []
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")
    monkeypatch.setattr(
        sys_probe, "run",
        _spy_run(calls, rc=71, out="",
                 err=f"0:45: execution error: {traffic_shape.PIPE_BUSY_MARKER} (71)"),
    )

    res = traffic_shape.apply_throttle("example.com", 512)

    assert res["ok"] is False
    assert "уже существует" in res["err"], "понятная ошибка про чужой pipe"
    assert res.get("token") is None
    assert "rollback" not in res, "до -E не дошли — откатывать нечего"
    assert len(calls) == 1, "никакого config/cleanup после отказа"


def test_clear_throttle_deletes_only_own_pipe(monkeypatch):
    # Инвариант владения: clear удаляет ТОЛЬКО pipe нашего id (создан после
    # busy-проверки apply) — чужие pipe не трогаются.
    calls = []
    monkeypatch.setattr(sys_probe, "run", _spy_run(calls, rc=0))

    traffic_shape.clear_throttle(token="5")

    script = calls[0][2]
    assert f"{traffic_shape.DNCTL} pipe {traffic_shape.PIPE_NUM} delete" in script
    # Ровно одно удаление pipe — только наш id.
    assert script.count("pipe") == script.count(f"pipe {traffic_shape.PIPE_NUM}")


# ============================ token lifecycle (баг 2 + issue #61 фикс 1) ============================
def test_apply_throttle_rollback_on_post_enable_failure(monkeypatch):
    # Issue #61: -E успел, но dnctl упал (rc!=0). РЕАЛЬНЫЙ osascript отбрасывает
    # stdout (out=""), токен доступен ТОЛЬКО из stderr (stderr-дубль цепочки).
    # Токен ОБЯЗАН распарситься из err + запуститься rollback (clear -> pfctl -X 5).
    calls = []
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")

    def fail_after_enable(cmd_list, timeout=None):
        calls.append(cmd_list)
        # apply-инвокация падает: out пуст (реальная семантика), stderr цепочки
        # (stderr-дубль токена + ошибка dnctl) аккумулирован в error message.
        if len(calls) == 1:
            return {
                "rc": 1,
                "out": "",
                "err": "0:123: execution error: Token : 5\ndnctl: setsockopt(IP_DUMMYNET_CONFIGURE): Operation not permitted (1)",
                "timeout": False,
            }
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(sys_probe, "run", fail_after_enable)

    res = traffic_shape.apply_throttle("example.com", 512)

    assert res["ok"] is False
    assert res["token"] == "5", "токен парсится из err при сбое после -E"
    assert "rollback" in res, "best-effort rollback приложен к ответу"
    assert len(calls) == 2, "второй вызов — rollback (только в failure-path)"
    rollback_script = calls[1][2]
    assert f"{traffic_shape.PFCTL} -X 5" in rollback_script, "rollback освобождает enable-ref"


def test_apply_throttle_no_token_no_rollback(monkeypatch):
    # Сбой самого -E (`|| exit $?`): out пуст (реальная семантика), токена нет
    # нигде -> token:None, rollback НЕ зван (нечего освобождать — утечки нет).
    calls = []
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")
    monkeypatch.setattr(
        sys_probe, "run",
        _spy_run(calls, rc=1, out="", err="0:99: execution error: pfctl: pf not enabled (1)"),
    )

    res = traffic_shape.apply_throttle("example.com", 512)

    assert res["ok"] is False
    assert res.get("token") is None
    assert "rollback" not in res
    assert len(calls) == 1, "без токена rollback не запускается"


def test_apply_throttle_ok_without_token_fail_closed(monkeypatch):
    # Issue #61 фикс 1 (fail-closed): rc=0, но токен не распарсен -> это СБОЙ
    # (pf включён, release-token неизвестен, enable-ref может течь), не ok:true.
    # Обязателен best-effort cleanup БЕЗ -X (токена нет): flush anchor + pipe delete.
    calls = []
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")
    monkeypatch.setattr(sys_probe, "run", _spy_run(calls, rc=0, out="", err=""))

    res = traffic_shape.apply_throttle("example.com", 512)

    assert res["ok"] is False, "rc=0 без токена — fail-closed, не успех"
    assert res.get("token") is None
    assert "enable-ref" in res["err"], "явная ошибка про возможную утечку enable-ref"
    assert "rollback" in res, "best-effort cleanup приложен к ответу"
    assert len(calls) == 2, "второй вызов — cleanup"
    cleanup_script = calls[1][2]
    assert "-X" not in cleanup_script, "токена нет — enable-ref не трогаем"
    assert traffic_shape.ANCHOR in cleanup_script, "cleanup чистит наш под-anchor"
    assert f"pipe {traffic_shape.PIPE_NUM} delete" in cleanup_script, "cleanup удаляет наш pipe"


def test_apply_throttle_timeout_token_lost(monkeypatch):
    # Timeout osascript (sys_probe: rc=None, out="", err="timeout"): состояние pf
    # неизвестно, токен потерян -> явная ошибка в результате, rollback невозможен.
    calls = []
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")
    monkeypatch.setattr(
        sys_probe, "run",
        _spy_run(calls, rc=None, out="", err="timeout", timed_out=True),
    )

    res = traffic_shape.apply_throttle("example.com", 512)

    assert res["ok"] is False
    assert res["timeout"] is True
    assert res.get("token") is None
    assert "rollback" not in res, "без токена откатывать нечего"
    assert "enable-ref" in res["err"], "явная ошибка: состояние pf неизвестно, возможна утечка"


def test_apply_throttle_exception_preserves_token(monkeypatch):
    # Широкий except (defensive): -E успел (token распарсен из err — реальная
    # семантика), но rollback бросил исключение -> apply не бросает наружу И не
    # теряет токен (token:"9").
    state = {"n": 0}
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "203.0.113.10")

    def enable_then_boom(cmd_list, timeout=None):
        state["n"] += 1
        if state["n"] == 1:
            # apply упал: out пуст, токен только в stderr-аккумуляторе.
            return {"rc": 1, "out": "", "err": "0:88: execution error: Token : 9\nboom (1)", "timeout": False}
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
