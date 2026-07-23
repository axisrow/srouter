"""ТДД-тесты health.check_all + _claude_proxy_probe: doctor видит РЕАЛЬНОЕ состояние Claude-proxy.

Пассивный lsof-probe показывает маршрут живого процесса и ловит direct leak, но не доказывает
поддержку proxy protocol. В частности, established TCP к SOCKS 10808 не означает успешный SOCKS
handshake или ответ API (#127). Поддержку доказывает только active real-CLI test с ожидаемым 401;
его тесты находятся в test_claude_transport.py.

_claude_proxy_probe() возвращает {status, source, detail}:
  status="ok"      — CC держит коннект к ожидаемому HTTP bridge 8118;
  status="down"    — CC имеет внешний direct socket;
  status="unknown" — только SOCKS TCP socket, idle, timeout или CC не запущен.
"""
import pytest as _pytest

import health
import privoxy_system


# Watchdog tests must not inspect the real user's launchd domain or write real lifecycle logs.
# Dedicated lifecycle tests below call the saved implementation explicitly with isolated paths.
_REAL_RECORD_WATCHDOG_LIFECYCLE = getattr(health, "_record_watchdog_lifecycle", None)


def _all_up_monkey(monkeypatch, *, probe_status="ok", probe_detail="runtime: коннект",
                   codex_status="ok", codex_detail="runtime: codex через SOCKS5"):
    """Мок: все порты+туннель живы; _claude_proxy_probe и _codex_proxy_probe отдаёт заданные status.

    Оба probe мокаем (иначе реальный ps/lsof найдёт живой CC/codex на dev-машине → ok → тест
    пройдёт случайно или упадёт в зависимости от того, что запущено). codex_status по умолчанию ok.

    Заглушка «туннель здоров» = (True, HTTP 200): недвусмысленно живой канал. Прежнее
    (True, HTTP 404) полагалось на «любой не-000 = жив» — после фикса #82 семантика строгая
    (5xx=down, 2xx/3xx/4xx=up), 404 остаётся up, но 200 читается однозначнее как здоровый."""
    monkeypatch.setattr(health, "_port_up", lambda port: True)
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200"))
    monkeypatch.setattr(health, "_claude_proxy_probe",
                        lambda: {"status": probe_status, "source": "runtime" if probe_status != "unknown" else "n/a",
                                 "detail": probe_detail})
    monkeypatch.setattr(health, "_codex_proxy_probe",
                        lambda: {"status": codex_status, "source": "runtime" if codex_status != "unknown" else "n/a",
                                 "detail": codex_detail})


# ============================ _claude_proxy_probe (детект lsof) ============================
# Реальный формат `ps comm=` на macOS — ПОЛНЫЕ ПУТИ (не basename, не усечённые):
#   /Users/x/.local/bin/claude                                    (CLI)
#   /Users/x/.local/share/claude/ClaudeCode.app/Contents/MacOS/claude  (GUI pty-host)
#   /Users/x/.local/share/claude/versions/2.1.201                 (version-runner — основной движок)
# Тесты используют именно эти форматы, чтобы ловить regression в фильтре детекции CC.
CLI_COMM = "/Users/me/.local/bin/claude"
GUI_COMM = "/Users/me/.local/share/claude/ClaudeCode.app/Contents/MacOS/claude"
VERSION_RUNNER_COMM = "/Users/me/.local/share/claude/versions/2.1.201"


def test_probe_ok_when_cc_connected_to_proxy(monkeypatch):
    """CLI CC (полный путь в comm) + lsof показал TCP к privoxy 8118 → status=ok."""
    def fake_run(cmd, timeout):
        if cmd and cmd[0] == "/bin/ps":
            return {"rc": 0, "out": f"12345 {CLI_COMM}\n", "err": "", "timeout": False}
        if cmd and cmd[0] == "/usr/sbin/lsof":
            return {"rc": 0, "out": f"claude 12345 axisrow 7u IPv4 ... TCP 127.0.0.1:51234->127.0.0.1:{health.PRIVOXY_PORT} (ESTABLISHED)\n", "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    res = health._claude_proxy_probe()
    assert res["status"] == "ok"
    assert res["source"] == "runtime"
    assert res["detail"]


def test_probe_detects_version_runner_cc(monkeypatch):
    """Regression: version-runner comm=`.../claude/versions/X.Y.Z` (basename=версия) — это тоже CC.

    Раньше whitelist `comm in ('claude','Claude')` пропускал его (basename='2.1.201'). Это основной
    движок CC, который реально держит коннект к privoxy. Фильтр должен его узнавать.
    """
    def fake_run(cmd, timeout):
        if cmd and cmd[0] == "/bin/ps":
            return {"rc": 0, "out": f"48008 {VERSION_RUNNER_COMM}\n", "err": "", "timeout": False}
        if cmd and cmd[0] == "/usr/sbin/lsof":
            return {"rc": 0, "out": f"2.1.201 48008 axisrow 7u IPv4 ... TCP 127.0.0.1:51234->127.0.0.1:{health.PRIVOXY_PORT} (ESTABLISHED)\n", "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    res = health._claude_proxy_probe()
    assert res["status"] == "ok", "version-runner CC должен детектиться (он держит коннект к privoxy)"


def test_probe_unknown_when_cc_has_only_socks_tcp_connection(monkeypatch):
    """Regression #127: TCP к xray доказывает listener/route, но не API transport."""
    def fake_run(cmd, timeout):
        if cmd and cmd[0] == "/bin/ps":
            return {"rc": 0, "out": f"12345 {CLI_COMM}\n", "err": "", "timeout": False}
        if cmd and cmd[0] == "/usr/sbin/lsof":
            return {"rc": 0, "out": f"claude 12345 axisrow 7u IPv4 ... TCP 127.0.0.1:51234->127.0.0.1:{health.XRAY_PORT} (ESTABLISHED)\n", "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    res = health._claude_proxy_probe()
    assert res["status"] == "unknown"
    assert "актив" in res["detail"].lower()
    assert "не доказывает" in res["detail"].lower()


def test_probe_down_when_cc_direct_leak(monkeypatch):
    """CC запущен (GUI comm), lsof показал external ESTABLISHED (не localhost) → down (DIRECT-LEAK).

    CC идёт НАПРЯМУЮ к api.anthropic.com мимо прокси — нарушение fail-closed-proxy-down.
    Doctor обязан детектить и сообщить (главная находка этой сессии).
    """
    def fake_run(cmd, timeout):
        if cmd and cmd[0] == "/bin/ps":
            return {"rc": 0, "out": f"12345 {GUI_COMM}\n", "err": "", "timeout": False}
        if cmd and cmd[0] == "/usr/sbin/lsof":
            # external ESTABLISHED — CC напрямую к Anthropic (не localhost)
            return {"rc": 0, "out": "claude 12345 axisrow 7u IPv4 ... TCP 192.168.1.5:51234->160.79.104.10:443 (ESTABLISHED)\n", "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    res = health._claude_proxy_probe()
    assert res["status"] == "down", "CC идёт напрямую (external) → down (DIRECT-LEAK, fail-closed violation)"


def test_probe_unknown_when_cc_idle_no_sockets(monkeypatch):
    """CC запущен, но нет активных сокетов (idle между запросами) → unknown (не down)."""
    def fake_run(cmd, timeout):
        if cmd and cmd[0] == "/bin/ps":
            return {"rc": 0, "out": f"12345 {CLI_COMM}\n", "err": "", "timeout": False}
        if cmd and cmd[0] == "/usr/sbin/lsof":
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    res = health._claude_proxy_probe()
    assert res["status"] == "unknown", "CC без активных сокетов → unknown (idle, не down)"


def test_probe_down_when_cc_mixed_proxy_and_direct_leak(monkeypatch):
    """HTTP proxy + external одновременно → down (mixed, direct-leak не маскируется proxy).

    Баг: has_proxy=True возвращал ok ДО проверки has_external → один PID через proxy,
    другой напрямую → doctor говорил ok. per-PID классификация: proxy+external = down (mixed).
    """
    def fake_run(cmd, timeout):
        if cmd and cmd[0] == "/bin/ps":
            return {"rc": 0, "out": f"101 {CLI_COMM}\n102 {CLI_COMM}\n", "err": "", "timeout": False}
        if cmd and cmd[0] == "/usr/sbin/lsof":
            # PID 101 через privoxy, PID 102 напрямую (external)
            return {"rc": 0, "out": (
                f"claude 101 axisrow 7u IPv4 ... TCP 127.0.0.1:51234->127.0.0.1:{health.PRIVOXY_PORT} (ESTABLISHED)\n"
                "claude 102 axisrow 7u IPv4 ... TCP 192.168.1.5:51235->160.79.104.10:443 (ESTABLISHED)\n"
            ), "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    res = health._claude_proxy_probe()
    assert res["status"] == "down", "proxy + direct-leak = mixed → down (не ok, direct-leak не маскирован)"


def test_probe_unknown_when_lsof_times_out(monkeypatch):
    """Regression: lsof timed out → status=unknown (НЕ down). Симметрично с ps-timeout.

    Раньше lsof-timeout падал в `down` → пользователь получал ложный degraded + совет «перезапусти CC»,
    хотя коннект мог быть жив (lsof просто не успел под нагрузкой).
    """
    def fake_run(cmd, timeout):
        if cmd and cmd[0] == "/bin/ps":
            return {"rc": 0, "out": f"12345 {CLI_COMM}\n", "err": "", "timeout": False}
        if cmd and cmd[0] == "/usr/sbin/lsof":
            return {"rc": None, "out": "", "err": "timeout", "timeout": True}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    res = health._claude_proxy_probe()
    assert res["status"] == "unknown", "lsof-timeout → unknown (не наградить ложным down)"



def test_probe_unknown_when_cc_not_running(monkeypatch):
    """CC не запущен (ps не нашёл claude) → status=unknown (НЕ down, НЕ ok)."""
    def fake_run(cmd, timeout):
        if cmd and cmd[0] == "/bin/ps":
            return {"rc": 0, "out": "", "err": "", "timeout": False}  # нет claude
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    res = health._claude_proxy_probe()
    assert res["status"] == "unknown", "CC не запущен → unknown (триггерит info-only в check_all)"


def test_probe_ignores_non_cc_processes(monkeypatch):
    """Не-CC процессы не детектятся: desktop Claude.app helper, codex, claude*-wrapper.

    Regression: раньше substring 'claude' в comm ловил desktop Claude.app и wrappers; whitelist basename
    + path-filter пропускает только реальный Claude Code (CLI/GUI/version-runner).
    """
    def fake_run(cmd, timeout):
        if cmd and cmd[0] == "/bin/ps":
            # desktop Claude.app helper (НЕ CC), codex, сторонний wrapper — ни один не CC
            return {"rc": 0, "out": "111 /Applications/Claude.app/Contents/Helpers/chrome-native-host\n222 /usr/local/bin/codex\n333 my-claude-wrapper\n", "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    res = health._claude_proxy_probe()
    assert res["status"] == "unknown", "desktop Claude.app / codex / wrapper — НЕ Claude Code"


# ============================ check_all (агрегация с info-only unknown) ============================
def test_check_all_degraded_when_cc_running_without_proxy(monkeypatch):
    """ДЫРА инцидента: порты+туннель живы, CC реально без прокси (runtime down) → degraded.

    Раньше (файл-only) это давало ложный OK. Теперь runtime видит CC без коннекта → degraded.
    """
    _all_up_monkey(monkeypatch, probe_status="down", probe_detail="runtime: CC без коннекта")
    result = health.check_all()
    assert result["status"] != "ok", "CC без прокси (runtime) → status НЕ ok"
    assert result["status"] == "degraded", "часть жива → degraded, не down"
    cp = [c for c in result["checks"] if "claude" in c["name"].lower()][0]
    assert cp["ok"] is False
    assert cp.get("detail"), "claude-proxy check должен иметь detail"


def test_check_all_ok_when_cc_connected_to_proxy(monkeypatch):
    """Всё живо + CC реально держит коннект (runtime ok) → status=ok (полный успех)."""
    _all_up_monkey(monkeypatch, probe_status="ok")
    result = health.check_all()
    assert result["status"] == "ok"


def test_check_all_ok_when_cc_not_running(monkeypatch):
    """CC НЕ запущен → claude-proxy check = info-only, НЕ роняет вердикт. Порты+туннель живы → ok.

    Раньше unknown сворачивался в файл (дыра доверия файлу). Теперь check_all НЕ агрегирует unknown —
    если srouter-стек жив, status=ok даже без CC. Проверять «CC юзает прокси» бессмысленно без CC.
    """
    _all_up_monkey(monkeypatch, probe_status="unknown", probe_detail="Claude Code не запущен")
    result = health.check_all()
    assert result["status"] == "ok", "CC не запущен → не агрегируем claude-proxy → ok если стек жив"
    cp = [c for c in result["checks"] if "claude" in c["name"].lower()][0]
    assert cp.get("info") is True, "unknown-check помечен info (не driver)"
    assert cp["ok"] is False, "unknown → ok:False в check, но не роняет агрегированный status"


def test_check_all_has_claude_proxy_check(monkeypatch):
    """В checks есть запись про claude-proxy (имя + ok-флаг + detail)."""
    _all_up_monkey(monkeypatch, probe_status="ok")
    result = health.check_all()
    names = [c["name"] for c in result["checks"]]
    assert any("claude" in n.lower() and "proxy" in n.lower() for n in names)


def test_check_all_down_when_everything_dead(monkeypatch):
    """Всё мертво → down (не degraded, не ok)."""
    monkeypatch.setattr(health, "_port_up", lambda port: False)
    monkeypatch.setattr(health, "_tunnel_up", lambda: (False, "connection-failed"))
    monkeypatch.setattr(health, "_claude_proxy_probe",
                        lambda: {"status": "down", "source": "runtime", "detail": "runtime"})
    monkeypatch.setattr(health, "_desktop_proxy_check",
                        lambda: {"status": "down", "detail": "down"})
    # codex-proxy тоже мокаем (иначе реальный ps/lsof найдёт живой codex → ok → не down).
    monkeypatch.setattr(health, "_codex_proxy_probe",
                        lambda: {"status": "down", "source": "runtime", "detail": "runtime"})

    result = health.check_all()
    assert result["status"] == "down"


# ============================ _tunnel_up HTTP semantics (issue #82, класс #3) ============================
def _tunnel_curl_returning(code_out):
    """Мок sys_probe.run для _tunnel_up: curl -w %{http_code} печатает заданный код (любой URL)."""
    return lambda cmd, timeout: {"rc": 0, "out": code_out, "err": "", "timeout": False}


def _tunnel_curl_per_target(codes):
    """Мок sys_probe.run с ответом per-URL: {'anthropic': '503', 'openai': '421'}.

    Таргет распознаётся по подстроке в последнем аргументе curl (URL). Неизвестный → '000'.
    Позволяет проверить избыточность двух таргетов, как в probe_tunnel."""
    def fake_run(cmd, timeout):
        url = cmd[-1] if cmd else ""
        for key, code in codes.items():
            if key in url:
                return {"rc": 0, "out": code, "err": "", "timeout": False}
        return {"rc": 0, "out": "000", "err": "", "timeout": False}
    return fake_run


def test_tunnel_up_5xx_is_down(monkeypatch):
    """503 от мёртвого/сбойного upstream за прокси → туннель НЕ жив. ДЫРА: watchdog слепнет,
    считая 5xx за 'жив' (code != '000')."""
    monkeypatch.setattr(health.sys_probe, "run", _tunnel_curl_returning("503"))
    ok, detail = health._tunnel_up()
    assert ok is False, f"5xx = мёртвый upstream за туннелем, а не 'жив', detail={detail}"
    assert "503" in detail


def test_tunnel_up_502_is_down(monkeypatch):
    """502 Bad Gateway (типовой ответ сбойного прокси/upstream) → down."""
    monkeypatch.setattr(health.sys_probe, "run", _tunnel_curl_returning("502"))
    ok, _ = health._tunnel_up()
    assert ok is False


def test_tunnel_up_404_is_up(monkeypatch):
    """404 (реальный ответ api.anthropic.com/ на '/') = канал жив: сервер ответил через туннель.
    Легит-случай, не ломаем: watchdog не должен ложно паниковать на 404."""
    monkeypatch.setattr(health.sys_probe, "run", _tunnel_curl_returning("404"))
    ok, detail = health._tunnel_up()
    assert ok is True, f"404 от живого сервера = туннель жив, detail={detail}"
    assert "404" in detail


def test_tunnel_up_200_is_up(monkeypatch):
    """200 — очевидно жив (не ломаем)."""
    monkeypatch.setattr(health.sys_probe, "run", _tunnel_curl_returning("200"))
    ok, _ = health._tunnel_up()
    assert ok is True


def test_tunnel_up_000_is_down(monkeypatch):
    """000 на всех таргетах — соединения нет (не ломаем существующее)."""
    monkeypatch.setattr(health.sys_probe, "run", _tunnel_curl_returning("000"))
    ok, detail = health._tunnel_up()
    assert ok is False
    assert "connection-failed" in detail


def test_tunnel_up_timeout_is_down(monkeypatch):
    """timeout на всех таргетах → down (не ломаем)."""
    monkeypatch.setattr(health.sys_probe, "run",
                        lambda cmd, timeout: {"rc": None, "out": "", "err": "timeout", "timeout": True})
    ok, detail = health._tunnel_up()
    assert ok is False
    assert "timeout" in detail


# --- избыточность двух таргетов (как probe_tunnel): origin-5xx одного вендора ≠ туннель упал ---
def test_tunnel_up_origin_5xx_one_vendor_stays_up(monkeypatch):
    """РЕГРЕСС: Anthropic origin-503 (сам вендор лежит), но OpenAI отвечает 421 → туннель ЖИВ.

    ДЫРА: single-target _tunnel_up бьёт только api.anthropic.com — при origin-outage Anthropic
    watchdog ложно крикнет 'туннель упал', хотя канал жив. probe_tunnel устойчив (два таргета,
    up = a OR o) — health обязан вести себя так же."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _tunnel_curl_per_target({"anthropic": "503", "openai": "421"}))
    ok, detail = health._tunnel_up()
    assert ok is True, f"origin-503 одного вендора при живом втором = туннель жив, detail={detail}"


def test_tunnel_up_origin_5xx_other_vendor_stays_up(monkeypatch):
    """Симметрично: OpenAI 500, Anthropic 200 → жив (второй таргет спасает)."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _tunnel_curl_per_target({"anthropic": "200", "openai": "500"}))
    ok, _ = health._tunnel_up()
    assert ok is True


def test_tunnel_up_both_5xx_is_down(monkeypatch):
    """Оба таргета 5xx → down: это уже не origin одного вендора, а сбой прокси/туннеля."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _tunnel_curl_per_target({"anthropic": "503", "openai": "502"}))
    ok, detail = health._tunnel_up()
    assert ok is False, f"оба 5xx = сбой канала, не origin, detail={detail}"


def test_tunnel_up_both_000_is_down(monkeypatch):
    """Оба таргета 000 (нет соединения ни к кому) → down."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _tunnel_curl_per_target({"anthropic": "000", "openai": "000"}))
    ok, detail = health._tunnel_up()
    assert ok is False


def test_tunnel_up_first_target_down_second_up(monkeypatch):
    """Первый таргет не отвечает (000), второй жив (200) → туннель жив (фолбэк работает)."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _tunnel_curl_per_target({"anthropic": "000", "openai": "200"}))
    ok, _ = health._tunnel_up()
    assert ok is True


# ============================ #129: endpoint-override detection (ANTHROPIC_BASE_URL) ============================
# Doctor должен детектить нестандартный ANTHROPIC_BASE_URL + NO_PROXY masking.
# Урок #127: doctor был слеп к endpoint-override → ложный SOCKS5-тест (CC к z.ai напрямую, не через прокси).

def test_endpoint_check_silent_when_standard(monkeypatch):
    """BASE_URL не задан (дефолт api.anthropic.com) → ok, silent."""
    monkeypatch.setattr(health, "_read_endpoint_config",
                        lambda: {"base_url": "", "no_proxy": "", "source": "shell"})
    res = health._endpoint_override_check()
    assert res["status"] == "ok"
    assert "стандарт" in res["detail"].lower()


def test_endpoint_check_ok_when_exact_anthropic_host(monkeypatch):
    """C2: hostname == api.anthropic.com (exact match) → ok, даже если в пути есть другие домены."""
    monkeypatch.setattr(health, "_read_endpoint_config",
                        lambda: {"base_url": "https://api.anthropic.com/v1/messages",
                                 "no_proxy": "", "source": "shell"})
    res = health._endpoint_override_check()
    assert res["status"] == "ok"


def test_endpoint_check_warns_on_lookalike_host(monkeypatch):
    """C2: api.anthropic.com.attacker.example → info (lookalike, НЕ ok).

    Substring match пропустил бы это как «стандартный» — security: подавляет WARN когда
    трафик уходит за Anthropic trust boundary. Exact hostname match ловит.
    """
    monkeypatch.setattr(health, "_read_endpoint_config",
                        lambda: {"base_url": "https://api.anthropic.com.attacker.example/",
                                 "no_proxy": "", "source": "shell"})
    res = health._endpoint_override_check()
    assert res["status"] == "info", "lookalike host → НЕ ok (exact hostname match)"


def test_endpoint_check_warns_when_override(monkeypatch):
    """BASE_URL=z.ai (нестандартный) → info WARN «endpoint override»."""
    monkeypatch.setattr(health, "_read_endpoint_config",
                        lambda: {"base_url": "https://api.z.ai/api/anthropic",
                                 "no_proxy": "localhost", "source": "settings.json"})
    res = health._endpoint_override_check()
    assert res["status"] == "info"
    assert "z.ai" in res["detail"]
    assert "override" in res["detail"].lower() or "нестандарт" in res["detail"].lower()


def test_endpoint_check_warns_when_in_no_proxy(monkeypatch):
    """BASE_URL=z.ai + z.ai в NO_PROXY → info WARN «CC ходит напрямую, прокси нерелевантен»."""
    monkeypatch.setattr(health, "_read_endpoint_config",
                        lambda: {"base_url": "https://api.z.ai/api/anthropic",
                                 "no_proxy": "localhost,127.0.0.1,::1,z.ai,.z.ai",
                                 "source": "settings.json"})
    res = health._endpoint_override_check()
    assert res["status"] == "info"
    assert "напрямую" in res["detail"].lower() or "no_proxy" in res["detail"].lower()


def test_check_all_has_endpoint_override_check(monkeypatch):
    """В checks есть запись про endpoint (ANTHROPIC_BASE_URL)."""
    _all_up_monkey(monkeypatch)
    result = health.check_all()
    names = [c["name"] for c in result["checks"]]
    assert any("endpoint" in n.lower() and "anthropic" in n.lower() for n in names), \
        f"должен быть endpoint-override check, got: {names}"


# ============================ #109: watchdog state-машина + _notify логирование ============================
# Баг: was_ok бинарный (state == "ok") → degraded→down не пушит. + _notify не логирует.


@_pytest.fixture(autouse=True)
def _block_real_watchdog_lifecycle(monkeypatch):
    if hasattr(health, "_record_watchdog_lifecycle"):
        monkeypatch.setattr(health, "_record_watchdog_lifecycle", lambda: None)


def test_watchdog_pushes_on_degraded_to_down(monkeypatch, tmp_path):
    """state=degraded → check_all=down → пуш (переход не-ok→down, не только ok→down)."""
    state_file = tmp_path / "watchdog.last"
    state_file.write_text("degraded")
    monkeypatch.setattr(health, "WATCHDOG_STATE", state_file)
    monkeypatch.setattr(health, "check_all", lambda **kw: {"status": "down", "checks": [{"name": "privoxy", "ok": False}]})
    notified = []
    monkeypatch.setattr(health, "_notify", lambda msg, sound="Glass": notified.append((msg, sound)))
    health.cmd_watchdog()
    assert len(notified) == 1, "degraded→down должен пушить"
    assert "упал" in notified[0][0]


def test_watchdog_pushes_on_ok_to_down(monkeypatch, tmp_path):
    """state=ok → check_all=down → пуш (regression: ok→down работал и раньше)."""
    state_file = tmp_path / "watchdog.last"
    state_file.write_text("ok")
    monkeypatch.setattr(health, "WATCHDOG_STATE", state_file)
    monkeypatch.setattr(health, "check_all", lambda **kw: {"status": "down", "checks": [{"name": "privoxy", "ok": False}]})
    notified = []
    monkeypatch.setattr(health, "_notify", lambda msg, sound="Glass": notified.append((msg, sound)))
    health.cmd_watchdog()
    assert len(notified) == 1


def test_watchdog_silent_on_down_to_down(monkeypatch, tmp_path):
    """state=down → check_all=down → молчит (не спамит)."""
    state_file = tmp_path / "watchdog.last"
    state_file.write_text("down")
    monkeypatch.setattr(health, "WATCHDOG_STATE", state_file)
    monkeypatch.setattr(health, "check_all", lambda **kw: {"status": "down", "checks": [{"name": "privoxy", "ok": False}]})
    notified = []
    monkeypatch.setattr(health, "_notify", lambda msg, sound="Glass": notified.append((msg, sound)))
    health.cmd_watchdog()
    assert len(notified) == 0, "down→down — молчит"


def test_watchdog_recovery_push_on_down_to_ok(monkeypatch, tmp_path):
    """state=down → check_all=ok → тихий пуш восстановления."""
    state_file = tmp_path / "watchdog.last"
    state_file.write_text("down")
    monkeypatch.setattr(health, "WATCHDOG_STATE", state_file)
    monkeypatch.setattr(health, "check_all", lambda **kw: {"status": "ok", "checks": []})
    notified = []
    monkeypatch.setattr(health, "_notify", lambda msg, sound="Glass": notified.append((msg, sound)))
    health.cmd_watchdog()
    assert len(notified) == 1
    assert "восстановлен" in notified[0][0]


# ============================ cycle-review #133: table-driven transition matrix ============================
# Codex C1: degraded→degraded спамило (is_ok collapse). Exact-state transitions решают.
# Полная матрица: каждый (prev, cur) → ожидаемое количество пушей.
_TRANSITIONS = [
    # (prev_state, cur_status, expected_pushes, description)
    ("ok", "down", 1, "ok→down: пуш (новое падение)"),
    ("degraded", "down", 1, "degraded→down: пуш (новое падение)"),
    ("ok", "degraded", 0, "ok→degraded: НЕ пуш (degraded — не «упал»)"),
    ("down", "down", 0, "down→down: молчит (не спам)"),
    ("degraded", "degraded", 0, "degraded→degraded: молчит (не спам — фикс C1)"),
    ("down", "ok", 1, "down→ok: пуш восстановления"),
    ("degraded", "ok", 1, "degraded→ok: пуш восстановления"),
    ("ok", "ok", 0, "ok→ok: молчит"),
    ("", "down", 1, "fresh→down: пуш (первый прогон, уже упало)"),
    ("", "ok", 0, "fresh→ok: НЕ пуш (первый прогон, всё ок — не восстановление)"),
    ("corrupt!!!", "down", 0, "corrupt→down: НЕ пуш (неизвестный prev — безопасно молчим)"),
]


@_pytest.mark.parametrize("prev,cur,expected,desc", _TRANSITIONS, ids=[t[3] for t in _TRANSITIONS])
def test_watchdog_transition_matrix(prev, cur, expected, desc, monkeypatch, tmp_path):
    """Table-driven: каждый (prev, cur) переход → ожидаемое количество пушей (#133 C1)."""
    state_file = tmp_path / "watchdog.last"
    if prev:
        state_file.write_text(prev)
    monkeypatch.setattr(health, "WATCHDOG_STATE", state_file)
    monkeypatch.setattr(health, "check_all",
                        lambda **kw: {"status": cur, "checks": [{"name": "test", "ok": False}] if cur != "ok" else []})
    notified = []
    monkeypatch.setattr(health, "_notify", lambda msg, sound="Glass": notified.append((msg, sound)))
    health.cmd_watchdog()
    assert len(notified) == expected, f"{desc}: ожидал {expected} пушей, получил {len(notified)}"


def test_notify_logs_to_file(monkeypatch, tmp_path):
    """_notify пишет audit trail в лог-файл (timestamp + msg)."""
    log_file = tmp_path / "srouter-watchdog.notify.log"
    monkeypatch.setattr(health, "WATCHDOG_NOTIFY_LOG", log_file)
    monkeypatch.setattr(health.sys_probe, "run", lambda cmd, timeout: {"rc": 0, "out": "", "err": "", "timeout": False})
    health._notify("test message", "Basso")
    content = log_file.read_text(encoding="utf-8")
    assert "test message" in content
    assert "Basso" in content


# ============================ #134: Desktop App proxy (launchctl getenv) ============================
# CLI читает settings.json, Desktop App читает launchctl getenv (gui-домен launchd). launchctl держит
# ТРИ ключа (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY); инцидент #127 — SOCKS5 сидел в HTTP_PROXY. Doctor
# показывает все найденные ключи «как есть»; SOCKS5 в ЛЮБОМ → down (Claude через SOCKS не умеет, #127).

# --- _desktop_proxy_check: классификация по desktop_keys (мокаем _read_proxy_sources целиком) ---

def test_desktop_proxy_ok_when_only_http(monkeypatch):
    """launchctl: HTTPS_PROXY=http://8118 (только HTTP) → ok, detail перечисляет ключ."""
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"HTTPS_PROXY": "http://127.0.0.1:8118"}})
    res = health._desktop_proxy_check()
    assert res["status"] == "ok"
    assert "HTTPS_PROXY" in res["detail"]


def test_desktop_proxy_down_when_socks5_in_https_proxy(monkeypatch):
    """SOCKS5 в HTTPS_PROXY → down (Desktop App не поддерживает SOCKS5)."""
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"HTTPS_PROXY": "socks5h://127.0.0.1:10808"}})
    res = health._desktop_proxy_check()
    assert res["status"] == "down"
    assert "socks" in res["detail"].lower() or "SOCKS5" in res["detail"]


def test_desktop_proxy_down_when_socks5_in_http_proxy(monkeypatch):
    """SOCKS5 в HTTP_PROXY (не HTTPS_PROXY) → down. РЕГРЕССИЯ на инцидент #127: SOCKS5 сидел в
    HTTP_PROXY, doctor (читая только HTTPS_PROXY) говорил ✅."""
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"HTTP_PROXY": "socks5h://127.0.0.1:10808"}})
    res = health._desktop_proxy_check()
    assert res["status"] == "down"
    assert "HTTP_PROXY" in res["detail"]


def test_desktop_proxy_down_when_socks5_in_all_proxy(monkeypatch):
    """SOCKS5 в ALL_PROXY → down (SOCKS5 в любом ключе — мина)."""
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"ALL_PROXY": "socks5h://127.0.0.1:10808"}})
    res = health._desktop_proxy_check()
    assert res["status"] == "down"


def test_desktop_proxy_ok_when_http_in_all_keys(monkeypatch):
    """Все три ключа HTTP → ok, detail перечисляет все найденные ключи «как есть»."""
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"HTTPS_PROXY": "http://127.0.0.1:8118",
                                                  "HTTP_PROXY": "http://127.0.0.1:8118",
                                                  "ALL_PROXY": "http://127.0.0.1:8118"}})
    res = health._desktop_proxy_check()
    assert res["status"] == "ok"
    assert "HTTPS_PROXY" in res["detail"]
    assert "HTTP_PROXY" in res["detail"]
    assert "ALL_PROXY" in res["detail"]


def test_desktop_proxy_unknown_when_no_launchctl(monkeypatch):
    """launchctl пуст (ничего не задано) → unknown, не driver (как claude-proxy)."""
    monkeypatch.setattr(health, "_read_proxy_sources", lambda: {"desktop_keys": {}})
    res = health._desktop_proxy_check()
    assert res["status"] == "unknown"


def test_desktop_proxy_down_shadows_socks5_even_with_http(monkeypatch):
    """HTTPS_PROXY=HTTP + HTTP_PROXY=SOCKS5 → down (не угадываем selector; SOCKS5 — мина).

    У приложений разный selector приоритетов (Claude/Node/Electron), мы его НЕ моделируем —
    SOCKS5 в любом ключе = конфиг грязный/опасный → down. Фиксирует границу обобщения #134."""
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"HTTPS_PROXY": "http://127.0.0.1:8118",
                                                  "HTTP_PROXY": "socks5h://127.0.0.1:10808"}})
    res = health._desktop_proxy_check()
    assert res["status"] == "down"


def test_desktop_proxy_http_host_named_socks_not_false_down(monkeypatch):
    """HTTP-прокси с 'socks' в имени хоста → ok (scheme=http, не подстрока).

    Регрессия на scheme-классификацию: 'http://socks.local:8118' — легитимный HTTP-прокси,
    подстрока 'socks' в нём НЕ должна давать down (канон loose-validator, health.py:313)."""
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"HTTPS_PROXY": "http://socks.local:8118"}})
    res = health._desktop_proxy_check()
    assert res["status"] == "ok"


def test_desktop_proxy_warns_on_settings_vs_launchctl_mismatch(monkeypatch):
    """settings.json HTTPS_PROXY (CLI) != launchctl HTTPS_PROXY (Desktop) → WARN расхождение.

    Issue #134 п.2: CLI и Desktop App читают прокси из РАЗНЫХ источников. Расхождение — реальный
    инцидент-класс (#127): один клиент работает, другой сломан, а doctor молчит. cycle-review gap:
    коммит ff0bd74 (обход всех 3 launchctl-ключей) заменил _read_proxy_sources без переноса
    cli_proxy/mismatch-логики из ad4ccc4 — регрессия, PR body всё ещё заявляет "Расхождение → WARN",
    но код и тесты её не содержали."""
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"HTTPS_PROXY": "http://127.0.0.1:8118"},
                                "cli_proxy": "socks5h://127.0.0.1:10808"})
    res = health._desktop_proxy_check()
    assert res["status"] == "warn"
    assert "socks5h://127.0.0.1:10808" in res["detail"]
    assert "http://127.0.0.1:8118" in res["detail"]


def test_desktop_proxy_silent_when_settings_matches_launchctl(monkeypatch):
    """settings.json HTTPS_PROXY == launchctl HTTPS_PROXY → ok, без WARN о расхождении."""
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"HTTPS_PROXY": "http://127.0.0.1:8118"},
                                "cli_proxy": "http://127.0.0.1:8118"})
    res = health._desktop_proxy_check()
    assert res["status"] == "ok"


def test_desktop_proxy_no_mismatch_check_when_cli_proxy_unset(monkeypatch):
    """cli_proxy пуст (CLI proxy не настроен) → нет ложного mismatch, обычная launchctl-классификация."""
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"HTTPS_PROXY": "http://127.0.0.1:8118"},
                                "cli_proxy": ""})
    res = health._desktop_proxy_check()
    assert res["status"] == "ok"


def test_desktop_proxy_socks5_down_takes_priority_over_mismatch(monkeypatch):
    """SOCKS5 в launchctl (down) важнее расхождения с CLI — down не маскируется в warn."""
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"HTTPS_PROXY": "socks5h://127.0.0.1:10808"},
                                "cli_proxy": "http://127.0.0.1:8118"})
    res = health._desktop_proxy_check()
    assert res["status"] == "down"


def test_read_proxy_sources_includes_cli_proxy_from_settings_json(monkeypatch):
    """_read_proxy_sources читает HTTPS_PROXY из settings.json как cli_proxy (issue #134 п.2)."""
    class FakeClaudeProxy:
        @staticmethod
        def _load():
            return {"env": {"HTTPS_PROXY": "http://127.0.0.1:8118"}}
    monkeypatch.setitem(__import__("sys").modules, "claude_proxy", FakeClaudeProxy())
    monkeypatch.setattr(health.sys_probe, "run", _lc_run_per_key({}))
    src = health._read_proxy_sources()
    assert src["cli_proxy"] == "http://127.0.0.1:8118"


# --- _read_proxy_sources: контракт обхода launchctl-ключей (мокаем sys_probe.run) ---

def _lc_run_per_key(vals, timeout_keys=()):
    """Мок sys_probe.run для launchctl getenv: возвращает out по ключу; timeout_keys → timeout=True."""
    def fake_run(cmd, timeout):
        key = cmd[-1]
        if key in timeout_keys:
            return {"rc": None, "out": "", "err": "", "timeout": True}
        return {"rc": 0, "out": vals.get(key, ""), "err": "", "timeout": False}
    return fake_run


def test_read_proxy_sources_reads_all_three_launchctl_keys(monkeypatch):
    """HTTPS_PROXY пуст, HTTP_PROXY=socks5h → desktop_keys содержит SOCKS5 (не теряется).

    ДЫРА на upstream: _read_proxy_sources читал только HTTPS_PROXY → терял SOCKS5 в HTTP_PROXY.
    """
    monkeypatch.setattr(health.sys_probe, "run",
                        _lc_run_per_key({"HTTPS_PROXY": "", "HTTP_PROXY": "socks5h://127.0.0.1:10808", "ALL_PROXY": ""}))
    src = health._read_proxy_sources()
    assert "HTTP_PROXY" in src["desktop_keys"]
    assert "socks" in src["desktop_keys"]["HTTP_PROXY"].lower(), f"SOCKS5 в HTTP_PROXY потерян: {src}"


def test_read_proxy_sources_collects_all_set_keys(monkeypatch):
    """Все три ключа заданы → все три в desktop_keys (показываем «как есть»)."""
    vals = {"HTTPS_PROXY": "http://127.0.0.1:8118",
            "HTTP_PROXY": "http://127.0.0.1:8118",
            "ALL_PROXY": "http://127.0.0.1:8118"}
    monkeypatch.setattr(health.sys_probe, "run", _lc_run_per_key(vals))
    src = health._read_proxy_sources()
    assert set(src["desktop_keys"]) == {"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"}


def test_read_proxy_sources_ignores_launchctl_timeout(monkeypatch):
    """sys_probe.run timeout для всех трёх → desktop_keys пуст (fail-soft).

    Timeout не должен давать ложный SOCKS5 или падение.
    """
    monkeypatch.setattr(health.sys_probe, "run",
                        _lc_run_per_key({}, timeout_keys=("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY")))
    src = health._read_proxy_sources()
    assert src["desktop_keys"] == {}


# ============================ #132: launchd lifecycle forensics ============================


def test_launchd_job_snapshot_parses_keepalive_state(monkeypatch, tmp_path):
    """Snapshot distinguishes a loaded KeepAlive job from an absent/booted-out job."""
    plist = tmp_path / "homebrew.mxcl.privoxy.plist"
    plist.write_text("<plist/>", encoding="utf-8")
    launchctl_output = """gui/501/homebrew.mxcl.privoxy = {
\tstate = running
\truns = 7
\tpid = 81045
\tlast exit code = 0
\tlast terminating signal = Terminated: 15
}
"""
    monkeypatch.setattr(
        health.sys_probe,
        "run",
        lambda cmd, timeout: {
            "rc": 0,
            "out": launchctl_output,
            "err": "",
            "timeout": False,
        },
    )

    snapshot = health._launchd_job_snapshot("homebrew.mxcl.privoxy", plist_path=plist)

    assert snapshot["loaded"] is True
    assert snapshot["state"] == "running"
    assert snapshot["runs"] == 7
    assert snapshot["pid"] == 81045
    assert snapshot["last_exit_code"] == "0"
    assert snapshot["last_terminating_signal"] == "Terminated: 15"
    assert snapshot["plist"]["exists"] is True
    assert snapshot["plist"]["inode"] == plist.stat().st_ino


def test_launchd_job_snapshot_marks_booted_out_job(monkeypatch, tmp_path):
    """launchctl print failure is recorded as loaded=false, not guessed to be a crash."""
    plist = tmp_path / "missing.plist"
    monkeypatch.setattr(
        health.sys_probe,
        "run",
        lambda cmd, timeout: {
            "rc": 113,
            "out": "",
            "err": "Could not find service",
            "timeout": False,
        },
    )

    snapshot = health._launchd_job_snapshot("homebrew.mxcl.privoxy", plist_path=plist)

    assert snapshot["loaded"] is False
    assert snapshot["state"] is None
    assert snapshot["pid"] is None
    assert snapshot["plist"]["exists"] is False
    assert "Could not find service" in snapshot["error"]


def test_record_watchdog_lifecycle_logs_only_changes(monkeypatch, tmp_path):
    """First sample seeds state; PID/runs/plist change produces one structured forensic event."""
    assert _REAL_RECORD_WATCHDOG_LIFECYCLE is not None
    state_file = tmp_path / "launchd-state.json"
    log_file = tmp_path / "launchd-events.jsonl"
    monkeypatch.setattr(health, "WATCHDOG_LIFECYCLE_STATE", state_file)
    monkeypatch.setattr(health, "WATCHDOG_LIFECYCLE_LOG", log_file)

    samples = iter([
        {
            "privoxy": {"loaded": True, "pid": 100, "runs": 1,
                        "plist": {"exists": True, "mtime_ns": 10, "inode": 20}},
            "xray": {"loaded": True, "pid": 955, "runs": 1,
                     "plist": {"exists": True, "mtime_ns": 1, "inode": 2}},
        },
        {
            "privoxy": {"loaded": True, "pid": 200, "runs": 2,
                        "plist": {"exists": True, "mtime_ns": 10, "inode": 20}},
            "xray": {"loaded": True, "pid": 955, "runs": 1,
                     "plist": {"exists": True, "mtime_ns": 1, "inode": 2}},
        },
    ])
    monkeypatch.setattr(health, "_collect_launchd_lifecycle", lambda: next(samples))

    _REAL_RECORD_WATCHDOG_LIFECYCLE()
    assert state_file.exists()
    assert not log_file.exists(), "baseline must not be reported as a lifecycle event"

    _REAL_RECORD_WATCHDOG_LIFECYCLE()
    event = __import__("json").loads(log_file.read_text(encoding="utf-8").strip())
    assert event["previous"]["privoxy"]["pid"] == 100
    assert event["current"]["privoxy"]["pid"] == 200
    assert event["current"]["privoxy"]["runs"] == 2


def test_watchdog_records_launchd_lifecycle(monkeypatch, tmp_path):
    """Every watchdog tick records lifecycle state independently of health transitions."""
    state_file = tmp_path / "watchdog.last"
    state_file.write_text("ok")
    monkeypatch.setattr(health, "WATCHDOG_STATE", state_file)
    monkeypatch.setattr(health, "check_all", lambda **kw: {"status": "ok", "checks": []})
    recorded = []
    monkeypatch.setattr(health, "_record_watchdog_lifecycle", lambda: recorded.append(True))

    health.cmd_watchdog()

    assert recorded == [True]


# ============================ #152: privoxy-log observability (doctor, info-only) ============================
# Молчаливый privoxy (config без директивы debug → logfile пуст) — observability-дыра: ни doctor,
# ни ручная диагностика не видят, что privoxy делает с запросами (флап к github через 8118).
# Doctor-чек показывает картину: logfile читается без sudo? debug включён? WARN при «debug on + пуст».


def _privoxy_tmp_layout(tmp_path, *, debug=0, logfile_bytes=b""):
    """Собирает изолированный ProtectedLayout в tmp с конфигом (debug-уровень) и logfile заданного размера.

    DEFAULT_LAYOUT — frozen dataclass, патчить атрибуты нельзя; _privoxy_log_observability_check
    принимает layout параметром (как validate_protected_config), поэтому передаём tmp-layout напрямую.
    """
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "logfile").write_bytes(logfile_bytes)
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_path = config_dir / "config"
    config_path.write_text(
        privoxy_system.protected_config_text(privoxy_system.DEFAULT_LAYOUT, debug=debug),
        encoding="utf-8",
    )
    return privoxy_system.ProtectedLayout(
        config_path=config_path,
        log_dir=log_dir,
    )


def test_privoxy_log_check_debug_off_info_hint(tmp_path):
    """config без debug (молчаливый, дефолт #141) → status=ok + подсказка включить SROUTER_PRIVOXY_DEBUG=2."""
    layout = _privoxy_tmp_layout(tmp_path, debug=0, logfile_bytes=b"")

    res = health._privoxy_log_observability_check(layout=layout)

    assert res["status"] == "ok"
    assert "SROUTER_PRIVOXY_DEBUG=2" in res["detail"]


def test_privoxy_log_check_debug_on_empty_logfile_warn(tmp_path):
    """debug включён, но logfile пустой → WARN: логирование есть, но privoxy не пишет (rights/logrotate/level?)."""
    layout = _privoxy_tmp_layout(tmp_path, debug=2, logfile_bytes=b"")

    res = health._privoxy_log_observability_check(layout=layout)

    assert res["status"] == "warn"
    assert "пуст" in res["detail"].lower() or "empty" in res["detail"].lower()


def test_privoxy_log_check_debug_on_nonempty_logfile_ok(tmp_path):
    """debug включён + logfile с байтами → ok (логирование реально работает)."""
    layout = _privoxy_tmp_layout(
        tmp_path, debug=2, logfile_bytes=b"2026-07-23 connect github.com:443\n",
    )

    res = health._privoxy_log_observability_check(layout=layout)

    assert res["status"] == "ok"
    assert "debug 2" in res["detail"]


def test_privoxy_log_check_degrades_when_config_unreadable(tmp_path):
    """config/logfile не существуют → не падает, отдаёт ok/info (fail-soft, как др. чеки health)."""
    layout = privoxy_system.ProtectedLayout(
        config_path=tmp_path / "missing-config",
        log_dir=tmp_path / "missing-logs",
    )

    res = health._privoxy_log_observability_check(layout=layout)

    assert res["status"] in ("ok", "info", "unknown")
    assert isinstance(res["detail"], str) and res["detail"]


def test_privoxy_log_check_debug_1_url_level_flagged_as_sensitive(tmp_path):
    """debug 1 = URLs (чувствительно) → ok, но detail упоминает чувствительность (privacy-сигнал)."""
    layout = _privoxy_tmp_layout(tmp_path, debug=1, logfile_bytes=b"line\n")

    res = health._privoxy_log_observability_check(layout=layout)

    assert res["status"] == "ok"
    assert "debug 1" in res["detail"]


def test_check_all_has_privoxy_log_check_info_only(monkeypatch):
    """privoxy-log observability чек присутствует в doctor (active_claude), info-only, не роняет вердикт."""
    _all_up_monkey(monkeypatch, probe_status="ok")
    # doctor-only чеки, запускающие реальные subprocess'ы — мокаем (предмет теста — wiring, не они).
    monkeypatch.setattr(health, "_privoxy_log_observability_check",
                        lambda **kw: {"status": "warn", "detail": "mock: debug on, logfile пуст"})
    monkeypatch.setattr(health, "_installed_versions_check",
                        lambda: {"status": "ok", "detail": "mock", "codex": [], "claude_code": []})
    monkeypatch.setattr(health, "_claude_transport_probe",
                        lambda: {"status": "unknown", "detail": "mock"})

    result = health.check_all(active_claude=True)

    log_check = [c for c in result["checks"] if "privoxy-log" in c["name"].lower()
                 or "observability" in c["name"].lower()]
    assert log_check, "privoxy-log observability чек должен быть в doctor checks"
    assert log_check[0].get("info") is True, "info-only: не driver, не роняет вердикт"
    # info-check не входит в drivers → не влияет на агрегированный status.
    drivers = [c for c in result["checks"] if not c.get("info")]
    assert log_check[0] not in drivers

    result = health.check_all(active_claude=True)

    log_check = [c for c in result["checks"] if "privoxy-log" in c["name"].lower()
                 or "observability" in c["name"].lower()]
    assert log_check, "privoxy-log observability чек должен быть в doctor checks"
    assert log_check[0].get("info") is True, "info-only: не driver, не роняет вердикт"
    # info-check не входит в drivers → не влияет на агрегированный status.
    drivers = [c for c in result["checks"] if not c.get("info")]
    assert log_check[0] not in drivers



# ============================ #143: runtime env живого CC (ps eww override detection) ============================
# Сценарий #143: CC запущен с ANTHROPIC_BASE_URL / ANTHROPIC_DEFAULT_*_MODEL override; пользователь
# сбросил настройки на стандартные, а ЖИВОЙ процесс сохранил env. Doctor читает файлы → видит
# «стандартный», а CC реально ходит на подменённый сервер. Файлы слепы — нужно env ЖИВОГО процесса.
# ps eww -p <pid> читает env процесса того же UID (эмпирически подтверждено). Fail-soft: чужой
# UID/sandbox → пустой вывод. Константы comm-формата — см. CLI_COMM/VERSION_RUNNER_COMM выше.

def _runtime_fake_run(pid_comm_pairs, pid_envs):
    """fake_run для #143: `ps -axo pid=,comm=` → PID-лист; `ps eww -p <pids>` → per-PID env.

    Различает команды по форме: ps с "-axo" даёт листинг процессов; ps с "eww" даёт env.
    pid_envs: {pid: "ANTHROPIC_*=value ANTHROPIC_*=value ..."} — env КАЖДОГО PID (формат реального
    ps eww: каждая строка процесса начинается с PID `^[0-9]+ `). Per-PID, не merged.
    """
    listing = "\n".join(f"{pid} {comm}" for pid, comm in pid_comm_pairs) + "\n"
    # ps eww отдаёт каждую строку процесса с PID в начале; заголовок отбрасывается парсером.
    eww = "\n".join(f"{pid} /path/claude {env}" for pid, env in pid_envs.items()) + "\n"

    def fake_run(cmd, timeout):
        if cmd and cmd[0] == "/bin/ps":
            if "eww" in cmd:
                return {"rc": 0, "out": eww, "err": "", "timeout": False}
            # ps -axo pid=,comm=
            return {"rc": 0, "out": listing, "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    return fake_run


def test_runtime_config_not_readable_when_cc_not_running(monkeypatch):
    """CC не запущен (ps -axo пуст) → readable=False, pids=[]. Fail-soft, не падает."""
    monkeypatch.setattr(health.sys_probe, "run", _runtime_fake_run([], {}))
    res = health._read_runtime_endpoint_config()
    assert res["readable"] is False
    assert res["pids"] == []
    assert res["per_pid"] == {}


def test_runtime_config_not_readable_when_ps_eww_empty(monkeypatch):
    """ps eww пуст (чужой UID/sandbox) → readable=False, но PID сохранены для forensics."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _runtime_fake_run([("12345", CLI_COMM)], {"12345": ""}))
    res = health._read_runtime_endpoint_config()
    assert res["readable"] is False
    assert res["pids"] == ["12345"], "PID сохранены для forensics даже когда env не читается"


def test_runtime_config_extracts_base_url_and_models(monkeypatch):
    """Эмпирические данные PID 77749: BASE_URL=z.ai + glm-модели. Regex их извлекает per-PID."""
    env = ("ANTHROPIC_BASE_URL=https://api.z.ai/api/anthropic "
           "ANTHROPIC_DEFAULT_HAIKU_MODEL=glm-4.7 "
           "ANTHROPIC_DEFAULT_SONNET_MODEL=glm-5-turbo "
           "ANTHROPIC_API_KEY=sk-secret")
    monkeypatch.setattr(health.sys_probe, "run",
                        _runtime_fake_run([("77749", VERSION_RUNNER_COMM)], {"77749": env}))
    res = health._read_runtime_endpoint_config()
    assert res["readable"] is True
    pid_env = res["per_pid"]["77749"]
    assert pid_env["ANTHROPIC_BASE_URL"] == "https://api.z.ai/api/anthropic"
    assert pid_env["ANTHROPIC_DEFAULT_HAIKU_MODEL"] == "glm-4.7"
    assert pid_env["ANTHROPIC_DEFAULT_SONNET_MODEL"] == "glm-5-turbo"


def test_runtime_check_unknown_when_cc_not_running(monkeypatch):
    """CC не запущен → status=unknown (info-only, как _claude_proxy_probe idle)."""
    monkeypatch.setattr(health, "_read_runtime_endpoint_config",
                        lambda: {"per_pid": {}, "pids": [], "readable": False})
    res = health._runtime_model_override_check()
    assert res["status"] == "unknown"
    assert "не запущен" in res["detail"]


def test_runtime_check_unknown_when_env_unreadable(monkeypatch):
    """env чужого UID/sandbox не читается → unknown, но PID в detail для forensics."""
    monkeypatch.setattr(health, "_read_runtime_endpoint_config",
                        lambda: {"per_pid": {}, "pids": ["123"], "readable": False})
    res = health._runtime_model_override_check()
    assert res["status"] == "unknown"
    assert "123" in res["detail"]


def test_runtime_check_info_when_base_url_override(monkeypatch):
    """runtime base_url=z.ai override → info (файлы тоже override)."""
    monkeypatch.setattr(health, "_read_runtime_endpoint_config",
                        lambda: {"per_pid": {"77749": {"ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic"}},
                                 "pids": ["77749"], "readable": True})
    monkeypatch.setattr(health, "_read_endpoint_config",
                        lambda: {"base_url": "https://api.z.ai/api/anthropic",
                                 "no_proxy": "", "source": "settings.json"})
    res = health._runtime_model_override_check()
    assert res["status"] == "info"
    assert "runtime endpoint" in res["detail"]
    assert "api.z.ai" in res["detail"]


def test_runtime_check_info_when_model_substitution(monkeypatch):
    """ANTHROPIC_DEFAULT_*_MODEL заданы → model substitution, даже если base_url чистый (стандартный)."""
    monkeypatch.setattr(health, "_read_runtime_endpoint_config",
                        lambda: {"per_pid": {"77749": {"ANTHROPIC_DEFAULT_SONNET_MODEL": "glm-5-turbo"}},
                                 "pids": ["77749"], "readable": True})
    monkeypatch.setattr(health, "_read_endpoint_config",
                        lambda: {"base_url": "", "no_proxy": "", "source": "default"})
    res = health._runtime_model_override_check()
    assert res["status"] == "info"
    assert "model substitution" in res["detail"]
    assert "glm-5-turbo" in res["detail"]


def test_runtime_check_info_stale_process_signal(monkeypatch):
    """КЛЮЧЕВОЙ кейс #143: runtime override есть, а файлы doctor ЧИСТЫ → stale process.

    Работающий CC держит override после того как пользователь сбросил настройки. Doctor по файлам
    слеп — именно этот сигнал ловит дыру. Ровно сценарий issue #143.
    """
    monkeypatch.setattr(health, "_read_runtime_endpoint_config",
                        lambda: {"per_pid": {"77749": {"ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic"}},
                                 "pids": ["77749"], "readable": True})
    monkeypatch.setattr(health, "_read_endpoint_config",
                        lambda: {"base_url": "", "no_proxy": "", "source": "default"})
    res = health._runtime_model_override_check()
    assert res["status"] == "info"
    assert "stale" in res["detail"].lower()


def test_runtime_check_ok_when_all_standard(monkeypatch):
    """runtime==стандартный, нет substitution, нет расхождения → ok, silent."""
    monkeypatch.setattr(health, "_read_runtime_endpoint_config",
                        lambda: {"per_pid": {"77749": {"ANTHROPIC_BASE_URL": "https://api.anthropic.com"}},
                                 "pids": ["77749"], "readable": True})
    monkeypatch.setattr(health, "_read_endpoint_config",
                        lambda: {"base_url": "", "no_proxy": "", "source": "default"})
    res = health._runtime_model_override_check()
    assert res["status"] == "ok"
    assert "стандарт" in res["detail"].lower()


def test_runtime_check_detail_never_leaks_api_key(monkeypatch):
    """Security mutation-гвард: detail НЕ выводит ANTHROPIC_API_KEY/AUTH_TOKEN (только base_url + DEFAULT_*).

    per_pid[p] содержит ВСЕ ANTHROPIC_* (включая секреты — doctor доверяет тому же UID). Но detail
    чека обязан фильтровать — иначе секрет в логе doctor. Ловит мутацию «вывести env целиком».
    """
    monkeypatch.setattr(health, "_read_runtime_endpoint_config",
                        lambda: {"per_pid": {"77749": {
                            "ANTHROPIC_API_KEY": "sk-secret-value",
                            "ANTHROPIC_AUTH_TOKEN": "tok-secret",
                            "ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic",
                            "ANTHROPIC_DEFAULT_HAIKU_MODEL": "glm-4.7"}},
                            "pids": ["77749"], "readable": True})
    monkeypatch.setattr(health, "_read_endpoint_config",
                        lambda: {"base_url": "https://api.z.ai/api/anthropic",
                                 "no_proxy": "", "source": "settings.json"})
    res = health._runtime_model_override_check()
    assert "sk-secret-value" not in res["detail"], "API key НЕ должен попадать в detail"
    assert "tok-secret" not in res["detail"], "AUTH token НЕ должен попадать в detail"
    assert "ANTHROPIC_API_KEY" not in res["detail"]
    assert "ANTHROPIC_AUTH_TOKEN" not in res["detail"]


def test_runtime_check_ps_eww_batched_per_pid_set(monkeypatch):
    """Mutation-гвард: ps eww вызывается ОДИН раз с батчем `-p pid1,pid2` (как lsof), не N раз в цикле."""
    seen_eww = []

    def fake_run(cmd, timeout):
        if cmd and cmd[0] == "/bin/ps":
            if "eww" in cmd:
                seen_eww.append(cmd)
                env = ("111 /path/claude ANTHROPIC_BASE_URL=https://api.anthropic.com\n"
                       "222 /path/claude ANTHROPIC_BASE_URL=https://api.anthropic.com")
                return {"rc": 0, "out": env, "err": "", "timeout": False}
            return {"rc": 0, "out": f"111 {CLI_COMM}\n222 {VERSION_RUNNER_COMM}\n",
                    "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    res = health._read_runtime_endpoint_config()
    assert res["readable"] is True
    assert len(seen_eww) == 1, f"ps eww должен зваться ОДИН раз (батч), got {len(seen_eww)}"
    # -p pid1,pid2 — запятая, как lsof-батч в _claude_proxy_probe.
    assert seen_eww[0] == ["/bin/ps", "eww", "-p", "111,222"], f"батч PID через запятую, got {seen_eww[0]}"


def test_runtime_env_check_present_in_doctor_path(monkeypatch):
    """check_all(active_claude=True) включает runtime-env чек; info-only (не driver)."""
    _all_up_monkey(monkeypatch, probe_status="ok")
    monkeypatch.setattr(health, "_privoxy_log_observability_check",
                        lambda **kw: {"status": "warn", "detail": "mock"})
    monkeypatch.setattr(health, "_installed_versions_check",
                        lambda: {"status": "ok", "detail": "mock", "codex": [], "claude_code": []})
    monkeypatch.setattr(health, "_claude_transport_probe",
                        lambda: {"status": "unknown", "detail": "mock"})
    monkeypatch.setattr(health, "_runtime_model_override_check",
                        lambda: {"status": "info", "detail": "mock: runtime override"})

    result = health.check_all(active_claude=True)
    names = [c["name"] for c in result["checks"]]
    rt = [c for c in result["checks"] if "runtime env" in c["name"].lower()
          and "anthropic" in c["name"].lower()]
    assert rt, f"runtime-env чек должен быть в doctor checks, got {names}"
    assert rt[0].get("info") is True, "info-only: не driver, не роняет вердикт"
    drivers = [c for c in result["checks"] if not c.get("info")]
    assert rt[0] not in drivers


def test_runtime_env_check_skipped_in_lightweight_path(monkeypatch):
    """ДЫРА (канон #145 cycle-r1): check_all(active_claude=False) (/health/watchdog) НЕ зовёт
    runtime-env чек — ps eww по живым PID = overhead/поверхность, не для лёгкого healthcheck."""
    _all_up_monkey(monkeypatch, probe_status="ok")
    calls = []
    monkeypatch.setattr(health, "_runtime_model_override_check",
                        lambda: calls.append(1) or {"status": "unknown", "detail": "не должно зваться"})
    result = health.check_all(active_claude=False)
    assert calls == [], "check_all(active_claude=False) НЕ должен звать runtime-env чек (лёгкий путь)"
    names = [c["name"] for c in result["checks"]]
    assert not any("runtime env" in n.lower() for n in names), \
        f"runtime-env чек не должен появляться в лёгком пути, got {names}"


def test_runtime_config_not_readable_when_no_anthropic_vars(monkeypatch):
    """cycle-review B2: ps eww дал вывод, но НИ ОДНОЙ ANTHROPIC_* не извлечено (мусор/чужой контекст)
    → readable=False. Иначе чек дал бы ложный ok «стандартный endpoint» без evidence (verify-dont-guess)."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _runtime_fake_run([("12345", CLI_COMM)],
                                          {"12345": "PATH=/usr/bin HOME=/tmp SHELL=/bin/zsh"}))
    res = health._read_runtime_endpoint_config()
    assert res["readable"] is False, "нет ANTHROPIC_* vars = нет evidence → не readable"
    assert res["pids"] == ["12345"], "PID сохранены для forensics"
    assert res["per_pid"] == {}


def test_runtime_check_unknown_when_no_anthropic_vars(monkeypatch):
    """cycle-review B2: env без ANTHROPIC_* → status=unknown (НЕ ложный ok)."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _runtime_fake_run([("12345", CLI_COMM)],
                                          {"12345": "PATH=/usr/bin HOME=/tmp"}))
    res = health._runtime_model_override_check()
    assert res["status"] == "unknown", "нет evidence → unknown, не ok"
    assert "12345" in res["detail"]


def test_runtime_env_check_info_only_even_when_ok(monkeypatch):
    """cycle-review S3: чек info-only БЕЗУСЛОВНО (как соседи) — даже при status=ok НЕ driver.

    Диагностика подмены модели — картина, не сбой стека; ok не должен стать driver
    (несогласованность с _installed_versions_check/_privoxy_log_observability_check).
    """
    _all_up_monkey(monkeypatch, probe_status="ok")
    monkeypatch.setattr(health, "_privoxy_log_observability_check",
                        lambda **kw: {"status": "warn", "detail": "mock"})
    monkeypatch.setattr(health, "_installed_versions_check",
                        lambda: {"status": "ok", "detail": "mock", "codex": [], "claude_code": []})
    monkeypatch.setattr(health, "_claude_transport_probe",
                        lambda: {"status": "unknown", "detail": "mock"})
    monkeypatch.setattr(health, "_runtime_model_override_check",
                        lambda: {"status": "ok", "detail": "стандартный"})

    result = health.check_all(active_claude=True)
    rt = [c for c in result["checks"] if "runtime env" in c["name"].lower()
          and "anthropic" in c["name"].lower()]
    assert rt, "runtime-env чек должен быть в doctor checks"
    assert rt[0].get("info") is True, "info-only БЕЗУСЛОВНО — даже ok не driver"
    assert rt[0]["ok"] is True, "ok-status → ok:True"
    drivers = [c for c in result["checks"] if not c.get("info")]
    assert rt[0] not in drivers, "info-only чек НЕ входит в drivers даже при ok"


def test_runtime_check_detects_override_when_mixed_pids(monkeypatch):
    """cycle-review Codex critical: ОДИН override-PID среди standard-PID НЕ должен маскироваться.

    ps eww батчит все PID в один вывод. dict(findall()) перезаписывает дубликаты ключей последним
    значением → один standard-процесс мог скрыть overridden (ложный ok). Это false-negative именно
    в сценарии #143 (несколько живых CC-сессий — штатно). Агрегация per-PID: ЛЮБОЙ override =
    unsafe runtime. Тест в ОБА порядка PID (override первым и последним) — ловит обе маскировки.
    """
    OVERRIDE_ENV = ("ANTHROPIC_BASE_URL=https://evil.example "
                    "ANTHROPIC_API_KEY=k-override "
                    "ANTHROPIC_DEFAULT_SONNET_MODEL=glm-evil")
    STANDARD_ENV = ("ANTHROPIC_BASE_URL=https://api.anthropic.com "
                    "ANTHROPIC_API_KEY=k-standard")
    OVERRIDE_PID, STANDARD_PID = "111", "222"
    OVERRIDE_COMM, STANDARD_COMM = CLI_COMM, VERSION_RUNNER_COMM

    def run_once(pid_order, env_order):
        # pid_order — порядок PID в ps -axo листинге; env_order — порядок в ps eww выводе.
        listing = "\n".join(f"{p} {c}" for p, c in pid_order) + "\n"
        eww = "\n".join(f"{p} /path/claude {env}" for p, env in env_order) + "\n"

        def fake_run(cmd, timeout):
            if cmd and cmd[0] == "/bin/ps":
                if "eww" in cmd:
                    return {"rc": 0, "out": eww, "err": "", "timeout": False}
                return {"rc": 0, "out": listing, "err": "", "timeout": False}
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        return fake_run

    monkeypatch.setattr(health, "_read_endpoint_config",
                        lambda: {"base_url": "", "no_proxy": "", "source": "default"})

    for label, fake in [
        ("override-first listing, override-first env",
         run_once([(OVERRIDE_PID, OVERRIDE_COMM), (STANDARD_PID, STANDARD_COMM)],
                  [(OVERRIDE_PID, OVERRIDE_ENV), (STANDARD_PID, STANDARD_ENV)])),
        ("override-last listing, override-last env",
         run_once([(STANDARD_PID, STANDARD_COMM), (OVERRIDE_PID, OVERRIDE_COMM)],
                  [(STANDARD_PID, STANDARD_ENV), (OVERRIDE_PID, OVERRIDE_ENV)])),
    ]:
        monkeypatch.setattr(health.sys_probe, "run", fake)
        res = health._runtime_model_override_check()
        # ЛЮБОЙ override-PID (evil.example) → info, НЕ ok. standard-процесс его не маскирует.
        assert res["status"] == "info", f"[{label}] override-PID не должен маскироваться, got {res['status']}"
        assert "evil.example" in res["detail"], f"[{label}] detail должен показать overridden endpoint"
