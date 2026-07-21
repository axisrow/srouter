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
import health


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


def test_notify_logs_to_file(monkeypatch, tmp_path):
    """_notify пишет audit trail в лог-файл (timestamp + msg)."""
    log_file = tmp_path / "srouter-watchdog.notify.log"
    monkeypatch.setattr(health, "WATCHDOG_NOTIFY_LOG", log_file)
    monkeypatch.setattr(health.sys_probe, "run", lambda cmd, timeout: {"rc": 0, "out": "", "err": "", "timeout": False})
    health._notify("test message", "Basso")
    content = log_file.read_text(encoding="utf-8")
    assert "test message" in content
    assert "Basso" in content
