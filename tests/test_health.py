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
import json

import pytest as _pytest
import pytest  # noqa: ICN003 — pytest.fail/raises в тестах ниже (#194)

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
    # issue #189: _codex_app_proxy_check и _desktop_proxy_check тоже дёргают ps/launchctl — мокаем
    # unknown (info-only), иначе реальный ps найдёт живой ChatGPT.app/CC на dev-машине и драйвит
    # вердикт (как _claude_proxy_probe/_codex_proxy_probe выше).
    monkeypatch.setattr(health, "_codex_app_proxy_check",
                        lambda: {"status": "unknown", "source": "n/a", "detail": "App не запущен (mock)"})
    monkeypatch.setattr(health, "_desktop_proxy_check",
                        lambda: {"status": "unknown", "detail": "launchctl (mock)"})
    # #194: _upstream_vps_reachable дёргает local_state.active_node + sys_probe.port_open — мокаем
    # «нет узла» (info-only), иначе реальный srouter.local.json на dev-машине (+ живой/мёртвый VPS)
    # драйвит вердикт недетерминированно. В этих тестах VPS-чек НЕ предмет проверки → info-заглушка.
    import local_state
    monkeypatch.setattr(local_state, "active_node", lambda path=None: {})
    # #204: _local_proxy_up дёргает launchctl print (через _service_running) — мокаем running=True,
    # иначе реальный launchd на dev-машине (protected/brew-mode, живой/мёртвый privoxy/xray)
    # драйвит вердикт недетерминированно. _port_up уже мокаем True выше → ok по контракту.
    monkeypatch.setattr(health, "_service_running", lambda label, domain=None: "running")


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
    # issue #189: _codex_app_proxy_check тоже дёргает ps — мокаем (иначе живой ChatGPT.app → ok → не down).
    monkeypatch.setattr(health, "_codex_app_proxy_check",
                        lambda: {"status": "down", "source": "gui-env", "detail": "down"})

    result = health.check_all()
    assert result["status"] == "down"


# ============================ #194: upstream VPS прямой TCP-probe (минуя прокси) ============================
# Корень (_tunnel_up бьёт через прокси к API-таргетам): connection-failed без различения «VPS мёртв»
# vs «локальный прокси упал». _upstream_vps_reachable() = socket.create_connection до
# active_node().endpoint_host:port БЕЗ прокси (sys_probe.port_open) — точно говорит «VPS мёртв».
#
# Контракт _upstream_vps_reachable() -> {status, detail}:
#   ok   — TCP-connect успешен (VPS жив);
#   down — TCP timeout/refused (VPS мёртв);
#   warn — placeholder TEST-NET 203.0.113.x (нельзя реально зондировать);
#   info — нет активного узла / нет endpoint_host.
# Интеграция в check_all: driver-усилитель ТОЛЬКО когда туннель fail + VPS down (гарантирует DOWN,
# не DEGRADED); VPS ok при туннель-fail → info «локальный прокси сломан (VPS жив)»; туннель ok → info.
def _mock_active_node(monkeypatch, node):
    """Подменить local_state.active_node() заданным узлом ({} = нет узла)."""
    import local_state
    monkeypatch.setattr(local_state, "active_node", lambda path=None: node)


def _mock_vps_tcp(monkeypatch, reachable):
    """Подменить прямой TCP-probe до VPS endpoint (минуя прокси). reachable=True/False."""
    monkeypatch.setattr(health.sys_probe, "port_open", lambda host, port, timeout=1.0: reachable)


def test_vps_unreachable_when_tunnel_fail_is_driver_down(monkeypatch):
    """ДЫРА #194: порты живы + туннель fail + VPS TCP-unreachable → DOWN (upstream VPS мёртв).

    Раньше connection-failed без различения. Теперь прямой TCP-probe доказывает «VPS мёртв»
    → driver-чек роняет вердикт в down (не degraded). VPS-смерть = critical-infra DOWN (#194).
    """
    _all_up_monkey(monkeypatch)  # порты + claude/codex/app/desktop — info/ok (не роняют)
    monkeypatch.setattr(health, "_tunnel_up", lambda: (False, "connection-failed"))
    _mock_active_node(monkeypatch, {"name": "vps-1", "endpoint_host": "198.51.100.7", "port": 443})
    _mock_vps_tcp(monkeypatch, reachable=False)
    result = health.check_all()
    assert result["status"] == "down", "VPS TCP-unreachable + туннель fail → DOWN (VPS мёртв)"
    vps = [c for c in result["checks"] if "vps" in c["name"].lower() and "upstream" in c["name"].lower()][0]
    assert vps["ok"] is False, "VPS-unreachable — driver (ok=False)"
    assert not vps.get("info"), "VPS-unreachable при туннель-fail — НЕ info (driver)"
    assert "VPS" in vps["detail"] or "endpoint" in vps["detail"], "detail объясняет: VPS мёртв"


def test_vps_reachable_when_tunnel_fail_distinguishes_local_proxy(monkeypatch):
    """ДЫРА #194: порты живы + туннель fail + VPS reachable → «локальный прокси сломан (VPS жив)».

    Прямой TCP-probe доказывает VPS жив → проблема НЕ в VPS. doctor различает: туннель-fail
    из-за локального прокси/туннеля, а не мёртвого VPS. VPS-чек = info (картина, не driver
    поверх туннель-fail — туннель уже driver). Канон: verify-don't-guess (прямая причина).
    """
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_tunnel_up", lambda: (False, "connection-failed"))
    _mock_active_node(monkeypatch, {"name": "vps-1", "endpoint_host": "198.51.100.7", "port": 443})
    _mock_vps_tcp(monkeypatch, reachable=True)
    result = health.check_all()
    # туннель-fail уже driver → status не ok. VPS жив → это не «всё мёртво».
    assert result["status"] in ("degraded", "down"), "туннель-fail → не ok"
    vps = [c for c in result["checks"] if "vps" in c["name"].lower() and "upstream" in c["name"].lower()][0]
    assert vps.get("info") is True, "VPS-reachable при туннель-fail — info (различение, не driver)"
    assert "жив" in vps["detail"].lower() or "reachable" in vps["detail"].lower(), \
        "detail говорит: VPS жив (проблема в локальном прокси/туннеле)"


def test_vps_reachable_when_tunnel_ok_is_info(monkeypatch):
    """Туннель ok + VPS reachable → ok; VPS-чек info-only (VPS-доступность не релевантна когда туннель жив)."""
    _all_up_monkey(monkeypatch, probe_status="ok")
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200"))
    _mock_active_node(monkeypatch, {"name": "vps-1", "endpoint_host": "198.51.100.7", "port": 443})
    _mock_vps_tcp(monkeypatch, reachable=True)
    result = health.check_all()
    assert result["status"] == "ok", "всё живо → ok"
    vps = [c for c in result["checks"] if "vps" in c["name"].lower() and "upstream" in c["name"].lower()][0]
    assert vps.get("info") is True, "туннель ok → VPS-чек info-only (не driver)"


def test_vps_no_active_node_is_info_only(monkeypatch):
    """Нет активного узла (active_node() = {}) → VPS-чек info-only, не роняет вердикт."""
    _all_up_monkey(monkeypatch, probe_status="ok")
    _mock_active_node(monkeypatch, {})  # нет узла
    _mock_vps_tcp(monkeypatch, reachable=True)  # не должно даже дёргаться
    result = health.check_all()
    assert result["status"] == "ok", "нет узла → не роняет вердикт"
    vps = [c for c in result["checks"] if "vps" in c["name"].lower() and "upstream" in c["name"].lower()][0]
    assert vps.get("info") is True, "нет узла → info-only"


def test_vps_placeholder_testnet_203_0_113_is_warn(monkeypatch):
    """Placeholder TEST-NET 203.0.113.x (RFC 5737) → warn: нельзя реально зондировать test-IP.

    Тестовая конфигурация / пример конфига содержит незаменённый placeholder — прямой TCP-probe
    до 203.0.113.x ничего не доказывает (адреса не маршрутизируются). Doctor предупреждает о
    placeholder, не врёт «VPS мёртв» и не падает. status=warn, чек info (placeholder — не сбой стека).
    """
    _all_up_monkey(monkeypatch, probe_status="ok")
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200"))
    _mock_active_node(monkeypatch, {"name": "example", "endpoint_host": "203.0.113.7", "port": 443})
    # port_open не должно вызываться для placeholder (детект до пробы).
    monkeypatch.setattr(health.sys_probe, "port_open",
                        lambda host, port, timeout=1.0: pytest.fail("placeholder не должен зондироваться"))
    vps_status = health._upstream_vps_reachable()
    assert vps_status["status"] == "warn", "placeholder 203.0.113.x → warn (нельзя зондировать)"
    result = health.check_all()
    assert result["status"] == "ok", "placeholder — warn, не роняет вердикт (туннель жив)"
    vps_check = [c for c in result["checks"] if "vps" in c["name"].lower() and "upstream" in c["name"].lower()][0]
    assert vps_check.get("info") is True, "placeholder — info-only (не driver)"


def test_vps_unreachable_does_not_mask_down_into_degraded(monkeypatch):
    """REGRESSION-гвард #194: VPS-unreachable при «всё мертво» НЕ превращает down в degraded.

    Защита от будущей регрессии: если кто-то сделает VPS-чек driver-ok=True (или info) при
    unreachable — проверка упадёт. status обязан остаться down, VPS-чек — driver ok=False.
    """
    monkeypatch.setattr(health, "_port_up", lambda port: False)
    monkeypatch.setattr(health, "_tunnel_up", lambda: (False, "connection-failed"))
    monkeypatch.setattr(health, "_claude_proxy_probe",
                        lambda: {"status": "down", "source": "runtime", "detail": "runtime"})
    monkeypatch.setattr(health, "_desktop_proxy_check", lambda: {"status": "down", "detail": "down"})
    monkeypatch.setattr(health, "_codex_proxy_probe",
                        lambda: {"status": "down", "source": "runtime", "detail": "runtime"})
    monkeypatch.setattr(health, "_codex_app_proxy_check",
                        lambda: {"status": "down", "source": "gui-env", "detail": "down"})
    _mock_active_node(monkeypatch, {"name": "vps-1", "endpoint_host": "198.51.100.7", "port": 443})
    _mock_vps_tcp(monkeypatch, reachable=False)
    result = health.check_all()
    assert result["status"] == "down", "всё мёртво + VPS unreachable → DOWN, не DEGRADED"
    vps = [c for c in result["checks"] if "vps" in c["name"].lower() and "upstream" in c["name"].lower()][0]
    assert vps["ok"] is False and not vps.get("info"), "VPS-unreachable — driver (не маскирует down)"


# ============================ #203: активный сетевой интерфейс/маршрут (нет сети vs VPS мёртв) ============================
# Корень: doctor не различал «нет сети вообще» (Wi-Fi/eth выкл, нет default route) от «VPS мёртв».
# _upstream_vps_reachable (#196) делает TCP-probe до VPS → при отсутствии сети TCP тоже timeout →
# ложно «VPS мёртв». _network_interface_up() проверяет ПЕРВЫМ (каскад ситуации #1 эпика #201):
# route -n get default → interface:, ИЛИ ifconfig → iface с inet (не loopback). Нет сети → driver
# «нет активного сетевого интерфейса/маршрута — подключи интернет», НЕ «VPS мёртв».
#
# Контракт _network_interface_up() -> {up: bool, detail}:
#   up=True   — есть default route (interface: в `route -n get default`) ИЛИ активный iface с inet;
#   up=False  — нет default route И нет iface с inet (не loopback) → нет сети.
# Канон: verify-dont-guess (прямая причина — маршрут/интерфейс, не догадка по TCP-timeout VPS),
# sys_probe #35 (no-hidden-magic), probe-semantics-from-primary-source (man route + эмпирика).
ROUTE = "/sbin/route"
IFCONFIG = "/sbin/ifconfig"

# Реальный вывод `route -n get default` на macOS при живой сети (эмпирика): rc=0 + interface:.
_ROUTE_DEFAULT_UP = (
    "   route to: default\n"
    "destination: default\n"
    "       mask: default\n"
    "  interface: en0\n"
)
# Нет default route: macOS отдаёт rc!=0 + "not in table" (man route). out может быть пустым.
_ROUTE_DEFAULT_NONE = {"rc": 1, "out": "route: writing to routing socket: not in table\n",
                       "err": "not in table", "timeout": False}

# Реальный вывод ifconfig при живой сети: en0 active + inet 192.168.1.17; lo0 = loopback (inet 127.0.0.1).
_IFCONFIG_UP = (
    "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n"
    "\tinet 127.0.0.1 netmask 0xff000000\n"
    "en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
    "\tinet 192.168.1.17 netmask 0xffffff00 broadcast 192.168.1.255\n"
    "\tstatus: active\n"
)
# Нет сети: только loopback (все физические интерфейсы без inet/down).
_IFCONFIG_LOOPBACK_ONLY = (
    "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n"
    "\tinet 127.0.0.1 netmask 0xff000000\n"
    "en0: flags=8802<BROADCAST,SIMPLEX,MULTICAST> mtu 1500\n"
    "\tstatus: inactive\n"
)


def _mock_route_ifconfig(monkeypatch, *, route_result, ifconfig_result=None):
    """Подменить sys_probe.run для route -n get default и ifconfig (канон node_selector mock).

    route_result — dict (как sys_probe.run) ИЛИ None (route не должен вызываться).
    ifconfig_result — dict ИЛИ None (ifconfig не должен вызываться).
    """
    def fake_run(cmd, timeout):
        if cmd[:3] == [ROUTE, "-n", "get"]:
            if route_result is None:
                raise AssertionError("route -n get default не должно вызываться в этом сценарии")
            return route_result
        if cmd[:1] == [IFCONFIG]:
            if ifconfig_result is None:
                raise AssertionError("ifconfig не должно вызываться в этом сценарии")
            return ifconfig_result
        return {"rc": 0, "out": "", "err": "", "timeout": False}
    monkeypatch.setattr(health.sys_probe, "run", fake_run)


def test_network_up_when_default_route_present(monkeypatch):
    """ДЫРА #203: route -n get default отдал interface: → сеть есть (up=True), ifconfig не нужен.

    Первый эшелон детекта: default route присутствует → интерфейс/маршрут активен. ifconfig НЕ
    должен дёргаться (есть route — этого достаточно, как node_selector._route_iface_from_output).
    """
    _mock_route_ifconfig(monkeypatch,
                         route_result={"rc": 0, "out": _ROUTE_DEFAULT_UP, "err": "", "timeout": False},
                         ifconfig_result=None)  # не должен вызываться
    r = health._network_interface_up()
    assert r["up"] is True, "default route есть → сеть активна"
    assert "en0" in r["detail"], "detail объясняет: маршрут через en0"


def test_network_up_via_ifconfig_when_no_default_route_but_iface_has_inet(monkeypatch):
    """ДЫРА #203: default route отсутствует, НО ifconfig показал iface с inet → сеть есть.

    Второй эшелон: route сброшен/кэш протух, но физический интерфейс ещё держит inet → сеть
    активна. route rc!=0 → проваливаемся в ifconfig, находим en0 с inet → up=True.
    """
    _mock_route_ifconfig(monkeypatch,
                         route_result=_ROUTE_DEFAULT_NONE,
                         ifconfig_result={"rc": 0, "out": _IFCONFIG_UP, "err": "", "timeout": False})
    r = health._network_interface_up()
    assert r["up"] is True, "нет default route, но iface с inet → сеть активна (второй эшелон)"


def test_network_down_when_no_default_route_and_loopback_only(monkeypatch):
    """ДЫРА #203 (КЛЮЧЕВОЙ): нет default route + ifconfig только loopback → НЕТ СЕТИ (up=False).

    Раньше doctor шёл в _upstream_vps_reachable → TCP timeout → ложно «VPS мёртв». Теперь
    _network_interface_up первым говорит «нет активного интерфейса/маршрута» — это совсем другая
    причина (подключи Wi-Fi/eth), не «VPS мёртв».
    """
    _mock_route_ifconfig(monkeypatch,
                         route_result=_ROUTE_DEFAULT_NONE,
                         ifconfig_result={"rc": 0, "out": _IFCONFIG_LOOPBACK_ONLY, "err": "", "timeout": False})
    r = health._network_interface_up()
    assert r["up"] is False, "нет route + только loopback → НЕТ СЕТИ"
    assert "нет" in r["detail"].lower() or "интерфейс" in r["detail"].lower() or "маршрут" in r["detail"].lower(), \
        "detail объясняет: нет активного интерфейса/маршрута (НЕ «VPS мёртв»)"


def test_network_down_takes_precedence_over_vps_dead_in_check_all(monkeypatch):
    """ДЫРА #203 (КАСКАД): нет сети → driver «нет сети», doctor НЕ лжёт «VPS мёртв».

    Сценарий эпика #201 ситуация 1: Wi-Fi выкл. Все порты живы (privoxy/xray/dashboard локально),
    но туннель fail (нечего гнать — нет сети). VPS-probe (#196) тоже дал бы timeout → ложно
    «VPS мёртв». _network_interface_up ПЕРЕД VPS-probe перехватывает: нет сети → точная причина
    «подключи интернет», VPS-чек подавляется (info-only, не «VPS мёртв» поверх «нет сети»).
    """
    _all_up_monkey(monkeypatch)  # порты живы; claude/codex/app/desktop — info/ok
    monkeypatch.setattr(health, "_tunnel_up", lambda: (False, "connection-failed"))
    # route + ifconfig: нет сети
    monkeypatch.setattr(health.sys_probe, "run", lambda cmd, timeout:
                        _ROUTE_DEFAULT_NONE if cmd[:3] == [ROUTE, "-n", "get"]
                        else {"rc": 0, "out": _IFCONFIG_LOOPBACK_ONLY, "err": "", "timeout": False}
                        if cmd[:1] == [IFCONFIG]
                        else {"rc": 0, "out": "", "err": "", "timeout": False})
    # VPS-probe (#196) ДАЖЕ ЕСЛИ бы звался — unreachable; но он не должен давать driver «VPS мёртв».
    _mock_active_node(monkeypatch, {"name": "vps-1", "endpoint_host": "198.51.100.7", "port": 443})
    _mock_vps_tcp(monkeypatch, reachable=False)
    result = health.check_all()
    net = [c for c in result["checks"] if "сеть" in c["name"].lower() or "интерфейс" in c["name"].lower() or "маршрут" in c["name"].lower()][0]
    assert net["ok"] is False, "нет сети — driver (ok=False)"
    assert not net.get("info"), "нет сети — НЕ info (driver, точная причина)"
    assert "VPS" not in net["detail"], "detail НЕ «VPS мёртв» — это «нет сети» (другая причина)"
    # VPS-чек при «нет сети» — info (подавлен, не нагромождает «VPS мёртв» поверх «нет сети»).
    vps = [c for c in result["checks"] if "vps" in c["name"].lower() and "upstream" in c["name"].lower()][0]
    assert vps.get("info") is True, "нет сети → VPS-чек подавлен (info), не водитель «VPS мёртв»"


def test_network_up_proceeds_to_vps_probe_in_check_all(monkeypatch):
    """ДЫРА #203: сеть есть → VPS-чек НЕ подавляется (proceeds to VPS-probe как обычно).

    Контр-гвард к test выше: когда сеть активна, _network_interface_up не должен маскировать
    реальную VPS-смерть. VPS-unreachable при живой сети → по-прежнему driver DOWN (#196).
    """
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_tunnel_up", lambda: (False, "connection-failed"))
    monkeypatch.setattr(health.sys_probe, "run", lambda cmd, timeout:
                        {"rc": 0, "out": _ROUTE_DEFAULT_UP, "err": "", "timeout": False}
                        if cmd[:3] == [ROUTE, "-n", "get"]
                        else {"rc": 0, "out": "", "err": "", "timeout": False})
    _mock_active_node(monkeypatch, {"name": "vps-1", "endpoint_host": "198.51.100.7", "port": 443})
    _mock_vps_tcp(monkeypatch, reachable=False)
    result = health.check_all()
    net = [c for c in result["checks"] if "сеть" in c["name"].lower() or "интерфейс" in c["name"].lower() or "маршрут" in c["name"].lower()][0]
    assert net["ok"] is True, "сеть есть → net-чек ok (не роняет вердикт)"
    vps = [c for c in result["checks"] if "vps" in c["name"].lower() and "upstream" in c["name"].lower()][0]
    assert vps["ok"] is False and not vps.get("info"), "сеть есть + VPS unreachable → VPS-чек driver (не подавлен)"
    assert result["status"] == "down", "сеть есть + VPS мёртв → DOWN (#196 контракт сохранён)"


def test_network_check_is_info_only_when_up(monkeypatch):
    """net-чек при up=True — info-only (не роняет вердикт, картина для диагностики).

    Когда сеть активна, нет причины её подсвечивать как driver. ok=True + info=True → не участвует
    в агрегации drivers (как endpoint-override/versions). Driver net-чек становится ТОЛЬКО при up=False.
    """
    _all_up_monkey(monkeypatch, probe_status="ok")
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200"))
    monkeypatch.setattr(health.sys_probe, "run", lambda cmd, timeout:
                        {"rc": 0, "out": _ROUTE_DEFAULT_UP, "err": "", "timeout": False}
                        if cmd[:3] == [ROUTE, "-n", "get"]
                        else {"rc": 0, "out": "", "err": "", "timeout": False})
    result = health.check_all()
    assert result["status"] == "ok", "всё живо → ok (net-чек не роняет)"
    net = [c for c in result["checks"] if "сеть" in c["name"].lower() or "интерфейс" in c["name"].lower() or "маршрут" in c["name"].lower()][0]
    assert net.get("info") is True, "сеть активна → info-only (не driver)"


# ============================ #204: локальный прокси (privoxy/xray) service-status ============================
# Ситуация #3 эпика #201: туннель fail без различения «VPS мёртв» (#194 — есть) vs «локальный прокси
# упал». _local_proxy_up() комбинирует _port_up (TCP-listen) + _service_running (launchd-state):
#   - port closed → «крах» (демон не слушает, упал/не стартовал);
#   - port open + service not-running → «зомби» (порт занят чем-то, но launchd-сервис не Running);
#   - оба up → ok.
# Канон: verify-don't-guess — service-status это ЯВНЫЙ сигнал (brew services info Running?),
# не догадка по port-open. Не используем `brew services info` (protected-mode privoxy = system
# daemon com.srouter.privoxy, brew его не видит → ложный зомби) — единый источник launchctl print
# для protected И brew-mode (как _launchd_job_snapshot health.py:_collect_launchd_lifecycle).

def test_local_proxy_ok_when_ports_up_and_services_running(monkeypatch):
    """Оба порта слушаются + оба сервиса Running → ok. Нормальное состояние стека."""
    monkeypatch.setattr(health, "_port_up", lambda port: True)
    monkeypatch.setattr(health, "_service_running", lambda label, domain=None: "running")
    result = health._local_proxy_up()
    assert result["status"] == "ok", "порты up + сервисы running → ok"


def test_local_proxy_down_when_port_closed(monkeypatch):
    """ДЫРА #204: privoxy port closed → down «крах» (демон не слушает). Раньше _port_up сам по себе
    молчал о причине. Теперь service-status объясняет: порт не слушается = прокси упал/не стартовал."""
    monkeypatch.setattr(health, "_port_up",
                        lambda port: False if port == health.PRIVOXY_PORT else True)
    monkeypatch.setattr(health, "_service_running", lambda label, domain=None: "running")
    result = health._local_proxy_up()
    assert result["status"] == "down", "privoxy port closed → down (крах)"
    assert "крах" in result["detail"].lower() or "port" in result["detail"].lower() \
        or "closed" in result["detail"].lower(), "detail объясняет: крах (port закрыт)"


def test_local_proxy_zombie_when_port_open_but_service_not_running(monkeypatch):
    """ДЫРА #204: port open + service NOT running → ЗОМБИ. Порт слушается (кем-то), но launchd-сервис
    не Running → privoxy-процесс отвалился от launchd (orphan) либо порт занят чужим. Раньше
    port-open давал ложный ok. Теперь service-status ловит несоответствие."""
    monkeypatch.setattr(health, "_port_up", lambda port: True)
    def fake_running(label, domain=None):
        return "not_running" if label == health.PRIVOXY_SYSTEM_LABEL or label == "homebrew.mxcl.privoxy" else "running"
    monkeypatch.setattr(health, "_service_running", fake_running)
    result = health._local_proxy_up()
    assert result["status"] == "down", "port open + service not-running → down (зомби)"
    assert "зомби" in result["detail"].lower() or "not-running" in result["detail"].lower() \
        or "not running" in result["detail"].lower(), "detail объясняет: зомби (service not-running)"


def test_local_proxy_down_when_xray_port_closed(monkeypatch):
    """xray port closed → down (крах xray). Оба компонента проверяются, не только privoxy."""
    monkeypatch.setattr(health, "_port_up",
                        lambda port: False if port == health.XRAY_PORT else True)
    monkeypatch.setattr(health, "_service_running", lambda label, domain=None: "running")
    result = health._local_proxy_up()
    assert result["status"] == "down", "xray port closed → down"
    assert "xray" in result["detail"].lower(), "detail указывает xray"


def test_local_proxy_not_zombie_when_launchctl_times_out(monkeypatch):
    """ДЫРА #204 (cycle-review Codex P1): launchctl print timeout -> service-status НЕ верифицируем.
    Канон fail-closed (как _read_gui_proxy_env): не различимо not-running от не-спросили.
    Раньше _service_running возвращал bool -> timeout->False -> port-open+False ложно зомби (с
    советом restart!). Теперь _service_running tri-state; при unknown НЕ утверждаем зомби —
    вердикт по port-open (ok, если порт слушается), с пометкой «service-status не верифицирован».
    privoxy реально работает (держит 8118), просто launchctl не ответил — НЕ роняем в зомби."""
    monkeypatch.setattr(health, "_port_up", lambda port: True)
    monkeypatch.setattr(health, "_service_running", lambda label, domain=None: "unknown")
    result = health._local_proxy_up()
    assert result["status"] == "ok", "timeout launchctl + port-open -> ok, НЕ ложный зомби"
    assert "зомби" not in result["detail"].lower(), \
        "timeout != зомби (fail-closed: не утверждаем без service-evidence)"


def test_local_proxy_zombie_requires_confirmed_not_running(monkeypatch):
    """Зомби требует ПОДТВЕРЖДЁННОГО not-running (state!=running, rc=0), не timeout/unknown.
    Регресс-гвард P1: только not_running (launchctl ответил, state waiting/exited) -> зомби."""
    monkeypatch.setattr(health, "_port_up", lambda port: True)
    monkeypatch.setattr(health, "_service_running", lambda label, domain=None: "not_running"
                        if (label == health.PRIVOXY_SYSTEM_LABEL or label == "homebrew.mxcl.privoxy")
                        else "running")
    result = health._local_proxy_up()
    assert result["status"] == "down", "port-open + confirmed not-running -> down (зомби)"
    assert "зомби" in result["detail"].lower()



# Интеграция в check_all: DRIVER когда туннель fail (проблема в локальном прокси, VPS жив/н/д).
# Туннель ok → info (картина, не driver — порты уже driver через _port_up чеки выше).

def test_local_proxy_driver_down_when_tunnel_fail_and_port_closed(monkeypatch):
    """ДЫРА #204: туннель fail + локальный прокси down (port closed) → driver. Раньше туннель-fail
    без причины. Теперь _local_proxy_up объясняет: «локальный прокси упал — restart»."""
    _all_up_monkey(monkeypatch)  # порты/claude/codex/app/desktop — ok/info, не роняют
    monkeypatch.setattr(health, "_tunnel_up", lambda: (False, "connection-failed"))
    # VPS жив (info-only, не маскирует локальный прокси) — различение от ситуации #2 (#194):
    _mock_active_node(monkeypatch, {"name": "vps-1", "endpoint_host": "198.51.100.7", "port": 443})
    _mock_vps_tcp(monkeypatch, reachable=True)
    # порты закрыты (крах) + сервисы (мок running из _all_up_monkey не релевантен — port-down = крах):
    monkeypatch.setattr(health, "_port_up", lambda port: False)
    result = health.check_all()
    assert result["status"] in ("degraded", "down"), "туннель fail + прокси down → не ok"
    lp = [c for c in result["checks"] if "локальн" in c["name"].lower() or "proxy-up" in c["name"].lower()
          or "local proxy" in c["name"].lower()][0]
    assert lp["ok"] is False, "локальный прокси down → driver (ok=False)"
    assert not lp.get("info"), "down — НЕ info (driver)"


def test_local_proxy_info_when_tunnel_ok(monkeypatch):
    """Туннель ok → _local_proxy_up = info-only (порты уже driver через _port_up чеки; сервис-статус
    не роняет вердикт когда канал и так жив). Канон: info-only когда проблема не актуальна."""
    _all_up_monkey(monkeypatch, probe_status="ok")
    # порты up + сервисы running (мок _all_up_monkey) → _local_proxy_up ok:
    result = health.check_all()
    assert result["status"] == "ok", "всё живо → ok"
    lp = [c for c in result["checks"] if "локальн" in c["name"].lower() or "local proxy" in c["name"].lower()
          or "proxy-up" in c["name"].lower()][0]
    assert lp.get("info") is True, "туннель ok → local-proxy чек info-only"


def test_service_running_uses_system_domain_for_protected_privoxy(monkeypatch):
    """protected-mode (privoxy_system.protection_present) → privoxy label=com.srouter.privoxy,
    domain=system. brew services info его НЕ видит → единый источник launchctl print (как
    _collect_launchd_lifecycle health.py:1658). Проверяем что _service_running зовётся с system
    domain для protected, gui для brew-mode."""
    calls = []

    def fake_run(cmd, timeout):
        calls.append(cmd)
        # rc=0 + state=running → running True (формат launchctl print).
        return {"rc": 0, "out": "\tstate = running;\n\tpid = 1234;\n", "err": "", "timeout": False}

    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    monkeypatch.setattr(health.privoxy_system, "protection_present", lambda: True)
    health._service_running(health.privoxy_system.SYSTEM_LABEL, domain="system")
    # проверяем что launchctl print system/<label>:
    assert any("print" in c and "system/" in " ".join(c) for c in calls), \
        "protected → launchctl print system/<label>"


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
    """SOCKS5 в HTTPS_PROXY → down (чужой SOCKS5, не codenv — Desktop App не поддерживает SOCKS5)."""
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"HTTPS_PROXY": "socks5h://127.0.0.1:10808"}})
    monkeypatch.setattr(health, "_codenv_managed", lambda: False)
    res = health._desktop_proxy_check()
    assert res["status"] == "down"
    assert "socks" in res["detail"].lower() or "SOCKS5" in res["detail"]


def test_desktop_proxy_down_when_socks5_in_http_proxy(monkeypatch):
    """SOCKS5 в HTTP_PROXY (не HTTPS_PROXY) → down. РЕГРЕССИЯ на инцидент #127: SOCKS5 сидел в
    HTTP_PROXY, doctor (читая только HTTPS_PROXY) говорил ✅."""
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"HTTP_PROXY": "socks5h://127.0.0.1:10808"}})
    monkeypatch.setattr(health, "_codenv_managed", lambda: False)
    res = health._desktop_proxy_check()
    assert res["status"] == "down"
    assert "HTTP_PROXY" in res["detail"]


def test_desktop_proxy_down_when_socks5_in_all_proxy(monkeypatch):
    """SOCKS5 в ALL_PROXY → down (чужой SOCKS5 в любом ключе — мина)."""
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"ALL_PROXY": "socks5h://127.0.0.1:10808"}})
    monkeypatch.setattr(health, "_codenv_managed", lambda: False)
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
    """HTTPS_PROXY=HTTP + HTTP_PROXY=SOCKS5 → down (чужой SOCKS5, не угадываем selector; SOCKS5 — мина).

    У приложений разный selector приоритетов (Claude/Node/Electron), мы его НЕ моделируем —
    SOCKS5 в любом ключе = конфиг грязный/опасный → down. Фиксирует границу обобщения #134."""
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"HTTPS_PROXY": "http://127.0.0.1:8118",
                                                  "HTTP_PROXY": "socks5h://127.0.0.1:10808"}})
    monkeypatch.setattr(health, "_codenv_managed", lambda: False)
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


def test_desktop_proxy_info_when_socks5_and_codenv_managed(monkeypatch):
    """SOCKS5 в launchctl + codenv-managed plist → info (намеренный codenv #189), НЕ driver-шум.

    Архитектурный конфликт #189/#127: codenv SOCKS5 лечит ChatGPT.app Rust app-server, но ломает
    Claude Desktop App. doctor показывает факт в detail, но НЕ роняет вердикт — иначе нормальная
    установка с codenv вечно degraded (шум, как PR #135 для PF).
    """
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"ALL_PROXY": "socks5h://127.0.0.1:10808"}})
    monkeypatch.setattr(health, "_codenv_managed", lambda: True)
    res = health._desktop_proxy_check()
    assert res["status"] == "info", f"codenv SOCKS5 → info (не driver-шум); got {res}"
    assert "codenv" in res["detail"].lower(), f"detail объясняет codenv-tradeoff; got {res}"


def test_desktop_proxy_down_when_socks5_foreign_no_codenv(monkeypatch):
    """SOCKS5 в launchctl БЕЗ codenv-managed → down (чужой корпоративный SOCKS5, инцидент #127-класс).

    Регрессия: codenv-aware НЕ должно глушить ИСТИННЫЙ инцидент — чужой SOCKS5 (не наш codenv) ломает
    Claude Desktop App, это настоящий down-driver.
    """
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"HTTPS_PROXY": "socks5h://10.0.0.1:1080"}})
    monkeypatch.setattr(health, "_codenv_managed", lambda: False)
    res = health._desktop_proxy_check()
    assert res["status"] == "down", f"чужой SOCKS5 (не codenv) → down (#127); got {res}"


def test_codenv_managed_no_crash_on_binary_plist(monkeypatch, tmp_path):
    """_codenv_managed НЕ крашится на бинарном/повреждённом plist → False (fail-safe).

    Cycle-review finding: Path.read_text(encoding=utf-8) на бинарном plist кидает UnicodeDecodeError
    (наследник ValueError, НЕ OSError). except OSError его пропускал → crash через _desktop_proxy_check
    → check_all (fail-open, нарушение srouter-critical-infra-24-7). codenv plist обычно XML, но может
    быть binary (plutil -convert binary1) или повреждён — один файл не должен ронять весь doctor.
    """
    plist = tmp_path / "Library" / "LaunchAgents" / f"{health._CODENV_LABEL}.plist"
    plist.parent.mkdir(parents=True)
    plist.write_bytes(b"\xff\xfe\x00\x01binary-plist-not-utf8")  # невалидный UTF-8
    monkeypatch.setattr(health.Path, "home", lambda: tmp_path)
    # НЕ должно бросать — fail-safe False (трактуем как «не наш codenv» → down для чужого SOCKS5).
    assert health._codenv_managed() is False


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
    """SOCKS5 в launchctl (down) важнее расхождения с CLI — down не маскируется в warn.

    Чужой SOCKS5 (не codenv) — down приоритетнее warn-расхождения."""
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"HTTPS_PROXY": "socks5h://127.0.0.1:10808"},
                                "cli_proxy": "http://127.0.0.1:8118"})
    monkeypatch.setattr(health, "_codenv_managed", lambda: False)
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


def test_runtime_check_unknown_when_some_pid_unreadable(monkeypatch):
    """cycle-review Codex c2: один PID без env (sandbox/permission) + другой standard → НЕ ok.

    Тот же класс #143 что cycle 1, следующий слой: override-PID мог быть тем, чей env не прочитан
    (per-process sandbox/permission failure / partial ps). Если standard-PID маскирует — ложный ok.
    Правило: override приоритетнее (info), но если override не найден и ХОТЯ БЫ ОДИН PID без
    evidence → unknown (verify-dont-guess: нет evidence для этого PID = не ok). Тест ОБА порядка.
    """
    UNREADABLE_PID, STANDARD_PID = "111", "222"
    UNREADABLE_COMM, STANDARD_COMM = CLI_COMM, VERSION_RUNNER_COMM
    STANDARD_ENV = "ANTHROPIC_BASE_URL=https://api.anthropic.com ANTHROPIC_API_KEY=k"

    def run_once(pid_order):
        listing = "\n".join(f"{p} {c}" for p, c in pid_order) + "\n"
        # UNREADABLE_PID: строка процесса есть, но env пуст (ps eww не отдал ANTHROPIC_*).
        # STANDARD_PID: standard endpoint.
        eww = (f"{UNREADABLE_PID} /path/claude \n"            # пустой env (непрочитан)
               f"{STANDARD_PID} /path/claude {STANDARD_ENV}\n")

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
        ("unreadable-first", run_once([(UNREADABLE_PID, UNREADABLE_COMM), (STANDARD_PID, STANDARD_COMM)])),
        ("unreadable-last", run_once([(STANDARD_PID, STANDARD_COMM), (UNREADABLE_PID, UNREADABLE_COMM)])),
    ]:
        monkeypatch.setattr(health.sys_probe, "run", fake)
        res = health._runtime_model_override_check()
        assert res["status"] == "unknown", \
            f"[{label}] PID без evidence → unknown (НЕ ok; standard-PID не маскирует), got {res['status']}"


# ============================ #186 codex-isolation PF kill-switch check ============================
# Doctor-чек PF codex kill-switch: info-only для всех «незамкнутых» состояний (no-lease /
# lease+no-user / lease+user+no-proc), ok только при реальном процессе под UID 503. НЕ driver
# (избегаем шума на нормальных установках, как PR #135). Gate под active_claude (doctor-only).
def _codex_iso_probes(monkeypatch, *, lease_status, provisioned, ps_out="", ps_rc=1):
    """Мок isolate_firewall.probe_codex_isolation/probe_codex_user + ps для _codex_isolation_check.

    lease_status: probe_codex_isolation()['status'] ('ok'|'down').
    provisioned: probe_codex_user()['provisioned'].
    ps_out/ps_rc: вывод `ps -u 503` (rc=0+out → процесс есть; rc=1+пусто → нет).
    """
    import isolate_firewall

    def fake_probe_lease(state_path=None):
        return {"status": lease_status, "token": "5", "applied_at": 1} if lease_status == "ok" \
            else {"status": lease_status, "token": None, "applied_at": None}

    def fake_probe_user():
        return ({"provisioned": True, "uid": "503", "name": "_srouter_codex", "gid": "503"}
                if provisioned else {"provisioned": False, "uid": None, "name": None, "gid": None})
    monkeypatch.setattr(isolate_firewall, "probe_codex_isolation", fake_probe_lease)
    monkeypatch.setattr(isolate_firewall, "probe_codex_user", fake_probe_user)

    def fake_run(cmd, timeout, **kwargs):
        if cmd and cmd[0] == "/bin/ps" and "-u" in cmd:
            return {"rc": ps_rc, "out": ps_out, "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}
    monkeypatch.setattr(health.sys_probe, "run", fake_run)


def test_codex_isolation_check_info_when_no_lease(monkeypatch):
    """Нет lease → info (не установлен по выбору, не сбой стека)."""
    _codex_iso_probes(monkeypatch, lease_status="down", provisioned=False)
    assert health._codex_isolation_check()["status"] == "info"


def test_codex_isolation_check_info_when_lease_no_user(monkeypatch):
    """Lease ok, но UID не provisioned → info (инфра загружена, матчить нечего)."""
    _codex_iso_probes(monkeypatch, lease_status="ok", provisioned=False)
    assert health._codex_isolation_check()["status"] == "info"


def test_codex_isolation_check_info_when_lease_user_no_proc(monkeypatch):
    """Lease ok + user provisioned, но НЕТ процесса под UID 503 → info (PF standby, sudo -u = follow-up).

    ps -u 503 для без-процесса UID → rc=1, пустой out (verify-dont-guess)."""
    _codex_iso_probes(monkeypatch, lease_status="ok", provisioned=True,
                      ps_out="", ps_rc=1)
    assert health._codex_isolation_check()["status"] == "info"


def test_codex_isolation_check_ok_when_proc_under_uid(monkeypatch):
    """Lease + user + процесс под UID 503 → ok (real fail-closed активна)."""
    _codex_iso_probes(monkeypatch, lease_status="ok", provisioned=True,
                      ps_out=" 1234 /usr/local/bin/codex\n", ps_rc=0)
    assert health._codex_isolation_check()["status"] == "ok"


def test_codex_isolation_check_info_when_ps_timeout(monkeypatch):
    """ps timeout → fail-soft info (не ложный ok, не падение)."""
    import isolate_firewall
    monkeypatch.setattr(isolate_firewall, "probe_codex_isolation",
                        lambda state_path=None: {"status": "ok", "token": "5", "applied_at": 1})
    monkeypatch.setattr(isolate_firewall, "probe_codex_user",
                        lambda: {"provisioned": True, "uid": "503", "name": "_srouter_codex", "gid": "503"})
    monkeypatch.setattr(health.sys_probe, "run",
                        lambda cmd, timeout, **kw: {"rc": 0, "out": "", "err": "", "timeout": True})
    assert health._codex_isolation_check()["status"] == "info"


def test_check_all_codex_isolation_gated_under_active_claude(monkeypatch):
    """check_all: codex-isolation чек ТОЛЬКО при active_claude=True (doctor-only), info НЕ driver.

    Проверяем gate + info-исключение из drivers (НЕ агрегатный status — он зависит от других
    doctor-чеков на машине). Инвариант: info-only codex-isolation не входит в drivers → не влияет
    на вердикт (избегаем шума как PR #135)."""
    _codex_iso_probes(monkeypatch, lease_status="down", provisioned=False)
    _all_up_monkey(monkeypatch, probe_status="ok", codex_status="ok")

    # active_claude=False (лёгкий /health/watchdog) — чека codex-isolation НЕТ.
    result = health.check_all(active_claude=False)
    names = [c["name"] for c in result["checks"]]
    assert not any("codex-isolation" in n for n in names), \
        f"лёгкий путь НЕ должен нести codex-isolation чек (overhead); checks={names}"

    # active_claude=True (doctor) — чек есть, info-only → НЕ driver (исключён из drivers).
    result = health.check_all(active_claude=True)
    ci = next(c for c in result["checks"] if "codex-isolation" in c["name"])
    assert ci.get("info") is True, "codex-isolation info-only (НЕ driver — avoid шума)"
    drivers = [c for c in result["checks"] if not c.get("info")]
    assert ci not in drivers, "info-only codex-isolation исключён из drivers (не роняет вердикт)"


def test_check_all_codex_isolation_ok_is_driver(monkeypatch):
    """При реальном процессе под UID 503 → ok=driver (НЕ info-only), но не падает статус ниже degraded."""
    _codex_iso_probes(monkeypatch, lease_status="ok", provisioned=True,
                      ps_out=" 1234 codex\n", ps_rc=0)
    _all_up_monkey(monkeypatch, probe_status="ok", codex_status="ok")
    result = health.check_all(active_claude=True)
    ci = next(c for c in result["checks"] if "codex-isolation" in c["name"])
    assert ci["ok"] is True, "real fail-closed активна → ok"
    assert not ci.get("info"), "ok — НЕ info-only (driver)"
    drivers = [c for c in result["checks"] if not c.get("info")]
    assert ci in drivers, "ok codex-isolation входит в drivers (real fail-closed = driver)"


# ============================ #200: рассинхрон endpoint local.json ↔ xray config (doctor) ============================
# Doctor видит РЕАЛЬНЫЙ endpoint (из рабочего xray config), не placeholder из local.json. Когда
# local.json держит test-IP 203.0.113.x, а xray — реальный VPS — это рассинхрон источника правды.
# verify-dont-guess: doctor показывает реальный адрес + WARN «local.json рассинхронизирован».
# Чек info-only (как endpoint-override) — не роняет вердикт стека, картина для диагностики.

def _xray_with_vless(address):
    """JSON-текст рабочего xray-config с vless-outbound на address (как _write_xray_config в test_local_state)."""
    return json.dumps({"outbounds": [
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "active", "protocol": "vless",
         "settings": {"vnext": [{"address": address, "port": 443}]}},
    ]})


def test_endpoint_xray_sync_check_ok_when_synced(tmp_path, monkeypatch):
    """ТДД #200-1: local.json endpoint == xray address → ok (синхрон)."""
    state_p = tmp_path / "srouter.local.json"
    xray_p = tmp_path / "xray-config.json"
    state_p.write_text(json.dumps({
        "nodes": [{"name": "sg-1", "endpoint_host": "85.136.181.198",
                   "route_ip": "85.136.181.198", "enabled": True}],
        "active_node": {"name": "sg-1", "pending": None},
    }), encoding="utf-8")
    xray_p.write_text(_xray_with_vless("85.136.181.198"), encoding="utf-8")

    chk = health._endpoint_xray_sync_check(state_path=str(state_p), xray_config_path=str(xray_p))
    assert chk["status"] == "ok", chk


def test_endpoint_xray_sync_check_warn_shows_real_endpoint_on_drift(tmp_path):
    """ТДД #200-5: local.json placeholder + xray реальный → warn, detail показывает РЕАЛЬНЫЙ endpoint.

    Канон verify-dont-guess: doctor показывает реальный адрес из xray (85.136.181.198), не placeholder
    (203.0.113.10), и предупреждает о рассинхроне.
    """
    state_p = tmp_path / "srouter.local.json"
    xray_p = tmp_path / "xray-config.json"
    state_p.write_text(json.dumps({
        "nodes": [{"name": "sg-1", "endpoint_host": "203.0.113.10",
                   "route_ip": "203.0.113.10", "enabled": True}],
        "active_node": {"name": "sg-1", "pending": None},
    }), encoding="utf-8")
    xray_p.write_text(_xray_with_vless("85.136.181.198"), encoding="utf-8")

    chk = health._endpoint_xray_sync_check(state_path=str(state_p), xray_config_path=str(xray_p))
    assert chk["status"] == "warn", chk
    detail = chk["detail"]
    assert "85.136.181.198" in detail, "detail показывает РЕАЛЬНЫЙ endpoint из xray"
    assert "203.0.113.10" in detail, "detail упоминает placeholder из local.json"
    assert "рассинхрон" in detail.lower() or "sync" in detail.lower()


def test_endpoint_xray_sync_check_info_when_no_xray_config(tmp_path):
    """xray-конфига нет → info (нечего сравнивать, fresh install). Не падает."""
    state_p = tmp_path / "srouter.local.json"
    xray_p = tmp_path / "missing.json"
    state_p.write_text(json.dumps({
        "nodes": [{"name": "sg-1", "endpoint_host": "203.0.113.10", "enabled": True}],
        "active_node": {"name": "sg-1", "pending": None},
    }), encoding="utf-8")

    chk = health._endpoint_xray_sync_check(state_path=str(state_p), xray_config_path=str(xray_p))
    assert chk["status"] == "info", chk


def test_endpoint_xray_sync_check_info_when_no_active_node(tmp_path):
    """Нет активного узла → info (apply ещё не настроен)."""
    state_p = tmp_path / "srouter.local.json"
    xray_p = tmp_path / "xray-config.json"
    state_p.write_text(json.dumps({
        "nodes": [], "active_node": {"name": None, "pending": None},
    }), encoding="utf-8")
    xray_p.write_text(_xray_with_vless("85.136.181.198"), encoding="utf-8")

    chk = health._endpoint_xray_sync_check(state_path=str(state_p), xray_config_path=str(xray_p))
    assert chk["status"] == "info", chk


def test_endpoint_xray_sync_check_is_info_only_in_check_all(tmp_path, monkeypatch):
    """Чек интегрирован в check_all как info-only (не driver — картина, не сбой стека)."""
    import local_state
    _all_up_monkey(monkeypatch, probe_status="ok")
    # pointing local_state + xray-config path в tmp через monkeypatch
    state_p = tmp_path / "srouter.local.json"
    xray_p = tmp_path / "xray-config.json"
    state_p.write_text(json.dumps({
        "nodes": [{"name": "sg-1", "endpoint_host": "203.0.113.10", "enabled": True}],
        "active_node": {"name": "sg-1", "pending": None},
    }), encoding="utf-8")
    xray_p.write_text(_xray_with_vless("85.136.181.198"), encoding="utf-8")
    monkeypatch.setattr(health, "_ENDPOINT_SYNC_STATE_PATH", str(state_p))
    monkeypatch.setattr(health, "_ENDPOINT_SYNC_XRAY_PATH", str(xray_p))

    result = health.check_all()
    es = next((c for c in result["checks"] if "endpoint" in c["name"].lower() and "xray" in c["name"].lower()), None)
    assert es is not None, "check_all содержит endpoint-xray-sync check"
    assert es.get("info") is True, "endpoint-xray-sync check — info-only (не driver)"
