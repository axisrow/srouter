"""ТДД-тесты health.check_all + _claude_proxy_probe: doctor видит РЕАЛЬНОЕ состояние Claude-proxy.

Контракт (дыра, найденная Codex review + инцидентом «без ИИ»): claude_proxy.status() читал только
ФАЙЛ settings.json, а не реальный CC. enable()/disable() пишут файл, но не перезапускают CC → окно
рассинхрона файл↔процесс. Решение: runtime-proof через lsof — CC держит established TCP к privoxy
(127.0.0.1:8118). Поведенческий proof из ядерной таблицы сокетов, надёжный для всех типов CC-сессий.

_claude_proxy_probe() возвращает {status, source, detail}:
  status="ok"      — CC запущен и держит коннект к privoxy (реально юзает прокси);
  status="down"    — CC запущен, но БЕЗ коннекта (идёт напрямую → PF режет → «без ИИ»);
  status="unknown" — CC не запущен (check_all НЕ агрегирует этот check — info-only, не driver).
"""
import health


def _all_up_monkey(monkeypatch, *, probe_status="ok", probe_detail="runtime: коннект"):
    """Мок: все порты+туннель живы; _claude_proxy_probe отдаёт заданный status."""
    monkeypatch.setattr(health, "_port_up", lambda port: True)
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 404"))
    monkeypatch.setattr(health, "_claude_proxy_probe",
                        lambda: {"status": probe_status, "source": "runtime" if probe_status != "unknown" else "n/a",
                                 "detail": probe_detail})


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
    """CLI CC (полный путь в comm) + lsof показал TCP к privoxy → status=ok."""
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


def test_probe_down_when_cc_without_proxy_connection(monkeypatch):
    """CC запущен (GUI comm=полный путь), но lsof НЕ показал коннект → status=down (инцидент «без ИИ»)."""
    def fake_run(cmd, timeout):
        if cmd and cmd[0] == "/bin/ps":
            return {"rc": 0, "out": f"12345 {GUI_COMM}\n", "err": "", "timeout": False}
        if cmd and cmd[0] == "/usr/sbin/lsof":
            return {"rc": 0, "out": "claude 12345 axisrow 7u IPv4 ... TCP 127.0.0.1:51234->22 (ESTABLISHED)\n", "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    res = health._claude_proxy_probe()
    assert res["status"] == "down"


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

    result = health.check_all()
    assert result["status"] == "down"
