"""ТДД-тесты health.check_all + _claude_proxy_probe: doctor видит РЕАЛЬНОЕ состояние Claude-proxy.

Пассивный lsof-probe показывает маршрут живого процесса и ловит direct leak, но не доказывает
поддержку proxy protocol. В частности, established TCP к SOCKS 10808 не означает успешный SOCKS
handshake или ответ API (#127). Поддержку доказывает только active real-CLI test с ожидаемым 401;
его тесты находятся в test_claude_transport.py.

_claude_proxy_probe() возвращает {status, source, detail}:
  status="ok"      — CC держит коннект к ожидаемому HTTP bridge 8118;
  status="down"    — CC имеет внешний direct socket с читаемым env (атрибутируемая утечка);
  status="unknown" — только SOCKS TCP socket, idle, timeout, CC не запущен, endpoint-override
                     в NO_PROXY (прямой ход намеренно, #329) или external у PID с нечитаемым
                     env (sandbox/чужой UID — атрибуция невозможна, #329).
"""
import json
import os

import pytest as _pytest
import pytest  # noqa: ICN003 — pytest.fail/raises в тестах ниже (#194)

import health
import metrics_store
import privoxy_system
import sys_probe


# Watchdog tests must not inspect the real user's launchd domain or write real lifecycle logs.
# Dedicated lifecycle tests below call the saved implementation explicitly with isolated paths.
_REAL_RECORD_WATCHDOG_LIFECYCLE = getattr(health, "_record_watchdog_lifecycle", None)

# #271: _all_up_monkey мокает _network_interface_up целиком (real route/ifconfig иначе гуляет по
# dev-машине). Тесты #203-каскада (test_network_down_*/test_network_up_proceeds_*/
# test_network_check_is_info_only_when_up, test_dns_*_masks/proceeds/info_only) намеренно проверяют
# РЕАЛЬНУЮ _network_interface_up через мок sys_probe.run (route/ifconfig) — им нужен настоящий
# helper, не заглушка. Восстанавливают его этой ссылкой ПОСЛЕ _all_up_monkey (late-binding).
_REAL_NETWORK_INTERFACE_UP = health._network_interface_up

# #271: аналогично — _codex_isolation_check тесты (test_check_all_codex_isolation_*) мокают
# isolate_firewall.probe_codex_isolation/probe_codex_user + ps через _codex_iso_probes ДО вызова
# _all_up_monkey; им нужна РЕАЛЬНАЯ _codex_isolation_check, не глобальная заглушка.
_REAL_CODEX_ISOLATION_CHECK = health._codex_isolation_check

# #329: аналогично — check_all-интеграционный тест override-гейта хочет РЕАЛЬНУЮ _claude_proxy_probe
# (ps/lsof через мок sys_probe.run), а не заглушку из _all_up_monkey.
_REAL_CLAUDE_PROXY_PROBE = health._claude_proxy_probe


def _std_endpoint(monkeypatch):
    """#329: мок endpoint-конфига «стандартный, без override» для probe-тестов.

    _claude_proxy_probe консультируется с _read_endpoint_config (через health-фасад) — без мока
    она читала бы РЕАЛЬНЫЙ ~/.claude/settings.json/launchctl/shell dev-машины (там z.ai-override)
    → тесты становились machine-dependent (канон unmocked-probe-is-both-slow-and-machine-dependent).
    base_url="" → overridden=False → probe работает в обычном режиме.
    """
    monkeypatch.setattr(health, "_read_endpoint_config",
                        lambda: {"base_url": "", "no_proxy": "", "source": "default"})


def _all_up_monkey(monkeypatch, *, probe_status="ok", probe_detail="runtime: коннект",
                   codex_status="ok", codex_detail="runtime: codex через SOCKS5"):
    """Мок: все порты+туннель живы; _claude_proxy_probe и _codex_proxy_probe отдаёт заданные status.

    Оба probe мокаем (иначе реальный ps/lsof найдёт живой CC/codex на dev-машине → ok → тест
    пройдёт случайно или упадёт в зависимости от того, что запущено). codex_status по умолчанию ok.

    Заглушка «туннель здоров» = (True, HTTP 200): недвусмысленно живой канал. Прежнее
    (True, HTTP 404) полагалось на «любой не-000 = жив» — после фикса #82 семантика строгая
    (5xx=down, 2xx/3xx/4xx=up), 404 остаётся up, но 200 читается однозначнее как здоровый.

    Канон: параллельная копия — tests/test_health_versions.py::_machine_state_monkey. Новый
    machine-state probe добавляй в ОБА списка — гвард test_machine_state_mock_guard.py падает,
    если этот (канонический) набор перестанет быть подмножеством versions-набора (issue #267)."""
    monkeypatch.setattr(health, "_port_up", lambda port: True)
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200", False, None))
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
    # Chromium system-proxy check (живая регрессия 2026-08-28) — та же причина, что и
    # _codex_app_proxy_check выше: дёргает ps/lsof, живой ChatGPT.app на dev-машине драйвил бы вердикт.
    monkeypatch.setattr(health, "_codex_app_chromium_proxy_check",
                        lambda: {"status": "unknown", "source": "n/a", "detail": "NetworkService не активен (mock)"})
    monkeypatch.setattr(health, "_desktop_proxy_check",
                        lambda: {"status": "unknown", "detail": "launchctl (mock)"})
    # #205: _dns_up дёргает _resolve_host (socket.getaddrinfo github.com) — мокаем резолв ok, иначе
    # реальный DNS dev-машины (особенно в sandbox без сети) драйвит DNS-чек недетерминированно и
    # ломает старые #196/#203 тесты (DNS-down стал бы driver). #205-тесты переопределяют своим _mock_dns.
    monkeypatch.setattr(health, "_resolve_host", lambda host: True)
    # #194: _upstream_vps_reachable дёргает local_state.active_node + sys_probe.port_open — мокаем
    # «нет узла» (info-only), иначе реальный srouter.local.json на dev-машине (+ живой/мёртвый VPS)
    # драйвит вердикт недетерминированно. В этих тестах VPS-чек НЕ предмет проверки → info-заглушка.
    import local_state
    monkeypatch.setattr(local_state, "active_node", lambda path=None: {})
    # #204: _local_proxy_up дёргает launchctl print (через _service_running) — мокаем running=True,
    # иначе реальный launchd на dev-машине (protected/brew-mode, живой/мёртвый privoxy/xray)
    # драйвит вердикт недетерминированно. _port_up уже мокаем True выше → ok по контракту.
    monkeypatch.setattr(health, "_service_running", lambda label, domain=None: "running")
    # #252 perf: _gfw_domain_check/_direct_first_check (active_claude-путь) делают РЕАЛЬНЫЙ прямой
    # curl (env -u) к github.com/z.ai через sys_probe.direct_probe — без мока каждый
    # check_all(active_claude=True) в сьюте платит секунды сетевого I/O (cProfile: ~4.4s + ~1.6s
    # на вызов, топ-1 виновник времени сьюта в #251). Тесты, которым нужен реальный wiring этих
    # чеков (test_gfw_domain_check_*/test_direct_first_check_*), переопределяют мок ПОСЛЕ этого
    # вызова через _mock_domain_probe/_mock_direct_first — late-binding monkeypatch.setattr
    # гарантирует, что их мок побеждает (эта функция вызывается первой везде).
    monkeypatch.setattr(health, "_gfw_domain_check",
                        lambda *a, **kw: {"status": "ok", "detail": "mock: GFW не режет"})
    monkeypatch.setattr(health, "_direct_first_check",
                        lambda: {"status": "ok", "detail": "mock: direct-first reachable"})
    # #271: остальные проб check_all(), которые дёргают реальные системные API (route/ifconfig,
    # launchctl print, dscl+ps, git config, файлы settings/xray/лог) без промежуточного слоя,
    # уже замоканного выше — Codex adversarial review на PR #268 показал, что гвард
    # test_machine_state_mock_guard.py проверял только «canon ⊆ versions», а не «canon покрывает
    # ВСЕ real probes check_all». Мокаем чек целиком (как _claude_proxy_probe/_codex_proxy_probe
    # выше) — иначе dev-машина (её route table, launchd jobs, dscl-пользователи, git-config,
    # диск с binary) недетерминированно драйвит detail/status этих info-only чеков.
    monkeypatch.setattr(health, "_network_interface_up",
                        lambda: {"up": True, "detail": "mock: сеть активна"})
    monkeypatch.setattr(health, "_endpoint_xray_sync_check",
                        lambda *a, **kw: {"status": "ok", "detail": "mock: endpoint синхронизирован"})
    # _codenv_job_check НЕ мокаем здесь безусловно (issue #271, allowlist test_machine_state_mock_guard.py):
    # test_health_codenv_job.py::_codenv_checks вызывает _all_up_monkey ПОСЛЕ того, как тест уже
    # замокал health._codenv_job_check своим сценарием (ok/down/unknown) — безусловный мок здесь
    # перезаписал бы его позже по времени и молча подменил бы сценарий. Тесты этого файла, которые
    # НЕ мокают _codenv_job_check сами, получают реальный launchctl print (см. allowlist).
    monkeypatch.setattr(health, "_vscode_proxy_check",
                        lambda: {"status": "unknown", "detail": "mock: VSCode не установлен"})
    monkeypatch.setattr(health, "_github_direct_check",
                        lambda: {"status": "ok", "detail": "mock: github direct"})
    monkeypatch.setattr(health, "_runtime_model_override_check",
                        lambda: {"status": "ok", "detail": "mock: без override"})
    monkeypatch.setattr(health, "_installed_versions_check",
                        lambda: {"status": "unknown", "detail": "mock: не установлено", "codex": [], "claude_code": []})
    monkeypatch.setattr(health, "_privoxy_log_observability_check",
                        lambda *a, **kw: {"status": "ok", "detail": "mock: privoxy-log ок"})
    monkeypatch.setattr(health, "_codex_isolation_check",
                        lambda: {"status": "info", "detail": "mock: PF kill-switch не установлен"})
    monkeypatch.setattr(health, "_claude_transport_probe",
                        lambda *a, **kw: {"status": "unknown", "detail": "mock: CC не запущен (real CLI)"})


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
    _std_endpoint(monkeypatch)
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
    _std_endpoint(monkeypatch)
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
    _std_endpoint(monkeypatch)
    res = health._claude_proxy_probe()
    assert res["status"] == "unknown"
    assert "актив" in res["detail"].lower()
    assert "не доказывает" in res["detail"].lower()


def test_probe_down_when_cc_direct_leak(monkeypatch):
    """CC запущен (GUI comm), lsof показал external ESTABLISHED (не localhost) → down (DIRECT-LEAK).

    CC идёт НАПРЯМУЮ к api.anthropic.com мимо прокси — нарушение fail-closed-proxy-down.
    Doctor обязан детектить и сообщить (главная находка этой сессии).
    #329: external PID с ЧИТАЕМЫМ env (`ps eww` same-UID, ALL_CAPS= в выводе) — полноправный
    субъект проверки: атрибуция нарушения возможна → red-ветка остаётся достижимой.
    """
    def fake_run(cmd, timeout):
        if cmd and cmd[0] == "/bin/ps" and cmd[1] == "-axo":
            return {"rc": 0, "out": f"12345 {GUI_COMM}\n", "err": "", "timeout": False}
        if cmd and cmd[0] == "/bin/ps" and cmd[1] == "eww":
            return {"rc": 0, "out": f"12345 ttys000 0:01.00 {GUI_COMM} HTTPS_PROXY=http://127.0.0.1:8118 HOME=/Users/me\n", "err": "", "timeout": False}
        if cmd and cmd[0] == "/usr/sbin/lsof":
            # external ESTABLISHED — CC напрямую к Anthropic (не localhost)
            return {"rc": 0, "out": "claude 12345 axisrow 7u IPv4 ... TCP 192.168.1.5:51234->160.79.104.10:443 (ESTABLISHED)\n", "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    _std_endpoint(monkeypatch)
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
    _std_endpoint(monkeypatch)
    res = health._claude_proxy_probe()
    assert res["status"] == "unknown", "CC без активных сокетов → unknown (idle, не down)"


def test_probe_down_when_cc_mixed_proxy_and_direct_leak(monkeypatch):
    """HTTP proxy + external одновременно → down (mixed, direct-leak не маскируется proxy).

    Баг: has_proxy=True возвращал ok ДО проверки has_external → один PID через proxy,
    другой напрямую → doctor говорил ok. per-PID классификация: proxy+external = down (mixed).
    #329: external PID 102 с читаемым env → атрибуция возможна → down остаётся.
    """
    def fake_run(cmd, timeout):
        if cmd and cmd[0] == "/bin/ps" and cmd[1] == "-axo":
            return {"rc": 0, "out": f"101 {CLI_COMM}\n102 {CLI_COMM}\n", "err": "", "timeout": False}
        if cmd and cmd[0] == "/bin/ps" and cmd[1] == "eww":
            return {"rc": 0, "out": (
                f"102 ttys000 0:01.00 {CLI_COMM} HTTPS_PROXY=http://127.0.0.1:8118 HOME=/Users/me\n"
            ), "err": "", "timeout": False}
        if cmd and cmd[0] == "/usr/sbin/lsof":
            # PID 101 через privoxy, PID 102 напрямую (external)
            return {"rc": 0, "out": (
                f"claude 101 axisrow 7u IPv4 ... TCP 127.0.0.1:51234->127.0.0.1:{health.PRIVOXY_PORT} (ESTABLISHED)\n"
                "claude 102 axisrow 7u IPv4 ... TCP 192.168.1.5:51235->160.79.104.10:443 (ESTABLISHED)\n"
            ), "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    _std_endpoint(monkeypatch)
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


# ============================ #329: endpoint-override gate + env-атрибуция external PID ============================
# Ложный ❌ инцидента: при легитимном z.ai endpoint-override (ANTHROPIC_BASE_URL в NO_PROXY —
# канон zai-direct-no-proxy, CC ходит напрямую BY DESIGN) probe красила прямой ход как
# «нарушение fail-closed», противореча endpoint-пробе, которая тот же факт признаёт намеренным.
# lsof-классификация endpoint-слепа (numeric IP без hostname) → при override в NO_PROXY проба
# неприменима (unknown, parity с endpoint-пробой), а не down. «Дополнительно» из issue: external
# PID с нечитаемым env (sandbox/чужой UID, ps eww same-UID only) — HTTPS_PROXY к нему
# неприменим/непроверяем → атрибуция нарушения только по PID с читаемым env.

# Живой позитив-кейс этой машины (мокается, не читается): z.ai override в NO_PROXY.
_ZAI_OVERRIDE_CFG = {"base_url": "https://api.z.ai/api/anthropic",
                     "no_proxy": "localhost,127.0.0.1,::1,z.ai,.z.ai,storage.googleapis.com",
                     "source": "shell"}
# external ESTABLISHED, похожий на утечку (не localhost) — ровно то, что probe видит при z.ai.
_EXTERNAL_LEAK_LINE = ("claude 12345 axisrow 7u IPv4 ... TCP "
                       "192.168.1.5:51234->160.79.104.10:443 (ESTABLISHED)\n")


def _ps_lsof_fake(ps_out, lsof_out, eww_out=""):
    """fake_run для связки ps -axo / ps eww / lsof — все прочие команды → пустой вывод."""
    def fake_run(cmd, timeout):
        if cmd and cmd[0] == "/bin/ps" and cmd[1] == "-axo":
            return {"rc": 0, "out": ps_out, "err": "", "timeout": False}
        if cmd and cmd[0] == "/bin/ps" and cmd[1] == "eww":
            return {"rc": 0, "out": eww_out, "err": "", "timeout": False}
        if cmd and cmd[0] == "/usr/sbin/lsof":
            return {"rc": 0, "out": lsof_out, "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}
    return fake_run


def test_probe_unknown_when_endpoint_in_no_proxy_override(monkeypatch):
    """#329 RED: z.ai override в NO_PROXY + CC external → unknown «проба неприменима», НЕ down.

    Раньше probe возвращала down «нарушение fail-closed» на легитимной конфигурации — ложный ❌
    на здоровой системе (и driver-дебаунс watchdog'а). Прямое соединение к endpoint намеренно;
    красная ветка детектора при этом остаётся достижимой (см. следующий тест).
    """
    monkeypatch.setattr(health.sys_probe, "run",
                        _ps_lsof_fake(f"12345 {CLI_COMM}\n", _EXTERNAL_LEAK_LINE))
    monkeypatch.setattr(health, "_read_endpoint_config", lambda: _ZAI_OVERRIDE_CFG)
    res = health._claude_proxy_probe()
    assert res["status"] == "unknown", \
        "endpoint в NO_PROXY → прямой ход намеренно, НЕ «нарушение fail-closed»"
    assert "неприменима" in res["detail"]
    assert "намеренно" in res["detail"]
    assert "160.79.104.10" in res["detail"] or "12345" in res["detail"], \
        "external-наблюдение остаётся в detail как форензика"


def test_probe_down_when_override_not_in_no_proxy(monkeypatch):
    """#329: override НЕ в NO_PROXY (прокси для endpoint обязателен) → проба применяется.

    Обе ветки гейта достижимы (канон detector-must-be-function-not-constant): внешний ход
    при endpoint-вне-NO_PROXY — по-прежнему доказанная утечка → down.
    """
    monkeypatch.setattr(health.sys_probe, "run",
                        _ps_lsof_fake(f"12345 {CLI_COMM}\n", _EXTERNAL_LEAK_LINE,
                                      eww_out=f"12345 ttys000 0:01.00 {CLI_COMM} HTTPS_PROXY=http://127.0.0.1:8118\n"))
    monkeypatch.setattr(health, "_read_endpoint_config",
                        lambda: {"base_url": "https://api.z.ai/api/anthropic",
                                 "no_proxy": "localhost,127.0.0.1", "source": "shell"})
    res = health._claude_proxy_probe()
    assert res["status"] == "down", "override вне NO_PROXY → fail-closed применим, external = утечка"


def test_probe_unknown_when_external_pid_env_unreadable(monkeypatch):
    """#329 «Дополнительно»: external у PID с нечитаемым env (sandbox/чужой UID) → НЕ down.

    ps eww читает env только same-UID: HTTPS_PROXY к такому процессу неприменим/непроверяем,
    атрибуция нарушения невозможна → unknown с форензикой, не «нарушение fail-closed».
    """
    monkeypatch.setattr(health.sys_probe, "run",
                        _ps_lsof_fake(f"12345 {CLI_COMM}\n", _EXTERNAL_LEAK_LINE, eww_out=""))
    _std_endpoint(monkeypatch)
    res = health._claude_proxy_probe()
    assert res["status"] == "unknown", "env PID не читается → атрибуция невозможна, не down"
    assert "12345" in res["detail"], "PID остаётся в detail как форензика"
    assert "не читается" in res["detail"]


def test_probe_mixed_down_with_unverified_forensics(monkeypatch):
    """#329: mixed — читаемый leak драйвит down, нечитаемый external остаётся форензикой.

    Читаемый PID 102 (leak) не маскируется нечитаемым 103, и наоборот: 103 не участвует
    в атрибуции, но виден в detail.
    """
    lsof_out = (
        f"claude 101 axisrow 7u IPv4 ... TCP 127.0.0.1:51234->127.0.0.1:{health.PRIVOXY_PORT} (ESTABLISHED)\n"
        "claude 102 axisrow 7u IPv4 ... TCP 192.168.1.5:51235->160.79.104.10:443 (ESTABLISHED)\n"
        "claude 103 axisrow 7u IPv4 ... TCP 192.168.1.5:51236->160.79.104.11:443 (ESTABLISHED)\n"
    )
    monkeypatch.setattr(health.sys_probe, "run",
                        _ps_lsof_fake(f"101 {CLI_COMM}\n102 {CLI_COMM}\n103 {CLI_COMM}\n", lsof_out,
                                      eww_out=f"102 ttys000 0:01.00 {CLI_COMM} HTTPS_PROXY=http://127.0.0.1:8118\n"))
    _std_endpoint(monkeypatch)
    res = health._claude_proxy_probe()
    assert res["status"] == "down", "читаемый external (102) → mixed down"
    assert "102" in res["detail"]
    assert "103" in res["detail"], "нечитаемый PID остаётся форензикой в detail"
    assert "не читается" in res["detail"]


def test_check_all_no_false_verdict_when_endpoint_override(monkeypatch):
    """#329 интеграция: z.ai override + runtime external → вердикт ok, check не driver.

    Сквозной регресс на инцидент: до фикса check_all падал в degraded из-за ложного
    «нарушение fail-closed» (watchdog пушил ложные алерты #315-класса).
    """
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_claude_proxy_probe", _REAL_CLAUDE_PROXY_PROBE)
    monkeypatch.setattr(health.sys_probe, "run",
                        _ps_lsof_fake(f"12345 {CLI_COMM}\n", _EXTERNAL_LEAK_LINE))
    monkeypatch.setattr(health, "_read_endpoint_config", lambda: _ZAI_OVERRIDE_CFG)
    result = health.check_all()
    assert result["status"] == "ok", "endpoint в NO_PROXY → claude-proxy не driver → вердикт ok"
    cp = [c for c in result["checks"] if "claude" in c["name"].lower()][0]
    assert cp.get("info") is True, "unknown-check помечен info (не driver)"
    assert "неприменима" in cp["detail"]


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
    monkeypatch.setattr(health, "_tunnel_up", lambda: (False, "connection-failed", False, None))
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
    # #189 follow-up round 2: _codex_app_chromium_proxy_check — новый driver (system-proxy для
    # Chromium network-service ChatGPT.app), тоже дёргает ps/lsof — мокаем (иначе живой ChatGPT.app
    # с рабочим системным SOCKS5 → ok → any_ok=True → degraded вместо down).
    monkeypatch.setattr(health, "_codex_app_chromium_proxy_check",
                        lambda: {"status": "down", "source": "runtime", "detail": "down"})
    # #250: _codenv_job_check тоже driver (не info на ok) — на машине с реально загруженным и
    # здоровым codenv LaunchAgent даёт живой ok → any_ok=True → degraded вместо down. Мокаем для
    # machine-independence (канон unmocked-probe-is-both-slow-and-machine-dependent).
    monkeypatch.setattr(health, "_codenv_job_check",
                        lambda **kw: {"status": "down", "detail": "down"})
    # #205: _dns_up дёргает реальный getaddrinfo — мокаем (детерминизм; «всё мёртво» → DNS-down ok).
    _mock_dns(monkeypatch, resolves=False)

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
    monkeypatch.setattr(health, "_tunnel_up", lambda: (False, "connection-failed", False, None))
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
    monkeypatch.setattr(health, "_tunnel_up", lambda: (False, "connection-failed", False, None))
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
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200", False, None))
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
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200", False, None))
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


def test_vps_placeholder_detector_matches_canonical(monkeypatch):
    """REGRESSION-гвард #198 (post-review #196): health детектит TEST-NET-placeholder ТОЧНО как
    canonical local_state._is_testnet_placeholder (единый источник правды).

    PR #196 ввёл собственный inline-предикат `host.startswith(_TESTNET_203_PREFIX) and count('.')==3`
    без octet-валидации → drift с canonical на 203.0.113.300/abc/-1/пустом (cycle-review Codex+я
    high-confirmed). Канон loose-validator-recurring-leak: граница валидируется строгим первоисточником
    в одном месте, не «почти-regex» в N. Этот тест падает, пока health не делегирует canonical.

    #278: тест проверяет только placeholder-детектор (строковую логику), не реальную сетевую
    доступность non-placeholder хостов — мокаем sys_probe.port_open, иначе agree_not-хосты
    (198.51.100.7/192.0.2.1/1.2.3.4/203.0.113) уходят в реальный TCP-таймаут 3s × 4 = 12s.
    """
    import local_state
    _mock_vps_tcp(monkeypatch, reachable=False)
    # Включаем drift-кейсы: prefix+count==3, НО octet невалиден → canonical=False, health-дубликат=True.
    drift_cases = ["203.0.113.300", "203.0.113.abc", "203.0.113.-1", "203.0.113."]
    # Согласованные кейсы (оба детектора): валидный placeholder / не-prefix / hostname / None.
    agree_placeholder = ["203.0.113.0", "203.0.113.10", "203.0.113.255"]
    agree_not = ["198.51.100.7", "192.0.2.1", "1.2.3.4", "vps.example.com", "203.0.113", "203.0.113.7.5"]
    # Эмпирически сверяем health-вердикт (status=="warn") с canonical предикатом.
    for host in drift_cases:
        health_is_warn = health._upstream_vps_reachable({"endpoint_host": host, "port": 443})["status"] == "warn"
        canonical = local_state._is_testnet_placeholder(host)
        assert health_is_warn == canonical, (
            f"DRIFT host={host!r}: health warn={health_is_warn} vs canonical placeholder={canonical} "
            f"— health обязан делегировать local_state._is_testnet_placeholder (единый источник)")
    for host in agree_placeholder:
        assert health._upstream_vps_reachable({"endpoint_host": host, "port": 443})["status"] == "warn", \
            f"{host!r} — валидный TEST-NET placeholder, оба детектора warn"
    for host in agree_not:
        # Не-placeholder: НЕ должен давать warn (info если невалиден, иначе ok/down через probe).
        assert health._upstream_vps_reachable({"endpoint_host": host, "port": 443})["status"] != "warn", \
            f"{host!r} — НЕ TEST-NET placeholder, health не должен звать его warn"


def test_vps_unreachable_does_not_mask_down_into_degraded(monkeypatch):
    """REGRESSION-гвард #194: VPS-unreachable при «всё мертво» НЕ превращает down в degraded.

    Защита от будущей регрессии: если кто-то сделает VPS-чек driver-ok=True (или info) при
    unreachable — проверка упадёт. status обязан остаться down, VPS-чек — driver ok=False.
    """
    monkeypatch.setattr(health, "_port_up", lambda port: False)
    monkeypatch.setattr(health, "_tunnel_up", lambda: (False, "connection-failed", False, None))
    monkeypatch.setattr(health, "_claude_proxy_probe",
                        lambda: {"status": "down", "source": "runtime", "detail": "runtime"})
    monkeypatch.setattr(health, "_desktop_proxy_check", lambda: {"status": "down", "detail": "down"})
    monkeypatch.setattr(health, "_codex_proxy_probe",
                        lambda: {"status": "down", "source": "runtime", "detail": "runtime"})
    monkeypatch.setattr(health, "_codex_app_proxy_check",
                        lambda: {"status": "down", "source": "gui-env", "detail": "down"})
    _mock_active_node(monkeypatch, {"name": "vps-1", "endpoint_host": "198.51.100.7", "port": 443})
    _mock_vps_tcp(monkeypatch, reachable=False)
    # #205: VPS-driver гвард требует net["up"] and dns["up"] (gaierror ≠ VPS-смерть). Мокаем DNS-up,
    # чтобы VPS-unreachable остался driver ok=False (семантика: сеть+DNS есть, VPS точно мёртв).
    _mock_dns(monkeypatch, resolves=True)
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
    monkeypatch.setattr(health, "_network_interface_up", _REAL_NETWORK_INTERFACE_UP)  # #271: real fn
    monkeypatch.setattr(health, "_tunnel_up", lambda: (False, "connection-failed", False, None))
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
    monkeypatch.setattr(health, "_network_interface_up", _REAL_NETWORK_INTERFACE_UP)  # #271: real fn
    monkeypatch.setattr(health, "_tunnel_up", lambda: (False, "connection-failed", False, None))
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
    monkeypatch.setattr(health, "_network_interface_up", _REAL_NETWORK_INTERFACE_UP)  # #271: real fn
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200", False, None))
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
    monkeypatch.setattr(health, "_tunnel_up", lambda: (False, "connection-failed", False, None))
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

# ============================ #205: DNS-резолв (DNS сломан vs VPS мёртв) ============================
# Корень: _upstream_vps_reachable (#196) зовёт sys_probe.port_open → socket.create_connection,
# которая САМА резолвит hostname endpoint'а. Сломанный DNS (упал dnsmasq/resolver) → gaierror →
# port_open=False → ложно «VPS мёртв». _dns_up() = socket.getaddrinfo тестового домена (НЕ endpoint:
# Reality-IP резолв не проверит DNS-стек). Проверяется МЕЖДУ #203 (нет сети) и #196 (VPS): нет сети
# подавляет DNS (бессмысленно резолвить без сети), DNS подавляет VPS (gaierror ≠ VPS-смерть). Нет
# резолва → driver «DNS сломан», НЕ «VPS».
#
# Контракт _dns_up() -> {up: bool, detail}:
#   up=True   — getaddrinfo отдал адрес (DNS работает);
#   up=False  — gaierror/OSError/timeout — DNS не резолвит (проверь dnsmasq/resolver).
# Канон: verify-dont-guess (прямая причина — resolve-ошибка), probe-semantics-from-primary-source
# (getaddrinfo NXDOMAIN → socket.gaierror, подкласс OSError — подтверждено эмпирически).


def _mock_dns(monkeypatch, *, resolves):
    """Подменить health._resolve_host (обёртка socket.getaddrinfo) для детерминированного теста.

    resolves=True/False — имитация успешного резолва / gaierror. Мокаем обёртку (а не socket
    напрямую), чтобы тест не зависел от реального DNS dev-машины и был детерминирован (как
    _mock_vps_tcp подменяет sys_probe.port_open, а не socket.create_connection).
    """
    monkeypatch.setattr(health, "_resolve_host", lambda host: resolves)


def test_dns_up_when_resolve_ok(monkeypatch):
    """ДЫРА #205: getaddrinfo отдал адрес → up=True, detail объясняет «DNS резолвит»."""
    _mock_dns(monkeypatch, resolves=True)
    r = health._dns_up()
    assert r["up"] is True, "резолв успешен → DNS работает"
    assert "резолв" in r["detail"].lower(), "detail объясняет: DNS резолвит"


def test_dns_down_when_resolve_fail(monkeypatch):
    """ДЫРА #205 (КЛЮЧЕВОЙ): getaddrinfo gaierror → up=False, detail «DNS не резолвит» (НЕ «VPS»).

    Раньше сломанный DNS проваливался в _upstream_vps_reachable → port_open(gaierror)=False → ложно
    «VPS мёртв». Теперь _dns_up говорит «DNS не резолвит — проверь резолвер» — это совсем другая
    причина (перезапусти dnsmasq/resolver), не «VPS мёртв».
    """
    _mock_dns(monkeypatch, resolves=False)
    r = health._dns_up()
    assert r["up"] is False, "gaierror → DNS не резолвит"
    assert "VPS" not in r["detail"], "detail НЕ «VPS мёртв» — это DNS (другая причина)"
    assert "резолв" in r["detail"].lower() or "dns" in r["detail"].lower(), \
        "detail объясняет: DNS не резолвит"


def test_dns_fail_masks_vps_dead_in_check_all(monkeypatch):
    """ДЫРА #205 (КАСКАД): DNS не резолвит → driver «DNS», VPS-чек подавлен (info), НЕ «VPS мёртв».

    Сценарий эпика #201 ситуация 4: dnsmasq/resolver упал. Сеть есть (#203 ok), DNS сломан,
    туннель fail (endpoint не резолвится), VPS-probe (#196) даже если бы звался — unreachable
    (gaierror маскирует реальное состояние VPS). Без фикса VPS-down давал бы driver DOWN (ложный
    «VPS мёртв»). С фиксом: DNS-down = driver, VPS-чек = info (подавлен — нельзя обвинять VPS,
    когда резолв не работает). Канон: verify-dont-guess (gaierror ≠ VPS-смерть).
    """
    _all_up_monkey(monkeypatch)  # порты живы; claude/codex/app/desktop — info/ok
    monkeypatch.setattr(health, "_network_interface_up", _REAL_NETWORK_INTERFACE_UP)  # #271: real fn
    monkeypatch.setattr(health, "_tunnel_up", lambda: (False, "connection-failed", False, None))
    # сеть есть (route default → en0) — мок sys_probe.run, как #203-каскадные тесты.
    monkeypatch.setattr(health.sys_probe, "run", lambda cmd, timeout:
                        {"rc": 0, "out": _ROUTE_DEFAULT_UP, "err": "", "timeout": False}
                        if cmd[:3] == [ROUTE, "-n", "get"]
                        else {"rc": 0, "out": "", "err": "", "timeout": False})
    # DNS сломан
    _mock_dns(monkeypatch, resolves=False)
    # VPS-probe (#196) ДАЖЕ ЕСЛИ бы звался — unreachable; но он не должен давать driver «VPS мёртв».
    _mock_active_node(monkeypatch, {"name": "vps-1", "endpoint_host": "vps.example.com", "port": 443})
    _mock_vps_tcp(monkeypatch, reachable=False)
    result = health.check_all()
    dns = [c for c in result["checks"] if "DNS" in c["name"]][0]
    assert dns["ok"] is False, "DNS сломан — driver (ok=False)"
    assert not dns.get("info"), "DNS сломан — НЕ info (driver, точная причина)"
    assert "VPS" not in dns["detail"], "detail НЕ «VPS мёртв» — это DNS (другая причина)"
    # VPS-чек при сломанном DNS — info (подавлен, не нагромождает «VPS мёртв» поверх «DNS сломан»).
    vps = [c for c in result["checks"] if "vps" in c["name"].lower() and "upstream" in c["name"].lower()][0]
    assert vps.get("info") is True, "DNS сломан → VPS-чек подавлен (info), не водитель «VPS мёртв»"


def test_network_down_suppresses_dns_check_in_check_all(monkeypatch):
    """ДЫРА #205 (КАСКАД сверху): нет сети → DNS-чек подавлен (info), единственный driver «нет сети».

    Сценарий: Wi-Fi выкл (#203 net-down) И DNS тоже не резолвит (gaierror — без сети резолвер всё
    равно не ответит). Без гварда net["up"] оба чека стали бы driver — «нет сети» И «DNS сломан»,
    две причины вместо одной первичной. Каскад #203→#205: нет сети подавляет DNS (как подавляет
    VPS-чек), «нет сети» остаётся единственным driver. Канон: verify-dont-guess (первичная причина).
    """
    _all_up_monkey(monkeypatch)  # порты живы; _resolve_host замокан True, но ниже переопределим
    monkeypatch.setattr(health, "_network_interface_up", _REAL_NETWORK_INTERFACE_UP)  # #271: real fn
    monkeypatch.setattr(health, "_tunnel_up", lambda: (False, "connection-failed", False, None))
    # НЕТ сети: route rc!=0 + ifconfig только loopback (как test_network_down_* из #203)
    monkeypatch.setattr(health.sys_probe, "run", lambda cmd, timeout:
                        _ROUTE_DEFAULT_NONE if cmd[:3] == [ROUTE, "-n", "get"]
                        else {"rc": 0, "out": _IFCONFIG_LOOPBACK_ONLY, "err": "", "timeout": False}
                        if cmd[:1] == [IFCONFIG]
                        else {"rc": 0, "out": "", "err": "", "timeout": False})
    # DNS тоже не резолвит (без сети резолвер всё равно не ответит)
    _mock_dns(monkeypatch, resolves=False)
    _mock_active_node(monkeypatch, {"name": "vps-1", "endpoint_host": "vps.example.com", "port": 443})
    _mock_vps_tcp(monkeypatch, reachable=False)
    result = health.check_all()
    net = [c for c in result["checks"] if "сеть" in c["name"].lower() or "маршрут" in c["name"].lower()][0]
    assert net["ok"] is False and not net.get("info"), "нет сети — driver (первичная причина)"
    # DNS-чек при «нет сети» — info (подавлен): не нагромождаем «DNS сломан» поверх «нет сети».
    dns = [c for c in result["checks"] if "DNS" in c["name"]][0]
    assert dns.get("info") is True, "нет сети → DNS-чек подавлен (info), единственный driver «нет сети»"


def test_dns_ok_proceeds_to_vps_probe_in_check_all(monkeypatch):
    """ДЫРА #205: DNS работает → VPS-чек НЕ подавляется (proceeds to VPS-probe как обычно).

    Контр-гвард к тесту выше: когда DNS работает, _dns_up не должен маскировать реальную
    VPS-смерть. VPS-unreachable при живой сети + работающем DNS → по-прежнему driver DOWN (#196).
    """
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_network_interface_up", _REAL_NETWORK_INTERFACE_UP)  # #271: real fn
    monkeypatch.setattr(health, "_tunnel_up", lambda: (False, "connection-failed", False, None))
    monkeypatch.setattr(health.sys_probe, "run", lambda cmd, timeout:
                        {"rc": 0, "out": _ROUTE_DEFAULT_UP, "err": "", "timeout": False}
                        if cmd[:3] == [ROUTE, "-n", "get"]
                        else {"rc": 0, "out": "", "err": "", "timeout": False})
    _mock_dns(monkeypatch, resolves=True)
    _mock_active_node(monkeypatch, {"name": "vps-1", "endpoint_host": "198.51.100.7", "port": 443})
    _mock_vps_tcp(monkeypatch, reachable=False)
    result = health.check_all()
    vps = [c for c in result["checks"] if "vps" in c["name"].lower() and "upstream" in c["name"].lower()][0]
    assert vps["ok"] is False and not vps.get("info"), \
        "DNS ok + VPS unreachable → VPS-чек driver (не подавлен)"
    assert result["status"] == "down", "DNS ok + VPS мёртв → DOWN (#196 контракт сохранён)"


def test_dns_check_is_info_only_when_up(monkeypatch):
    """DNS-чек при up=True — info-only (не роняет вердикт, картина для диагностики).

    Когда DNS работает, нет причины подсвечивать его как driver. ok=True + info=True → не участвует
    в агрегации drivers (как net-up/endpoint-override/versions). Driver DNS-чек становится ТОЛЬКО
    при up=False.
    """
    _all_up_monkey(monkeypatch, probe_status="ok")
    monkeypatch.setattr(health, "_network_interface_up", _REAL_NETWORK_INTERFACE_UP)  # #271: real fn
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200", False, None))
    monkeypatch.setattr(health.sys_probe, "run", lambda cmd, timeout:
                        {"rc": 0, "out": _ROUTE_DEFAULT_UP, "err": "", "timeout": False}
                        if cmd[:3] == [ROUTE, "-n", "get"]
                        else {"rc": 0, "out": "", "err": "", "timeout": False})
    _mock_dns(monkeypatch, resolves=True)
    result = health.check_all()
    assert result["status"] == "ok", "всё живо → ok (DNS-чек не роняет)"
    dns = [c for c in result["checks"] if "DNS" in c["name"]][0]
    assert dns.get("info") is True, "DNS работает → info-only (не driver)"


# ============================ #206: GFW per-domain (github режется vs нет сети/VPS) ============================
# Корень: GFW избирателен — режет конкретные домены (github) по TLS-fingerprint, другие (z.ai) —
# пропускает. Doctor сваливал это в «туннель fail» / «VPS мёртв». _gfw_domain_check = ПРЯМОЙ curl к
# доменам (env -u, минуя прокси): timeout/reset/connection-failed = режется; HTTP < 500 = не режется
# (даже 404 = живой ответ сервера, канал до домена работает — та же семантика, что sys_probe.tunnel_code_up).
# Вердикт: github режется И z.ai ок → «github режется GFW». Оба режутся → НЕ GFW (нет сети/VPS —
# первичная причина уже выше в каскаде). z.ai — канонически НЕ GFW-target (zai-direct-no-proxy, moonbridge).
# Каскад #201: ...→сеть(#203)→DNS(#205)→VPS(#196)→прокси(#204)→GFW per-domain(этот). info-only ВСЕГДА
# (картина для конкретного домена, не сбой стека): режется → подсказка «нужен прокси/VPS для домена».
# Канон: verify-dont-guess (прямая причина — прямой curl минуя прокси), zai-direct-no-proxy (z.ai —
# эталон «не режется»), noisy-log-better-than-no-log (точная причина в detail).
#
# Контракт _direct_domain_probe(host) -> {"reachable": bool, "kind": str}: reachable=True если сервер
# ответил HTTP < 500 (канал до домена работает). kind: ok | timeout | connection-failed (для detail).
# Контракт _gfw_domain_check(domains) -> {status, detail}: status = gfw | ok | info.
#   gfw  — SOME домен режется (timeout/connection-failed) И контрольный (z.ai) не режется → «режется GFW»;
#   ok   — все домены reachable (ничто не режется);
#   info — контрольный z.ai тоже режется → НЕ GFW (нет сети/VPS), или нечем сравнить.

def _mock_domain_probe(monkeypatch, results):
    """Подменить health._direct_domain_probe (обёртка прямого curl env -u) для детерминированного теста.

    results: {host: {"reachable": bool, "kind": str}} — имитация ответа прямого curl per-домен.
    Мокаем обёртку (а не sys_probe.run напрямую), чтобы тест не зависел от реального GFW dev-машины
    и был детерминирован (как _mock_dns подменяет _resolve_host, а не socket.getaddrinfo).
    """
    def _fake(host):
        r = results.get(host)
        if r is None:
            return {"reachable": True, "kind": "ok"}  # неизвестный домен — по умолчанию reachable
        return dict(r)
    monkeypatch.setattr(health, "_direct_domain_probe", _fake)


def _mock_doctor_only_checks(monkeypatch):
    """Заглушить doctor-only чеки, запускающие реальные subprocess'ы (npm/brew/claude/dscl/ps eww).

    Предмет check_all-тестов GFW — wiring (чек присутствует/info-only), не эти тяжёлые пробы.
    Без моков active_claude-путь тормозит на реальных binary-сканированиях/transport-probe (как
    test_check_all_has_privoxy_log_check_info_only мокает их же). Канон: детерминизм тестов.

    GFW/direct-first (_gfw_domain_check/_direct_first_check) НЕ мокаются здесь — дефолтный мок
    для них живёт в _all_up_monkey (вызывается ПЕРЕД специфичными _mock_domain_probe/
    _mock_direct_first во всех тестах, а эта функция — ПОСЛЕ них; безусловный мок здесь затирал
    бы специфичный мок из-за late-binding monkeypatch.setattr, см. #252 регресс
    test_direct_first_check_info_when_some_blocked).
    """
    monkeypatch.setattr(health, "_installed_versions_check",
                        lambda: {"status": "ok", "detail": "mock", "codex": [], "claude_code": []})
    monkeypatch.setattr(health, "_claude_transport_probe",
                        lambda: {"status": "unknown", "detail": "mock"})
    monkeypatch.setattr(health, "_runtime_model_override_check",
                        lambda: {"status": "ok", "detail": "mock"})
    monkeypatch.setattr(health, "_privoxy_log_observability_check",
                        lambda **kw: {"status": "ok", "detail": "mock"})
    monkeypatch.setattr(health, "_codex_isolation_check",
                        lambda: {"status": "info", "detail": "mock"})


def test_direct_domain_probe_http_response_is_reachable(monkeypatch):
    """ДЫРА #206: прямой curl (env -u) к домену ответил HTTP < 500 → reachable (не режется).

    Даже 404 = живой ответ: канал до домена работает (та же семантика, что sys_probe.tunnel_code_up
    для туннеля — 4xx это ЖИВОЙ канал). GFW даёт timeout/reset/connection-failed, НЕ HTTP-ответ.
    """
    # curl отдал HTTP 404 → сервер ответил → reachable
    # _direct_domain_probe делегирует sys_probe.direct_probe(), который зовёт self.run на
    # _default_manager (bound method), а не module-level sys_probe.run — патч атрибута модуля
    # здесь не перехватывает вызов (issue #252 блокер: без мока тест держался на реальной сети).
    monkeypatch.setattr(sys_probe._default_manager, "run",
                        lambda cmd, timeout, env=None: {"rc": 0, "out": "404", "err": "", "timeout": False})
    r = health._direct_domain_probe("github.com")
    assert r["reachable"] is True, "HTTP 404 = сервер ответил → канал работает (не режется)"
    assert r["kind"] == "ok"


def test_direct_domain_probe_timeout_is_cut(monkeypatch):
    """ДЫРА #206: прямой curl timeout → НЕ reachable (режется / нет ответа)."""
    monkeypatch.setattr(sys_probe._default_manager, "run",
                        lambda cmd, timeout, env=None: {"rc": None, "out": "", "err": "", "timeout": True})
    r = health._direct_domain_probe("github.com")
    assert r["reachable"] is False, "timeout → домен не отвечает напрямую"
    assert "timeout" in r["kind"], "kind маркирует timeout"


def test_direct_domain_probe_connection_failed_is_cut(monkeypatch):
    """ДЫРА #206: прямой curl 000 (connection-failed/reset) → НЕ reachable (режется)."""
    monkeypatch.setattr(sys_probe._default_manager, "run",
                        lambda cmd, timeout, env=None: {"rc": 0, "out": "000", "err": "", "timeout": False})
    r = health._direct_domain_probe("github.com")
    assert r["reachable"] is False, "000 = соединение не установлено → режется/сброшено"
    assert r["kind"] == "connection-failed"


def test_direct_domain_probe_5xx_reachable_but_upstream_error(monkeypatch):
    """ДЫРА #206 (cycle-review): прямой curl HTTP 5xx → reachable=True (домен ответил, GFW НЕ режет),
    но kind="upstream-error" (НЕ "ok").

    GFW даёт timeout/reset, НЕ HTTP-ответ → 5xx доказывает достижимость (не GFW-блокировка). НО 5xx —
    не «ok»: сервер ответил, но сам лежит (vendor down). Канон sys_probe.tunnel_code_up (5xx = мёртвый
    канал) + #207 паттерн (_tunnel_target_up отдаёт kind="upstream-error" для 5xx, не "ok").
    cycle-review score 85: docstring говорит «reachable = HTTP < 500», но код возвращал kind="ok" для
    5xx — противоречие. reachable=True сохраняется (домен достижим для GFW-вердикта), kind разделяет.
    """
    monkeypatch.setattr(sys_probe._default_manager, "run",
                        lambda cmd, timeout, env=None: {"rc": 0, "out": "503", "err": "", "timeout": False})
    r = health._direct_domain_probe("github.com")
    assert r["reachable"] is True, "5xx = сервер ответил → домен достижим (GFW НЕ режет)"
    assert r["kind"] == "upstream-error", "5xx ≠ ok: kind=upstream-error (как #207 _tunnel_target_up)"


def test_direct_domain_probe_strips_proxy_env(monkeypatch):
    """ДЫРА #206 (канон zai-direct-no-proxy): прямой curl идёт МИНУЯ прокси (env -u).

    Регресс-гвард: probe БЕЗ прокси доказывает реальную достижимость домена. Если прокси-env
    останется, github пойдёт через privoxy/xray → VPS, и «режется GFW» станет «VPS мёртв» (та же
    подмена, что #199 git-proxy маскировал). Мок ловит env-аргумент sys_probe.run.

    _direct_domain_probe делегирует sys_probe.direct_probe(), который зовёт self.run на
    _default_manager (bound method) — патч module-level sys_probe.run не перехватывает (issue #252
    блокер: тест держался на реальной сети вместо мока).
    """
    captured = {}

    def _fake_run(cmd, timeout, env=None):
        captured["env"] = env
        return {"rc": 0, "out": "404", "err": "", "timeout": False}
    monkeypatch.setattr(sys_probe._default_manager, "run", _fake_run)
    monkeypatch.setattr(os, "environ", {"HTTPS_PROXY": "http://127.0.0.1:8118",
                                        "HTTP_PROXY": "http://127.0.0.1:8118",
                                        "ALL_PROXY": "http://127.0.0.1:8118",
                                        "NO_PROXY": "localhost"})
    health._direct_domain_probe("github.com")
    env = captured.get("env") or {}
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
        assert key not in env, f"прямой curl минует прокси: {key} не должен попасть в env"


def test_gfw_check_github_cut_zai_ok_is_gfw(monkeypatch):
    """ДЫРА #206 (КЛЮЧЕВОЙ): github timeout + z.ai ok → «github режется GFW».

    Сценарий эпика #201 ситуация 5: GFW режет github (TLS-fingerprint), z.ai пропускает (zai-direct-
    no-proxy — moonbridge ходит напрямую). Прямой curl: github timeout, z.ai отвечает. Вердикт gfw.
    """
    _mock_domain_probe(monkeypatch, {
        "github.com": {"reachable": False, "kind": "timeout"},
        "api.z.ai": {"reachable": True, "kind": "ok"},
    })
    r = health._gfw_domain_check()
    assert r["status"] == "gfw", "github режется + z.ai ок → GFW избирательно режет github"
    assert "github" in r["detail"].lower(), "detail называет режущийся домен"
    assert "GFW" in r["detail"] or "режется" in r["detail"].lower(), "detail объясняет: GFW режется"


def test_gfw_check_all_ok_is_not_gfw(monkeypatch):
    """ДЫРА #206: github ok + z.ai ok → не GFW (ничто не режется).

    Нормальная сеть без GFW-блокировки: оба домена отвечают напрямую → ok.
    """
    _mock_domain_probe(monkeypatch, {
        "github.com": {"reachable": True, "kind": "ok"},
        "api.z.ai": {"reachable": True, "kind": "ok"},
    })
    r = health._gfw_domain_check()
    assert r["status"] != "gfw", "оба домена reachable → НЕ GFW"


def test_gfw_check_both_cut_is_not_gfw(monkeypatch):
    """ДЫРА #206: github timeout + z.ai timeout → НЕ GFW (нет сети / VPS).

    GFW избирателен. Если ОБА домена режутся (включая контрольный z.ai — канонически не GFW-target),
    это НЕ GFW-блокировка, а более общая причина (нет сети/VPS/нет маршрута), которая уже ловится
    выше в каскаде (#203 сеть, #196 VPS). GFW-вердикт требует, чтобы контрольный домен был reachable.
    """
    _mock_domain_probe(monkeypatch, {
        "github.com": {"reachable": False, "kind": "timeout"},
        "api.z.ai": {"reachable": False, "kind": "timeout"},
    })
    r = health._gfw_domain_check()
    assert r["status"] != "gfw", "оба режутся (включая z.ai) → НЕ GFW (нет сети/VPS, не избирательно)"


def test_gfw_check_info_only_in_check_all(monkeypatch):
    """ДЫРА #206 (КАСКАД): GFW-чек в check_all — info-only ВСЕГДА (картина, не driver).

    Даже когда github режется GFW, это не роняет вердикт стека: прокси/VPS могут работать для других
    доменов. GFW — scoped-диагностика конкретного домена (как endpoint-override/_github_direct_check),
    подсказка «нужен прокси/VPS для github», не сбой стека. Канон: verify-dont-guess (точная причина
    в detail), не driver (избегаем шума — github может не быть нужен пользователю прямо сейчас).
    """
    _all_up_monkey(monkeypatch, probe_status="ok")
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200", False, None))
    _mock_domain_probe(monkeypatch, {
        "github.com": {"reachable": False, "kind": "timeout"},
        "api.z.ai": {"reachable": True, "kind": "ok"},
    })
    # doctor-only чеки, запускающие реальные subprocess'ы (npm/brew/claude/dscl) — мокаем (предмет
    # теста — GFW-wiring, не они; как test_check_all_has_privoxy_log_check_info_only).
    _mock_doctor_only_checks(monkeypatch)
    # GFW-чек — doctor-only (active_claude): _direct_domain_probe делает прямой curl к github/z.ai
    # = сетевой overhead/поверхность, не для лёгкого /health/watchdog (как _codex_isolation_check).
    result = health.check_all(active_claude=True)
    gfw = next((c for c in result["checks"] if "GFW" in c["name"] or "gfw" in c["name"].lower()), None)
    assert gfw is not None, "check_all(active_claude=True) содержит GFW per-domain check"
    assert gfw.get("info") is True, "GFW-чек info-only (не driver — картина для конкретного домена)"
    drivers = [c for c in result["checks"] if not c.get("info")]
    assert gfw not in drivers, "info-only GFW исключён из drivers (не роняет вердикт)"


def test_gfw_check_absent_in_light_health(monkeypatch):
    """ДЫРА #206 (регресс-гвард): лёгкий check_all() (без active_claude) НЕ делает GFW-чек.

    /health (dashboard) и watchdog (раз в ~20с) — лёгкие. Прямой curl к github/z.ai = сетевой
    overhead + DoS-поверхность (как _installed_versions_check/_codex_isolation_check под gate).
    GFW-пер-домен — ТОЛЬКО doctor-путь (active_claude=True). Канон: gate-is-for-arbitrary-p... /
    srouter-critical-infra-24-7 (лёгкий healthcheck не тормозит на внешних curl).
    """
    _all_up_monkey(monkeypatch, probe_status="ok")
    _mock_domain_probe(monkeypatch, {
        "github.com": {"reachable": False, "kind": "timeout"},
        "api.z.ai": {"reachable": True, "kind": "ok"},
    })
    result = health.check_all()  # БЕЗ active_claude — лёгкий путь
    names = " ".join(c["name"] for c in result["checks"])
    assert "GFW per-domain" not in names, \
        f"лёгкий путь НЕ должен нести GFW-чек (overhead/поверхность); checks={names}"


def test_print_report_gfw_cut_advises_proxy_for_domain(monkeypatch, capsys):
    """ДЫРА #206: doctor _print_report при GFW-выборе говорит «нужен прокси/VPS для github».

    Регресс-гвард: ранее github timeout валился в «проверь узел/VPS». При GFW-блокировке узел/VPS
    НЕ виноваты — github режется избирательно, нужен прокси именно для github. Канон:
    verify-dont-guess (точная причина), noisy-log-better-than-no-log (подсказка в отчёте).
    """
    _all_up_monkey(monkeypatch, probe_status="ok")
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200", False, None))
    _mock_domain_probe(monkeypatch, {
        "github.com": {"reachable": False, "kind": "timeout"},
        "api.z.ai": {"reachable": True, "kind": "ok"},
    })
    _mock_doctor_only_checks(monkeypatch)
    result = health.check_all(active_claude=True)
    health._print_report(result)
    out = capsys.readouterr().out
    assert "GFW" in out, f"отчёт должен назвать GFW-блокировку, got:\n{out}"
    assert "github" in out.lower(), f"отчёт должен назвать режущийся домен (github), got:\n{out}"


# ============================ #197: direct-first check в check_all (info-only, gate под active_claude) ============================
def _mock_direct_first(monkeypatch, *, reachable=None, blocked=None, raises=False):
    """Подменить health._direct_first_check для детерминированного теста."""
    if raises:
        def _fake():
            raise RuntimeError("direct_first import boom")
        monkeypatch.setattr(health, "_direct_first_check", lambda: {"status": "unknown",
                             "detail": "direct-first detect недоступен — check пропущен"})
        return
    reachable = reachable or []
    blocked = blocked or []
    if reachable and not blocked:
        status, detail = "ok", f"direct-first: {', '.join(reachable)} → напрямую (NO_PROXY)"
    elif reachable:
        status, detail = "info", f"direct: {', '.join(reachable)}; через прокси: {', '.join(blocked)}"
    else:
        status, detail = "info", f"direct-first: все candidate через прокси ({', '.join(blocked)})"
    monkeypatch.setattr(health, "_direct_first_check", lambda: {"status": status, "detail": detail})


def test_direct_first_check_info_only_in_check_all(monkeypatch):
    """#197: direct-first чек в check_all — info-only ВСЕГДА (картина, не driver).

    Даже когда часть candidate-доменов идёт через прокси, это не роняет вердикт стека — direct-first
    это resilience-оптимизация (переживает смерть VPS для direct-доменов), не health-инвариант.
    """
    _all_up_monkey(monkeypatch, probe_status="ok")
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200", False, None))
    _mock_direct_first(monkeypatch, reachable=["z.ai"], blocked=[])
    _mock_doctor_only_checks(monkeypatch)
    result = health.check_all(active_claude=True)
    df = next((c for c in result["checks"] if "direct-first" in c["name"].lower()), None)
    assert df is not None, "check_all(active_claude=True) содержит direct-first check"
    assert df.get("info") is True, "direct-first чек info-only (не driver)"
    drivers = [c for c in result["checks"] if not c.get("info")]
    assert df not in drivers, "info-only direct-first исключён из drivers (не роняет вердикт)"


def test_direct_first_check_absent_in_light_health(monkeypatch):
    """Регресс-гвард: лёгкий check_all() (без active_claude) НЕ делает direct-first чек.

    /health (dashboard) и watchdog — лёгкие. direct_first.detect() делает прямой curl per-domain =
    сетевой overhead, не для лёгкого пути (тот же паттерн, что GFW per-domain #206).
    """
    _all_up_monkey(monkeypatch, probe_status="ok")
    _mock_direct_first(monkeypatch, reachable=["z.ai"], blocked=[])
    result = health.check_all()  # БЕЗ active_claude — лёгкий путь
    names = " ".join(c["name"] for c in result["checks"])
    assert "direct-first" not in names.lower(), \
        f"лёгкий путь НЕ должен нести direct-first чек (overhead); checks={names}"


def test_direct_first_check_ok_when_all_reachable(monkeypatch):
    _all_up_monkey(monkeypatch, probe_status="ok")
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200", False, None))
    _mock_direct_first(monkeypatch, reachable=["z.ai"], blocked=[])
    _mock_doctor_only_checks(monkeypatch)
    result = health.check_all(active_claude=True)
    df = next(c for c in result["checks"] if "direct-first" in c["name"].lower())
    assert df["ok"] is True


def test_direct_first_check_info_when_some_blocked(monkeypatch):
    _all_up_monkey(monkeypatch, probe_status="ok")
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200", False, None))
    _mock_direct_first(monkeypatch, reachable=["z.ai"], blocked=["cut.example.com"])
    _mock_doctor_only_checks(monkeypatch)
    result = health.check_all(active_claude=True)
    df = next(c for c in result["checks"] if "direct-first" in c["name"].lower())
    assert df["ok"] is False  # status != ok, но всё равно info-only (не driver — проверено выше)
    assert df.get("info") is True


def test_direct_first_check_wraps_exceptions_as_unknown(monkeypatch):
    """direct_first.detect() бросил → _direct_first_check не падает, статус unknown (не мок чека
    самого себя — проверяем реальный try/except внутри _direct_first_check, канон probe-контракта:
    не бросает наружу)."""
    import direct_first as direct_first_mod

    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(direct_first_mod, "detect", boom)
    r = health._direct_first_check()
    assert r["status"] == "unknown"
    assert "недоступен" in r["detail"]


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
    ok, detail, _, _ = health._tunnel_up()
    assert ok is False, f"5xx = мёртвый upstream за туннелем, а не 'жив', detail={detail}"
    assert "503" in detail


def test_tunnel_up_502_is_down(monkeypatch):
    """502 Bad Gateway (типовой ответ сбойного прокси/upstream) → down."""
    monkeypatch.setattr(health.sys_probe, "run", _tunnel_curl_returning("502"))
    ok, _, _, _ = health._tunnel_up()
    assert ok is False


def test_tunnel_up_404_is_up(monkeypatch):
    """404 (реальный ответ api.anthropic.com/ на '/') = канал жив: сервер ответил через туннель.
    Легит-случай, не ломаем: watchdog не должен ложно паниковать на 404."""
    monkeypatch.setattr(health.sys_probe, "run", _tunnel_curl_returning("404"))
    ok, detail, _, _ = health._tunnel_up()
    assert ok is True, f"404 от живого сервера = туннель жив, detail={detail}"
    assert "404" in detail


def test_tunnel_up_200_is_up(monkeypatch):
    """200 — очевидно жив (не ломаем)."""
    monkeypatch.setattr(health.sys_probe, "run", _tunnel_curl_returning("200"))
    ok, _, _, _ = health._tunnel_up()
    assert ok is True


def test_tunnel_up_000_is_down(monkeypatch):
    """000 на всех таргетах — соединения нет (не ломаем существующее)."""
    monkeypatch.setattr(health.sys_probe, "run", _tunnel_curl_returning("000"))
    ok, detail, _, _ = health._tunnel_up()
    assert ok is False
    assert "connection-failed" in detail


def test_tunnel_up_timeout_is_down(monkeypatch):
    """timeout на всех таргетах → down (не ломаем)."""
    monkeypatch.setattr(health.sys_probe, "run",
                        lambda cmd, timeout: {"rc": None, "out": "", "err": "timeout", "timeout": True})
    ok, detail, _, _ = health._tunnel_up()
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
    ok, detail, _, _ = health._tunnel_up()
    assert ok is True, f"origin-503 одного вендора при живом втором = туннель жив, detail={detail}"


def test_tunnel_up_origin_5xx_other_vendor_stays_up(monkeypatch):
    """Симметрично: OpenAI 500, Anthropic 200 → жив (второй таргет спасает)."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _tunnel_curl_per_target({"anthropic": "200", "openai": "500"}))
    ok, _, _, _ = health._tunnel_up()
    assert ok is True


def test_tunnel_up_both_5xx_is_down(monkeypatch):
    """Оба таргета 5xx → down: это уже не origin одного вендора, а сбой прокси/туннеля."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _tunnel_curl_per_target({"anthropic": "503", "openai": "502"}))
    ok, detail, _, _ = health._tunnel_up()
    assert ok is False, f"оба 5xx = сбой канала, не origin, detail={detail}"


def test_tunnel_up_both_000_is_down(monkeypatch):
    """Оба таргета 000 (нет соединения ни к кому) → down."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _tunnel_curl_per_target({"anthropic": "000", "openai": "000"}))
    ok, detail, _, _ = health._tunnel_up()
    assert ok is False


def test_tunnel_up_first_target_down_second_up(monkeypatch):
    """Первый таргет не отвечает (000), второй жив (200) → туннель жив (фолбэк работает)."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _tunnel_curl_per_target({"anthropic": "000", "openai": "200"}))
    ok, _, _, _ = health._tunnel_up()
    assert ok is True


# ============================ #207: vendor outage ============================
# Оба таргета HTTP 5xx = канал жив, оба вендора лежат.
# TCP-fail/timeout = сеть/VPS, не vendor.


def test_tunnel_up_both_5xx_vendor_outage_detail(monkeypatch):
    """Оба таргета 5xx -> down, detail vendor outage (не VPS)."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _tunnel_curl_per_target({"anthropic": "503", "openai": "502"}))
    ok, detail, _, _ = health._tunnel_up()
    assert ok is False
    assert health.VENDOR_OUTAGE_MARKER in detail, f"got: {detail}"


def test_tunnel_up_one_5xx_other_ok_no_vendor_outage(monkeypatch):
    """Один 5xx + другой ok = up, не vendor outage."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _tunnel_curl_per_target({"anthropic": "503", "openai": "200"}))
    ok, detail, _, _ = health._tunnel_up()
    assert ok is True
    assert health.VENDOR_OUTAGE_MARKER not in detail


def test_tunnel_up_tcp_fail_not_vendor_outage(monkeypatch):
    """Оба 000 (TCP-fail) = down, НЕ vendor outage."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _tunnel_curl_per_target({"anthropic": "000", "openai": "000"}))
    ok, detail, _, _ = health._tunnel_up()
    assert ok is False
    assert health.VENDOR_OUTAGE_MARKER not in detail
    assert "connection-failed" in detail


def test_tunnel_up_timeout_not_vendor_outage(monkeypatch):
    """Оба timeout = down, НЕ vendor outage."""
    monkeypatch.setattr(health.sys_probe, "run",
        lambda cmd, timeout: {"rc": None, "out": "", "err": "", "timeout": True})
    ok, detail, _, _ = health._tunnel_up()
    assert ok is False
    assert health.VENDOR_OUTAGE_MARKER not in detail


def test_tunnel_up_mixed_5xx_and_tcp_not_vendor_outage(monkeypatch):
    """Один 5xx + один TCP-fail = down, НЕ vendor outage."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _tunnel_curl_per_target({"anthropic": "503", "openai": "000"}))
    ok, detail, _, _ = health._tunnel_up()
    assert ok is False
    assert health.VENDOR_OUTAGE_MARKER not in detail



# --- #207 check_all cascade: vendor outage distinguishes от «VPS мёртв» ---
# Каскад: ...→сеть(#203)→VPS(#196)→туннель→vendor outage(#207, HTTP-level).
# При vendor outage: сеть жива, VPS жив (TCP-коннект проходит), local-proxy жив,
# но туннель 5xx на обоих таргетах. Tunnel-check detail = «vendor outage»,
# VPS/local-proxy НЕ driver (они живы). Канон: verify-dont-guess, noisy-log-better-than-no-log.

def _vendor_outage_check_all(monkeypatch, codes=("503", "502")):
    """Общая setup для #207 vendor-outage тестов: живые порты/CC/codex + оба вендора 5xx +
    сеть/VPS/local-proxy живы → возвращаем check_all() result (туннель = vendor outage).

    codes — HTTP-коды двух вендоров (попадают в detail). Мокаем _tunnel_up целиком (как
    _all_up_monkey для живого туннеля) — return-контракт #207 (ok, detail, is_vendor_outage).
    """
    _all_up_monkey(monkeypatch, probe_status="ok")
    joined = "; ".join(f"upstream-error HTTP {code}" for code in codes)
    detail = f"{health.VENDOR_OUTAGE_MARKER} — оба вендора лежат, канал жив ({joined})"
    monkeypatch.setattr(health, "_tunnel_up", lambda: (False, detail, True, None))
    monkeypatch.setattr(health, "_route_default_interface", lambda: "en0")
    _mock_active_node(monkeypatch, {"name": "vps-1", "endpoint_host": "198.51.100.7", "port": 443})
    _mock_vps_tcp(monkeypatch, reachable=True)
    return health.check_all()


def test_check_all_vendor_outage_distinguishes_from_vps_dead(monkeypatch):
    """Оба vendor 5xx + VPS жив + сеть жива → tunnel-check «vendor outage», VPS не driver.

    Регресс-гвард #207: при vendor outage doctor НЕ должен врать «VPS мёртв» (VPS-чек info,
    жив) — tunnel-check драйвит down с точной причиной «vendor outage».
    """
    result = _vendor_outage_check_all(monkeypatch)
    tun = [c for c in result["checks"] if "туннель" in c["name"]][0]
    assert tun["ok"] is False, "оба vendor 5xx → tunnel down"
    assert health.VENDOR_OUTAGE_MARKER in tun["detail"], f"detail должен сказать vendor outage, got: {tun['detail']}"
    assert tun.get("category") == "vendor-outage", "vendor outage помечен структурно в category"
    # VPS жив → info-only (НЕ driver). При vendor outage VPS НЕ мёртв — канал проходит до вендора.
    vps = [c for c in result["checks"] if "vps" in c["name"].lower() and "upstream" in c["name"].lower()][0]
    assert vps.get("info") is True, "VPS жив при vendor outage → info (не driver «VPS мёртв»)"
    assert vps["ok"] is True


def test_check_all_vendor_outage_detail_surfaces_in_report(monkeypatch):
    """Vendor outage: detail чётко говорит «оба вендора лежат, канал жив» (noisy-log)."""
    result = _vendor_outage_check_all(monkeypatch, codes=("500", "503"))
    tun = [c for c in result["checks"] if "туннель" in c["name"]][0]
    assert "канал жив" in tun["detail"], f"detail должен подчеркнуть что канал жив, got: {tun['detail']}"
    assert "503" in tun["detail"] or "500" in tun["detail"], "detail должен содержать HTTP-коды вендоров"


def test_print_report_vendor_outage_says_likely_vendor(monkeypatch, capsys):
    """#207: doctor _print_report при vendor outage говорит «вероятно вендор» (не ваша инфра).

    Регресс-гвард: ранее при любом туннель-fail doctor советовал «проверь узел». При vendor
    outage узел/VPS/прокси ЖИВЫ — совет чинить узел вводит в заблуждение. Канон:
    verify-dont-guess (формулировка «вероятно», не категорично), noisy-log-better-than-no-log.
    """
    result = _vendor_outage_check_all(monkeypatch)
    health._print_report(result)
    out = capsys.readouterr().out
    assert health.VENDOR_OUTAGE_MARKER in out, f"отчёт должен назвать vendor outage, got:\n{out}"
    assert "вероятно" in out.lower(), f"должен сказать «вероятно вендор» (не категорично), got:\n{out}"
    assert "не ваша инфраструктура" in out.lower(), f"должен сказать что проблема не у пользователя, got:\n{out}"
    # НЕ должен советовать «проверь узел» (узел жив при vendor outage).
    assert "проверь узел" not in out, f"не должен вести чинить узел при vendor outage, got:\n{out}"


def test_print_report_tunnel_fail_no_vendor_outage_advises_node(monkeypatch, capsys):
    """#207 negative: реальный туннель-fail (connection-failed, НЕ 5xx) → совет «проверь узел».

    Регресс-гвард: vendor outage-ветка не должна маскировать настоящий туннель-fail.
    """
    _all_up_monkey(monkeypatch, probe_status="ok")
    monkeypatch.setattr(health, "_tunnel_up", lambda: (False, "connection-failed", False, None))
    monkeypatch.setattr(health, "_route_default_interface", lambda: "en0")
    _mock_active_node(monkeypatch, {"name": "vps-1", "endpoint_host": "198.51.100.7", "port": 443})
    _mock_vps_tcp(monkeypatch, reachable=False)
    result = health.check_all()
    health._print_report(result)
    out = capsys.readouterr().out
    assert "проверь узел" in out, f"туннель-fail (не vendor) → совет проверить узел, got:\n{out}"
    assert health.VENDOR_OUTAGE_MARKER not in out


# ==================== рендер _print_report: info ⊥ ok (две независимые оси) ====================
# ДЫРА: `mark = "⚠️" if c.get("info") else (...)` читал info РАНЬШЕ ok → для info-чека ok не
# читался никогда. Но info означает «не участвует в агрегации вердикта» (drivers), а НЕ «есть о
# чём предупредить». Оси ортогональны; рендер склеил их и потерял ok → 12 успешных проверок
# (DNS резолвит, сеть активна, VPS доступен...) рисовались жёлтым, и в этом шуме тонули
# реальные ❌. PR #262 обошёл это точечно для codenv, деформировав семантику одного чека
# вместо одной строки рендера. Канон: fix-once-document-decisions.
_MARK_OK, _MARK_WARN, _MARK_FAIL = "✅", "⚠️", "❌"



def test_print_report_healthy_info_check_renders_ok_not_warning(capsys):
    """info + ok=True → ✅, НЕ ⚠️ (главный кейс: «DNS резолвит» помечался предупреждением)."""
    health._print_report({"status": "ok", "checks": [
        {"name": "DNS (резолв тестового домена)", "ok": True, "info": True,
         "detail": "DNS резолвит: github.com (резолвер работает)"},
    ]})
    out = capsys.readouterr().out
    assert _MARK_OK in out, f"здоровый info-чек = ✅ (info ≠ предупреждение), got:\n{out}"
    assert _MARK_WARN not in out, \
        f"успешная проверка НЕ может быть ⚠️ — info это «не driver», а не «сломано», got:\n{out}"


def test_print_report_info_check_not_ok_stays_warning(capsys):
    """info + ok=False → ⚠️ сохраняется (намеренный tradeoff #189 / PF-lease «по выбору»).

    Гвард от переусердствования: чиня жёлтое-на-здоровом, нельзя убить жёлтое-на-больном.
    """
    health._print_report({"status": "degraded", "checks": [
        {"name": "desktop proxy (launchctl)", "ok": False, "info": True,
         "detail": "SOCKS5 в launchctl = srouter codenv (#189) — намеренный tradeoff"},
    ]})
    out = capsys.readouterr().out
    assert _MARK_WARN in out, f"не-driver требует внимания = ⚠️, got:\n{out}"
    assert _MARK_FAIL not in out, f"info-чек НЕ ❌ (не роняет вердикт), got:\n{out}"


def test_print_report_driver_marks_unchanged(capsys):
    """driver-чеки (без info) не затронуты: ok→✅, fail→❌."""
    health._print_report({"status": "degraded", "checks": [
        {"name": "privoxy (8118)", "ok": True, "detail": ""},
        {"name": "codex-proxy (маршрут TUI)", "ok": False, "detail": "идёт напрямую"},
    ]})
    out = capsys.readouterr().out
    privoxy_line = next(ln for ln in out.splitlines() if "privoxy" in ln)
    codex_line = next(ln for ln in out.splitlines() if "codex-proxy" in ln)
    assert _MARK_OK in privoxy_line, f"driver ok = ✅, got: {privoxy_line}"
    assert _MARK_FAIL in codex_line, f"driver fail = ❌, got: {codex_line}"
    assert _MARK_WARN not in out, f"driver-чеки не жёлтые, got:\n{out}"


def test_print_report_healthy_stack_has_no_warning_noise(capsys):
    """Интеграция: здоровый стек не даёт ⚠️-шума, реальный ❌ видно сразу.

    Ровно тот отчёт, с которым пришёл пользователь: 16 жёлтых строк при 2 настоящих сбоях.
    """
    healthy_info = [
        {"name": n, "ok": True, "info": True, "detail": d} for n, d in (
            ("сеть (default route / активный интерфейс)", "сеть активна: default route через ppp0"),
            ("DNS (резолв тестового домена)", "DNS резолвит: github.com"),
            ("upstream VPS (TCP-коннект до endpoint)", "endpoint placeholder TEST-NET"),
            ("локальный прокси (privoxy/xray service-status)", "локальный прокси жив"),
            ("gh/git direct (github env -u)", "github идёт напрямую"),
        )
    ]
    checks = ([{"name": "privoxy (8118)", "ok": True, "detail": ""}] + healthy_info
              + [{"name": "codex-proxy (маршрут TUI)", "ok": False, "detail": "напрямую"}])
    health._print_report({"status": "degraded", "checks": checks})
    out = capsys.readouterr().out
    assert out.count(_MARK_WARN) == 0, \
        f"здоровые info-чеки не шумят жёлтым (было 16 таких строк), got:\n{out}"
    assert out.count(_MARK_FAIL) == 1, f"единственный реальный сбой виден, got:\n{out}"
    assert out.count(_MARK_OK) == 6, f"5 info-ok + 1 driver-ok = ✅, got:\n{out}"



# ===== ok ≠ «не смогли проверить»: третья ось, склеенная в ok у производителей (cycle-review PR #296) =====
# ДЫРА (Codex P2): рендер стал читать ok ПЕРВЫМ — корректно. Но два производителя ставили ok=True
# не в значении «прошло», а в значении «не роняй вердикт»: codenv unknown («launchctl недоступен»)
# и endpoint-override (докстринг _endpoint_override_check: «Иначе → info (WARN)», а check_all
# хардкодил ok=True). Раньше их скрывала info-ветка рендера; после фикса рендера они рисуются ✅ —
# «состояние не определено» и «нестандартный endpoint в обход туннеля» выдаются за подтверждённое
# здоровье. Это fail-open (verify-dont-guess), и чинить его надо У ИСТОЧНИКА: ok обязан значить
# «проверено и прошло», иначе рендер снова придётся деформировать под потребителя (fix-once).


def _check_by_name(result, needle):
    """Единственный чек, чьё имя содержит needle (падает громко, если ноль/несколько)."""
    hits = [c for c in result["checks"] if needle.lower() in c["name"].lower()]
    assert len(hits) == 1, f"ожидался ровно один чек с {needle!r}, got: {[c['name'] for c in hits]}"
    return hits[0]


def test_codenv_unknown_is_not_ok_in_check_all(monkeypatch):
    """codenv unknown («launchctl недоступен») → ok=False + info=True, НЕ ok=True.

    info говорит «не driver» (вердикт не роняем), ok=False — «здоровье НЕ подтверждено».
    Комментарий check_all обещает ровно это: «не притворяется подтверждённо здоровым».
    """
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_codenv_job_check", lambda *a, **kw: {
        "status": "unknown", "detail": "состояние не определено (launchctl print недоступен/таймаут)"})
    cj = _check_by_name(health.check_all(), "codenv")
    assert cj.get("info") is True, f"unknown не роняет вердикт (info), got: {cj}"
    assert cj["ok"] is False, f"«не смогли проверить» ≠ ok — иначе рендер даст ✅, got: {cj}"


def test_codenv_ok_stays_ok_in_check_all(monkeypatch):
    """Гвард от переусердствования: ДОКАЗАННО здоровый codenv остаётся ok=True без info."""
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_codenv_job_check", lambda *a, **kw: {
        "status": "ok", "detail": "codenv LaunchAgent загружен и здоров (last exit code = 0)"})
    cj = _check_by_name(health.check_all(), "codenv")
    assert cj["ok"] is True and not cj.get("info"), f"здоровый codenv = driver-✅, got: {cj}"


def test_endpoint_override_is_not_ok_in_check_all(monkeypatch):
    """Нестандартный endpoint (status=info=WARN) → ok=False + info=True, НЕ захардкоженный ok=True.

    #129: CC уходит мимо туннеля на чужой endpoint. Это ровно то, о чём doctor обязан
    предупредить — ✅ здесь скрывает утечку trust boundary за «здоровьем».
    """
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_read_endpoint_config", lambda: {
        "base_url": "https://api.z.ai/api/anthropic", "no_proxy": "", "source": "settings.json"})
    eo = _check_by_name(health.check_all(), "ANTHROPIC_BASE_URL")
    assert eo.get("info") is True, f"endpoint-override не driver (info), got: {eo}"
    assert eo["ok"] is False, f"override = WARN, а не подтверждённое здоровье, got: {eo}"


def test_endpoint_standard_is_ok_in_check_all(monkeypatch):
    """Гвард: стандартный endpoint (status=ok) остаётся ok=True + info=True → ✅ без шума."""
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_read_endpoint_config",
                        lambda: {"base_url": "", "no_proxy": "", "source": "shell"})
    eo = _check_by_name(health.check_all(), "ANTHROPIC_BASE_URL")
    assert eo["ok"] is True and eo.get("info") is True, f"стандартный endpoint = тихий ✅, got: {eo}"


def test_unverified_checks_render_warning_not_ok(monkeypatch, capsys):
    """Связка check_all → _print_report: «не смогли проверить» и override дают ⚠️, не ✅.

    Именно эту связку сломал бы фикс рендера в одиночку: обе строки печатались ✅ с текстом
    «состояние не определено» / «нестандартный endpoint» — fail-open в лицо пользователю.
    """
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_codenv_job_check", lambda *a, **kw: {
        "status": "unknown", "detail": "состояние не определено (launchctl print недоступен/таймаут)"})
    monkeypatch.setattr(health, "_read_endpoint_config", lambda: {
        "base_url": "https://api.z.ai/api/anthropic", "no_proxy": "", "source": "settings.json"})
    health._print_report(health.check_all())
    out = capsys.readouterr().out
    codenv_line = next(ln for ln in out.splitlines() if "codenv" in ln.lower())
    endpoint_line = next(ln for ln in out.splitlines() if "ANTHROPIC_BASE_URL" in ln)
    assert _MARK_WARN in codenv_line, f"непроверенное здоровье = ⚠️, got: {codenv_line}"
    assert _MARK_OK not in codenv_line, f"«не определено» НЕ ✅, got: {codenv_line}"
    assert _MARK_WARN in endpoint_line, f"endpoint-override = ⚠️, got: {endpoint_line}"
    assert _MARK_OK not in endpoint_line, f"override мимо туннеля НЕ ✅, got: {endpoint_line}"


# ===== ok-misuse — КЛАСС, а не отдельные случаи (cycle-review PR #296, раунд 2) =====
# Раунд 1 починил codenv и endpoint-override. Codex (P2, раунд 2) показал vscode-proxy с той же
# формулой `ok = status != "down"`. Аудит check_all нашёл ЕЩЁ ЧЕТЫРЕ производителя того же класса:
# хардкод ok=True (upstream VPS, версии) и `!= "warn"` (xray-sync, gh-direct, privoxy-log).
# Инвариант (а не перечень случаев): ok == «проверено и прошло» == status == "ok". Всё остальное
# (unknown «не смогли проверить», warn, info «неприменим», down) — НЕ ok. Ось «не роняй вердикт»
# выражается ТОЛЬКО через info. Худший кейс: «VPS не отвечает: TCP timeout» печатался ✅.
# Канон: fix-once-document-decisions — чиним инвариант, иначе следующий вариант придёт третьим раундом.

_OK_INVARIANT_CASES = [
    # (needle имени чека, имя мокаемого чека, статус «не ok», ожидаемый detail-фрагмент)
    ("vscode-proxy", "_vscode_proxy_check", "unknown", "не задан"),
    ("local.json ↔ xray", "_endpoint_xray_sync_check", "info", "неприменим"),
    ("gh/git direct", "_github_direct_check", "unknown", "timeout"),
    ("версии", "_installed_versions_check", "unknown", "не установлено"),
    ("privoxy-log", "_privoxy_log_observability_check", "info", "неприменим"),
    ("GFW per-domain", "_gfw_domain_check", "info", "нет доменов для GFW-теста"),
]


@_pytest.mark.parametrize("needle,attr,status,detail", _OK_INVARIANT_CASES,
                          ids=[c[0] for c in _OK_INVARIANT_CASES])
def test_non_ok_status_is_not_rendered_ok(monkeypatch, needle, attr, status, detail):
    """Ни один info-чек со статусом != ok не имеет ok=True (иначе рендер даёт ✅ на непроверенном)."""
    _all_up_monkey(monkeypatch)
    payload = {"status": status, "detail": detail}
    if attr == "_installed_versions_check":
        payload |= {"codex": [], "claude_code": []}
    monkeypatch.setattr(health, attr, lambda *a, **kw: payload)
    c = _check_by_name(health.check_all(active_claude=True), needle)
    assert c.get("info") is True, f"{needle}: остаётся не-driver (info), got: {c}"
    assert c["ok"] is False, f"{needle}: status={status} ≠ подтверждённое здоровье, got: {c}"


@_pytest.mark.parametrize("needle,attr", [(c[0], c[1]) for c in _OK_INVARIANT_CASES],
                          ids=[c[0] for c in _OK_INVARIANT_CASES])
def test_ok_status_stays_ok(monkeypatch, needle, attr):
    """Гвард от переусердствования: status=ok у тех же чеков остаётся ok=True (тихий ✅)."""
    _all_up_monkey(monkeypatch)
    payload = {"status": "ok", "detail": "mock: проверено и прошло"}
    if attr == "_installed_versions_check":
        payload |= {"codex": [], "claude_code": []}
    monkeypatch.setattr(health, attr, lambda *a, **kw: payload)
    c = _check_by_name(health.check_all(active_claude=True), needle)
    assert c["ok"] is True, f"{needle}: подтверждённо здоровый = ✅, got: {c}"


def test_upstream_vps_down_is_not_ok_when_tunnel_alive(monkeypatch):
    """VPS мёртв при живом туннеле → ok=False + info=True, НЕ захардкоженный ok=True.

    Худший кейс класса: doctor печатал ✅ «VPS не отвечает: TCP timeout». info здесь верен
    (туннель жив → вердикт не роняем, #194), но ok=True превращал реальный сбой в зелёную галочку.
    """
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_upstream_vps_reachable",
                        lambda *a, **kw: {"status": "down", "detail": "VPS не отвечает: TCP timeout"})
    vps = _check_by_name(health.check_all(), "upstream VPS")
    assert vps.get("info") is True, f"туннель жив → VPS-чек не driver, got: {vps}"
    assert vps["ok"] is False, f"«VPS не отвечает» ≠ ✅, got: {vps}"


def test_upstream_vps_down_stays_driver_when_tunnel_fails(monkeypatch):
    """Гвард #194: VPS down + туннель fail + сеть/DNS живы → DRIVER (info снят), вердикт падает."""
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_upstream_vps_reachable",
                        lambda *a, **kw: {"status": "down", "detail": "VPS не отвечает: TCP timeout"})
    monkeypatch.setattr(health, "_tunnel_up", lambda *a, **kw: (False, "mock: туннель мёртв", False, None))
    vps = _check_by_name(health.check_all(), "upstream VPS")
    assert not vps.get("info"), f"#194: VPS-смерть при мёртвом туннеле = driver, got: {vps}"
    assert vps["ok"] is False, f"driver-сбой, got: {vps}"


def test_no_check_claims_ok_while_status_not_ok(monkeypatch):
    """Гвард класса: НИ ОДИН чек не помечен ok=True, когда все производители вернули не-ok.

    Ловит следующего носителя формулы `!= "down"` / хардкода ok=True, не дожидаясь ревью.
    """
    _all_up_monkey(monkeypatch)
    for attr, payload in (
        ("_vscode_proxy_check", {"status": "unknown", "detail": "not-ok: vscode"}),
        ("_endpoint_xray_sync_check", {"status": "info", "detail": "not-ok: sync"}),
        ("_github_direct_check", {"status": "unknown", "detail": "not-ok: gh"}),
        ("_privoxy_log_observability_check", {"status": "info", "detail": "not-ok: plo"}),
        ("_upstream_vps_reachable", {"status": "down", "detail": "not-ok: vps"}),
        ("_codenv_job_check", {"status": "unknown", "detail": "not-ok: codenv"}),
        ("_gfw_domain_check", {"status": "info", "detail": "not-ok: gfw"}),
        ("_installed_versions_check",
         {"status": "unknown", "detail": "not-ok: versions", "codex": [], "claude_code": []}),
    ):
        monkeypatch.setattr(health, attr, lambda *a, _p=payload, **kw: _p)
    monkeypatch.setattr(health, "_read_endpoint_config",
                        lambda: {"base_url": "https://api.z.ai/x", "no_proxy": "", "source": "mock"})
    # Сверяем только те чеки, чьи производители мы принудили в не-ok (маркер в detail) — прочие
    # info-чеки идут через _all_up_monkey со status=ok и обязаны остаться ✅.
    liars = [c["name"] for c in health.check_all(active_claude=True)["checks"]
             if c.get("info") and c["ok"] and (c.get("detail") or "").startswith("not-ok:")]
    assert not liars, f"ok=True при status != ok — ✅ на непроверенном: {liars}"


# ===== GFW-совет гейтится на status=="gfw", а не на ok (cycle-review PR #296, раунд 3) =====
# РЕГРЕССИЯ, внесённая в 4fc8d84 (Codex P2): _print_report читал `not gfw_check["ok"]` как прокси
# для «status == gfw» — комментарий рядом это прямо и декларировал. После выравнивания ok на
# `status == "ok"` условие стало истинным и для status="info" («контрольный домен недоступен —
# GFW-тест неприменим»), и doctor при ОБЩЕМ СБОЕ СЕТИ уверенно советовал «GFW режет домен...
# контрольный домен отвечает» — прямо противореча пробе и уводя от настоящей причины.
# Корень тот же, что у всего PR: потребитель склеивал две оси (здесь «не ok» ≠ «GFW»). Чиним
# как везде — несём НАСТОЯЩИЙ статус в чек (канон category, как vendor-outage у туннеля #207),
# а не откатываем ok обратно в перегруженный флаг.


def test_gfw_advice_only_when_domain_actually_cut(monkeypatch, capsys):
    """status="gfw" → совет про GFW печатается (положительный путь сохранён)."""
    health._print_report({"status": "degraded", "checks": [
        {"name": "privoxy (8118)", "ok": False, "detail": "порт закрыт"},
        {"name": "GFW per-domain (github vs z.ai прямой curl)", "ok": False, "info": True,
         "category": "gfw", "detail": "github режется, контрольный z.ai отвечает"},
    ]})
    out = capsys.readouterr().out
    assert "GFW режет домен" in out, f"реальный GFW обязан давать совет, got:\n{out}"


def test_no_gfw_advice_when_probe_inapplicable(capsys):
    """status="info" («контрольный домен недоступен») → совета про GFW НЕТ.

    Общий сбой сети: проба явно говорит «не GFW». Совет «контрольный домен отвечает» здесь
    ложь и уводит от настоящей причины (сеть/DNS), которую doctor печатает выше.
    """
    health._print_report({"status": "degraded", "checks": [
        {"name": "privoxy (8118)", "ok": False, "detail": "порт закрыт"},
        {"name": "GFW per-domain (github vs z.ai прямой curl)", "ok": False, "info": True,
         "detail": "контрольный домен недоступен — GFW-тест неприменим (общий сбой сети)"},
    ]})
    out = capsys.readouterr().out
    assert "GFW режет домен" not in out, \
        f"«не смогли проверить» ≠ «GFW режет» — ложный совет уводит от причины, got:\n{out}"


def test_gfw_check_carries_status_category(monkeypatch):
    """check_all несёт настоящий статус GFW-пробы в category (не восстанавливать его из ok)."""
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_gfw_domain_check",
                        lambda *a, **kw: {"status": "gfw", "detail": "github режется"})
    c = _check_by_name(health.check_all(active_claude=True), "GFW per-domain")
    assert c.get("category") == "gfw", f"реальный GFW помечен category=gfw, got: {c}"
    assert c["ok"] is False and c.get("info") is True, f"GFW не driver, но и не ✅, got: {c}"


def test_gfw_check_info_is_not_categorized_gfw(monkeypatch):
    """status="info" не получает category=gfw — иначе совет вернётся через другую дверь."""
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_gfw_domain_check",
                        lambda *a, **kw: {"status": "info", "detail": "контрольный домен недоступен"})
    c = _check_by_name(health.check_all(active_claude=True), "GFW per-domain")
    assert c.get("category") != "gfw", f"«неприменимо» ≠ GFW, got: {c}"
    assert c["ok"] is False, f"непроверенное ≠ ✅ (инвариант раунда 2), got: {c}"


# --- #207 edge-cases (Codex cycle-review P1#2, P2#4): vacuous-truth guard + no-response/bad-code ---
def _tunnel_curl_raw_per_target(responses):
    """Мок sys_probe.run с RAW-ответом per-URL: {"anthropic": {"out": "", "timeout": False}, ...}.

    В отличие от _tunnel_curl_per_target (только http-код), позволяет задать no-response (out="")
    и bad-code (out="garbage"). Таргет распознаётся по подстроке URL. Неизвестный → 000.
    """
    def fake_run(cmd, timeout):
        url = cmd[-1] if cmd else ""
        for key, resp in responses.items():
            if key in url:
                return {"rc": 0, "out": resp.get("out", ""), "err": "", "timeout": resp.get("timeout", False)}
        return {"rc": 0, "out": "000", "err": "", "timeout": False}
    return fake_run


def test_tunnel_up_empty_targets_not_vendor_outage(monkeypatch):
    """P1#2 (Codex): пустой TUNNEL_TARGETS НЕ должен давать ложный vendor outage (all([])=True).

    Регресс-гвард vacuous-truth: ранний `if not TUNNEL_TARGETS: return ..., False` защищает от
    ложного маркера при пустом кортеже (production-константа непустая, но guard явный).
    """
    monkeypatch.setattr(health, "TUNNEL_TARGETS", ())
    ok, detail, is_vendor_outage, _ = health._tunnel_up()
    assert ok is False
    assert is_vendor_outage is False
    assert health.VENDOR_OUTAGE_MARKER not in detail, f"пустые targets не vendor outage, got: {detail}"


def test_tunnel_up_both_no_response_not_vendor_outage(monkeypatch):
    """P2#4: оба таргета no-response (пустой out) → down, НЕ vendor outage."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _tunnel_curl_raw_per_target({"anthropic": {"out": ""}, "openai": {"out": ""}}))
    ok, detail, _, _ = health._tunnel_up()
    assert ok is False
    assert health.VENDOR_OUTAGE_MARKER not in detail, f"no-response не vendor outage, got: {detail}"
    assert "no-response" in detail


def test_tunnel_up_both_bad_code_not_vendor_outage(monkeypatch):
    """P2#4: оба таргета bad-code (нечисловой) → down, НЕ vendor outage."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _tunnel_curl_raw_per_target({"anthropic": {"out": "garbage"}, "openai": {"out": "XYZ"}}))
    ok, detail, _, _ = health._tunnel_up()
    assert ok is False
    assert health.VENDOR_OUTAGE_MARKER not in detail, f"bad-code не vendor outage, got: {detail}"


def test_tunnel_up_5xx_and_no_response_not_vendor_outage(monkeypatch):
    """P2#4: один 5xx + один no-response → down, НЕ vendor outage (не все 5xx)."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _tunnel_curl_raw_per_target({"anthropic": {"out": "503"}, "openai": {"out": ""}}))
    ok, detail, _, _ = health._tunnel_up()
    assert ok is False
    assert health.VENDOR_OUTAGE_MARKER not in detail, f"5xx+no-response не vendor outage, got: {detail}"


def test_tunnel_up_5xx_and_bad_code_not_vendor_outage(monkeypatch):
    """P2#4: один 5xx + один bad-code → down, НЕ vendor outage."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _tunnel_curl_raw_per_target({"anthropic": {"out": "503"}, "openai": {"out": "garbage"}}))
    ok, detail, _, _ = health._tunnel_up()
    assert ok is False
    assert health.VENDOR_OUTAGE_MARKER not in detail, f"5xx+bad-code не vendor outage, got: {detail}"


def test_check_all_vendor_outage_status_is_down_not_ok(monkeypatch):
    """P2#5 (Codex): vendor outage → result status down/degraded (НЕ ok). Канал до вендора мёртв.

    Vendor outage = агенты не могут работать = реальный сбой для пользователя (srouter-critical-infra-24-7).
    Tunnel-check driver-down даёт НЕ-ok вердикт — это намеренно, не маскируем в ok.
    """
    result = _vendor_outage_check_all(monkeypatch)
    assert result["status"] != "ok", f"vendor outage не ok (канал до вендора мёртв), got: {result['status']}"

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


# ============================ #329: _endpoint_direct_override / _host_in_no_proxy / _pids_env_readable ============================

def test_endpoint_direct_override_true_for_zai_in_no_proxy(monkeypatch):
    """#329: z.ai override + z.ai в NO_PROXY → overridden=True (CC ходит напрямую by design)."""
    monkeypatch.setattr(health, "_read_endpoint_config", lambda: _ZAI_OVERRIDE_CFG)
    res = health._endpoint_direct_override()
    assert res["overridden"] is True
    assert res["host"] == "api.z.ai"
    assert res["base_url"] == "https://api.z.ai/api/anthropic"


def test_endpoint_direct_override_false_when_not_in_no_proxy(monkeypatch):
    """#329: override вне NO_PROXY → overridden=False (прокси для endpoint обязателен)."""
    monkeypatch.setattr(health, "_read_endpoint_config",
                        lambda: {"base_url": "https://api.z.ai/api/anthropic",
                                 "no_proxy": "localhost,127.0.0.1", "source": "shell"})
    assert health._endpoint_direct_override()["overridden"] is False


def test_endpoint_direct_override_false_for_standard_and_empty(monkeypatch):
    """#329: стандартный endpoint (exact api.anthropic.com) и пустой base → overridden=False."""
    monkeypatch.setattr(health, "_read_endpoint_config",
                        lambda: {"base_url": "https://api.anthropic.com",
                                 "no_proxy": "api.anthropic.com", "source": "shell"})
    assert health._endpoint_direct_override()["overridden"] is False, \
        "стандартный хост не override, даже если кто-то внес его в NO_PROXY"
    monkeypatch.setattr(health, "_read_endpoint_config",
                        lambda: {"base_url": "", "no_proxy": "z.ai", "source": "default"})
    assert health._endpoint_direct_override()["overridden"] is False


def test_endpoint_direct_override_false_for_lookalike_outside_no_proxy(monkeypatch):
    """#329 C2-канон: lookalike api.anthropic.com.attacker.example вне NO_PROXY → False (проба применяется)."""
    monkeypatch.setattr(health, "_read_endpoint_config",
                        lambda: {"base_url": "https://api.anthropic.com.attacker.example/",
                                 "no_proxy": "localhost", "source": "shell"})
    assert health._endpoint_direct_override()["overridden"] is False


def test_host_in_no_proxy_exact_and_subdomain_only():
    """#129 семантика членства: exact match или subdomain, НЕ substring (lookalike-атака)."""
    no_proxy = "localhost,127.0.0.1,::1,z.ai,.z.ai,storage.googleapis.com"
    assert health._host_in_no_proxy("z.ai", no_proxy) is True
    assert health._host_in_no_proxy("api.z.ai", no_proxy) is True, "subdomain через .z.ai"
    assert health._host_in_no_proxy("storage.googleapis.com", no_proxy) is True
    assert health._host_in_no_proxy("notz.ai", no_proxy) is False, "substring НЕ считается"
    assert health._host_in_no_proxy("evil-z.ai", no_proxy) is False
    assert health._host_in_no_proxy("z.ai", "") is False


def test_pids_env_readable_sections_by_pid(monkeypatch):
    """#329: readable = PID-секции с хотя бы одним ALL_CAPS= токеном; секция без env не читается."""
    out = (
        f"  PID TTY           TIME CMD\n"
        f"100 ttys000 0:01.00 {CLI_COMM} HTTPS_PROXY=http://127.0.0.1:8118 HOME=/Users/me\n"
        f"200 ttys001 0:01.00 {CLI_COMM}\n"
    )
    monkeypatch.setattr(health.sys_probe, "run",
                        lambda cmd, timeout: {"rc": 0, "out": out, "err": "", "timeout": False})
    assert health._pids_env_readable(["100", "200", "300"]) == {"100"}, \
        "200 без env и отсутствующий 300 не читаются"


def test_pids_env_readable_fail_soft(monkeypatch):
    """#329: timeout / пустой вывод / пустой список → пустое set (никто не читается)."""
    monkeypatch.setattr(health.sys_probe, "run",
                        lambda cmd, timeout: {"rc": None, "out": "", "err": "timeout", "timeout": True})
    assert health._pids_env_readable(["100"]) == set()
    monkeypatch.setattr(health.sys_probe, "run",
                        lambda cmd, timeout: {"rc": 0, "out": "", "err": "", "timeout": False})
    assert health._pids_env_readable(["100"]) == set()
    assert health._pids_env_readable([]) == set()


# ============================ #109: watchdog state-машина + _notify логирование ============================
# Баг: was_ok бинарный (state == "ok") → degraded→down не пушит. + _notify не логирует.


@_pytest.fixture(autouse=True)
def _block_real_watchdog_lifecycle(monkeypatch, tmp_path):
    if hasattr(health, "_record_watchdog_lifecycle"):
        monkeypatch.setattr(health, "_record_watchdog_lifecycle", lambda: None)
    # PR #326 review P2: audit-JSONL — ПРОД-файл (сюда же пишет launchd-watchdog): тесты
    # без собственного setattr не должны дописывать фейковые переходы в живой лог.
    if hasattr(health, "WATCHDOG_STATUS_LOG"):
        monkeypatch.setattr(health, "WATCHDOG_STATUS_LOG",
                            tmp_path / "srouter-watchdog.status.jsonl")
    # Канон #265 (ambient env травит параметризуемые заглушки): cooldown-env снимаем,
    # тесты задают его явно через monkeypatch.setenv.
    monkeypatch.delenv(_COOLDOWN_ENV if hasattr(health, "_DEGRADED_NOTIFY_COOLDOWN_ENV")
                       else "SROUTER_WATCHDOG_DEGRADED_COOLDOWN", raising=False)


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


# ============ watchdog-plist запускает health.py КАК СКРИПТ — self-import должен это пережить ============
# launchagents/com.srouter.watchdog.plist (srouter_cli.py:_install_generic_launchagent script_path=
# env.root / "health.py") вызывает `<python> .../health.py watchdog` — прямой запуск файла, НЕ
# `-m health`. При таком запуске исполняемый модуль регистрируется в sys.modules как '__main__', а
# не 'health'. health_probes.py делает `import health as _health_facade` (циклический self-import
# для monkeypatch-совместимости, канон #158) — при запуске как __main__ Python не находит 'health' в
# sys.modules и заново импортирует/исполняет health.py под ключом 'health', создавая ВТОРОЙ,
# независимый объект модуля. У этого второго объекта _tunnel_up() (health_probes.py) обращается к
# _health_facade.TUNNEL_TARGETS ДО того, как звёздный ре-экспорт `from health_probes import *`
# (внутри его же, второй, инициализации) успевает связать имя — AttributeError.
def test_health_py_runs_standalone_via_watchdog_invocation(tmp_path):
    """Точь-в-точь вызов watchdog-plist: `<python> health.py watchdog` не должен падать.

    Реальный launchd ProgramArguments = [python_bin, str(env.root / "health.py"), "watchdog"]
    (srouter_cli.py). subprocess здесь — единственный способ воспроизвести __main__ vs 'health'
    дуализацию: обычный `import health` (как делает srouter.py:_cmd_doctor) не задевает баг.
    """
    import subprocess
    import sys as _sys
    from pathlib import Path as _Path

    repo_root = _Path(__file__).resolve().parent.parent
    env = dict(os.environ)
    # HOME → tmp_path уводит WATCHDOG_LIFECYCLE_LOG/WATCHDOG_NOTIFY_LOG (Path.home()-based) из-под
    # реального пользователя, чтобы subprocess не гонялся с живым launchd-watchdog за один лог-файл
    # и не слал спурионные macOS-уведомления (cycle-review #311). WATCHDOG_STATE/LIFECYCLE_STATE
    # остаются хардкодом /tmp/srouter-watchdog.* (health.py) — не параметризуемы через env, вне
    # скоупа этого фикса (self-import, не state-path рефакторинг).
    env["HOME"] = str(tmp_path)
    # Реальные сетевые probe (privoxy/xray/tunnel) не подняты в CI/sandbox — это ожидаемо и не
    # предмет теста; предмет теста — что процесс не падает с AttributeError на TUNNEL_TARGETS.
    result = subprocess.run(
        [_sys.executable, str(repo_root / "health.py"), "watchdog"],
        cwd=str(repo_root), env=env, capture_output=True, text=True, timeout=30,
    )
    assert "AttributeError" not in result.stderr, (
        f"watchdog-инвокация упала с AttributeError (self-import __main__ vs 'health'):\n{result.stderr}"
    )
    assert "TUNNEL_TARGETS" not in result.stderr, result.stderr
    # Traceback — самостоятельная проверка (cycle-review #311, Codex): падение с ЛЮБЫМ другим
    # исключением (TypeError/NameError и т.п. от будущего регресса) не должно проходить незамеченным
    # только потому, что в stderr нет буквальных строк "AttributeError"/"TUNNEL_TARGETS". returncode
    # НЕ используется — cmd_watchdog() легитимно возвращает 1 при status != "ok" (health.py:605),
    # это не крах, а fail-closed health-контракт; ассертить нужно "процесс не упал", не "стек здоров".
    assert "Traceback (most recent call last)" not in result.stderr, (
        f"watchdog-инвокация упала с необработанным исключением:\n{result.stderr}"
    )


# ============================ cycle-review #133: table-driven transition matrix ============================
# Codex C1: degraded→degraded спамило (is_ok collapse). Exact-state transitions решают.
# Полная матрица: каждый (prev, cur) → ожидаемое количество пушей.
_TRANSITIONS = [
    # (prev_state, cur_status, expected_pushes, description)
    ("ok", "down", 1, "ok→down: пуш (новое падение)"),
    ("degraded", "down", 1, "degraded→down: пуш (новое падение)"),
    # #315 (п.1 — симметрия): «восстановление» только из down; деградация — событие.
    # Legacy-строка в prev (как все строки матрицы) = last_degraded_push=0 (cooldown истёк),
    # поэтому ok→degraded здесь пушится.
    ("ok", "degraded", 1, "ok→degraded: пуш «деградировал» (#315 п.1)"),
    ("down", "down", 0, "down→down: молчит (не спам; смена состава — отдельные тесты #315)"),
    ("degraded", "degraded", 0, "degraded→degraded: молчит (не спам — фикс C1)"),
    ("down", "ok", 1, "down→ok: пуш восстановления"),
    ("degraded", "ok", 0, "degraded→ok: молчит — НЕ восстановление (#315 п.1)"),
    ("ok", "ok", 0, "ok→ok: молчит"),
    ("", "down", 1, "fresh→down: пуш (первый прогон, уже упало)"),
    ("", "ok", 0, "fresh→ok: НЕ пуш (первый прогон, всё ок — не восстановление)"),
    ("corrupt!!!", "down", 0, "corrupt→down: НЕ пуш (неизвестный prev — безопасно молчим)"),
    ("", "degraded", 1, "fresh→degraded: пуш «деградировал» (первый прогон уже не-ok, #315)"),
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


# ============================ #315: семантика нотификаций watchdog (fix-план п.1–3) ============================
# Диагностика #315: серии «стек восстановлен» без единого «упал» = осцилляция ok↔degraded —
# ok→degraded молчал, degraded→ok пушит «восстановлен». Перманентный degraded глотал реальные
# туннельные провалы (degraded→degraded молчит даже при смене состава упавших драйверов).
# Новая семантика: «восстановлен» только из down; ok→degraded — «деградировал» с cooldown;
# смена НАБОРА упавших драйверов без смены статуса — тоже событие (cooldown); audit-JSONL статуса.

import time as _time315  # noqa: E402 — локальный импорт блока #315

_COOLDOWN_ENV = "SROUTER_WATCHDOG_DEGRADED_COOLDOWN"


def _wd315_watchdog_harness(monkeypatch, tmp_path, cur, failed, prev_state=None, env=None):
    """Общая обвязка тестов #315: state-файл (JSON или legacy-строка), мок check_all/_notify.

    Возвращает список (msg, sound) нотификаций и путь status-JSONL (tmp_path).
    """
    state_file = tmp_path / "watchdog.last"
    if isinstance(prev_state, dict):
        # notified_failed по умолчанию = failed (состав уже уведомлён) — тесты, которым
        # важно «не уведомлён», задают notified_failed явно.
        prev_state = {**{"notified_failed": prev_state.get("failed")}, **prev_state}
        state_file.write_text(json.dumps(prev_state, ensure_ascii=False))
    elif prev_state is not None:
        state_file.write_text(prev_state)
    status_log = tmp_path / "srouter-watchdog.status.jsonl"
    monkeypatch.setattr(health, "WATCHDOG_STATE", state_file)
    monkeypatch.setattr(health, "WATCHDOG_STATUS_LOG", status_log)
    monkeypatch.setattr(health, "check_all", lambda **kw: {
        "status": cur,
        "checks": ([{"name": name, "ok": False} for name in failed] if failed
                   else [{"name": "privoxy", "ok": True}]),
    })
    notified = []
    monkeypatch.setattr(health, "_notify", lambda msg, sound="Glass": notified.append((msg, sound)))
    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)
    return notified, status_log, state_file


def test_watchdog_degradation_push_content(monkeypatch, tmp_path):
    """ok→degraded (#315 п.1): пуш «деградировал» со списком драйверов, звук Ping."""
    notified, _, _ = _wd315_watchdog_harness(
        monkeypatch, tmp_path, "degraded", ["claude-proxy", "туннель"],
        prev_state={"status": "ok", "failed": [], "last_degraded_push": 0.0},
        env={_COOLDOWN_ENV: "0"})
    health.cmd_watchdog()
    assert len(notified) == 1
    assert "деградир" in notified[0][0]
    assert "claude-proxy" in notified[0][0] and "туннель" in notified[0][0]
    assert notified[0][1] == "Ping"


def test_watchdog_degradation_push_suppressed_within_cooldown(monkeypatch, tmp_path):
    """ok→degraded при недавнем degraded-пуше (cooldown не истёк) — молчит (#315 п.1)."""
    notified, _, _ = _wd315_watchdog_harness(
        monkeypatch, tmp_path, "degraded", ["claude-proxy"],
        prev_state={"status": "ok", "failed": [], "last_degraded_push": _time315.time() - 60},
        env={_COOLDOWN_ENV: "900"})
    health.cmd_watchdog()
    assert len(notified) == 0, "cooldown 900с не истёк — деградация не пушится"


def test_watchdog_degradation_push_passes_after_cooldown(monkeypatch, tmp_path):
    """ok→degraded после истечения cooldown — пуш идёт (#315 п.1)."""
    notified, _, _ = _wd315_watchdog_harness(
        monkeypatch, tmp_path, "degraded", ["claude-proxy"],
        prev_state={"status": "ok", "failed": [], "last_degraded_push": _time315.time() - 1000},
        env={_COOLDOWN_ENV: "900"})
    health.cmd_watchdog()
    assert len(notified) == 1


def test_watchdog_pushes_on_failed_set_change_same_status(monkeypatch, tmp_path):
    """degraded{a}→degraded{a,b} — смена состава упавших драйверов пушится (#315 п.3):
    перманентный degraded больше не глотает новые причины (туннель упал на фоне MIXED)."""
    notified, _, _ = _wd315_watchdog_harness(
        monkeypatch, tmp_path, "degraded", ["claude-proxy", "туннель"],
        prev_state={"status": "degraded", "failed": ["claude-proxy"], "last_degraded_push": 0.0},
        env={_COOLDOWN_ENV: "0"})
    health.cmd_watchdog()
    assert len(notified) == 1
    assert "состав" in notified[0][0] and "туннель" in notified[0][0]


def test_watchdog_no_push_when_failed_set_unchanged(monkeypatch, tmp_path):
    """degraded{a}→degraded{a} — состав не изменился, статус не изменился → молчит."""
    notified, _, _ = _wd315_watchdog_harness(
        monkeypatch, tmp_path, "degraded", ["claude-proxy"],
        prev_state={"status": "degraded", "failed": ["claude-proxy"], "last_degraded_push": 0.0},
        env={_COOLDOWN_ENV: "0"})
    health.cmd_watchdog()
    assert len(notified) == 0


def test_watchdog_failed_set_change_requires_known_prev_failed(monkeypatch, tmp_path):
    """Legacy-строка в prev (failed неизвестен) — смену состава НЕ детектим: только статусы.

    Обратная совместимость state-файла, оставшегося от предыдущей версии watchdog'а."""
    notified, _, _ = _wd315_watchdog_harness(
        monkeypatch, tmp_path, "degraded", ["claude-proxy"],
        prev_state="degraded", env={_COOLDOWN_ENV: "0"})
    health.cmd_watchdog()
    assert len(notified) == 0, "degraded→degraded с legacy prev (набор неизвестен) — молчит"


def test_watchdog_down_to_down_set_change_pushes(monkeypatch, tmp_path):
    """down{a}→down{a,b}: смена состава отказа при стабильном down — тоже событие (#315 п.3)."""
    notified, _, _ = _wd315_watchdog_harness(
        monkeypatch, tmp_path, "down", ["privoxy", "туннель"],
        prev_state={"status": "down", "failed": ["privoxy"], "last_degraded_push": 0.0},
        env={_COOLDOWN_ENV: "0"})
    health.cmd_watchdog()
    assert len(notified) == 1
    assert "состав" in notified[0][0]


def test_watchdog_status_jsonl_logged_on_change(monkeypatch, tmp_path):
    """Audit-JSONL статуса (#315 п.2): при изменении {status, failed} пишется событие
    previous/current — ретроспективный анализ осцилляций больше не невозможен."""
    _, status_log, _ = _wd315_watchdog_harness(
        monkeypatch, tmp_path, "degraded", ["claude-proxy"],
        prev_state={"status": "ok", "failed": [], "last_degraded_push": 0.0},
        env={_COOLDOWN_ENV: "0"})
    health.cmd_watchdog()
    lines = [json.loads(line) for line in status_log.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0]["previous"] == {"status": "ok", "failed": []}
    assert lines[0]["current"] == {"status": "degraded", "failed": ["claude-proxy"]}
    assert "timestamp" in lines[0]


def test_watchdog_status_jsonl_baseline_quiet(monkeypatch, tmp_path):
    """Первый снимок (state-файла нет) — тихий baseline: JSONL не пишется (как lifecycle)."""
    _, status_log, _ = _wd315_watchdog_harness(
        monkeypatch, tmp_path, "degraded", ["claude-proxy"],
        prev_state=None, env={_COOLDOWN_ENV: "0"})
    health.cmd_watchdog()
    assert not status_log.exists()


def test_watchdog_status_jsonl_quiet_when_unchanged(monkeypatch, tmp_path):
    """Неизменный {status, failed} — JSONL не пишется (не раздуваем лог на каждом ~20с-тике)."""
    _, status_log, _ = _wd315_watchdog_harness(
        monkeypatch, tmp_path, "degraded", ["claude-proxy"],
        prev_state={"status": "degraded", "failed": ["claude-proxy"], "last_degraded_push": 0.0},
        env={_COOLDOWN_ENV: "0"})
    health.cmd_watchdog()
    assert not status_log.exists()


def test_watchdog_state_written_as_json(monkeypatch, tmp_path):
    """State-файл пишется JSON-ом {status, failed, notified_failed, last_degraded_push} (#315):
    смена состава детектится между прогонами, cooldown переживает осцилляцию."""
    _, _, state_file = _wd315_watchdog_harness(
        monkeypatch, tmp_path, "degraded", ["claude-proxy"],
        prev_state={"status": "ok", "failed": [], "notified_failed": [], "last_degraded_push": 0.0},
        env={_COOLDOWN_ENV: "0"})
    health.cmd_watchdog()
    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert state["status"] == "degraded"
    assert state["failed"] == ["claude-proxy"]
    assert state["notified_failed"] == ["claude-proxy"]
    assert state["last_degraded_push"] > 0


# ============================ #315 round 2: cycle-review Codex findings ============================
# P1-1: suppressed cooldown'ом смена состава терялась НАВСЕГДА (failed продвигался,
# last_degraded_push — нет). P1-2/P1-3: гонка параллельных прогонов (дубли пушей,
# потеря state, metrics double-write) + неатомарная запись state.

def test_watchdog_suppressed_set_change_survives_cooldown(monkeypatch, tmp_path):
    """P1-1: смена состава, подавленная cooldown'ом, пушится ПОСЛЕ его истечения.

    Прогон 1 (cooldown не истёк): уведомление подавлено — state обязан помнить, что
    этот состав ЕЩЁ НЕ УВЕДОМЛЁН (notified_failed не продвигается). Прогон 2 (cooldown
    истёк): состав отличается от уведомлённого → пуш. Регрессия round 1: failed сразу
    записывался новым → прогон 2 видел «не изменилось» и событие терялось навсегда."""
    notified, _, state_file = _wd315_watchdog_harness(
        monkeypatch, tmp_path, "degraded", ["claude-proxy", "туннель"],
        prev_state={"status": "degraded", "failed": ["claude-proxy"],
                    "notified_failed": ["claude-proxy"],
                    "last_degraded_push": _time315.time() - 60},
        env={_COOLDOWN_ENV: "900"})
    health.cmd_watchdog()
    assert len(notified) == 0, "cooldown не истёк — подавлено"
    # время прошло (эмуляция: тик каждые ~20с) — cooldown истёк
    state = json.loads(state_file.read_text(encoding="utf-8"))
    state["last_degraded_push"] = _time315.time() - 1000
    state_file.write_text(json.dumps(state, ensure_ascii=False))
    monkeypatch.setattr(health, "check_all", lambda **kw: {
        "status": "degraded",
        "checks": [{"name": name, "ok": False} for name in ("claude-proxy", "туннель")]})
    health.cmd_watchdog()
    assert len(notified) == 1, "после истечения cooldown неуведомлённый состав должен пушиться"
    assert "состав" in notified[0][0]


def test_watchdog_suppressed_new_degradation_survives_cooldown(monkeypatch, tmp_path):
    """P1-1 (ok→degraded вариант): подавленная новой деградацией не теряется — после
    cooldown пользователь узнаёт о составе, пусть и лейблом «состав изменился»."""
    notified, _, state_file = _wd315_watchdog_harness(
        monkeypatch, tmp_path, "degraded", ["claude-proxy"],
        prev_state={"status": "ok", "failed": [], "notified_failed": [],
                    "last_degraded_push": _time315.time() - 60},
        env={_COOLDOWN_ENV: "900"})
    health.cmd_watchdog()
    assert len(notified) == 0
    state = json.loads(state_file.read_text(encoding="utf-8"))
    state["last_degraded_push"] = _time315.time() - 1000
    state_file.write_text(json.dumps(state, ensure_ascii=False))
    monkeypatch.setattr(health, "check_all", lambda **kw: {
        "status": "degraded",
        "checks": [{"name": "claude-proxy", "ok": False}]})
    health.cmd_watchdog()
    assert len(notified) == 1


def test_watchdog_skips_when_another_run_holds_lock(monkeypatch, tmp_path):
    """P1-2/P1-3: параллельный прогон (flock занят) пропускает тик — не дублирует пуш,
    не перезаписывает state, не пишет audit-JSONL (гонка двух cmd_watchdog)."""
    import fcntl
    notified, status_log, state_file = _wd315_watchdog_harness(
        monkeypatch, tmp_path, "down", ["privoxy"],
        prev_state={"status": "ok", "failed": [], "notified_failed": [], "last_degraded_push": 0.0},
        env={_COOLDOWN_ENV: "0"})
    lock_path = tmp_path / "watchdog.last.lock"
    with open(lock_path, "w") as other_run:
        fcntl.flock(other_run.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        health.cmd_watchdog()
    assert len(notified) == 0, "параллельный прогон не должен пушить"
    assert not status_log.exists(), "параллельный прогон не должен писать audit-JSONL"
    assert json.loads(state_file.read_text(encoding="utf-8"))["status"] == "ok", \
        "state не перезаписан параллельным прогоном"


def test_watchdog_state_write_is_atomic(monkeypatch, tmp_path):
    """P1-2: state пишется через _atomic_write_text (tmp+fsync+rename), не write_text —
    оборванная запись не оставляет битый файл, который следующий прогон счёл бы fresh."""
    calls = []
    real_atomic = health._write_watchdog_state

    def spy_atomic(path, text):
        calls.append(str(path))
        return real_atomic(path, text)

    monkeypatch.setattr(health, "_write_watchdog_state", spy_atomic)
    _wd315_watchdog_harness(
        monkeypatch, tmp_path, "ok", [],
        prev_state={"status": "ok", "failed": [], "notified_failed": [], "last_degraded_push": 0.0},
        env={_COOLDOWN_ENV: "0"})
    health.cmd_watchdog()
    assert any("watchdog.last" in c for c in calls), "state должен писаться через _write_watchdog_state"


# ============================ #315 round 3: Codex findings ============================

def test_watchdog_silent_on_degraded_to_ok_with_notified_set(monkeypatch, tmp_path):
    """F1 (round 3): degraded с уведомлённым составом → ok — ТИШИНА, не ложный
    «стек деградировал ()»: unnotified не должен вычисляться при cur=ok."""
    notified, _, _ = _wd315_watchdog_harness(
        monkeypatch, tmp_path, "ok", [],
        prev_state={"status": "degraded", "failed": ["claude-proxy"],
                    "notified_failed": ["claude-proxy"], "last_degraded_push": 0.0},
        env={_COOLDOWN_ENV: "0"})
    health.cmd_watchdog()
    assert len(notified) == 0, "degraded→ok — молчим (#315 п.1), даже если состав был уведомлён"


def test_watchdog_set_comparison_order_insensitive(monkeypatch, tmp_path):
    """Round 4 (P2): failed — МНОЖЕСТВО драйверов: смена порядка перечисления
    ([a,b]→[b,a]) не событие — ни Ping, ни ложная запись в audit-JSONL."""
    notified, status_log, _ = _wd315_watchdog_harness(
        monkeypatch, tmp_path, "degraded", ["туннель", "claude-proxy"],
        prev_state={"status": "degraded", "failed": ["claude-proxy", "туннель"],
                    "notified_failed": ["claude-proxy", "туннель"],
                    "last_degraded_push": 0.0},
        env={_COOLDOWN_ENV: "0"})
    health.cmd_watchdog()
    assert len(notified) == 0, "перестановка порядка драйверов — не смена состава"
    assert not status_log.exists(), "audit-JSONL не пишет ложное изменение при перестановке"


# ============================ PR #326 review: P2/P3 findings ============================

def test_watchdog_status_log_isolated_from_prod(monkeypatch, tmp_path):
    """P2 (review): autouse-фикстура уводит WATCHDOG_STATUS_LOG в tmp_path — прогон
    тестов не дописывает фейковые переходы в живой ~/Library/Logs/srouter-watchdog.status.jsonl,
    куда параллельно пишет launchd-watchdog."""
    assert str(health.WATCHDOG_STATUS_LOG).startswith(str(tmp_path)), \
        "audit-JSONL обязан быть изолирован autouse-фикстурой даже в тестах без явного setattr"
    assert _COOLDOWN_ENV not in os.environ, \
        "ambient cooldown-env снят (канон #265 — не травить параметризуемые заглушки)"


def test_watchdog_heterogeneous_failed_does_not_crash_loop(monkeypatch, tmp_path):
    """P3 (review, блокирующий): гетерогенный failed из битого state ([3, 'x']) —
    sorted([3,'x']) бросает TypeError ДО записи state → crash-loop на каждом тике
    (/tmp world-writable), нотификации мертвы до ручной чистки. Парсинг обязан
    «не бросать» (докстринг) и файл — перезаписаться каноничным видом."""
    state_file = tmp_path / "watchdog.last"
    state_file.write_text(json.dumps({
        "status": "degraded", "failed": [3, "x", "claude-proxy"],
        "notified_failed": [None, "x"], "last_degraded_push": 0.0}, ensure_ascii=False))
    monkeypatch.setattr(health, "WATCHDOG_STATE", state_file)
    monkeypatch.setattr(health, "check_all", lambda **kw: {
        "status": "degraded", "checks": [{"name": "claude-proxy", "ok": False}]})
    monkeypatch.setattr(health, "_notify", lambda msg, sound="Glass": None)
    health.cmd_watchdog()  # не должен бросать
    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert state["failed"] == ["claude-proxy"], \
        "state перезаписан каноничным видом текущего прогона (битый [3,'x'] не зациклил тик)"


def test_watchdog_last_degraded_push_clamped(monkeypatch, tmp_path):
    """P3 (review): nan/inf/отрицательный last_degraded_push из битого state навсегда
    глушат degraded-класс (сравнение с nan всегда False) — кламп в [0, now] → 0,
    уведомление о деградации доставляется."""
    for bad in (float("nan"), float("inf"), -5.0, "garbage"):
        state_file = tmp_path / "watchdog.last"
        state_file.write_text(json.dumps({
            "status": "ok", "failed": [], "notified_failed": [],
            "last_degraded_push": bad}, ensure_ascii=False))
        monkeypatch.setattr(health, "WATCHDOG_STATE", state_file)
        notified = []
        monkeypatch.setattr(health, "check_all", lambda **kw: {
            "status": "degraded", "checks": [{"name": "claude-proxy", "ok": False}]})
        monkeypatch.setattr(health, "_notify", lambda msg, sound="Glass": notified.append(msg))
        monkeypatch.setenv(_COOLDOWN_ENV, "0")
        health.cmd_watchdog()
        assert len(notified) == 1, f"bad last_degraded_push={bad!r} не должен глушить пуш"


def test_watchdog_down_to_degraded_shrinking_set_not_degradation(monkeypatch, tmp_path):
    """P3 (review): down{туннель,privoxy}→degraded{privoxy} — статус УЛУЧШИЛСЯ, набор
    сократился: лейбл «состав ... изменился», не «стек деградировал» (ложное ухудшение)."""
    notified, _, _ = _wd315_watchdog_harness(
        monkeypatch, tmp_path, "degraded", ["privoxy"],
        prev_state={"status": "down", "failed": ["privoxy", "туннель"],
                    "notified_failed": ["privoxy", "туннель"], "last_degraded_push": 0.0},
        env={_COOLDOWN_ENV: "0"})
    health.cmd_watchdog()
    assert len(notified) == 1
    assert "состав" in notified[0][0], "не-ok→не-ok — всегда «состав изменился»"
    assert "деградир" not in notified[0][0], "ложное ухудшение в момент улучшения"


def test_degraded_cooldown_env_parsing_branches(monkeypatch):
    """P3 (review): ветки env-парсера — мусор → дефолт 900, clamp 86400, отрицательные → 0."""
    monkeypatch.delenv(_COOLDOWN_ENV, raising=False)
    assert health._degraded_notify_cooldown_sec() == 900
    monkeypatch.setenv(_COOLDOWN_ENV, "garbage")
    assert health._degraded_notify_cooldown_sec() == 900
    monkeypatch.setenv(_COOLDOWN_ENV, "999999")
    assert health._degraded_notify_cooldown_sec() == 86400
    monkeypatch.setenv(_COOLDOWN_ENV, "-5")
    assert health._degraded_notify_cooldown_sec() == 0
    monkeypatch.setenv(_COOLDOWN_ENV, "120")
    assert health._degraded_notify_cooldown_sec() == 120


def test_watchdog_legacy_state_baselines_notified_set(monkeypatch, tmp_path):
    """F3 (round 3): после legacy-строки первый прогон принимает текущий состав как
    notified-baseline (тихая миграция, канон lifecycle-baseline) — ПОСЛЕДУЮЩИЕ смены
    состава детектятся. Регрессия: notified_failed оставался null навсегда."""
    notified, _, state_file = _wd315_watchdog_harness(
        monkeypatch, tmp_path, "degraded", ["claude-proxy"],
        prev_state="degraded", env={_COOLDOWN_ENV: "0"})
    health.cmd_watchdog()
    assert len(notified) == 0, "legacy prev — тихий baseline"
    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert state["notified_failed"] == ["claude-proxy"], \
        "после миграции notified_failed = текущий состав (baseline), не null"
    # смена состава теперь видна
    monkeypatch.setattr(health, "check_all", lambda **kw: {
        "status": "degraded",
        "checks": [{"name": name, "ok": False} for name in ("claude-proxy", "туннель")]})
    health.cmd_watchdog()
    assert len(notified) == 1
    assert "состав" in notified[0][0]


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


# ============ issue #192: _codenv_managed — маркер в plist НЕДОСТАТОЧЕН, нужен реально-loaded ============
#
# До фикса _codenv_managed() определял managed ТОЛЬКО по маркеру на диске. Stale-plist сценарий
# (codenv когда-то был, bootout без удаления plist) → маркер остаётся, job в launchd уже нет →
# _codenv_managed() всё равно True → _desktop_proxy_check классифицирует ЧУЖОЙ SOCKS5 как info
# вместо down → инцидент #127 молча замаскирован. Фикс: managed = маркер В PLIST И job ЗАГРУЖЕН
# (install_lib._launchd_is_loaded, домен-осознанный `launchctl print`, rc=0 loaded/113 not-found/
# иначе unknown fail-safe). Поверх текущего компромисса (info для активного codenv-SOCKS5, #135) —
# не вместо него: активный codenv по-прежнему должен давать info, не down.

def _write_codenv_plist(tmp_path, monkeypatch, *, with_marker=True):
    plist = tmp_path / "Library" / "LaunchAgents" / f"{health._CODENV_LABEL}.plist"
    plist.parent.mkdir(parents=True)
    body = health._CODENV_MARKER if with_marker else "not-a-marker"
    plist.write_text(body, encoding="utf-8")
    monkeypatch.setattr(health.Path, "home", lambda: tmp_path)


def test_codenv_managed_false_on_stale_plist_marker_present_not_loaded(monkeypatch, tmp_path):
    """Маркер в plist ЕСТЬ, но job НЕ загружен в launchd (rc=113) → False (инцидент #127 не заглушен).

    Stale-plist сценарий: codenv когда-то стоял, потом bootout без удаления plist. Пользователь
    ставит ЧУЖОЙ SOCKS5 вручную. До фикса маркер-на-диске давал managed=True → _desktop_proxy_check
    молчал про чужой SOCKS5 (info вместо down). После фикса — только маркер+loaded=True даёт managed.
    """
    _write_codenv_plist(tmp_path, monkeypatch, with_marker=True)
    runner = lambda cmd, timeout: {"rc": 113, "out": "", "err": "Could not find service",
                                    "timeout": False}
    assert health._codenv_managed(runner=runner) is False


def test_codenv_managed_true_when_marker_and_loaded(monkeypatch, tmp_path):
    """Маркер в plist ЕСТЬ и job загружен (rc=0) → True (канон #135 сохранён — активный codenv видим)."""
    _write_codenv_plist(tmp_path, monkeypatch, with_marker=True)
    runner = lambda cmd, timeout: {"rc": 0, "out": "com.srouter.codenv = { state = running }",
                                    "err": "", "timeout": False}
    assert health._codenv_managed(runner=runner) is True


def test_codenv_managed_false_when_no_plist(monkeypatch, tmp_path):
    """Нет plist вообще → False, независимо от launchd-состояния (как раньше)."""
    monkeypatch.setattr(health.Path, "home", lambda: tmp_path)
    runner = lambda cmd, timeout: {"rc": 0, "out": "", "err": "", "timeout": False}
    assert health._codenv_managed(runner=runner) is False


def test_codenv_managed_false_when_launchctl_unknown(monkeypatch, tmp_path):
    """Маркер в plist ЕСТЬ, но launchctl print timeout/unknown (rc=None) → False (fail-safe).

    Не выдумываем managed=True без доказательства loaded — та же fail-safe семантика, что
    install_lib._launchd_is_loaded: неизвестное состояние НЕ трактуется как «загружен».
    """
    _write_codenv_plist(tmp_path, monkeypatch, with_marker=True)
    runner = lambda cmd, timeout: {"rc": None, "out": "", "err": "timeout", "timeout": True}
    assert health._codenv_managed(runner=runner) is False


def test_codenv_managed_desktop_proxy_down_on_stale_plist_foreign_socks5(monkeypatch, tmp_path):
    """Интеграционный регресс-гард: stale-plist (маркер есть, НЕ loaded) + чужой SOCKS5 → down.

    Фиксирует именно сценарий инцидента #127 из issue #192: до фикса _desktop_proxy_check видел
    маркер на диске и классифицировал чужой SOCKS5 как info (замаскированный инцидент). Мокаем
    sys_probe.run (default runner _codenv_managed без явного runner) — реальная интеграция без
    инъекции, как её увидит _desktop_proxy_check в проде.
    """
    _write_codenv_plist(tmp_path, monkeypatch, with_marker=True)
    monkeypatch.setattr(health.sys_probe, "run",
                        lambda cmd, timeout=3, **kw: {"rc": 113, "out": "", "err": "",
                                                       "timeout": False})
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"HTTPS_PROXY": "socks5h://10.0.0.1:1080"}})
    res = health._desktop_proxy_check()
    assert res["status"] == "down", f"stale-plist + чужой SOCKS5 → down (#127); got {res}"


def test_codenv_managed_desktop_proxy_info_when_actually_loaded(monkeypatch, tmp_path):
    """Интеграционный гард канона #135: маркер + реально loaded → info, не down."""
    _write_codenv_plist(tmp_path, monkeypatch, with_marker=True)
    monkeypatch.setattr(health.sys_probe, "run",
                        lambda cmd, timeout=3, **kw: {"rc": 0, "out": "state = running",
                                                       "err": "", "timeout": False})
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"ALL_PROXY": "socks5h://127.0.0.1:10808"}})
    res = health._desktop_proxy_check()
    assert res["status"] == "info", f"активный codenv (loaded) → info (канон #135); got {res}"


def test_codenv_managed_true_does_not_mask_foreign_socks_value(monkeypatch, tmp_path):
    """Codex (cycle-review PR #219, confidence 0.93): codenv loaded И managed — НЕ означает, что
    ЛЮБОЕ SOCKS5-значение в launchctl принадлежит codenv. `launchctl print gui/<uid>/com.srouter.codenv`
    rc=0 доказывает только «job с этим label зарегистрирован», не то, что ИМЕННО он записал
    конкретное значение, найденное в _read_proxy_sources() непосредственно перед вызовом.

    Сценарий: codenv загружен (managed=True), но КТО-ТО ДРУГОЙ параллельно прописал чужой SOCKS5
    в тот же launchctl gui-домен ключ (10.0.0.1:1080, не codenv-эндпоинт 127.0.0.1:10808) — тот же
    класс инцидента #127, который расширяет заявленный fix issue #192. До этого теста
    _desktop_proxy_check доверял ГОЛОМУ факту codenv-managed без сверки конкретного SOCKS5-значения
    с известным codenv endpoint (dashboard_common.SOCKS_PROXY_URL) → down.
    """
    _write_codenv_plist(tmp_path, monkeypatch, with_marker=True)
    monkeypatch.setattr(health.sys_probe, "run",
                        lambda cmd, timeout=3, **kw: {"rc": 0, "out": "state = running",
                                                       "err": "", "timeout": False})
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {"HTTPS_PROXY": "socks5h://10.0.0.1:1080"}})
    res = health._desktop_proxy_check()
    assert res["status"] == "down", (
        f"codenv managed=True, НО SOCKS5-значение чужое (не codenv endpoint) → down "
        f"(инцидент #127 не должен маскироваться просто фактом codenv-loaded); got {res}")


def test_codenv_managed_true_mixed_keys_one_foreign_still_down(monkeypatch, tmp_path):
    """Mutation-гард: ОДИН ключ = настоящий codenv endpoint, ДРУГОЙ — чужой SOCKS5 → down.

    Различает `all(...)` (корректно: down, т.к. не ВСЕ ключи codenv) от `any(...)` (баг: любое
    совпадение хотя бы одного ключа с codenv-endpoint дало бы info, замаскировав чужой ключ рядом).
    """
    _write_codenv_plist(tmp_path, monkeypatch, with_marker=True)
    monkeypatch.setattr(health.sys_probe, "run",
                        lambda cmd, timeout=3, **kw: {"rc": 0, "out": "state = running",
                                                       "err": "", "timeout": False})
    monkeypatch.setattr(health, "_read_proxy_sources",
                        lambda: {"desktop_keys": {
                            "HTTPS_PROXY": "socks5h://127.0.0.1:10808",  # настоящий codenv
                            "ALL_PROXY": "socks5h://10.0.0.1:1080",      # чужой
                        }})
    res = health._desktop_proxy_check()
    assert res["status"] == "down", (
        f"один ключ codenv, другой чужой → down (all(), не any()); got {res}")


# ============ Codex round 2 (cycle-review PR #219, confidence 0.96): _read_proxy_sources domain ==========
#
# _read_proxy_sources() читала Desktop-ключи через голый `launchctl getenv KEY` — caller-context
# домен, НЕ gui/<uid> (тот же класс бага, что issue #191/_read_gui_proxy_env docstring). Из SSH/cron/
# AO-shell getenv отвечает НЕ из gui-домена → сравнение SOCKS5-значения с _CODENV_SOCKS_URL (round-2
# фикс) могло сверяться с НЕ тем значением, что реально видит Desktop App. Фикс: _read_proxy_sources
# делегирует Desktop-ключи в _read_gui_proxy_env() (`launchctl print gui/<uid>`, тот же домен-осознанный
# источник, что _codenv_managed уже использует) — единая точка домена для всей проверки codenv-trust.

def test_read_proxy_sources_uses_gui_domain_not_caller_getenv(monkeypatch):
    """_read_proxy_sources() читает Desktop-ключи через _read_gui_proxy_env (domain-aware), а НЕ
    через голый `launchctl getenv` (caller-context, может отличаться от gui/<uid> в SSH/cron/AO-shell).
    """
    monkeypatch.setattr(health, "_read_gui_proxy_env",
                        lambda **kw: {"keys": {"HTTPS_PROXY": "http://127.0.0.1:8118"}, "verifiable": True})
    src = health._read_proxy_sources()
    assert src["desktop_keys"] == {"HTTPS_PROXY": "http://127.0.0.1:8118"}


def test_read_proxy_sources_unverifiable_gui_domain_gives_empty_keys(monkeypatch):
    """launchctl print gui/<uid> недоступен (timeout/unknown domain) → desktop_keys пуст, НЕ выдумываем
    значения из caller-context getenv (fail-closed, тот же канон что _read_gui_proxy_env)."""
    monkeypatch.setattr(health, "_read_gui_proxy_env",
                        lambda **kw: {"keys": {}, "verifiable": False})
    src = health._read_proxy_sources()
    assert src["desktop_keys"] == {}


def test_desktop_proxy_domain_mismatch_does_not_certify_foreign_socks_as_codenv(monkeypatch, tmp_path):
    """Интеграционный регресс-гард на сам Codex round-2 finding: codenv managed=True (gui-домен
    подтверждён через launchctl print), НО launchctl print gui/<uid> ДЛЯ ПРОКСИ-КЛЮЧЕЙ показывает
    чужой SOCKS5 (10.0.0.1:1080, не codenv endpoint) — должно быть down, а не info.

    До фикса _read_proxy_sources брала это же значение из caller-context getenv, что в общем случае
    может НЕ совпадать с тем, что реально в gui-домене — теперь оба чтения (_codenv_managed И
    desktop-ключи) идут через один и тот же domain-aware `launchctl print gui/<uid>` источник.
    """
    _write_codenv_plist(tmp_path, monkeypatch, with_marker=True)
    monkeypatch.setattr(health.sys_probe, "run",
                        lambda cmd, timeout=3, **kw: {"rc": 0, "out": "state = running",
                                                       "err": "", "timeout": False})
    monkeypatch.setattr(health, "_read_gui_proxy_env",
                        lambda **kw: {"keys": {"HTTPS_PROXY": "socks5h://10.0.0.1:1080"}, "verifiable": True})
    res = health._desktop_proxy_check()
    assert res["status"] == "down", (
        f"gui-домен показывает чужой SOCKS5 (не codenv) → down, даже если codenv managed=True; got {res}")


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
    monkeypatch.setattr(health, "_read_gui_proxy_env", lambda **kw: {"keys": {}, "verifiable": True})
    src = health._read_proxy_sources()
    assert src["cli_proxy"] == "http://127.0.0.1:8118"


# --- _read_proxy_sources: контракт обхода launchctl-ключей (мокаем _read_gui_proxy_env, domain-aware
# `launchctl print gui/<uid>` — cycle-review PR #219 round 2, не голый per-key getenv) ---

def test_read_proxy_sources_reads_all_three_launchctl_keys(monkeypatch):
    """HTTPS_PROXY пуст (нет ключа), HTTP_PROXY=socks5h → desktop_keys содержит SOCKS5 (не теряется).

    ДЫРА на upstream: _read_proxy_sources читал только HTTPS_PROXY → терял SOCKS5 в HTTP_PROXY.
    """
    monkeypatch.setattr(health, "_read_gui_proxy_env",
                        lambda **kw: {"keys": {"HTTP_PROXY": "socks5h://127.0.0.1:10808"},
                                      "verifiable": True})
    src = health._read_proxy_sources()
    assert "HTTP_PROXY" in src["desktop_keys"]
    assert "socks" in src["desktop_keys"]["HTTP_PROXY"].lower(), f"SOCKS5 в HTTP_PROXY потерян: {src}"


def test_read_proxy_sources_collects_all_set_keys(monkeypatch):
    """Все три ключа заданы → все три в desktop_keys (показываем «как есть»)."""
    vals = {"HTTPS_PROXY": "http://127.0.0.1:8118",
            "HTTP_PROXY": "http://127.0.0.1:8118",
            "ALL_PROXY": "http://127.0.0.1:8118"}
    monkeypatch.setattr(health, "_read_gui_proxy_env",
                        lambda **kw: {"keys": dict(vals), "verifiable": True})
    src = health._read_proxy_sources()
    assert set(src["desktop_keys"]) == {"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"}


def test_read_proxy_sources_ignores_launchctl_timeout(monkeypatch):
    """launchctl print gui/<uid> не верифицируем (timeout/unknown domain) → desktop_keys пуст (fail-closed).

    Timeout не должен давать ложный SOCKS5 или падение.
    """
    monkeypatch.setattr(health, "_read_gui_proxy_env", lambda **kw: {"keys": {}, "verifiable": False})
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
    monkeypatch.setattr(health, "_codex_isolation_check", _REAL_CODEX_ISOLATION_CHECK)  # #271: real fn

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
    monkeypatch.setattr(health, "_codex_isolation_check", _REAL_CODEX_ISOLATION_CHECK)  # #271: real fn
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


def test_endpoint_xray_sync_check_no_active_is_not_reported_as_fresh_install(tmp_path):
    """#200 regression: xray config СУЩЕСТВУЕТ, но без tag=active → НЕ "fresh install" враньё.

    Реальный сценарий (verify-dont-guess, воспроизведено на живой машине): рабочий xray config
    существует и валиден, но outbound назван "reality-out" (не сгенерирован через gen_xray_config
    с его контрактом tag="active" — сторонний/устаревший конфиг). read_xray_active_address тогда
    отдаёт xray_status="no_active" (НЕ "absent"), но _endpoint_xray_sync_check раньше сворачивал
    оба случая в один текст через `if not xray:` (xray == "" для обоих), маскируя реальность
    "config есть, но не тот тег" под "конфига вообще нет (fresh install)".
    """
    state_p = tmp_path / "srouter.local.json"
    xray_p = tmp_path / "xray-config.json"
    state_p.write_text(json.dumps({
        "nodes": [{"name": "sg-1", "endpoint_host": "203.0.113.10",
                   "route_ip": "203.0.113.10", "enabled": True}],
        "active_node": {"name": "sg-1", "pending": None},
    }), encoding="utf-8")
    # outbound БЕЗ tag="active" (реальный tag="reality-out") — xray_status станет "no_active".
    xray_p.write_text(json.dumps({"outbounds": [
        {"tag": "reality-out", "protocol": "vless",
         "settings": {"vnext": [{"address": "85.136.181.198", "port": 443}]}},
        {"tag": "direct", "protocol": "freedom"},
    ]}), encoding="utf-8")

    chk = health._endpoint_xray_sync_check(state_path=str(state_p), xray_config_path=str(xray_p))
    assert chk["status"] == "warn", chk
    detail = chk["detail"].lower()
    assert "fresh install" not in detail, (
        f"конфиг СУЩЕСТВУЕТ (просто без tag=active) — 'fresh install' здесь ложь: {chk['detail']}"
    )
    # Точная формулировка ветки no_active — не соседняя ветка "оба реальных, но разные" (mutation:
    # если сравнение xray_status=="no_active" сломать тайпо, выполнение проваливается в generic
    # "рассинхрон... оба реальные" ветку — тоже без "fresh install", но БЕЗ "tag=active" в тексте).
    assert "tag=active" in detail, f"detail должен явно называть отсутствующий tag=active: {chk['detail']}"
    assert "рассинхрон" not in detail, (
        f"это НЕ generic-рассинхрон ветка (оба реальных адреса) — это специфичная no_active: {chk['detail']}"
    )


def test_endpoint_xray_sync_check_unreadable_is_not_reported_as_fresh_install(tmp_path):
    """#200 regression: xray config СУЩЕСТВУЕТ, но битый (не JSON) → НЕ "fresh install" враньё."""
    state_p = tmp_path / "srouter.local.json"
    xray_p = tmp_path / "xray-config.json"
    state_p.write_text(json.dumps({
        "nodes": [{"name": "sg-1", "endpoint_host": "203.0.113.10",
                   "route_ip": "203.0.113.10", "enabled": True}],
        "active_node": {"name": "sg-1", "pending": None},
    }), encoding="utf-8")
    xray_p.write_text("{not valid json", encoding="utf-8")

    chk = health._endpoint_xray_sync_check(state_path=str(state_p), xray_config_path=str(xray_p))
    assert chk["status"] == "warn", chk
    detail = chk["detail"].lower()
    assert "fresh install" not in detail, (
        f"конфиг СУЩЕСТВУЕТ (просто битый) — 'fresh install' здесь ложь: {chk['detail']}"
    )
    assert "повреждён" in detail or "не парсится" in detail or "unreadable" in detail
    # Отличается от no_active-ветки (не про tag=active) и от generic-рассинхрон ветки.
    assert "tag=active" not in detail, f"unreadable — не про отсутствующий тег: {chk['detail']}"
    assert "рассинхрон" not in detail, f"unreadable — не generic-рассинхрон: {chk['detail']}"


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


# ============================ heartbeat-метрики туннеля (timing из curl -w) ============================
# Watchdog каждые ~20с УЖЕ шлёт curl через туннель; теперь из того же ответа достаётся
# разложение времени (connect/TLS/TTFB/total) и пишется в metrics_store JSONL с
# интервалом probes.metrics_interval_sec. Ноль дополнительного сетевого трафика.

def _timing_curl(out):
    """Мок sys_probe.run: curl -w печатает заданную строку (код + 4 тайминга в секундах)."""
    return lambda cmd, timeout: {"rc": 0, "out": out, "err": "", "timeout": False}


def test_tunnel_target_up_returns_four_tuple_contract(monkeypatch):
    """Контракт 4-tuple: без таймингов (no-response) timing — dict с None-мс, не None."""
    monkeypatch.setattr(health.sys_probe, "run", _timing_curl(""))
    ok, detail, kind, timing = health._tunnel_target_up("https://api.anthropic.com/")
    assert ok is False
    assert kind == "no-response"
    assert timing["status"] == "no-response"
    assert timing["total_ms"] is None


def test_tunnel_target_up_timing_ok_path(monkeypatch):
    monkeypatch.setattr(health.sys_probe, "run", _timing_curl("200 0.012 0.045 0.120 0.260"))
    ok, detail, kind, timing = health._tunnel_target_up("https://api.anthropic.com/")
    assert ok is True
    assert kind == "ok"
    assert timing["target"] == "api.anthropic.com"
    assert timing["code"] == "200"
    assert timing["status"] == "ok"
    assert timing["connect_ms"] == 12
    assert timing["tls_ms"] == 33       # appconnect − connect = 45 − 12
    assert timing["ttfb_ms"] == 75      # starttransfer − appconnect = 120 − 45
    assert timing["total_ms"] == 260


def test_tunnel_target_up_timing_partial_on_failure(monkeypatch):
    """connection-failed (000) может нести частичные тайминги — ms-поля None, не мусор."""
    monkeypatch.setattr(health.sys_probe, "run", _timing_curl("000 0.001"))
    ok, detail, kind, timing = health._tunnel_target_up("https://api.anthropic.com/")
    assert ok is False
    assert kind == "connection-failed"
    assert timing["status"] == "connection-failed"
    assert timing["connect_ms"] == 1
    assert timing["tls_ms"] is None
    assert timing["total_ms"] is None


def test_tunnel_target_up_timing_includes_rc_err(monkeypatch):
    """#315 п.5: rc/err пробы попадают в timing → metrics-события. Сигнатуры отказов
    (#301 матрица: exit 56/35/28 ↔ xray-мёртв/узел-отказ/узел-висит) собираются
    ProbeManager.run, но до сих пор отбрасывались — ретроспективная классификация
    провалов по логам была невозможна."""
    monkeypatch.setattr(health.sys_probe, "run", lambda cmd, timeout: {
        "rc": 28, "out": "000 0.001",
        "err": "curl: (28) Connection timed out after 4001 milliseconds", "timeout": False})
    ok, detail, kind, timing = health._tunnel_target_up("https://api.anthropic.com/")
    assert ok is False
    assert kind == "connection-failed"
    assert timing["rc"] == 28
    assert "4001" in timing["err"]


def test_tunnel_target_up_timing_minimum_on_probe_timeout(monkeypatch):
    """Probe-timeout (процесс убит до -w): timing — минимум {status:timeout, rc/err},
    не None (#315 round 2 / Codex P2-4): именно timeout-класс терял причину — fallback
    metrics писал {"status":"down"} без err. Теперь build_event видит rc/err и timeout."""
    monkeypatch.setattr(health.sys_probe, "run",
                        lambda cmd, timeout: {"rc": None, "out": "",
                                              "err": "curl: operation timed out\ntimeout",
                                              "timeout": True})
    ok, detail, kind, timing = health._tunnel_target_up("https://api.anthropic.com/")
    assert ok is False
    assert kind == "timeout"
    assert timing["status"] == "timeout"
    assert timing["rc"] is None
    assert "timeout" in timing["err"]
    assert timing["target"] == "api.anthropic.com", \
        "контракт metrics: target — hostname (Codex F2 round 3), не полный URL"
    ev = metrics_store.build_event(timing, now=1700000000.0)
    assert ev["status"] == "timeout"
    assert ev["err"] is not None


def test_tunnel_up_keeps_first_target_timing_for_series(monkeypatch):
    """timing всегда от ПЕРВОГО таргета — стабильная серия, даже когда up по второму."""
    def fake_run(cmd, timeout):
        url = cmd[-1] if cmd else ""
        if "anthropic" in url:
            return {"rc": 0, "out": "503 0.010 0.050 0.060 0.080", "err": "", "timeout": False}
        return {"rc": 0, "out": "200 0.009 0.030 0.040 0.050", "err": "", "timeout": False}
    monkeypatch.setattr(health.sys_probe, "run", fake_run)
    ok, detail, vendor, timing = health._tunnel_up()
    assert ok is True
    assert timing["target"] == "api.anthropic.com"
    assert timing["code"] == "503"


def test_check_all_carries_tunnel_timing(monkeypatch):
    """timing доезжает до check-дикта туннеля — consumer (watchdog) не парсит detail."""
    _all_up_monkey(monkeypatch)
    monkeypatch.setattr(health, "_tunnel_up",
                        lambda: (True, "HTTP 200", False,
                                 {"target": "api.anthropic.com", "code": "200", "status": "ok",
                                  "connect_ms": 1, "tls_ms": 40, "ttfb_ms": 60, "total_ms": 150}))
    result = health.check_all()
    tun = next(c for c in result["checks"] if c["name"].startswith("туннель"))
    assert tun["timing"]["total_ms"] == 150


def test_check_all_tunnel_check_carries_structural_id(monkeypatch):
    """check_all обязан ставить id="tunnel": consumer'ы находят чек по структурному
    ключу, а не по префиксу человекочитаемого name (переименование метки не должно
    тихо ломать потребителя — канон loose-validator-recurring-leak)."""
    monkeypatch.setattr(health, "_port_up", lambda port: True)
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200", False, None))
    result = health.check_all(active_claude=False)
    assert any(c.get("id") == "tunnel" for c in result["checks"])


# ============================ _metrics_probe_options ============================

def _mock_state(monkeypatch, probes):
    import local_state
    monkeypatch.setattr(local_state, "load_state", lambda path=None: {"probes": probes})


def test_metrics_probe_options_defaults(monkeypatch):
    _mock_state(monkeypatch, {})
    opts = health._metrics_probe_options()
    assert opts == {"enabled": True, "interval_sec": 60, "retention_days": 7}


def test_metrics_probe_options_respects_config(monkeypatch):
    _mock_state(monkeypatch, {"metrics_enabled": False, "metrics_interval_sec": 300,
                              "metrics_retention_days": 3})
    opts = health._metrics_probe_options()
    assert opts == {"enabled": False, "interval_sec": 300, "retention_days": 3}


def test_metrics_probe_options_clamps_garbage(monkeypatch):
    _mock_state(monkeypatch, {"metrics_interval_sec": 1, "metrics_retention_days": 0})
    opts = health._metrics_probe_options()
    assert opts["interval_sec"] == 20      # чаще watchdog-тика (~20с) бессмысленно
    assert opts["retention_days"] == 1


# ============================ _record_watchdog_metrics ============================

def _metrics_env(monkeypatch, tmp_path, probes=None):
    """Мок окружения записи метрик: state-файл + JSONL в tmp, конфиг probes."""
    import local_state
    monkeypatch.setattr(health, "WATCHDOG_METRICS_STATE", tmp_path / "metrics.last.json")
    monkeypatch.setattr(health.metrics_store, "METRICS_LOG", tmp_path / "metrics.jsonl")
    _mock_state(monkeypatch, probes if probes is not None else {})
    # legacy-блок lifecycle не нужен: _record_watchdog_lifecycle закрыт autouse-фикстурой
    _ = local_state


def _tunnel_result(timing=None, ok=True):
    # id — структурный ключ чека: consumer находит туннель по нему, а не по префиксу
    # человекочитаемого name (переименование строки не должно гасить метрики).
    check = {"id": "tunnel", "name": "туннель (api.anthropic.com через прокси)", "ok": ok,
             "detail": "HTTP 200", "timing": timing}
    return {"status": "ok" if ok else "down", "checks": [check]}


def test_record_watchdog_metrics_writes_timing_event(monkeypatch, tmp_path):
    _metrics_env(monkeypatch, tmp_path)
    health._record_watchdog_metrics(_tunnel_result(
        timing={"target": "api.anthropic.com", "code": "200", "status": "ok",
                "connect_ms": 1, "tls_ms": 40, "ttfb_ms": 60, "total_ms": 150}))
    import metrics_store
    events = metrics_store.read_timing_events(log_path=tmp_path / "metrics.jsonl")
    assert len(events) == 1
    assert events[0]["total_ms"] == 150
    assert events[0]["status"] == "ok"
    assert (tmp_path / "metrics.last.json").exists()


def test_record_watchdog_metrics_throttles_by_interval(monkeypatch, tmp_path):
    _metrics_env(monkeypatch, tmp_path, probes={"metrics_interval_sec": 3600})
    res = _tunnel_result(timing={"status": "ok", "total_ms": 100})
    health._record_watchdog_metrics(res)
    health._record_watchdog_metrics(res)
    import metrics_store
    events = metrics_store.read_timing_events(log_path=tmp_path / "metrics.jsonl")
    assert len(events) == 1, "внутри interval_sec повторная запись подавлена"


def test_record_watchdog_metrics_down_event_without_timing(monkeypatch, tmp_path):
    """timing None (curl убит таймаутом) — фиксируем статус провала: failure_rate окна
    обязан видеть и падения, не только выжившие замеры."""
    _metrics_env(monkeypatch, tmp_path)
    health._record_watchdog_metrics(_tunnel_result(timing=None, ok=False))
    import metrics_store
    events = metrics_store.read_timing_events(log_path=tmp_path / "metrics.jsonl")
    assert len(events) == 1
    assert events[0]["status"] == "down"
    assert events[0]["total_ms"] is None


def test_record_watchdog_metrics_finds_tunnel_by_id_not_name(monkeypatch, tmp_path):
    """Туннель ищется по структурному id, а не по префиксу name: переименование
    (или i18n) человекочитаемой строки не должно тихо гасить запись метрик."""
    _metrics_env(monkeypatch, tmp_path)
    res = _tunnel_result(timing={"status": "ok", "total_ms": 111})
    res["checks"][0]["name"] = "tunnel (renamed label)"
    health._record_watchdog_metrics(res)
    import metrics_store
    events = metrics_store.read_timing_events(log_path=tmp_path / "metrics.jsonl")
    assert len(events) == 1 and events[0]["total_ms"] == 111


def test_record_watchdog_metrics_disabled_writes_nothing(monkeypatch, tmp_path):
    _metrics_env(monkeypatch, tmp_path, probes={"metrics_enabled": False})
    health._record_watchdog_metrics(_tunnel_result(timing={"status": "ok"}))
    assert not (tmp_path / "metrics.jsonl").exists()


def test_record_watchdog_metrics_never_raises(monkeypatch, tmp_path):
    _metrics_env(monkeypatch, tmp_path)
    monkeypatch.setattr(health.metrics_store, "append_timing_event",
                        lambda event, log_path=None: (_ for _ in ()).throw(OSError("disk full")))
    health._record_watchdog_metrics(_tunnel_result(timing={"status": "ok"}))  # не бросает


def test_cmd_watchdog_records_metrics(monkeypatch, tmp_path):
    """Интеграция: cmd_watchdog после check_all пишет метрику (best-effort, без мока
    check_all упадёт на сетевых пробах — мокаем целиком, как transition-тесты)."""
    _metrics_env(monkeypatch, tmp_path)
    monkeypatch.setattr(health, "check_all",
                        lambda **kw: _tunnel_result(timing={"status": "ok", "total_ms": 120}))
    monkeypatch.setattr(health, "WATCHDOG_STATE", tmp_path / "watchdog.last")
    monkeypatch.setattr(health, "_notify", lambda msg, sound="Glass": None)
    health.cmd_watchdog()
    health.cmd_watchdog()  # второй тик — внутри интервала, записи нет
    import metrics_store
    events = metrics_store.read_timing_events(log_path=tmp_path / "metrics.jsonl")
    assert len(events) == 1
