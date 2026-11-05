"""TDD: doctor covers ChatGPT.app Chromium via active macOS system SOCKS."""
import health
import system_proxy_control


NETWORK_PROCESS = (
    "96016 /Applications/ChatGPT.app/Contents/Frameworks/Codex Framework.framework/Versions/"
    "151/Helpers/Codex (Service).app/Contents/MacOS/Codex (Service) "
    "--type=utility --utility-sub-type=network.mojom.NetworkService\n"
)
GPU_PROCESS = (
    "96015 /Applications/ChatGPT.app/Contents/Frameworks/Codex Framework.framework/Versions/"
    "151/Helpers/Codex (Service).app/Contents/MacOS/Codex (Service) --type=gpu-process\n"
)


def _run(ps_out, lsof_out=""):
    def fake(cmd, timeout):
        if cmd[0] == "/bin/ps":
            return {"rc": 0, "out": ps_out, "err": "", "timeout": False}
        if cmd[0] == "/usr/sbin/lsof":
            return {"rc": 0, "out": lsof_out, "err": "", "timeout": False}
        return {"rc": 1, "out": "", "err": "unexpected", "timeout": False}
    return fake


def _route(pid, target):
    return (f"Codex\\x20 {pid} axisrow 60u IPv4 0xABC 0t0 "
            f"TCP 127.0.0.1:55689->{target} (ESTABLISHED)\n")


def _status(*, enabled):
    return {
        "status": "ok", "service": "Wi-Fi", "interface": "en0", "target": enabled,
        "socks": {"enabled": enabled, "server": "127.0.0.1", "port": 10808,
                  "authenticated": False},
    }


def test_chromium_check_reports_disabled_wifi_socks_as_root_cause(monkeypatch):
    monkeypatch.setattr(health.sys_probe, "run", _run(NETWORK_PROCESS, _route("96016", "8.8.8.8:443")))
    monkeypatch.setattr(system_proxy_control, "status", lambda: _status(enabled=False))
    res = health._codex_app_chromium_proxy_check()
    assert res["status"] == "down"
    assert "Wi-Fi" in res["detail"]
    assert "system-proxy repair" in res["detail"]
    assert "codex-app-proxy" not in res["detail"]
    assert "перезапуст" not in res["detail"].lower()


def test_chromium_check_ok_with_system_socks_and_runtime_evidence(monkeypatch):
    monkeypatch.setattr(health.sys_probe, "run",
                        _run(NETWORK_PROCESS, _route("96016", "127.0.0.1:10808")))
    monkeypatch.setattr(system_proxy_control, "status", lambda: _status(enabled=True))
    res = health._codex_app_chromium_proxy_check()
    assert res["status"] == "ok"


def test_chromium_check_still_down_if_configured_but_runtime_direct(monkeypatch):
    monkeypatch.setattr(health.sys_probe, "run", _run(NETWORK_PROCESS, _route("96016", "8.8.8.8:443")))
    monkeypatch.setattr(system_proxy_control, "status", lambda: _status(enabled=True))
    res = health._codex_app_chromium_proxy_check()
    assert res["status"] == "down"
    assert "напрямую" in res["detail"].lower()
    assert "codex-app-proxy" not in res["detail"]


NETWORK_PROCESS_2 = (
    "96017 /Applications/ChatGPT.app/Contents/Frameworks/Codex Framework.framework/Versions/"
    "151/Helpers/Codex (Service).app/Contents/MacOS/Codex (Service) "
    "--type=utility --utility-sub-type=network.mojom.NetworkService\n"
)


def test_chromium_check_down_when_one_network_pid_socks_and_other_external(monkeypatch):
    """codex-review (Codex rescue, PR #314): два NetworkService PID одновременно (перезапуск/апдейт
    App) — один держит SOCKS5, другой течёт external напрямую. Наличие ЛЮБОГО socks-сокета не должно
    маскировать реальный direct-leak другого PID (mixed → down, не ok)."""
    ps_out = NETWORK_PROCESS + NETWORK_PROCESS_2
    lsof_out = _route("96016", "127.0.0.1:10808") + _route("96017", "8.8.8.8:443")
    monkeypatch.setattr(health.sys_probe, "run", _run(ps_out, lsof_out))
    monkeypatch.setattr(system_proxy_control, "status", lambda: _status(enabled=True))
    res = health._codex_app_chromium_proxy_check()
    assert res["status"] == "down", (
        f"один PID external ДОЛЖЕН давать down, даже если другой PID через SOCKS5; got {res}"
    )


def test_chromium_check_does_not_claim_system_socks_correct_when_status_unverified(monkeypatch):
    """codex-review (Codex adversarial-review, PR #314): external-leak доказан, но
    system_proxy_control.status() вернул unknown (route/networksetup не читаются) — старый fallback
    безусловно утверждал 'системный SOCKS настроен корректно', скрывая совет 'system-proxy repair'
    именно на пути, где сам status() не смог ничего проверить.
    """
    monkeypatch.setattr(health.sys_probe, "run", _run(NETWORK_PROCESS, _route("96016", "8.8.8.8:443")))
    monkeypatch.setattr(system_proxy_control, "status",
                        lambda: {"status": "unknown", "target": False, "socks": None,
                                 "detail": "нет активного default route"})
    res = health._codex_app_chromium_proxy_check()
    assert res["status"] == "down"
    assert "настроен корректно" not in res["detail"].lower(), (
        f"detail ложно заявляет, что системный SOCKS настроен корректно, хотя status() не смог "
        f"это подтвердить (unknown); got {res}"
    )


def test_non_network_chromium_helpers_are_ignored(monkeypatch):
    monkeypatch.setattr(health.sys_probe, "run", _run(GPU_PROCESS, _route("96015", "8.8.8.8:443")))
    monkeypatch.setattr(system_proxy_control, "status",
                        lambda: (_ for _ in ()).throw(AssertionError("must not inspect system proxy")))
    res = health._codex_app_chromium_proxy_check()
    assert res["status"] == "unknown"


# ============ Эффективный снапшот + ps-argv (контракт владельца 2026-11-05) ============
# ChatGPT.app = группа Claude.app: только 10808, никогда direct. При NE-VPN primary
# (HitVPN/VeePN ephemeral) scutil-снапшот ПУСТ, а именные network service могут честно
# показывать target=True — Chromium всё равно уходит direct (пустой снапшот). Запуск из
# Dock не передаёт --proxy-server. Вердикт: пустой снапшот + запуск без флага = direct
# (down) с рецептом «обёртка ~/bin/codex-app-proxy или srouter wrappers codex-app install»,
# а не ok/repair-совет по именным сервисам.
EMPTY_SNAPSHOT = ("<dictionary> {\n  HTTPEnable : 0\n  HTTPSEnable : 0\n  SOCKSEnable : 0\n"
                  "  ProxyAutoConfigEnable : 0\n}\n")
FILLED_SNAPSHOT = ("<dictionary> {\n  HTTPEnable : 0\n  HTTPSEnable : 0\n  SOCKSEnable : 1\n"
                   "  SOCKSProxy : 127.0.0.1\n  SOCKSPort : 10808\n"
                   "  ProxyAutoConfigEnable : 0\n}\n")
MAIN_NOFLAG = "900 /Applications/ChatGPT.app/Contents/MacOS/ChatGPT\n"
MAIN_FLAG = ("900 /Applications/ChatGPT.app/Contents/MacOS/ChatGPT "
             "--proxy-server=socks5://127.0.0.1:10808\n")


def _run_snap(ps_out, lsof_out="", scutil_out=EMPTY_SNAPSHOT, scutil_timeout=False):
    def fake(cmd, timeout):
        if cmd[0] == "/bin/ps":
            return {"rc": 0, "out": ps_out, "err": "", "timeout": False}
        if cmd[0] == "/usr/sbin/lsof":
            return {"rc": 0, "out": lsof_out, "err": "", "timeout": False}
        if cmd[0] == "/usr/sbin/scutil":
            if scutil_timeout:
                return {"rc": None, "out": "", "err": "timeout", "timeout": True}
            return {"rc": 0, "out": scutil_out, "err": "", "timeout": False}
        return {"rc": 1, "out": "", "err": "unexpected", "timeout": False}
    return fake


def test_direct_verdict_when_snapshot_empty_and_no_flag(monkeypatch):
    """Пустой снапшот (scutil: ни одного прокси, NE-VPN-класс) + запуск без --proxy-server →
    down DIRECT с рецептом «обёртка / codex-app install», НЕ ok и НЕ repair-совет по именным
    сервисам — даже когда system_proxy_control показывает target=True (именные сервисы
    настроены, но снапшот пуст → Chromium идёт мимо них)."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _run_snap(NETWORK_PROCESS + MAIN_NOFLAG,
                                  _route("96016", "8.8.8.8:443")))
    monkeypatch.setattr(system_proxy_control, "status", lambda: _status(enabled=True))
    res = health._codex_app_chromium_proxy_check()
    assert res["status"] == "down", f"пустой снапшот + без флага = direct → down; got {res}"
    detail = res["detail"].lower()
    assert "codex-app-proxy" in detail, f"рецепт — обёртка: {res}"
    assert "codex-app install" in detail, f"рецепт — Dock-launcher: {res}"
    assert "system-proxy repair" not in detail, \
        f"repair именных сервисов пустой снапшот не чинит; got {res}"


def test_direct_verdict_without_route_evidence(monkeypatch):
    """Пустой снапшот + без флага → down даже без lsof-доказательства (idle): конфигурация
    детерминирована — Chromium с пустым снапшотом и без флага пойдёт direct на первом
    запросе. Config-level evidence, а не wall-clock (канон wall-clock-assert-is-not-the-invariant)."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _run_snap(NETWORK_PROCESS + MAIN_NOFLAG, lsof_out=""))
    monkeypatch.setattr(system_proxy_control, "status", lambda: _status(enabled=True))
    res = health._codex_app_chromium_proxy_check()
    assert res["status"] == "down", f"пустой снапшот + без флага → down без lsof; got {res}"
    assert "codex-app" in res["detail"].lower(), f"рецепт в detail: {res}"


def test_flag_present_on_empty_snapshot_routes_normally(monkeypatch):
    """Пустой снапшот, но процесс несёт --proxy-server (launcher/обёртка) → ветка не стреляет,
    вердикт по маршруту: SOCKS5 → ok."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _run_snap(NETWORK_PROCESS + MAIN_FLAG,
                                  _route("96016", "127.0.0.1:10808")))
    monkeypatch.setattr(system_proxy_control, "status", lambda: _status(enabled=True))
    res = health._codex_app_chromium_proxy_check()
    assert res["status"] == "ok", f"флаг есть + маршрут SOCKS5 → ok; got {res}"


def test_filled_snapshot_keeps_named_service_branch(monkeypatch):
    """Снапшот НЕ пуст (SOCKS включён) + без флага + external → прежняя ветка именных
    сервисов (system-proxy repair), новая direct-ветка не стреляет."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _run_snap(NETWORK_PROCESS + MAIN_NOFLAG,
                                  _route("96016", "8.8.8.8:443"),
                                  scutil_out=FILLED_SNAPSHOT))
    monkeypatch.setattr(system_proxy_control, "status", lambda: _status(enabled=False))
    res = health._codex_app_chromium_proxy_check()
    assert res["status"] == "down", f"SOCKS выключен при непустом снапшоте → down; got {res}"
    assert "system-proxy repair" in res["detail"], f"прежний рецепт сохранён: {res}"


def test_snapshot_unknown_falls_back_to_route_branches(monkeypatch):
    """scutil не ответил (timeout) → снапшот нечитаем: fail-closed, новой ветки нет, прежняя
    логика по lsof + именным сервисам (НЕ false-direct на нечитаемом источнике)."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _run_snap(NETWORK_PROCESS + MAIN_NOFLAG,
                                  _route("96016", "8.8.8.8:443"),
                                  scutil_timeout=True))
    monkeypatch.setattr(system_proxy_control, "status", lambda: _status(enabled=False))
    res = health._codex_app_chromium_proxy_check()
    assert res["status"] == "down"
    assert "system-proxy repair" in res["detail"], f"fallback на прежнюю ветку: {res}"
    assert "codex-app install" not in res["detail"], \
        f"launcher-рецепт на нечитаемом снапшоте — ложный диагноз; got {res}"


def test_check_all_wires_chromium_system_proxy_as_doctor_driver(monkeypatch):
    monkeypatch.setattr(health, "_codex_app_chromium_proxy_check",
                        lambda: {"status": "down", "detail": "Wi-Fi SOCKS выключен"})
    monkeypatch.setattr(health, "_codex_app_proxy_check",
                        lambda: {"status": "ok", "detail": "Rust SOCKS ok"})
    monkeypatch.setattr(health, "_claude_transport_probe",
                        lambda: {"status": "unknown", "detail": "not running"})
    monkeypatch.setattr(health, "_installed_versions_check",
                        lambda: {"status": "info", "detail": "skip"})
    monkeypatch.setattr(health, "_runtime_model_override_check",
                        lambda: {"status": "info", "detail": "skip"})
    monkeypatch.setattr(health, "_codex_isolation_check",
                        lambda: {"status": "info", "detail": "skip"})
    monkeypatch.setattr(health, "_gfw_domain_check",
                        lambda: {"status": "info", "detail": "skip"})
    monkeypatch.setattr(health, "_direct_first_check",
                        lambda: {"status": "info", "detail": "skip"})
    monkeypatch.setattr(health, "_network_known_check",
                        lambda: {"status": "ok", "detail": "mock: сеть известна"})
    # #408: новые doctor-чеки дёргают реальный curl/pgrep — та же изоляция (#252 канон)
    monkeypatch.setattr(health, "_anthropic_exit_check",
                        lambda: {"status": "ok", "detail": "mock: 401"})
    monkeypatch.setattr(health, "_xray_config_freshness_check",
                        lambda: {"status": "ok", "detail": "mock: конфиг свежий"})
    result = health.check_all(active_claude=True)
    check = next(c for c in result["checks"] if "Chromium" in c["name"])
    assert check["ok"] is False
    assert not check.get("info")
