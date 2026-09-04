"""ТДД-тесты health._codex_app_proxy_check: doctor диагностирует ChatGPT.app без прокси (#189).

Корень #189 (verify, lsof per-process + logs_2.sqlite): ChatGPT.app = Electron-оболочка над
Rust-бинарником. Rust app-server (/Resources/codex, основной WS к wss://chatgpt.com) НЕ уважает
системный SOCKS, берёт ТОЛЬКО env SOCKS5 из launchd gui-домена (codenv LaunchAgent). codenv снят/битый
→ env пуст → Rust app-server напрямую → GFW рвёт ('failed to connect... error_kind=TimedOut').

Чек детектит: App-codex процессы активны (ps по /ChatGPT.app/.../codex) И launchctl gui-домен НЕ
содержит SOCKS5 → status=down DRIVER с диагнозом «восстанови codenv (srouter install)». Когда App
не запущен / gui-env не верифицируем → unknown (info-only, не роняет вердикт — fail-closed).

Контракт _codex_app_proxy_check() → {status, source, detail}:
  status="ok"      — App-codex активен И gui-env содержит SOCKS5 (codenv работает);
  status="warn"    — App-codex активен, gui-env только HTTP (privoxy рвёт WS #120);
  status="down"    — App-codex активен, gui-env пуст (codenv снят/битый) — DRIVER;
  status="unknown" — App не запущен ИЛИ gui-env не верифицируем (info-only).
"""
import health

APP_CODEX_COMM = "/Applications/ChatGPT.app/Contents/Resources/codex"  # Rust app-server ChatGPT.app
SOCKS5 = "socks5h://127.0.0.1:10808"
PRIVOXY = "http://127.0.0.1:8118"


def _fake(ps_out, gui_env_text="", gui_verifiable=True, lsof_out="", lsof_rc=0, lsof_timeout=False):
    """fake_run: ps → ps_out; launchctl print gui/<uid> → gui_env_text; lsof -p <app_pids> → lsof_out.

    _read_gui_proxy_env парсит `launchctl print gui/<uid>` блок `environment = { ... }` (getenv НЕ
    принимает домен-аргумент — Usage: getenv <key> — молча игнорирует домен, давая пусто/ложный down).
    gui_env_text = сырой текст environment-блока (для имитации print-вывода). gui_verifiable=False →
    timeout launchctl (fail-closed → unknown, не false-down).
    lsof_out = lsof-вывод для App-PID (runtime-маршрут). lsof_rc≠0 / lsof_timeout → lsof-сбой (не ok).
    """
    def fake_run(cmd, timeout):
        if cmd and cmd[0] == "/bin/ps":
            return {"rc": 0, "out": ps_out, "err": "", "timeout": False}
        if cmd and cmd[0] == "/bin/launchctl" and len(cmd) >= 2 and cmd[1] == "print":
            if not gui_verifiable:
                return {"rc": None, "out": "", "err": "timeout", "timeout": True}
            return {"rc": 0, "out": gui_env_text, "err": "", "timeout": False}
        if cmd and cmd[0] == "/usr/sbin/lsof":
            if lsof_timeout:
                return {"rc": None, "out": "", "err": "timeout", "timeout": True}
            return {"rc": lsof_rc, "out": lsof_out, "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}
    return fake_run


def _lsof_external(pid, port=443):
    """lsof-строка: App-PID держит external ESTABLISHED (direct, без localhost-прокси)."""
    return (f"codex {pid} axisrow 32u IPv4 0xABC 0t0 "
            f"TCP 192.168.1.17:55607->31.13.95.48:{port} (ESTABLISHED)\n")


def _lsof_socks(pid):
    """lsof-строка: App-PID через SOCKS5 10808 (как должно быть при рабочем codenv + свежем App)."""
    return (f"codex {pid} axisrow 32u IPv4 0xABC 0t0 "
            f"TCP 127.0.0.1:55607->127.0.0.1:10808 (ESTABLISHED)\n")


def _lsof_privoxy(pid):
    """lsof-строка: App-PID через privoxy 8118 (HTTP, рвёт long-lived WS #120 — НЕ SOCKS5)."""
    return (f"codex {pid} axisrow 32u IPv4 0xABC 0t0 "
            f"TCP 127.0.0.1:55607->127.0.0.1:8118 (ESTABLISHED)\n")


def _gui_env(keys):
    """Сырой текст блока environment из `launchctl print gui/<uid>` для заданных ключей.

    Обёрнут в 'environment = {' / '}' (как реально отдаёт launchctl print). Пустой keys → пустой env
    (только обёртка), _read_gui_proxy_env вернёт verifiable=True, keys={} → down (codenv снят).
    """
    inner = "".join(f"\t\t{k} => {v}\n" for k, v in (keys or {}).items())
    return f"\tenvironment = {{\n{inner}\t}}\n"


SOCKS5 = "socks5h://127.0.0.1:10808"
PRIVOXY = "http://127.0.0.1:8118"


def test_app_proxy_down_when_app_running_and_gui_env_empty(monkeypatch):
    """App-codex активен + gui-env пуст → down DRIVER: codenv снят/битый, восстанови srouter install.

    Это и есть корень #189: ChatGPT.app Rust app-server без прокси → WS к chatgpt.com тайм-аутится.
    """
    ps = f"60826 {APP_CODEX_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run", _fake(ps, _gui_env({})))
    res = health._codex_app_proxy_check()
    assert res["status"] == "down", f"App активен + gui-env пуст → down (codenv снят); got {res}"
    detail = res["detail"].lower()
    assert "codenv" in detail or "install" in detail, f"detail объясняет фикс (codenv/install); got {res}"


def test_app_proxy_ok_when_app_running_and_gui_socks5(monkeypatch):
    """App-codex активен + gui-env SOCKS5 + lsof подтверждает 10808 → ok: свежий App, codenv работает."""
    ps = f"60826 {APP_CODEX_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run",
                        _fake(ps, _gui_env({"HTTPS_PROXY": SOCKS5, "HTTP_PROXY": SOCKS5, "ALL_PROXY": SOCKS5}),
                              lsof_out=_lsof_socks("60826")))
    res = health._codex_app_proxy_check()
    assert res["status"] == "ok", f"App активен + gui SOCKS5 + lsof 10808 → ok; got {res}"


def test_app_proxy_down_when_stale_app_direct_despite_gui_socks5(monkeypatch):
    """STALE App (запущен ДО codenv install) + gui-env SOCKS5 + lsof external → down, НЕ ok.

    Cycle-1 finding: launchctl setenv НЕ ретроактивен — Rust app-server, запущенный до codenv, держит
    старый прямой маршрут, пока gui-env уже обновлён. Чек по одному gui-env давал ложный ok (false-ok).
    lsof App-PID показывает external ESTABLISHED → down с диагнозом «перезапусти ChatGPT.app».
    App-PID исключён из _codex_proxy_probe (TUI) → этот чек единственный, кто видит App direct-сокеты.
    """
    ps = f"60826 {APP_CODEX_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run",
                        _fake(ps, _gui_env({"HTTPS_PROXY": SOCKS5, "ALL_PROXY": SOCKS5}),
                              lsof_out=_lsof_external("60826")))
    res = health._codex_app_proxy_check()
    assert res["status"] == "down", f"stale App direct (gui SOCKS5, lsof external) → down, не ok; got {res}"
    detail = res["detail"].lower()
    assert "перезапуст" in detail or "restart" in detail or "direct" in detail, \
        f"detail объясняет: нужен рестарт App (setenv не ретроактивен); got {res}"


def test_app_proxy_distinguishes_chromium_helper_direct_from_rust_stale(monkeypatch):
    """Direct Chromium helper gets a Chromium-specific diagnosis, not a false Rust stale diagnosis."""
    helper = (
        "/Applications/ChatGPT.app/Contents/Frameworks/Codex Framework.framework/Versions/"
        "151.0.7922.170/Helpers/Codex (Service).app/Contents/MacOS/Codex (Service)"
    )
    ps = f"96016 {helper}\n"
    monkeypatch.setattr(health.sys_probe, "run",
                        _fake(ps, _gui_env({"ALL_PROXY": SOCKS5}),
                              lsof_out=_lsof_external("96016")))
    res = health._codex_app_proxy_check()
    assert res["status"] == "down"
    detail = res["detail"].lower()
    assert "chromium" in detail or "helper" in detail
    assert "rust app-server" not in detail


def test_app_proxy_unknown_when_app_idle_no_socks_socket(monkeypatch):
    """App активен + gui-env SOCKS5, но lsof НЕ показал 10808 (idle/нет ESTABLISHED) → unknown, НЕ ok.

    Cycle-2 finding: ok требовал positive SOCKS5 evidence. Пустой/idle lsof → нет доказательства
    маршрута → нельзя утверждать ok (App может быть сломан/переподключается). fail-closed: unknown.
    """
    ps = f"60826 {APP_CODEX_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run",
                        _fake(ps, _gui_env({"HTTPS_PROXY": SOCKS5, "ALL_PROXY": SOCKS5}),
                              lsof_out=""))  # idle — нет ESTABLISHED
    res = health._codex_app_proxy_check()
    assert res["status"] == "unknown", f"idle App (нет SOCKS-сокета) → unknown, не ok; got {res}"


def test_app_proxy_warn_when_app_via_privoxy_not_socks(monkeypatch):
    """App активен + gui-env SOCKS5, но lsof показывает privoxy 8118 (НЕ SOCKS5) → warn, НЕ ok.

    Cycle-2 finding: ESTABLISHED к другому localhost-прокси (8118) ≠ SOCKS5-маршрут. privoxy рвёт
    long-lived WS (#120) → warn (degraded), не ok. App выбрал privoxy вместо SOCKS5 (stale env).
    """
    ps = f"60826 {APP_CODEX_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run",
                        _fake(ps, _gui_env({"HTTPS_PROXY": SOCKS5, "ALL_PROXY": SOCKS5}),
                              lsof_out=_lsof_privoxy("60826")))
    res = health._codex_app_proxy_check()
    assert res["status"] == "warn", f"App через privoxy (не SOCKS5) → warn, не ok; got {res}"


def test_app_proxy_unknown_when_lsof_nonzero_rc(monkeypatch):
    """App активен + gui-env SOCKS5, но lsof rc≠0 (сбой, НЕ timeout) → unknown, НЕ ok.

    Cycle-2 finding: lsof-сбой (rc≠0, пустой out) — не timeout, но и не доказательство маршрута.
    Нельзя утверждать ok без positive SOCKS5 evidence → fail-closed: unknown.
    """
    ps = f"60826 {APP_CODEX_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run",
                        _fake(ps, _gui_env({"HTTPS_PROXY": SOCKS5, "ALL_PROXY": SOCKS5}),
                              lsof_out="", lsof_rc=1))
    res = health._codex_app_proxy_check()
    assert res["status"] == "unknown", f"lsof rc≠0 → unknown (fail-closed), не ok; got {res}"


def test_app_proxy_ok_when_socks_in_all_proxy_only(monkeypatch):
    """codenv ставит ALL_PROXY=socks5h + lsof подтверждает 10808 → ok (свежий App)."""
    ps = f"60826 {APP_CODEX_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run",
                        _fake(ps, _gui_env({"ALL_PROXY": SOCKS5}), lsof_out=_lsof_socks("60826")))
    res = health._codex_app_proxy_check()
    assert res["status"] == "ok", f"ALL_PROXY SOCKS5 + lsof 10808 → ok; got {res}"


def test_app_proxy_unknown_when_managed_privoxy_gui_env(monkeypatch):
    """#340: gui-env = наш managed privoxy-формат (HTTP_PROXY_URL) → НЕ warn, а unknown (info).

    С #340 codenv ставит scheme-ключи = privoxy (терминальное плечо): это НОРМАЛЬНОЕ состояние
    установки, а не «App через privoxy рвёт WS» — иначе нормальная установка вечно degraded
    (канон PR #135). Rust app-server сегодня спавнится с санитизованным env без прокси
    (ps eww, #340) — gui-env до него не доходит; реальный маршрут App-PID по-прежнему ловит
    runtime-ветка (lsof privoxy → warn #120). Fail-closed: ok без runtime-доказательства не
    заявляем → unknown (info-only, не driver)."""
    ps = f"60826 {APP_CODEX_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run",
                        _fake(ps, _gui_env({"HTTPS_PROXY": PRIVOXY, "HTTP_PROXY": PRIVOXY})))
    res = health._codex_app_proxy_check()
    assert res["status"] == "unknown", f"managed privoxy gui-env — норма #340 → unknown; got {res}"


def test_app_proxy_warn_when_gui_http_proxy_is_foreign(monkeypatch):
    """Чужой http-прокси в gui-env (не наш privoxy-формат #340) → warn как раньше (#120 класс)."""
    ps = f"60826 {APP_CODEX_COMM}\n"
    foreign = "http://10.0.0.5:3128"
    monkeypatch.setattr(health.sys_probe, "run",
                        _fake(ps, _gui_env({"HTTPS_PROXY": foreign, "HTTP_PROXY": foreign})))
    res = health._codex_app_proxy_check()
    assert res["status"] == "warn", f"чужой http-прокси в gui → warn; got {res}"


# ============ #340: residual-SOCKS в gui-домене (launchctl-источник, не убран старой версией) ============
def _fake_codenv_managed(monkeypatch, *, managed):
    """Мок _codenv_managed → managed (plist+loaded) / False — без обращения к реальному дому."""
    import health_codenv
    monkeypatch.setattr(health_codenv, "_codenv_managed", lambda runner=None: managed)


def test_gui_socks_residual_warn_when_managed_codenv_still_socks(monkeypatch):
    """#340: socks5h в gui-домене при managed codenv → warn (старая версия скрипта / residual).

    Канон-issue #340: предупреждать о launchctl-источнике. После перехода codenv на privoxy-
    плечо socks в gui = residual от старой установки → сигнал «перепримени install / дождись
    прогона агента (≤5 мин)», а не молчание."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _fake("", _gui_env({"ALL_PROXY": SOCKS5, "HTTPS_PROXY": SOCKS5})))
    _fake_codenv_managed(monkeypatch, managed=True)
    res = health._gui_socks_residual_check()
    assert res["status"] == "warn", f"residual socks при managed codenv → warn; got {res}"
    assert "unsetenv" in res["detail"] or "install" in res["detail"].lower(), \
        f"detail предлагает remediation; got {res}"


def test_gui_socks_residual_not_ours_when_codenv_not_managed(monkeypatch):
    """socks в gui-домене БЕЗ managed codenv — чужой (не наша зона; desktop-check уже down-ит) →
    unknown/info: не дублируем чужой вердикт своим warn (#189 codenv-aware семантика)."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _fake("", _gui_env({"ALL_PROXY": "socks5://10.0.0.9:1080"})))
    _fake_codenv_managed(monkeypatch, managed=False)
    res = health._gui_socks_residual_check()
    assert res["status"] == "unknown", f"чужой socks — вне контракта srouter; got {res}"


def test_gui_socks_residual_warn_when_lowercase_only(monkeypatch):
    """#340 (review): residual socks ТОЛЬКО в lower-case ключах (all_proxy/https_proxy) — warn.

    Дефолтный keys_filter _read_gui_proxy_env (LAUNCHCTL_PROXY_KEYS) — только верхний регистр;
    старая версия srouter-codex-env.sh ставила И lower-case. Детектор обязан видеть весь
    residual-класс (канон detector-must-be-function-not-constant): warn-ветка достижима на
    lower-case-only входе."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _fake("", _gui_env({"all_proxy": SOCKS5, "https_proxy": SOCKS5})))
    _fake_codenv_managed(monkeypatch, managed=True)
    res = health._gui_socks_residual_check()
    assert res["status"] == "warn", f"lower-case residual socks → warn; got {res}"


def test_gui_socks_residual_keys_parity():
    """#340 (review): residual-набор ключей = CODEX_LAUNCHCTL_UNSET_KEYS (scheme-часть).

    Локальная копия в health_codenv нужна из-за цикла импортов (codex_wrappers → health), но
    она обязана следовать за контрактом снятия — иначе новый ключ появится в uninstall, а
    детектор его молча пропустит (drift двух копий)."""
    import codex_wrappers
    import health_codenv
    assert set(health_codenv._LAUNCHCTL_RESIDUAL_SOCKS_KEYS) == \
        set(codex_wrappers.CODEX_LAUNCHCTL_UNSET_KEYS) - {"NO_PROXY", "no_proxy"}, (
        f"residual-ключи health_codenv должны совпадать с scheme-частью "
        f"CODEX_LAUNCHCTL_UNSET_KEYS: {health_codenv._LAUNCHCTL_RESIDUAL_SOCKS_KEYS}")


def test_gui_socks_residual_ok_when_privoxy_or_empty(monkeypatch):
    """Наш новый формат (privoxy scheme-ключи, ALL_PROXY пуст/нет) → ok."""
    monkeypatch.setattr(health.sys_probe, "run",
                        _fake("", _gui_env({"HTTPS_PROXY": PRIVOXY, "HTTP_PROXY": PRIVOXY})))
    _fake_codenv_managed(monkeypatch, managed=True)
    res = health._gui_socks_residual_check()
    assert res["status"] == "ok", f"privoxy gui-домен (#340) → ok; got {res}"


def test_gui_socks_residual_unknown_when_gui_unverifiable(monkeypatch):
    """launchctl print не ответил → unknown (fail-closed, info-only): «не смогли спросить» ≠ «чисто»."""
    monkeypatch.setattr(health.sys_probe, "run", _fake("", "", gui_verifiable=False))
    _fake_codenv_managed(monkeypatch, managed=True)
    res = health._gui_socks_residual_check()
    assert res["status"] == "unknown", f"gui не верифицируем → unknown; got {res}"


def test_app_proxy_unknown_when_app_not_running(monkeypatch):
    """App не запущен → unknown (info-only): проверять «App без прокси» бессмысленно без App."""
    monkeypatch.setattr(health.sys_probe, "run", _fake("", _gui_env({})))
    res = health._codex_app_proxy_check()
    assert res["status"] == "unknown", f"App не запущен → unknown (info); got {res}"


def test_app_proxy_unknown_when_gui_env_unverifiable(monkeypatch):
    """App активен + launchctl timeout → unknown (info): fail-closed, не false-down.

    Канон fail-closed: не различимо «gui-env пуст» vs «не смогли спросить launchctl» → не роняем.
    """
    ps = f"60826 {APP_CODEX_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run", _fake(ps, gui_verifiable=False))
    res = health._codex_app_proxy_check()
    assert res["status"] == "unknown", f"gui-env не верифицируем → unknown (fail-closed); got {res}"


def test_app_proxy_unknown_when_no_environment_block(monkeypatch):
    """App активен + launchctl print НЕ содержит блока environment → unknown (fail-closed, не false-down).

    Edge-case (cycle-review): `launchctl print gui/999999` (несуществующий домен) отдаёт rc=0 с
    'out=Bad request. Could not find domain...', НЕ stderr. Парсер без блока environment = НЕ ВЕРИМ
    (не различимо «домен недоступен/формат иной» от «codenv снят») → verifiable=False → unknown.
    Иначе: пустой out (нет блока) → keys={} → false-down «codenv не загружен» на ровном месте.
    Отличие от down-теста: там блок environment ЕСТЬ, но ключей proxy нет (реальное codenv-снятие).
    """
    ps = f"60826 {APP_CODEX_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run", _fake(ps, gui_env_text="Bad request.\nCould not find domain for user\n"))
    res = health._codex_app_proxy_check()
    assert res["status"] == "unknown", f"нет блока environment → unknown (fail-closed); got {res}"


def test_app_proxy_detects_chatgpt_app_path(monkeypatch):
    """App-PID по /ChatGPT.app/.../codex детектится (регрессия: раньше смешивался с CLI в TUI-чеке)."""
    # CLI-codex PID НЕ должен считаться App (он в TUI-чеке, не здесь)
    cli_comm = "/opt/homebrew/lib/node_modules/@openai/codex/x/aarch64-apple-darwin/bin/codex"
    ps = f"22415 {cli_comm}\n"  # только CLI, без App
    monkeypatch.setattr(health.sys_probe, "run", _fake(ps, _gui_env({})))
    res = health._codex_app_proxy_check()
    assert res["status"] == "unknown", f"CLI-codex (не App) → App не запущен → unknown; got {res}"


# Chromium network-service helper ChatGPT.app (регрессия #189 follow-up, verify-dont-guess):
# comm — полный путь ВНУТРИ .app/-бандла, basename НЕ "codex" (не матчит _is_codex_binary_comm) →
# старый AND-детект (_is_codex_binary_comm И _is_codex_app_comm) отбрасывал этот процесс целиком,
# несмотря на то что он реально течёт мимо прокси (эмпирика: lsof показал ~37 SYN_SENT сокетов
# напрямую к 192.168.1.x/китайский IPv6, ни одного к 10808/8118, при корректном gui-env SOCKS5).
CHROMIUM_HELPER_COMM = (
    "/Applications/ChatGPT.app/Contents/Frameworks/Codex Framework.framework/Versions/"
    "151.0.7922.170/Helpers/Codex (Service).app/Contents/MacOS/Codex (Service)"
)


def test_app_proxy_detects_chromium_helper_without_codex_basename(monkeypatch):
    """Chromium network-service helper (comm НЕ basename 'codex', но путь /ChatGPT.app/) детектится
    как App-related процесс — НЕ должен давать ложный unknown «App не запущен».

    Баг: _codex_app_proxy_check раньше матчил App-PID через _is_codex_binary_comm(comm) AND
    _is_codex_app_comm(comm) — basename-условие отсеивало любой helper с comm вида
    ".../Codex (Service).app/Contents/MacOS/Codex (Service)" (basename "Codex (Service)" ≠ "codex").
    Единственный процесс ChatGPT.app в ps-выводе — этот helper (Rust app-server не запущен отдельно) →
    старый код видел app_pids=[] → status="unknown" "не запущен", хотя стек активен и течёт мимо прокси.
    """
    ps = f"71234 {CHROMIUM_HELPER_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run", _fake(ps, _gui_env({})))
    res = health._codex_app_proxy_check()
    assert res["status"] != "unknown", (
        f"Chromium network-service helper активен — не должно быть ложного "
        f"'App не запущен'; got {res}"
    )
    # codex-review (PR #314): detail теперь честно уточняет, что именно Rust app-server не запущен
    # (Chromium жив) — это НЕ тот баг, для которого написан тест (старый код видел app_pids=[] и
    # лгал «ChatGPT.app/Codex.app не запущен» целиком, хотя Chromium-стек активен).
    assert "chatgpt.app/codex.app не запущен" not in res["detail"].lower(), \
        f"detail лжёт про весь App целиком; got {res}"


def test_app_proxy_down_when_chromium_helper_leaks_direct_despite_gui_socks5(monkeypatch):
    """Chromium helper держит external ESTABLISHED мимо прокси, хотя gui-env SOCKS5 корректен → down.

    Живая эмпирика сессии: launchctl getenv показывал верный socks5h://127.0.0.1:10808, НО Chromium
    network-service процесс (comm без basename 'codex') слал ~37 сокетов напрямую — ни один не шёл
    через 10808/8118. Это ровно симптом net::ERR_CONNECTION_TIMED_OUT в UI (GFW режет прямой путь).
    """
    ps = f"71234 {CHROMIUM_HELPER_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run",
                        _fake(ps, _gui_env({"HTTPS_PROXY": SOCKS5, "ALL_PROXY": SOCKS5}),
                              lsof_out=_lsof_external("71234")))
    res = health._codex_app_proxy_check()
    assert res["status"] == "down", (
        f"Chromium helper течёt мимо прокси (gui-env SOCKS5 корректен, lsof external) → down; got {res}"
    )


# Generic .app-helper (ни rust, ни chromium network-service) — _codex_app_process_kind классифицирует
# его как "helper" (docstring health_codex.py:73 «must not be reported as the Rust app-server»), но
# _codex_app_proxy_check проверяет external_by_kind ТОЛЬКО по "chromium"/"rust" (health_codenv.py
# :700-713) — leak с "helper"-kind PID падает в generic Rust-ветку и врёт диагнозом.
GENERIC_HELPER_COMM = "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"


def test_app_proxy_empty_gui_env_does_not_blame_rust_when_only_chromium_running(monkeypatch):
    """codex-review (Codex rescue, PR #314): единственный живой процесс — Chromium network-service
    helper (Rust app-server НЕ запущен). gui-env пуст — это НОРМАЛЬНО (codenv нужен только Rust'у,
    не Chromium — тот берёт прокси из системного SOCKS через отдельный
    _codex_app_chromium_proxy_check). Старый текст «ChatGPT.app Rust app-server без прокси... srouter
    install (codenv)» здесь ложный диагноз: Rust не запущен, и codenv install ничего не чинит для
    чисто-Chromium случая.
    """
    ps = f"71234 {CHROMIUM_HELPER_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run", _fake(ps, _gui_env({})))
    res = health._codex_app_proxy_check()
    detail = res["detail"].lower()
    assert "srouter install (codenv)" not in detail and "восстановить: srouter install" not in detail, (
        f"detail советует чинить codenv для Rust, хотя Rust не запущен (только Chromium); got {res}"
    )
    assert "не запущен" in detail, f"detail должен честно называть причину: Rust не запущен; got {res}"


def test_app_proxy_down_diagnosis_does_not_blame_rust_for_generic_helper_leak(monkeypatch):
    """Non-rust non-chromium .app-helper течёт мимо прокси → down НЕ должен обвинять Rust app-server
    (никакого 'Resources/codex' PID вообще не запущено — обвинение было бы ложным).
    """
    ps = f"81234 {GENERIC_HELPER_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run",
                        _fake(ps, _gui_env({"HTTPS_PROXY": SOCKS5, "ALL_PROXY": SOCKS5}),
                              lsof_out=_lsof_external("81234")))
    res = health._codex_app_proxy_check()
    assert res["status"] == "down", f"generic helper leak должен быть down; got {res}"
    assert "rust app-server" not in res["detail"].lower(), (
        f"detail ложно обвиняет Rust app-server, хотя течёт non-rust non-chromium helper; got {res}"
    )
