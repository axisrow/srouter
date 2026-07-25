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


def test_app_proxy_warn_when_app_running_and_gui_http_only(monkeypatch):
    """App-codex активен + gui-env только HTTP (privoxy) → warn: privoxy рвёт long-lived WS (#120)."""
    ps = f"60826 {APP_CODEX_COMM}\n"
    monkeypatch.setattr(health.sys_probe, "run",
                        _fake(ps, _gui_env({"HTTPS_PROXY": PRIVOXY, "HTTP_PROXY": PRIVOXY})))
    res = health._codex_app_proxy_check()
    assert res["status"] == "warn", f"App на privoxy → warn (WS порвётся #120); got {res}"


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
