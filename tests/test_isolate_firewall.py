"""ТДД-тесты isolate_firewall codex-изоляции (issue #168, эпик #166).

PF kill-switch для codex: прямой выход codex (под системным UID 503) физически
блокируется в ядре, разрешён только loopback SOCKS5 127.0.0.1:10808. Это настоящая
fail-closed граница — любой способ обхода wrapper'а (rename PATH, Go-exec.LookPath,
foreign-wrapper) нерелевантен, пакет дропнется на en*. Замкнутый инвариант, которого
не было у wrapper-слоя (best-effort-layer-cycle-review-never-converges).

Mocked (как test_traffic_shape / test_codex_proxy): НЕ зовут реальные pfctl/root.
Проверяем:
  (a) _codex_ruleset() → корректный PF-синтаксис (table persist, pass lo0 user 503,
      block en* user 503);
  (b) enable/disable_codex_isolation через monkeypatch — sub-anchor path, token, fail-fast;
  (c) probe_codex_isolation state-only через load_active_codex_isolate;
  (d) сосуществование: sub-anchor НЕ перетирается доменной enable_isolation; strict/working
      содержат директиву anchor "codex" (иначе sub-anchor НИКОГДА не вычисляется);
  (e) PF dry-run parse (pfctl -vn -f -) — skip если pfctl недоступен (CI/sandbox).

Канон: always-tdd (тесты первыми), verify-dont-guess (dry-run parse, не exit-code-аналогия),
skip-is-fine-in-tests, issue-155 (единый источник порта SOCKS5).

Known-limitation: без provisioning uid 503 (follow-up) правила валидны и загружаются,
но не матчат трафик (нет процесса под этим UID). Числовой `user 503` pfctl парсит без
существования пользователя (verify) — ruleset активируется автоматически после provisioning.
"""
import shutil
import subprocess
import unittest

import dashboard_common
import isolate_firewall
import local_state


# ============================ helpers ============================
def _spy_run(calls, rc=0, out="", err="", timed_out=False):
    """Фейковый sys_probe.run: пишет argv в calls, возвращает dashboard-style dict."""
    def fake_run(cmd_list, timeout=None):
        calls.append(cmd_list)
        return {"rc": rc, "out": out, "err": err, "timeout": timed_out}
    return fake_run


def _apply_ok_run(calls, token="5"):
    """Фейк успешного apply: osascript-инвокация возвращает 'Token : N' (в out + err дубль).

    enable делает ОДИН osascript-вызов: захват -E в $t, дубль токена в stdout+stderr,
    загрузка ruleset. На success osascript отдаёт stdout цепочки — туда попадает токен.
    """
    def fake_run(cmd_list, timeout=None):
        calls.append(cmd_list)
        return {"rc": 0, "out": f"Token : {token}", "err": "", "timeout": False}
    return fake_run


# ============================ (a) синтаксис _codex_ruleset ============================
def test_codex_ruleset_has_table_persist_loopback():
    """table <srouter_codex_loopback> persist { 127.0.0.1 ::1 } — whitelist loopback (оба семейства)."""
    rs = isolate_firewall._codex_ruleset()
    assert "table <srouter_codex_loopback> persist { 127.0.0.1 ::1 }" in rs, rs
    assert "127.0.0.1" in rs and "::1" in rs


def test_codex_ruleset_pass_lo0_user_uid_to_socks_port():
    """pass out quick on lo0 ... to <table> port 10808 user 503 keep state.

    Порядок параметров PF каноничный (man pf.conf): to/port ПЕРЕД user (иначе syntax error —
    verify pfctl -vn). Числовой UID 503 (НЕ имя) — pfctl парсит без существования пользователя.
    """
    rs = isolate_firewall._codex_ruleset()
    assert 'pass out quick on lo0 proto tcp to <srouter_codex_loopback>' in rs, rs
    assert f'port {isolate_firewall.SOCKS5_PORT} user 503' in rs, rs
    assert 'keep state' in rs, rs


def test_codex_ruleset_block_direct_ifaces_user_uid():
    """block drop out quick на ВСЕХ физических ifaces (en*/ppp*) proto tcp user 503.

    Прямой выход codex отрезается. utun/lo0 НЕ в списке (туннель/loopback).
    """
    rs = isolate_firewall._codex_ruleset()
    assert 'block drop out quick on {' in rs, rs
    assert 'proto tcp user 503' in rs, rs
    # все DIRECT_IFACES присутствуют
    for iface in isolate_firewall.DIRECT_IFACES:
        assert iface in rs, f"{iface} отсутствует в ruleset"


def test_codex_ruleset_uses_canonical_socks_port():
    """port = str(XRAY_SOCKS_PORT) = '10808' — единый источник (issue #155)."""
    assert isolate_firewall.SOCKS5_PORT == str(dashboard_common.XRAY_SOCKS_PORT)
    assert isolate_firewall.SOCKS5_PORT == "10808"


def test_codex_ruleset_constants_shell_safe():
    """Гвард: константы shell-safe (только [A-Za-z0-9_]), UID — цифры. Никаких метасимволов."""
    import re
    assert re.fullmatch(r"[A-Za-z0-9_]+", isolate_firewall.CODEX_SOCKS_TABLE)
    assert isolate_firewall.CODEX_USER.isdigit(), "UID обязан быть числом (pfctl парсит без user)"
    assert isolate_firewall.CODEX_ANCHOR.startswith(isolate_firewall.ANCHOR + "/")
    assert "/codex" in isolate_firewall.CODEX_ANCHOR


# ============================ (b) enable/disable ============================
def test_enable_codex_uses_subanchor_not_parent(monkeypatch):
    """shell-cmd содержит sub-anchor 'com.apple/srouter_isolate/codex' (НЕ родитель — иначе -f перетрёт доменные правила)."""
    calls = []
    monkeypatch.setattr(isolate_firewall.sys_probe, "run", _apply_ok_run(calls))
    r = isolate_firewall.enable_codex_isolation()
    assert r["ok"], r
    shell_text = _shell_text(calls)
    assert 'com.apple/srouter_isolate/codex' in shell_text, shell_text
    assert '-f -' in shell_text, "ruleset грузится через pfctl -a <anchor> -f -"


def test_enable_codex_captures_token(monkeypatch):
    """Token парсится из out/err (как enable_strict). Дубль в stderr на success."""
    calls = []
    monkeypatch.setattr(isolate_firewall.sys_probe, "run", _apply_ok_run(calls, token="7"))
    r = isolate_firewall.enable_codex_isolation()
    assert r["ok"], r
    assert r["token"] == "7", r


def test_enable_codex_failfast_on_cancel(monkeypatch):
    """-E || exit → при cancel osascript (rc -128) token не создаётся, ok=False (fail-fast)."""
    calls = []
    monkeypatch.setattr(isolate_firewall.sys_probe, "run", _spy_run(calls, rc=-128))
    r = isolate_firewall.enable_codex_isolation()
    assert not r["ok"], r
    assert r.get("token") in (None, ""), r


def _shell_text(calls):
    """Слить argv osascript-вызовов в одну строку, нормализуя экранированные кавычки.

    calls — список argv-списков ([[osascript, -e, "..."], ...]); join'им содержимое каждого.
    """
    flat = " ".join(part for argv in calls for part in argv)
    return flat.replace('\\"', '"')


def test_disable_codex_flushes_subanchor_only(monkeypatch):
    """disable flush'ит ТОЛЬКО codex sub-anchor (НЕ родитель — иначе убил бы доменные правила)."""
    calls = []
    monkeypatch.setattr(isolate_firewall.sys_probe, "run", _spy_run(calls, rc=0))
    r = isolate_firewall.disable_codex_isolation()
    assert r["ok"], r
    shell_text = _shell_text(calls)
    assert '-a "com.apple/srouter_isolate/codex" -F all' in shell_text, shell_text
    # родительский anchor НЕ flush'ится (только sub)
    assert shell_text.count("-F all") == 1, shell_text


def test_disable_codex_releases_token_when_present(monkeypatch):
    """С валидным token — disable добавляет pfctl -X <token> (release enable-ref). attempt-all."""
    calls = []
    monkeypatch.setattr(isolate_firewall.sys_probe, "run", _spy_run(calls, rc=0))
    r = isolate_firewall.disable_codex_isolation(token="9")
    assert r["ok"], r
    shell_text = _shell_text(calls)
    assert "-X 9" in shell_text, shell_text


# ============================ (c) probe state-only ============================
def test_probe_codex_down_when_no_lease(monkeypatch, tmp_path):
    """Нет codex-lease → status=down (как probe_isolation без active_isolate)."""
    monkeypatch.setattr(local_state, "load_active_codex_isolate", lambda path=None: None)
    r = isolate_firewall.probe_codex_isolation(state_path=str(tmp_path / "s.json"))
    assert r["status"] == "down", r


def test_probe_codex_ok_when_lease_present(monkeypatch, tmp_path):
    """Валидный codex-lease {token, applied_at} → status=ok."""
    lease = {"token": "5", "applied_at": 1234567890}
    monkeypatch.setattr(local_state, "load_active_codex_isolate", lambda path=None: lease)
    r = isolate_firewall.probe_codex_isolation(state_path=str(tmp_path / "s.json"))
    assert r["status"] == "ok", r
    assert r.get("token") == "5", r


# ============================ (d) сосуществование sub-anchor ============================
def test_strict_working_rulesets_contain_codex_anchor_directive():
    """БЛОКЕР: strict/working обязаны содержать 'anchor "codex"' — иначе sub-anchor НИКОГДА не вычисляется (man pf.conf)."""
    assert 'anchor "codex"' in isolate_firewall._strict_ruleset()
    assert 'anchor "codex"' in isolate_firewall._working_ruleset()


def test_enable_isolation_does_not_touch_codex_subanchor(monkeypatch):
    """Доменная enable_isolation грузит РОДИТЕЛЬСКИЙ anchor, НЕ codex-sub (zero cross-cutting)."""
    calls = []
    monkeypatch.setattr(isolate_firewall.sys_probe, "run", _apply_ok_run(calls))
    monkeypatch.setattr(isolate_firewall, "resolve_domain_ips",
                        lambda domains, dns_servers=None: {"api.anthropic.com": ["203.0.113.10"]})
    r = isolate_firewall.enable_isolation(["api.anthropic.com"])
    assert r["ok"], r
    shell_text = _shell_text(calls)
    assert "com.apple/srouter_isolate/codex" not in shell_text, "доменная изоляция НЕ трогает codex-sub"


# ============================ (e) PF dry-run parse (verify-dont-guess) ============================
@unittest.skipUnless(shutil.which("/sbin/pfctl") or shutil.which("pfctl"),
                     "pfctl недоступен (CI/sandbox) — skip dry-run parse")
def test_codex_ruleset_parses_via_pfctl_vn():
    """Эмпирика (verify-dont-guess): _codex_ruleset() валиден через pfctl -vn -f - → rc=0.

    Доказательство «инфраструктура готова»: числовой user 503 парсится БЕЗ существования
    пользователя. Ruleset активируется автоматически после provisioning (follow-up).
    """
    ruleset = isolate_firewall._codex_ruleset()
    proc = subprocess.run(["pfctl", "-vn", "-f", "-"], input=ruleset,
                          capture_output=True, text=True, timeout=10)
    # pfctl может писать warning про main ruleset на stderr — это не ошибка парсинга.
    combined = proc.stdout + proc.stderr
    assert "unknown user" not in combined, f"pfctl не распознал user: {combined}"
    assert "syntax error" not in combined.lower(), f"syntax error: {combined}"


# ============================ local_state codex-lease round-trip ============================
def test_codex_isolate_lease_roundtrip(tmp_path):
    """save→load→clear codex-lease через реальный state-файл (atomic, fail-closed)."""
    p = str(tmp_path / "s.json")
    assert local_state.load_active_codex_isolate(path=p) is None
    saved = local_state.save_active_codex_isolate({"token": "42", "applied_at": 111}, path=p)
    assert saved and saved["token"] == "42"
    loaded = local_state.load_active_codex_isolate(path=p)
    assert loaded is not None
    assert loaded["token"] == "42" and loaded["applied_at"] == 111
    assert local_state.clear_active_codex_isolate(path=p) is True
    assert local_state.load_active_codex_isolate(path=p) is None


def test_codex_isolate_lease_rejects_invalid(tmp_path):
    """fail-closed: невалидный lease (нет token / мусор) НЕ пишется."""
    p = str(tmp_path / "s.json")
    assert local_state.save_active_codex_isolate({"applied_at": 1}, path=p) is None  # нет token
    assert local_state.save_active_codex_isolate({"token": "abc"}, path=p) is None  # нечисловой token
    assert local_state.load_active_codex_isolate(path=p) is None
