"""e2e-тесты srouter_cli.cmd_protect: человековые вкл/выкл PF-изоляции Anthropic.

`protect on` = enable_strict + persist lease (phase="strict") в runtime.active_isolate:
lease ОБЯЗАН писаться, иначе дашборд-карточка /api/isolate (тот же ключ) врёт «выключено»
при работающем PF (канон «два контура противоречат» #341). Повторный on при живом lease —
отказ БЕЗ pfctl-вызова: enable_strict не идемпотентна (каждый вызов = новый pfctl -E
ref/token, isolate_firewall.py:328) — повторный enable течёт ref'ом. `protect off` —
disable_strict(token из lease) + clear; без lease disable всё равно зовётся (fail-safe:
lease мог потеряться, якорь PF — нет). status — probe_isolation (state-only), strict
рендерится как нормальный steady-state (probe красит warn по бут-семантике — здесь норма).

Моки ставим на srouter_cli — модуль-ВЛАДЕЛЕЦ команд (#259, см. test_srouter_uninstall_cmd):
cmd_protect резолвит isolate_firewall/local_state в globals srouter_cli.
"""
from types import SimpleNamespace

import srouter_cli


def _args(action="on", state=None):
    """args как argparse отдаёт для `srouter protect <action> [--state]` (canonical
    ставит set_defaults парсера; алиасы — те же parser-объекты, см. build_parser)."""
    return SimpleNamespace(protect_action=action, canonical=action, state=state)


def _stub_isolate(monkeypatch, *, enable=None, disable=None, probe=None):
    """Стаб isolate_firewall + журнал вызовов enable/disable (для инвариантов «не звать»)."""
    calls = {"enable": 0, "disable": []}

    def enable_strict():
        calls["enable"] += 1
        return dict(enable) if enable is not None else {"ok": True, "token": "777"}

    def disable_strict(token=None):
        calls["disable"].append(token)
        return {"ok": True}

    monkeypatch.setattr(srouter_cli, "isolate_firewall", SimpleNamespace(
        enable_strict=enable_strict,
        disable_strict=disable_strict,
        probe_isolation=probe or (lambda state_path=None: {"status": "down", "phase": "none"}),
    ))
    return calls


def _stub_lease(monkeypatch, *, lease=None):
    """Стаб local_state (только isolate-функции) + журнал save/clear."""
    calls = {"save": [], "clear": 0}

    def save_active_isolate(entry, path=None):
        calls["save"].append(entry)
        return entry

    def clear_active_isolate(path=None):
        calls["clear"] += 1
        return True

    monkeypatch.setattr(srouter_cli, "local_state", SimpleNamespace(
        load_active_isolate=lambda path=None: lease,
        save_active_isolate=save_active_isolate,
        clear_active_isolate=clear_active_isolate,
        preflight_state_write=lambda path=None: True,
    ))
    return calls


# ============================ on ============================

def test_protect_on_enables_strict_and_persists_lease(monkeypatch, capsys):
    """on: enable_strict ok+token → rc 0, «включена» в stdout, lease сохранён
    с phase="strict" и тем же token (контур дашборда обязан видеть включенное)."""
    calls = _stub_isolate(monkeypatch)
    lease_calls = _stub_lease(monkeypatch)
    rc = srouter_cli.cmd_protect(_args("on"))
    out = capsys.readouterr().out
    assert rc == 0
    assert "включена" in out
    assert calls["enable"] == 1, "enable_strict должен вызываться ровно раз"
    assert len(lease_calls["save"]) == 1, "lease обязан персиститься (канон #341)"
    saved = lease_calls["save"][0]
    assert saved["phase"] == "strict"
    assert str(saved["token"]) == "777"


def test_protect_on_refuses_when_lease_active_without_pf_call(monkeypatch, capsys):
    """on при живом lease → отказ rc 1, enable_strict НЕ вызывается (pfctl -E ref течёт)."""
    calls = _stub_isolate(monkeypatch)
    _stub_lease(monkeypatch, lease={"phase": "strict", "token": "1", "domains": [],
                                    "ports": [80, 443]})
    rc = srouter_cli.cmd_protect(_args("on"))
    err_out = capsys.readouterr()
    assert rc == 1
    assert "уже включена" in err_out.out
    assert calls["enable"] == 0, "повторный enable_strict = новый pfctl-ref — отказ ДО вызова"


def test_protect_on_cancelled_password_no_lease(monkeypatch, capsys):
    """on с отменой пароля osascript → «отменено», rc 1, lease не пишется."""
    calls = _stub_isolate(monkeypatch, enable={"ok": False, "cancelled": True, "token": None})
    lease_calls = _stub_lease(monkeypatch)
    rc = srouter_cli.cmd_protect(_args("on"))
    out = capsys.readouterr().out
    assert rc == 1
    assert "отменен" in out
    assert lease_calls["save"] == []


def test_protect_on_missing_token_refuses(monkeypatch, capsys):
    """ok=False (включая ref-течь без token) → rc 1, lease не пишется."""
    calls = _stub_isolate(monkeypatch, enable={"ok": False, "cancelled": False,
                                               "timeout": False, "token": None,
                                               "err": "pf включён, но release-token не получен"})
    lease_calls = _stub_lease(monkeypatch)
    rc = srouter_cli.cmd_protect(_args("on"))
    assert rc == 1
    assert lease_calls["save"] == []
    assert calls["enable"] == 1


def test_protect_on_preflight_fail_refuses_before_pf(monkeypatch, capsys):
    """preflight_state_write False → отказ rc 1 ДО pfctl (гейт #68 как в /api/isolate/enable):
    GUI-пароль и pf-ref не сжигаются."""
    calls = _stub_isolate(monkeypatch)
    lease_calls = _stub_lease(monkeypatch)
    monkeypatch.setattr(srouter_cli.local_state, "preflight_state_write",
                        lambda path=None: False)
    rc = srouter_cli.cmd_protect(_args("on"))
    out = capsys.readouterr().out
    assert rc == 1
    assert "недоступен на запись" in out
    assert calls["enable"] == 0, "pf-ref не создаётся до доказанного save-пути"
    assert lease_calls["save"] == []


def test_protect_on_save_rollback(monkeypatch, capsys):
    """save lease не удался → rollback disable_strict(token), rc 2 (fail-closed)."""
    calls = _stub_isolate(monkeypatch)
    lease_calls = _stub_lease(monkeypatch)
    # save «ломаем» после стационарного стаба
    monkeypatch.setattr(srouter_cli.local_state, "save_active_isolate",
                        lambda entry, path=None: None)
    rc = srouter_cli.cmd_protect(_args("on"))
    assert rc == 2
    assert calls["disable"] == ["777"], "rollback обязан снять якорь с тем же token"
    assert lease_calls["clear"] == 0


def test_protect_on_timeout_exit_2(monkeypatch, capsys):
    """timeout pfctl — инфраструктурный сбой → rc 2, stderr."""
    _stub_isolate(monkeypatch, enable={"ok": False, "cancelled": False, "timeout": True,
                                       "token": None, "err": "timeout"})
    _stub_lease(monkeypatch)
    rc = srouter_cli.cmd_protect(_args("on"))
    captured = capsys.readouterr()
    assert rc == 2
    assert "timeout" in captured.err


# ============================ off ============================

def test_protect_off_disables_and_clears(monkeypatch, capsys):
    """off при живом lease → disable_strict(token из lease) + clear, rc 0."""
    calls = _stub_isolate(monkeypatch)
    lease_calls = _stub_lease(monkeypatch, lease={"phase": "strict", "token": "42",
                                                  "domains": [], "ports": [80, 443]})
    rc = srouter_cli.cmd_protect(_args("off"))
    out = capsys.readouterr().out
    assert rc == 0
    assert "снята" in out
    assert calls["disable"] == ["42"], "token из lease идёт в pfctl -X"
    assert lease_calls["clear"] == 1


def test_protect_off_idempotent_without_lease(monkeypatch, capsys):
    """off без lease → disable_strict(None) всё равно зовётся (fail-safe flush), rc 0."""
    calls = _stub_isolate(monkeypatch)
    _stub_lease(monkeypatch, lease=None)
    rc = srouter_cli.cmd_protect(_args("off"))
    out = capsys.readouterr().out
    assert rc == 0
    assert "выключена" in out
    assert calls["disable"] == [None]


# ============================ status ============================

_STRICT_PROBE = {"status": "warn", "phase": "strict", "domains": [], "ips": {},
                 "unresolved": [], "ports": [80, 443], "applied_at": 1234}


def test_protect_status_strict_is_normal_steady_state(monkeypatch, capsys):
    """status при phase=strict → «ВКЛ» как норма (probe-warn бут-семантики не протекает);
    --state пробрасывается в probe (status работает с тем же state, что on/off)."""
    seen = {}

    def probe(state_path=None):
        seen["state_path"] = state_path
        return dict(_STRICT_PROBE)

    _stub_isolate(monkeypatch, probe=probe)
    rc = srouter_cli.cmd_protect(_args("status"))
    out = capsys.readouterr().out
    assert rc == 0
    assert "ВКЛ" in out
    assert "warn" not in out
    assert seen["state_path"] is None, "дефолтный --state доходит до probe"


def test_protect_status_working(monkeypatch, capsys):
    """status при working-lease (создан дашбордом) → «ВКЛ», rc 0."""
    probe = {"status": "ok", "phase": "working", "domains": ["api.anthropic.com"],
             "ips": {"api.anthropic.com": ["160.79.104.10"]}, "unresolved": [],
             "ports": [80, 443], "applied_at": 1234}
    _stub_isolate(monkeypatch, probe=lambda state_path=None: probe)
    rc = srouter_cli.cmd_protect(_args("status"))
    out = capsys.readouterr().out
    assert rc == 0
    assert "ВКЛ" in out
    assert "1 IP" in out


def test_protect_status_down_exit_1(monkeypatch, capsys):
    _stub_isolate(monkeypatch, probe=lambda state_path=None: {"status": "down",
                                                              "phase": "none"})
    rc = srouter_cli.cmd_protect(_args("status"))
    out = capsys.readouterr().out
    assert rc == 1
    assert "ВЫКЛ" in out


def test_protect_status_unknown_exit_2(monkeypatch, capsys):
    _stub_isolate(monkeypatch, probe=lambda state_path=None: {"status": "unknown",
                                                              "phase": "none",
                                                              "error": "битый state"})
    rc = srouter_cli.cmd_protect(_args("status"))
    captured = capsys.readouterr()
    assert rc == 2
    assert "нечитаем" in captured.err


# ============================ парсер и алиасы ============================

def test_protect_parser_wires_func_and_accepts_aliases():
    """build_parser: protect on/off/status + алиасы enable/disable/вкл/выкл → cmd_protect."""
    parser = srouter_cli.build_parser()
    for action in ("on", "off", "status", "enable", "disable", "вкл", "выкл"):
        args = parser.parse_args(["protect", action])
        assert args.protect_action == action
        assert args.func is srouter_cli.cmd_protect


def test_protect_alias_enable_maps_to_on(monkeypatch, capsys):
    """Алиас enable через НАСТОЯЩИЙ парсер ведёт себя как on: aliases= — тот же
    parser-объект, canonical из set_defaults подменяет typed-спеллинг алиаса."""
    # build_parser ДО стаба local_state: дефолты парсера читают реальный модуль.
    args = srouter_cli.build_parser().parse_args(["protect", "enable"])
    calls = _stub_isolate(monkeypatch)
    lease_calls = _stub_lease(monkeypatch)
    assert args.canonical == "on"
    rc = srouter_cli.cmd_protect(args)
    assert rc == 0
    assert calls["enable"] == 1
    assert len(lease_calls["save"]) == 1
