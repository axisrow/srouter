"""#410: общий post-install этап — паритет srouter install ↔ install.sh apply + wrappers repair.

Инцидент 2026-10-08 (Claude.app регион-блок, живая машина): doctor советовал «запусти
srouter install», но этап wrapper'ов жил ТОЛЬКО в srouter_cli.cmd_install — `./install.sh apply`
ставил стек без wrapper'ов/codenv/marker-миграций, а полный `srouter install` на конфликтной
машине блокировался. Фикс (канон fix-once, «оба CLI — тонкие обёртки»): этап — одна реализация
`srouter_cli.run_post_install`; main (install.sh apply) зовёт её после успешного apply_install.

Плюс точечный `srouter wrappers repair` — исполняемый совет doctor'а gui-wrappers для машины,
где полный install заблокирован (#200-guard/foreign): тем же продакшн-кодом установки
wrapper'ов, без brew/конфигов/DNS/рестартов; marker-gate чужое не трогает.
"""
import json
from pathlib import Path
from types import SimpleNamespace

import install_cleanup
import srouter_cli


class _FakeInstallEnv:
    """InstallEnv-стаб для main: from_env(state_path=..., prefix=...) как у боевого."""

    @classmethod
    def from_env(cls, state_path=None, prefix=None):
        return SimpleNamespace(state_path=state_path, prefix=prefix,
                               launchagent_dir=None, root=Path("."))


def _stub_main_success(monkeypatch, tmp_path, *, apply_result=None):
    """main(["apply", "-y"]) с застенными apply_install/этапом; возвращает (seen, stage_calls)."""
    seen = {}
    stage_calls = []
    monkeypatch.setattr(install_cleanup, "InstallEnv", _FakeInstallEnv)
    monkeypatch.setattr(install_cleanup, "apply_install",
                        lambda **k: (seen.update(k), apply_result or {"ok": True, "blocked": [], "actions": []})[1])
    monkeypatch.setattr(srouter_cli, "run_post_install",
                        lambda env, runner, **k: (stage_calls.append(k), "ЭТАП OK")[1])
    monkeypatch.setattr(srouter_cli, "make_privileged_runner",
                        lambda *a, **k: (lambda cmd, t: {"rc": 0}))
    return seen, stage_calls


# ================================ #410: install.sh apply выполняет этап ================================

def test_apply_runs_post_install_stage(monkeypatch, capsys, tmp_path):
    """ГЛАВНЫЙ красный тест #410: `./install.sh apply -y` после успешного apply_install обязан
    выполнить общий post-install этап (wrapper'ы/codenv/marker-миграции) — раньше этапа там
    не было, и wrapper отсутствовал неограниченно долго (инцидент 2026-10-08)."""
    seen, stage_calls = _stub_main_success(monkeypatch, tmp_path)

    rc = install_cleanup.main(["apply", "-y", "--state", str(tmp_path / "state.json")])

    assert rc == 0
    assert len(stage_calls) == 1, (
        f"#410: install.sh apply обязан вызвать run_post_install ровно раз; вызовы: {stage_calls}")
    assert stage_calls[0].get("record") is True, "свежий state (без legacy) → record=True"
    assert stage_calls[0].get("proxy_force", False) is False, (
        "у install.sh apply нет --force-proxy-overwrite → force=False (канон #307: чужое не перезаписывать)")
    out = capsys.readouterr().out
    assert "ЭТАП OK" in out, f"summary этапа печатается оператору: {out}"


def test_apply_stage_failure_reports_partial_rc2(monkeypatch, capsys, tmp_path):
    """Контракт cmd_install сохранён: raise (OSError) из этапа → rc=2 «частично», не тихий exit 0."""
    _stub_main_success(monkeypatch, tmp_path)

    def boom(env, runner, **k):
        raise OSError("install_files_invalid")

    monkeypatch.setattr(srouter_cli, "run_post_install", boom)

    rc = install_cleanup.main(["apply", "-y", "--state", str(tmp_path / "state.json")])

    assert rc == 2, "сбой истории восстановления не маскируется успешным apply"
    assert "частично" in capsys.readouterr().err.lower()


def test_apply_failure_skips_stage(monkeypatch, capsys, tmp_path):
    """apply_install не удался → этап не выполняется (нечего «post»-ить)."""
    _stub_main_success(monkeypatch, tmp_path,
                       apply_result={"ok": False, "blocked": ["xray_endpoint_overwrite_blocked"]})

    rc = install_cleanup.main(["apply", "-y", "--state", str(tmp_path / "state.json")])

    assert rc == 2
    captured = capsys.readouterr()
    assert "ЭТАП OK" not in captured.out and "ЭТАП OK" not in captured.err


def test_init_mode_skips_stage(monkeypatch, capsys, tmp_path):
    """init — bootstrap-режим (всё skip, без LaunchAgent): этап не выполняется. Паритет этапа —
    только для apply (#410); init осознанно минимальный, сюрпризных записей не добавляем."""
    seen, stage_calls = _stub_main_success(monkeypatch, tmp_path)

    rc = install_cleanup.main(["init", "-y", "--state", str(tmp_path / "state.json")])

    assert rc == 0
    assert stage_calls == [], "init не должен выполнять post-install этап"
    assert seen.get("install_launchagent") is False


# ================================ #410: record-режим из PRE-apply state ================================

def test_apply_record_false_for_legacy_state(monkeypatch, capsys, tmp_path):
    """Legacy-state (managed-записи в detected_environment без install_files) → этапу record=False.
    Считывается ДО apply_install (после apply запись этапа сама создала бы install_files)."""
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({
        "detected_environment": {"xray": {"management": {"managed": True}}},
    }), encoding="utf-8")
    _, stage_calls = _stub_main_success(monkeypatch, tmp_path)

    rc = install_cleanup.main(["apply", "-y", "--state", str(state_path)])

    assert rc == 0
    # should_record_install_files здесь НЕ застенен — проверяем реальный предикат сквозь main.
    assert stage_calls[0].get("record") is False, "legacy-state → record=False (не переписывать legacy-форму)"


def test_apply_record_true_for_fresh_state(monkeypatch, capsys, tmp_path):
    """Свежий/пустой state → record=True (install_restore ведёт историю для uninstall)."""
    _stub_main_success(monkeypatch, tmp_path)

    rc = install_cleanup.main(["apply", "-y", "--state", str(tmp_path / "absent.json")])

    assert rc == 0


# ================================ #410: cmd_install delegates to the stage ================================

def _stub_cmd_install_wiring(monkeypatch):
    """Минимальный стаб cmd_install до apply_install (детали этапа мокаются точечно в тестах)."""
    monkeypatch.setattr(srouter_cli, "_env_from_args",
                        lambda args: SimpleNamespace(root=Path("."), state_path=Path("/private/tmp/srouter-unit-state.json")))
    monkeypatch.setattr(srouter_cli, "make_privileged_runner", lambda *a, **k: (lambda cmd, t: {"rc": 0}))
    monkeypatch.setattr(srouter_cli, "build_plan", lambda **k: {"components": {}})
    monkeypatch.setattr(srouter_cli, "format_plan", lambda p: "")
    monkeypatch.setattr(srouter_cli, "apply_install",
                        lambda **k: {"ok": True, "blocked": [], "actions": []})
    import sys as _sys
    monkeypatch.setattr(_sys, "stdin", SimpleNamespace(isatty=lambda: False))


def test_cmd_install_passes_record_and_force_to_stage(monkeypatch, capsys):
    """cmd_install делегирует этап run_post_install с record из PRE-apply state и force из флага.
    Гвард проводки: флаги не теряются при переносе тела в общую функцию (#410 fix-once)."""
    _stub_cmd_install_wiring(monkeypatch)
    stage_calls = []
    monkeypatch.setattr(srouter_cli, "should_record_install_files", lambda env: False)
    monkeypatch.setattr(srouter_cli, "run_post_install",
                        lambda env, runner, **k: (stage_calls.append(k), "ЭТАП OK")[1])

    args = SimpleNamespace(state=None, prefix=None, launchagents_dir=None, python=None,
                           yes=True, force_proxy_overwrite=True)
    rc = srouter_cli.cmd_install(args)

    assert rc == 0
    assert stage_calls == [{"record": False, "proxy_force": True}], stage_calls
    assert "ЭТАП OK" in capsys.readouterr().out


# ================================ #410: srouter wrappers repair ================================

def _wrappers_repair_args():
    return SimpleNamespace(state=None, prefix=None, launchagents_dir=None, python=None)


def test_wrappers_repair_installs_family(monkeypatch, capsys):
    """`srouter wrappers repair` ставит ОБЕ ветки семейства gui-wrapper'ов тем же продакшн-кодом,
    что install: codex-* (_install_codex_wrappers) + claude-app (_install_claude_app_wrapper).
    Инцидент 2026-10-08: тот же объём делался /tmp-скриптом вне продукта."""
    calls = []
    monkeypatch.setattr(srouter_cli, "_env_from_args",
                        lambda args: SimpleNamespace(root=Path("."), state_path=Path("/tmp/x.json")))
    monkeypatch.setattr(srouter_cli, "_install_codex_wrappers",
                        lambda env: (calls.append("codex"), "codex: установлен")[1])
    monkeypatch.setattr(srouter_cli, "_install_claude_app_wrapper",
                        lambda env: (calls.append("claude"), "claude: установлен")[1])

    rc = srouter_cli.cmd_wrappers_repair(_wrappers_repair_args())

    assert rc == 0
    assert calls == ["codex", "claude"], f"обе ветки семейства вызваны; вызовы: {calls}"
    out = capsys.readouterr().out
    assert "codex: установлен" in out and "claude: установлен" in out


def test_parser_has_wrappers_repair():
    """Парсер: `srouter wrappers repair` — sub-subparser как у system-proxy/git-proxy."""
    args = srouter_cli.build_parser().parse_args(["wrappers", "repair"])
    assert args.wrappers_action == "repair"
    assert args.func is srouter_cli.cmd_wrappers_repair


# ================================ #410: doctor-подсказка исполнима ================================

def test_should_record_install_files_predicate(tmp_path):
    """Предикат record-режима: legacy-state → False; fresh/пустой → True; install_files есть → True."""
    env = SimpleNamespace(state_path=str(tmp_path / "state.json"))
    assert srouter_cli.should_record_install_files(env) is True, "нет state → fresh"

    (tmp_path / "state.json").write_text(json.dumps({
        "detected_environment": {"xray": {"management": {"managed": True}}},
    }), encoding="utf-8")
    assert srouter_cli.should_record_install_files(env) is False, "legacy без install_files → False"

    (tmp_path / "state.json").write_text(json.dumps({
        "detected_environment": {
            "xray": {"management": {"managed": True}},
            "install_files": {"claude": {}},
        },
    }), encoding="utf-8")
    assert srouter_cli.should_record_install_files(env) is True, "install_files уже ведётся → True"
