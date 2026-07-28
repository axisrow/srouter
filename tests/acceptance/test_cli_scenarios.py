"""Приёмочные CLI-сценарии в Docker-полигоне (issue #116, follow-up #114).

Расширяет `test_install_uninstall_idempotent.py` (только install/uninstall идемпотентность) тремя
дополнительными реальными CLI-сценариями:
  - `srouter status`/`srouter doctor` — read-only цикл (без install, безопасно в любом состоянии).
  - conflict-resolution (adopt/overwrite/skip) — реальный CLI `install_lib.py apply --<name> <choice>`
    против «чужого» (non-srouter-managed) конфига в build-context.
  - edge-case из #110/#111 (cycle-review #111 cycle 2 finding B): свежий install без backup → uninstall
    НЕ должен репортить leftover (это managed-состояние, не stale/partial).

Тот же fail-closed sentinel-gate, что и в test_install_uninstall_idempotent.py (SROUTER_ACCEPTANCE=1
+ Linux + /srouter-acceptance-sentinel + изолированный HOME) — см. docstring там для полного
обоснования канона privileged-boundary-fail-closed.
"""
import os
import subprocess
import sys

import pytest

_SENTINEL = "/srouter-acceptance-sentinel"

pytestmark = [
    pytest.mark.acceptance,
    pytest.mark.skipif(
        not (
            os.environ.get("SROUTER_ACCEPTANCE") == "1"
            and sys.platform == "linux"
            and os.path.exists(_SENTINEL)
        ),
        reason="acceptance-тест: только в Docker-полигоне (SROUTER_ACCEPTANCE=1 + Linux + sentinel)",
    ),
]


def _cli_env(tmp_path):
    """Тот же env-контракт, что test_install_uninstall_idempotent.py::_cli_env."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return {
        **os.environ,
        "HOME": str(home),
        "SROUTER_STATE_PATH": str(tmp_path / "srouter.local.json"),
        "SROUTER_PREFIX": str(tmp_path / "homebrew"),
        "SROUTER_LAUNCHAGENTS_DIR": str(tmp_path / "LaunchAgents"),
        "SROUTER_LOG_DIR": str(tmp_path / "logs"),
    }


def test_status_read_only_before_install(tmp_path):
    """`srouter status` — read-only, безопасен без install (LaunchAgent ещё не существует).

    srouter.py::cmd_status читает launchctl list (stub всегда возвращает пустую таблицу — путь 3,
    docker/stubs/launchctl.sh) + наличие plist на диске. Без install оба источника пусты →
    детерминированный rc=1 ("НЕ загружен"), не крашится и не виснет.
    """
    env = _cli_env(tmp_path)

    result = subprocess.run(["srouter", "status"], env=env, capture_output=True, timeout=15)

    assert result.returncode == 1, (
        f"status без install должен быть rc=1 (не загружен), не краш. rc={result.returncode}\n"
        f"stdout:\n{result.stdout.decode(errors='replace')}\n"
        f"stderr:\n{result.stderr.decode(errors='replace')}"
    )
    assert b"srouter.dashboard" in result.stdout, "status должен назвать LaunchAgent по имени"


def test_doctor_read_only_reports_degraded_without_stack(tmp_path):
    """`srouter doctor` — read-only, детерминированно репортит DEGRADED без реального прокси-стека.

    health.check_all делает реальные probe (порты/DNS/туннель) — в контейнере без xray/privoxy/VPS
    все компоненты честно "down"/"warn" → rc=1. Тест проверяет, что doctor НЕ виснет (timeout) и НЕ
    крашится (traceback), а завершается предсказуемым кодом — сам полигон не эмулирует живой прокси.
    """
    env = _cli_env(tmp_path)

    result = subprocess.run(["srouter", "doctor"], env=env, capture_output=True, timeout=30)

    assert result.returncode in (0, 1), (
        f"doctor должен вернуть 0 (ok) или 1 (degraded), не краш. rc={result.returncode}\n"
        f"stderr:\n{result.stderr.decode(errors='replace')}"
    )
    assert b"Traceback" not in result.stderr, (
        f"doctor не должен падать с traceback:\n{result.stderr.decode(errors='replace')}"
    )


def _write_foreign_xray_config(tmp_path):
    """Кладёт non-srouter-managed xray config.json (без marker) → провоцирует conflict в build_plan."""
    xray_dir = tmp_path / "homebrew" / "etc" / "xray"
    xray_dir.mkdir(parents=True, exist_ok=True)
    (xray_dir / "config.json").write_text('{"foreign": true}\n', encoding="utf-8")


def test_conflict_plan_reports_foreign_config(tmp_path):
    """install_lib.py plan детектирует «чужой» (non-srouter) config → CONFLICT, без выбора не пишет.

    srouter.py::cmd_install у не-TTY subprocess без conflicts всегда вернёт rc=2 «разрешите вручную»
    (нет CLI-флага --on-conflict в srouter entry-point — см. issue #116 п.4 исследование). Программные
    choices (adopt/overwrite/skip) доступны через install_lib.py apply --<name> <choice> (install.sh
    entry-point) — тестируем реальный CLI-путь, которым конфликт РЕАЛЬНО разрешается программно.
    """
    env = _cli_env(tmp_path)
    _write_foreign_xray_config(tmp_path)

    plan = subprocess.run(
        ["python3", "install_lib.py", "plan",
         "--state", env["SROUTER_STATE_PATH"], "--prefix", env["SROUTER_PREFIX"],
         "--launchagents-dir", env["SROUTER_LAUNCHAGENTS_DIR"]],
        cwd="/srouter", env=env, capture_output=True, timeout=15,
    )

    assert plan.returncode == 0, f"plan не должен падать: {plan.stderr.decode(errors='replace')}"
    assert b"CONFLICT" in plan.stdout, (
        f"plan должен показать CONFLICT для чужого xray config:\n{plan.stdout.decode(errors='replace')}"
    )
    assert b"foreign_config" in plan.stdout


@pytest.mark.parametrize("choice", ["overwrite", "adopt", "skip"])
def test_conflict_resolution_via_explicit_choice(tmp_path, choice):
    """Каждый conflict-resolution choice (adopt/overwrite/skip) реально проходит через CLI, rc=0.

    - overwrite: чужой config перезаписывается + создаётся backup (issue #110/#111 backup-контракт).
    - adopt: чужой config остаётся как есть, srouter «усыновляет» (управляет без перезаписи).
    - skip: компонент вообще не трогается apply'ем.
    Все три — реальный `python3 install_lib.py apply` subprocess, не FakeRunner/юнит-мок.
    """
    env = _cli_env(tmp_path)
    _write_foreign_xray_config(tmp_path)
    xray_config = tmp_path / "homebrew" / "etc" / "xray" / "config.json"
    original_content = xray_config.read_text(encoding="utf-8")

    apply = subprocess.run(
        ["python3", "install_lib.py", "apply", "-y",
         "--xray", choice, "--privoxy", "skip", "--dnsmasq", "skip",
         "--state", env["SROUTER_STATE_PATH"], "--prefix", env["SROUTER_PREFIX"],
         "--launchagents-dir", env["SROUTER_LAUNCHAGENTS_DIR"]],
        cwd="/srouter", env=env, capture_output=True, timeout=30,
    )

    assert apply.returncode == 0, (
        f"apply --xray {choice} должен пройти rc=0. rc={apply.returncode}\n"
        f"stdout:\n{apply.stdout.decode(errors='replace')}\n"
        f"stderr:\n{apply.stderr.decode(errors='replace')}"
    )

    if choice == "overwrite":
        backups = list(xray_config.parent.glob("config.json.srouter-backup-*"))
        assert backups, "overwrite должен создать backup чужого конфига (issue #110/#111 контракт)"
        assert xray_config.read_text(encoding="utf-8") != original_content, (
            "overwrite должен заменить содержимое config.json на srouter-managed"
        )
    elif choice == "skip":
        assert xray_config.read_text(encoding="utf-8") == original_content, (
            "skip НЕ должен трогать содержимое чужого config.json"
        )
    elif choice == "adopt":
        assert xray_config.read_text(encoding="utf-8") == original_content, (
            "adopt НЕ перезаписывает содержимое (усыновление «как есть», без backup/overwrite)"
        )


def test_fresh_install_without_backup_reports_no_leftover(tmp_path):
    """Edge-case #110/#111 finding B: свежий install (marker есть, backup отсутствует) → uninstall
    НЕ должен считать это leftover.

    cycle-review #111 cycle 2 finding B (install_lib.py:1382+) сузил определение leftover: managed=True
    + marker есть + backup отсутствует — нормальное определённое managed-состояние (первый install),
    НЕ stale. Юнит-тест test_uninstall_flow.py::test_apply_uninstall_no_leftover_for_fresh_install_without_backup
    покрывает это через FakeRunner; здесь — тот же сценарий end-to-end через реальный CLI-subprocess.
    """
    env = _cli_env(tmp_path)

    install = subprocess.run(["srouter", "install", "-y"], env=env, capture_output=True, timeout=60)
    assert install.returncode == 0, (
        f"install должен пройти rc=0 (чистая установка, без чужих конфигов). rc={install.returncode}\n"
        f"stderr:\n{install.stderr.decode(errors='replace')}"
    )

    # Свежий install не создаёт backup (нет что бэкапить — конфигов не было). uninstall должен
    # признать managed-состояние без leftover, а не «stale, нет backup → leftover».
    uninstall = subprocess.run(["srouter", "uninstall", "-y"], env=env, capture_output=True, timeout=60)

    assert uninstall.returncode == 0, (
        f"uninstall свежего install (без backup) должен быть rc=0, НЕ leftover (finding B). "
        f"rc={uninstall.returncode}\n"
        f"stdout:\n{uninstall.stdout.decode(errors='replace')}\n"
        f"stderr:\n{uninstall.stderr.decode(errors='replace')}"
    )
