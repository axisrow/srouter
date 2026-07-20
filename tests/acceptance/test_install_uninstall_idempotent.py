"""Приёмочные тесты реального CLI srouter в Docker-полигоне (issue #112).

End-to-end приёмка install/uninstall цикла в изолированном Linux-контейнере с macOS-binary stub'ами.
Герметичные pytest (744 шт.) покрывают бизнес-логику через FakeRunner+tmp_path, но НЕ запускают
реальный CLI целиком. Этот модуль закрывает зазор: `srouter install`/`uninstall` как subprocess против
in-container окружения (fake launchctl/brew/networksetup/osascript/route по тем же абсолютным путям).

Skip без SROUTER_ACCEPTANCE=1 — чтобы не ломать 744 быстрых теста на dev-машине. Запускается только
внутри Docker-полигона: `./docker/run-acceptance.sh`.
"""
import os
import subprocess

import pytest

pytestmark = [
    pytest.mark.acceptance,
    pytest.mark.skipif(
        os.environ.get("SROUTER_ACCEPTANCE") != "1",
        reason="acceptance-тест: только в Docker-полигоне (SROUTER_ACCEPTANCE=1)",
    ),
]


def _cli_env(tmp_path):
    """Окружение для дочернего `srouter` CLI: все macOS-пути перебиты на in-container tmp.

    envvars читаются _env_from_args (srouter.py) → InstallEnv.from_env (install_lib.py:74-86):
    SROUTER_PREFIX/STATE_PATH/LAUNCHAGENTS_DIR/PYTHON/LOG_DIR — все крюки есть. CLI-флаги НЕ передаём —
    намеренно через env, чтобы протестировать, что env-параметризация работает (канон: ноль правок кода).
    """
    return {
        **os.environ,
        "SROUTER_STATE_PATH": str(tmp_path / "srouter.local.json"),
        "SROUTER_PREFIX": str(tmp_path / "homebrew"),
        "SROUTER_LAUNCHAGENTS_DIR": str(tmp_path / "LaunchAgents"),
        "SROUTER_LOG_DIR": str(tmp_path / "logs"),
    }


def test_uninstall_then_install_is_idempotent(tmp_path):
    """Приёмка #110/#112: полный CLI-цикл uninstall→install в Linux-полигоне → rc=0 (без macOS).

    До Docker-полигона (без stub'ов launchctl/brew) install падал на первом brew services. После
    stub'ов → rc=0 (или честный rc=2 с leftover), идемпотентно. Это доказывает, что бизнес-логика
    #110/#111 работает end-to-end в окружении без macOS, а не только под FakeRunner.
    """
    env = _cli_env(tmp_path)

    uninstall = subprocess.run(["srouter", "uninstall", "-y"], env=env, capture_output=True)
    install = subprocess.run(["srouter", "install", "-y"], env=env, capture_output=True)
    # Повторный uninstall — идемпотентность: не накапливает конфликты, не падает на «своём старом».
    uninstall2 = subprocess.run(["srouter", "uninstall", "-y"], env=env, capture_output=True)

    assert install.returncode == 0, (
        f"install должен пройти rc=0 в полигоне со stub'ами. rc={install.returncode}\n"
        f"stdout:\n{install.stdout.decode(errors='replace')}\n"
        f"stderr:\n{install.stderr.decode(errors='replace')}"
    )
    assert uninstall2.returncode in (0, 2), (
        f"повторный uninstall должен быть rc=0 (полный откат) или rc=2 (честный partial leftover), "
        f"не краш. rc={uninstall2.returncode}\n"
        f"stderr:\n{uninstall2.stderr.decode(errors='replace')}"
    )
