"""install.sh apply не может отрендерить plist питоном без flask (инцидент 2026-10-08).

Полный путь инцидента: ./install.sh apply без SROUTER_PYTHON → install.sh дефолтил
/usr/bin/python3 (Apple) → install_lib.py исполняется им же → from_env sys.executable =
тот же Apple-python (фикс from_env для этого пути no-op) → plist с python_bin без
flask → CrashLoop демона. Гейт: для apply выбранный python обязан импортировать flask —
иначе fail-closed с диагнозом, а не тихий запуск с последующим краш-лупом.
"""
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO / "install.sh"


def _stub_python(tmp_path, rc):
    p = tmp_path / f"stubpy_rc{rc}"
    p.write_text(f"#!/bin/sh\nexit {rc}\n", encoding="utf-8")
    p.chmod(0o755)
    return str(p)


def _run_install_sh(tmp_path, stub_rc):
    env = {"SROUTER_PYTHON": _stub_python(tmp_path, stub_rc), "PATH": "/usr/bin:/bin"}
    return subprocess.run(["bash", str(INSTALL_SH), "apply", "--yes"],
                          capture_output=True, text=True, env=env, timeout=30)


def test_install_sh_apply_dies_when_python_lacks_flask(tmp_path):
    """python без flask (stub rc=1) → apply обязан упасть ДО exec с диагнозом и ремонтом,
    не молча (молча = rc 1 без текста, как до гейта)."""
    r = _run_install_sh(tmp_path, stub_rc=1)
    assert r.returncode == 1
    assert "flask" in r.stderr
    assert "SROUTER_PYTHON" in r.stderr


def test_install_sh_apply_passes_gate_and_execs(tmp_path):
    """python «с flask» (stub rc=0) → гейт пропускает, exec уходит в stub —
    install_lib.py не исполняется, тест без побочных эффектов."""
    r = _run_install_sh(tmp_path, stub_rc=0)
    assert r.returncode == 0
