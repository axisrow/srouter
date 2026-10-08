"""Красный тест инцидента 2026-10-08: InstallEnv.from_env дефолтил python_bin в
/usr/bin/python3 (Apple python БЕЗ flask) — ./install.sh apply отрендерил им plist
демона → CrashLoop ModuleNotFoundError: No module named 'flask'.

Канон srouter.py:_env_from_args: дефолт = sys.executable (интерпретатор команды —
в нём гарантированно есть flask как зависимость пакета srouter), SROUTER_PYTHON —
старший override. Фикс в from_env закрывает ОБА CLI (srouter install и ./install.sh).
"""
import sys

from install_config import InstallEnv


def test_from_env_python_bin_defaults_to_running_interpreter(monkeypatch):
    monkeypatch.delenv("SROUTER_PYTHON", raising=False)
    env = InstallEnv.from_env()
    assert env.python_bin == sys.executable


def test_from_env_srouter_python_override_wins(monkeypatch):
    monkeypatch.setenv("SROUTER_PYTHON", "/opt/custom/python3")
    env = InstallEnv.from_env()
    assert env.python_bin == "/opt/custom/python3"
