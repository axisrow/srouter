import sys
from pathlib import Path
from unittest import mock

import pytest

# Добавляем корень проекта в sys.path, чтобы root-level модули (local_state и т.д.)
# были видны из tests/ без копирования и без установки пакета.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


@pytest.fixture(autouse=True)
def _block_osascript_admin(monkeypatch):
    """Глобальный предохранитель: ни один тест не должен вызывать реальный osascript с
    'with administrator privileges' — это выпрыгнет GUI-диалогом пароля.

    Перехватываем subprocess.run (основа sys_probe.run): если команда = osascript с admin-мостом,
    возвращаем success no-op вместо реального вызова. Тесты, которым нужно проверять argv
    osascript-вызовов, мокают sys_probe.run сами (поверх этого fixture — monkeypatch выигрывает
    у fixture, т.к. fixture выполняется раньше).
    """
    import subprocess
    _real_run = subprocess.run

    def _guarded_run(cmd, *args, **kwargs):
        try:
            is_osascript = isinstance(cmd, list) and cmd and "osascript" in str(cmd[0])
        except Exception:
            is_osascript = False
        if is_osascript:
            # osascript с admin — возвращаем success no-op (тест не должен звать GUI).
            return mock.Mock(returncode=0, stdout="", stderr="")
        return _real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", _guarded_run)
