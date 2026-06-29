import sys
from pathlib import Path

# Добавляем корень проекта в sys.path, чтобы root-level модули (local_state и т.д.)
# были видны из tests/ без копирования и без установки пакета.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
