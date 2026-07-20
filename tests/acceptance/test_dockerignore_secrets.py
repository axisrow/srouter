"""TDD-гвард: .dockerignore + .gitignore РЕАЛЬНО игнорируют секреты (cycle-review #114 C1/C3/C4).

COPY . в Dockerfile копирует ВЕСЬ build-context; .gitignore НЕ фильтрует Docker (разные механизмы).
Без .dockerignore секреты (srouter.local.json с Reality-материалом/UUID/endpoints, srouter_config.py,
.env, atomic-write temp .tmp, timestamped backup) запекаются в слой образа → утечка.

C4 (Codex confidence 1.0): inline-комментарии на строке паттерна ломают ignore — Docker/git парсят '#'
как комментарий ТОЛЬКО в начале строки. `srouter.local.json.tmp    # comment` НЕ матчит реальный файл.
Substring-тест (C3) это пропустил — паттерн в тексте есть, но не работает. Этот гард проверяет
РЕАЛЬНУЮ семантику через `git check-ignore` (ground truth для gitignore; dockerignore использует те же
паттерны). Не skip'ится SROUTER_ACCEPTANCE (static — git check-ignore, ничего деструктивного).
"""
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]

# Секретные/локальные пути, которые ДОЛЖНЫ игнорироваться (build-context + git). Каждый — реальный
# артефакт, что srouter пишет на диск: config, atomic-write temp, timestamped backup, privacy-cache.
_SECRET_PATHS = [
    "srouter.local.json",
    "srouter.local.json.tmp",      # save_state atomic-write (local_state.py:596)
    "srouter_config.py",
    ".env",
    "srouter.hot_routes.json",
    "srouter.hot_routes.json.tmp",
    "config.srouter-backup-2026-07-20T000000Z",   # _backup() timestamped (install_lib.py:599)
]


def _git_check_ignore(path: str) -> bool:
    """True если git РЕАЛЬНО игнорирует path (ground truth для gitignore-семантики).

    `git check-ignore <path>` возвращает rc=0, если путь игнорируется. rc=1 — не игнорируется. Docker
    .dockerignore использует те же pattern-семантики, так что git check-ignore валиден как прокси для
    обоих (C4: inline-коммент в .dockerignore так же ломает паттерн).
    """
    result = subprocess.run(
        ["git", "-C", str(_ROOT), "check-ignore", path],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def test_dockerignore_exists_and_covers_secrets():
    """.dockerignore существует и покрывает секреты/локальный-state (C1). Static-наличие.

    Работает и в контейнере (нет .git) — просто проверяет файл.
    """
    dockerignore = _ROOT / ".dockerignore"
    assert dockerignore.exists(), (
        ".dockerignore отсутствует — COPY . в acceptance.Dockerfile утащит секреты в образ. "
        ".gitignore НЕ фильтрует Docker build-context."
    )


def test_secret_paths_actually_ignored():
    """Секретные пути РЕАЛЬНО игнорируются git (C3+C4) — не просто паттерн-в-файле, а работающий.

    C4 поймал: паттерн `srouter.local.json.tmp    # comment` в .gitignore/.dockerignore есть (substring-
    тест проходил), НО git check-ignore НЕ игнорирует файл (inline-коммент ломает паттерн — '#' только
    в начале строки). Этот тест — ground-truth через git check-ignore на каждом реальном секретном артефакте.

    Только host-side: в Docker-контейнере .git исключён (.dockerignore) → git check-ignore неприменим.
    Тестируем целостность ignore-файлов на dev-машине (где .git есть).
    """
    if not (_ROOT / ".git").exists():
        pytest.skip("host-side гард: в контейнере .git исключён — git check-ignore неприменим")
    not_ignored = [p for p in _SECRET_PATHS if not _git_check_ignore(p)]
    assert not not_ignored, (
        f"Эти секретные пути НЕ игнорируются git (значит, и .dockerignore их не исключит — те же "
        f"паттерны; COPY . утащит в образ): {not_ignored}. "
        f"Частая причина (C4): inline-комментарий на строке паттерна — '#' только в начале строки."
    )
