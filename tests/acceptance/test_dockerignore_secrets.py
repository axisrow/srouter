"""TDD-гвард: .dockerignore + .gitignore РЕАЛЬНО игнорируют секреты (cycle-review #114 C1/C3/C4/C5/C6).

COPY . в Dockerfile копирует ВЕСЬ build-context; .gitignore НЕ фильтрует Docker (разные механизмы).
Без .dockerignore секреты (srouter.local.json с Reality-материалом, srouter_config.py, server/.env с
XRAY_PRIVATE_KEY/UUID/SHORT_ID, atomic-write temp .tmp, timestamped backup) запекаются в слой образа.

История цикл-ревью:
- C1: нет .dockerignore → секреты в образе.
- C3: .tmp/backup не покрыты.
- C4: inline-комментарии на строке паттерна ломали ignore (Docker/git '#' только в начале строки).
- C5: glob .env без ** не покрывал server/.env (Docker требует ** для поддиректорий).
- C6: git check-ignore валидирует .gitignore, НЕ .dockerignore → гард молчал на мутацию .dockerignore.

Два независимых гард'а:
  - .gitignore → git check-ignore (ground truth git-семантики). Host-side (в контейнере .git исключён).
  - .dockerignore → ручной parse + pattern-match (** → .*, * → [^/]*), Docker/semantics. Работает везде
    (не зависит от .git) — это и есть Docker security gate, которого не хватало (C6).
"""
import re
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]

# Секретные/локальные пути, которые ДОЛЖНЫ игнорироваться. Каждый — реальный артефакт srouter.
# C5: server/.env (Reality-секреты XRAY_PRIVATE_KEY/UUID/SHORT_ID) — отдельный уровень вложенности.
_SECRET_PATHS = [
    "srouter.local.json",
    "srouter.local.json.tmp",      # save_state atomic-write (local_state.py:596)
    "srouter_config.py",
    ".env",
    "srouter.hot_routes.json",
    "srouter.hot_routes.json.tmp",
    "config.srouter-backup-2026-07-20T000000Z",   # _backup() timestamped (install_lib.py:599)
    "server/.env",                 # C5: nested (server/README.md — Reality-секреты)
    "server/rendered/node.json",   # C5: сгенерированный артефакт с ключами (server/.generated)
]


def _git_check_ignore(path: str) -> bool:
    """True если git РЕАЛЬНО игнорирует path (ground truth для .gitignore-семантики)."""
    result = subprocess.run(
        ["git", "-C", str(_ROOT), "check-ignore", path],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def _dockerignore_patterns() -> list:
    """Прочитать .dockerignore → список паттернов (skip '#'-строк и пустых). .dockerignore: negate '!'."""
    di = _ROOT / ".dockerignore"
    if not di.exists():
        return []
    patterns = []
    for line in di.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        # C4: '#' как комментарий только в НАЧАЛЕ строки. Если '#' не в начале — это часть паттерна
        # (баг). Мы парсим только чистые паттерн-строки; inline-comment-строки сюда попадают целиком
        # (с мусором) и НЕ сматчат реальный файл → тест поймает (C4 regression).
        if not stripped or stripped.startswith("#"):
            continue
        patterns.append(stripped)
    return patterns


def _dockerignore_matches(path: str, patterns: list) -> bool:
    """Соответствует ли path хотя бы одному .dockerignore-паттерну (Docker/gitignore semantics).

    Трансляция glob → regex:
      - ведущий `**/` → опциональный любой префикс директории (`(.*/)?`) — чтобы `**/.env` матчило и
        корневой `.env`, и `server/.env` (Docker semantics: ** в начале покрывает любой уровень).
      - внутреннее `**` → `.*` (любой путь вкл. /).
      - `*` → `[^/]*` (сегмент без /).
      - `?` → `.`.
    Negate `!` инвертирует последнее совпадение. Упрощённая семантика (без directory-only) — достаточно.
    """
    matched = False
    for pat in patterns:
        negate = pat.startswith("!")
        if negate:
            pat = pat[1:]
        regex = re.escape(pat)
        # Ведущий **/ → опциональный dir-префикс (чтобы **/.env матчило и корень, и поддиректории).
        regex = regex.replace(r"\*\*/", r"(?:.*/)?", 1)
        # Оставшиеся ** → любой путь.
        regex = regex.replace(r"\*\*", ".*")
        regex = regex.replace(r"\*", "[^/]*").replace(r"\?", ".")
        if re.fullmatch(regex, path):
            matched = not negate
    return matched


def test_dockerignore_exists():
    """`.dockerignore` существует (C1). Без него COPY . тащит секреты в образ.

    Работает и в контейнере. `.gitignore` НЕ проверяем тут — он исключён из образа (.dockerignore),
    в рантайме не нужен; его наличие проверяет host-side git-гард ниже.
    """
    assert (_ROOT / ".dockerignore").exists(), ".dockerignore отсутствует"


def test_secret_paths_ignored_by_git():
    """Секретные пути РЕАЛЬНО игнорируются git (C3+C4) — git check-ignore ground truth.

    Host-side: в контейнере .git исключён → skip. Это гард .gitignore (commit-leakage).
    """
    if not (_ROOT / ".git").exists():
        pytest.skip("host-side: в контейнере .git исключён — git check-ignore неприменим")
    not_ignored = [p for p in _SECRET_PATHS if not _git_check_ignore(p)]
    assert not not_ignored, (
        f"Секретные пути НЕ игнорируются git: {not_ignored}. "
        f"Частая причина (C4): inline-комментарий на строке паттерна."
    )


def test_secret_paths_ignored_by_dockerignore():
    """Секретные пути покрыты .dockerignore паттернами (C5+C6) — независимый Docker security gate.

    git check-ignore НЕ валидирует .dockerignore (C6). Этот тест парсит .dockerignore и проверяет
    pattern-match напрямую. Работает и в контейнере (не зависит от .git) — это и есть Docker-gate.
    C5: server/.env требует ** (Docker glob без ** матчит только корень контекста).
    """
    patterns = _dockerignore_patterns()
    not_covered = [p for p in _SECRET_PATHS if not _dockerignore_matches(p, patterns)]
    assert not_covered == [], (
        f"Секретные пути НЕ покрыты .dockerignore паттернами: {not_covered}. "
        f"C5: для поддиректорий нужен ** (server/.env). C4: inline-комментарий ломает паттерн."
    )
