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

Три независимых гард'а:
  - .gitignore → git check-ignore (ground truth git-семантики). Host-side (в контейнере .git исключён).
  - .dockerignore → ручной parse + pattern-match (** → .*, * → [^/]*), Docker/semantics. Работает везде
    (не зависит от .git).
  - Docker-native canary (issue #116) → реальный `docker build` с временными секретными файлами в
    build-context + `docker run test -e` на готовом образе. Ручной parse выше приближает Docker-семантику
    регулярками, но не гарантирует 100% совпадение с реальным движком (directory-only паттерны, ** в
    середине пути). Canary — это правда напрямую от Docker, без посредника-парсера.
"""
import re
import shutil
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
    C5: server/.env требует ** (Docker glob без ** матчит только корень build-context).
    """
    patterns = _dockerignore_patterns()
    not_covered = [p for p in _SECRET_PATHS if not _dockerignore_matches(p, patterns)]
    assert not_covered == [], (
        f"Секретные пути НЕ покрыты .dockerignore паттернами: {not_covered}. "
        f"C5: для поддиректорий нужен ** (server/.env). C4: inline-комментарий ломает паттерн."
    )


# ---------------------------------------------------------------------------
# Docker-native build-context canary (issue #116)
# ---------------------------------------------------------------------------

_CANARY_IMAGE = "srouter-dockerignore-canary"
_CANARY_DOCKERFILE = _ROOT / "docker" / "canary.Dockerfile"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    probe = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
    return probe.returncode == 0


@pytest.fixture(scope="module")
def canary_image():
    """Собрать реальный Docker-образ из репо С временными секретными файлами в build-context.

    Ни один путь из _SECRET_PATHS не должен существовать ДО теста (иначе рискуем утащить
    настоящий локальный секрет разработчика в docker build или удалить его в finally) —
    fail-closed: если хоть один уже существует, skip (не создаём/не удаляем чужие файлы).
    """
    if not _docker_available():
        pytest.skip("Docker недоступен в этом окружении (docker CLI/daemon)")

    preexisting = [p for p in _SECRET_PATHS if (_ROOT / p).exists()]
    if preexisting:
        pytest.skip(
            f"secret-пути уже существуют на диске (реальные локальные файлы?): {preexisting}. "
            f"Canary не трогает существующие файлы — пропуск, чтобы не рисковать чужими секретами."
        )

    created = []
    try:
        for rel in _SECRET_PATHS:
            target = _ROOT / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("canary-secret-should-not-be-in-image\n", encoding="utf-8")
            created.append(target)

        build = subprocess.run(
            [
                "docker", "build",
                "-f", str(_CANARY_DOCKERFILE),
                "-t", _CANARY_IMAGE,
                str(_ROOT),
            ],
            capture_output=True, text=True, timeout=180,
        )
        assert build.returncode == 0, (
            f"docker build canary упал rc={build.returncode}\n"
            f"stdout:\n{build.stdout}\nstderr:\n{build.stderr}"
        )
        yield _CANARY_IMAGE
    finally:
        for target in created:
            target.unlink(missing_ok=True)
        # Подчистить опустевшие созданные поддиректории (server/rendered/), не трогая server/.
        rendered_dir = _ROOT / "server" / "rendered"
        if rendered_dir.exists() and not any(rendered_dir.iterdir()):
            rendered_dir.rmdir()
        subprocess.run(["docker", "rmi", "-f", _CANARY_IMAGE], capture_output=True)


def test_secret_paths_absent_from_docker_build_context(canary_image):
    """Docker-native canary (issue #116, Codex cycle-4 рекомендация): реальный docker build/run,
    не ручной parse. Секретные файлы физически лежат в build-context на момент `docker build` —
    если .dockerignore их не отфильтровал, они окажутся в образе, и `test -e` внутри контейнера
    найдёт их.
    """
    leaked = []
    for rel in _SECRET_PATHS:
        check = subprocess.run(
            ["docker", "run", "--rm", canary_image, "test", "-e", f"/ctx/{rel}"],
            capture_output=True, timeout=30,
        )
        if check.returncode == 0:
            leaked.append(rel)
    assert leaked == [], (
        f"Секретные файлы попали в реальный Docker build-context (canary): {leaked}. "
        f".dockerignore не фильтрует их на практике, несмотря на ручной parse-гвард выше."
    )
