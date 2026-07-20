"""TDD-гвард: .dockerignore защищает секреты от попадания в Docker-образ (cycle-review #114 C1).

COPY . в Dockerfile копирует ВЕСЬ build-context, .gitignore НЕ фильтрует Docker (разные механизмы).
Без .dockerignore секреты (srouter.local.json с Reality-материалом/UUID/endpoints, srouter_config.py,
.env) запекаются в слой образа → утечка через экспорт/registry/build-cache. Этот тест требует, чтобы
.dockerignore существовал и покрывал ключевые паттерны. Не skip'ится SROUTER_ACCEPTANCE (чистый static
— читает файл, ничего не запускает).
"""
from pathlib import Path

_DOCKERIGNORE = Path(__file__).resolve().parents[2] / ".dockerignore"

# Паттерны, которые ДОЛЖНЫ быть в .dockerignore — секреты и локальный state (зеркало .gitignore,
# НО для Docker build-context, т.к. .gitignore тут НЕ работает).
_REQUIRED_PATTERNS = [
    "srouter.local.json",
    "srouter_config.py",
    ".env",
    "srouter.hot_routes.json",
    ".git",          # build-context раздувается .git; не нужен в образе
    "__pycache__",
    ".pytest_cache",
]


def test_dockerignore_exists_and_covers_secrets():
    """.dockerignore существует и покрывает секреты/локальный-state (cycle-review #114 C1).

    Без файла — COPY . в acceptance.Dockerfile печёт srouter.local.json (Reality-материал, UUID узлов,
    endpoints) и srouter_config.py в слой образа. .gitignore НЕ фильтрует Docker build-context.
    """
    assert _DOCKERIGNORE.exists(), (
        f".dockerignore отсутствует — COPY . в acceptance.Dockerfile утащит секреты в образ "
        f"(srouter.local.json с Reality-материалом, srouter_config.py, .env). "
        f".gitignore НЕ фильтрует Docker build-context."
    )
    content = _DOCKERIGNORE.read_text(encoding="utf-8")
    missing = [p for p in _REQUIRED_PATTERNS if p not in content]
    assert not missing, f".dockerignore не покрывает критичные паттерны: {missing}"
