"""Гвард единого источника констант прокси (issue #155).

PRIVOXY=127.0.0.1:8118 и XRAY_SOCKS=127.0.0.1:10808 раньше дублировались по файлам
(dashboard_common.py, health.py, gen_xray_config.py) — при смене порта легко забыть
одну копию → рассинхронизация и трудноотлаживаемые баги маршрутизации.

Этот тест — регрессионный гвард: ни один файл дерева, КРОМЕ единого источника
(dashboard_common.py), не определяет порт-литералы прокси как константу.

Паттерн эталона more-options-better: единые константы в одном модуле, остальные
файлы только импортируют. Никакой новой магии — просто единый импорт.
"""
from pathlib import Path
import sys

import pytest

import dashboard_common

ROOT = Path(__file__).resolve().parent.parent

# Единый источник истины портов прокси. Если имя меняется — это осознанная правка
# канона, тест подстраивается здесь (и только здесь).
SOURCE = "dashboard_common.py"


def _py_files():
    """Все .py-файлы дерева, кроме venv/.git/__pycache__ и сгенерённого артефакта."""
    skip_parts = {".git", "__pycache__", ".venv", "venv", "node_modules"}
    for p in ROOT.rglob("*.py"):
        if any(part in skip_parts for part in p.parts):
            continue
        yield p


# Паттерны ОПРЕДЕЛЕНИЯ портов прокси как модульных констант (присваивание литерала).
# Регрессия против re-дублирования: новый файл не должен заводить свой 8118/10808.
# Намеренно не ловим упоминания портов в строках/сообщениях/тестовых данных — только
# факты присваивания константе (тот самый класс дрейфа, что описан в issue #155).
PROXY_PORT_DEFINE_PATTERNS = [
    r"\bPRIVOXY_PORT\s*=\s*\d",
    r"\bXRAY_PORT\s*=\s*\d",
    r"\bXRAY_SOCKS_PORT\s*=\s*\d",
    r"\bPRIVOXY_SOCKS_PORT\s*=\s*\d",
    # Поймать любой *_PORT = <порт прокси> как константу (8118/10808).
    r"\b\w*_PORT\s*=\s*81[0-9]{2}\b",
    r"\b\w*_PORT\s*=\s*108\d{2}\b",
]

# Паттерны host:port-литералов в ОПРЕДЕЛЕНИИ констант (не в любой строке):
# PRIVOXY = ("127.0.0.1", 8118) / HTTP_PROXY_URL = "http://127.0.0.1:8118" и т.п.
PROXY_ADDR_DEFINE_PATTERNS = [
    r'\bPRIVOXY\s*=\s*\(\s*["\']127\.0\.0\.1["\']',
    r'\bXRAY_SOCKS\s*=\s*\(\s*["\']127\.0\.0\.1["\']',
    r'\bHTTP_PROXY_URL\s*=\s*["\']http://127\.0\.0\.1:811',
    r'\bSOCKS_PROXY_URL\s*=\s*["\']socks5',
]


def test_single_source_defines_proxy_port_constants():
    """Ни один файл дерева, кроме dashboard_common.py, не определяет порт прокси как
    локальную константу. Ловит именно класс дрейфа issue #155 (рассинхронизация копий)."""
    offenders = {}
    for path in _py_files():
        if path.name == SOURCE or path.name == "test_proxy_constants.py":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line in text.splitlines():
            stripped = line.lstrip()
            # Гвард проверяет исполняемые ОПРЕДЕЛЕНИЯ констант, не комментарии/docstrings
            # и не сам тест-гвард (его паттерны легитимно упоминают дубли как спецификацию).
            if stripped.startswith("#") or stripped.startswith(("'''", '"""')):
                continue
            for pat in PROXY_PORT_DEFINE_PATTERNS + PROXY_ADDR_DEFINE_PATTERNS:
                import re
                if re.search(pat, line):
                    # Легитимный fallback: модуль, обязанный работать без srouter_config
                    # (install-путь), держит try-импорт из источника с fallback на то же
                    # каноническое значение. Это осознанный fallback, помеченный явно видимым
                    # маркером canonical-fallback-port — НЕ свежий дубликат (issue #155).
                    if "canonical-fallback-port" in line:
                        continue
                    offenders.setdefault(path.relative_to(ROOT), []).append(line.strip())
    assert not offenders, (
        "Найдены дублированные определения констант прокси вне единого источника "
        f"{SOURCE}. Импортируй из dashboard_common (issue #155). Нарушители:\n"
        + "\n".join(f"  {f}: {lines}" for f, lines in sorted(offenders.items()))
    )


def test_dashboard_common_is_canonical_source():
    """dashboard_common.py определяет канонические именованные константы портов.
    Это anchor-контракт: единый источник обязан существовать и содержать именно
    именованные константы (PRIVOXY_PORT/XRAY_SOCKS_PORT), а не голые литералы в кортеже."""
    assert dashboard_common.PRIVOXY_PORT == 8118
    assert dashboard_common.XRAY_SOCKS_PORT == 10808
    assert dashboard_common.PRIVOXY_ADDR == ("127.0.0.1", 8118)
    assert dashboard_common.XRAY_SOCKS_ADDR == ("127.0.0.1", 10808)
    # Производные адреса выражены через единый источник (anti-drift).
    assert dashboard_common.HTTP_PROXY_URL == f"http://127.0.0.1:{dashboard_common.PRIVOXY_PORT}"
    assert dashboard_common.PRIVOXY == dashboard_common.PRIVOXY_ADDR
    assert dashboard_common.XRAY_SOCKS == dashboard_common.XRAY_SOCKS_ADDR


def test_health_reexports_canonical_ports():
    """health.PRIVOXY_PORT / health.XRAY_PORT — публичный API (тесты/acceptance завязаны).
    Должны реэкспортить единый источник, а не хардкодить литерал (иначе дрейф вернётся)."""
    import health
    assert health.PRIVOXY_PORT is dashboard_common.PRIVOXY_PORT
    assert health.XRAY_PORT is dashboard_common.XRAY_SOCKS_PORT


def test_gen_xray_uses_canonical_socks_port():
    """gen_xray_config.XRAY_SOCKS_PORT — реэкспорт источника, не локальный литерал 10808."""
    import gen_xray_config
    assert gen_xray_config.XRAY_SOCKS_PORT is dashboard_common.XRAY_SOCKS_PORT


def test_gen_xray_fallback_does_not_mask_real_import_errors():
    """gen_xray_config обязан работать без srouter_config (install-путь), поэтому ловит
    SystemExit от dashboard_common и падает на fallback. НО это не должно маскировать
    РЕАЛЬНЫЕ ошибки импорта (SyntaxError, ImportError) в dashboard_common — иначе баг в
    источнике тихо проглатывается, и разработчик видит «всё работает» на мёртвом fallback
    (no-hidden-magic-follow-canon). Допускается маскировать только SystemExit (то, что
    dashboard_common реально поднимает при отсутствии конфига), а НЕ BaseException целиком.

    Реализовано через subprocess: подменяем dashboard_common в sys.modules на модуль,
    чей import падает ImportError, и импортируем gen_xray_config в свежем процессе.
    Если except ловит BaseException → gen_xray_config тихо проглатывает ошибку, exit=0,
    XRAY_SOCKS_PORT=10808 → тест ПАДАЕТ (баг маскируется). После фикса (except SystemExit)
    ImportError пробивается, subprocess падает ненулевым кодом → тест ЗЕЛЁНЫЙ.
    """
    import subprocess

    root = Path(__file__).resolve().parent.parent
    # Скрипт подменяет dashboard_common на падающий-ImportError модуль ДО импорта
    # gen_xray_config, в изолированном процессе (не трогая состояние pytest).
    probe = (
        "import sys, types\n"
        "broken = types.ModuleType('dashboard_common')\n"
        "def _boom(*a, **k):\n"
        "    raise ImportError('real bug in dashboard_common')\n"
        "broken.__spec__ = None\n"
        "broken.__path__ = []\n"
        "# Перехватываем встроенный import: при запросе dashboard_common — ImportError.\n"
        "_orig_import = __builtins__.__import__ if isinstance(__builtins__, dict) else __builtins__.__import__\n"
        "def _fake_import(name, *args, **kwargs):\n"
        "    if name == 'dashboard_common':\n"
        "        raise ImportError('real bug in dashboard_common')\n"
        "    return _orig_import(name, *args, **kwargs)\n"
        "import builtins\n"
        "builtins.__import__ = _fake_import\n"
        "import gen_xray_config\n"
        "print('MASKED:', gen_xray_config.XRAY_SOCKS_PORT)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=str(root),
        capture_output=True,
        text=True,
    )
    # Если импорт dashboard_common падает ImportError и это маскируется (BaseException),
    # процесс выйдет 0 и напечатает 'MASKED: 10808'. Правильное поведение — ImportError
    # пробивается (except ловит только SystemExit), процесс падает ненулевым кодом.
    masked = "MASKED" in result.stdout
    assert not masked, (
        "gen_xray_config маскирует РЕАЛЬНУЮ ошибку импорта dashboard_common (ImportError) "
        "через except BaseException — баг источника становится невидимым на мёртвом fallback "
        f"(no-hidden-magic). stdout={result.stdout!r} stderr={result.stderr[-400:]!r}"
    )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
