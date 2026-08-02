import sys
from pathlib import Path
from unittest import mock

import pytest

# Добавляем корень проекта в sys.path, чтобы root-level модули (local_state и т.д.)
# были видны из tests/ без копирования и без установки пакета.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ===================== issue #257: прогретый fake-codex (обход syspolicyd-штрафа) =====================
# macOS syspolicyd (Gatekeeper/XProtect) берёт ~0.4s за ПЕРВЫЙ exec каждого НОВОГО inode; повторный exec
# того же inode — ~0.006s (замеры в #257). Тесты wrapper'а создают fake-codex заглушку в tmp_path на
# каждый тест → новый inode → новый штраф. Заглушки при этом отличаются только тем, ЧТО они пишут и с
# каким rc выходят — их содержимое/inode ни в одном тесте не является предметом проверки (inode-ассерты
# в test_wrapper_skips_itself_hardlink/skips_other_managed_copy относятся к WRAPPER'у, не к заглушке).
#
# Поэтому: одна универсальная заглушка, параметризуемая через env, создаётся один раз за сессию и
# прогревается exec'ом. Тесты получают её через os.link (hardlink) — тот же inode, штрафа нет.
# Hardlink, а не копия: копия = новый inode = штраф возвращается (проверено).
#
# Почему hardlink здесь законен, хотя в #257 он отброшен для WRAPPER'а: там inode wrapper'а — предмет
# антирекурсионных тестов (os.link + assert st_ino), подмена превратила бы их в no-op. Здесь речь о
# fake-codex — обычной заглушке, чей inode не проверяется нигде. Гвард против тихой регрессии (заглушка
# перестала переиспользовать inode → оптимизация стала no-op) — tests/test_fake_codex_fixture.py.
# 8 прокси-переменных, которые wrapper обязан санировать через `env -u` (#96): верхний/нижний регистр
# + ALL_PROXY + NO_PROXY. Единый источник для дампа заглушкой и для ассертов в тестах.
PROXY_ENV_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                  "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy")

_FAKE_CODEX_ENV_DUMP = "".join(
    f"    printf '{k}=%s\\n' \"${k}\"\n" for k in PROXY_ENV_KEYS
)

_FAKE_CODEX_BODY = (
    "#!/bin/sh\n"
    "# srouter tests: универсальная fake-codex заглушка (issue #257, прогретый inode).\n"
    "# Параметризация через env, а не через содержимое файла — чтобы inode переиспользовался.\n"
    "#   SROUTER_FAKE_OUT  — куда писать (пусто → не писать)\n"
    "#   SROUTER_FAKE_TAG  — что писать (маркер «какой именно codex запущен»)\n"
    "#   SROUTER_FAKE_ARGV — куда дампить argv построчно (пусто → не дампить)\n"
    "#   SROUTER_FAKE_ENV  — куда дампить прокси-переменные как KEY=value (пусто → не дампить)\n"
    "#   SROUTER_FAKE_RC   — с каким кодом выйти (по умолчанию 0)\n"
    '[ -n "${SROUTER_FAKE_OUT:-}" ] && printf \'%s\' "${SROUTER_FAKE_TAG:-}" > "$SROUTER_FAKE_OUT"\n'
    '[ -n "${SROUTER_FAKE_ARGV:-}" ] && printf \'%s\\n\' "$@" > "$SROUTER_FAKE_ARGV"\n'
    'if [ -n "${SROUTER_FAKE_ENV:-}" ]; then\n'
    "  {\n"
    + _FAKE_CODEX_ENV_DUMP
    + '  } > "$SROUTER_FAKE_ENV"\n'
    "fi\n"
    'exit "${SROUTER_FAKE_RC:-0}"\n'
)


# Ключи, которыми параметризуется fake-codex заглушка. Единый источник для scrubber'а и гвардов.
FAKE_CODEX_ENV_KEYS = ("SROUTER_FAKE_OUT", "SROUTER_FAKE_TAG", "SROUTER_FAKE_ARGV",
                       "SROUTER_FAKE_ENV", "SROUTER_FAKE_RC")


@pytest.fixture(scope="session", autouse=True)
def _scrub_ambient_fake_codex_env():
    """Вычистить ambient SROUTER_FAKE_* из os.environ на время сессии (#257, cycle-review).

    Тесты строят окружение дочернего процесса как env={**os.environ, ...} — любая SROUTER_FAKE_*,
    которую конкретный тест НЕ переопределяет, пролезла бы из shell'а разработчика в заглушку.
    Опаснее всех SROUTER_FAKE_RC: её переопределяет только test_cli_launcher_propagates_exit_status,
    поэтому экспортированная снаружи RC=99 заставляла заглушку выходить 99 под каждым check=True →
    9 красных тестов без единого намёка на причину, при зелёном CI («works on my machine» наоборот).

    Чистим ОДИН раз на границе сессии, а не оборачиваем каждый env-словарь: барьер структурный, его
    нельзя забыть применить в новом тесте. Гвард — test_ambient_srouter_fake_env_is_scrubbed."""
    import os

    saved = {k: os.environ.pop(k) for k in FAKE_CODEX_ENV_KEYS if k in os.environ}
    try:
        yield
    finally:
        os.environ.update(saved)


@pytest.fixture(scope="session")
def fake_codex_master(tmp_path_factory, _scrub_ambient_fake_codex_env):
    """Session-scoped прогретая fake-codex заглушка (#257).

    Возвращает Path к мастер-файлу, чей inode УЖЕ прошёл syspolicyd (первый exec сделан здесь).
    Тесты обязаны получать свои копии через fake_codex (hardlink), а не через write_text/copy —
    иначе новый inode и штраф ~0.4s возвращается.

    tmp_path_factory (а не tempfile) — гарантирует ту же ФС, что и tmp_path тестов: os.link через
    границу ФС падает EXDEV. Под pytest-xdist basetemp у каждого воркера свой (popen-gwN), поэтому
    мастер (и штраф за его прогрев) — один на ВОРКЕР, а не один на сессию: ~10 штрафов под -n auto
    вместо ~18 на каждый exec. Выигрыш сохраняется, но он меньше «одного раза за сессию».

    Явная зависимость от _scrub_ambient_fake_codex_env: прогрев обязан идти уже с вычищенным
    окружением (иначе ambient SROUTER_FAKE_OUT заставил бы заглушку писать файл при прогреве).
    """
    import subprocess

    master = tmp_path_factory.mktemp("fake-codex-master") / "codex"
    master.write_text(_FAKE_CODEX_BODY, encoding="utf-8")
    master.chmod(0o755)
    # Прогрев: первый exec платит syspolicyd-штраф один раз за воркера. Без OUT/ARGV/ENV/RC —
    # заглушка ничего не пишет и выходит 0. check=False: цена прогрева, а не проверка.
    subprocess.run([str(master)], capture_output=True, timeout=60)
    return master


@pytest.fixture
def fake_codex(fake_codex_master):
    """Фабрика hardlink'ов на прогретую заглушку (#257): make(dest) → Path(dest).

    dest — куда положить заглушку (директория создаётся при необходимости). Тот же inode, что у
    мастера → syspolicyd-штрафа нет. Поведение задаётся env при запуске (SROUTER_FAKE_*), см.
    _FAKE_CODEX_BODY.
    """
    import os

    def make(dest):
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        os.link(fake_codex_master, dest)
        return dest

    return make


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
        is_sudo = isinstance(cmd, list) and cmd and str(cmd[0]) == "/usr/bin/sudo"
        if is_osascript:
            # osascript с admin — возвращаем success no-op (тест не должен звать GUI).
            return mock.Mock(returncode=0, stdout="", stderr="")
        if is_sudo:
            # Новый protected-Privoxy path спрашивает пароль через sudo. Ни один unit/CI-тест не
            # имеет права трогать живой system-domain; конкретные тесты подменяют runner явно.
            return mock.Mock(returncode=77, stdout="", stderr="sudo blocked by pytest guard")
        return _real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", _guarded_run)
