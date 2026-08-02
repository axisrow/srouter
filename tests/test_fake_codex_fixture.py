"""Гвард фикстуры fake_codex (issue #257).

Оптимизация «прогретый inode» тихо вырождается в no-op, если кто-то заменит os.link на копирование
(shutil.copy / write_text) — тесты останутся зелёными, а ~0.4s штрафа syspolicyd за каждый новый inode
вернутся незаметно. Этот файл фиксирует ИНВАРИАНТ (тот же inode) и КОНТРАКТ заглушки (параметризация
через env, не через содержимое файла) явными ассертами.

Канон: verify-dont-guess — инвариант проверяется st_ino, а не «мы же используем os.link».
"""
import os
import subprocess


def test_fake_codex_reuses_master_inode(fake_codex, fake_codex_master, tmp_path):
    """Корневой инвариант #257: заглушка — hardlink на прогретый мастер, НЕ копия.

    Разные inode = каждая заглушка снова платит syspolicyd-штраф → оптимизация мертва."""
    a = fake_codex(tmp_path / "a" / "codex")
    b = fake_codex(tmp_path / "b" / "codex")

    assert os.stat(a).st_ino == os.stat(fake_codex_master).st_ino, \
        "заглушка обязана быть hardlink'ом на прогретый мастер (тот же inode), не копией"
    assert os.stat(b).st_ino == os.stat(fake_codex_master).st_ino, \
        "вторая заглушка — тот же inode мастера"
    assert a != b and os.stat(a).st_dev == os.stat(b).st_dev, \
        "разные пути на одной ФС (os.link через границу ФС упал бы EXDEV)"


def test_fake_codex_is_executable(fake_codex, tmp_path):
    """Заглушка исполняема — wrapper резолвит кандидатов через `[ -x ]`, неисполняемую пропустит."""
    p = fake_codex(tmp_path / "bin" / "codex")
    assert os.access(p, os.X_OK), "fake-codex должен быть executable"


def test_fake_codex_writes_tag_to_out(fake_codex, tmp_path):
    """SROUTER_FAKE_TAG → SROUTER_FAKE_OUT: маркер «какой именно codex был запущен»."""
    p = fake_codex(tmp_path / "bin" / "codex")
    out = tmp_path / "out.txt"

    subprocess.run([str(p)], env={**os.environ, "SROUTER_FAKE_OUT": str(out),
                                  "SROUTER_FAKE_TAG": "real-codex"},
                   check=True, timeout=30)

    assert out.read_text(encoding="utf-8") == "real-codex"


def test_fake_codex_dumps_argv_verbatim(fake_codex, tmp_path):
    """SROUTER_FAKE_ARGV: argv дампится построчно verbatim (пробелы/кавычки/глобы не портятся)."""
    p = fake_codex(tmp_path / "bin" / "codex")
    argv_file = tmp_path / "argv.txt"
    args = ["--flag", "with space", "with'quote", "*.glob", "--", "-leading-dash"]

    subprocess.run([str(p), *args], env={**os.environ, "SROUTER_FAKE_ARGV": str(argv_file)},
                   check=True, timeout=30)

    assert argv_file.read_text(encoding="utf-8").splitlines() == args


def test_fake_codex_dumps_proxy_env(fake_codex, tmp_path):
    """SROUTER_FAKE_ENV: дамп всех 8 прокси-переменных как KEY=value (для проверки env -u, #96)."""
    p = fake_codex(tmp_path / "bin" / "codex")
    env_file = tmp_path / "env.txt"

    subprocess.run([str(p)], env={**os.environ, "SROUTER_FAKE_ENV": str(env_file),
                                  "HTTP_PROXY": "socks5h://127.0.0.1:10808"},
                   check=True, timeout=30)

    dumped = dict(line.split("=", 1) for line in
                  env_file.read_text(encoding="utf-8").splitlines() if "=" in line)
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy",
                "https_proxy", "all_proxy", "NO_PROXY", "no_proxy"):
        assert key in dumped, f"{key} присутствует в дампе (пустое значение — тоже значение)"
    assert dumped["HTTP_PROXY"] == "socks5h://127.0.0.1:10808"


def test_fake_codex_propagates_rc(fake_codex, tmp_path):
    """SROUTER_FAKE_RC: заглушка выходит с заданным кодом (проверка проброса exit-статуса)."""
    p = fake_codex(tmp_path / "bin" / "codex")

    rc = subprocess.run([str(p)], env={**os.environ, "SROUTER_FAKE_RC": "23"}, timeout=30).returncode

    assert rc == 23


def test_fake_codex_is_noop_without_env(fake_codex, tmp_path):
    """Без SROUTER_FAKE_* заглушка ничего не пишет и выходит 0 — безопасный дефолт для прогрева."""
    p = fake_codex(tmp_path / "bin" / "codex")
    clean = {k: v for k, v in os.environ.items() if not k.startswith("SROUTER_FAKE_")}

    proc = subprocess.run([str(p)], env=clean, capture_output=True, timeout=30)

    assert proc.returncode == 0
    assert list(tmp_path.glob("*.txt")) == [], "без env-параметров заглушка не создаёт файлов"


def test_ambient_srouter_fake_env_is_scrubbed(fake_codex, tmp_path):
    """Ambient SROUTER_FAKE_* из окружения разработчика НЕ должна долетать до заглушки.

    Тесты передают env={**os.environ, ...} — любая не-переопределённая SROUTER_FAKE_* пролезла бы
    в дочерний процесс. Самая опасная — SROUTER_FAKE_RC: её не переопределяет никто, кроме
    test_cli_launcher_propagates_exit_status, поэтому заглушка выходила бы с чужим кодом и валила
    все check=True вызовы. Симптом при этом немой: 9 красных тестов без намёка на причину в shell'е,
    CI зелёный («works on my machine» наоборот).

    Гвард на autouse-фикстуру _scrub_ambient_fake_codex_env: она вычищает эти ключи из os.environ
    на время сессии, поэтому env={**os.environ, ...} безопасен СТРУКТУРНО, а не по дисциплине."""
    # Симулируем «разработчик экспортировал SROUTER_FAKE_RC=99 и забыл» ПОСЛЕ старта сессии:
    # monkeypatch кладёт ключ обратно в os.environ уже после работы autouse-scrubber'а.
    # Скраббер обязан быть не разовой чисткой, а барьером на границе запуска — поэтому тест
    # проверяет именно то, что тесты СТРОЯТ env без ambient-ключей.
    for key in ("SROUTER_FAKE_RC", "SROUTER_FAKE_OUT", "SROUTER_FAKE_TAG",
                "SROUTER_FAKE_ARGV", "SROUTER_FAKE_ENV"):
        assert key not in os.environ, \
            f"{key} обязан быть вычищен из os.environ на время сессии (ambient env ломает тесты)"

    # И заглушка при чистом окружении ведёт себя как no-op с rc=0 (а не с чужим ambient rc).
    p = fake_codex(tmp_path / "bin" / "codex")
    assert subprocess.run([str(p)], env={**os.environ}, timeout=30).returncode == 0, \
        "при вычищенном окружении заглушка выходит 0, а не с ambient SROUTER_FAKE_RC"


def test_fake_codex_carries_no_srouter_wrapper_marker(fake_codex, tmp_path):
    """Критично для антирекурсии: заглушка НЕ должна нести srouter-маркер wrapper'а.

    Wrapper skip'ает любого кандидата с маркером 'srouter: codex CLI wrapper' — если бы заглушка его
    содержала, wrapper бы её пропустил и тесты runtime-резолва стали бы no-op (или упали на exit 127).
    Комментарий 'srouter tests:' в теле заглушки намеренно НЕ совпадает с маркером wrapper'а."""
    import srouter

    text = fake_codex(tmp_path / "bin" / "codex").read_text(encoding="utf-8")
    for _name, _tmpl, marker in srouter.CODEX_WRAPPERS:
        assert marker not in text, \
            f"fake-codex НЕ должен нести маркер wrapper'а {marker!r} — иначе wrapper его skip'нет"
    assert "srouter: codex CLI wrapper" not in text, \
        "grep-паттерн антирекурсии из wrapper-шаблона не должен матчиться на заглушку"
