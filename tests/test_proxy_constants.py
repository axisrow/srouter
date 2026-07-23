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
import re as _re
import sys

import pytest

import dashboard_common
import install_lib

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
    # case-insensitive: ловит PRIVOXY_PORT, privoxy_port, XRAY_PORT и т.п.
    r"(?i)\bPRIVOXY_PORT\s*=\s*\d",
    r"(?i)\bXRAY_PORT\s*=\s*\d",
    r"(?i)\bXRAY_SOCKS_PORT\s*=\s*\d",
    r"(?i)\bPRIVOXY_SOCKS_PORT\s*=\s*\d",
    # Поймать любой *_PORT = <порт прокси> как константу (8118/10808).
    r"(?i)\b\w*_PORT\s*=\s*81[0-9]{2}\b",
    r"(?i)\b\w*_PORT\s*=\s*108\d{2}\b",
]

# Паттерны host:port-литералов в ОПРЕДЕЛЕНИИ констант (не в любой строке):
# PRIVOXY = ("127.0.0.1", 8118) / HTTP_PROXY_URL = "http://127.0.0.1:8118" и т.п.
# Ловим канонические URL-имена с суффиксом _URL; голые HTTP_PROXY/SOCKS_PROXY НЕ ловим —
# это легитимные имена тестовых fixtures (tests/test_claude_transport.py), не дрейф канона.
PROXY_ADDR_DEFINE_PATTERNS = [
    r'(?i)\bPRIVOXY\s*=\s*\(\s*["\']127\.0\.0\.1["\']',
    r'(?i)\bXRAY_SOCKS\s*=\s*\(\s*["\']127\.0\.0\.1["\']',
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


# =============================================================================
# issue #165: parity-гвард для ОСТАВШИХСЯ runtime-источников портов (shell/config).
#
# PR #162 (#155) централизовал Python-константы и завёл grep-гвард на `_PORT = <литерал>`.
# Но он НЕ покрывал формы, где порт живёт ВНУТРИ строки/конфига, а не как Python-константа:
#   - shell-скрипты (diag, launchagents) — shell не импортирует Python;
#   - статичный install-template templates/privoxy.config;
#   - dict-литералы (install_lib.PORTS) и f-строки генераторов (privoxy_system).
# Сценарий отказа (из issue #165): сменили канонический порт → dashboard/health/xray
# переключились, а installed Privoxy + клиенты + installer-проверки остались на старом →
# полный отказ прокси. Паритет против единого источника исключает этот drift.
#
# Стратегия по рекомендации issue: для shell/config — parity-тест (mutation-альтернатива),
# т.к. grep-гвард на `_PORT =` эти формы не ловит. Источник истины — dashboard_common;
# если порт меняется там, тест указывает каждое место, обязанное следовать за ним.
# =============================================================================

# Регэкспы извлечения порта из строки. Ловят ТОЛЬКО host:port loopback (127.0.0.1:NNNN),
# не голые числа и не placeholder'ы (USER:PASS@YOUR_VPS_IP:1080 — заглушка VPS, не канон).
_LOOPBACK_PORT = _re.compile(r"127\.0\.0\.1:(?P<port>\d{4,5})")
# shell `VAR_PORT="NNNN"` (или без кавычек) — голый порт-литерал без host. Ловит drift-форму,
# которую host:port-регэксп пропускает (PRIVOXY_PORT="8118" в srouter-diag.sh). Намеренно узкий:
# только имена, оканчивающиеся на _PORT, чтобы не цеплять произвольные числа в скриптах.
_SHELL_PORT_VAR = _re.compile(r'(?P<name>\w*_PORT)=["\']?(?P<port>\d{4,5})["\']?\b')


def _loopback_ports(text):
    """Множество всех 127.0.0.1:PORT вхождений в text (только loopback, не VPS-placeholder)."""
    return {int(m.group("port")) for m in _LOOPBACK_PORT.finditer(text)}


def _shell_port_var_assignments(text):
    """{varname: port} для `VAR_PORT="NNNN"` литералов в shell (drift-форма без host)."""
    return {m.group("name"): int(m.group("port")) for m in _SHELL_PORT_VAR.finditer(text)}


def _canonical_proxy_ports():
    """Канонические прокси-порты из единого источника (dashboard_common)."""
    return {dashboard_common.PRIVOXY_PORT, dashboard_common.XRAY_SOCKS_PORT}


def test_install_lib_ports_follow_canonical_source():
    """install_lib.PORTS (dict-литерал, не `_PORT =`) обязан брать порты из источника,
    а не хардкодить 8118/10808. install_lib работает без srouter_config (install-путь),
    поэтому держит canonical-fallback на то же значение. Проверка ordered (ключ→порт), не set —
    ловит swap PORTS['xray']↔PORTS['privoxy'], который дал бы install-проверкам чужой порт."""
    assert install_lib.PORTS["xray"][1] == dashboard_common.XRAY_SOCKS_PORT, (
        "install_lib.PORTS['xray'] разошёлся с каноническим XRAY_SOCKS_PORT (issue #165)."
    )
    assert install_lib.PORTS["privoxy"][1] == dashboard_common.PRIVOXY_PORT, (
        "install_lib.PORTS['privoxy'] разошёлся с каноническим PRIVOXY_PORT (issue #165)."
    )
    # dnsmasq UDP 53 — НЕ прокси-порт, остаётся локальным литералом (вне scope).
    assert install_lib.PORTS["dnsmasq"] == ("udp", 53)


def _assert_directive_port(text, directive, expected_port):
    """Строгая (ordered) проверка: privoxy-директива обязана нести ИМЕННО expected_port.
    Ловит swap (listen-address:10808 + forward-socks5t:8118), который set-сравнение пропускает —
    set {8118,10808}=={8118,10808} даже при перепутанных назначениях (cycle-review PR #177, Codex).
    Ожидается ровно одно вхождение directive с host:port; port обязан == expected_port."""
    lines = [ln for ln in text.splitlines()
             if ln.lstrip().startswith(directive) and "127.0.0.1:" in ln]
    assert lines, f"директива '{directive}' с 127.0.0.1:PORT отсутствует"
    ports = _loopback_ports("\n".join(lines))
    assert ports == {expected_port}, (
        f"директива '{directive}' должна нести ровно канонический порт {expected_port}, "
        f"а несёт {ports}. Swap портов между директивами = полный отказ прокси (issue #165)."
    )


def test_privoxy_protected_config_follows_canonical_ports(tmp_path):
    """privoxy_system.protected_config_text() — listen-address/forward-socks5t обязаны нести
    ИМЕННО свои канонические порты (ordered, не set): listen-address → PRIVOXY_PORT,
    forward-socks5t → XRAY_SOCKS_PORT. Swap (privoxy слушает SOCKS-порт, bridge на HTTP-порт)
    даёт полный отказ прокси — set-сравнение это пропускает, поэтому строгая привязка директивы."""
    import privoxy_system

    layout = privoxy_system.ProtectedLayout(
        helper_path=tmp_path / "h", launchdaemon_path=tmp_path / "ld",
        config_dir=tmp_path / "c", config_path=tmp_path / "c" / "config",
        templates_dir=tmp_path / "t", manifest_path=tmp_path / "m",
        backup_root=tmp_path / "b", log_dir=tmp_path / "l",
        stdout_path=tmp_path / "o", stderr_path=tmp_path / "e",
        sudoers_path=tmp_path / "s",
    )
    config = privoxy_system.protected_config_text(layout)
    _assert_directive_port(config, "listen-address", dashboard_common.PRIVOXY_PORT)
    _assert_directive_port(config, "forward-socks5t", dashboard_common.XRAY_SOCKS_PORT)


def test_install_template_privoxy_config_follows_canonical_ports():
    """templates/privoxy.config — статичный install-template (копируется в config при install).
    listen-address/forward-socks5t обязаны нести ИМЕННО свои канонические порты (ordered, не set),
    иначе installed Privoxy слушает не тот порт, что health/xray (drift → полный отказ прокси).
    Swap ловится строгой привязкой директивы → порт."""
    template = ROOT / "templates" / "privoxy.config"
    assert template.exists(), "templates/privoxy.config отсутствует"
    text = template.read_text(encoding="utf-8")
    _assert_directive_port(text, "listen-address", dashboard_common.PRIVOXY_PORT)
    _assert_directive_port(text, "forward-socks5t", dashboard_common.XRAY_SOCKS_PORT)


def test_privoxy_system_helper_runs_isolated_without_dashboard_common(tmp_path):
    """Regression (Codex cycle-review PR #177): privoxy_system — root-only helper, копируется
    ОДНИМ файлом в /Library/PrivilegedHelperTools и исполняется через sudo. Рядом НЕТ
    dashboard_common.py (и srouter_config.py). Любой верхне-уровневый `from dashboard_common
    import ...` ронял helper ModuleNotFoundError в production — baseline main работал, PR #177
    падал (чистая регрессия). Helper обязан быть stdlib-only: порты — локальные литералы с
    parity-гвёрдом (test_privoxy_protected_config_follows_canonical_ports).

    Симулируем production: копируем ТОЛЬКО privoxy_system.py в изолированную директорию,
    запускаем как скрипт в чистом окружении (env -i, без проекта в sys.path) и требуем, чтобы
    helper дошёл до своей первой проверки (root_required), а не упал на импорте."""
    import shutil
    import subprocess

    isolated = tmp_path / "PrivilegedHelperTools"
    isolated.mkdir()
    helper = isolated / "com.srouter.privoxyctl"
    shutil.copy2(ROOT / "privoxy_system.py", helper)

    # env -i — чистое окружение launchd-стиля: НЕТ PYTHONPATH, НЕТ проекта в sys.path,
    # CWD не содержит dashboard_common. -S отключает site (максимальная изоляция от dev-окружения).
    result = subprocess.run(
        [sys.executable, "-S", str(helper), "status"],
        cwd="/",
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": "/var/root"},
        timeout=15,
    )
    # Helper намеренно выходит ненулевым при не-root (root_required) — это его контракт, не падение.
    # Regression-критерий: импорт верхнего уровня НЕ должен падать на ModuleNotFoundError/dashboard_common.
    assert "dashboard_common" not in result.stderr, (
        "privoxy_system helper тянет dashboard_common на верхнем уровне → ModuleNotFoundError в "
        f"production (cycle-review PR #177 regression). stderr={result.stderr[-400:]!r}"
    )
    assert "Traceback" not in result.stderr, (
        f"helper упал с traceback в изолированном окружении. stderr={result.stderr[-400:]!r}"
    )
    # Дошёл до своей первой проверки (helper запущен не под root в тесте) — значит импорт прошёл.
    assert "root_required" in result.stdout, (
        f"helper не дошёл до root-проверки (импорт должен пройти без dashboard_common). "
        f"stdout={result.stdout!r} stderr={result.stderr[-400:]!r}"
    )


# --- shell-скрипты: runtime proxy-endpoints следуют за каноническим SOCKS/HTTP портом ---

def _assert_shell_proxy_endpoints_follow_canonical(script_rel, expected_port_map):
    """Общий parity-чекер shell-скрипта против канонического источника портов.

    expected_port_map: {varname: expected_canonical_port}, где varname — чистое имя переменной
    (БЕЗ `=`), которая несёт порт. Покрываются ДВЕ формы drift-риска (issue #165):
      1. host:port-литерал в строке: `BRIDGE="http://127.0.0.1:8118"` — ловится через loopback-регэксп;
      2. голый порт-литерал без host: `PRIVOXY_PORT="8118"` — ловится через _SHELL_PORT_VAR.
    Ловит drift: если кто-то поменяет порт в скрипте, но не в dashboard_common — падает.
    """
    script = ROOT / script_rel
    assert script.exists(), f"{script_rel} отсутствует"
    text = script.read_text(encoding="utf-8")
    canonical = _canonical_proxy_ports()

    # (1) ВСЕ loopback-порты скрипта обязаны быть подмножеством канонических.
    found_loopback = _loopback_ports(text)
    assert found_loopback <= canonical, (
        f"{script_rel} содержит loopback-порт вне канонического набора (issue #165): "
        f"found={found_loopback}, canonical={canonical}. "
        "127.0.0.1:PORT обязаны совпадать с PRIVOXY_PORT/XRAY_SOCKS_PORT."
    )

    # (2) ВСЕ `*_PORT="NNNN"` литералы обязаны быть подмножеством канонических (DNSMASQ_PORT=53
    # — НЕ прокси, отдельно whitelisted). Ловит drift-форму без host (srouter-diag PRIVOXY_PORT).
    shell_vars = _shell_port_var_assignments(text)
    non_proxy_port_vars = {"DNSMASQ_PORT"}  # 53 — не прокси-порт, вне scope централизации
    for varname, port in shell_vars.items():
        if varname in non_proxy_port_vars:
            continue
        assert port in canonical, (
            f"{script_rel}: {varname}={port} — не канонический прокси-порт (issue #165), "
            f"canonical={canonical}. Переменная обязана следовать за dashboard_common."
        )

    # (3) Контекстная привязка: каждая указанная переменная несёт именно ожидаемый канонический порт.
    for varname, expected_port in expected_port_map.items():
        # Форма `VAR_PORT="NNNN"` (голый порт, без host).
        if varname in shell_vars:
            actual = shell_vars[varname]
            assert actual == expected_port, (
                f"{script_rel}: {varname}={actual} должен быть {expected_port} "
                f"(канонический {varname}, issue #165 drift)."
            )
            continue
        # Иначе host:port-литерал в строке, содержащей `varname=` (BRIDGE="http://127.0.0.1:8118").
        matching = [ln for ln in text.splitlines() if f"{varname}=" in ln and "127.0.0.1:" in ln]
        assert matching, (
            f"{script_rel}: нет '{varname}=' ни как VAR_PORT=\"NNNN\", ни как 127.0.0.1:PORT"
        )
        for line in matching:
            ports = _loopback_ports(line)
            assert expected_port in ports, (
                f"{script_rel}: '{line.strip()}' ({varname}) должна нести "
                f"канонический порт {expected_port}, а несёт {ports} (issue #165 drift)."
            )


def test_launchagent_codex_env_follows_canonical_socks_port():
    """srouter-codex-env.sh выставляет GUI env PROXY=socks5h://127.0.0.1:XRAY_SOCKS_PORT.
    Shell не импортирует Python — parity-гвард против dashboard_common.XRAY_SOCKS_PORT."""
    _assert_shell_proxy_endpoints_follow_canonical(
        "launchagents/srouter-codex-env.sh",
        {"PROXY": dashboard_common.XRAY_SOCKS_PORT},
    )


def test_launchagent_codex_app_wrapper_follows_canonical_socks_port():
    """srouter-codex-app-proxy-wrapper.sh: CHROMIUM_PROXY_URL=socks5://127.0.0.1:XRAY_SOCKS_PORT
    (Chromium --proxy-server, не понимает socks5h). Parity против XRAY_SOCKS_PORT."""
    _assert_shell_proxy_endpoints_follow_canonical(
        "launchagents/srouter-codex-app-proxy-wrapper.sh",
        {"CHROMIUM_PROXY_URL": dashboard_common.XRAY_SOCKS_PORT},
    )


def test_srouter_diag_follows_canonical_ports():
    """srouter-diag.sh: BRIDGE=http 8118, PRIVOXY_PORT=8118, XRAY_SOCKS_PORT=10808.
    Все три обязаны совпадать с каноническими (issue #165)."""
    _assert_shell_proxy_endpoints_follow_canonical(
        "srouter-diag.sh",
        {
            "BRIDGE": dashboard_common.PRIVOXY_PORT,
            "PRIVOXY_PORT": dashboard_common.PRIVOXY_PORT,
            "XRAY_SOCKS_PORT": dashboard_common.XRAY_SOCKS_PORT,
        },
    )


def test_diag_proxy_follows_canonical_bridge_port():
    """diag-proxy.sh: BRIDGE=http://127.0.0.1:8118 (privoxy). Паритет против PRIVOXY_PORT.
    SOCKS=...:1080 — заглушка VPS (USER:PASS@YOUR_VPS_IP), НЕ loopback 127.0.0.1, гард её не трогает."""
    _assert_shell_proxy_endpoints_follow_canonical(
        "diag-proxy.sh",
        {"BRIDGE": dashboard_common.PRIVOXY_PORT},
    )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
