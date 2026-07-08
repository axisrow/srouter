"""Shell-тесты для diag-proxy.sh с fake curl (запуск всего скрипта, без сети).

Канон подмены бинарника — как в srouter-diag.sh / test_srouter_diag.py: скрипт зовёт
не голый `curl`, а `${SROUTER_CURL:-...}`, и тест подставляет fake через env-переменную.

Находка #10 (issue #82): probe_direct склеивал write-out и FAIL. При провале curl печатал
частичный write-out (`000/...`) в stdout И затем срабатывал `|| echo FAIL($?)`, из-за чего
колонка DIRECT в таблице получала `000/...FAIL(28)`. probe() ловит rc отдельно
(`curl ...; rc=$?; if [ $rc -ne 0 ]`) и при провале печатает РОВНО `FAIL(rc)`, отбрасывая
write-out. probe_direct должен вести себя так же.
"""
import os
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "diag-proxy.sh"


def test_diag_proxy_bash_syntax():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


def _make_fake_curl(tmp_path):
    """Fake curl: direct-режим (нет '-x') роняет соединение как GFW-обрыв — печатает
    частичный write-out '000/0.5s' и выходит 28. Proxy-режим ('-x ...') успешен → '200/0.1s'.
    dig тоже подменяем на no-op, чтобы тест не ходил в реальный DNS.
    """
    fake = tmp_path / "fake_curl.sh"
    fake.write_text(
        "#!/usr/bin/env bash\n"
        'for a in "$@"; do [[ "$a" == "-x" ]] && { printf "200/0.100s"; exit 0; }; done\n'
        # direct-путь: partial write-out в stdout + ненулевой rc (как оборванный curl -w).
        'printf "000/0.500s"\n'
        "exit 28\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    return fake


def _make_fake_dig(tmp_path):
    fake = tmp_path / "fake_dig.sh"
    fake.write_text(
        "#!/usr/bin/env bash\nprintf '203.0.113.10\\n'\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    return fake


def _run_diag(tmp_path, label="novpn"):
    env = os.environ.copy()
    env["SROUTER_CURL"] = str(_make_fake_curl(tmp_path))
    env["SROUTER_DIG"] = str(_make_fake_dig(tmp_path))
    return subprocess.run(
        [str(SCRIPT), label],
        capture_output=True,
        env=env,
        text=True,
        timeout=30,
    )


def _direct_column(stdout, host="api.anthropic.com"):
    """Достать значение колонки DIRECT из строки таблицы для host."""
    for line in stdout.splitlines():
        if line.startswith(host):
            cols = [c.strip() for c in line.split("|")]
            # HOST | DNS | DIRECT | BRIDGE | SOCKS5
            return cols[2] if len(cols) > 2 else ""
    return None


def test_direct_column_on_curl_failure_is_exact_fail_code(tmp_path):
    """RED для #10: direct-curl роняет 000/0.5s + rc28 → колонка DIRECT ровно 'FAIL(28)'."""
    result = _run_diag(tmp_path)
    direct = _direct_column(result.stdout)

    assert direct is not None, f"строка api.anthropic.com не найдена:\n{result.stdout}"
    assert direct == "FAIL(28)", (
        f"probe_direct склеил write-out и FAIL: колонка DIRECT = {direct!r}, ожидалось 'FAIL(28)'"
    )
    assert "000/" not in direct


def test_direct_column_on_success_is_write_out(tmp_path):
    """GREEN-контроль: когда direct-curl успешен, колонка DIRECT — чистый write-out."""
    # Пере-собираем fake curl, который всегда успешен (в т.ч. direct).
    fake = tmp_path / "always_ok_curl.sh"
    fake.write_text(
        "#!/usr/bin/env bash\nprintf '200/0.123s'\nexit 0\n", encoding="utf-8"
    )
    fake.chmod(0o755)
    env = os.environ.copy()
    env["SROUTER_CURL"] = str(fake)
    env["SROUTER_DIG"] = str(_make_fake_dig(tmp_path))
    result = subprocess.run(
        [str(SCRIPT), "novpn"], capture_output=True, env=env, text=True, timeout=30
    )
    direct = _direct_column(result.stdout)

    assert direct == "200/0.123s", f"успешный direct исказил write-out: {direct!r}"
    assert "FAIL" not in direct
    # sanity: fail-паттерн вообще не должен встречаться при полном успехе
    assert re.search(r"FAIL\(\d+\)", result.stdout) is None
