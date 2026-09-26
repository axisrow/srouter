"""Shell-тесты для diag-proxy.sh с fake curl (запуск всего скрипта, без сети).

Канон подмены бинарника — как в srouter-diag.sh / test_srouter_diag.py: скрипт зовёт
не голый `curl`, а `${SROUTER_CURL:-...}`, и тест подставляет fake через env-переменную.

Находка #10 (issue #82): probe_direct склеивал write-out и FAIL. При провале curl печатал
частичный write-out (`000/...`) в stdout И затем срабатывал `|| echo FAIL($?)`, из-за чего
колонка DIRECT в таблице получала `000/...FAIL(28)`. probe() ловит rc отдельно
(`curl ...; rc=$?; if [ $rc -ne 0 ]`) и при провале печатает РОВНО `FAIL(rc)`, отбрасывая
write-out. probe_direct должен вести себя так же.

Issue #366: SOCKS5-колонка ходила в плейсхолдер YOUR_VPS_IP из заготовки → вечный FAIL(6)
и ложная тревога «SOCKS сломан» при живой сети. Теперь цель берётся из local.json
(первый enabled node → probe.socks_port, override SROUTER_SOCKS); без state — честный
SKIPPED в колонке, а не FAIL.
"""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
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


# --- issue #366: SOCKS5-цель из local.json, честный SKIPPED без state ---

def _make_recorder_curl(bin_dir):
    # recorder: пишет свои аргументы в $SROUTER_CURL_CAPTURE и всегда отвечает 200 —
    # позволяет ассертить, КАКУЮ цель curl-у подставил скрипт, без реальной сети.
    path = bin_dir / "fake-recorder-curl.sh"
    path.write_text(
        "#!/bin/sh\n"
        'printf \'%s\\n\' "$@" >> "$SROUTER_CURL_CAPTURE"\n'
        "echo '200/0.1s'\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


def _run_diag_recorder(tmp_path, state_path):
    capture = tmp_path / "curl.args"
    false_bin = shutil.which("false")
    assert false_bin
    env = os.environ.copy()
    env.update(
        {
            "SROUTER_PYTHON": sys.executable,
            "SROUTER_CURL": str(_make_recorder_curl(tmp_path)),
            "SROUTER_DIG": false_bin,
            "SROUTER_CURL_CAPTURE": str(capture),
            "SROUTER_STATE_PATH": str(state_path) if state_path else str(tmp_path / "missing.json"),
        }
    )
    result = subprocess.run(
        ["bash", str(SCRIPT), "novpn"],
        capture_output=True,
        env=env,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    return result, capture


def test_diag_proxy_socks_target_comes_from_local_state(tmp_path):
    """#366: SOCKS5-колонка ходит в per-node SOCKS из local.json (первый enabled node
    → probe.socks_port), а не в плейсхолдер из заготовки."""
    state_path = tmp_path / "srouter.local.json"
    state_path.write_text(
        json.dumps(
            {
                "nodes": [
                    {
                        "name": "sg-1",
                        "endpoint_host": "203.0.113.10",
                        "enabled": True,
                        "probe": {"socks_port": 11080},
                    },
                    {
                        "name": "hk-disabled",
                        "endpoint_host": "203.0.113.20",
                        "enabled": False,
                        "probe": {"socks_port": 11081},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    result, capture = _run_diag_recorder(tmp_path, state_path)

    args = capture.read_text(encoding="utf-8")
    assert "socks5h://127.0.0.1:11080" in args  # enabled узел, его порт
    assert "11081" not in args  # disabled узел не тестируем
    assert "YOUR_VPS_IP" not in args  # плейсхолдер не утекает в curl


def test_diag_proxy_socks_prefers_active_node_over_first_enabled(tmp_path):
    """Codex P2 на #366: BRIDGE-плечо маршрутизирует через active_node (генерированный
    xray-роут), поэтому SOCKS5-колонка обязана мерить порт активного узла, а не первого
    enabled. Fallback на первый enabled — только если активного нет/без валидного порта."""
    state_path = tmp_path / "srouter.local.json"
    state_path.write_text(
        json.dumps(
            {
                "nodes": [
                    {
                        "name": "sg-1",
                        "endpoint_host": "203.0.113.10",
                        "enabled": True,
                        "probe": {"socks_port": 11080},
                    },
                    {
                        "name": "hk-1",
                        "endpoint_host": "203.0.113.20",
                        "enabled": True,
                        "probe": {"socks_port": 11081},
                    },
                ],
                "active_node": {"name": "hk-1", "pending": None},
            }
        ),
        encoding="utf-8",
    )

    result, capture = _run_diag_recorder(tmp_path, state_path)

    args = capture.read_text(encoding="utf-8")
    assert "socks5h://127.0.0.1:11081" in args  # активный hk-1, не первый enabled sg-1
    assert "socks5h://127.0.0.1:11080" not in args


def test_diag_proxy_without_state_skips_socks_column_honestly(tmp_path):
    """#366: нет state/порта → колонка SKIPPED, а не FAIL от попытки подключиться
    к несуществующему хосту-заглушке."""
    result, capture = _run_diag_recorder(tmp_path, None)

    assert "SKIPPED" in result.stdout
    assert "YOUR_VPS_IP" not in capture.read_text(encoding="utf-8")
