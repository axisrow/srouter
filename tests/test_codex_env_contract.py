"""Контракт маршрутизации 2026-10-07: ambient env-прокси не сеется ни в один слой.

Единый источник whitelist — srouter.local.json (routing.active/active_ips). Через туннель
ходит только явно попросившее (xray-правила, srouter git-proxy, per-tool wrappers, curl -x);
всё остальное — напрямую. srouter-codex-env.sh — единственный писатель в gui-домен launchd:
по контракту он НЕ ставит прокси-ключи (ambient HTTP(S)_PROXY = ложные «прямые» пробы,
рестарт xray рвёт TLS чужого трафика) и ГАРАНТИРОВАННО снимает residual-ключи — launchctl
setenv не ретроактивен и не снимает то, чего не ставит: старые версии скрипта сеяли socks5h
ALL_PROXY (#331/#340) и privoxy 8118 scheme-ключи, residual жил бы в gui-домене вечно.

Тест гоняет скрипт с подставным launchctl (PATH-stub, записывает вызовы) — сеть и
настоящий launchctl не трогаются; позитивный контроль (>=6 перехваченных вызовов)
гарантирует, что ассерты не вакуумны при мёртвом перехвате.
"""

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "launchagents" / "srouter-codex-env.sh"

PROXY_KEYS = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"]


@pytest.fixture
def launchctl_log(tmp_path, monkeypatch):
    """PATH-stub launchctl: каждый вызов дописывается в лог, rc=0. Возвращает путь к логу."""
    log = tmp_path / "launchctl-calls.log"
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    stub = stub_dir / "launchctl"
    stub.write_text('#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$LAUNCHCTL_CALLS_LOG"\nexit 0\n')
    stub.chmod(0o755)
    monkeypatch.setenv("LAUNCHCTL_CALLS_LOG", str(log))
    monkeypatch.setenv("PATH", f"{stub_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("SROUTER_PYTHON", "/usr/bin/expr")
    yield log


def _run_script():
    return subprocess.run(
        ["/bin/sh", str(SCRIPT)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_contract_no_proxy_seeding_and_residual_cleanup(launchctl_log):
    """Скрипт не ставит НИ ОДНОГО прокси-ключа и снимает все шесть (upper+lower, scheme+all)."""
    r = _run_script()
    assert r.returncode == 0, f"скрипт упал: {r.stderr}"

    assert launchctl_log.exists(), "launchctl-stub ни разу не вызвался — перехват мёртв"
    calls = [line.split() for line in
             launchctl_log.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(calls) >= len(PROXY_KEYS), (
        f"перехват неполный ({len(calls)} вызовов) — ассерты были бы вакуумными"
    )

    setenv = [c for c in calls if c[:1] == ["setenv"]]
    assert setenv == [], (
        "ambient-прокси сеется в gui-домен — нарушение контракта строгого whitelist: "
        f"{setenv}"
    )
    unset_names = {c[1] for c in calls if c[:1] == ["unsetenv"] and len(c) > 1}
    assert unset_names == set(PROXY_KEYS), (
        f"residual-чистка неполна: не хватает {set(PROXY_KEYS) - unset_names}"
    )


def test_contract_no_blocking_probe_in_periodic_agent():
    """Агент стреляет каждые 300с — serial-curl probe (#197 direct_first) в нём недопустим:
    сотни секунд блокировки worst-case на каждый прогон. NO_PROXY-посев снят вместе с probe
    (без ambient-прокси NO_PROXY инертен)."""
    code = "\n".join(ln for ln in SCRIPT.read_text(encoding="utf-8").splitlines()
                     if not ln.lstrip().startswith("#"))
    assert "direct_first" not in code and "no_proxy_string" not in code, (
        "периодический агент не должен гонять сетевой NO_PROXY-probe"
    )
