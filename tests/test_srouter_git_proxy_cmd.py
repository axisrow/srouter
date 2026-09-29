"""ТДД-тесты `srouter git-proxy` CLI (status/enable/disable) — единый тумблер git-прокси.

Контекст 2026-09-30: git-прокси размазан по трём слоям (managed urlmatch-ключ git_proxy,
бесхозные глобальные http.proxy/https.proxy, локальные override'ы репо) — doctor видел только
первый. CLI-тумблер управляет всеми: status показывает ЭФФЕКТИВНЫЙ вердикт (effective_proxy),
enable/disable — managed-ключ, disable --full — плюс бесхозные глобальные (с force-гейтом на
чужие значения, контракт #307).

Тесты бьют по РЕАЛЬНОМУ git (HOME → tmp_path, контракт #222 — не мокать rc-семантику).
"""
import argparse
import os
import subprocess

import pytest

import git_proxy
import srouter_cli

EXPECTED_GIT_PROXY = git_proxy._PROXY


@pytest.fixture
def real_git_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    # status/disable вне репо: cwd не репо → локальный слой absent (rc=128 → absent, не unknown)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _raw_add(key, val, home):
    subprocess.run(
        ["git", "config", "--global", "--add", key, val],
        env=dict(os.environ, HOME=str(home)), capture_output=True, text=True, check=True,
    )


def _get_all_global(key, home):
    r = subprocess.run(
        ["git", "config", "--global", "--get-all", key],
        env=dict(os.environ, HOME=str(home)), capture_output=True, text=True,
    )
    return r.returncode, r.stdout.strip()


def _ns(action, full=False, force=False):
    return argparse.Namespace(gitproxy_action=action, full=full, force=force)


# ============================ status ============================

def test_status_rc0_and_effective_verdict(real_git_home, capsys):
    _raw_add("https.proxy", "http://127.0.0.1:8118", real_git_home)
    rc = srouter_cli.cmd_git_proxy(_ns("status"))
    out = capsys.readouterr().out
    assert rc == 0
    assert "8118" in out, "вердикт обязан показать эффективный прокси (global-generic 8118)"
    assert "direct" in out.lower() or "напрямую" in out.lower() or "privoxy" in out.lower() \
        or "прокси" in out.lower(), out


def test_status_lists_layers(real_git_home, capsys):
    rc = srouter_cli.cmd_git_proxy(_ns("status"))
    out = capsys.readouterr().out
    assert rc == 0
    # все три слоя названы, даже когда пусты (truthful-таблица, а не только вердикт)
    assert "urlmatch" in out
    assert "http.proxy" in out


# ============================ enable ============================

def test_enable_writes_managed_key(real_git_home, capsys):
    rc = srouter_cli.cmd_git_proxy(_ns("enable"))
    out = capsys.readouterr().out
    assert rc == 0
    rcode, val = _get_all_global(git_proxy.KEY, real_git_home)
    assert rcode == 0 and val == EXPECTED_GIT_PROXY
    assert EXPECTED_GIT_PROXY in out


def test_enable_refuses_foreign_without_force(real_git_home, capsys):
    _raw_add(git_proxy.KEY, "http://corp.example:8080", real_git_home)
    rc = srouter_cli.cmd_git_proxy(_ns("enable"))
    out = capsys.readouterr().out
    assert rc != 0, "чужое значение без --force — отказ (#307)"
    assert "corp.example" in out, "отказ обязан показать чужое значение"
    rcode, val = _get_all_global(git_proxy.KEY, real_git_home)
    assert rcode == 0 and val == "http://corp.example:8080", "конфиг не тронут"


def test_enable_warns_when_local_override_shadows(real_git_home, tmp_path, capsys):
    """enable включает global, но локальный override репо продолжает глушить — обязан предупредить."""
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "--local", git_proxy.KEY, ""],
                   check=True, capture_output=True)
    (real_git_home / "wd").mkdir()
    os.chdir(repo)
    rc = srouter_cli.cmd_git_proxy(_ns("enable"))
    out = capsys.readouterr().out
    assert rc == 0
    assert "локальн" in out.lower() or "local" in out.lower(), \
        "enable обязан предупредить о локальном override, который побеждает global"


# ============================ disable ============================

def test_disable_plain_keeps_stray(real_git_home, capsys):
    """disable без --full снимает только managed-ключ; бесхозные глобальные остаются (и это
    видно в выводе)."""
    assert git_proxy.enable(force=True)["ok"] is True
    _raw_add("https.proxy", "http://127.0.0.1:8118", real_git_home)
    rc = srouter_cli.cmd_git_proxy(_ns("disable"))
    out = capsys.readouterr().out
    assert rc == 0
    assert _get_all_global(git_proxy.KEY, real_git_home)[0] == 1, "managed-ключ снят"
    assert _get_all_global("https.proxy", real_git_home)[0] == 0, "бесхозный ключ НЕ тронут"
    assert "8118" in out, "вывод честно сообщает про оставшийся бесхозный слой"


def test_disable_full_purges_stray_and_prints_removed(real_git_home, capsys):
    assert git_proxy.enable(force=True)["ok"] is True
    _raw_add("http.proxy", "http://127.0.0.1:8118", real_git_home)
    _raw_add("https.proxy", "http://127.0.0.1:8118", real_git_home)
    rc = srouter_cli.cmd_git_proxy(_ns("disable", full=True))
    out = capsys.readouterr().out
    assert rc == 0
    assert _get_all_global(git_proxy.KEY, real_git_home)[0] == 1
    assert _get_all_global("http.proxy", real_git_home)[0] == 1
    assert _get_all_global("https.proxy", real_git_home)[0] == 1
    # снятые значения напечатаны для восстановления вручную (они вне managed-множества)
    assert out.count("http://127.0.0.1:8118") >= 2, out


def test_disable_full_idempotent(real_git_home, capsys):
    rc = srouter_cli.cmd_git_proxy(_ns("disable", full=True))
    assert rc == 0, "повторный disable --full без объектов — идемпотентный ok"


def test_disable_full_refuses_foreign_stray_without_force(real_git_home, capsys):
    _raw_add("https.proxy", "http://corp.example:8080", real_git_home)
    rc = srouter_cli.cmd_git_proxy(_ns("disable", full=True))
    out = capsys.readouterr().out
    assert rc != 0, "чужое значение бесхозного ключа без --force — отказ (#307)"
    assert _get_all_global("https.proxy", real_git_home)[0] == 0, "конфиг не тронут"
    assert "corp.example" in out


def test_disable_full_force_removes_foreign_stray(real_git_home, capsys):
    _raw_add("https.proxy", "http://corp.example:8080", real_git_home)
    rc = srouter_cli.cmd_git_proxy(_ns("disable", full=True, force=True))
    out = capsys.readouterr().out
    assert rc == 0
    assert _get_all_global("https.proxy", real_git_home)[0] == 1
    assert "corp.example" in out, "снятое чужое значение напечатано для восстановления"
