"""CLI-тесты `srouter go-proxy` (status/enable/disable) — тумблер Go-модулей (2026-09-30).

Изоляция от живой машины: GOENV → tmp (go env -w пишет туда, эмпирика), WRAPPER_PATH → tmp,
env-прокси хоста счищены (ambient-env канон #265). Реальный go (канон #222; skip на CI без go).
"""
import argparse
import os

import pytest

import go_proxy
import srouter_cli

requires_go = pytest.mark.skipif(
    not os.path.exists(go_proxy.GO), reason="go не установлен на этой машине")


@pytest.fixture
def go_home(tmp_path, monkeypatch):
    monkeypatch.setenv("GOENV", str(tmp_path / "goenv"))
    monkeypatch.setattr(go_proxy, "WRAPPER_PATH", tmp_path / "bin" / "go")
    monkeypatch.chdir(tmp_path)
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
                "ALL_PROXY", "all_proxy", "GOPROXY"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path


def _ns(action, mode="mirror", full=False, force=False):
    return argparse.Namespace(goproxy_action=action, mode=mode, full=full, force=force)


@requires_go
def test_status_rc0_and_verdict_direct(go_home, capsys):
    rc = srouter_cli.cmd_go_proxy(_ns("status"))
    out = capsys.readouterr().out
    assert rc == 0
    assert "GOPROXY" in out and "wrapper" in out, "truthful-таблица слоёв"
    assert "НАПРЯМУЮ" in out, "пустая машина — честный direct (GFW-блок proxy.golang.org)"


@requires_go
def test_enable_mirror_writes_and_status_shows_mirror(go_home, capsys):
    assert srouter_cli.cmd_go_proxy(_ns("enable")) == 0
    out = capsys.readouterr().out
    assert "mirror" in out and "goproxy.cn" in out
    capsys.readouterr()
    assert srouter_cli.cmd_go_proxy(_ns("status")) == 0
    assert "зеркало" in capsys.readouterr().out, "вердикт зеркала в status"


@requires_go
def test_enable_refuses_foreign_without_force(go_home, capsys):
    import subprocess
    subprocess.run([go_proxy.GO, "env", "-w", "GOPROXY=http://corp.example:8080"], check=True)
    rc = srouter_cli.cmd_go_proxy(_ns("enable"))
    out = capsys.readouterr().out
    assert rc != 0 and "corp.example" in out, "чужой GOPROXY — отказ с именем значения (#307)"


@requires_go
def test_enable_tunnel_prints_wrapper(go_home, capsys):
    rc = srouter_cli.cmd_go_proxy(_ns("enable", mode="tunnel"))
    out = capsys.readouterr().out
    assert rc == 0 and "tunnel" in out and "wrapper" in out


@requires_go
def test_disable_full_prints_removed_and_idempotent(go_home, capsys):
    assert srouter_cli.cmd_go_proxy(_ns("enable")) == 0
    capsys.readouterr()
    assert srouter_cli.cmd_go_proxy(_ns("disable", full=True)) == 0
    out = capsys.readouterr().out
    assert "goproxy.cn" in out, "снятое значение напечатано для восстановления"
    assert srouter_cli.cmd_go_proxy(_ns("disable", full=True)) == 0, "идемпотентно"
