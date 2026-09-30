"""srouter go-proxy: тумблер Go-модулей в обход GFW (2026-09-30).

proxy.golang.org — GFW-чёрная дыра напрямую (эмпирика 2026-09-30: direct TCP-timeout 000,
через туннель socks5 10808 — 200 за 1.2с; тот же класс, что github.com 09-29). Go читает
транспортный прокси ТОЛЬКО из env процесса (`go env -w HTTPS_PROXY` → «unknown go command
variable», эмпирика), поэтому два режима:

  mirror — `go env -w GOPROXY=https://goproxy.cn,direct`: зеркало в Китае, GFW не трогает,
           VPS-независимо (канон #199: dev-workflow жив при мёртвом туннеле);
  tunnel — marker-managed wrapper ~/bin/go, экспортирующий HTTPS_PROXY/HTTP_PROXY=
           socks5://127.0.0.1:10808 + NO_PROXY (loopback + z.ai, канон zai-direct-no-proxy).
           Прецедент codex-wrappers; ~/bin в PATH ставит srouter install.

Состояние = сам GOENV-файл + сам wrapper (единый источник правды, как git_proxy = ~/.gitconfig).
Тесты бьют по РЕАЛЬНОМУ go (GOENV → tmp — изоляция от живой машины; канон #222 real_git_home:
rc-семантику реального инструмента не мокаем; skip-is-fine — CI-полигон без go).
"""
import os
import stat

import pytest

import go_proxy

requires_go = pytest.mark.skipif(
    not os.path.exists(go_proxy.GO), reason="go не установлен на этой машине")


@pytest.fixture
def go_home(tmp_path, monkeypatch):
    monkeypatch.setenv("GOENV", str(tmp_path / "goenv"))
    monkeypatch.setattr(go_proxy, "WRAPPER_PATH", tmp_path / "bin" / "go")
    # ambient-env канон (#265): env-прокси хоста не должен перевирать вердикты status
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path


def _goproxy():
    return go_proxy.goproxy_layer()["value"]


def _wrapper_text():
    return go_proxy.WRAPPER_PATH.read_text(encoding="utf-8")


# ============================ goproxy_layer ============================

@requires_go
def test_goproxy_default_is_not_mirror(go_home):
    layer = go_proxy.goproxy_layer()
    assert layer["state"] == "default", layer
    assert layer["value"].startswith("https://proxy.golang.org"), layer


@requires_go
def test_goproxy_mirror_after_manual_write(go_home):
    import subprocess
    subprocess.run([go_proxy.GO, "env", "-w", "GOPROXY=" + go_proxy.MIRROR_GOPROXY], check=True)
    assert go_proxy.goproxy_layer()["state"] == "mirror"


@requires_go
def test_goproxy_foreign_value_is_classified(go_home):
    import subprocess
    subprocess.run([go_proxy.GO, "env", "-w", "GOPROXY=http://corp.example:8080"], check=True)
    assert go_proxy.goproxy_layer()["state"] == "foreign"


# ============================ enable: mirror ============================

@requires_go
def test_enable_mirror_writes_goproxy(go_home):
    res = go_proxy.enable(mode="mirror")
    assert res["ok"] is True, res
    assert _goproxy() == go_proxy.MIRROR_GOPROXY, "read-back verify: значение в GOENV-файле"


@requires_go
def test_enable_mirror_idempotent(go_home):
    assert go_proxy.enable(mode="mirror")["ok"] is True
    assert go_proxy.enable(mode="mirror")["ok"] is True, "повторный enable — ok"


@requires_go
def test_enable_mirror_refuses_foreign_without_force(go_home):
    import subprocess
    subprocess.run([go_proxy.GO, "env", "-w", "GOPROXY=http://corp.example:8080"], check=True)
    res = go_proxy.enable(mode="mirror")
    assert res["ok"] is False, "чужой GOPROXY без --force — отказ (#307-канон)"
    assert "corp.example" in res["error"], res["error"]
    assert _goproxy() == "http://corp.example:8080", "конфиг не тронут"


@requires_go
def test_enable_mirror_force_overwrites_foreign(go_home):
    import subprocess
    subprocess.run([go_proxy.GO, "env", "-w", "GOPROXY=http://corp.example:8080"], check=True)
    res = go_proxy.enable(mode="mirror", force=True)
    assert res["ok"] is True and _goproxy() == go_proxy.MIRROR_GOPROXY


def test_enable_unknown_mode_refused(go_home):
    res = go_proxy.enable(mode="direct")   # вайтлист режимов (канон route-scope-validator)
    assert res["ok"] is False and "mode" in res["error"].lower()


# ============================ enable: tunnel (wrapper) ============================

@requires_go
def test_enable_tunnel_writes_managed_wrapper(go_home):
    res = go_proxy.enable(mode="tunnel")
    assert res["ok"] is True, res
    text = _wrapper_text()
    lines = text.splitlines()
    assert lines[0].strip() == go_proxy.WRAPPER_MARKER, "маркер первой строкой (whole-line канон)"
    assert "socks5://127.0.0.1:10808" in text, "туннельный socks5 в env wrapper'а"
    assert "z.ai" in text, "NO_PROXY несёт z.ai (канон zai-direct-no-proxy)"
    assert lines[-1].startswith("exec ") and go_proxy.GO in lines[-1], "exec реального go"
    mode = stat.S_IMODE(go_proxy.WRAPPER_PATH.stat().st_mode)
    assert mode & stat.S_IXUSR, "wrapper исполняемый"


@requires_go
def test_enable_tunnel_refuses_unmanaged_wrapper_without_force(go_home):
    go_proxy.WRAPPER_PATH.parent.mkdir(parents=True, exist_ok=True)
    go_proxy.WRAPPER_PATH.write_text("#!/bin/sh\necho corporate-go\n", encoding="utf-8")
    res = go_proxy.enable(mode="tunnel")
    assert res["ok"] is False, "чужой ~/bin/go без --force не перезаписываем"
    assert _wrapper_text() == "#!/bin/sh\necho corporate-go\n", "файл не тронут"


@requires_go
def test_enable_tunnel_force_overwrites_unmanaged(go_home):
    go_proxy.WRAPPER_PATH.parent.mkdir(parents=True, exist_ok=True)
    go_proxy.WRAPPER_PATH.write_text("#!/bin/sh\necho corporate-go\n", encoding="utf-8")
    res = go_proxy.enable(mode="tunnel", force=True)
    assert res["ok"] is True and go_proxy.wrapper_layer()["managed"] is True


# ============================ disable ============================

@requires_go
def test_disable_removes_managed_wrapper(go_home):
    assert go_proxy.enable(mode="tunnel")["ok"] is True
    res = go_proxy.disable()
    assert res["ok"] is True and not go_proxy.WRAPPER_PATH.exists()


@requires_go
def test_disable_keeps_mirror_goproxy_without_full(go_home):
    assert go_proxy.enable(mode="mirror")["ok"] is True
    res = go_proxy.disable()
    assert res["ok"] is True
    assert _goproxy() == go_proxy.MIRROR_GOPROXY, "без --full GOPROXY не трогаем"


@requires_go
def test_disable_full_unsets_managed_mirror(go_home):
    assert go_proxy.enable(mode="mirror")["ok"] is True
    res = go_proxy.disable(full=True)
    assert res["ok"] is True
    assert _goproxy() != go_proxy.MIRROR_GOPROXY, "--full снимает managed-значение"
    assert "goproxy.cn" in res["removed"][0], "снятое значение напечатано для восстановления"


@requires_go
def test_disable_full_refuses_foreign_goproxy_without_force(go_home):
    import subprocess
    subprocess.run([go_proxy.GO, "env", "-w", "GOPROXY=http://corp.example:8080"], check=True)
    res = go_proxy.disable(full=True)
    assert res["ok"] is False and "corp.example" in res["error"]
    assert _goproxy() == "http://corp.example:8080"


@requires_go
def test_disable_full_idempotent(go_home):
    assert go_proxy.disable(full=True)["ok"] is True, "без объектов — идемпотентный ok"
    assert go_proxy.disable(full=True)["ok"] is True


# ============================ status ============================

@requires_go
def test_status_verdicts_mirror_and_tunnel(go_home):
    s = go_proxy.status()
    assert s["verdict"] == "direct", "ничего не настроено — честный direct (GFW-блокирован)"
    go_proxy.enable(mode="mirror")
    assert go_proxy.status()["verdict"] == "mirror"
    go_proxy.enable(mode="tunnel")
    s = go_proxy.status()
    assert s["verdict"] == "tunnel", "wrapper побеждает (реальный путь свежего go)"


@requires_go
def test_status_reports_ambient_env_as_layer(go_home, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://wprp.example:3128")
    s = go_proxy.status()
    assert s["env_proxy"] == "http://wprp.example:3128", "ambient env показан как слой, не спрятан"
