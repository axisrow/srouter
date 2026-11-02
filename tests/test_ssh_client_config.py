"""ssh_client_config (#438): парсинг ~/.ssh/config, аудит туннеля, managed-include setup.

Все операции — на tmp-фикстурах (живой ~/.ssh/config не читается и не меняется).
"""
import pytest

import ssh_client_config as scc

NC = "nc -x 127.0.0.1:10808 -X 5 %h %p"


def _home(tmp_path, config_text="", managed_text=None):
    ssh = tmp_path / ".ssh"
    ssh.mkdir(exist_ok=True)
    if config_text:
        (ssh / "config").write_text(config_text, encoding="utf-8")
    if managed_text is not None:
        (ssh / "srouter.conf").write_text(managed_text, encoding="utf-8")
    return tmp_path


# ============================ парсер ============================


def test_parse_host_sections_params_and_comments(tmp_path):
    p = _home(tmp_path, """\
# comment
Host de-1
    HostName 78.47.183.125
    ProxyCommand=nc -x 127.0.0.1:10808 -X 5 %h %p

Host *   # inline comment
    ForwardAgent no
""")
    sections = scc.parse_config(tmp_path / ".ssh" / "config", home=tmp_path)
    assert len(sections) == 2
    assert sections[0]["patterns"] == ["de-1"]
    assert sections[0]["params"]["ProxyCommand"] == NC
    assert sections[0]["params"]["HostName"] == "78.47.183.125"
    assert sections[1]["patterns"] == ["*"]
    assert sections[1]["params"]["ForwardAgent"] == "no"


def test_parse_include_recursive_relative_to_ssh_dir(tmp_path):
    ssh = tmp_path / ".ssh"
    (ssh / "conf.d").mkdir(parents=True)
    (ssh / "conf.d" / "extra.conf").write_text("Host box\n    User root\n", encoding="utf-8")
    (ssh / "config").write_text("Include conf.d/extra.conf\n\nHost *\n    ServerAliveInterval 15\n",
                                encoding="utf-8")
    sections = scc.parse_config(ssh / "config", home=tmp_path)
    assert [s["patterns"] for s in sections] == [["box"], ["*"]]
    assert sections[0]["source"].endswith("extra.conf")


def test_parse_include_depth_cap_no_infinite_loop(tmp_path):
    _home(tmp_path, "Include config\n")  # self-include
    sections = scc.parse_config(tmp_path / ".ssh" / "config", home=tmp_path)
    assert isinstance(sections, list)  # завершилось, не зациклилось


def test_parse_missing_file_fail_soft(tmp_path):
    assert scc.parse_config(tmp_path / ".ssh" / "config", home=tmp_path) == []


def test_host_match_patterns():
    assert scc.host_matches(["*"], "anything.example")
    assert scc.host_matches(["de-*", "!de-failed"], "de-1")
    assert not scc.host_matches(["de-*", "!de-failed"], "de-failed")
    assert not scc.host_matches(["de-*"], "sg-1")
    assert scc.host_matches(["*.example.com"], "a.example.com")
    # только негативные паттерны = «всё кроме»
    assert scc.host_matches(["!direct.example"], "other.example")
    assert not scc.host_matches(["!direct.example"], "direct.example")


def test_effective_params_first_obtained_wins(tmp_path):
    p = _home(tmp_path, f"""\
Host de-1
    ProxyCommand none

Host *
    ProxyCommand {NC}
    ServerAliveInterval 15
""")
    sections = scc.parse_config(tmp_path / ".ssh" / "config", home=tmp_path)
    de1 = scc.effective_params("de-1", sections)
    assert de1["ProxyCommand"] == "none", "первое полученное значение побеждает"
    other = scc.effective_params("sg-1", sections)
    assert other["ProxyCommand"] == NC
    assert other["ServerAliveInterval"] == "15"


# ============================ аудит ============================


def test_audit_ok_with_defaults_and_keepalive(tmp_path):
    _home(tmp_path, f"""\
Host *
    ProxyCommand {NC}
    ServerAliveInterval 15
    ServerAliveCountMax 4
""")
    out = scc.audit(home=tmp_path)
    assert out["status"] == "ok", out
    assert out["detail"]


def test_audit_warn_when_keepalive_missing(tmp_path):
    _home(tmp_path, f"Host *\n    ProxyCommand {NC}\n")
    out = scc.audit(home=tmp_path)
    assert out["status"] == "warn"
    assert "ServerAlive" in out["detail"]


def test_audit_down_when_custom_host_bypasses_tunnel(tmp_path):
    _home(tmp_path, f"""\
Host direct-host
    ProxyCommand none

Host *
    ProxyCommand {NC}
""")
    out = scc.audit(home=tmp_path)
    assert out["status"] == "down"
    assert "direct-host" in out["detail"]


def test_audit_down_when_foreign_proxy_command(tmp_path):
    _home(tmp_path, f"""\
Host work
    ProxyCommand nc -x 10.0.0.1:9050 %h %p

Host *
    ProxyCommand {NC}
    ServerAliveInterval 15
    ServerAliveCountMax 4
""")
    out = scc.audit(home=tmp_path)
    assert out["status"] == "down"
    assert "work" in out["detail"]


def test_audit_down_when_no_default_and_host_without_proxy(tmp_path):
    _home(tmp_path, "Host de-1\n    HostName 78.47.183.125\n")
    out = scc.audit(home=tmp_path)
    assert out["status"] == "down"


def test_audit_down_when_no_config(tmp_path):
    """Конфига нет = любой ssh пойдёт напрямую = нарушение контракта #438 (лечится setup)."""
    _home(tmp_path)
    out = scc.audit(home=tmp_path)
    assert out["status"] == "down"
    assert "setup" in out["detail"]


def test_audit_warn_on_unverifiable_match(tmp_path):
    _home(tmp_path, f"""\
Match exec /usr/bin/choose-proxy
    ProxyCommand {NC}

Host *
    ProxyCommand {NC}
    ServerAliveInterval 15
    ServerAliveCountMax 4
""")
    out = scc.audit(home=tmp_path)
    assert out["status"] == "warn", out
    assert "Match" in out["detail"]


def test_audit_down_wins_over_unverifiable_match(tmp_path):
    """Offenders (хост мимо туннеля) не затираются warn'ом unverifiable-Match (ревью PR #451).

    Down — максимальная серьёзность: реальный обход туннеля важнее невычислимости Match;
    сам Match при этом остаётся упомянутым в detail."""
    _home(tmp_path, f"""\
Match exec /usr/bin/choose-proxy
    ProxyCommand {NC}

Host work
    ProxyCommand none

Host *
    ProxyCommand {NC}
    ServerAliveInterval 15
    ServerAliveCountMax 4
""")
    out = scc.audit(home=tmp_path)
    assert out["status"] == "down", out
    assert "work" in out["detail"], "offender назван"
    assert "Match" in out["detail"], "unverifiable тоже упомянут"


def test_audit_never_raises_on_garbage(tmp_path):
    _home(tmp_path, "\n\nKeyWithoutValue\n!!!\n")
    out = scc.audit(home=tmp_path)
    assert out["status"] in ("warn", "down", "unknown")


# ============================ setup ============================


def test_setup_writes_managed_include_and_config(tmp_path):
    _home(tmp_path)
    out = scc.setup(home=tmp_path)

    assert out["ok"] is True and out["changed"] is True, out
    managed = (tmp_path / ".ssh" / "srouter.conf").read_text(encoding="utf-8")
    assert "# srouter" in managed and "Host *" in managed
    assert NC in managed
    assert "ServerAliveInterval 15" in managed and "ServerAliveCountMax 4" in managed
    cfg = (tmp_path / ".ssh" / "config").read_text(encoding="utf-8")
    assert "Include" in cfg and "srouter.conf" in cfg


def test_setup_idempotent(tmp_path):
    _home(tmp_path)
    first = scc.setup(home=tmp_path)
    cfg_before = (tmp_path / ".ssh" / "config").read_bytes()
    second = scc.setup(home=tmp_path)

    assert first["ok"] and second["ok"]
    assert second["changed"] is False
    assert (tmp_path / ".ssh" / "config").read_bytes() == cfg_before
    assert (tmp_path / ".ssh" / "config").read_text(encoding="utf-8").count("Include") == 1


def test_setup_backs_up_existing_config_once(tmp_path):
    _home(tmp_path, "Host legacy\n    User root\n")
    out = scc.setup(home=tmp_path)

    assert out["ok"] is True
    backup = out.get("backup")
    assert backup, "backup создан для существующего конфига"
    assert "Host legacy" in backup.read_text(encoding="utf-8")
    scc.setup(home=tmp_path)
    assert scc.setup(home=tmp_path)["changed"] is False


def test_setup_after_setup_audit_ok(tmp_path):
    """Конечное состояние: audit зелёный (дефолт include дозаполняет ServerAlive)."""
    _home(tmp_path, f"Host *\n    ProxyCommand {NC}\n")  # как на живой машине сейчас
    scc.setup(home=tmp_path)
    out = scc.audit(home=tmp_path)
    assert out["status"] == "ok", out


def test_setup_custom_keepalive_params(tmp_path):
    _home(tmp_path)
    scc.setup(home=tmp_path, interval=30, countmax=3)
    managed = (tmp_path / ".ssh" / "srouter.conf").read_text(encoding="utf-8")
    assert "ServerAliveInterval 30" in managed
    assert "ServerAliveCountMax 3" in managed


def test_setup_socks_port_follows_canonical(tmp_path):
    import dashboard_common
    _home(tmp_path)
    foreign = dashboard_common.XRAY_SOCKS_PORT + 1  # чужой порт ≠ канон (гвард #155)
    scc.setup(home=tmp_path, socks_port=foreign)
    managed = (tmp_path / ".ssh" / "srouter.conf").read_text(encoding="utf-8")
    assert f"127.0.0.1:{foreign}" in managed


def test_audit_respects_port_override(tmp_path):
    import dashboard_common
    foreign = dashboard_common.XRAY_SOCKS_PORT + 1  # чужой порт ≠ канон (гвард #155)
    _home(tmp_path, f"Host *\n    ProxyCommand nc -x 127.0.0.1:{foreign} -X 5 %h %p\n"
                    "    ServerAliveInterval 15\n    ServerAliveCountMax 4\n")
    assert scc.audit(home=tmp_path, socks_port=foreign)["status"] == "ok"
    assert scc.audit(home=tmp_path)["status"] == "down", "чужой порт — не наш туннель"


@pytest.mark.parametrize("text", ["", "Host *\n", "Host * !x\n    ProxyCommand " + NC + "\n"])
def test_audit_no_crash_on_edge_shapes(tmp_path, text):
    _home(tmp_path, text)
    out = scc.audit(home=tmp_path)
    assert out["status"] in ("ok", "warn", "down", "unknown")
