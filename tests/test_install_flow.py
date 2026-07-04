import json
from pathlib import Path

import install_lib
import sys_probe


class FakeRunner:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def __call__(self, cmd, timeout):
        self.calls.append(list(cmd))
        key = tuple(cmd)
        return self.responses.get(key, {"rc": 0, "out": "", "err": "", "timeout": False})


def _env(tmp_path):
    return install_lib.InstallEnv(
        root=Path(__file__).resolve().parent.parent,
        prefix=tmp_path / "homebrew",
        state_path=tmp_path / "srouter.local.json",
        launchagent_dir=tmp_path / "LaunchAgents",
        now="2026-06-29T00:00:00Z",
    )


def test_plan_does_not_write_local_state(tmp_path):
    env = _env(tmp_path)

    plan = install_lib.build_plan(env=env, runner=FakeRunner(), port_checker=lambda *_: False)

    assert plan["mode"] == "plan"
    assert not env.state_path.exists()


def test_install_lib_reuses_shared_probe_helpers():
    assert install_lib.run is sys_probe.run
    assert install_lib.port_open is sys_probe.port_open
    assert install_lib._parse_brew_services is sys_probe.parse_brew_services


def test_conflict_detection_reports_foreign_config_and_port_owner(tmp_path):
    env = _env(tmp_path)
    config_path = env.component_paths("privoxy")["config"]
    config_path.parent.mkdir(parents=True)
    config_path.write_text("listen-address 127.0.0.1:8118\n", encoding="utf-8")
    lsof = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nforeign 123 me 5u IPv4 0t0 TCP 127.0.0.1:8118 (LISTEN)\n"
    runner = FakeRunner({(install_lib.LSOF, "-nP", "-iTCP:8118", "-sTCP:LISTEN"): {"rc": 0, "out": lsof, "err": "", "timeout": False}})

    plan = install_lib.build_plan(env=env, runner=runner, port_checker=lambda host, port, timeout=0.5: port == 8118)
    privoxy = plan["components"]["privoxy"]

    assert privoxy["conflict"] is True
    assert "foreign_config" in privoxy["conflicts"]
    assert "foreign_port" in privoxy["conflicts"]
    assert privoxy["port_owner"]["pid"] == "123"


def test_apply_blocks_without_confirm_and_without_writing_state(tmp_path):
    env = _env(tmp_path)

    result = install_lib.apply_install(env=env, confirm=False, choices={}, runner=FakeRunner(), port_checker=lambda *_: False)

    assert result["ok"] is False
    assert result["blocked"] == ["confirmation_required"]
    assert not env.state_path.exists()


def test_apply_blocks_unresolved_conflict(tmp_path):
    env = _env(tmp_path)
    config_path = env.component_paths("privoxy")["config"]
    config_path.parent.mkdir(parents=True)
    config_path.write_text("foreign config\n", encoding="utf-8")

    result = install_lib.apply_install(env=env, confirm=True, choices={}, runner=FakeRunner(), port_checker=lambda *_: False)

    assert result["ok"] is False
    assert "privoxy" in result["blocked"]
    assert config_path.read_text(encoding="utf-8") == "foreign config\n"
    assert not env.state_path.exists()


def test_apply_blocks_invalid_traffic_guard_before_writing_xray_config(tmp_path):
    env = _env(tmp_path)
    env.state_path.write_text(
        json.dumps({"traffic_guard": {"mode": "on", "domains": {"example.com": "block", "api.example.com": "allow"}}}),
        encoding="utf-8",
    )

    result = install_lib.apply_install(
        env=env,
        confirm=True,
        choices={},
        runner=FakeRunner(),
        port_checker=lambda *_: False,
        install_launchagent=False,
    )

    assert result["ok"] is False
    assert result["blocked"] == ["traffic_guard_invalid"]
    assert "traffic_guard" in result["error"]
    assert "api.example.com" in result["error"]
    assert not env.component_paths("xray")["config"].exists()


def test_apply_allows_invalid_traffic_guard_when_xray_is_skipped(tmp_path):
    env = _env(tmp_path)
    env.state_path.write_text(
        json.dumps({"traffic_guard": {"mode": "auto", "domains": {"video.example.com": "block"}}}),
        encoding="utf-8",
    )

    result = install_lib.apply_install(
        env=env,
        confirm=True,
        choices={"xray": "skip", "privoxy": "skip", "dnsmasq": "skip"},
        runner=FakeRunner(),
        port_checker=lambda *_: False,
        install_launchagent=False,
    )

    assert result["ok"] is True
    assert all(action["mode"] == "skipped" for action in result["actions"])
    assert not env.component_paths("xray")["config"].exists()


def test_adopt_conflict_marks_component_unmanaged_and_does_not_write_config(tmp_path):
    env = _env(tmp_path)
    config_path = env.component_paths("privoxy")["config"]
    config_path.parent.mkdir(parents=True)
    config_path.write_text("foreign config\n", encoding="utf-8")

    result = install_lib.apply_install(
        env=env,
        confirm=True,
        choices={"privoxy": "adopt", "xray": "skip", "dnsmasq": "skip"},
        runner=FakeRunner(),
        port_checker=lambda *_: False,
    )

    assert result["ok"] is True
    assert config_path.read_text(encoding="utf-8") == "foreign config\n"
    state = json.loads(env.state_path.read_text(encoding="utf-8"))
    assert state["detected_environment"]["privoxy"]["management"] == {"mode": "adopted", "managed": False}


def test_overwrite_conflict_backs_up_and_writes_managed_config(tmp_path):
    env = _env(tmp_path)
    config_path = env.component_paths("privoxy")["config"]
    config_path.parent.mkdir(parents=True)
    config_path.write_text("foreign config\n", encoding="utf-8")

    result = install_lib.apply_install(
        env=env,
        confirm=True,
        choices={"privoxy": "overwrite", "xray": "skip", "dnsmasq": "skip"},
        runner=FakeRunner(),
        port_checker=lambda *_: False,
    )

    assert result["ok"] is True
    assert install_lib.MARKER in config_path.read_text(encoding="utf-8")
    backup_path = config_path.with_name("config.srouter-backup-2026-06-29T000000Z")
    assert backup_path.read_text(encoding="utf-8") == "foreign config\n"
    state = json.loads(env.state_path.read_text(encoding="utf-8"))
    assert state["detected_environment"]["privoxy"]["backup"] == str(backup_path)


def test_apply_blocks_broken_existing_state_without_overwriting(tmp_path):
    env = _env(tmp_path)
    broken = '{ "nodes": [{"name": "real-secret-node"}], '
    env.state_path.write_text(broken, encoding="utf-8")

    result = install_lib.apply_install(
        env=env,
        confirm=True,
        choices={"xray": "skip", "privoxy": "skip", "dnsmasq": "skip"},
        runner=FakeRunner(),
        port_checker=lambda *_: False,
    )

    assert result["ok"] is False
    assert result["blocked"] == ["state_unreadable"]
    assert env.state_path.read_text(encoding="utf-8") == broken


def test_foreign_config_with_marker_substring_is_conflict_and_blocks_apply(tmp_path):
    env = _env(tmp_path)
    config_path = env.component_paths("privoxy")["config"]
    config_path.parent.mkdir(parents=True)
    original = "# my own notes about srouter-managed alternatives\nlisten-address 127.0.0.1:8118\n"
    config_path.write_text(original, encoding="utf-8")

    result = install_lib.apply_install(
        env=env,
        confirm=True,
        choices={"xray": "skip", "dnsmasq": "skip"},
        runner=FakeRunner(),
        port_checker=lambda *_: False,
    )

    assert result["ok"] is False
    assert "privoxy" in result["blocked"]
    assert config_path.read_text(encoding="utf-8") == original


def test_foreign_config_with_marker_like_header_is_conflict_and_blocks_apply(tmp_path):
    env = _env(tmp_path)
    config_path = env.component_paths("privoxy")["config"]
    config_path.parent.mkdir(parents=True)
    original = "# srouter-managed: not generated by srouter\nlisten-address 127.0.0.1:8118\n"
    config_path.write_text(original, encoding="utf-8")

    result = install_lib.apply_install(
        env=env,
        confirm=True,
        choices={"xray": "skip", "dnsmasq": "skip"},
        runner=FakeRunner(),
        port_checker=lambda *_: False,
    )

    assert result["ok"] is False
    assert "privoxy" in result["blocked"]
    assert config_path.read_text(encoding="utf-8") == original


def test_real_text_templates_have_exact_managed_marker():
    root = Path(__file__).resolve().parent.parent

    assert install_lib._has_marker(root / "templates" / "privoxy.config") is True
    assert install_lib._has_marker(root / "templates" / "dnsmasq.conf") is True


def test_install_retries_bootstrap_when_domain_busy(monkeypatch, tmp_path):
    """apply_install выживает при гонке занятого домена: первый bootstrap rc=5, второй rc=0 → ok.

    Без _launchd_reload install падал бы: один bootstrap rc=5 → fallback load -w (или ошибка).
    Теперь retry доводит до успеха. Канон always-tdd.
    """
    # Зануляем интервалы — мгновенный тест без реальных слипов.
    monkeypatch.setattr(install_lib, "_BOOTSTRAP_RETRY_DELAY", 0)
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    env = _env(tmp_path)

    calls = []

    def runner(cmd, timeout):
        calls.append(list(cmd))
        sub = cmd[1] if len(cmd) > 1 else ""
        if sub == "bootstrap":
            n = sum(1 for c in calls if c[1] == "bootstrap")
            return {"rc": 5 if n == 1 else 0, "out": "", "err": "", "timeout": False}
        # list (для _launchd_default_is_loaded / poll) → не загружен, выгрузился сразу.
        if sub == "list":
            return {"rc": 0, "out": "999\t0\tcom.other\n", "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    result = install_lib.apply_install(
        env=env,
        confirm=True,
        choices={"xray": "skip", "dnsmasq": "skip"},
        runner=runner,
        port_checker=lambda *_: False,
    )
    bootstraps = [c for c in calls if c[1] == "bootstrap"]
    assert result["ok"] is True, f"apply должен выстоять при гонке: {result}"
    assert len(bootstraps) >= 2, "первый bootstrap rc=5 → нужна retry-попытка"
