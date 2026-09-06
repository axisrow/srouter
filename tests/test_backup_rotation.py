"""PR-2 #339: ротация поколений (контракт v2 §3) + чистка USER_BACKUPS_DIR в uninstall.

Контракт (issue #339, подтверждён автором):
- A4 (install-конфиги, ~/.zshrc): при создании нового поколения удалять старые СВЕРХ
  окна (дефолт 3 последних валидных); env-ручка SROUTER_BACKUP_KEEP, 0 = без ротации;
- FAIL-CLOSED invariant: rotation не имеет права удалить поколение, на которое
  ссылается state (единственная копия несмёрженных пользовательских правок), и не
  имеет права удалить единственное поколение — при любом сомнении лишнее сохраняется;
- uninstall обязан чистить ~/Library/Application Support/srouter/backups/ — бэкапы
  собственных артефактов srouter содержат секреты и не переживают uninstall (v2 §1).
"""
import json
from pathlib import Path

import backup_lib
import install_lib

from test_install_flow import FakeRunner, _env, _port_checker_managed_up


def _seed_generations(config_path, stamps):
    """Поколения рядом с target (старые к новым по порядку stamps)."""
    backups = []
    for stamp in stamps:
        p = config_path.with_name(config_path.name + backup_lib.BACKUP_INFIX + stamp)
        p.write_text(f"gen {stamp}\n", encoding="utf-8")
        backups.append(p)
    return backups


# ============================ backup_lib.rotate_backups ============================
def test_rotate_keeps_window_of_newest_and_deletes_older(tmp_path):
    """Дефолт-окно 3: из 5 поколений удаляются 2 самых старых, 3 новых остаются."""
    target = tmp_path / "config"
    target.write_text("current\n", encoding="utf-8")
    gens = _seed_generations(target, [
        "2026-01-01T000000Z", "2026-02-01T000000Z", "2026-03-01T000000Z",
        "2026-04-01T000000Z", "2026-05-01T000000Z",
    ])

    result = backup_lib.rotate_backups(target)

    assert result["deleted"] == [gens[0], gens[1]]
    assert backup_lib.discover(target) == gens[2:]


def test_rotate_keep_zero_disables_rotation(tmp_path):
    """SROUTER_BACKUP_KEEP=0 — ротация выключена: поколения не трогаются (контракт §3)."""
    target = tmp_path / "config"
    target.write_text("current\n", encoding="utf-8")
    gens = _seed_generations(target, ["2026-01-01T000000Z", "2026-02-01T000000Z",
                                      "2026-03-01T000000Z", "2026-04-01T000000Z"])

    result = backup_lib.rotate_backups(target, keep=0)

    assert result["deleted"] == []
    assert backup_lib.discover(target) == gens


def test_rotate_never_deletes_state_pointed_generation(tmp_path):
    """FAIL-CLOSED: поколение, названное state-поинтером (protected), не удаляется,
    даже когда оно за окном. «Единственная копия несмёрженных правок» неприкосновенна."""
    target = tmp_path / "config"
    target.write_text("current\n", encoding="utf-8")
    gens = _seed_generations(target, [
        "2026-01-01T000000Z", "2026-02-01T000000Z", "2026-03-01T000000Z",
        "2026-04-01T000000Z", "2026-05-01T000000Z",
    ])

    result = backup_lib.rotate_backups(target, keep=3, protected=[gens[0]])

    # Удаляется только НЕзащищённое за окном; protected-первенец остаётся
    assert result["deleted"] == [gens[1]]
    assert gens[0].exists()
    assert backup_lib.discover(target) == [gens[0]] + gens[2:]


def test_rotate_never_deletes_single_generation(tmp_path):
    """Единственное поколение не удаляется ни при каких настройках окна (fail-closed)."""
    target = tmp_path / "config"
    target.write_text("current\n", encoding="utf-8")
    gens = _seed_generations(target, ["2026-01-01T000000Z"])

    result = backup_lib.rotate_backups(target, keep=3)

    assert result["deleted"] == []
    assert backup_lib.discover(target) == gens


def test_rotate_deletion_failure_is_reported_not_raised(tmp_path, monkeypatch):
    """Ротация — best-effort: сбой unlink попадает в report, не роняет install."""
    target = tmp_path / "config"
    target.write_text("current\n", encoding="utf-8")
    gens = _seed_generations(target, ["2026-01-01T000000Z", "2026-02-01T000000Z",
                                      "2026-03-01T000000Z", "2026-04-01T000000Z",
                                      "2026-05-01T000000Z"])

    real_unlink = Path.unlink

    def flaky_unlink(self, *args, **kwargs):
        if self == gens[0]:
            raise OSError("EPERM")
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", flaky_unlink)

    result = backup_lib.rotate_backups(target, keep=3)

    assert gens[0].exists(), "сбойный не удалён, но и не потерян из report"
    assert gens[1].exists() is False
    assert gens[0] in result["failed"]


def test_rotate_keep_resolved_from_env(tmp_path, monkeypatch):
    """SROUTER_BACKUP_KEEP — env-ручка окна (канон more-options-better): 2 → окно 2."""
    target = tmp_path / "config"
    target.write_text("current\n", encoding="utf-8")
    gens = _seed_generations(target, ["2026-01-01T000000Z", "2026-02-01T000000Z",
                                      "2026-03-01T000000Z", "2026-04-01T000000Z"])
    monkeypatch.setenv("SROUTER_BACKUP_KEEP", "2")

    result = backup_lib.rotate_backups(target)

    assert result["deleted"] == gens[:2]
    assert backup_lib.discover(target) == gens[2:]


def test_rotate_invalid_env_keep_falls_back_to_default(tmp_path, monkeypatch):
    """Мусор в SROUTER_BACKUP_KEEP — дефолт 3, не краш и не «ротация всё»."""
    target = tmp_path / "config"
    target.write_text("current\n", encoding="utf-8")
    gens = _seed_generations(target, ["2026-01-01T000000Z", "2026-02-01T000000Z",
                                      "2026-03-01T000000Z", "2026-04-01T000000Z"])
    monkeypatch.setenv("SROUTER_BACKUP_KEEP", "не-число")

    result = backup_lib.rotate_backups(target)

    assert result["deleted"] == [gens[0]]
    assert backup_lib.discover(target) == gens[1:]


# ============================ purge USER_BACKUPS_DIR ============================
def test_purge_user_backups_removes_dir_with_contents(tmp_path, monkeypatch):
    """Uninstall чистит каталог бэкапов собственных артефактов: секреты не переживают
    uninstall (контракт v2 §1). Каталог целиком, вместе с содержимым."""
    backups_dir = tmp_path / "backups"
    (backups_dir / "state").mkdir(parents=True)
    (backups_dir / "state" / "srouter.local.json.srouter-backup-2026-01-01T000000Z").write_text(
        json.dumps({"nodes": [{"name": "secret"}]}), encoding="utf-8")
    monkeypatch.setattr(backup_lib, "USER_BACKUPS_DIR", backups_dir)

    result = backup_lib.purge_user_backups()

    assert result == "purged"
    assert not backups_dir.exists()


def test_purge_user_backups_absent_dir_is_ok(tmp_path, monkeypatch):
    monkeypatch.setattr(backup_lib, "USER_BACKUPS_DIR", tmp_path / "absent")

    assert backup_lib.purge_user_backups() == "absent"


# ============================ интеграция: apply_install ротирует ============================
def test_apply_install_rotates_stale_generations_beyond_window(tmp_path):
    """Обрывы/повторные install'ы копят поколения без чистки (инвентарь #339 A4).
    После успешного apply-поколения старше окна удаляются, новейшие (включая свежее)
    остаются; state-поинтер Fresh-цикла неприкосновенен."""
    env = _env(tmp_path)
    config_path = env.component_paths("privoxy")["config"]
    config_path.parent.mkdir(parents=True)
    config_path.write_text("foreign config\n", encoding="utf-8")
    # 4 реликта прошлых циклов (все старее created_at-границы текущего env.now)
    stale = _seed_generations(config_path, [
        "2026-01-01T000000Z", "2026-02-01T000000Z",
        "2026-03-01T000000Z", "2026-04-01T000000Z",
    ])

    runner = FakeRunner()
    result = install_lib.apply_install(
        env=env,
        confirm=True,
        choices={"privoxy": "overwrite", "xray": "skip", "dnsmasq": "skip"},
        runner=runner,
        port_checker=_port_checker_managed_up(runner.calls),
    )

    assert result["ok"] is True, result
    fresh = config_path.with_name("config.srouter-backup-2026-06-29T000000Z")
    assert fresh.exists()
    # окно 3: свежее + 2 новейших реликта остаются, 2 старейших удалены
    assert not stale[0].exists()
    assert not stale[1].exists()
    assert stale[2].exists()
    assert stale[3].exists()
    state = json.loads(env.state_path.read_text(encoding="utf-8"))
    assert state["detected_environment"]["privoxy"]["backup"] == str(fresh)


def test_apply_install_rotation_env_keep_zero_disables(tmp_path, monkeypatch):
    """SROUTER_BACKUP_KEEP=0 действует и через install-путь: поколения не трогаются
    (осознанное «хранить всё» — контракт §3, канон more-options-better)."""
    env = _env(tmp_path)
    config_path = env.component_paths("privoxy")["config"]
    config_path.parent.mkdir(parents=True)
    config_path.write_text("foreign config\n", encoding="utf-8")
    stale = _seed_generations(config_path, [
        "2026-01-01T000000Z", "2026-02-01T000000Z",
        "2026-03-01T000000Z", "2026-04-01T000000Z",
    ])
    monkeypatch.setenv("SROUTER_BACKUP_KEEP", "0")

    runner = FakeRunner()
    result = install_lib.apply_install(
        env=env,
        confirm=True,
        choices={"privoxy": "overwrite", "xray": "skip", "dnsmasq": "skip"},
        runner=runner,
        port_checker=_port_checker_managed_up(runner.calls),
    )

    assert result["ok"] is True, result
    assert all(g.exists() for g in stale), "ротация выключена — реликты не тронуты"
    assert config_path.with_name("config.srouter-backup-2026-06-29T000000Z").exists()


# ============================ интеграция: uninstall чистит USER_BACKUPS_DIR ============================
def test_ensure_home_bin_rotates_zshrc_generations(monkeypatch, tmp_path):
    """~/.zshrc-поколения (A6, контракт §3) ротируются тем же примитивом: повторные
    install'ы не копят .zshrc.srouter-backup-* бесконечно (инвентарь #339 A6)."""
    from test_srouter_codex_zsh import _mock_home
    import codex_wrappers
    import install_lib

    home = _mock_home(monkeypatch, tmp_path)
    env = install_lib.InstallEnv(
        root=Path(__file__).resolve().parent.parent,
        prefix=tmp_path / "homebrew",
        state_path=tmp_path / "srouter.local.json",
        launchagent_dir=home / "Library" / "LaunchAgents",
        now="2026-07-04T00:00:00Z",
    )
    zshrc = home / ".zshrc"
    zshrc.write_text("export PATH=/usr/local/bin:$PATH\n", encoding="utf-8")
    stale = _seed_generations(zshrc, [
        "2026-01-01T000000Z", "2026-02-01T000000Z",
        "2026-03-01T000000Z", "2026-04-01T000000Z",
    ])

    codex_wrappers._ensure_home_bin_in_path(env)

    fresh = home / ".zshrc.srouter-backup-2026-07-04T000000Z"
    assert fresh.exists(), "свежее поколение создано"
    # окно 3: свежее + 2 новейших реликта; 2 старейших удалены
    assert not stale[0].exists()
    assert not stale[1].exists()
    assert stale[2].exists() and stale[3].exists()


def test_apply_uninstall_purges_user_backups_dir(tmp_path, monkeypatch):
    from test_uninstall_flow import FakeRunner as UninstallRunner, _write_state

    env = _env(tmp_path)
    backups_dir = tmp_path / "appsupport" / "backups"
    backups_dir.mkdir(parents=True)
    (backups_dir / "srouter.local.json.srouter-backup-2026-01-01T000000Z").write_text(
        json.dumps({"nodes": [{"name": "secret-vps"}]}), encoding="utf-8")
    monkeypatch.setattr(backup_lib, "USER_BACKUPS_DIR", backups_dir)
    _write_state(env)

    result = install_lib.apply_uninstall(
        env=env, confirmations={"configs": True}, runner=UninstallRunner(),
    )

    assert result["ok"] is True
    assert not backups_dir.exists(), "секреты бэкапов не переживают uninstall (v2 §1)"
