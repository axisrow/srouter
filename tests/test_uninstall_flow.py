import json
import plistlib
from pathlib import Path

import pytest

import install_lib


class FakeRunner:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def __call__(self, cmd, timeout):
        self.calls.append(list(cmd))
        if tuple(cmd) in self.responses:
            return self.responses[tuple(cmd)]
        # `launchctl print <domain>/<label>` по умолчанию → rc=113 (service-not-found = НЕ загружен):
        # в чистом install/uninstall-окружении реальный агент никто не поднимал. Иначе default rc=0
        # читался бы как «загружен» → poll _launchd_unload крутил бы полный settle (домен-осознанная
        # проверка через print, cycle-review #93).
        if len(cmd) > 1 and cmd[1] == "print":
            return {"rc": 113, "out": "", "err": "Could not find service", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}


def _env(tmp_path):
    return install_lib.InstallEnv(
        root=Path(__file__).resolve().parent.parent,
        prefix=tmp_path / "homebrew",
        state_path=tmp_path / "srouter.local.json",
        launchagent_dir=tmp_path / "LaunchAgents",
        now="2026-06-29T00:00:00Z",
    )


def _write_state(env, detected=None, network=None):
    state = {
        "schema_version": 1,
        "nodes": [],
        "active_node": {"name": None, "pending": None},
        "probes": {},
        "network": network or {"channels": {"wifi_service": "Wi-Fi"}},
        "traffic_guard": {"mode": "off", "domains": {}},
        "detected_environment": detected or {},
        "runtime": {},
    }
    env.state_path.write_text(json.dumps(state), encoding="utf-8")
    return state


def _managed_component(env, name, backup_path):
    config_path = env.component_paths(name)["config"]
    return {
        "config_path": str(config_path),
        "backup": str(backup_path),
        "management": {"mode": "managed", "managed": True},
    }


def _write_removable_launchagent(env):
    """Реальный srouter-managed plist на диске + detected-entry, дающий removable=True.

    _launchagent_uninstall_item: removable = managed(entry) AND marker_present(plist на диске).
    Пишем plist с LAUNCHAGENT_MARKER по env.launchagent_path() и managed-entry в detected — тогда
    plan['launchagent']['removable'] is True и _unload_launchagent доходит до bootout+poll+unlink.
    Возвращает путь к plist.
    """
    plist_path = env.launchagent_path()
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    plist_path.write_text(
        f"<?xml version='1.0'?>\n<!-- {install_lib.LAUNCHAGENT_MARKER} -->\n"
        "<plist version='1.0'><dict>"
        f"<key>Label</key><string>{install_lib.LAUNCHAGENT_LABEL}</string>"
        "</dict></plist>\n",
        encoding="utf-8")
    return plist_path


class ListRunner:
    """runner с диспетчеризацией по cmd[1]: `print` гонит loaded-состояния последовательно.

    canned-dict FakeRunner не умеет sequence-состояний (нужно True→False по каждому print-вызову для
    poll'а _launchd_unload). Проверка выгрузки — домен-осознанный `launchctl print` (cycle-review #93):
    loaded кодируется rc (True→rc0 / False→rc113=service-not-found / None→timeout). list_states:
    [True/False/None,...] на каждый вызов print (держим последнее при исчерпании). bootout/прочее → успех.
    """
    def __init__(self, list_states):
        self.list_states = list_states
        self.calls = []
        self._i = 0

    def __call__(self, cmd, timeout):
        self.calls.append(list(cmd))
        sub = cmd[1] if len(cmd) > 1 else ""
        if sub == "print":
            idx = min(self._i, len(self.list_states) - 1)
            self._i += 1
            loaded = self.list_states[idx]
            if loaded is None:
                return {"rc": None, "out": "", "err": "timeout", "timeout": True}
            if loaded:
                return {"rc": 0, "out": f"{install_lib.LAUNCHAGENT_LABEL} = {{ state = running }}",
                        "err": "", "timeout": False}
            return {"rc": 113, "out": "", "err": "Could not find service", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}


def _bootouts(calls):
    return [c for c in calls if len(c) > 1 and c[1] == "bootout"]


class PrintFailureRunner:
    """runner, у которого `print` возвращает заданный сбойный/живой dict.

    Эмулирует: домен недоступен (rc=112), сломанный launchctl (rc≠0 / rc=None,timeout=False —
    FileNotFoundError/PermissionError/OSError), ИЛИ агент жив (rc=0). Всё, кроме rc=113 (и timeout
    отдельно), → None (unknown) в _launchd_is_loaded → fail-safe. bootout/прочее → успех.
    """
    def __init__(self, print_result):
        self.print_result = print_result
        self.calls = []

    def __call__(self, cmd, timeout):
        self.calls.append(list(cmd))
        if len(cmd) > 1 and cmd[1] == "print":
            return dict(self.print_result)
        return {"rc": 0, "out": "", "err": "", "timeout": False}


def test_uninstall_plan_does_not_call_runner_or_touch_files(tmp_path):
    env = _env(tmp_path)
    backup = tmp_path / "privoxy.backup"
    backup.write_text("foreign config\n", encoding="utf-8")
    config = env.component_paths("privoxy")["config"]
    config.parent.mkdir(parents=True)
    config.write_text("# srouter-managed-config-v1\n", encoding="utf-8")
    _write_state(env, {"privoxy": _managed_component(env, "privoxy", backup)})
    runner = FakeRunner()

    plan = install_lib.build_uninstall_plan(env=env, runner=runner)

    assert plan["mode"] == "uninstall-plan"
    assert runner.calls == []
    assert config.read_text(encoding="utf-8") == "# srouter-managed-config-v1\n"
    assert backup.read_text(encoding="utf-8") == "foreign config\n"
    assert "srouter.local.json" in plan["user_data_retained"]


def test_uninstall_adopted_component_is_left_untouched(tmp_path):
    env = _env(tmp_path)
    config = env.component_paths("privoxy")["config"]
    config.parent.mkdir(parents=True)
    config.write_text("foreign config\n", encoding="utf-8")
    _write_state(
        env,
        {
            "privoxy": {
                "config_path": str(config),
                "management": {"mode": "adopted", "managed": False},
            }
        },
    )
    runner = FakeRunner()

    result = install_lib.apply_uninstall(
        env=env,
        confirmations={"configs": True, "services": True, "dns": True, "launchagent": True},
        runner=runner,
    )

    assert result["ok"] is True
    assert config.read_text(encoding="utf-8") == "foreign config\n"
    assert any(item["status"] == "adopted — left untouched" for item in result["components"])
    assert all("privoxy" not in call for call in runner.calls)


def test_uninstall_skipped_component_is_not_reported_as_adopted(tmp_path):
    env = _env(tmp_path)
    _write_state(
        env,
        {
            "privoxy": {
                "config_path": str(env.component_paths("privoxy")["config"]),
                "management": {"mode": "skipped", "managed": False},
            }
        },
    )

    plan = install_lib.build_uninstall_plan(env=env)
    privoxy = next(item for item in plan["components"] if item["name"] == "privoxy")

    assert privoxy["status"] == "unmanaged — left untouched"


def test_uninstall_restores_managed_config_only_after_category_confirmation(tmp_path):
    env = _env(tmp_path)
    backup = tmp_path / "privoxy.backup"
    backup.write_text("foreign config\n", encoding="utf-8")
    config = env.component_paths("privoxy")["config"]
    config.parent.mkdir(parents=True)
    config.write_text("# srouter-managed-config-v1\nlisten-address 127.0.0.1:8118\n", encoding="utf-8")
    _write_state(env, {"privoxy": _managed_component(env, "privoxy", backup)})

    skipped = install_lib.apply_uninstall(env=env, confirmations={"configs": False}, runner=FakeRunner())
    assert skipped["ok"] is True
    assert "srouter-managed-config-v1" in config.read_text(encoding="utf-8")

    restored = install_lib.apply_uninstall(env=env, confirmations={"configs": True}, runner=FakeRunner())
    assert restored["ok"] is True
    assert config.read_text(encoding="utf-8") == "foreign config\n"


def test_uninstall_restore_then_separate_stop_services_does_not_stop_restored_component(tmp_path):
    env = _env(tmp_path)
    backup = tmp_path / "privoxy.backup"
    backup.write_text("foreign config\n", encoding="utf-8")
    config = env.component_paths("privoxy")["config"]
    config.parent.mkdir(parents=True)
    config.write_text("# srouter-managed-config-v1\nlisten-address 127.0.0.1:8118\n", encoding="utf-8")
    _write_state(env, {"privoxy": _managed_component(env, "privoxy", backup)})

    restored = install_lib.apply_uninstall(env=env, confirmations={"configs": True}, runner=FakeRunner())
    assert restored["ok"] is True
    state_after_restore = json.loads(env.state_path.read_text(encoding="utf-8"))
    assert state_after_restore["detected_environment"]["privoxy"]["management"] == {
        "mode": "restored",
        "managed": False,
    }

    runner = FakeRunner()
    stopped = install_lib.apply_uninstall(env=env, confirmations={"services": True}, runner=runner)

    assert stopped["ok"] is True
    assert [install_lib.BREW, "services", "stop", "privoxy"] not in runner.calls


def test_uninstall_does_not_delete_user_data_by_default(tmp_path):
    env = _env(tmp_path)
    backup = tmp_path / "xray.backup"
    backup.write_text('{"foreign": true}\n', encoding="utf-8")
    config = env.component_paths("xray")["config"]
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"srouter": {"marker": install_lib.MARKER}}), encoding="utf-8")
    bundle = tmp_path / "deploy-bundles" / "node.json"
    bundle.parent.mkdir()
    bundle.write_text("bundle\n", encoding="utf-8")
    _write_state(env, {"xray": _managed_component(env, "xray", backup)})

    result = install_lib.apply_uninstall(
        env=env,
        confirmations={"configs": True, "services": True, "dns": True, "launchagent": True},
        runner=FakeRunner(),
    )

    assert result["ok"] is True
    assert env.state_path.exists()
    assert backup.exists()
    assert bundle.exists()


def test_install_apply_writes_loopback_launchagent_and_records_management(tmp_path):
    env = _env(tmp_path)
    runner = FakeRunner()

    result = install_lib.apply_install(
        env=env,
        confirm=True,
        choices={"xray": "skip", "privoxy": "skip", "dnsmasq": "skip"},
        runner=runner,
        port_checker=lambda *_args, **_kwargs: False,
    )

    assert result["ok"] is True
    plist_path = env.launchagent_path()
    assert plist_path.exists()
    plist = plistlib.loads(plist_path.read_bytes())
    assert plist["Label"] == install_lib.LAUNCHAGENT_LABEL
    assert plist["RunAtLoad"] is True
    assert plist["ProgramArguments"] == [env.python_bin, str(env.root / "dashboard.py")]
    assert "0.0.0.0" not in plist_path.read_text(encoding="utf-8")
    assert [install_lib.LAUNCHCTL, "bootstrap", f"gui/{install_lib.os.getuid()}", str(plist_path)] in runner.calls

    state = json.loads(env.state_path.read_text(encoding="utf-8"))
    assert state["detected_environment"]["launchagent"]["management"] == {"mode": "managed", "managed": True}


def test_install_init_style_apply_can_skip_launchagent_lifecycle(tmp_path):
    env = _env(tmp_path)
    runner = FakeRunner()

    result = install_lib.apply_install(
        env=env,
        confirm=True,
        choices={"xray": "skip", "privoxy": "skip", "dnsmasq": "skip"},
        runner=runner,
        port_checker=lambda *_args, **_kwargs: False,
        install_launchagent=False,
    )

    assert result["ok"] is True
    assert not env.launchagent_path().exists()
    assert all(install_lib.LAUNCHCTL not in call for call in runner.calls)


# ============================ сайт B: _unload_launchagent (bootout-and-confirm-unloaded, issue #84) ============================
def _managed_launchagent_detected():
    """detected-entry для launchagent: managed + дефолтный label (→ item['label']=LAUNCHAGENT_LABEL)."""
    return {"management": {"mode": "managed", "managed": True}}


def test_uninstall_launchagent_unlinks_after_confirmed_unload(tmp_path, monkeypatch):
    """Агент подтверждённо выгрузился (print True→False, т.е. rc0→rc113) → plist удалён, ok+changed."""
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    env = _env(tmp_path)
    plist_path = _write_removable_launchagent(env)
    _write_state(env, {"launchagent": _managed_launchagent_detected()})
    runner = ListRunner(list_states=[True, False])  # ещё висит → выгрузился

    result = install_lib.apply_uninstall(
        env=env, confirmations={"launchagent": True}, runner=runner)

    assert result["ok"] is True
    assert any(a.get("category") == "launchagent" and a.get("changed") for a in result["actions"]), \
        "launchagent-действие changed=True"
    assert not plist_path.exists(), "после подтверждённой выгрузки plist удалён"
    assert len(_bootouts(runner.calls)) == 1, "bootout ровно один раз"


def test_uninstall_launchagent_keeps_plist_when_still_loaded(tmp_path, monkeypatch):
    """ПРАЙМ-ЦЕЛЬ (тест 8): агент ещё загружен после settle → plist НЕ удалён, blocked.

    На СТАРОМ коде B (unlink безусловно после bootout) этот тест ПАДАЕТ — доказывает латентную
    гонку. settle-потолок ≈0 (иначе poll крутил бы 2с), print всегда rc0 → state=True → fail-safe.
    Живой StartInterval-агент иначе пере-применял бы мёртвый конфиг.
    """
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_lib, "_BOOTOUT_SETTLE_MAX_WAIT", 0)
    env = _env(tmp_path)
    plist_path = _write_removable_launchagent(env)
    _write_state(env, {"launchagent": _managed_launchagent_detected()})
    runner = ListRunner(list_states=[True] * 6)  # не выгружается

    result = install_lib.apply_uninstall(
        env=env, confirmations={"launchagent": True}, runner=runner)

    assert result["ok"] is False
    assert result["blocked"] == ["launchagent_unload_failed"]
    assert plist_path.exists(), "агент ещё загружен → plist оставлен (fail-safe)"


def test_uninstall_launchagent_keeps_plist_when_list_timeout(tmp_path, monkeypatch):
    """list timeout (None = неизвестно) → fail-safe: plist НЕ удалён, blocked. None-ветка для B."""
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    env = _env(tmp_path)
    plist_path = _write_removable_launchagent(env)
    _write_state(env, {"launchagent": _managed_launchagent_detected()})
    runner = ListRunner(list_states=[None])  # list timeout → state=None

    result = install_lib.apply_uninstall(
        env=env, confirmations={"launchagent": True}, runner=runner)

    assert result["ok"] is False
    assert result["blocked"] == ["launchagent_unload_failed"]
    assert plist_path.exists(), "list timeout (неизвестно) → plist оставлен (fail-safe)"


@pytest.mark.parametrize("print_result", [
    {"rc": 1, "out": "", "err": "boom", "timeout": False},                              # прочий rc
    {"rc": None, "out": "", "err": "FileNotFoundError: launchctl", "timeout": False},   # OSError-путь
], ids=["nonzero_rc", "launch_failure"])
def test_uninstall_launchagent_keeps_plist_when_print_fails(tmp_path, monkeypatch, print_result):
    """Сломанный launchctl print (rc≠0/≠113 / rc=None,timeout=False — НЕ timeout) → fail-safe: plist ОСТАВЛЕН.

    Регресс-гард раунда 1 (на print): _launchd_is_loaded возвращает None (не False) на сбойном
    print → state is not False → _unload_launchagent НЕ удаляет plist живого агента.
    """
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_lib, "_BOOTOUT_SETTLE_MAX_WAIT", 0)
    env = _env(tmp_path)
    plist_path = _write_removable_launchagent(env)
    _write_state(env, {"launchagent": _managed_launchagent_detected()})
    runner = PrintFailureRunner(print_result)

    result = install_lib.apply_uninstall(
        env=env, confirmations={"launchagent": True}, runner=runner)

    assert result["ok"] is False
    assert result["blocked"] == ["launchagent_unload_failed"]
    assert plist_path.exists(), "сломанный print (неизвестно) → plist оставлен (fail-safe)"


@pytest.mark.parametrize("print_result", [
    # bootout «сработал» (rc игнорируется), но print показывает агента ЖИВЫМ (rc=0) — не выгрузился.
    {"rc": 0, "out": "com.srouter.dashboard = { state = running }", "err": "", "timeout": False},
    # print rc=112: домен gui/<uid> недоступен (не-gui контекст, SSH/cron) — НЕ «агента нет».
    {"rc": 112, "out": "", "err": "Could not find domain", "timeout": False},
], ids=["still_alive_rc0", "domain_not_found_rc112"])
def test_uninstall_launchagent_keeps_plist_on_domain_mismatch(tmp_path, monkeypatch, print_result):
    """РЕГРЕСС-ГАРД ДОМЕН-MISMATCH (cycle-review #93, 2-я critical): fail-safe при живом агенте / недоступном домене.

    До фикса _launchd_is_loaded звал legacy `launchctl list` БЕЗ домена → из не-gui контекста
    gui-агент не виден → list rc=0 без label → False («выгружен») → _unload_launchagent удалял plist
    ЖИВОГО gui-агента. Теперь домен-осознанный `print gui/<uid>/<label>`: rc=0 (жив) → True, rc=112
    (домен недоступен) → None; оба → state is not False → plist ОСТАВЛЕН. На коде до фикса падал.
    """
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_lib, "_BOOTOUT_SETTLE_MAX_WAIT", 0)
    env = _env(tmp_path)
    plist_path = _write_removable_launchagent(env)
    _write_state(env, {"launchagent": _managed_launchagent_detected()})
    runner = PrintFailureRunner(print_result)

    result = install_lib.apply_uninstall(
        env=env, confirmations={"launchagent": True}, runner=runner)

    assert result["ok"] is False
    assert result["blocked"] == ["launchagent_unload_failed"]
    assert plist_path.exists(), "живой агент / недоступный домен → plist оставлен (fail-safe)"


def test_uninstall_launchagent_not_removable_is_noop(tmp_path):
    """Non-removable item (нет plist/маркера) → {ok:True, changed:False}, НЕТ bootout (ранний возврат)."""
    env = _env(tmp_path)
    # plist на диске нет → marker_present False → removable False.
    _write_state(env, {"launchagent": _managed_launchagent_detected()})
    runner = ListRunner(list_states=[False])

    result = install_lib.apply_uninstall(
        env=env, confirmations={"launchagent": True}, runner=runner)

    assert result["ok"] is True
    assert not any(a.get("category") == "launchagent" for a in result["actions"]), \
        "non-removable → нет launchagent-действия"
    assert _bootouts(runner.calls) == [], "non-removable → ранний возврат, bootout не вызван"


# ============================ сайт B identity: plist↔label bound (issue #94 DEFECT B) ============================
# label и plist_path берутся НЕЗАВИСИМОМ из state-item. marker_present проверяет маркер в plist, но НЕ
# проверяет, что Label ВНУТРИ plist == item['label'] == целевой агент. При state-drift (label агента X,
# path агента Y) или marker-preserving label swap: _launchd_unload bootout'ит label X → rc 113 (X не
# найден = «выгружен») → unlink удаляет plist_path ЖИВОГО агента Y. Codex репрод: label com.srouter.stale
# + path com.srouter.dashboard.plist → unlink dashboard.plist при живом dashboard.
# Fix: plistlib.load(plist_path), требовать Label==expected==path-derived, fail-closed на любой mismatch.
def _mismatch_item(env, *, plist_label, item_label):
    """state-item с РАССИНХРОНИЗИРОВАННЫМИ label (item) и plist (на диске).

    plist_path указывает на файл, содержащий plist_label (имя файла + Label внутри = plist_label).
    item['label'] = item_label (рассинхрон от state-drift). removable=True: маркер присутствует.
    Воспроизводит сценарий DEFECT B: bootout по item_label (не найден → rc113 → «выгружен») → unlink
    plist_path живого plist_label-агента.
    """
    plist_path = env.launchagent_dir / f"{plist_label}.plist"
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    plist_path.write_text(
        f"<?xml version='1.0'?>\n<!-- {install_lib.LAUNCHAGENT_MARKER} -->\n"
        "<plist version='1.0'><dict>"
        f"<key>Label</key><string>{plist_label}</string>"
        "</dict></plist>\n",
        encoding="utf-8")
    return {
        "label": item_label,
        "plist_path": str(plist_path),
        "managed": True,
        "adopted": False,
        "marker_present": True,
        "removable": True,
        "status": "managed — unload/remove available",
    }


def test_unload_launchagent_fails_closed_on_label_plist_mismatch(monkeypatch, tmp_path):
    """DEFECT B: item.label ≠ Label внутри plist → fail-closed, plist ЖИВОГО агента НЕ удалён.

    label=com.srouter.stale (item), plist=com.srouter.dashboard.plist (Label внутри = dashboard).
    bootout com.srouter.stale → rc 113 (не найден) → state False («выгружен»). БЕЗ identity-проверки
    код unlink'ает dashboard.plist — ЖИВОЙ агент. Теперь: plistlib.load требует Label==item_label, на
    mismatch → ok=False, plist оставлен. На коде до фикса тест ПАДАЕТ (plist удаляется).
    """
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    env = _env(tmp_path)
    item = _mismatch_item(env, plist_label="com.srouter.dashboard",
                          item_label="com.srouter.stale")
    plist_path = Path(item["plist_path"])
    # print по item_label (stale) → rc 113 (stale не найден = «выгружен») → дыра без identity-связки.
    runner = ListRunner(list_states=[False])

    result = install_lib._unload_launchagent(item, runner)

    assert result["ok"] is False, "mismatch label↔plist → fail-closed (НЕ удалять чужой plist)"
    assert result.get("blocked") == "launchagent_identity_mismatch", \
        f"blocked идентифицирует именно identity-mismatch: {result}"
    assert plist_path.exists(), "plist ЖИВОГО агента НЕ удалён (identity-mismatch)"


def test_unload_launchagent_unlinks_when_label_matches_plist(monkeypatch, tmp_path):
    """DEFECT B (контроль): item.label == Label внутри plist == path-derived → корректный unlink.

    Identity связана: единый label на всех уровнях. bootout → state False → plistlib.load подтверждает
    Label==item_label → unlink безопасен. Регресс-гард: валидный путь не сломан identity-проверкой.
    """
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    env = _env(tmp_path)
    # item.label == plist_label == имя файла → тождество.
    item = _mismatch_item(env, plist_label=install_lib.LAUNCHAGENT_LABEL,
                          item_label=install_lib.LAUNCHAGENT_LABEL)
    plist_path = Path(item["plist_path"])
    runner = ListRunner(list_states=[False])

    result = install_lib._unload_launchagent(item, runner)

    assert result["ok"] is True and result.get("changed") is True
    assert not plist_path.exists(), "label совпал → plist безопасно удалён"


def test_unload_launchagent_fails_closed_on_path_label_mismatch(monkeypatch, tmp_path):
    """DEFECT B: имя файла plist ≠ его внутренний Label → fail-closed (path-derived ≠ in-plist).

    Даже если item.label совпадает с одним из них, рассинхрон имя-файла↔Label-внутри = аномалия
    (файл подменён). path-derived label — третий арбитр: все три должны совпасть.
    """
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    env = _env(tmp_path)
    # Файл называется stale.plist, но внутри Label=dashboard — подмена.
    item = _mismatch_item(env, plist_label="com.srouter.dashboard",
                          item_label="com.srouter.stale")
    # Переименуем файл так, чтобы имя ≠ внутренний Label, но item.plist_path указывал на него.
    plist_path = Path(item["plist_path"])
    renamed = env.launchagent_dir / "com.srouter.stale.plist"
    plist_path.rename(renamed)
    item["plist_path"] = str(renamed)
    # item.label==stale==имя файла, но Label внутри=dashboard → mismatch path↔in-plist.
    runner = ListRunner(list_states=[False])

    result = install_lib._unload_launchagent(item, runner)

    assert result["ok"] is False, "имя файла ≠ Label внутри → fail-closed"
    assert renamed.exists(), "подозрительный plist НЕ удалён"


def test_unload_launchagent_fails_closed_on_missing_label_key(monkeypatch, tmp_path):
    """DEFECT B: plist без ключа Label (или невалидный) → fail-closed, НЕ unlink.

    Нельзя доверять item.label, если plist не подтверждает identity собственным Label. Нет Label →
    identity не верифицируема → fail-closed (как и любой mismatch).
    """
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    env = _env(tmp_path)
    plist_path = env.launchagent_dir / f"{install_lib.LAUNCHAGENT_LABEL}.plist"
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    plist_path.write_text(
        f"<?xml version='1.0'?>\n<!-- {install_lib.LAUNCHAGENT_MARKER} -->\n"
        "<plist version='1.0'><dict><key>RunAtLoad</key><true/></dict></plist>\n",
        encoding="utf-8")
    item = {"label": install_lib.LAUNCHAGENT_LABEL, "plist_path": str(plist_path),
            "removable": True}
    runner = ListRunner(list_states=[False])

    result = install_lib._unload_launchagent(item, runner)

    assert result["ok"] is False, "plist без Label → identity не верифицируема → fail-closed"
    assert plist_path.exists(), "plist без Label НЕ удалён"


def test_unload_launchagent_fails_closed_on_malformed_xml_plist(monkeypatch, tmp_path):
    """DEFECT B: битый XML plist (ExpatError) → fail-closed, НЕ unlink, без traceback.

    ExpatError — отдельная иерархия (НЕ подкласс ValueError): недозакрытый тег / мусор. plistlib
    пробрасывает ExpatError, его надо ловить явно — иначе _unload_launchagent упадёт с traceback
    вместо контролируемого {ok:False}. Имя файла совпадает с label (нормальный путь), но контент
    невалиден → identity не верифицируема → fail-closed.
    """
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    env = _env(tmp_path)
    plist_path = env.launchagent_dir / f"{install_lib.LAUNCHAGENT_LABEL}.plist"
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    plist_path.write_text(
        f"<?xml version='1.0'?>\n<!-- {install_lib.LAUNCHAGENT_MARKER} -->\n"
        "<plist version='1.0'><dict><key>Label</key><string>broken",  # недозакрытый XML
        encoding="utf-8")
    item = {"label": install_lib.LAUNCHAGENT_LABEL, "plist_path": str(plist_path),
            "removable": True}
    runner = ListRunner(list_states=[False])

    result = install_lib._unload_launchagent(item, runner)

    assert result["ok"] is False, "битый XML plist → fail-closed (без traceback)"
    assert result.get("blocked") == "launchagent_identity_mismatch"
    assert plist_path.exists(), "битый plist НЕ удалён"


def test_unload_launchagent_identity_check_before_unlink_live_agent(monkeypatch, tmp_path):
    """DEFECT B e2e: apply_uninstall с state-drift → ЖИВОЙ агент НЕ затронут.

    Сценарий Codex: plan['launchagent'] имеет label=com.srouter.stale, plist_path=dashboard.plist
    (живой). Без identity-связки: bootout stale (rc113) → unlink dashboard.plist. Теперь mismatch
    перехватывается ДО unlink → ok=False, apply_uninstall блокируется, plist живого агента цел.
    """
    monkeypatch.setattr(install_lib, "_BOOTOUT_POLL_INTERVAL", 0)
    env = _env(tmp_path)
    item = _mismatch_item(env, plist_label="com.srouter.dashboard",
                          item_label="com.srouter.stale")
    live_plist = Path(item["plist_path"])
    # Подменим plan['launchagent'] через detected, дающий рассинхрон item — но _launchagent_uninstall_item
    # всегда ставит path=launchagent_path(). Поэтому тестируем границу напрямую через apply_uninstall,
    # monkeypatch'ив build_uninstall_plan чтобы вернуть наш mismatched item.
    plan = install_lib.build_uninstall_plan(env=env)
    plan["launchagent"] = item
    monkeypatch.setattr(install_lib, "build_uninstall_plan", lambda **kw: plan)
    runner = ListRunner(list_states=[False])  # bootout stale → rc113 → «выгружен»

    result = install_lib.apply_uninstall(env=env, confirmations={"launchagent": True}, runner=runner)

    assert result["ok"] is False, "mismatch блокирует uninstall (fail-closed)"
    assert "launchagent_identity_mismatch" in (result.get("blocked") or []), \
        f"blocked идентифицирует identity-mismatch: {result.get('blocked')}"
    assert live_plist.exists(), "ЖИВОЙ dashboard.plist НЕ удалён при state-drift"
