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
        if key in self.responses:
            return self.responses[key]
        # `launchctl print <domain>/<label>` по умолчанию → rc=113 (service-not-found = НЕ загружен):
        # в install-окружении реальный агент не поднят. Иначе default rc=0 читался бы как «загружен»
        # → poll _launchd_unload крутил бы полный settle (домен-осознанная проверка, cycle-review #93).
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


# ============================ issue #110 Дефект 2: stale-managed = reclaimable (не foreign) ============================
# install через _inspect_component считает компонент foreign ТОЛЬКО по маркеру в файле (стр.386):
#   managed = config_path.exists() and _has_marker(config_path)
# State-память (detected_environment[name].management.managed, которую сам install пишет через
# _write_state_after_apply) ИГНОРИРУЕТСЯ. Поэтому «свой старый» конфиг (install ставил → state.managed=True,
# но маркер пропал при смене версии/правке) = foreign_config → конфликт → non-TTY install падает rc=2 сразу
# после uninstall. Корень #110: двойное определение managed (uninstall верит state, install верит файлу).
#
# Фикс: _inspect_component получает явный параметр prior_detected, отличает reclaimable (state.managed=True,
# маркера нет — «свой старый», авторазрешается с backup) от foreign (нет ни маркера, ни state).
# mode:"restored" — легально возвращённый uninstall'ом чужой → НЕ reclaimable (остаётся foreign).
def _write_config_without_marker(env, name, content="foreign config\n"):
    """Конфиг БЕЗ srouter-маркера (как «свой старый» после потери маркера, или истинно чужой)."""
    config_path = env.component_paths(name)["config"]
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(content, encoding="utf-8")
    return config_path


def _detected(env, name, *, mode, managed):
    """detected_environment-entry как его пишет install/uninstall (management.mode + managed)."""
    return {
        name: {
            "config_path": str(env.component_paths(name)["config"]),
            "management": {"mode": mode, "managed": managed},
        }
    }


def test_inspect_component_reclaimable_when_state_managed_but_no_marker(tmp_path):
    """Дефект 2: state mode=managed/managed=True, маркер пропал → reclaimable=True, НЕ foreign, НЕ conflict.

    На СТАРОМ коде (стр.386 — только маркер) config без маркера = managed=False → foreign_config →
    conflict=True. Фикс: prior_detected подключён, state_managed=True → managed=True, reclaimable=True.
    Тест падает TypeError (нет параметра prior_detected) → потом assert (не foreign) → потом зелёный.
    """
    env = _env(tmp_path)
    _write_config_without_marker(env, "privoxy")
    detected = _detected(env, "privoxy", mode="managed", managed=True)

    item = install_lib._inspect_component(
        "privoxy", env, FakeRunner(), lambda *_a, **_kw: False, prior_detected=detected)

    assert item["reclaimable"] is True, "state.managed=True + нет маркера → «свой старый», reclaimable"
    assert "foreign_config" not in item["conflicts"], "reclaimable НЕ foreign_config"
    assert item["conflict"] is False, "reclaimable НЕ блокирует install"


def test_inspect_component_foreign_when_no_state_no_marker(tmp_path):
    """Граница: true-foreign (entry нет в state, маркера нет) → foreign_config, конфликт, НЕ reclaimable.

    «Чужой конфиг рядом» (srouter никогда не ставил) — это легитимное состояние, но для install это
    конфликт, требующий adopt/overwrite/skip. reclaimable=False — НЕ авторазрешается.
    """
    env = _env(tmp_path)
    _write_config_without_marker(env, "privoxy")

    item = install_lib._inspect_component(
        "privoxy", env, FakeRunner(), lambda *_a, **_kw: False, prior_detected={})

    assert item["reclaimable"] is False
    assert "foreign_config" in item["conflicts"]
    assert item["conflict"] is True


def test_inspect_component_restored_is_foreign_not_reclaimable(tmp_path):
    """mode=restored — легально возвращённый uninstall'ом чужой конфиг → НЕ reclaimable, остаётся foreign.

    Uninstall при restore кладёт бывший пользовательский конфиг (без маркера) обратно и пишет
    mode:'restored' (install_lib._mark_component_restored:888). Install НЕ должен молча перезаписать
    его как «свой старый» — restored = чужой, требует явного решения. Только mode=managed даёт reclaimable.
    """
    env = _env(tmp_path)
    _write_config_without_marker(env, "privoxy")
    detected = _detected(env, "privoxy", mode="restored", managed=False)

    item = install_lib._inspect_component(
        "privoxy", env, FakeRunner(), lambda *_a, **_kw: False, prior_detected=detected)

    assert item["reclaimable"] is False, "restored = легальный чужой, НЕ reclaimable"
    assert "foreign_config" in item["conflicts"], "restored остаётся foreign (требует явного решения)"


def test_apply_install_reclaimable_creates_backup_then_overwrites(tmp_path):
    """Дефект 2 ядро: reclaimable → backup создаётся (старый конфиг сохранён), конфиг перезаписан с маркером.

    КРИТИЧНО (находка Plan-агента): просто убрать conflict для state-managed — недостаточно. apply_install
    (стр.700) делает backup ТОЛЬКО при choice=='overwrite'. Без явного backup reclaimable перезапишется
    БЕЗ бэкапа → молчаливая потеря, если state устарел (под «своим старым» чужой). Фикс: reclaimable
    ВСЕГДА получает backup (needs_backup = overwrite OR reclaimable), затем перезапись с маркером.
    """
    env = _env(tmp_path)
    config_path = _write_config_without_marker(env, "privoxy", content="my old managed config\n")
    env.state_path.write_text(
        json.dumps({
            "schema_version": 1, "nodes": [], "active_node": {"name": None, "pending": None},
            "probes": {}, "network": {"channels": {"wifi_service": "Wi-Fi"}},
            "traffic_guard": {"mode": "off", "domains": {}},
            "detected_environment": _detected(env, "privoxy", mode="managed", managed=True),
            "runtime": {},
        }),
        encoding="utf-8")

    result = install_lib.apply_install(
        env=env, confirm=True, choices={"xray": "skip", "dnsmasq": "skip"},
        runner=FakeRunner(), port_checker=lambda *_a, **_kw: False)

    assert result["ok"] is True, f"reclaimable авторазрешается (с backup), не блокирует: {result}"
    # Старый конфиг сохранён в backup (.srouter-backup-*).
    backups = list(config_path.parent.glob("config.srouter-backup-*"))
    assert backups, "reclaimable ВСЕГДА создаёт backup перед перезаписью (канон fail-closed)"
    assert backups[0].read_text(encoding="utf-8") == "my old managed config\n", "backup = прежний конфиг"
    # Новый конфиг имеет srouter-маркер (перезаписан как managed).
    assert install_lib.MARKER in config_path.read_text(encoding="utf-8"), "конфиг перезаписан с маркером"


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
        # print (для _launchd_is_loaded / poll) → rc=113 (service-not-found = не загружен, выгрузился
        # сразу). Домен-осознанная проверка через `launchctl print` (cycle-review #93).
        if sub == "print":
            return {"rc": 113, "out": "", "err": "Could not find service", "timeout": False}
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


# ============================ cycle-review #111 cycle 1: adversarial findings (Codex) ============================
# Два finding от Codex adversarial review (confidence 0.99), оба реальны. Чиним через ТДД.

# Finding 1 (HIGH): persisted ownership НЕ привязан к записанному config_path.
# _inspect_component давал reclaimable по state.managed=True, не сравнивая prior["config_path"] с текущим
# config_path. Сценарий: смена --prefix (напр. /opt/homebrew → /usr/local) → state от старого prefix
# делает чужой markerless-конфиг по НОВОМУ пути reclaimable → install молча перезаписывает его (даже с
# backup — service disruption) без adopt/overwrite/skip. Фикс: reclaimable только при совпадении путей.
def test_inspect_component_reclaimable_requires_matching_config_path(tmp_path):
    """Finding 1: state.managed=True, НО config_path в state ≠ текущий → НЕ reclaimable (foreign).

    Смена prefix: state хранит старый путь, текущий config_path — новый. Чужой конфиг по новому пути
    НЕ должен стать «своим старым» только по записи state.managed. Привязка ownership к совпадению пути.
    """
    env = _env(tmp_path)
    _write_config_without_marker(env, "privoxy")
    # state хранит ДРУГОЙ config_path (как при смене prefix — старое расположение).
    detected = {"privoxy": {
        "config_path": str(tmp_path / "old-prefix" / "privoxy" / "config"),
        "management": {"mode": "managed", "managed": True},
    }}

    item = install_lib._inspect_component(
        "privoxy", env, FakeRunner(), lambda *_a, **_kw: False, prior_detected=detected)

    assert item["reclaimable"] is False, "state от ДРУГОГО пути не авторизует reclaimable"
    assert "foreign_config" in item["conflicts"], "несовпадение пути → foreign (требует явного выбора)"


# Finding 2 (MEDIUM): reclaimable подавляет НЕ связанные conflict-типы (non_brew_binary).
# unresolved-блок exempted ВЕСЬ компонент при reclaimable, хотя reclaimable computed независимо от
# conflicts. Сценарий: stale-managed компонент + рядом чужой non-Homebrew бинарник → non_brew_binary
# молча поглощён → install/restart brew-сервиса при живом чужом бинарнике → конкуренция/падение.
# Фикс: reclaimable авто-разрешает ТОЛЬКО foreign_config/foreign_port, не non_brew_binary.
def test_inspect_component_non_brew_binary_blocks_even_when_reclaimable(tmp_path, monkeypatch):
    """Finding 2 (downstream): reclaimable + non_brew_binary → apply_install ДОЛЖЕН блокировать.

    В _inspect_component reclaimable-компонент с non_brew_binary правильно остаётся conflict=True
    (foreign_config/foreign_port погашены managed, но non_brew_binary добавлен отдельно). Дыра — в
    downstream-фильтрах (apply_install unresolved, cmd_install interactive): `conflict and not
    reclaimable` exempted ВЕСЬ компонент, поглощая non_brew_binary. Сценарий: чужой non-Homebrew
    бинарник рядом со stale-managed конфигом → install молча ставит brew-сервис → конкуренция/падение.
    Фикс: exempted только если ЕДИНСТВЕННЫЕ конфликты — foreign_config/foreign_port (покрыты reclaimable).
    """
    env = _env(tmp_path)
    config_path = _write_config_without_marker(env, "privoxy")
    env.state_path.write_text(
        json.dumps({
            "schema_version": 1, "nodes": [], "active_node": {"name": None, "pending": None},
            "probes": {}, "network": {"channels": {"wifi_service": "Wi-Fi"}},
            "traffic_guard": {"mode": "off", "domains": {}},
            "detected_environment": _detected(env, "privoxy", mode="managed", managed=True),
            "runtime": {},
        }),
        encoding="utf-8")
    # non_brew_binary: подменяем component_paths → существующий чужой non-Homebrew бинарник.
    fake_non_brew = tmp_path / "foreign-bin" / "privoxy"
    fake_non_brew.parent.mkdir(parents=True)
    fake_non_brew.write_text("#!/bin/sh\n", encoding="utf-8")
    original_paths = env.component_paths

    def paths_with_non_brew(name):
        paths = dict(original_paths(name))
        paths["non_brew"] = [fake_non_brew]
        return paths

    monkeypatch.setattr(env, "component_paths", paths_with_non_brew)

    result = install_lib.apply_install(
        env=env, confirm=True, choices={"xray": "skip", "dnsmasq": "skip"},
        runner=FakeRunner(), port_checker=lambda *_a, **_kw: False)

    # reclaimable НЕ должен авторазрешать компонент с non_brew_binary — отдельная угроза требует решения.
    assert result["ok"] is False, ("non_brew_binary при reclaimable НЕ должен авто-разрешаться: "
                                   "install должен блокировать и требовать явного решения")
    assert "privoxy" in result["blocked"], "privoxy в blocked (non_brew_binary не поглощён reclaimable)"


def test_inspect_component_foreign_port_blocks_even_when_reclaimable(tmp_path, monkeypatch):
    """cycle-review #111 cycle 2 finding D: reclaimable НЕ должен гасить foreign_port.

    reclaimable-компонент (state managed, маркер пропал) с ЧУЖИМ процессом на порту: `if owner and not
    managed` НЕ добавляет foreign_port (managed=True от state). Значит reclaimable молча авто-применяется
    при живом чужом процессе → brew restart поверх чужого → конкуренция/падение. Симметрично finding 2
    (non_brew_binary), но про port. Фикс: foreign_port добавляется при чужом owner даже для stale-managed
    (маркера нет → мы не уверены, что слушатель наш).
    """
    env = _env(tmp_path)
    config_path = _write_config_without_marker(env, "privoxy")
    detected = _detected(env, "privoxy", mode="managed", managed=True)
    # Чужой процесс на порту 8118: _port_owner зовёт lsof, возвращаем чужой вывод.
    lsof_out = "COMMAND PID USER FD TYPE DEVICE NODE NAME\nforeignd 999 me 5u IPv4 0t0 TCP 127.0.0.1:8118 (LISTEN)\n"
    runner = FakeRunner({(install_lib.LSOF, "-nP", "-iTCP:8118", "-sTCP:LISTEN"):
                         {"rc": 0, "out": lsof_out, "err": "", "timeout": False}})

    item = install_lib._inspect_component(
        "privoxy", env, runner, lambda *_a, **_kw: True, prior_detected=detected)

    assert item["reclaimable"] is True, "stale-managed → reclaimable"
    assert "foreign_port" in item["conflicts"], ("чужой процесс на порту → foreign_port, даже при "
                                                 "reclaimable (маркера нет → слушатель может быть чужим)")
    assert item["conflict"] is True, "foreign_port блокирует reclaimable (не авто-применение при чужом процессе)"
