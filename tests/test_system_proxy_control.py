"""TDD: explicit macOS SOCKS repair/restore for normal ChatGPT.app Dock launches."""
import fcntl
import json
import os
import threading

from types import SimpleNamespace

import local_state
import system_proxy_control


ROUTE_EN0 = "   route to: default\n  interface: en0\n"
SERVICE_ORDER = """An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)
(2) iPhone USB
(Hardware Port: iPhone USB, Device: en8)
"""


class ProxyRunner:
    def __init__(self, *, enabled=False, server="127.0.0.1", port=10808,
                 authenticated=False, fail_on=None):
        self.enabled = enabled
        self.server = server
        self.port = port
        self.authenticated = authenticated
        self.fail_on = fail_on
        self.calls = []

    def mutations(self):
        return [c for c in self.calls if len(c) > 1 and c[1].startswith("-set")]

    def __call__(self, cmd, timeout):
        self.calls.append(list(cmd))
        if self.fail_on and cmd[1] == self.fail_on:
            return {"rc": 1, "out": "", "err": "forced failure", "timeout": False}
        if cmd == [system_proxy_control.ROUTE, "-n", "get", "default"]:
            return {"rc": 0, "out": ROUTE_EN0, "err": "", "timeout": False}
        if cmd[1:] == ["-listnetworkserviceorder"]:
            return {"rc": 0, "out": SERVICE_ORDER, "err": "", "timeout": False}
        if cmd[1:3] == ["-getsocksfirewallproxy", "Wi-Fi"]:
            out = (f"Enabled: {'Yes' if self.enabled else 'No'}\n"
                   f"Server: {self.server}\nPort: {self.port}\n"
                   f"Authenticated Proxy Enabled: {1 if self.authenticated else 0}\n")
            return {"rc": 0, "out": out, "err": "", "timeout": False}
        if cmd[1:3] == ["-setsocksfirewallproxystate", "Wi-Fi"]:
            self.enabled = cmd[3] == "on"
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        if cmd[1:3] == ["-setsocksfirewallproxy", "Wi-Fi"]:
            self.server, self.port = cmd[3], int(cmd[4])
            self.authenticated = False
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        return {"rc": 1, "out": "", "err": f"unexpected: {cmd}", "timeout": False}


def _args(tmp_path, action):
    return SimpleNamespace(system_proxy_action=action, state=str(tmp_path / "state.json"))


ROUTE_EN1 = "   route to: default\n  interface: en1\n"
SERVICE_ORDER_EN1_EN10 = """An asterisk (*) denotes that a network service is disabled.
(1) USB 10G LAN
(Hardware Port: USB 10G LAN, Device: en10)
(2) Thunderbolt Ethernet
(Hardware Port: Thunderbolt Ethernet, Device: en1)
"""


def test_service_for_interface_does_not_substring_match_en1_into_en10():
    """codex-review (Codex rescue, PR #314): _service_for_interface матчит `Device: {iface}` подстрокой
    — default interface 'en1' матчит и строку 'Device: en10)', если en10 идёт РАНЬШЕ en1 в service order.
    repair() тогда мутирует SOCKS не того адаптера (en10, не активный en1) — привилегированная операция
    на неверном канале, живой канал остаётся без прокси, а лог заявляет успех.
    """
    def runner(cmd, timeout):
        if cmd == [system_proxy_control.ROUTE, "-n", "get", "default"]:
            return {"rc": 0, "out": ROUTE_EN1, "err": "", "timeout": False}
        if cmd[1:] == ["-listnetworkserviceorder"]:
            return {"rc": 0, "out": SERVICE_ORDER_EN1_EN10, "err": "", "timeout": False}
        return {"rc": 1, "out": "", "err": f"unexpected: {cmd}", "timeout": False}

    service = system_proxy_control._service_for_interface("en1", runner)
    assert service == "Thunderbolt Ethernet", (
        f"'en1' должен матчить ТОЛЬКО точный Device: en1, не 'en10' по substring; got {service!r}"
    )


def test_status_resolves_active_service_from_default_interface():
    runner = ProxyRunner(enabled=False)
    st = system_proxy_control.status(runner=runner)
    assert st["status"] == "ok"
    assert st["interface"] == "en0"
    assert st["service"] == "Wi-Fi"
    assert st["socks"] == {
        "enabled": False, "server": "127.0.0.1", "port": 10808, "authenticated": False,
    }
    assert st["target"] is False


def test_repair_enables_existing_target_without_install_or_app_restart(tmp_path):
    runner = ProxyRunner(enabled=False)
    res = system_proxy_control.repair(path=tmp_path / "state.json", runner=runner)
    assert res["ok"] is True
    assert runner.enabled is True
    mutations = [c for c in runner.calls if c[1].startswith("-set")]
    assert mutations == [[system_proxy_control.NETWORKSETUP,
                          "-setsocksfirewallproxystate", "Wi-Fi", "on"]]
    saved = local_state.load_state(tmp_path / "state.json")["runtime"]["system_proxy"]
    assert saved["leases"]["Wi-Fi"]["previous"]["enabled"] is False  # leases-формат (#316)


def test_repair_backs_up_disabled_foreign_endpoint_then_sets_target(tmp_path):
    runner = ProxyRunner(enabled=False, server="old.proxy", port=1080)
    res = system_proxy_control.repair(path=tmp_path / "state.json", runner=runner)
    assert res["ok"] is True
    assert (runner.server, runner.port, runner.enabled) == ("127.0.0.1", 10808, True)
    active = local_state.load_state(tmp_path / "state.json")["runtime"]["system_proxy"]["leases"]["Wi-Fi"]
    assert active["previous"]["server"] == "old.proxy"
    assert active["previous"]["port"] == 1080


def test_repair_refuses_enabled_foreign_proxy_without_mutation(tmp_path):
    runner = ProxyRunner(enabled=True, server="corp.proxy", port=1080)
    res = system_proxy_control.repair(path=tmp_path / "state.json", runner=runner)
    assert res["ok"] is False
    assert res["conflict"] is True
    assert not [c for c in runner.calls if c[1].startswith("-set")]


def test_repair_refuses_authenticated_proxy_without_mutation(tmp_path):
    runner = ProxyRunner(enabled=False, server="corp.proxy", port=1080, authenticated=True)
    res = system_proxy_control.repair(path=tmp_path / "state.json", runner=runner)
    assert res["ok"] is False
    assert not [c for c in runner.calls if c[1].startswith("-set")]


def test_repair_rolls_back_endpoint_when_enable_fails(tmp_path):
    runner = ProxyRunner(enabled=False, server="old.proxy", port=1080,
                         fail_on="-setsocksfirewallproxystate")
    res = system_proxy_control.repair(path=tmp_path / "state.json", runner=runner)
    assert res["ok"] is False
    assert (runner.server, runner.port, runner.enabled) == ("old.proxy", 1080, False)
    saved = local_state.load_state(tmp_path / "state.json")["runtime"]["system_proxy"]
    assert saved["leases"] == {}  # успешный rollback => pending расчищен (restore-инвариант #316)


def test_restore_returns_previous_state_and_clears_lease(tmp_path):
    runner = ProxyRunner(enabled=False, server="old.proxy", port=1080)
    assert system_proxy_control.repair(path=tmp_path / "state.json", runner=runner)["ok"]
    res = system_proxy_control.restore(path=tmp_path / "state.json", runner=runner)
    assert res["ok"] is True
    assert (runner.server, runner.port, runner.enabled) == ("old.proxy", 1080, False)
    saved = local_state.load_state(tmp_path / "state.json")["runtime"]["system_proxy"]
    assert saved["leases"] == {}  # restore расчистил lease


def test_restore_refuses_external_drift(tmp_path):
    runner = ProxyRunner(enabled=False)
    assert system_proxy_control.repair(path=tmp_path / "state.json", runner=runner)["ok"]
    runner.server = "changed.externally"
    res = system_proxy_control.restore(path=tmp_path / "state.json", runner=runner)
    assert res["ok"] is False
    assert res["conflict"] is True
    assert runner.server == "changed.externally"


def test_repair_fails_closed_when_active_service_unresolved(tmp_path):
    runner = ProxyRunner()

    def no_route(cmd, timeout):
        if cmd[0] == system_proxy_control.ROUTE:
            return {"rc": 1, "out": "", "err": "no route", "timeout": False}
        return runner(cmd, timeout)

    res = system_proxy_control.repair(path=tmp_path / "state.json", runner=no_route)
    assert res["ok"] is False
    assert not [c for c in runner.calls if len(c) > 1 and c[1].startswith("-set")]


# ==========================================================================
# issue #316: atomicity/durability lease (4 находки cycle-review #314)
# ==========================================================================

CORP_PREVIOUS = {"enabled": False, "server": "corp.proxy", "port": 1080, "authenticated": False}

SERVICE_ORDER_TWO = """An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)
(2) Thunderbolt Ethernet
(Hardware Port: Thunderbolt Ethernet, Device: en1)
"""


def _seed_sp(path, section):
    """Записать runtime.system_proxy напрямую (новый leases- или legacy active-формат)."""
    state = local_state.load_state(path)
    state.setdefault("runtime", {})["system_proxy"] = section
    assert local_state.save_state(state, path) is not None


def _sp_section(path):
    return local_state.load_state(path)["runtime"]["system_proxy"]


class MultiServiceRunner:
    """Два network service с независимым SOCKS-состоянием (находка 3, сценарий B:
    Wi-Fi <-> Ethernet между вызовами repair). Активный интерфейс переключается на лету."""

    def __init__(self, *, default_iface="en0"):
        self.default_iface = default_iface
        self.socks = {
            "Wi-Fi": {"enabled": False, "server": "old.proxy", "port": 1080, "authenticated": False},
            "Thunderbolt Ethernet": {"enabled": False, "server": "", "port": None,
                                     "authenticated": False},
        }
        self.calls = []
        self.fail_on = None

    def set_default_iface(self, iface):
        self.default_iface = iface

    def mutations(self):
        return [c for c in self.calls if len(c) > 1 and c[1].startswith("-set")]

    def __call__(self, cmd, timeout):
        self.calls.append(list(cmd))
        if self.fail_on and len(cmd) > 1 and cmd[1] == self.fail_on:
            return {"rc": 1, "out": "", "err": "forced failure", "timeout": False}
        if cmd == [system_proxy_control.ROUTE, "-n", "get", "default"]:
            return {"rc": 0, "out": f"   route to: default\n  interface: {self.default_iface}\n",
                    "err": "", "timeout": False}
        if cmd[1:] == ["-listnetworkserviceorder"]:
            return {"rc": 0, "out": SERVICE_ORDER_TWO, "err": "", "timeout": False}
        if len(cmd) > 2 and cmd[1] in ("-getsocksfirewallproxy", "-setsocksfirewallproxy",
                                       "-setsocksfirewallproxystate"):
            service = cmd[2]
            if service not in self.socks:
                return {"rc": 1, "out": "", "err": f"unknown service {service}", "timeout": False}
            s = self.socks[service]
            if cmd[1] == "-getsocksfirewallproxy":
                out = (f"Enabled: {'Yes' if s['enabled'] else 'No'}\nServer: {s['server']}\n"
                       f"Port: {s['port']}\n"
                       f"Authenticated Proxy Enabled: {1 if s['authenticated'] else 0}\n")
                return {"rc": 0, "out": out, "err": "", "timeout": False}
            if cmd[1] == "-setsocksfirewallproxystate":
                s["enabled"] = cmd[3] == "on"
                return {"rc": 0, "out": "", "err": "", "timeout": False}
            s["server"], s["port"] = cmd[3], int(cmd[4])
            s["authenticated"] = False
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        return {"rc": 1, "out": "", "err": f"unexpected: {cmd}", "timeout": False}


# --- Находка 1: backup сохраняется ПОСЛЕ мутации; возврат _save_lease игнорируется ---


def test_repair_persists_previous_before_first_mutation(tmp_path):
    """#316-1 (write-preflight): backup предыдущего endpoint обязан быть на диске ДО первой
    networksetup-мутации. Иначе SIGKILL/ENOSPC между мутацией и записью lease = система
    изменена, backup прежнего прокси нигде не сохранён, restore никогда не сработает."""
    state_file = tmp_path / "state.json"
    runner = ProxyRunner(enabled=False, server="old.proxy", port=1080)

    def spying(cmd, timeout):
        if len(cmd) > 2 and cmd[1] == "-setsocksfirewallproxy" and cmd[2] == "Wi-Fi":
            data = json.loads(state_file.read_text())  # момент ПЕРЕД первой мутацией
            return_plain = data["runtime"]["system_proxy"]["leases"]["Wi-Fi"]["previous"]
            assert return_plain["server"] == "old.proxy", (
                "backup previous обязан быть записан на диск ДО первой мутации (write-preflight)")
        return runner(cmd, timeout)

    res = system_proxy_control.repair(path=state_file, runner=spying)
    assert res["ok"] is True
    lease = _sp_section(state_file)["leases"]["Wi-Fi"]
    assert lease["previous"]["server"] == "old.proxy"


def test_repair_refuses_when_state_unwritable_before_any_mutation(tmp_path):
    """#316-1: сбой записи lease был проглочен (_save_lease -> False игнорировался) — repair
    применял мутацию без backup и возвращал ok=True. Теперь отказ ДО любой мутации."""
    state_dir = tmp_path / "state.json"
    state_dir.mkdir()  # каталог: load_state_checked -> readable=False
    runner = ProxyRunner(enabled=False, server="old.proxy", port=1080)
    res = system_proxy_control.repair(path=state_dir, runner=runner)
    assert res["ok"] is False
    assert not [c for c in runner.calls if c[1].startswith("-set")], (
        "недоказуемый backup = ноль мутаций (fail-closed)")


def test_repair_crash_after_enable_recovers_on_next_repair(tmp_path):
    """#316-1 (SIGKILL-инъекция): crash между последней мутацией и promote — на диске остаётся
    repairing-lease с НАСТОЯЩИМ previous. Следующий repair подтверждает lease в active и НЕ
    перезаписывает previous нашим endpoint'ом; restore после этого возвращает чужой прокси."""
    state_file = tmp_path / "state.json"
    _seed_sp(state_file, {"leases": {"Wi-Fi": {
        "phase": "repairing", "service": "Wi-Fi", "previous": dict(CORP_PREVIOUS)}}})
    runner = ProxyRunner(enabled=False, server="127.0.0.1", port=10808)  # target, выключен
    res = system_proxy_control.repair(path=state_file, runner=runner)
    assert res["ok"] is True
    lease = _sp_section(state_file)["leases"]["Wi-Fi"]
    assert lease["phase"] == "active"
    assert lease["previous"] == CORP_PREVIOUS, "stale pending не должен затираться нашим endpoint'ом"
    res = system_proxy_control.restore(path=state_file, runner=runner)
    assert res["ok"] is True
    assert (runner.server, runner.port, runner.enabled) == ("corp.proxy", 1080, False)


def test_repair_stale_pending_dropped_when_system_moved_on(tmp_path):
    """#316-1: repairing-lease остался, а система НЕ содержит нашего endpoint (crash до первой
    мутации или внешний откат) — stale pending сбрасывается, repair работает как обычно со
    свежим backup реального pre-repair состояния."""
    state_file = tmp_path / "state.json"
    _seed_sp(state_file, {"leases": {"Wi-Fi": {
        "phase": "repairing", "service": "Wi-Fi", "previous": dict(CORP_PREVIOUS)}}})
    runner = ProxyRunner(enabled=False, server="other.proxy", port=3128)
    res = system_proxy_control.repair(path=state_file, runner=runner)
    assert res["ok"] is True
    lease = _sp_section(state_file)["leases"]["Wi-Fi"]
    assert lease["previous"]["server"] == "other.proxy"
    assert (runner.server, runner.port) == ("127.0.0.1", 10808)


# --- Находка 2: restore меняет endpoint раньше, чем выключает канал ---


def test_restore_disables_channel_before_touching_endpoint(tmp_path):
    """#316-2 (off-first): restore обязан СНАЧАЛА выключить канал, потом менять endpoint, затем
    восстанавливать state по previous.enabled. Выключенный канал с любым endpoint не может
    направить трафик ОС на чужой прокси (канон fail-closed-proxy-down)."""
    runner = ProxyRunner(enabled=False, server="old.proxy", port=1080)
    state_file = tmp_path / "state.json"
    assert system_proxy_control.repair(path=state_file, runner=runner)["ok"]
    order = []

    def spying(cmd, timeout):
        if len(cmd) > 1 and cmd[1].startswith("-set"):
            order.append(cmd[1])
        return runner(cmd, timeout)

    res = system_proxy_control.restore(path=state_file, runner=spying)
    assert res["ok"] is True
    assert order == ["-setsocksfirewallproxystate", "-setsocksfirewallproxy",
                     "-setsocksfirewallproxystate"]


def test_restore_endpoint_failure_never_leaves_foreign_endpoint_enabled(tmp_path):
    """#316-2 сценарий отказа: запись endpoint падает (например, отменён admin-диалог) — при
    off-first канал УЖЕ выключен, чужой endpoint не может остаться ВКЛЮЧЁННЫМ на системном
    уровне; lease не расчищен — retry дочитывает."""
    runner = ProxyRunner(enabled=False, server="old.proxy", port=1080)
    state_file = tmp_path / "state.json"
    assert system_proxy_control.repair(path=state_file, runner=runner)["ok"]
    runner.fail_on = "-setsocksfirewallproxy"
    res = system_proxy_control.restore(path=state_file, runner=runner)
    assert res["ok"] is False
    assert runner.enabled is False, (
        "чужой/непроверенный endpoint не имеет права остаться включённым после сбоя restore")
    assert _sp_section(state_file)["leases"]["Wi-Fi"]["phase"] == "restoring"


def test_restore_resumes_after_crash_mid_restore(tmp_path):
    """#316-2 (SIGKILL-инъекция): crash в restore после off+endpoint, до финального state —
    backup НЕ теряется и не залипает в conflict: следующий restore дочитывает финальный state
    по previous.enabled и расчищает lease."""
    state_file = tmp_path / "state.json"
    previous = {"enabled": True, "server": "corp.proxy", "port": 1080, "authenticated": False}
    _seed_sp(state_file, {"leases": {"Wi-Fi": {
        "phase": "restoring", "service": "Wi-Fi", "previous": previous}}})
    # Система: endpoint уже вернули на corp.proxy, канал off (crash перед финальным state on).
    runner = ProxyRunner(enabled=False, server="corp.proxy", port=1080)
    res = system_proxy_control.restore(path=state_file, runner=runner)
    assert res["ok"] is True
    assert runner.enabled is True
    assert "Wi-Fi" not in _sp_section(state_file)["leases"]


def test_restore_clears_lease_when_already_fully_restored(tmp_path):
    """#316-2: crash ПОСЛЕ последней мутации, до расчистки lease — следующий restore видит
    completed-состояние и чистит lease БЕЗ единой мутации (без залипания в conflict)."""
    state_file = tmp_path / "state.json"
    previous = {"enabled": True, "server": "corp.proxy", "port": 1080, "authenticated": False}
    _seed_sp(state_file, {"leases": {"Wi-Fi": {
        "phase": "restoring", "service": "Wi-Fi", "previous": previous}}})
    runner = ProxyRunner(enabled=True, server="corp.proxy", port=1080)
    res = system_proxy_control.restore(path=state_file, runner=runner)
    assert res["ok"] is True
    assert not runner.mutations()
    assert "Wi-Fi" not in _sp_section(state_file)["leases"]


# --- Находка 3: повторный repair затирает backup первого чужого прокси ---


def test_repair_enable_branch_keeps_existing_backup(tmp_path):
    """#316-3 сценарий A: повторный repair при нашем endpoint (ветка включения канала) НЕ имеет
    права перезаписывать существующий lease — иначе corp.proxy backup теряется навсегда."""
    state_file = tmp_path / "state.json"
    _seed_sp(state_file, {"leases": {"Wi-Fi": {
        "phase": "active", "service": "Wi-Fi", "previous": dict(CORP_PREVIOUS)}}})
    runner = ProxyRunner(enabled=False)  # наш endpoint, канал выключен
    res = system_proxy_control.repair(path=state_file, runner=runner)
    assert res["ok"] is True
    assert runner.enabled is True
    lease = _sp_section(state_file)["leases"]["Wi-Fi"]
    assert lease["previous"] == CORP_PREVIOUS, (
        "чужой backup пользователя неприкосновенен (канон rollback-byte-exact)")


def test_per_service_leases_survive_wifi_ethernet_switch(tmp_path):
    """#316-3 сценарий B: repair на втором сервисе не затирает lease первого (per-service
    leases); restore возвращает ОБА сервиса и чистит оба lease."""
    runner = MultiServiceRunner(default_iface="en0")
    state_file = tmp_path / "state.json"
    assert system_proxy_control.repair(path=state_file, runner=runner)["ok"]
    runner.set_default_iface("en1")
    runner.socks["Thunderbolt Ethernet"] = {
        "enabled": False, "server": "eth.proxy", "port": 3128, "authenticated": False}
    assert system_proxy_control.repair(path=state_file, runner=runner)["ok"]
    leases = _sp_section(state_file)["leases"]
    assert leases["Wi-Fi"]["previous"]["server"] == "old.proxy"
    assert leases["Thunderbolt Ethernet"]["previous"]["server"] == "eth.proxy"
    res = system_proxy_control.restore(path=state_file, runner=runner)
    assert res["ok"] is True
    assert (runner.socks["Wi-Fi"]["server"], runner.socks["Wi-Fi"]["enabled"]) == ("old.proxy", False)
    assert (runner.socks["Thunderbolt Ethernet"]["server"],
            runner.socks["Thunderbolt Ethernet"]["enabled"]) == ("eth.proxy", False)
    assert _sp_section(state_file)["leases"] == {}


def test_legacy_single_slot_lease_migrates_on_restore(tmp_path):
    """#316-3: миграция формата state с обратной совместимостью (прецедент #326): legacy
    {active: {...}} с дисков уже установленных машин восстанавливается, файл переписывается в
    leases-формат."""
    state_file = tmp_path / "state.json"
    _seed_sp(state_file, {"active": {"service": "Wi-Fi", "previous": dict(CORP_PREVIOUS)}})
    runner = ProxyRunner(enabled=True)  # наш target включён — как после старого repair
    res = system_proxy_control.restore(path=state_file, runner=runner)
    assert res["ok"] is True
    assert (runner.server, runner.port, runner.enabled) == ("corp.proxy", 1080, False)
    sp = _sp_section(state_file)
    assert sp["leases"] == {}
    assert "active" not in sp


# --- Находка 4: нет межпроцессной блокировки repair/restore ---


def test_repair_busy_lock_refuses_then_proceeds_after_release(tmp_path):
    """#316-4: чужой flock на state-lock файле -> вторая команда отказывает (busy) с нулём
    мутаций; после отпускания лока — проходит (bounded-wait, не мгновенный отказ)."""
    state_file = tmp_path / "state.json"
    lock_path = tmp_path / "state.json.system_proxy.lock"
    acquired = threading.Event()
    release = threading.Event()

    def holder():
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            acquired.set()
            release.wait(5)
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    t = threading.Thread(target=holder)
    t.start()
    assert acquired.wait(5)
    runner = ProxyRunner(enabled=False, server="old.proxy", port=1080)
    res = system_proxy_control.repair(path=state_file, runner=runner, lock_timeout=0.3)
    assert res["ok"] is False
    assert res.get("busy") is True
    assert not runner.mutations(), "busy = ноль networksetup-мутаций (иначе lost update lease)"
    release.set()
    t.join(5)
    res = system_proxy_control.repair(path=state_file, runner=runner, lock_timeout=10)
    assert res["ok"] is True


def test_restore_busy_lock_refuses_without_mutation(tmp_path):
    """#316-4: restore под чужим flock тоже отказывает без мутаций — сериализация нужна всей
    транзакции read->mutate->save, а не только записи state."""
    state_file = tmp_path / "state.json"
    lock_path = tmp_path / "state.json.system_proxy.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)  # держим из этого же процесса (flock per-file-description)
        # lease готовим напрямую в state — живой repair тоже под локом, seed надёжнее:
        _seed_sp(state_file, {"leases": {"Wi-Fi": {
            "phase": "active", "service": "Wi-Fi", "previous": dict(CORP_PREVIOUS)}}})
        runner2 = ProxyRunner(enabled=True)
        res = system_proxy_control.restore(path=state_file, runner=runner2, lock_timeout=0.3)
        assert res["ok"] is False
        assert res.get("busy") is True
        assert not runner2.mutations()
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


# --- cycle-review PR #334: раздельная диагностика busy vs недоступный лок ---


def test_lock_unavailable_is_not_reported_as_busy(tmp_path):
    """cycle-review #334 (1): lock-файл физически недоступен (родительский каталог занят
    регулярным файлом) — это НЕ 'чужая операция держит лок'. Диагностика обязана называть
    I/O-причину; busy остаётся только для реально удерживаемого flock."""
    blocker = tmp_path / "blocker"
    blocker.write_text("regular file, mkdir под ним невозможен")
    state_file = blocker / "state.json"
    runner = ProxyRunner(enabled=False, server="old.proxy", port=1080)
    res = system_proxy_control.repair(path=state_file, runner=runner, lock_timeout=0.3)
    assert res["ok"] is False
    assert res.get("busy") is not True, "I/O-сбой лока не имеет права маскироваться под busy"
    assert "недоступен" in res["err"] and "сериализация" in res["err"]
    assert not runner.mutations()

    runner2 = ProxyRunner(enabled=True)
    res = system_proxy_control.restore(path=state_file, runner=runner2, lock_timeout=0.3)
    assert res["ok"] is False
    assert res.get("busy") is not True
    assert not runner2.mutations()


# --- cycle-review PR #334 (2): мусорный/отрицательный lock-таймаут -> безопасный дефолт ---


def test_lock_timeout_invalid_falls_back_to_default(monkeypatch):
    """cycle-review #334 (2): отрицательный таймаут делал дедлайн 'уже просроченным' — мгновенный
    busy с нулевым ожиданием вместо честной работы. Канон more-options-better (эталон
    lock_hierarchy._default_timeout_sec): мусор -> безопасный дефолт; 0 = вечно — сохраняется."""
    spc = system_proxy_control
    assert spc._lock_timeout_sec(-1) == spc._LOCK_TIMEOUT_DEFAULT_SEC
    assert spc._lock_timeout_sec(-0.001) == spc._LOCK_TIMEOUT_DEFAULT_SEC
    assert spc._lock_timeout_sec(0) == 0
    assert spc._lock_timeout_sec(2.5) == 2.5
    monkeypatch.setenv("SROUTER_SYSTEM_PROXY_LOCK_TIMEOUT_SEC", "-5")
    assert spc._lock_timeout_sec(None) == spc._LOCK_TIMEOUT_DEFAULT_SEC
    monkeypatch.setenv("SROUTER_SYSTEM_PROXY_LOCK_TIMEOUT_SEC", "мусор")
    assert spc._lock_timeout_sec(None) == spc._LOCK_TIMEOUT_DEFAULT_SEC
    monkeypatch.setenv("SROUTER_SYSTEM_PROXY_LOCK_TIMEOUT_SEC", "7")
    assert spc._lock_timeout_sec(None) == 7.0

