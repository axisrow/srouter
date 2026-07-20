"""ТДД-тесты issue #115: privoxy падает из-за гонки рестартов за порт 8118.

Две дыры (по двум ПРИНЯТЫМ решениям):

РЕШЕНИЕ 1 (elliptic scope, вариант 1) — whitelist-инвариант:
  templates/privoxy.config (и его рендер) НИКОГДА не содержат директив, отсутствующих в
  privoxy 4.2.0. Чужой brew-sample НЕ трогаем (канон no-touch-чужого-без-маркера) — brew его
  перегенерит. Вместо этого whitelist известных директив ловит будущий regression: если кто-то
  добавит в шаблон feature-gated директиву (напр. elliptic-curve-keys — валидна ТОЛЬКО при
  FEATURE_HTTPS_INSPECTION, без неё privoxy 4.2.0 логирует "Ignoring unrecognized directive"
  и launchd KeepAlive может молотить рестарты на error-выхлопе).

РЕШЕНИЕ 2 (throttle locus, вариант 1) — stop→poll→start→poll в _restart_component:
  Слепой `brew services restart` заменён на stop → poll освобождения порта 8118 → start →
  poll поднятия 8118 с константами settle/timeout. Повторяет канонный эталон _launchd_reload
  (bootout→poll→bootstrap-retry). Гонка `Fatal: can't bind to 127.0.0.1:8118` исключена
  структурно: новый процесс стартует ТОЛЬКО после подтверждённого освобождения порта.

Канон always-tdd: тесты ПЕРВЫМИ (падают на дыре), потом фикс. verify-dont-guess: poll доказывает
состояние порта (через port_checker), не фиксированный sleep.
"""
from pathlib import Path

import install_lib


# ============================ РЕШЕНИЕ 1: whitelist директив privoxy 4.2.0 ============================

def test_privoxy_whitelist_covers_all_template_directives():
    """Каждая директива templates/privoxy.config должна быть в whitelist известных privoxy 4.2.0.

    Whitelist — строгий первоисточник (privoxy 4.2.0 user-manual, разделы 7.1-7.6 — БЕЗ 7.7
    HTTPS-Inspection, который feature-gated: elliptic-curve-keys/ca-directory/... валидны только
    при FEATURE_HTTPS_INSPECTION, без неё → "Ignoring unrecognized directive"). Ловит regression:
    кто-то добавит в шаблон директиву, которую базовая brew-сборка не распознаёт.
    """
    root = Path(__file__).resolve().parent.parent
    template = (root / "templates" / "privoxy.config").read_text(encoding="utf-8")
    directives = _config_directives(template)

    assert directives, "шаблон privoxy.config должен содержать хотя бы одну директиву"
    unknown = sorted(d for d in directives if d not in install_lib.PRIVOXY_KNOWN_DIRECTIVES)
    assert not unknown, f"шаблон privoxy.config содержит директивы не из whitelist privoxy 4.2.0: {unknown}"


def test_privoxy_whitelist_excludes_feature_gated_https_inspection_directives():
    """elliptic-curve-keys и прочие 7.7-директивы НЕ в whitelist — без FEATURE_HTTPS_INSPECTION
    privoxy 4.2.0 логирует "Ignoring unrecognized directive" (issue #115 симптом 1)."""
    feature_gated = {"elliptic-curve-keys", "ca-directory", "ca-cert-file", "ca-key-file",
                     "ca-password", "certificate-directory", "cipher-list", "trusted-cas-file"}
    leaked = sorted(feature_gated & install_lib.PRIVOXY_KNOWN_DIRECTIVES)
    assert not leaked, f"feature-gated HTTPS-Inspection директивы не должны быть в whitelist: {leaked}"


def test_privoxy_whitelist_includes_directives_used_by_template():
    """whitelist должен включать базовые директивы, которые реально нужны шаблону srouter
    (listen-address / toggle / enable-remote-toggle / enable-edit-actions / enforce-blocks /
    buffer-limit / forward-socks5t) — иначе валидный шаблон стал бы conflict'ом."""
    needed = {"listen-address", "toggle", "enable-remote-toggle", "enable-edit-actions",
              "enforce-blocks", "buffer-limit", "forward-socks5t"}
    missing = sorted(needed - install_lib.PRIVOXY_KNOWN_DIRECTIVES)
    assert not missing, f"whelist privoxy 4.2.0 не содержит нужных шаблону директив: {missing}"


def _config_directives(text):
    """Извлечь директивы (первое слово в каждой активной строке), пропуская комментарии/пустые."""
    directives = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        directives.add(stripped.split()[0])
    return directives


# ============================ РЕШЕНИЕ 2: stop→poll→start→poll в _restart_component ============================

class _PortProbe:
    """Фейк port_checker с запрограммированной последовательностью состояний порта.

    states: список bool последовательно — что возвращает port_open на каждый poll. Эмулирует
    «старый процесс ещё держит порт» (True→True→False при освобождении) или «новый поднимается
    с задержкой» (False→False→True после start). Записывает возвращённые значения в .results
    (для проверок «poll видел busy→free перед start») и вызовы в .calls.
    """
    def __init__(self, states):
        self._states = list(states)
        self._i = 0
        self.calls = []
        self.results = []

    def __call__(self, host, port, _timeout=0.5):
        self.calls.append((host, port))
        idx = min(self._i, len(self._states) - 1)
        self._i += 1
        val = self._states[idx]
        self.results.append(val)
        return val


class _PortProbeForApply:
    """Stateful port_checker для связки apply_install: build_plan тоже дёргает port_checker
    (для каждого компонента + probe_readiness), расходуя последовательность _PortProbe до restart.

    Поэтому probe «знает», когда стартовал целевой сервис: mark_started(name) переключает порт
    этого компонента в «поднят» (с опциональной задержкой). До start — порт свободен; после —
    поднимается. host:port→состояние; poll _restart_component видит реальную эволюцию порта
    вокруг stop/start.
    """
    def __init__(self, *, up_ports=None, busy_after_stop=None):
        self._up = set(up_ports or [])
        self._busy_after_stop = set(busy_after_stop or [])
        self.calls = []

    def mark_started(self, port):
        self._busy_after_stop.discard(port)
        self._up.add(port)

    def __call__(self, host, port, _timeout=0.5):
        self.calls.append((host, port))
        if port in self._up:
            return True
        if port in self._busy_after_stop:
            return True
        return False


def _make_services_runner(*, stop_rc=0, start_rc=0, restart_rc=0):
    """Фейк runner, различающий brew services подкоманды (stop/start/restart) по cmd[2].

    brew services вызовы идут как [BREW, "services", <sub>, <name>] (dnsmasq — с sudo спереди,
    поэтому индексируем cmd[2] надёжно и для sudo-варианта). Возвращает заданные rc для каждой подкоманды.
    """
    def runner(cmd, _timeout):
        # Найдём подкоманду services: cmd.index("services")+1
        sub = ""
        if "services" in cmd:
            idx = cmd.index("services")
            if idx + 1 < len(cmd):
                sub = cmd[idx + 1]
        if sub == "stop":
            return {"rc": stop_rc, "out": "", "err": "", "timeout": False}
        if sub == "start":
            return {"rc": start_rc, "out": "", "err": "", "timeout": False}
        if sub == "restart":
            return {"rc": restart_rc, "out": "", "err": "", "timeout": False}
        # brew list / brew install / lsof / launchctl — дефолт success.
        return {"rc": 0, "out": "", "err": "", "timeout": False}
    return runner


def test_restart_component_uses_stop_then_start_not_restart(monkeypatch):
    """_restart_component НЕ вызывает `brew services restart` (гонка за порт 8118, issue #115).

    Вместо этого — `brew services stop` → `brew services start`. На нелеченом коде тест падает:
    _restart_component дёргает единственный `restart`, без stop/start.
    """
    monkeypatch.setattr(install_lib, "_PORT_SETTLE_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_lib, "_PORT_SETTLE_MAX_WAIT", 0)
    monkeypatch.setattr(install_lib, "_PORT_UP_MAX_WAIT", 0)
    calls = []
    runner = _make_services_runner()
    base = runner

    def recording(cmd, timeout):
        calls.append(list(cmd))
        return base(cmd, timeout)

    res = install_lib._restart_component("privoxy", recording, port_checker=_PortProbe([False, True]))

    def _subs():
        out = []
        for c in calls:
            if "services" in c:
                idx = c.index("services")
                out.append(c[idx + 1] if idx + 1 < len(c) else "?")
        return out

    subs = _subs()
    assert "restart" not in subs, "_restart_component не должен использовать `brew services restart` (гонка за порт)"
    assert "stop" in subs and "start" in subs, "_restart_component должен делать stop→start"
    assert res.get("rc") == 0
    # Порядок: stop ДО start.
    assert subs.index("stop") < subs.index("start")


def test_restart_component_waits_for_port_release_before_start(monkeypatch):
    """ГОНКА: после stop порт ещё занят (старый процесс/TIME_WAIT держит 8118). start НЕ должен
    уходить, пока port_checker не подтвердит освобождение. Иначе `Fatal: can't bind to 8118`.

    Усиленный assertion (cycle-review #118 round 1): недостаточно «poll был» — нужно доказать, что
    poll-loop РЕАЛЬНО ждал перехода busy→free: среди poll'ов до start есть И True (видели занятость),
    И False (дождались освобождения). Мутация: если бы код делал один poll и шёл к start без ожидания
    — assert видел бы только [True] без False → падает.
    """
    monkeypatch.setattr(install_lib, "_PORT_SETTLE_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_lib, "_PORT_SETTLE_MAX_WAIT", 2.0)
    monkeypatch.setattr(install_lib, "_PORT_UP_MAX_WAIT", 0)
    # После stop порт: занят, занят, свободен (старый процесс отпускает с задержкой).
    probe = _PortProbe([True, True, False, True])
    polls_before_start = []

    def recording(cmd, timeout):
        # Фиксируем срез poll-результатов на момент вызова brew services start.
        if "services" in cmd and "start" in cmd[cmd.index("services"):]:
            polls_before_start.extend(probe.results)
        return runner(cmd, timeout)

    runner = _make_services_runner()
    install_lib._restart_component("privoxy", recording, port_checker=probe)

    # poll-loop РЕАЛЬНО ждал: видел busy (True), потом дождался free (False) — ДО start.
    assert True in polls_before_start, "poll должен был увидеть занятость порта (старый процесс держит)"
    assert False in polls_before_start, "poll должен был дождаться освобождения порта перед start"


def test_restart_component_fails_when_port_never_releases(monkeypatch):
    """После stop порт НИКОГДА не освобождается (висячий процесс) → fail, НЕ стартуем новый поверх
    (fail-closed: лучше сломать установку, чем запустить конкурирующий процесс → петля рестартов)."""
    monkeypatch.setattr(install_lib, "_PORT_SETTLE_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_lib, "_PORT_SETTLE_MAX_WAIT", 0)
    monkeypatch.setattr(install_lib, "_PORT_UP_MAX_WAIT", 0)
    probe = _PortProbe([True] * 10)  # порт вечно занят
    calls = []
    runner = _make_services_runner()

    def recording(cmd, timeout):
        calls.append(list(cmd))
        return runner(cmd, timeout)

    res = install_lib._restart_component("privoxy", recording, port_checker=probe)
    assert res.get("rc") != 0, "порт не освободился → restart должен провалиться (fail-closed)"
    # start НЕ вызывался (нечего поднимать поверх занятого порта).
    started = any("services" in c and "start" in c[c.index("services"):] for c in calls)
    assert not started, "start не должен вызываться, пока порт занят"


def test_restart_component_polls_port_up_after_start(monkeypatch):
    """После start порт должен подняться (с задержкой) — poll это доказывает. Если не поднялся за
    потолок → fail (verify-dont-guess: не фиксированный sleep, а подтверждение состояния порта)."""
    monkeypatch.setattr(install_lib, "_PORT_SETTLE_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_lib, "_PORT_SETTLE_MAX_WAIT", 0)
    monkeypatch.setattr(install_lib, "_PORT_UP_MAX_WAIT", 0)
    probe = _PortProbe([False, False])  # освобождается сразу, но после start НЕ поднимается
    calls = []
    runner = _make_services_runner()

    def recording(cmd, timeout):
        calls.append(list(cmd))
        return runner(cmd, timeout)

    res = install_lib._restart_component("privoxy", recording, port_checker=probe)
    assert res.get("rc") != 0, "порт не поднялся после start → restart должен провалиться"


def test_restart_component_success_when_stop_release_start_up(monkeypatch):
    """Happy path: stop ok → порт освобождается → start ok → порт поднимается → rc=0."""
    monkeypatch.setattr(install_lib, "_PORT_SETTLE_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_lib, "_PORT_SETTLE_MAX_WAIT", 0)
    monkeypatch.setattr(install_lib, "_PORT_UP_MAX_WAIT", 0)
    probe = _PortProbe([False, True])  # освобождается → поднимается
    res = install_lib._restart_component("privoxy", _make_services_runner(), port_checker=probe)
    assert res.get("rc") == 0


def test_restart_component_dnsmasq_uses_sudo_for_stop_and_start(monkeypatch):
    """dnsmasq запускается под sudo (port 53) — stop/start тоже под sudo, polling UDP-порта 53."""
    monkeypatch.setattr(install_lib, "_PORT_SETTLE_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_lib, "_PORT_SETTLE_MAX_WAIT", 0)
    monkeypatch.setattr(install_lib, "_PORT_UP_MAX_WAIT", 0)
    calls = []
    runner = _make_services_runner()

    def recording(cmd, timeout):
        calls.append(list(cmd))
        return runner(cmd, timeout)

    install_lib._restart_component("dnsmasq", recording, port_checker=_PortProbe([False, True]))
    # Каждый brew services stop/start для dnsmasq должен идти под sudo.
    svc_cmds = [c for c in calls if "services" in c]
    assert svc_cmds, "dnsmasq restart должен дёргать brew services"
    for c in svc_cmds:
        assert install_lib.SUDO in c, f"dnsmasq brew services должен идти под sudo: {c}"


def test_apply_install_polls_port_in_managed_privoxy_flow(monkeypatch, tmp_path):
    """Связка apply→restart→port (канон always-tdd: покрывать связку компонентов, не только изоляцию).

    apply_install для managed privoxy вызывает _restart_component, который делает stop→poll→start→poll.
    На нелеченом коде apply вызывает слепой `brew services restart` без poll (дыра apply_install:775-777).

    probe эмулирует эволюцию порта вокруг stop/start: build_plan зондит порты всех компонентов
    (расходуя stateless-пробу), а _restart_component для privoxy видит «после stop свободен → после
    start поднят». mark_started переключает порт 8118 в «поднят» ровно в момент brew services start.
    """
    monkeypatch.setattr(install_lib, "_PORT_SETTLE_POLL_INTERVAL", 0)
    monkeypatch.setattr(install_lib, "_PORT_SETTLE_MAX_WAIT", 0)
    monkeypatch.setattr(install_lib, "_PORT_UP_MAX_WAIT", 0)
    env = install_lib.InstallEnv(
        root=Path(__file__).resolve().parent.parent,
        prefix=tmp_path / "homebrew",
        state_path=tmp_path / "srouter.local.json",
        launchagent_dir=tmp_path / "LaunchAgents",
        now="2026-07-20T00:00:00Z",
    )
    calls = []
    runner = _make_services_runner()
    probe = _PortProbeForApply()  # все порты свободны до start

    def recording(cmd, timeout):
        calls.append(list(cmd))
        res = runner(cmd, timeout)
        # brew services start <name> → соответствующий порт поднялся (симметрия реального сервиса).
        if "services" in cmd and "start" in cmd[cmd.index("services"):]:
            name = cmd[cmd.index("services") + 2]
            _, port = install_lib.PORTS[name]
            probe.mark_started(port)
        return res

    result = install_lib.apply_install(
        env=env,
        confirm=True,
        choices={"privoxy": "overwrite", "xray": "skip", "dnsmasq": "skip"},
        runner=recording,
        port_checker=probe,
        install_launchagent=False,
    )
    assert result["ok"] is True, result
    # Ни один brew services не должен быть `restart` (слепой — гонка).
    restart_cmds = [c for c in calls if "services" in c and "restart" in c[c.index("services"):]]
    assert not restart_cmds, "apply не должен использовать `brew services restart` для managed-компонента"
    # privoxy рестартнулся через stop→start (а не skipped).
    privoxy_start = [c for c in calls if "services" in c and "start" in c[c.index("services"):] and c[-1] == "privoxy"]
    privoxy_stop = [c for c in calls if "services" in c and "stop" in c[c.index("services"):] and c[-1] == "privoxy"]
    assert privoxy_stop and privoxy_start, "managed privoxy должен идти через stop→start"
