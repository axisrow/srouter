"""Explicit repair/restore для системного macOS SOCKS-прокси активного network service.

Зачем этот модуль отдельно от `system_proxy.py`. `system_proxy.py` — намеренно READ-ONLY
(канон: смена системного прокси меняет поведение ВСЕЙ ОС для всех приложений сразу, выходит
за границу «дашборд управляет своим стеком»). Живая регрессия показала, что этой границы
недостаточно: у Wi-Fi адрес был сохранён верно (`127.0.0.1:10808`), но канал SOCKS был
выключен — Chromium network-service процесс ChatGPT.app (обычный запуск из Dock, БЕЗ
`--proxy-server`) уходил напрямую, пока Rust app-server уже работал через launchd-env
(codenv). doctor не мог это ни увидеть, ни починить — единственным «фиксом» оставался ручной
`~/bin/codex-app-proxy`, что и было неверным контрактом (issue-обсуждение зафиксировало: normal
Dock-launch обязан снова работать сам по себе).

Этот модуль — explicit, отдельно вызываемая операция (`srouter system-proxy repair|restore`),
НЕ скрытая часть install/start/watchdog. Она:
  - определяет активный network service по default route (`route -n get default` → interface →
    `networksetup -listnetworkserviceorder` → сервис для этого device);
  - читает текущий SOCKS endpoint этого сервиса (`networksetup -getsocksfirewallproxy`);
  - если endpoint уже наш (127.0.0.1:10808) — просто включает канал (state=on), если выключен;
  - если endpoint чужой и ВЫКЛЮЧЕН — бэкапит его в srouter.local.json (runtime.system_proxy),
    затем выставляет наш endpoint и включает;
  - если endpoint чужой и УЖЕ ВКЛЮЧЁН (или authenticated) — отказывает без мутации: это чей-то
    реальный прокси, перезаписывать нельзя (канон privileged-boundary-fail-closed).
  - `restore()` возвращает сохранённый endpoint, но ТОЛЬКО если текущее состояние совпадает с
    тем, что мы применили (никакого внешнего дрейфа) — иначе отказ (conflict), без мутации.

State — единый ключ `active` (НЕ двухфазный pending/active, в отличие от active_throttle/
active_isolate): лиз пишется ПОСЛЕ подтверждённой успешной мутации (networksetup гарантирует
атомарность одной команды — нет промежуточного состояния, которое нужно было бы восстанавливать
при крахе между двумя networksetup-вызовами); при сбое любого шага — rollback к previous endpoint,
лиз не сохраняется вовсе.
"""
import logging

import local_state
import sys_probe
from install_lib import NETWORKSETUP, ROUTE

try:
    from dashboard_common import XRAY_SOCKS_ADDR as _XRAY_SOCKS_ADDR  # noqa: F401 (canonical-fallback-port)
except SystemExit:  # без srouter_config.py (install-путь) — тот же fallback, что в других модулях
    _XRAY_SOCKS_ADDR = ("127.0.0.1", 10808)  # canonical-fallback-port

_log = logging.getLogger("srouter.system_proxy_control")

# Канонический endpoint — единый источник dashboard_common.XRAY_SOCKS_ADDR (issue #155).
TARGET_SERVER, TARGET_PORT = _XRAY_SOCKS_ADDR


def _run(cmd, timeout, runner):
    return runner(cmd, timeout)


def _mutate(cmd, runner, *, timeout=20):
    """Выполнить привилегированную networksetup-мутацию. (result, err) — err=None при успехе.

    Единая точка rc/timeout-проверки для repair()/restore() (4 мутирующих вызова используют
    один и тот же fail-closed паттерн — timeout ИЛИ rc не в {0, None} = сбой).
    """
    r = _run(cmd, timeout, runner)
    if r.get("timeout") or r.get("rc") not in (0, None):
        return None, r.get("err", "")
    return r, None


def _default_interface(runner):
    """Интерфейс default route. Не переиспользует health_probes._route_default_interface —
    та жёстко привязана к sys_probe.run (без инъекции runner), а этот модуль тестируется
    fake-runner'ом; кроме того health_probes/health_codenv образуют цикл импортов с этим модулем
    (health_codenv импортирует system_proxy_control на уровне модуля). Тот же формат `route -n
    get default` → строка 'interface:' (см. health_probes.py канон), парсинг сознательно локальный.
    """
    r = _run([ROUTE, "-n", "get", "default"], 3, runner)
    if r.get("timeout") or r.get("rc") not in (0, None):
        return ""
    for line in (r.get("out") or "").splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            return line.split(":", 1)[1].strip()
    return ""


def _service_for_interface(iface, runner):
    """Имя network service (`networksetup` label) для устройства iface, или ''.

    `networksetup -listnetworkserviceorder` печатает пары строк:
        (1) Wi-Fi
        (Hardware Port: Wi-Fi, Device: en0)
    Первая непустая непронумерованная строка выше — имя сервиса.
    """
    r = _run([NETWORKSETUP, "-listnetworkserviceorder"], 4, runner)
    if r.get("timeout") or r.get("rc") not in (0, None):
        return ""
    pending_name = ""
    for raw in (r.get("out") or "").splitlines():
        line = raw.strip()
        if line.startswith("(") and "Hardware Port" not in line and ")" in line:
            # "(1) Wi-Fi" -> "Wi-Fi"
            pending_name = line.split(")", 1)[1].strip()
            continue
        if line.startswith("(Hardware Port"):
            if f"Device: {iface}" in line or f"Device: {iface})" in line:
                return pending_name
    return ""


def _read_socks(service, runner):
    r = _run([NETWORKSETUP, "-getsocksfirewallproxy", service], 4, runner)
    if r.get("timeout") or r.get("rc") not in (0, None):
        return None
    fields = {}
    for line in (r.get("out") or "").splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    return {
        "enabled": fields.get("Enabled", "No").strip().lower() == "yes",
        "server": fields.get("Server", ""),
        "port": int(fields["Port"]) if fields.get("Port", "").isdigit() else None,
        "authenticated": fields.get("Authenticated Proxy Enabled", "0").strip() == "1",
    }


def status(*, runner=sys_probe.run):
    """Текущее состояние системного SOCKS активного network service. Не бросает.

    {status: ok|unknown, interface, service, socks: {...}, target: bool}
    target=True когда endpoint уже наш (127.0.0.1:10808) И канал включён.
    """
    iface = _default_interface(runner)
    if not iface:
        return {"status": "unknown", "interface": "", "service": "", "socks": None, "target": False,
                "detail": "нет активного default route — network service не определён"}
    service = _service_for_interface(iface, runner)
    if not service:
        return {"status": "unknown", "interface": iface, "service": "", "socks": None, "target": False,
                "detail": f"не найден network service для интерфейса {iface}"}
    socks = _read_socks(service, runner)
    if socks is None:
        return {"status": "unknown", "interface": iface, "service": service, "socks": None,
                "target": False, "detail": f"networksetup -getsocksfirewallproxy {service} не отвечает"}
    is_target = bool(socks["enabled"] and socks["server"] == TARGET_SERVER
                      and socks["port"] == TARGET_PORT)
    return {"status": "ok", "interface": iface, "service": service, "socks": socks, "target": is_target}


def _lease_key():
    return "system_proxy"


def repair(*, path=None, runner=sys_probe.run):
    """Включить/выставить наш системный SOCKS endpoint на активном network service.

    Идемпотентно: уже настроено и включено -> ok без мутации. Выключен наш endpoint ->
    только `-setsocksfirewallproxystate on`. Чужой ВЫКЛЮЧЕННЫЙ endpoint -> бэкап + перезапись.
    Чужой ВКЛЮЧЁННЫЙ/authenticated endpoint -> отказ БЕЗ мутации (conflict=True) — это может
    быть настоящий рабочий прокси пользователя, перезаписывать нельзя (fail-closed).
    """
    st = status(runner=runner)
    if st["status"] != "ok":
        return {"ok": False, "conflict": False, "err": st.get("detail", "система не определена")}

    service = st["service"]
    socks = st["socks"]

    if socks["server"] == TARGET_SERVER and socks["port"] == TARGET_PORT:
        # Наш endpoint уже стоит — просто включаем канал, если выключен.
        if socks["enabled"]:
            return {"ok": True, "conflict": False, "changed": False}
        _, err = _mutate([NETWORKSETUP, "-setsocksfirewallproxystate", service, "on"], runner)
        if err is not None:
            return {"ok": False, "conflict": False, "err": err}
        _save_lease(path, service=service, previous=socks)
        return {"ok": True, "conflict": False, "changed": True}

    if socks["enabled"] or socks["authenticated"]:
        # Чужой прокси уже активен — не трогаем (может быть реальный рабочий прокси пользователя).
        _log.warning("system_proxy_control: %s уже настроен на чужой SOCKS (%s:%s), repair отказал",
                     service, socks["server"], socks["port"])
        return {"ok": False, "conflict": True,
                "err": f"{service}: уже настроен чужой SOCKS-прокси "
                       f"({socks['server']}:{socks['port']}), не перезаписываю"}

    # Чужой endpoint, но выключен — безопасно бэкапить и подменить.
    previous = dict(socks)
    _, err1 = _mutate(
        [NETWORKSETUP, "-setsocksfirewallproxy", service, TARGET_SERVER, str(TARGET_PORT)], runner)
    if err1 is not None:
        return {"ok": False, "conflict": False, "err": err1}
    _, err2 = _mutate([NETWORKSETUP, "-setsocksfirewallproxystate", service, "on"], runner)
    if err2 is not None:
        # Rollback endpoint (state ещё не тронут — networksetup default state = off не зависит
        # от endpoint, поэтому endpoint-write назад достаточно для восстановления prior state).
        _run([NETWORKSETUP, "-setsocksfirewallproxy", service,
              previous["server"] or "", str(previous["port"] or 0)], 20, runner)
        return {"ok": False, "conflict": False, "err": err2}

    _save_lease(path, service=service, previous=previous)
    return {"ok": True, "conflict": False, "changed": True}


def _save_lease(path, *, service, previous):
    state, readable = local_state.load_state_checked(path)
    if not readable:
        return False
    runtime = state.setdefault("runtime", {})
    runtime[_lease_key()] = {"active": {"service": service, "previous": previous}}
    return local_state.save_state(state, path) is not None


def restore(*, path=None, runner=sys_probe.run):
    """Вернуть сохранённый endpoint, только если текущее состояние совпадает с тем, что мы
    применили (repair). Внешний дрейф (кто-то сам поменял прокси после repair) -> отказ,
    без мутации — иначе можно затереть чужое намеренное изменение.
    """
    state = local_state.load_state(path)
    lease = (state.get("runtime") or {}).get(_lease_key())
    if not lease or not lease.get("active"):
        return {"ok": False, "conflict": False, "err": "нет сохранённого состояния для восстановления"}

    active = lease["active"]
    service = active["service"]
    previous = active["previous"]

    current = _read_socks(service, runner)
    if current is None:
        return {"ok": False, "conflict": False, "err": f"{service}: не удалось прочитать текущее состояние"}
    if not (current["enabled"] and current["server"] == TARGET_SERVER and current["port"] == TARGET_PORT):
        return {"ok": False, "conflict": True,
                "err": f"{service}: состояние изменилось извне с момента repair, restore отменён"}

    _, err1 = _mutate([NETWORKSETUP, "-setsocksfirewallproxy", service,
                       previous["server"] or "", str(previous["port"] or 0)], runner)
    if err1 is not None:
        return {"ok": False, "conflict": False, "err": err1}
    state_flag = "on" if previous.get("enabled") else "off"
    _, err2 = _mutate([NETWORKSETUP, "-setsocksfirewallproxystate", service, state_flag], runner)
    if err2 is not None:
        return {"ok": False, "conflict": False, "err": err2}

    st, readable = local_state.load_state_checked(path)
    if readable:
        runtime = st.setdefault("runtime", {})
        runtime[_lease_key()] = {"active": None}
        local_state.save_state(st, path)
    return {"ok": True, "conflict": False}
