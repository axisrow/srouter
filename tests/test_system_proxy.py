"""Системный macOS-прокси (scutil --proxy) — READ-ONLY probe.

Канон probe-semantics-from-primary-source: парсер написан по реальному выводу
`scutil --proxy` (формат `<dictionary> {` + строки `Ключ : значение`), не по аналогии.

Модуль намеренно НЕ умеет писать: смена системного прокси меняет поведение всей ОС
для всех приложений разом и выходит за границу «дашборд управляет своим стеком».
"""
import sys_probe
import system_proxy


# Реальный вывод с машины (всё выключено) — снят эмпирически, не выдуман.
SCUTIL_ALL_OFF = """<dictionary> {
  ExcludeSimpleHostnames : 0
  FTPPassive : 1
  HTTPEnable : 0
  HTTPSEnable : 0
  ProxyAutoConfigEnable : 0
  ProxyAutoDiscoveryEnable : 0
  SOCKSEnable : 0
}"""

# Формат при включённом HTTP+SOCKS: появляются Proxy/Port ключи.
SCUTIL_HTTP_AND_SOCKS_ON = """<dictionary> {
  ExcludeSimpleHostnames : 0
  FTPPassive : 1
  HTTPEnable : 1
  HTTPPort : 3128
  HTTPProxy : squid.example.com
  HTTPSEnable : 0
  ProxyAutoConfigEnable : 0
  SOCKSEnable : 1
  SOCKSPort : 10808
  SOCKSProxy : 127.0.0.1
}"""

SCUTIL_PAC_ON = """<dictionary> {
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://wpad.example.com/proxy.pac
  HTTPEnable : 0
  HTTPSEnable : 0
  SOCKSEnable : 0
}"""


def _fake_run(out, *, timed_out=False, rc=0):
    """Заглушка sys_probe.run. Имя timed_out НЕ совпадает с параметром run(timeout=...) —
    иначе аргумент вызова затенил бы значение замыкания и таймаут-ветка не проверялась бы."""
    def run(cmd, timeout=None, env=None):
        return {"out": out, "err": "", "rc": rc, "timeout": timed_out}
    return run


def test_all_off_gives_every_channel_disabled(monkeypatch):
    monkeypatch.setattr(sys_probe, "run", _fake_run(SCUTIL_ALL_OFF))
    st = system_proxy.status()
    assert st["status"] == "ok"
    assert st["any_enabled"] is False
    for channel in ("http", "https", "socks", "pac"):
        assert st[channel]["enabled"] is False, channel


def test_http_and_socks_enabled_are_parsed_with_server_and_port(monkeypatch):
    monkeypatch.setattr(sys_probe, "run", _fake_run(SCUTIL_HTTP_AND_SOCKS_ON))
    st = system_proxy.status()
    assert st["any_enabled"] is True
    assert st["http"] == {"enabled": True, "server": "squid.example.com", "port": 3128}
    assert st["socks"] == {"enabled": True, "server": "127.0.0.1", "port": 10808}
    # HTTPS остаётся выключенным — Enable-флаги независимы.
    assert st["https"]["enabled"] is False


def test_pac_is_reported_separately_from_manual_proxies(monkeypatch):
    """PAC — отдельный механизм: ручные прокси выключены, но система всё равно проксирует."""
    monkeypatch.setattr(sys_probe, "run", _fake_run(SCUTIL_PAC_ON))
    st = system_proxy.status()
    assert st["pac"] == {"enabled": True, "url": "http://wpad.example.com/proxy.pac"}
    assert st["any_enabled"] is True


def test_timeout_degrades_to_unknown_and_never_raises(monkeypatch):
    """Probe-канон: не бросает, честный unknown вместо выдуманного 'выключено'."""
    monkeypatch.setattr(sys_probe, "run", _fake_run("", timed_out=True))
    st = system_proxy.status()
    assert st["status"] == "unknown"
    assert st["any_enabled"] is None  # НЕ False — мы не знаем


def test_garbage_output_degrades_to_unknown(monkeypatch):
    monkeypatch.setattr(sys_probe, "run", _fake_run("не словарь вовсе"))
    st = system_proxy.status()
    assert st["status"] == "unknown"


def test_uses_absolute_binary_path_and_list_args(monkeypatch):
    """Канон: абсолютный путь (launchd PATH пуст), список аргументов, никогда shell=True."""
    seen = {}

    def run(cmd, timeout=None, env=None):
        seen["cmd"] = cmd
        return {"out": SCUTIL_ALL_OFF, "err": "", "rc": 0, "timeout": False}

    monkeypatch.setattr(sys_probe, "run", run)
    system_proxy.status()
    assert isinstance(seen["cmd"], list)
    assert seen["cmd"][0].startswith("/")
    assert seen["cmd"] == [system_proxy.SCUTIL, "--proxy"]


def test_module_is_read_only_no_write_api():
    """Осознанное решение плана: системный прокси НЕ пишем."""
    assert not hasattr(system_proxy, "enable")
    assert not hasattr(system_proxy, "disable")
