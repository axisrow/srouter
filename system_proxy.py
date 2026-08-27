"""Системный сетевой прокси macOS — READ-ONLY probe через `scutil --proxy`.

Зачем отдельный модуль: srouter управляет своим стеком (privoxy/xray) и настройками
конкретных потребителей (git, Claude Code, VSCode, codex), но системный прокси macOS
до сих пор не входил в картину ВООБЩЕ. Из-за этого пользователь не мог ответить на
вопрос «какой прокси включён»: Wi-Fi мог проксировать трафик мимо всего, что показывал
дашборд.

Почему только чтение (осознанное архитектурное решение, не недоделка):
  - `networksetup -setwebproxy` меняет поведение ВСЕЙ ОС для всех приложений разом —
    это выходит за границу «дашборд управляет своим стеком»;
  - privileged_ops.is_allowed — fail-closed whitelist, пропускающий из networksetup
    ровно `-setdnsservers`; расширять его ради глобальной мутации нельзя без веской
    причины (канон privileged-boundary-fail-closed).
Показать «система: прокси выключен / включён на X» достаточно, чтобы снять путаницу.

Первоисточник формата (канон probe-semantics-from-primary-source — снято эмпирически,
не по аналогии): `scutil --proxy` печатает

    <dictionary> {
      HTTPEnable : 1
      HTTPPort : 3128
      HTTPProxy : squid.example.com
      SOCKSEnable : 0
    }

Ключи <Channel>Enable/<Channel>Proxy/<Channel>Port появляются независимо: выключенный
канал печатает только Enable : 0 (без Proxy/Port). PAC — отдельный механизм
(ProxyAutoConfigEnable + ProxyAutoConfigURLString), при котором ручные прокси могут
быть выключены, а трафик всё равно проксируется.

Probe-канон: НИКОГДА не бросает, всегда возвращает dict со `status`.
"""
import sys_probe

# Абсолютный путь: launchd/GUI PATH не содержит /usr/sbin (канон dashboard_common).
SCUTIL = "/usr/sbin/scutil"

# Каналы: наш id -> префикс ключей scutil. FTP намеренно опущен (не влияет на HTTP-стек srouter).
_CHANNELS = (("http", "HTTP"), ("https", "HTTPS"), ("socks", "SOCKS"))

# Маркер валидного вывода: без него не отличить пустой ответ от «всё выключено».
_DICT_MARKER = "<dictionary>"


def _parse_scutil_dict(text):
    """`Ключ : значение` -> dict[str, str]. Значения с ':' внутри (URL) не режем."""
    out = {}
    for line in (text or "").splitlines():
        key, sep, value = line.partition(" : ")
        if not sep:
            continue
        key = key.strip()
        if key:
            out[key] = value.strip()
    return out


def _flag(raw, key):
    """scutil печатает булевы как 0/1. Любое иное значение -> False (fail-closed)."""
    return raw.get(key, "0").strip() == "1"


def _port(raw, key):
    """Порт как int; отсутствующий/нечисловой -> None (не выдумываем 0)."""
    try:
        return int(raw[key])
    except (KeyError, TypeError, ValueError):
        return None


def _unknown(detail):
    """Честное «не знаю»: any_enabled=None, а НЕ False — иначе выдуманное «выключено»."""
    empty = {"enabled": None, "server": "", "port": None}
    return {
        "status": "unknown",
        "any_enabled": None,
        "detail": detail,
        "http": dict(empty),
        "https": dict(empty),
        "socks": dict(empty),
        "pac": {"enabled": None, "url": ""},
    }


def status():
    """Состояние системного прокси macOS. Не бросает.

    {status: ok|unknown, any_enabled: bool|None, detail: str,
     http/https/socks: {enabled, server, port}, pac: {enabled, url}}

    any_enabled — «система вообще куда-то проксирует?» (учитывает и PAC). None при
    unknown: неизвестность не равна выключенности (канон verify-dont-guess).
    """
    r = sys_probe.run([SCUTIL, "--proxy"], timeout=3)
    if r.get("timeout"):
        return _unknown("scutil --proxy: таймаут")
    out = r.get("out") or ""
    if _DICT_MARKER not in out:
        return _unknown("scutil --proxy: неожиданный формат вывода")

    raw = _parse_scutil_dict(out)
    result = {"status": "ok", "detail": ""}
    enabled_any = False

    for name, prefix in _CHANNELS:
        on = _flag(raw, prefix + "Enable")
        result[name] = {
            "enabled": on,
            "server": raw.get(prefix + "Proxy", ""),
            "port": _port(raw, prefix + "Port"),
        }
        enabled_any = enabled_any or on

    pac_on = _flag(raw, "ProxyAutoConfigEnable")
    result["pac"] = {"enabled": pac_on, "url": raw.get("ProxyAutoConfigURLString", "")}
    result["any_enabled"] = enabled_any or pac_on
    return result
