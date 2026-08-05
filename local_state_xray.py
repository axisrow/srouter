"""#200: рассинхрон endpoint local.json ↔ xray config — чтение рабочего xray-конфига и sync.

Извлечено из local_state.py (issue #158, декомпозиция крупных файлов). Обращается к core state
I/O и к local_state_nodes через фасад `local_state` (facade-lookup, канон
moving-caller-inverts-mock-ownership — см. docstring local_state_traffic_guard.py).

Единый источник правды: srouter.local.json — canonical state (active_node.endpoint_host). Но
РАБОЧИЙ xray config (туда gen_xray_config._vless_outbound пишет resolve_route_ip) держит
РЕАЛЬНЫЙ VPS-address, а local.json мог остаться placeholder'ом (test-IP 203.0.113.x, RFC 5737 —
вписан в example / старая генерация / ручная правка xray в обход srouter). В этом окне
gen_xray_config.generate_config генерит из local_state.active_node() → `srouter apply`
ПЕРЕЗАПИШЕТ рабочий xray config placeholder'ом и сломает прокси (когда VPS оживёт). Эти функции:
detect drift, sync endpoint из xray, и apply-защита поверх них.
"""
import json
from pathlib import Path

import local_state

# Куда gen_xray_config пишет рабочий конфиг (источник истины address узла).
XRAY_CONFIG_PATH = "/opt/homebrew/etc/xray/config.json"

# TEST-NET 203.0.113.0/24 (RFC 5737) — документационные адреса, НЕ маршрутизируются в интернете.
# Встречаются в srouter.local.example.json / srouter_config.example.py (placeholder). Та же константа
# живет в health._TESTNET_203_PREFIX (#194); здесь — canonical источник для apply/doctor (#200).
_TESTNET_203_PREFIX = "203.0.113."


def read_xray_active_address(config_path=XRAY_CONFIG_PATH):
    """Прочитать address АКТИВНОГО Reality-узла из рабочего xray-конфига с различением состояний.

    Возвращает {status, address}:
      - absent    — файла нет (fresh install): применять fresh-install-логику (нечего ломать);
      - unreadable — файл существует, но битый (не JSON / не dict): fail-closed, НЕ fresh install;
      - no_active — валидный JSON, но нет outbound с tag="active" (или без валидного address);
      - ok        — address активного outbound'а.
    Канон verify-dont-guess + fail-closed (cycle-review Codex critical 0.94): absent и unreadable
    РАЗНЫЕ состояния — раньше оба давали '' → apply-гард считал битый рабочий config fresh-install'ом
    и перезаписывал его (outage). Не бросает (probe-канон).
    """
    p = Path(config_path)
    if not p.exists():
        return {"status": "absent", "address": ""}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # OSError: ошибки файла/чтения; ValueError: невалидные данные (JSONDecodeError — подкласс ValueError)
        return {"status": "unreadable", "address": ""}
    if not isinstance(data, dict):
        return {"status": "unreadable", "address": ""}
    # АКТИВНЫЙ outbound = tag=="active" (канон gen_xray_config: active_outbound = _vless_outbound(active, "active")).
    # cycle-review Codex critical 0.98: gen_xray_config эмиттит probe-out-* vless ПЕРЕД active → первый
    # vless = probe-узел (чужой endpoint). Выбор по tag=active, а не «первый vless», иначе sync/compare/
    # guard работают с endpoint probe-узла, не active (sync импортил бы чужой endpoint в active-узел).
    for ob in data.get("outbounds") or []:
        if not isinstance(ob, dict) or ob.get("tag") != "active":
            continue
        vnext = (ob.get("settings") or {}).get("vnext") or []
        if vnext and isinstance(vnext[0], dict):
            addr = vnext[0].get("address")
            if isinstance(addr, str) and local_state._is_valid_host(addr):
                return {"status": "ok", "address": addr}
    # active-outbound есть, но без валидного address; ИЛИ active-outbound'а нет вовсе
    return {"status": "no_active", "address": ""}


def _read_xray_vless_address(config_path=XRAY_CONFIG_PATH):
    """Прочитать address АКТИВНОГО Reality-узла из рабочего xray-конфига. Возвращает '' если не ok.

    Тонкая обёртка над read_xray_active_address для backwards-compat (sync_route_ip_from_xray #136,
    consumer'ы, которым нужен просто address). Для новой логики #200 использовать read_xray_active_address
    (различает absent/unreadable/no_active — нужно для apply fail-closed). Не бросает.
    """
    return read_xray_active_address(config_path)["address"]


def sync_route_ip_from_xray(name, xray_config_path=XRAY_CONFIG_PATH, path=None):
    """Синхронизировать route_ip узла <name> из рабочего xray-конфига.

    xray-конфиг — источник истины (туда gen_xray_config пишет resolve_route_ip). Если state держит
    placeholder/рассинхрон — берём реальный address из xray и пишем в node.route_ip. После этого и
    gen_xray, и node_selector._route_node_ip читают консистентный IP. Не бросает.

    Возвращает {ok: bool, route_ip: str}. ok=False если xray-конфига нет / узел не найден / битый.
    """
    address = _read_xray_vless_address(xray_config_path)
    if not address:
        return {"ok": False, "route_ip": ""}
    try:
        state, readable = local_state._load_state_checked(path)
        if not readable:
            return {"ok": False, "route_ip": ""}
    except (OSError, ValueError, TypeError):
        # OSError: ошибки файла; ValueError: ошибки структуры; TypeError: ошибки типа данных
        return {"ok": False, "route_ip": ""}
    nodes = local_state._nodes_from_state(state)
    updated = False
    for n in nodes:
        if isinstance(n, dict) and n.get("name") == name:
            if n.get("route_ip") != address:
                n["route_ip"] = address
                updated = True
            break
    else:
        return {"ok": False, "route_ip": ""}  # узел не найден
    if updated:
        try:
            local_state.save_state(state, path)
        except (OSError, ValueError, TypeError):
            # OSError: ошибки записи; ValueError: ошибки структуры; TypeError: ошибки типа данных
            return {"ok": False, "route_ip": ""}
    return {"ok": True, "route_ip": address}


def _is_testnet_placeholder(host):
    """True если host — TEST-NET 203.0.113.x (RFC 5737) placeholder, не реальный VPS.

    Только IPv4-форму 203.0.113.NNN: count('.')==3 + префикс. Невалидный host → False (не placeholder).
    Канон: test-IP не маршрутизируется → его нельзя писать в рабочий xray config и по нему нельзя
    судить о реальном endpoint (verify-dont-guess).
    """
    if not isinstance(host, str) or not host:
        return False
    if host.count(".") != 3 or not host.startswith(_TESTNET_203_PREFIX):
        return False
    octet = host[len(_TESTNET_203_PREFIX):]
    return octet.isdigit() and 0 <= int(octet) <= 255


def active_endpoint_host(path=None):
    """endpoint_host активного узла из canonical state (или ''). Никогда не бросает.

    active_node() уже разрешает active->enabled-fallback; здесь лишь достаём endpoint_host. ''
    когда узла нет / нет endpoint_host / host невалиден. Это — то, что gen_xray_config возьмёт
    для генерации address (через resolve_route_ip), т.е. candidate для placeholder-overwrite.
    """
    node = local_state.active_node(path)
    host = node.get("endpoint_host") if isinstance(node, dict) else None
    if not isinstance(host, str) or not host or not local_state._is_valid_host(host):
        return ""
    return host


def compare_endpoint_with_xray(state_path=None, xray_config_path=XRAY_CONFIG_PATH):
    """Сравнить endpoint активного узла (canonical state) с address из рабочего xray config (#200).

    xray config — runtime-истина (gen_xray_config пишет туда resolve_route_ip(node)). Если state
    рассинхронизирован (placeholder), xray держит реальный рабочий IP. Возвращает:
      {synced: bool, local: str, xray: str, placeholder: bool, xray_status: str}
      - local   — endpoint_host активного узла ('' если нет);
      - xray    — address из tag=active outbound ('' если нет/бит/без active);
      - xray_status — absent (fresh install) / unreadable (битый, fail-closed) / no_active / ok;
      - placeholder — local — TEST-NET 203.0.113.x (auto-sync применим);
      - synced  — True когда нет дрейфа: xray absent (fresh install, нечего ломать) ИЛИ local==xray.
                  False на unreadable/no_active (apply должен иметь шанс fail-closed, cycle-review
                  Codex critical 0.94) ИЛИ когда local != xray.
    Не бросает (probe-канон). Применяется и в apply-защите, и в doctor.
    """
    local = active_endpoint_host(state_path)
    xr = read_xray_active_address(xray_config_path)
    xray_status, xray = xr["status"], xr["address"]
    base = {"local": local, "xray": xray, "placeholder": _is_testnet_placeholder(local),
            "xray_status": xray_status}
    # absent xray (fresh install) — нечего сравнивать/ломать → synced (apply свободен).
    if xray_status == "absent":
        return {**base, "synced": True}
    # unreadable/no_active существующего config — НЕ fresh install: synced=False, чтобы apply-гард
    # мог fail-closed (пользователь решает, через --force или чинит config), а не молча перезаписывал.
    if xray_status != "ok":
        return {**base, "synced": False}
    # ok: synced если совпадает (нет local — тоже synced: нет узла, не с чем сравнивать active).
    if not local:
        return {**base, "synced": True}
    return {**base, "synced": local == xray}


def sync_endpoint_from_xray(xray_config_path=XRAY_CONFIG_PATH, path=None):
    """Импортировать реальный address из xray config в endpoint_host активного узла (#200 sync).

    Применяется когда local.json — placeholder (TEST-NET), а рабочий xray config держит реальный VPS.
    Единый источник правды = local.json canonical: sync делает его правдивым (перезаписывает placeholder
    реальным address из xray). После этого и gen_xray, и apply читают консистентный endpoint.

    Target-узел резолвится ЧЕРЕЗ active_node() — ровно тот же объект, что compare_endpoint_with_xray и
    apply-гард считают активным (cycle-review /review medium): раньше sync искал по active_node.name
    литерально и мог писать endpoint в disabled-узел (имя=disabled), пока active_node() брал fallback
    enabled-узел → sync «успешен», но compare всё ещё видит placeholder → бесконечный цикл.

    НЕ авто-overwrite когда local уже реальный (НЕ placeholder) и расходится с xray: оба «настоящие»
    адреса — выбор пользователя, detect-only (compare_endpoint_with_xray), не молчаливая подмена
    (канон no-hidden-magic / privileged-boundary: не угадываем, какой «правильнее»).

    Возвращает {ok: bool, endpoint: str, changed: bool}. ok=False если xray-конфига нет / узла нет /
    local не placeholder. Не бросает (fail-soft как sync_route_ip_from_xray).
    """
    xr = read_xray_active_address(xray_config_path)
    address = xr["address"]
    if xr["status"] != "ok" or not address:
        return {"ok": False, "endpoint": "", "changed": False}
    try:
        state, readable = local_state._load_state_checked(path)
        if not readable:
            return {"ok": False, "endpoint": "", "changed": False}
    except (OSError, ValueError, TypeError):
        # OSError: ошибки файла; ValueError: ошибки структуры; TypeError: ошибки типа данных
        return {"ok": False, "endpoint": "", "changed": False}

    # Резолв target через active_node() — единственный источник правды «какой узел активен».
    # active_node() уже внутри делает read state (тот же path); но нам нужна мутируемая ссылка на
    # запись в state["nodes"], чтобы save_state записал изменение. Поэтому ищем запись по имени
    # активного узла (после active_node()-резолва), НЕ по литеральному active_node.name из state.
    active = local_state.active_node(path) if path else local_state.active_node()
    active_name = active.get("name") if isinstance(active, dict) else None
    if not active_name:
        return {"ok": False, "endpoint": "", "changed": False}
    nodes = local_state._nodes_from_state(state)
    target = next((n for n in nodes if isinstance(n, dict) and n.get("name") == active_name), None)
    if target is None:
        return {"ok": False, "endpoint": "", "changed": False}

    local_host = target.get("endpoint_host")
    # Только placeholder → auto-sync. Реальный расходящийся local — отказ (detect-only выше).
    if not _is_testnet_placeholder(local_host):
        if local_host == address:
            return {"ok": True, "endpoint": address, "changed": False}
        return {"ok": False, "endpoint": address, "changed": False}

    target["endpoint_host"] = address
    # route_ip для IP-literal endpoint == сам endpoint (resolve_route_ip passthrough). Держим синхронно,
    # иначе gen_xray возьмёт route_ip=placeholder из старого состояния. Только если route_ip тоже
    # placeholder/пуст — не подменяем уже-валидный пользовательский route_ip без нужды.
    rip = target.get("route_ip")
    if not isinstance(rip, str) or not rip or _is_testnet_placeholder(rip):
        target["route_ip"] = address
    try:
        if local_state.save_state(state, path) is None:
            return {"ok": False, "endpoint": "", "changed": False}
    except (OSError, ValueError, TypeError):
        # OSError: ошибки записи; ValueError: ошибки структуры; TypeError: ошибки типа данных
        return {"ok": False, "endpoint": "", "changed": False}
    return {"ok": True, "endpoint": address, "changed": True}
