#!/usr/bin/env python3
"""Генератор xray-конфига из unified local state `srouter.local.json`.

Контракт: этот файл — единственный владелец полного xray config. Будущие фичи
расширяют его через kwargs/hook-и, а не патчат сборку inline в dashboard/install.
"""
from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path

import local_state


MARKER = "srouter-managed"
ROOT = Path(__file__).resolve().parent
TEMPLATE_PATH = ROOT / "templates" / "xray-config.template.json"
LISTEN_HOST = "127.0.0.1"

# SOCKS-порт xray — единый источник dashboard_common (issue #155). gen_xray_config должен
# работать и в среде без srouter_config (install-путь): dashboard_common при отсутствии
# конфига поднимает SystemExit (BaseException, не Exception) — ловим BaseException, иначе
# install упадёт раньше, чем сможет сгенерировать конфиг. Fallback = то же каноническое
# значение; строка помечена маркером canonical-fallback-port — tests/test_proxy_constants.py
# разрешает её как осознанный fallback, а не свежий дубликат.
try:
    from dashboard_common import XRAY_SOCKS_PORT  # noqa: F401  (canonical-fallback-port)
except BaseException:  # noqa: BLE001  — SystemExit от dashboard_common в среде без srouter_config
    XRAY_SOCKS_PORT = 10808  # canonical-fallback-port

TRAFFIC_GUARD_BLACKHOLE_TAG = "traffic-guard-blackhole"

_TAG_RE = re.compile(r"[^A-Za-z0-9_-]+")
_HEX_RE = re.compile(r"^[A-Fa-f0-9]{0,32}\Z")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:-]+\Z")


class TrafficGuardValidationError(ValueError):
    """Traffic Guard невалиден; генерация должна fail-closed, а не выключать защиту."""

    def __init__(self, errors):
        self.errors = [str(error) for error in errors if error] or ["traffic_guard invalid"]
        super().__init__("traffic_guard невалиден: " + "; ".join(self.errors))


def _default_template():
    return {
        "log": {"loglevel": "warning"},
        "srouter": {"marker": MARKER, "managed": True, "generated_by": "gen_xray_config.py"},
        "inbounds": [],
        "outbounds": [],
        "routing": {"domainStrategy": "AsIs", "rules": []},
    }


def _load_template(path=None):
    """Загрузить JSON-template. Ошибка чтения деградирует в безопасный skeleton."""
    p = Path(path) if path else TEMPLATE_PATH
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return _default_template()
    except (OSError, ValueError, TypeError):
        return _default_template()
    data.setdefault("log", {"loglevel": "warning"})
    data.setdefault("srouter", {})
    data.setdefault("inbounds", [])
    data.setdefault("outbounds", [])
    data.setdefault("routing", {})
    if not isinstance(data["routing"], dict):
        data["routing"] = {}
    data["routing"].setdefault("domainStrategy", "AsIs")
    data["routing"].setdefault("rules", [])
    return data


def _safe_tag(value, fallback="node"):
    raw = value if isinstance(value, str) and value else fallback
    tag = _TAG_RE.sub("-", raw).strip("-")
    return tag or fallback


def _valid_host(value):
    try:
        return local_state._is_valid_host(value)
    except Exception:
        return False


def _safe_host(value, fallback=""):
    if _valid_host(value):
        return value
    return fallback if _valid_host(fallback) else ""


def _safe_token(value, fallback=""):
    if isinstance(value, str) and _TOKEN_RE.match(value):
        return value
    return fallback if isinstance(fallback, str) and _TOKEN_RE.match(fallback) else ""


def _safe_short_id(value):
    if isinstance(value, str) and _HEX_RE.match(value):
        return value
    return ""


def _safe_port(value, default=443):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default
    return port if 1 <= port <= 65535 else default


def _main_socks_inbound():
    return {
        "tag": "srouter-socks",
        "listen": LISTEN_HOST,
        "port": XRAY_SOCKS_PORT,
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": False},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
    }


def _probe_inbound(node):
    probe = node.get("probe") if isinstance(node.get("probe"), dict) else {}
    port = _safe_port(probe.get("socks_port"), default=0)
    if not port:
        return {}
    name = _safe_tag(node.get("name"))
    return {
        "tag": f"probe-{name}",
        "listen": LISTEN_HOST,
        "port": port,
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": False},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
    }


def _vless_outbound(node, tag, *, state_path=None):
    """Собрать VLESS+Reality outbound. Невалидные поля очищаются, не интерполируются."""
    if not isinstance(node, dict):
        return {}
    endpoint = _safe_host(node.get("endpoint_host"))
    address = _safe_host(local_state.resolve_route_ip(node, path=state_path), endpoint) or endpoint
    if not address:
        return {}
    reality = node.get("reality") if isinstance(node.get("reality"), dict) else {}
    sni = _safe_host(reality.get("sni"), endpoint)
    dest = _safe_host(reality.get("dest"), f"{sni}:443" if sni else "")
    user = {
        "id": _safe_token(node.get("uuid")),
        "encryption": "none",
    }
    flow = _safe_token(reality.get("flow"))
    if flow:
        user["flow"] = flow
    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": _safe_port(node.get("port"), default=443),
                    "users": [user],
                }
            ]
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "serverName": sni,
                "fingerprint": "chrome",
                "publicKey": _safe_token(reality.get("public_key")),
                "shortId": _safe_short_id(reality.get("short_id")),
                "spiderX": "/",
            },
        },
        "srouter": {
            "node": node.get("name") or "",
            "reality_dest": dest,
        },
    }


def _apply_outbound_hook(outbound, outbound_hook, *, node, role):
    if not outbound_hook:
        return outbound
    try:
        patched = outbound_hook(copy.deepcopy(outbound), node=node, role=role)
        return patched if isinstance(patched, dict) else outbound
    except Exception:
        return outbound


def traffic_guard_validation_errors(state_path=None, traffic_guard_channel=None):
    """Ошибки Traffic Guard для apply/preflight-слоёв. Пустой список значит generation-safe."""
    guard = local_state.traffic_guard_config(path=state_path, channel=traffic_guard_channel)
    if guard.get("valid") is not True:
        errors = guard.get("errors") if isinstance(guard.get("errors"), list) else []
        return [str(error) for error in errors if error] or ["traffic_guard invalid"]
    if guard.get("mode") == "auto":
        channel = guard.get("channel")
        if not channel:
            return ['traffic_guard.mode "auto" requires traffic_guard_channel or traffic_guard.channel']
        # Канал резолвлен, но для него (после usb_tether->metered fallback) 0 политик:
        # config сгенерировался бы валидным с пустой защитой — тихое fail-open. Fail-closed.
        domains = guard.get("domains") if isinstance(guard.get("domains"), dict) else {}
        if not domains:
            return [f"traffic_guard.auto: selected channel {channel} has no policies"]
    return []


def validate_traffic_guard_for_generation(state_path=None, traffic_guard_channel=None):
    """Fail-closed gate: invalid guard не должен рендериться как обычный config."""
    errors = traffic_guard_validation_errors(state_path=state_path, traffic_guard_channel=traffic_guard_channel)
    if errors:
        raise TrafficGuardValidationError(errors)
    return local_state.traffic_guard_config(path=state_path, channel=traffic_guard_channel)


def _traffic_guard_domains(state_path=None, policy=None, guard=None, traffic_guard_channel=None):
    guard = (
        guard
        if isinstance(guard, dict)
        else validate_traffic_guard_for_generation(state_path=state_path, traffic_guard_channel=traffic_guard_channel)
    )
    if guard.get("mode") not in ("on", "auto") or guard.get("valid") is not True:
        return []
    domains = guard.get("domains") if isinstance(guard.get("domains"), dict) else {}
    out = []
    for domain, domain_policy in domains.items():
        if policy is not None and domain_policy != policy:
            continue
        if _valid_host(domain):
            # Xray `domain:example.com` покрывает exact + subdomains.
            out.append(f"domain:{domain}")
    return out


def _traffic_guard_blackhole_outbound():
    return {"tag": TRAFFIC_GUARD_BLACKHOLE_TAG, "protocol": "blackhole", "settings": {}}


def generate_config(
    state_path=None,
    *,
    extra_inbounds=None,
    extra_rules=None,
    extra_outbounds=None,
    outbound_hook=None,
    template_path=None,
    traffic_guard_channel=None,
):
    """Вернуть dict xray config.

    Extension API:
    - extra_inbounds / extra_rules / extra_outbounds добавляют секции без правки тела генератора;
    - outbound_hook(outbound, *, node, role) может заменить outbound для active/probe ролей.
    Невалидный Traffic Guard бросает TrafficGuardValidationError: для block-фичи нужен fail-closed.
    """
    cfg = _load_template(template_path)
    cfg = copy.deepcopy(cfg)
    cfg["srouter"] = {
        **(cfg.get("srouter") if isinstance(cfg.get("srouter"), dict) else {}),
        "marker": MARKER,
        "managed": True,
        "generated_by": "gen_xray_config.py",
    }

    nodes = local_state.load_nodes(path=state_path)
    active = local_state.active_node(path=state_path)

    inbounds = [_main_socks_inbound()]
    rules = []
    outbounds = [{"tag": "direct", "protocol": "freedom", "settings": {}}]
    traffic_guard = validate_traffic_guard_for_generation(
        state_path=state_path, traffic_guard_channel=traffic_guard_channel
    )
    block_domains = _traffic_guard_domains(
        state_path, policy="block", guard=traffic_guard, traffic_guard_channel=traffic_guard_channel
    )
    allow_domains = _traffic_guard_domains(
        state_path, policy="allow", guard=traffic_guard, traffic_guard_channel=traffic_guard_channel
    )

    for node in nodes:
        inbound = _probe_inbound(node)
        if not inbound:
            continue
        inbounds.append(inbound)
        name = _safe_tag(node.get("name"))
        tag = f"probe-out-{name}"
        outbound = _vless_outbound(node, tag, state_path=state_path)
        outbound = _apply_outbound_hook(outbound, outbound_hook, node=node, role="probe")
        if outbound:
            outbounds.append(outbound)
            rules.append({"type": "field", "inboundTag": [inbound["tag"]], "outboundTag": tag})

    if block_domains:
        outbounds.append(_traffic_guard_blackhole_outbound())
        rules.append(
            {
                "type": "field",
                "inboundTag": ["srouter-socks"],
                "domain": block_domains,
                "outboundTag": TRAFFIC_GUARD_BLACKHOLE_TAG,
            }
        )

    active_outbound = _vless_outbound(active, "active", state_path=state_path)
    active_outbound = _apply_outbound_hook(active_outbound, outbound_hook, node=active, role="active")
    if active_outbound:
        outbounds.append(active_outbound)
        cfg["srouter"]["active_node"] = active.get("name") or ""
        cfg["srouter"]["active_reality_dest"] = active_outbound.get("srouter", {}).get("reality_dest", "")
        if allow_domains:
            rules.append(
                {
                    "type": "field",
                    "inboundTag": ["srouter-socks"],
                    "domain": allow_domains,
                    "outboundTag": "active",
                }
            )

    if isinstance(extra_inbounds, list):
        inbounds.extend([item for item in extra_inbounds if isinstance(item, dict)])
    if isinstance(extra_outbounds, list):
        outbounds.extend([item for item in extra_outbounds if isinstance(item, dict)])
    if isinstance(extra_rules, list):
        rules.extend([item for item in extra_rules if isinstance(item, dict)])

    cfg["inbounds"] = inbounds
    cfg["outbounds"] = outbounds
    cfg["routing"] = cfg.get("routing") if isinstance(cfg.get("routing"), dict) else {}
    cfg["routing"]["domainStrategy"] = cfg["routing"].get("domainStrategy") or "AsIs"
    cfg["routing"]["rules"] = rules
    return cfg


def write_config(output_path, state_path=None, **kwargs):
    """Атомарно записать config. Возвращает True/False, не бросает."""
    path = Path(output_path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        cfg = generate_config(state_path=state_path, **kwargs)
        tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        tmp.replace(path)
        return True
    except (OSError, TypeError, ValueError):
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description="Сгенерировать xray config из srouter.local.json")
    parser.add_argument("--state", dest="state_path", default=None, help="Путь к srouter.local.json")
    parser.add_argument("-o", "--output", dest="output_path", default=None, help="Куда записать config.json")
    parser.add_argument(
        "--traffic-guard-channel",
        dest="traffic_guard_channel",
        default=None,
        help="Канал для mode:auto: wifi, usb_tether/usb или metered",
    )
    args = parser.parse_args(argv)

    try:
        cfg = generate_config(state_path=args.state_path, traffic_guard_channel=args.traffic_guard_channel)
        text = json.dumps(cfg, ensure_ascii=False, indent=2) + "\n"
        if args.output_path:
            path = Path(args.output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        else:
            print(text, end="")
        return 0
    except Exception as exc:  # CLI-граница: не роняем stack trace в пользователя.
        print(f"Ошибка генерации xray config: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
