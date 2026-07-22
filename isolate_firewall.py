"""PF-изоляция Proxy-доменов: прямой путь отрезается в ядре (fail-closed).

Цель: пакеты к Proxy-доменам (api.anthropic.com и др.) НЕ могут уйти через реальные
интерфейсы (en0/ppp0) — только через прокси-узел (xray→VPS). Даже если Claude Code
забудет HTTPS_PROXY или любая программа полезет напрямую — PF режет в ядре. Если
прокси упал — трафик в никуда (fail-closed), НЕ напрямую.

Двухфазная загрузка (закрывает стартовое окно гонки — между бутом и dig+pfctl):
  ФАЗА 1 (strict, при RunAtLoad): блокируем подсети Anthropic (160.79.104.0/21) —
          claude.ai отрезан с первой секунды, интернет жив. Подсети зашиты константой,
          dig не нужен.
  ФАЗА 2 (working, после dig+pfctl): блокируем КОНКРЕТНЫЕ IP Proxy-доменов — точно,
          минимально. srouter переключает, как только таблица IP собрана.
  ESCAPE-HATCH: если srouter сломался и не снял strict за N сек — launchd выгружает
          strict (чтобы не остаться без сети при падении srouter).

Механика (переиспользует паттерны traffic_shape.py — тот же osascript admin-мост,
pfctl -E/-X reference-counting, fail-fast &&-цепочка, дубль токена в stderr):
  - dig @<dns> <domain> +short  → canonical IP домена («глаза» — узнать IP).
  - pfctl -a <anchor> -t <table> -T replace <ips>  → положить IP в таблицу PF («руки»).

Модель маршрутизации (почему не мешает туннелю): xray на mac соединяется только с
IP VPS (route_ip), НЕ с IP api.anthropic.com. Значит PF-блок по destination = IP
CloudFront/Anthropic отрезает только прямой путь приложения, а легитимный прокси-путь
(loopback→xray→VPS) проходит беспрепятственно.

PF-инфраструктура: anchor com.apple/srouter_isolate (под-anchor com.apple/*, уже
объявлен в /etc/pf.conf — main ruleset НЕ трогаем). Две таблицы в anchor:
  <srouter_cloudfront_subnets> — подсети Anthropic (strict-фаза).
  <srouter_proxy_ips>           — конкретные IP Proxy-доменов (working-фаза).
Без persist (избыточен при страховке подсетями + имеет минусы: ghost-таблицы,
рассинхрон). Без dummynet/pipe (это не shaping — нет DNCTL, нет busy-probe).

Границы безопасности: shell-текст собирается ТОЛЬКО из констант (пути бинарей, флаги,
имена таблиц/anchor, подсети) и ВАЛИДИРОВАННЫХ значений (canonical IP через
ipaddress round-trip). Домены в shell НЕ попадают — dig вызывается через sys_probe.run
как список аргументов (не shell), его вывод валидируется _ip_literal перед -T replace.
Функции не бросают: при сбое возвращают структированный dict.
"""
import ipaddress

import local_state
import sys_probe
import traffic_shape  # переиспользуем osascript-мост, валидаторы, парсер токена
from dashboard_common import _applescript_text  # единый канон экранирования (issue #154)

# ============================ константы (shell-safe) ============================
PFCTL = "/sbin/pfctl"
OSASCRIPT = "/usr/bin/osascript"
DIG = "/usr/bin/dig"

# Под-anchor внутри com.apple/* (как srouter_throttle) — main pf ruleset НЕ трогаем.
ANCHOR = "com.apple/srouter_isolate"

# Две PF-таблицы в anchor: strict (подсети) и working (конкретные IP).
STRICT_TABLE = "srouter_cloudfront_subnets"
TABLE = "srouter_proxy_ips"

# Интерфейсы, где режем прямой путь: физические en* и PPP-VPN ppp*.
# utun НЕ включаем — это туннели (xray/WireGuard/IPv6), их блок убил бы прокси.
# lo0 не включаем — loopback (privoxy→xray локально).
DIRECT_IFACES = ("en0", "en1", "en2", "en3", "en4", "en5", "en6", "ppp0", "ppp1")

# Подсети Anthropic для strict-фазы (страховка при буте, до dig). Это собственные
# подсети Anthropic, PBC (не широкие CloudFront) — узко, минимум побочных эффектов.
# IP всех Proxy-доменов (api/console.anthropic.com, claude.ai) живут здесь.
# ОБА семейства: IPv4 (160.79.104.0/21) и IPv6 (2607:6bc0::/32) — без v6 строгая фаза
# бесполезна (curl/программы предпочитают v6 при наличии AAAA).
ANTHROPIC_SUBNETS = ("160.79.104.0/21", "2607:6bc0::/32")

# Публичные DNS для резолва (НЕ системный dnsmasq — он может отдать кэш/подмену ISP).
PUBLIC_DNS = ("8.8.8.8", "1.1.1.1", "223.5.5.5", "119.29.29.29")

# Дефолтные Proxy-домены (меняются в дашборде).
DEFAULT_DOMAINS = ("api.anthropic.com", "console.anthropic.com", "claude.ai")

# Порты блокировки: только HTTP/HTTPS (CloudFront IP хостят много доменов).
DEFAULT_PORTS = (80, 443)

_TIMEOUT_SEC = 60

# Переиспользуем хелперы traffic_shape (DRY — тот же osascript-мост, та же семантика).
_ip_literal = traffic_shape._ip_literal
_valid_token = traffic_shape._valid_token
_parse_token = traffic_shape._parse_token
_isolate_result = traffic_shape._shape_result   # та же форма (ok/cancelled/rc/out/err/timeout)
_reject = traffic_shape._reject
# _applescript_text импортирован сверху из dashboard_common (канон, issue #154).


def _admin_run(shell_cmd):
    """Привилегированный запуск shell_cmd через osascript admin-мост (канон traffic_shape).

    shell_cmd обязан быть собран ТОЛЬКО из констант и validated значений.
    """
    applescript = f'do shell script "{_applescript_text(shell_cmd)}" with administrator privileges'
    return _isolate_result(sys_probe.run([OSASCRIPT, "-e", applescript], timeout=_TIMEOUT_SEC))


# ============================ валидация портов/подсетей ============================
def _valid_port(port):
    """Порт в shell-безопасной форме (строка из цифр 1..65535) или None."""
    if isinstance(port, bool):
        return None
    if isinstance(port, int):
        n = port
    elif isinstance(port, str) and port.isdigit():
        n = int(port)
    else:
        return None
    return str(n) if 1 <= n <= 65535 else None


def _valid_subnet(subnet):
    """Canonical CIDR-подсеть или None (для strict-таблицы — зашитые константы)."""
    if not isinstance(subnet, str) or "%" in subnet:
        return None
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return None
    return str(net)


def _ports_spec(ports):
    """Список портов → shell-safe '{ 80 443 }' или None при невалидном."""
    out = []
    for p in (ports or DEFAULT_PORTS):
        vp = _valid_port(p)
        if vp is None:
            return None
        out.append(vp)
    if not out:
        return None
    return "{ " + " ".join(out) + " }"


def _ifaces_spec():
    """Список интерфейсов в shell-safe '{ en0 en1 ... }' (из константы)."""
    return "{ " + " ".join(DIRECT_IFACES) + " }"


# ============================ резолв доменов → IPs ============================
def resolve_domain_ips(domains, dns_servers=PUBLIC_DNS):
    """domains → {domain: [canonical ip,...]}. fail-soft per domain (пустой список при сбое).

    Резолвит ОБА семейства: A (IPv4, dig без типа) и AAAA (IPv6). Без v6 изоляция
    бесполезна — curl/программы предпочитают IPv6 при наличии AAAA (Happy Eyeballs),
    и трафик уходит по v6 мимо v4-таблицы. PF mixed-таблица принимает v4+v6 вместе.

    dig вызывается через sys_probe.run как список аргументов (НЕ shell) — домен не
    интерполируется в shell-текст. Вывод валидируется _ip_literal (отбрасываем CNAME
    и неканонические формы) перед любым использованием.
    """
    result = {}
    for domain in domains or []:
        if not local_state._is_valid_host(domain):
            result[domain] = []
            continue
        ips = []
        seen = set()
        for dns in dns_servers:
            # "" = default query (A/IPv4), "AAAA" = IPv6. Оба семейства обязательны для fail-closed.
            for qtype in ("", "AAAA"):
                r = sys_probe.run([DIG, f"@{dns}", domain, qtype, "+short", "+time=3", "+tries=1"], timeout=6)
                if r.get("timeout"):
                    continue
                for line in (r.get("out") or "").splitlines():
                    line = line.strip()
                    if _ip_literal(line) and line not in seen:
                        seen.add(line)
                        ips.append(line)
        result[domain] = ips
    return result


# ============================ PF ruleset'ы ============================
def _strict_ruleset():
    """PF-ruleset для strict-фазы (подсети Anthropic)."""
    valid = [s for s in (_valid_subnet(sub) for sub in ANTHROPIC_SUBNETS) if s]
    subnets = " ".join(valid)
    ports = _ports_spec(DEFAULT_PORTS)
    return (
        f"table <{STRICT_TABLE}> {{ {subnets} }}\n"
        f"block drop out quick on {_ifaces_spec()} proto tcp to <{STRICT_TABLE}> port {ports}\n"
    )


def _working_ruleset(ports=DEFAULT_PORTS):
    """PF-ruleset для working-фазы (конкретные IP; таблица заполняется отдельно через -T replace)."""
    ports_spec = _ports_spec(ports)
    return (
        f"table <{TABLE}> {{ }}\n"
        f"block drop out quick on {_ifaces_spec()} proto tcp to <{TABLE}> port {ports_spec}\n"
    )


# ============================ публичный API: strict-фаза ============================
def enable_strict():
    """ФАЗА 1: загрузить strict-ruleset (подсети Anthropic). Не требует dig.

    Используется launchd при буте (RunAtLoad). pfctl -E + загрузка anchor. Без
    переключения в working — это делает enable_isolation, когда таблица IP готова.
    Возвращает dict (ok/cancelled/rc/token/out/err/timeout).
    """
    try:
        ruleset = _strict_ruleset()
        # -E (token, дубль в stderr) && загрузка ruleset. fail-fast.
        shell_cmd = (
            f"t=$({PFCTL} -E 2>&1) || exit $?; "
            f"printf '%s\\n' \"$t\"; printf '%s\\n' \"$t\" 1>&2; "
            f"printf '{_applescript_text(ruleset)}' | {PFCTL} -a \"{ANCHOR}\" -f -"
        )
        res = _admin_run(shell_cmd)
        token = _parse_token(res.get("out")) or _parse_token(res.get("err"))
        res["token"] = token
        if res["ok"] and not token:
            res["ok"] = False
            res["err"] = ("pf включён, но release-token не получен — enable-ref может течь; "
                          + (res["err"] or "")).rstrip("; ")
        return res
    except Exception as exc:
        return {**_reject(f"enable_strict failed: {exc}"), "token": None}


def disable_strict(token=None):
    """Снять strict-ruleset (escape-hatch или перед working-переключением).

    attempt-all: flush anchor + освободить enable-ref (если token валиден).
    Идемпотентно. Функция не бросает.
    """
    try:
        steps = [f'{PFCTL} -a "{ANCHOR}" -F all']  # сброс правил + таблиц anchor
        tok = _valid_token(token)
        if tok is not None:
            steps.append(f"{PFCTL} -X {tok}")
        body = "; ".join(f"{step} || rc=1" for step in steps)
        return _admin_run(f"rc=0; {body}; exit $rc")
    except Exception as exc:
        return _reject(f"disable_strict failed: {exc}")


# ============================ публичный API: working-фаза ============================
def enable_isolation(domains, ports=DEFAULT_PORTS, token=None):
    """ФАЗА 2: включить рабочую изоляцию — dig домены → конкретные IP → working-ruleset.

    Заменяет strict-ruleset (если был) на working с конкретными IP. Одна osascript-
    инвокация: -E (token) → загрузить working-ruleset (пустая таблица) → -T replace
    конкретных IP. fail-fast &&.

    domains: список доменов (validated через resolve_domain_ips).
    ports: (80, 443) по умолчанию.
    token: если уже захвачен (повторное enable) — переиспользуем, иначе -E.
    Возвращает dict + token + domains→ips + unresolved + ports. Не бросает.
    """
    try:
        ports_spec = _ports_spec(ports)
        if ports_spec is None:
            return {**_reject("ports должны быть целыми 1..65535"), "token": None,
                    "domains": {}, "unresolved": [], "ports": list(ports or DEFAULT_PORTS)}
        if not domains:
            return {**_reject("список доменов пуст"), "token": None,
                    "domains": {}, "unresolved": [], "ports": list(ports or DEFAULT_PORTS)}

        resolved = resolve_domain_ips(domains)
        all_ips = []
        unresolved = []
        for domain, ips in resolved.items():
            if ips:
                all_ips.extend(ips)
            else:
                unresolved.append(domain)
        all_ips = list(dict.fromkeys(all_ips))  # дедуп, порядок сохранён

        ruleset = _working_ruleset(ports)
        ips_arg = " ".join(all_ips) if all_ips else ""
        # Загрузить working-ruleset (пустая таблица) && заполнить её IP через -T replace.
        load = f"printf '{_applescript_text(ruleset)}' | {PFCTL} -a \"{ANCHOR}\" -f -"
        fill = (f"{PFCTL} -a \"{ANCHOR}\" -t {TABLE} -T replace {ips_arg}"
                if ips_arg else ":")  # нет IP — таблица остаётся пустой (правило не сработает)

        tok = _valid_token(token)
        if tok is not None:
            shell_cmd = f"{load} && {fill}"
        else:
            shell_cmd = (
                f"t=$({PFCTL} -E 2>&1) || exit $?; "
                f"printf '%s\\n' \"$t\"; printf '%s\\n' \"$t\" 1>&2; "
                f"{load} && {fill}"
            )
        res = _admin_run(shell_cmd)
        new_token = tok or _parse_token(res.get("out")) or _parse_token(res.get("err"))
        res["token"] = new_token
        res["domains"] = resolved
        res["unresolved"] = unresolved
        res["ports"] = list(ports or DEFAULT_PORTS)
        if res["ok"] and not new_token:
            res["ok"] = False
            res["err"] = ("pf включён, но release-token не получен — enable-ref может течь; "
                          + (res["err"] or "")).rstrip("; ")
        return res
    except Exception as exc:
        return {**_reject(f"enable_isolation failed: {exc}"), "token": None,
                "domains": {}, "unresolved": [], "ports": list(ports or DEFAULT_PORTS)}


def refresh_isolation_ips(domains, ports=DEFAULT_PORTS, token=None):
    """Re-dig домены → -T replace IP без перевыпуска токена (periodic refresh).

    IP меняются у CloudFront/Anthropic → re-резолв + обновление таблицы. ruleset НЕ
    перезагружается (только таблица). Требует, что PF уже включён (token захвачен).
    Возвращает dict + domains→ips + unresolved + ports. Не бросает.
    """
    try:
        resolved = resolve_domain_ips(domains)
        all_ips, unresolved = [], []
        for domain, ips in resolved.items():
            if ips:
                all_ips.extend(ips)
            else:
                unresolved.append(domain)
        all_ips = list(dict.fromkeys(all_ips))
        ips_arg = " ".join(all_ips) if all_ips else ""
        # -T replace требует PF включённым. Если не включён — -T молча вернёт ошибку.
        fill = (f"{PFCTL} -a \"{ANCHOR}\" -t {TABLE} -T replace {ips_arg}"
                if ips_arg else f"{PFCTL} -a \"{ANCHOR}\" -t {TABLE} -T flush")
        res = _admin_run(fill)
        res["domains"] = resolved
        res["unresolved"] = unresolved
        res["ports"] = list(ports or DEFAULT_PORTS)
        return res
    except Exception as exc:
        return {**_reject(f"refresh failed: {exc}"),
                "domains": {}, "unresolved": [], "ports": list(ports or DEFAULT_PORTS)}


def disable_isolation(token=None):
    """Снять изоляцию полностью: flush anchor + освободить enable-ref.

    attempt-all, идемпотентно. token из enable_isolation/enable_strict.
    """
    try:
        steps = [f'{PFCTL} -a "{ANCHOR}" -F all']
        tok = _valid_token(token)
        if tok is not None:
            steps.append(f"{PFCTL} -X {tok}")
        body = "; ".join(f"{step} || rc=1" for step in steps)
        return _admin_run(f"rc=0; {body}; exit $rc")
    except Exception as exc:
        return _reject(f"disable_isolation failed: {exc}")


# ============================ probe (state-only, без привилегий) ============================
def probe_isolation(state_path=None):
    """Статус изоляции для дашборда. НЕ зовёт pfctl (требует root) — только state.

    Возвращает dict со status (ok|warn|down|unknown), phase (strict|working|none),
    domains, ips (снимок из lease), unresolved, ports, applied_at. probe-канон:
    всегда dict со status, не бросает.
    """
    try:
        lease = local_state.load_active_isolate(path=state_path) or {}
        if not lease:
            return {"status": "down", "phase": "none", "domains": [], "ips": {},
                    "unresolved": [], "ports": list(DEFAULT_PORTS), "applied_at": None}
        domains = lease.get("domains", [])
        ips = lease.get("ips", {})
        unresolved = lease.get("unresolved", [])
        ports = lease.get("ports", list(DEFAULT_PORTS))
        phase = lease.get("phase", "working")
        applied_at = lease.get("applied_at")
        has_ips = any(ips.values())
        if phase == "strict":
            status = "warn"   # strict = страховка, рабочей таблицы ещё нет
        elif has_ips:
            status = "ok"
        else:
            status = "warn"   # working, но IP пустые (все домены unresolved)
        return {"status": status, "phase": phase, "domains": domains, "ips": ips,
                "unresolved": unresolved, "ports": ports, "applied_at": applied_at}
    except Exception as exc:
        return {"status": "unknown", "phase": "none", "error": str(exc),
                "domains": [], "ips": {}, "unresolved": [], "ports": list(DEFAULT_PORTS)}


# ============================ CLI (для launchd jobs) ============================
def main(argv=None):
    """CLI для launchd: enable/disable/refresh/enable-strict/disable-strict/status."""
    import argparse
    p = argparse.ArgumentParser(prog="isolate_firewall", description="PF-изоляция Proxy-доменов.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("enable-strict", help="Фаза 1: подсети Anthropic (RunAtLoad).")
    sub.add_parser("disable-strict", help="Снять strict (escape-hatch).")
    pe = sub.add_parser("enable", help="Фаза 2: конкретные IP (dig+pfctl).")
    pe.add_argument("--state", default=None)
    pd = sub.add_parser("disable", help="Снять изоляцию.")
    pd.add_argument("--state", default=None)
    pr = sub.add_parser("refresh", help="Re-dig + -T replace.")
    pr.add_argument("--state", default=None)
    sub.add_parser("status", help="Статус (state-only).").add_argument("--state", default=None)
    args = p.parse_args(argv)

    if args.cmd == "enable-strict":
        r = enable_strict()
        print(f"strict: ok={r.get('ok')} token={r.get('token')}")
        return 0 if r.get("ok") else 2
    if args.cmd == "disable-strict":
        r = disable_strict()
        return 0 if r.get("ok") else 2
    if args.cmd == "status":
        print(probe_isolation(getattr(args, "state", None)))
        return 0
    # enable/disable/refresh — читают lease из state для token/доменов
    lease = local_state.load_active_isolate(path=getattr(args, "state", None)) or {}
    cfg = local_state.load_state(path=getattr(args, "state", None)) or {}
    iso_cfg = (cfg.get("isolate") if isinstance(cfg, dict) else {}) or {}
    domains = iso_cfg.get("domains") or list(DEFAULT_DOMAINS)
    ports = iso_cfg.get("ports") or list(DEFAULT_PORTS)
    token = lease.get("token")
    if args.cmd == "enable":
        r = enable_isolation(domains, ports=ports, token=token)
        print(f"enable: ok={r.get('ok')} token={r.get('token')} unresolved={r.get('unresolved')}")
        return 0 if r.get("ok") else 2
    if args.cmd == "disable":
        r = disable_isolation(token=token)
        return 0 if r.get("ok") else 2
    if args.cmd == "refresh":
        r = refresh_isolation_ips(domains, ports=ports, token=token)
        print(f"refresh: ok={r.get('ok')} unresolved={r.get('unresolved')}")
        return 0 if r.get("ok") else 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
