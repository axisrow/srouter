"""ssh_client_config (#438): аудит и дефолты клиентского ~/.ssh/config.

Контекст #438: порт 22 наружу закрыт — SSH обязан ходить через туннель (ProxyCommand
nc -x 127.0.0.1:<socks> -X 5). Дефолт `Host *` перекрывается кастомными секциями
(first-obtained-wins: первое полученное значение параметра побеждает), а без
ServerAliveInterval/CountMax долгие сессии выглядят мёртвыми при кратковременных
просадках туннеля. Модуль только ЧИТАЕТ конфиг (audit) и пишет managed-include по
явной команде `srouter ssh setup` (политика roadmap: observe → manual action).
Живой ~/.ssh/config сам по себе не переписывается.

Парсер — минимальный, под нужды аудита: Host/Match/Include, `Key Value` и `Key=Value`,
комментарии. Не поддерживает backslash-переносы строк (для отслеживаемых ключей не встречаются).
ssh-паттерны: `*`/`?`, `!`-негация (список совпадает, если совпал хоть один позитивный
паттерн и ни один негативный). Match: вычислимы только `all` и `host/originalhost`;
остальные критерии — unverifiable (аудит честно предупреждает, а не угадывает).
"""
from pathlib import Path
import fnmatch
import glob as _glob
import time

try:
    from dashboard_common import XRAY_SOCKS_PORT  # noqa: F401 (canonical-fallback-port)
except (ImportError, SyntaxError):  # SyntaxError чтобы не маскировать реальные ошибки источника
    XRAY_SOCKS_PORT = 10808  # canonical-fallback-port

MANAGED_INCLUDE_NAME = "srouter.conf"
INCLUDE_MARKER = "# srouter:managed-include (#438)"
MANAGED_MARKER = "# srouter:managed ssh defaults (#438)"
DEFAULT_KEEPALIVE_INTERVAL = 15
DEFAULT_KEEPALIVE_COUNTMAX = 4
_INCLUDE_DEPTH_MAX = 4
_MATCH_EVALUABLE = ("host", "originalhost")
_MATCH_UNVERIFIABLE = ("canonical", "final", "exec", "localuser", "user", "group")
# каноническое написание отслеживаемых ключей (ssh регистронезависим, аудит — нет)
_PARAM_CANONICAL = {
    "proxycommand": "ProxyCommand",
    "serveraliveinterval": "ServerAliveInterval",
    "serveralivecountmax": "ServerAliveCountMax",
}


def _strip_comment_tokens(tokens):
    """Обрезать токены с первого, начинающегося на '#' (ssh: комментарий после whitespace)."""
    out = []
    for t in tokens:
        if t.startswith("#"):
            break
        out.append(t)
    return out


def _unquote(text):
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def _split_line(line):
    """(ключ_как_написан, [значения]) из строки конфига; None для пустых/комментариев/мусора."""
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    if "=" in text and " " not in text.split("=", 1)[0]:
        key, rest = text.split("=", 1)
        tokens = rest.split()
    else:
        parts = text.split(None, 1)
        key, tokens = parts[0], (parts[1].split() if len(parts) > 1 else [])
    tokens = [_unquote(t) for t in _strip_comment_tokens(tokens)]
    if not tokens and key.lower() not in ("host", "match", "include"):
        return None  # ключ без значения — ssh такую строку отверг бы; молча пропускаем
    return key, tokens


def _resolve_include(token, home):
    """Развернуть токен Include: '~/' от home (не от process-HOME — тесты/канон), glob."""
    if token.startswith("~/"):
        pattern = str(Path(home) / token[2:])
    elif _glob.has_magic(token) or not Path(token).is_absolute():
        pattern = str(Path(home) / ".ssh" / token)
    else:
        pattern = token
    return sorted(_glob.glob(pattern))


def parse_config(path, home=None, _depth=0):
    """Распарсить ssh-конфиг в упорядоченный список секций (включая Include-рекурсию).

    Секция: {kind: host|match, patterns: [..], match_all, unverifiable, params: {K: V},
    source}. Отсутствующий файл → [] (фейл-софт). Циклы Include гасятся depth-cap.
    """
    if _depth > _INCLUDE_DEPTH_MAX:
        return []
    path = Path(path)
    home = Path(home) if home else path.parent.parent
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, ValueError, TypeError):
        return []
    sections = []
    for raw in lines:
        parsed = _split_line(raw)
        if parsed is None:
            continue
        key, tokens = parsed
        low = key.lower()
        if low == "include":
            for token in tokens:
                for inc in _resolve_include(token, home):
                    sections.extend(parse_config(inc, home=home, _depth=_depth + 1))
            continue
        if low in ("host", "match"):
            section = {"kind": low, "patterns": [], "match_all": False,
                       "unverifiable": False, "params": {}, "source": str(path)}
            if low == "match":
                i = 0
                while i < len(tokens):
                    tok = tokens[i]
                    if tok == "all":
                        section["match_all"] = True
                    elif tok in _MATCH_EVALUABLE and i + 1 < len(tokens):
                        section["patterns"].extend(tokens[i + 1].split(","))
                        i += 1
                    elif tok in _MATCH_UNVERIFIABLE:
                        section["unverifiable"] = True
                        if i + 1 < len(tokens) and tokens[i + 1] not in (
                                _MATCH_EVALUABLE + _MATCH_UNVERIFIABLE + ("all",)):
                            i += 1
                    i += 1
            else:
                section["patterns"] = list(tokens)
            sections.append(section)
            continue
        if not sections:
            continue  # параметры до первой секции ssh применяет всегда — для аудита игнорируем
        sections[-1]["params"].setdefault(_PARAM_CANONICAL.get(low, key), " ".join(tokens))
    return sections


def host_matches(patterns, hostname):
    """ssh-семантика Host-паттернов: `*`/`?` wildcards, `!`-негация (негативный паттерн
    исключает хост из секции целиком). Только негативные паттерны = «всё кроме»."""
    if not patterns:
        return False
    matched = has_positive = False
    for pat in patterns:
        negated = pat.startswith("!")
        ok = fnmatch.fnmatchcase(hostname, pat[1:] if negated else pat)
        if negated and ok:
            return False
        if not negated:
            has_positive = True
            matched = matched or ok
    return matched if has_positive else True


def section_matches(section, hostname):
    """True/False — секция применима к хосту; None — невычислимо (Match exec/...)."""
    if section.get("kind") == "host":
        return host_matches(section.get("patterns"), hostname)
    if section.get("match_all"):
        return True
    patterns = section.get("patterns") or []
    if patterns:
        return host_matches(patterns, hostname)
    return None  # unverifiable-критерии без host-паттернов


def effective_params(hostname, sections):
    """Словарь эффективных параметров хоста: первое полученное значение побеждает
    (ssh-канон first-obtained-wins). Секции с невычислимым Match пропускаются — их
    применимость аудитор помечает отдельно (unverifiable), а не угадывает."""
    out = {}
    for section in sections:
        if section_matches(section, hostname) is True:
            for key, value in section.get("params", {}).items():
                out.setdefault(key, value)
    return out


def _proxy_is_tunnel(proxy_cmd, socks_port):
    if not proxy_cmd:
        return False
    return f"127.0.0.1:{socks_port}" in str(proxy_cmd)


def audit(config_path=None, *, home=None, socks_port=None):
    """Аудит «SSH ходит через туннель?» по клиентскому конфигу. Read-only, не бросает.

    Возвращает {status, detail} (probe-канон ok/warn/down/unknown):
      down    — хотя бы один известный хост (или дефолт для произвольного) идёт мимо
                туннеля: нет ProxyCommand / none / чужой прокси; или конфига нет вовсе;
      warn    — туннель есть, но нет ServerAlive-дефолтов (сессии «мертвые» при просадках)
                или есть невычислимый Match с ProxyCommand;
      ok      — все известные хосты через 127.0.0.1:<socks> + keepalive-дефолты заданы.
    """
    socks_port = socks_port or XRAY_SOCKS_PORT
    home = Path(home) if home else Path.home()
    config_path = Path(config_path) if config_path else home / ".ssh" / "config"
    sections = parse_config(config_path, home=home)
    if not sections:
        return {"status": "down",
                "detail": "нет ~/.ssh/config или он пуст — SSH пойдёт напрямую (порт 22 закрыт); "
                          "лечится `srouter ssh setup` (#438)"}

    # хосты для проверки: конкретные имена из Host/Match-host + синтетический «произвольный»
    hosts = {"srouter-default.invalid"}
    for section in sections:
        for pat in section.get("patterns") or []:
            pat = pat[1:] if pat.startswith("!") else pat
            if pat and not any(ch in pat for ch in "*?"):
                hosts.add(pat)

    offenders, unverifiable = [], []
    for hostname in sorted(hosts):
        pc = effective_params(hostname, sections).get("ProxyCommand")
        if pc is None:
            offenders.append(f"{hostname}: нет ProxyCommand — пойдёт напрямую")
        elif str(pc).lower() == "none":
            offenders.append(f"{hostname}: ProxyCommand none — напрямую")
        elif not _proxy_is_tunnel(pc, socks_port):
            offenders.append(f"{hostname}: ProxyCommand мимо туннеля ({pc})")
    for section in sections:
        if section.get("unverifiable") and "ProxyCommand" in section.get("params", {}):
            unverifiable.append(section.get("source", "?"))

    detail = "; ".join(offenders)
    status = "down" if offenders else "ok"
    if unverifiable:
        detail = (f"Match с невычислимыми критериями задаёт ProxyCommand ({', '.join(unverifiable)}) "
                  f"— проверьте вручную" + (f"; {detail}" if detail else ""))
        status = "warn"
    if status == "ok":
        defaults = effective_params("srouter-default.invalid", sections)
        try:
            interval = int(defaults.get("ServerAliveInterval", "0"))
            countmax = int(defaults.get("ServerAliveCountMax", "0"))
        except (ValueError, TypeError):
            interval = countmax = 0
        if interval <= 0 or countmax <= 0:
            status = "warn"
            detail = ("нет дефолтов ServerAliveInterval/ServerAliveCountMax — долгие сессии "
                      "выглядят мёртвыми при кратковременных просадках туннеля; "
                      "лечится `srouter ssh setup`")
        else:
            detail = (f"SSH через туннель 127.0.0.1:{socks_port}, keepalive "
                      f"{interval}x{countmax} — долгие сессии переживают просадки")
    return {"status": status, "detail": detail}


def managed_content(socks_port=None, interval=DEFAULT_KEEPALIVE_INTERVAL,
                    countmax=DEFAULT_KEEPALIVE_COUNTMAX):
    """Текст managed-include: дефолты SSH-через-туннель для всех хостов."""
    socks_port = socks_port or XRAY_SOCKS_PORT
    return (
        f"{MANAGED_MARKER} — перегенерируется `srouter ssh setup`, не править вручную\n"
        "Host *\n"
        f"    ProxyCommand nc -x 127.0.0.1:{socks_port} -X 5 %h %p\n"
        f"    ServerAliveInterval {interval}\n"
        f"    ServerAliveCountMax {countmax}\n"
    )


def setup(config_path=None, *, home=None, socks_port=None,
          interval=DEFAULT_KEEPALIVE_INTERVAL, countmax=DEFAULT_KEEPALIVE_COUNTMAX):
    """Ручное действие (#438): managed-include с дефолтами + `Include` в конец ~/.ssh/config.

    Include В КОНЦЕ: our `Host *` работает как дефолт (first-obtained-wins — явные настройки
    кастомных секций сохраняются, опасные из них ловит audit). Idempotent: маркеры не
    дублируются, backup (.srouter-backup-<ts>) только при первой модификации. Не бросает.
    """
    home = Path(home) if home else Path.home()
    ssh_dir = home / ".ssh"
    config_path = Path(config_path) if config_path else ssh_dir / "config"
    managed_path = ssh_dir / MANAGED_INCLUDE_NAME
    content = managed_content(socks_port, interval, countmax)
    include_line = f"{INCLUDE_MARKER} — не удалять\nInclude ~/.ssh/{MANAGED_INCLUDE_NAME}\n"
    changed, backup_path = False, None
    try:
        ssh_dir.mkdir(parents=True, exist_ok=True)
        if not managed_path.exists() or managed_path.read_text(encoding="utf-8") != content:
            managed_path.write_text(content, encoding="utf-8")
            managed_path.chmod(0o600)
            changed = True
        if config_path.exists():
            text = config_path.read_text(encoding="utf-8")
            if INCLUDE_MARKER not in text:
                ts = int(time.time())
                backup_path = config_path.with_name(
                    config_path.name + f".srouter-backup-{ts}")
                backup_path.write_text(text, encoding="utf-8")
                config_path.write_text(text.rstrip("\n") + "\n\n" + include_line,
                                       encoding="utf-8")
                changed = True
        else:
            config_path.write_text(include_line, encoding="utf-8")
            changed = True
        config_path.chmod(0o600)
    except OSError as exc:
        return {"ok": False, "changed": changed, "err": f"setup_failed:{exc}",
                "backup": backup_path, "managed": str(managed_path)}
    return {"ok": True, "changed": changed, "backup": backup_path,
            "managed": str(managed_path), "config": str(config_path)}
