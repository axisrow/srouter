"""Тумблер Go-модулей в обход GFW: srouter go-proxy status/enable/disable (2026-09-30).

proxy.golang.org — GFW-чёрная дыра напрямую (эмпирика 2026-09-30: direct TCP-timeout,
через socks5 10808 — 200 за 1.2с; тот же класс, что github.com 09-29). Особенности Go,
определяющие дизайн:

- Транспортный прокси читается ТОЛЬКО из env процесса: `go env -w HTTPS_PROXY=...`
  отвергается («unknown go command variable»), персистентного аналога git-конфига нет.
- `go env -w GOPROXY=...` персистентен (GOENV-файл), но GOPROXY — адрес МОДУЛЬНОГО прокси,
  не транспортного; зеркало goproxy.cn доступно из Китая напрямую, без туннеля.

Два режима:
  mirror — GOPROXY=https://goproxy.cn,direct (зеркало в Китае; VPS-независимо, канон #199);
  tunnel — marker-managed wrapper ~/bin/go (прецедент codex-wrappers), экспортирующий
           HTTPS_PROXY/HTTP_PROXY=socks5://127.0.0.1:10808 + NO_PROXY (loopback + z.ai).

Состояние = сам GOENV-файл + сам wrapper — единого srouter-state нет (канон git_proxy:
«состояние = сам ~/.gitconfig»). Все функции fail-soft (probe-канон), мутации под
cross-process flock (упрощение против git_proxy: у go env нет multi-value/txn-семантики —
одна single-value запись; достаточно lock + read-back verify).

Force-гейты (#307-канон): чужой GOPROXY и чужой (unmanaged) ~/bin/go без force не трогаем.
"""
import contextlib
import fcntl
import os
import shutil
from pathlib import Path

import sys_probe

GO = "/opt/homebrew/bin/go"
MIRROR_GOPROXY = "https://goproxy.cn,direct"
OFFICIAL_PREFIX = "https://proxy.golang.org"
TUNNEL_PROXY = "socks5://127.0.0.1:10808"
# Канон zai-direct-no-proxy: z.ai/.z.ai безусловно + loopback (BUILTIN_FALLBACK_NO_PROXY direct_first).
NO_PROXY_VALUE = "localhost,127.0.0.1,::1,z.ai,.z.ai"
WRAPPER_MARKER = "# srouter: go proxy wrapper (managed)"
WRAPPER_PATH = Path.home() / "bin" / "go"
_LOCKFILE = Path.home() / ".srouter-go-proxy.lock"
_MODES = ("mirror", "tunnel")


@contextlib.contextmanager
def _mutation_lock():
    """Cross-process flock (эталон local_state._routing_config_lock #139). Не бросает."""
    fd = None
    try:
        fd = os.open(_LOCKFILE, os.O_CREAT | os.O_RDWR, 0o644)
        fcntl.flock(fd, fcntl.LOCK_EX)
    except OSError:
        pass  # лок не критичен: одиночная запись single-value всё равно атомарна
    try:
        yield
    finally:
        if fd is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def _run_go(args, timeout=10):
    return sys_probe.run([GO, *args], timeout=timeout)


def goproxy_layer():
    """Эффективный GOPROXY из реального go: {value, state} — state ∈
    unknown | unset | default | mirror | foreign | direct. Не бросает."""
    r = _run_go(["env", "GOPROXY"])
    if r.get("timeout") or r.get("rc") != 0:
        return {"value": None, "state": "unknown", "err": r.get("err")}
    value = (r.get("out") or "").strip()
    if not value:
        return {"value": value, "state": "unset"}
    if value == "direct":
        return {"value": value, "state": "direct"}
    if value == MIRROR_GOPROXY:
        return {"value": value, "state": "mirror"}
    if value.startswith(OFFICIAL_PREFIX):
        return {"value": value, "state": "default"}
    return {"value": value, "state": "foreign"}


def wrapper_layer(path=None):
    """{present, managed, target}: файл без маркера — чужой бинарь (не трогаем без force)."""
    wrapper = Path(path) if path else WRAPPER_PATH
    try:
        text = wrapper.read_text(encoding="utf-8")
    except OSError:
        return {"present": False, "managed": False, "target": None}
    lines = text.splitlines()
    managed = bool(lines) and lines[0].strip() == WRAPPER_MARKER  # whole-line канон
    target = None
    for line in reversed(lines):
        if line.startswith("exec "):
            # exec "/path" "$@" → кавычки снятия: целевой путь писался в кавычках
            target = line.split()[1].strip('"') if len(line.split()) > 1 else None
            break
    return {"present": True, "managed": managed, "target": target}


def _real_go(path=None):
    """Путь реального go для wrapper: константа, иначе первый go в PATH — не сам wrapper
    (~/bin стоит в PATH раньше /opt/homebrew/bin — иначе обёртка сама себя бы exec-ала)."""
    wrapper = Path(path) if path else WRAPPER_PATH
    if os.path.exists(GO):
        return GO
    for d in os.environ.get("PATH", "").split(os.pathsep):
        cand = Path(d) / "go"
        if cand.exists():
            try:
                if cand.resolve() != wrapper.resolve():
                    return str(cand)
            except OSError:
                return str(cand)
    return None


def _wrapper_text(real_go):
    return "\n".join([
        WRAPPER_MARKER,
        "# srouter go-proxy tunnel: Go-модули через туннель (proxy.golang.org — GFW-блок).",
        f'export HTTPS_PROXY="{TUNNEL_PROXY}"',
        f'export HTTP_PROXY="{TUNNEL_PROXY}"',
        f'export NO_PROXY="{NO_PROXY_VALUE}"',
        f'export no_proxy="{NO_PROXY_VALUE}"',
        f'exec "{real_go}" "$@"',
        "",
    ])


def enable(mode="mirror", force=False):
    """Включить режим. mirror → go env -w; tunnel → wrapper ~/bin/go. Read-back verify."""
    if mode not in _MODES:
        return {"ok": False, "error": f"неизвестный mode {mode!r} (ожидается {'|'.join(_MODES)})"}
    with _mutation_lock():
        if mode == "mirror":
            cur = goproxy_layer()
            if cur["state"] == "foreign" and not force:
                return {"ok": False,
                        "error": f"чужой GOPROXY={cur['value']!r} — нужен --force (#307)"}
            r = _run_go(["env", "-w", f"GOPROXY={MIRROR_GOPROXY}"])
            if r.get("timeout") or r.get("rc") != 0:
                return {"ok": False, "error": f"go env -w failed: {r.get('err')}"}
            if goproxy_layer()["value"] != MIRROR_GOPROXY:
                return {"ok": False, "error": "read-back verify failed после go env -w"}
            return {"ok": True, "mode": "mirror", "goproxy": MIRROR_GOPROXY}

        # tunnel
        real = _real_go()
        if not real:
            return {"ok": False, "error": "исполняемый go не найден (ни константа, ни PATH)"}
        w = wrapper_layer()
        if w["present"] and not w["managed"] and not force:
            return {"ok": False,
                    "error": f"чужой {WRAPPER_PATH} (без маркера) — нужен --force (#307)"}
        from local_state import _atomic_write_text  # канон atomic-save (tmp+fsync+rename) #139
        if not _atomic_write_text(WRAPPER_PATH, _wrapper_text(real)):
            return {"ok": False, "error": "не удалось записать wrapper"}
        try:
            os.chmod(WRAPPER_PATH, 0o755)
        except OSError as exc:
            return {"ok": False, "error": f"chmod wrapper: {exc}"}
        w2 = wrapper_layer()
        if not w2["managed"] or w2["target"] != real:
            return {"ok": False, "error": "read-back verify failed после записи wrapper"}
        return {"ok": True, "mode": "tunnel", "wrapper": str(WRAPPER_PATH), "target": real}


def disable(full=False, force=False):
    """Выключить: снять wrapper (если managed); full → снять managed mirror-GOPROXY.
    Снятые значения возвращаются в removed[] для ручного восстановления (канон git-proxy)."""
    removed = []
    errors = []
    with _mutation_lock():
        w = wrapper_layer()
        if w["present"]:
            if not w["managed"] and not force:
                errors.append(f"чужой {WRAPPER_PATH} (без маркера) — нужен --force (#307)")
            else:
                removed.append(f"wrapper {WRAPPER_PATH} (target={w['target']})")
                try:
                    WRAPPER_PATH.unlink()
                except OSError as exc:
                    errors.append(f"unlink wrapper: {exc}")
                if WRAPPER_PATH.exists():
                    errors.append("read-back verify failed: wrapper на месте после unlink")
        if full:
            cur = goproxy_layer()
            if cur["state"] == "mirror":
                r = _run_go(["env", "-u", "GOPROXY"])
                if r.get("timeout") or r.get("rc") != 0:
                    errors.append(f"go env -u failed: {r.get('err')}")
                elif goproxy_layer()["state"] == "mirror":
                    errors.append("read-back verify failed: GOPROXY не снят")
                else:
                    removed.append(f"GOPROXY={MIRROR_GOPROXY} (go env -u)")
            elif cur["state"] == "foreign":
                if not force:
                    errors.append(f"чужой GOPROXY={cur['value']!r} — нужен --force (#307)")
                else:
                    r = _run_go(["env", "-u", "GOPROXY"])
                    if r.get("timeout") or r.get("rc") != 0:
                        errors.append(f"go env -u failed: {r.get('err')}")
                    elif goproxy_layer()["state"] == "foreign":
                        errors.append("read-back verify failed: чужой GOPROXY не снят")
                    else:
                        removed.append(f"GOPROXY={cur['value']} (go env -u --force)")
    if errors:
        return {"ok": False, "error": "; ".join(errors), "removed": removed}
    return {"ok": True, "removed": removed}


def status():
    """Truthful слои + вердикт: что сделает свежий `go build` в новом shell."""
    w = wrapper_layer()
    g = goproxy_layer()
    env_proxy = (os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
                 or os.environ.get("https_proxy") or os.environ.get("http_proxy"))
    if w["managed"]:
        verdict = "tunnel"
    elif g["state"] == "mirror":
        verdict = "mirror"
    elif g["state"] == "foreign":
        verdict = "foreign"
    else:
        verdict = "direct"  # proxy.golang.org напрямую — GFW-блок (эмпирика 2026-09-30)
    return {"wrapper": w, "goproxy": g, "env_proxy": env_proxy, "verdict": verdict}
