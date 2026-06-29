"""Ранжирование узлов и ручной two-phase active-node apply.

v1 только считает и применяет явный выбор пользователя. Автопереключения здесь нет:
recommendation возвращает совет, а select_node меняет active только после успешного
render-pending + restart gate.
"""
from __future__ import annotations

import copy
import subprocess
import threading

import gen_xray_config
import local_state


BREW = "/opt/homebrew/bin/brew"
XRAY_CONFIG_PATH = "/opt/homebrew/etc/xray/config.json"
XRAY_RESTART_CMD = [BREW, "services", "restart", "xray"]

W_TPUT, W_LAT, W_LOSS = 0.45, 0.35, 0.20
SWITCH_MARGIN = 0.05
_RESTART_TIMEOUT_SEC = 40
_UNUSABLE_STATUSES = {"down", "unknown"}
_SELECT_LOCK = threading.Lock()


def _num(value):
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _clamp(value, low=0.0, high=1.0):
    return max(low, min(high, value))


def _norm(value, values, *, higher_is_better=True):
    """Min-max нормализация в [0,1]; при нулевом разбросе метрика считается лучшей."""
    if value is None:
        return 0.0
    nums = [v for v in values if v is not None]
    if not nums:
        return 0.0
    lo, hi = min(nums), max(nums)
    if hi == lo:
        return 1.0
    n = (value - lo) / (hi - lo)
    return n if higher_is_better else 1.0 - n


def _is_usable(metrics):
    if not isinstance(metrics, dict):
        return False
    if metrics.get("status") in _UNUSABLE_STATUSES:
        return False
    return _num(metrics.get("ping_ms")) is not None


def score_node(metrics):
    """Pure score одного узла; та же нормализация, что у rank_nodes для single-node окна."""
    ranked = rank_nodes([metrics])
    return ranked[0].get("score") if ranked else None


def rank_nodes(metrics_list):
    """Отсортировать узлы best->worst, сохранив негодные измерения в конце."""
    rows = [copy.deepcopy(m) for m in metrics_list if isinstance(m, dict)] if isinstance(metrics_list, list) else []
    usable = [m for m in rows if _is_usable(m)]
    pings = [_num(m.get("ping_ms")) for m in usable]
    throughputs = [_num(m.get("throughput_kbps")) for m in usable]

    for row in rows:
        if not _is_usable(row):
            row["score"] = None
            row["rank"] = None
            continue
        ping = _num(row.get("ping_ms"))
        throughput = _num(row.get("throughput_kbps"))
        loss = _num(row.get("loss"))
        lat_score = _norm(ping, pings, higher_is_better=False)
        tput_score = _norm(throughput, throughputs, higher_is_better=True)
        loss_score = 1.0 - _clamp((loss or 0.0) / 100.0)
        row["score"] = W_TPUT * tput_score + W_LAT * lat_score + W_LOSS * loss_score
        row["rank"] = 0

    rows.sort(
        key=lambda m: (
            m.get("score") is None,
            -(m.get("score") or 0.0),
            str(m.get("name") or ""),
        )
    )

    rank = 1
    for row in rows:
        if row.get("score") is None:
            row["rank"] = None
            continue
        row["rank"] = rank
        rank += 1
    return rows


def recommendation(metrics_list, active_name):
    """Вернуть observe/manual рекомендацию без мутаций и без сетевых вызовов."""
    ranked = rank_nodes(metrics_list)
    score_window = [
        {"name": item.get("name"), "score": item.get("score"), "status": item.get("status")}
        for item in ranked
    ]
    usable = [item for item in ranked if item.get("score") is not None]
    if not usable:
        return {"active": active_name, "best": None, "score_window": score_window, "recommendation": "no-data"}

    best = usable[0]
    best_name = best.get("name")
    active = next((item for item in usable if item.get("name") == active_name), None)
    if best_name == active_name:
        rec = "hold"
    elif active is None or (best.get("score") or 0.0) - (active.get("score") or 0.0) > SWITCH_MARGIN:
        rec = f"switch:{best_name}"
    else:
        rec = "hold"
    return {"active": active_name, "best": best_name, "score_window": score_window, "recommendation": rec}


def _default_runner(cmd_list, timeout):
    """Локальный runner в формате dashboard.run: список аргументов, shell не используется."""
    if not isinstance(cmd_list, list):
        return {"rc": None, "out": "", "err": "cmd must be list", "timeout": True}
    try:
        proc = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout)
        return {"rc": proc.returncode, "out": proc.stdout.strip(), "err": proc.stderr.strip(), "timeout": False}
    except subprocess.TimeoutExpired:
        return {"rc": None, "out": "", "err": "timeout", "timeout": True}
    except Exception as exc:
        return {"rc": None, "out": "", "err": str(exc), "timeout": True}


def _active_name(state_path=None):
    active = local_state.active_node(path=state_path) or {}
    return active.get("name") if isinstance(active, dict) else None


def _pending_name(state_path=None):
    state, readable = local_state.load_state_checked(path=state_path)
    if not readable:
        return None
    active = state.get("active_node") if isinstance(state, dict) else {}
    if not isinstance(active, dict):
        return None
    return active.get("pending")


def _run_restart(runner):
    try:
        result = runner(list(XRAY_RESTART_CMD), _RESTART_TIMEOUT_SEC)
    except Exception as exc:
        return {"rc": None, "out": "", "err": str(exc), "timeout": True}
    return result if isinstance(result, dict) else {"rc": None, "out": "", "err": "bad runner result", "timeout": True}


def _restart_failed(result):
    return bool(result.get("timeout")) or result.get("rc") != 0


def _rollback(state_path, config_path, runner):
    """Blocking откат: если previous-конфиг не восстановлен, вызывающий обязан сигналить failure."""
    try:
        local_state.clear_pending(path=state_path)
    except Exception as exc:
        return {"ok": False, "error": f"clear pending failed: {exc}", "restore_ok": False}
    try:
        restored = gen_xray_config.write_config(config_path, state_path=state_path)
    except Exception as exc:
        return {"ok": False, "error": f"rollback config restore failed: {exc}", "restore_ok": False}
    if not restored:
        return {"ok": False, "error": "rollback config restore failed", "restore_ok": False}
    restart = _run_restart(runner)
    return {"ok": True, "restore_ok": True, "restart": restart}


def _rollback_failed(previous, failed_step, rollback, *, error=None, extra=None):
    out = {
        "ok": False,
        "active": previous,
        "step": "rollback_failed",
        "failed_step": failed_step,
        "error": rollback.get("error") or error or "rollback failed",
        "rollback": rollback,
    }
    if isinstance(extra, dict):
        out.update(extra)
    return out


def _pending_active_hook(pending_name, state_path):
    """outbound_hook: только active-outbound заменяется на outbound pending-узла."""
    def hook(outbound, *, node, role):
        if role != "active":
            return outbound
        try:
            pending = local_state.get_node(pending_name, path=state_path)
            rendered = gen_xray_config._vless_outbound(pending, "active", state_path=state_path)
            return rendered if isinstance(rendered, dict) and rendered else outbound
        except Exception:
            return outbound

    return hook


def select_node(name, *, enabled_names, runner=None, state_path=None, config_path=XRAY_CONFIG_PATH):
    """Безопасно применить ручной active-node выбор. Функция никогда не бросает наружу."""
    with _SELECT_LOCK:
        return _select_node_locked(
            name,
            enabled_names=enabled_names,
            runner=runner,
            state_path=state_path,
            config_path=config_path,
        )


def _select_node_locked(name, *, enabled_names, runner=None, state_path=None, config_path=XRAY_CONFIG_PATH):
    runner = runner or _default_runner
    previous = None
    begun = False
    try:
        previous = _active_name(state_path)
        allowed = {n for n in enabled_names if isinstance(n, str)} if enabled_names is not None else set()
        if name not in allowed:
            return {"ok": False, "active": previous, "step": "whitelist", "error": "node not enabled or unknown"}

        local_state.begin_active_node_change(name, path=state_path)
        begun = True
        if _pending_name(state_path) != name:
            local_state.clear_pending(path=state_path)
            return {"ok": False, "active": previous, "step": "begin", "error": "pending was not written"}

        rendered = gen_xray_config.write_config(
            config_path,
            state_path=state_path,
            outbound_hook=_pending_active_hook(name, state_path),
        )
        if not rendered:
            rollback = _rollback(state_path, config_path, runner)
            if not rollback.get("ok"):
                return _rollback_failed(previous, "generate", rollback, error="xray config generation failed")
            return {"ok": False, "active": previous, "step": "generate", "error": "xray config generation failed"}

        restart = _run_restart(runner)
        if _restart_failed(restart):
            rollback = _rollback(state_path, config_path, runner)
            if not rollback.get("ok"):
                return _rollback_failed(
                    previous,
                    "restart",
                    rollback,
                    error=restart.get("err") or "xray restart failed",
                    extra={"restart": restart},
                )
            return {
                "ok": False,
                "active": previous,
                "step": "restart",
                "error": restart.get("err") or "xray restart failed",
                "restart": restart,
            }

        local_state.commit_active_node_change(name, path=state_path)
        current = _active_name(state_path)
        if current != name:
            rollback = _rollback(state_path, config_path, runner)
            if not rollback.get("ok"):
                return _rollback_failed(previous, "commit", rollback, error="active node was not committed")
            return {"ok": False, "active": previous, "step": "commit", "error": "active node was not committed"}
        return {"ok": True, "active": current, "step": "done"}
    except Exception as exc:
        if begun:
            rollback = _rollback(state_path, config_path, runner)
            if not rollback.get("ok"):
                return _rollback_failed(previous, "internal", rollback, error=str(exc))
        return {"ok": False, "active": previous, "step": "internal", "error": str(exc)}
