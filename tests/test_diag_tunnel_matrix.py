"""Shell-тесты diag-tunnel-matrix.sh: матрица «цели × раунды» через SOCKS-туннель + вердикт.

Фаза 0 (эксперимент github-direct 2026-10-11): «туннель умер целиком» опровергнут —
умирают ЦЕЛИ (sg-1 не достукивается до Google), а туннель жив. Скрипт делает это
наблюдение повторяемым: N раундов по 4 целям через socks5h, таблица + вердикт
(«всё живо» / «всё мёртво» / «цель-селективно: …»). Канон подмены бинарника —
как в diag-proxy.sh (SROUTER_CURL/SROUTER_STATE_PATH/SROUTER_SOCKS).
"""
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "diag-tunnel-matrix.sh"


def _run(script_args, curl_behavior, tmp_path, state=None):
    """Запустить скрипт с fake curl; curl_behavior — 'selective'|'all_dead'|'all_ok'."""
    if curl_behavior == "all_dead":
        body = 'exit 28\n'
    elif curl_behavior == "all_ok":
        body = 'printf "200/0.1s"\nexit 0\n'
    else:  # selective: github/anthropic живы, youtube/gstatic мертвы (матрица 10-11)
        body = (
            'case "$*" in *youtube.com*|*gstatic.com*) exit 28;; esac\n'
            'printf "200/0.1s"\nexit 0\n'
        )
    fake = tmp_path / "fake_curl.sh"
    fake.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    fake.chmod(0o755)
    state_path = tmp_path / "srouter.local.json"
    if state is None:
        state_path.write_text(
            '{"nodes": [{"name": "sg-1", "enabled": true,'
            ' "probe": {"socks_port": 11080}}]}',
            encoding="utf-8",
        )
        state = state_path
    env = os.environ.copy()
    env.update({
        "SROUTER_CURL": str(fake),
        "SROUTER_STATE_PATH": str(state),
        "SROUTER_PYTHON": sys.executable,
    })
    return subprocess.run(
        ["bash", str(SCRIPT), "1"], capture_output=True, env=env, text=True, timeout=60,
    )


def test_bash_syntax():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


def test_selective_targets_produce_target_selective_verdict(tmp_path):
    """github жив, youtube/gstatic мертвы → «цель-селективно», а не «всё мёртво»."""
    result = _run(["1"], "selective", tmp_path)
    assert result.returncode == 0, result.stderr
    assert "цель-селективно" in result.stdout
    assert "youtube.com" in result.stdout  # мёртвая цель названа по имени
    assert "github.com" in result.stdout


def test_all_dead_produce_tunnel_dead_verdict(tmp_path):
    """Все 4 цели мертвы в раунде → «всё мёртво» (туннель/узел целиком)."""
    result = _run(["1"], "all_dead", tmp_path)
    assert result.returncode == 0, result.stderr
    verdicts = [l for l in result.stdout.splitlines() if l.startswith("Вердикт:")]
    assert verdicts == ["Вердикт: всё мёртво — туннель/узел целиком (не цель-селективно)."]


def test_all_ok_produce_alive_verdict(tmp_path):
    result = _run(["1"], "all_ok", tmp_path)
    assert result.returncode == 0, result.stderr
    assert "всё живо" in result.stdout


def test_curl_target_is_socks_proxy_from_state(tmp_path):
    """Цель curl — socks5h порт активного узла из local.json (канон #366)."""
    capture = tmp_path / "curl.args"
    fake = tmp_path / "recorder.sh"
    fake.write_text(
        "#!/usr/bin/env bash\n"
        'printf \'%s\\n\' "$@" >> "$SROUTER_CURL_CAPTURE"\n'
        'printf "200/0.1s"\nexit 0\n',
        encoding="utf-8",
    )
    fake.chmod(0o755)
    state_path = tmp_path / "srouter.local.json"
    state_path.write_text(
        '{"active_node": {"name": "hk-1"},'
        ' "nodes": ['
        '{"name": "sg-1", "enabled": true, "probe": {"socks_port": 11080}},'
        '{"name": "hk-1", "enabled": true, "probe": {"socks_port": 11081}}]}',
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.update({
        "SROUTER_CURL": str(fake),
        "SROUTER_STATE_PATH": str(state_path),
        "SROUTER_PYTHON": sys.executable,
        "SROUTER_CURL_CAPTURE": str(capture),
    })
    result = subprocess.run(
        ["bash", str(SCRIPT), "1"], capture_output=True, env=env, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    args = capture.read_text(encoding="utf-8")
    assert "socks5h://127.0.0.1:11081" in args  # активный hk-1
    assert "11080" not in args
