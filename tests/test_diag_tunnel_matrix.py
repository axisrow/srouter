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


def _run(script_args, curl_behavior, tmp_path, state=None, speed="500000Bps"):
    """Запустить скрипт с fake curl; curl_behavior — 'selective'|'all_dead'|'all_ok'."""
    if curl_behavior == "all_dead":
        body = 'exit 28\n'
    elif curl_behavior == "all_ok":
        body = 'printf "200/0.1s/%s"\nexit 0\n' % speed
    else:  # selective: github/anthropic живы, youtube/gstatic мертвы (матрица 10-11)
        body = (
            'case "$*" in *youtube.com*|*gstatic.com*) exit 28;; esac\n'
            'printf "200/0.1s/%s"\nexit 0\n' % speed
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


def test_low_speed_of_live_targets_is_bandwidth_window_verdict(tmp_path):
    """10-11: DPI-окно душит туннель по скорости (~10 Bps) — «живые» ответы крошечные,
    матрица обязана звать это битрейт-окном, а не цель-селективностью (сервер чист).
    #428: битрейт-окно — ТОЛЬКО когда ВСЕ цели отвечали: душение = медленные ответы,
    FAIL(28) (ни одного ответа) — недоступность цели, это цель-селективная смерть."""
    result = _run(["1"], "all_ok", tmp_path, speed="100Bps")
    assert result.returncode == 0, result.stderr
    assert "битрейт-окно" in result.stdout
    assert "цель-селективно" not in result.stdout.split("Вердикт:")[-1]


def test_dead_target_is_not_reported_as_bandwidth_window(tmp_path):
    """#428, прогон 2026-10-14 11:44: github МЁРТВ (FAIL×2), живые цели медленные (911Bps) —
    вердикт обязан быть «цель-селективно — мертвы: …», а не «битрейт-окно: хосты отвечают»
    (мёртвая цель НЕ отвечала ни в одном раунде, «ждать окно» — ложный совет)."""
    result = _run(["1"], "selective", tmp_path, speed="911Bps")
    assert result.returncode == 0, result.stderr
    verdict = result.stdout.split("Вердикт:")[-1]
    assert "цель-селективно" in verdict, f"мёртвая цель = цель-селективно, got: {verdict}"
    assert "битрейт-окно" not in verdict, f"FAIL(28) ≠ душение, got: {verdict}"
    assert "youtube.com" in verdict  # мёртвая цель названа в вердикте
    # честность второй строки: живые цели МЕДЛЕННЫЕ — нельзя печатать «Живые цели быстрые»
    assert "Живые цели быстрые" not in result.stdout


def test_fast_round_of_flapping_target_counts_toward_max_speed(tmp_path):
    """#428, прогон 2026-10-14 09:42: флап-цель github (FAIL → 200/124462Bps) — скорость
    успешного раунда ЛЮБОЙ цели участвует в max_speed; иначе вердикт считал «макс 1099 Bps»
    по одним «жив»-целям и звал битрейт-окном ситуацию, где большие ответы пролезали быстро."""
    count = tmp_path / "round.count"
    fake = tmp_path / "fake_curl.sh"
    fake.write_text(
        "#!/usr/bin/env bash\n"
        'case "$*" in *github.com*)\n'
        '  n=$(cat "$SROUTER_FAKE_COUNT" 2>/dev/null || echo 0)\n'
        '  n=$((n+1)); printf "%s" "$n" > "$SROUTER_FAKE_COUNT"\n'
        '  if [ "$n" -eq 1 ]; then exit 28; fi\n'
        '  printf "200/4.6s/124462Bps"; exit 0;;\n'
        "esac\n"
        'printf "200/1.4s/1099Bps"; exit 0\n',
        encoding="utf-8",
    )
    fake.chmod(0o755)
    state_path = tmp_path / "srouter.local.json"
    state_path.write_text(
        '{"nodes": [{"name": "sg-1", "enabled": true,'
        ' "probe": {"socks_port": 11080}}]}',
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.update({
        "SROUTER_CURL": str(fake),
        "SROUTER_STATE_PATH": str(state_path),
        "SROUTER_PYTHON": sys.executable,
        "SROUTER_FAKE_COUNT": str(count),
    })
    result = subprocess.run(
        ["bash", str(SCRIPT), "2"], capture_output=True, env=env, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "цель-селективно" in result.stdout, result.stdout
    assert "124462" in result.stdout, \
        f"быстрый раунд флап-цели обязан попасть в max_speed вердикта, got: {result.stdout}"
    # дискриминатор «скорость учтена ВЕРДИКТОМ»: при игноре быстрого раунда max_speed=1099
    # (только «жив»-цели) и печаталась бы «Живые цели медленные», а не быстрые
    assert "Живые цели быстрые" in result.stdout, result.stdout
    assert "битрейт-окно" not in result.stdout


def test_curl_target_is_socks_proxy_from_state(tmp_path):
    """Цель curl — socks5h порт активного узла из local.json (канон #366)."""
    capture = tmp_path / "curl.args"
    fake = tmp_path / "recorder.sh"
    fake.write_text(
        "#!/usr/bin/env bash\n"
        'printf \'%s\\n\' "$@" >> "$SROUTER_CURL_CAPTURE"\n'
        'printf "200/0.1s/500000Bps"\nexit 0\n',
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
