#!/usr/bin/env bash
# Матрица «цели × раунды» через SOCKS-туннель: какая цель мертва, а какая жива.
# Ответ на вопрос «как github может флапать в туннеле, если всё должно флапать?»:
# матрица показывает, что умирают ЦЕЛИ (например, Google с конкретного узла),
# а не туннель целиком (наблюдение 2026-10-11: github 200, youtube/gstatic dead).
#
# Использование:  ./diag-tunnel-matrix.sh [раунды]   (по умолчанию 2)
# Вердикт: «всё живо» | «всё мёртво» | «цель-селективно: <мертвы …>».
#
# Канон подмены бинарника — как в diag-proxy.sh: SROUTER_CURL/SROUTER_STATE_PATH/
# SROUTER_SOCKS; SOCKS-цель берётся из local.json (активный узел → probe.socks_port).

ROUNDS="${1:-2}"
CURL_BIN="${SROUTER_CURL:-curl}"
PY_BIN="${SROUTER_PYTHON:-python3}"

STATE_PATH="${SROUTER_STATE_PATH:-$(dirname "$0")/srouter.local.json}"
SOCKS="${SROUTER_SOCKS:-}"
if [ -z "$SOCKS" ] && [ -f "$STATE_PATH" ]; then
  SOCKS_PORT=$("$PY_BIN" - "$STATE_PATH" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        state = json.load(fh)
except Exception:
    raise SystemExit(0)
active = state.get("active_node")
active_name = active.get("name") if isinstance(active, dict) else None
fallback = None
for node in state.get("nodes") or []:
    if not (isinstance(node, dict) and node.get("enabled")):
        continue
    probe = node.get("probe") if isinstance(node.get("probe"), dict) else {}
    port = probe.get("socks_port")
    if not (isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535):
        continue
    if node.get("name") == active_name:
        print(port)
        break
    if fallback is None:
        fallback = port
else:
    if fallback is not None:
        print(fallback)
PY
)
  [ -n "$SOCKS_PORT" ] && SOCKS="socks5h://127.0.0.1:$SOCKS_PORT"
fi

# Четыре цели: github (эксперимент), Claude (strict — только туннель), Google ×2
# (наблюдение 10-11: с sg-1 именно они мертвы, github жив — дискриминатор).
TARGETS=(github.com api.anthropic.com youtube.com www.gstatic.com)

if [ -z "$SOCKS" ]; then
  echo "SOCKS-цель не найдена (нет local.json/probe.socks_port; задай SROUTER_SOCKS)" >&2
  exit 1
fi
echo "Матрица туннеля: $SOCKS, раундов: $ROUNDS @ $(date '+%Y-%m-%d %H:%M:%S')"

# probe <host>: первый цифрой код ответа (2xx-4xx = хост ответил, путь жив),
# при обрыве/таймауте — FAIL(rc). rc ловим отдельно: при провале curl -w печатает
# частичный write-out ('000/...'), склеивать его с FAIL нельзя (канон #82).
probe() {
  local out
  out=$("$CURL_BIN" -x "$SOCKS" -s -o /dev/null --max-time 12 \
        -w "%{http_code}/%{time_total}s" "https://$1/" 2>/dev/null)
  local rc=$?
  if [ $rc -ne 0 ]; then echo "FAIL($rc)"; else echo "$out"; fi
}

declare -a DEAD=()
for h in "${TARGETS[@]}"; do
  row=""
  ok=0
  for _ in $(seq "$ROUNDS"); do
    v=$(probe "$h")
    row="$row $v"
    case "$v" in [2-4]*) ok=$((ok + 1));; esac
  done
  if [ "$ok" -eq "$ROUNDS" ]; then
    verdict="жив"
  elif [ "$ok" -eq 0 ]; then
    verdict="МЁРТВ"; DEAD+=("$h")
  else
    verdict="флап"; DEAD+=("$h")
  fi
  printf "%-22s |%s  → %s\n" "$h" "$row" "$verdict"
done

echo
if [ "${#DEAD[@]}" -eq "${#TARGETS[@]}" ]; then
  echo "Вердикт: всё мёртво — туннель/узел целиком (не цель-селективно)."
elif [ "${#DEAD[@]}" -eq 0 ]; then
  echo "Вердикт: всё живо."
else
  dead_list="$(printf '%s ' "${DEAD[@]}")"
  echo "Вердикт: цель-селективно (туннель жив) — мертвы: $dead_list."
  echo "Мёртвая цель недостижима С УЗЛА (DNS/блок на VPS) — чинится на сервере узла."
fi
