#!/bin/sh
# srouter: codex CLI wrapper (managed)
#
# Codex CLI → напрямую SOCKS5 (xray), минуя privoxy (HTTP-CONNECT-прокси на порту brew-сервиса).
# privoxy портит WebSocket-стриминг Codex → "Reconnecting 1..5/5 → request timed out".
# xray-native SOCKS5 держит WS стабильно. socks5h:// = DNS резолвится на стороне прокси
# (важно за GFW — не утекает локальный DNS). Claude Code остаётся на privoxy (ему нужен HTTP).
#
# Issue #96: terminal-shell наследует HTTP_PROXY=privoxy из ~/.claude/settings.json
# (Claude Code env), и это перебивает launchctl SOCKS5 → Codex молча идёт через privoxy → режёт WS.
# Поэтому launcher сначала СБРАСЫВАЕТ все 8 прокси-переменных через /usr/bin/env -u, а затем
# детерминированно выставляет SOCKS5. Это гарантирует SOCKS-маршрут независимо от того, кто и как
# испортил окружение до нас. Одного -u недостаточно (даст direct) — всегда переустанавливаем.
#
# Issue #144 (подход A): реальный codex НЕ вшивается install-тайм. Wrapper РАНТАЙМ-резолвит его по
# PATH ВЫЗЫВАЮЩЕЙ оболочки, МИНУЯ сам себя (антирекурсия). Один wrapper ловит любую версию codex,
# оказавшуюся в PATH caller'а — в т.ч. после brew upgrade (binary сменился в том же пути → подхватится
# автоматически, reinstall не нужен). Раньше путь вшивался install-тайм в обёртку → >1 codex на диске
# или caller с другим PATH шли напрямую (fail-closed нарушен).
#
# ГРАНИЦА — BEST-EFFORT, НЕ fail-closed: wrapper перехватывает ТОЛЬКО вызовы, дошедшие до этого файла
# (через ~/bin/codex или shell-функцию codex() в ~/.zshrc). Прямой абсолютный путь /opt/.../codex,
# `node .../codex.js`, exec.LookPath с другим PATH (AO-worktree) — НЕ перехватываются. Настоящая
# fail-closed граница = сетевой PF kill-switch (isolate_firewall.py, отдельный слой).
#
# Вызывается shell-функцией codex() из ~/.zshrc по абсолютному пути (srouter install) — тогда порядок
# brew в PATH не важен. Для не-zsh вызывающих сторон (bash, command codex, GUI) стабильная точка
# входа — сам этот launcher ~/bin/codex.
# Первый комментарий — маркер srouter (uninstall удаляет только своё, чужой wrapper не трогает).
PROXY="__SROUTER_CODEX_PROXY_URL__"
LOOPBACK="__SROUTER_CODEX_NO_PROXY__"

# realpath себя ($0): нужен, чтобы при обходе PATH пропустить самого себя (антирекурсия). readlink -f
# доступен в macOS /bin/sh (BSD readlink поддерживает -f с Monterey+); fallback — сам $0 без -f.
SELF="$0"
SELF_REAL="$SELF"
if command -v readlink >/dev/null 2>&1; then
  _rl="$(readlink -f "$SELF" 2>/dev/null)" && [ -n "$_rl" ] && SELF_REAL="$_rl"
fi

# Рантайм-резолв codex по PATH вызывающего, минуя сам wrapper. Обходим каждую директорию PATH, ищем
# первый codex, чей realpath ≠ realpath wrapper'а. Так wrapper никогда не exec'нет сам себя (#144).
_codex_bin=""
_save_IFS="$IFS"
IFS=":"
for _dir in $PATH; do
  IFS="$_save_IFS"
  [ -z "$_dir" ] && continue
  _cand="$_dir/codex"
  # -x проверяет executable (как test -x); пропускаем директории/несуществующие.
  [ -f "$_cand" ] && [ -x "$_cand" ] || continue
  _cand_real="$_cand"
  if command -v readlink >/dev/null 2>&1; then
    _cr="$(readlink -f "$_cand" 2>/dev/null)" && [ -n "$_cr" ] && _cand_real="$_cr"
  fi
  # Антирекурсия: пропускаем самих себя (wrapper может быть в PATH и/или симлинком).
  [ "$_cand_real" = "$SELF_REAL" ] && continue
  _codex_bin="$_cand"
  break
done
IFS="$_save_IFS"

if [ -z "$_codex_bin" ]; then
  printf 'srouter codex wrapper: реальный codex не найден в PATH (минуя wrapper). Установи codex.\n' >&2
  exit 127
fi

exec /usr/bin/env \
  -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  -u http_proxy -u https_proxy -u all_proxy \
  -u NO_PROXY -u no_proxy \
  HTTP_PROXY="$PROXY" HTTPS_PROXY="$PROXY" ALL_PROXY="$PROXY" \
  http_proxy="$PROXY" https_proxy="$PROXY" all_proxy="$PROXY" \
  NO_PROXY="$LOOPBACK" no_proxy="$LOOPBACK" \
  "$_codex_bin" "$@"
