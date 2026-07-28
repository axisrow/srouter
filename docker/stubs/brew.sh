#!/bin/sh
# srouter acceptance: stub macOS /opt/homebrew/bin/brew (path 3, stateful ТОЛЬКО для services
# start/stop/restart — issue #116 п.2: усилено по реальной потребности, не заранее).
# srouter зовёт brew через runner([BREW, sub, ...]). Эмулируем ответы по cmd[1], достаточные для
# install/uninstall: services-list пустой (чистая установка с нуля), install — успех.
#
# Контракт (по первоисточнику install_lib.py):
#   services list             → rc=0, header "Name Status User File Log Plist" без строк.
#                               parse_brew_services парсит "name state" — пустой вывод → states={} →
#                               build_plan видит service="none" (чистая ветка установки с нуля).
#   services start/stop/restart <name> → rc=0 + РЕАЛЬНЫЙ listener на порту сервиса (см. ниже).
#   list --versions <name>    → rc=0, "<name> <version>" (пакет «установлен», чтобы _ensure_package
#                               не пытался реально brew install).
#   install <name>            → rc=0.
#   --version                 → rc=0, фейковая версия.
#
# Stateful services (issue #116 п.2, найдено при прогоне acceptance после #115/PR#118):
# install_lib.py::_restart_component poll'ит РЕАЛЬНЫЙ TCP/UDP порт (sys_probe.port_open) после
# `services start` — rc=0 недостаточно, порт должен реально открыться, иначе install падает
# <name>_restart_failed (xray_port_not_up). Тупой rc=0-stub был достаточен ДО #115 (слепой restart);
# #115 добавил port-poll гонку-guard ПОСЛЕ мерджа #114 — полигон не был адаптирован (не было CI,
# issue #116 п.3, регрессия не поймана). port_listener.py поднимает/останавливает реальный
# listener по pid-файлу в /tmp/srouter-acceptance-ports/<name>.pid — идемпотентно (stop без
# запущенного listener'а — no-op, start после start убивает старый и поднимает новый).
_PORT_DIR="/tmp/srouter-acceptance-ports"
_LISTENER="/opt/srouter-acceptance/port_listener.py"

_service_addr() {
  # (proto, port) — зеркало install_lib.py:95-99 PORTS. dnsmasq=udp/53 требует root bind (ok, root).
  case "$1" in
    xray) echo "tcp 10808" ;;
    privoxy) echo "tcp 8118" ;;
    dnsmasq) echo "udp 53" ;;
    *) echo "" ;;
  esac
}

_stop_listener() {
  name="$1"
  pidfile="$_PORT_DIR/$name.pid"
  if [ -f "$pidfile" ]; then
    pid="$(cat "$pidfile" 2>/dev/null)"
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
    rm -f "$pidfile"
  fi
}

_start_listener() {
  name="$1"
  addr="$(_service_addr "$name")"
  [ -z "$addr" ] && return 0
  proto="$(echo "$addr" | cut -d' ' -f1)"
  port="$(echo "$addr" | cut -d' ' -f2)"
  mkdir -p "$_PORT_DIR"
  _stop_listener "$name"
  nohup python3 "$_LISTENER" "$proto" "$port" "$_PORT_DIR/$name.pid" >/dev/null 2>&1 &
  # Дать listener'у реально забиндиться перед возвратом (poll вместо фиксированного sleep —
  # _restart_component всё равно ждёт своим poll'ом, но короткий wait тут снижает шум первой итерации).
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -f "$_PORT_DIR/$name.pid" ] && break
    sleep 0.1
  done
}

sub="$1"
case "$sub" in
  services)
    action="$2"
    name="$3"
    case "$action" in
      list)
        # Заголовок как у реального `brew services list` (parse_brew_services берёт поля 0 и 1).
        echo "Name      Status  User  File  Log  Plist"
        exit 0
        ;;
      start)
        _start_listener "$name"
        exit 0
        ;;
      restart|run)
        _start_listener "$name"
        exit 0
        ;;
      stop)
        _stop_listener "$name"
        exit 0
        ;;
      *)
        exit 0
        ;;
    esac
    ;;
  list)
    # `brew list --versions <name>` — _ensure_package проверяет, что пакет установлен.
    # При --versions печатаем "<name> <version>". Без --versions (голый list) — пустой вывод.
    if [ "$2" = "--versions" ]; then
      shift 2
      for pkg in "$@"; do
        echo "$pkg 0.0.0-stub"
      done
    fi
    exit 0
    ;;
  install)
    exit 0
    ;;
  --version)
    echo "Homebrew 0.0.0-stub (srouter acceptance)"
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
