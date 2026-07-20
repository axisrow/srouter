#!/bin/sh
# srouter acceptance: stub macOS /sbin/route (тупой no-op — путь 3).
# BSD-route синтаксис отличается от Linux `ip route`. srouter зовёт:
#   route -n get default        → probe gateway (dashboard_network, не критично для install/uninstall).
#   route -n get -host <ip>     → probe route-to-VPS (dashboard_network, не критично).
#   route -n add/delete -host   → split-route (dashboard sudo_route + srouter._remove_active_split_route).
#
# Для install/uninstall критичен только `route -n delete -host <ip>` в uninstall (_remove_active_split_route).
# Возвращаем rc=0 (маршрут «удалён» или «не было» — код в _remove_active_split_route толерантен к rc).
# Probe-команды `get` возвращают rc=0 без gateway — probe_route_to_vps/probe_vpn дадут empty/down,
# но это отображение статуса, не install/uninstall-цикл.
sub="$1"
case "$sub" in
  -n)
    # route -n get [...] или route -n add/delete -host [...]
    action="$2"
    case "$action" in
      get)
        # Нет gateway/интерфейса в контейнере — probe получит пустой ответ (не падает).
        exit 0
        ;;
      add|delete)
        # Split-route операция — успех (no-op). Идемпотентность: повторный delete тоже rc=0.
        exit 0
        ;;
      *)
        exit 0
        ;;
    esac
    ;;
  *)
    exit 0
    ;;
esac
