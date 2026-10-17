#!/bin/sh
# srouter acceptance: stub macOS /usr/sbin/networksetup (тупой no-op — путь 3).
# srouter зовёт networksetup для DNS/network-services. В Docker нет Wi-Fi-интерфейса — возвращаем
# правдоподобные пустые ответы, чтобы install/uninstall не падали.
#
# Контракт (по первоисточнику install_lib.py / dashboard_connectivity.py):
#   -listallnetworkservices     → header + одна запись "Wi-Fi" (нужно для _apply_dns: найдет Wi-Fi
#                                 service → -setdnsservers Wi-Fi ...). Без записи DNS-ветка skip'нет.
#   -listallhardwareports       → пустой вывод (probe_ifaces — не критично для install/uninstall).
#   -setdnsservers <svc> <ip>   → rc=0 (применение DNS = no-op в контейнере).
#   -setdnsservers <svc> Empty  → rc=0 (сброс DNS при uninstall).
#   -getdnsservers <svc>        → rc=0, "There aren't any DNS Servers set on Wi-Fi." (как на macOS).
#   прочее                      → rc=0 (fail-soft).
sub="$1"
dns_state="$HOME/.srouter-acceptance-dns"
case "$sub" in
  -listallnetworkservices)
    echo "An asterisk (*) denotes that a network service is disabled."
    echo "Wi-Fi"
    exit 0
    ;;
  -listallhardwareports)
    # Пустой список hardware-портов — probe-ветка, не блокирует install/uninstall.
    exit 0
    ;;
  -setdnsservers)
    shift 2
    if [ "$1" = Empty ]; then
      rm -f "$dns_state"
    else
      printf '%s\n' "$@" > "$dns_state"
    fi
    exit 0
    ;;
  -getdnsservers)
    if [ -f "$dns_state" ]; then
      cat "$dns_state"
    else
      echo "There aren't any DNS Servers set on Wi-Fi."
    fi
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
