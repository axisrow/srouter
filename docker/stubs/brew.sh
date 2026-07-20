#!/bin/sh
# srouter acceptance: stub macOS /opt/homebrew/bin/brew (тупой, stateless — путь 3).
# srouter зовёт brew через runner([BREW, sub, ...]). Эмулируем ответы по cmd[1], достаточные для
# install/uninstall: services-list пустой (чистая установка с нуля), install/restart/stop — успех.
#
# Контракт (по первоисточнику install_lib.py):
#   services list             → rc=0, header "Name Status User File Log Plist" без строк.
#                               parse_brew_services парсит "name state" — пустой вывод → states={} →
#                               build_plan видит service="none" (чистая ветка установки с нуля).
#   services start/stop/restart <name> → rc=0 (успех). Тупой stub НЕ хранит состояние — restart
#                               после stop тоже успех (идемпотентность CLI проверяем, не brew).
#   list --versions <name>    → rc=0, "<name> <version>" (пакет «установлен», чтобы _ensure_package
#                               не пытался реально brew install).
#   install <name>            → rc=0.
#   --version                 → rc=0, фейковая версия.
sub="$1"
case "$sub" in
  services)
    action="$2"
    case "$action" in
      list)
        # Заголовок как у реального `brew services list` (parse_brew_services берёт поля 0 и 1).
        echo "Name      Status  User  File  Log  Plist"
        exit 0
        ;;
      start|stop|restart|run)
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
