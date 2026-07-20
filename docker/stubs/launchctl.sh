#!/bin/sh
# srouter acceptance: stub macOS /bin/launchctl (тупой, stateless — путь 3).
# srouter зовёт launchctl через runner([LAUNCHCTL, sub, ...]) и парсит rc/out. Эмулируем ответы
# по cmd[1] (subcommand), достаточные для install/uninstall без реального launchd.
#
# Контракт (по первоисточнику install_lib.py / srouter.py):
#   print gui/<uid>/<label>  → rc=113 (service-not-found = «не загружен»). ЕДИНСТВЕННЫЙ достоверный
#                              «выгружен» в _launchd_is_loaded (tristate). rc=0 означал бы «загружен».
#   bootstrap / bootout     → rc=0 (успех). bootout «уже выгружен» — не ошибка (код игнорирует rc).
#   load -w                 → rc=0 (legacy fallback, после неудачного bootstrap).
#   list / list <domain>    → rc=0, пустая таблица с header (parse_brew_services-стиль: парсит поля).
#   getenv <domain> <key>   → rc=0, пустой stdout = переменной нет в gui-домене (верификация снятия).
#   setenv / unsetenv       → rc=0.
#   прочее                  → rc=0 (fail-soft).
set -e
sub="$1"
case "$sub" in
  print)
    # service-not-found → агент не загружен (тупой stub: никогда ничего не загружаем).
    echo "Could not find service" 1>&2
    exit 113
    ;;
  list)
    # Пустая таблица services с header (как реальный launchctl list).
    echo "PID	Status	Label"
    exit 0
    ;;
  getenv)
    # Пустой stdout = переменная отсутствует (верификация unsetenv в _remove_launchctl_env).
    exit 0
    ;;
  bootstrap|bootout|load|setenv|unsetenv|enable|disable|print-cache)
    exit 0
    ;;
  *)
    # Неизвестная subcommand — fail-soft (не валидируем argv строго).
    exit 0
    ;;
esac
