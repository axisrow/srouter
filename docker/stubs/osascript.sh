#!/bin/sh
# srouter acceptance: stub macOS /usr/bin/osascript (тупой no-op — путь 3).
# osascript = macOS GUI-пароль через 'do shell script ... with administrator privileges'. В Docker
# контейнер запускается от root → make_privileged_runner идёт по am_root-ветке (без osascript). НО
# stub обязателен: если код всё же доходит до _to_osascript (не-root путь / ppp-hook) — должен быть
# no-op, а не «command not found».
#
# srouter зовёт: [OSASCRIPT, "-e", 'do shell script "..." with administrator privileges']. Возвращаем
# rc=0 + пустой stdout = «команда выполнена успешно». Этого достаточно — код osascript-моста парсит
# rc, а не stdout (внешняя команда внутри do-shell-script сама пишет куда надо).
exit 0
