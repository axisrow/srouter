#!/bin/sh
# srouter: мгновенная реакция на поднятие PPP-VPN — добавить split-route до VPS через en0.
# Запускается macOS pppd от ROOT при VPN up (ppp0). Без osascript (уже root).
# srouter install копирует этот шаблон в /etc/ppp/ip-up (chmod +x, root:wheel).
exec __SROUTER_PYTHON_BIN__ __SROUTER_ROOT_DIR__/health.py ensure-split-route-root 2>>__SROUTER_LOG_ERR__
