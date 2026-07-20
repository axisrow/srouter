# srouter privoxy-лаборатория: изоляция host-privoxy для поимки причины самопадений (#123).
#
# Решающий эксперимент: privoxy в чистой Docker-среде (без launchd KeepAlive, без host-memory-jettison,
# без чужих signals). Если тут стабилен — корень на хосте; если тоже фликает — privoxy-баг.
#
# Топология: контейнерный privoxy (8119) → host-xray (10808 через host.docker.internal) → Reality.
# host-xray остаётся (стабилен с 3 июля), контейнер = только privoxy.
#
# Ключевое для поимки причины:
# - tini как PID-1: корректный catch SIGPIPE/SIGSEGV/signal (частая причина молчаливых падений —
#   privoxy падает от signal БЕЗ записи в лог; tini + --no-daemon → crash виден в docker logs/events).
# - --no-daemon: privoxy foreground, stdout → docker logs.
# - debug 8192: трассировка коннектов (host-config этого не делал — слепое пятно).
# - elliptic-curve-keys убран: чистый сигнал падения без шума non-fatal error.
FROM alpine:3.22

# privoxy + tini (PID-1 для catch сигналов). ca-certificates — для HTTPS upstream.
RUN apk add --no-cache privoxy tini ca-certificates

# Минимальный конфиг эксперимента (см. privoxy-lab.conf). СВОЙ — не brew-sample (убран elliptic-curve-keys,
# добавлен debug 8192, forward в host-xray через host.docker.internal).
COPY privoxy-lab.conf /etc/privoxy/config

# tini PID-1 → privoxy --no-daemon (foreground, stdout→docker logs). Crash/signal виден в docker events.
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["privoxy", "--no-daemon", "--pidfile", "/tmp/privoxy.pid", "/etc/privoxy/config"]
