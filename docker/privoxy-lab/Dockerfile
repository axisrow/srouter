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
#
# cycle-review #125 C1: alpine apk даёт privoxy 3.0.34, а host = 4.2.0 — эксперимент невалиден
# (сравниваем разные версии). Поэтому собираем privoxy 4.2.0 из исходников (тот же upstream).
FROM alpine:3.22 AS builder

# Сборочные зависимости для privoxy 4.2.0 из исходников.
RUN apk add --no-cache build-base autoconf automake libtool pcre2-dev curl-dev zlib-dev openssl-dev \
    && curl -sSL https://www.privoxy.org/sf-download-mirror/Sources/4.2.0%20%28stable%29/privoxy-4.2.0-stable-src.tar.gz \
       | tar xz -C /tmp \
    && cd /tmp/privoxy-4.2.0-stable \
    && autoheader && autoconf \
    && ./configure --prefix=/usr --sysconfdir=/etc/privoxy --localstatedir=/var \
    && make -j$(nproc) \
    && make install

FROM alpine:3.22

# tini (PID-1), ca-certificates (HTTPS upstream). Копируем собранный privoxy 4.2.0 из builder.
RUN apk add --no-cache tini ca-certificates pcre2 zlib libretls
COPY --from=builder /usr/sbin/privoxy /usr/sbin/privoxy
COPY --from=builder /etc/privoxy/templates /etc/privoxy/templates

# Минимальный конфиг эксперимента (см. privoxy-lab.conf). СВОЙ — не brew-sample (убран elliptic-curve-keys,
# добавлен debug 8192, forward в host-xray через host.docker.internal).
COPY privoxy-lab.conf /etc/privoxy/config

# tini PID-1 → privoxy --no-daemon (foreground, stdout→docker logs). Crash/signal виден в docker events.
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["privoxy", "--no-daemon", "--pidfile", "/tmp/privoxy.pid", "/etc/privoxy/config"]
