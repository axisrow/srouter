# syntax=docker/dockerfile:1.7

ARG XRAY_VERSION=25.6.8

# Официальный pinned-образ Xray: используем его как источник бинаря и geodata.
FROM ghcr.io/xtls/xray-core:${XRAY_VERSION} AS xray

# Runtime с bash/envsubst/openssl для defensive entrypoint и первого запуска.
FROM alpine:3.22

RUN apk add --no-cache bash ca-certificates gettext openssl

COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray
COPY --from=xray /usr/local/share/xray /usr/local/share/xray

COPY config.template.json /etc/srouter-reality/config.template.json
COPY entrypoint.sh /usr/local/bin/srouter-reality-entrypoint.sh

RUN mkdir -p /etc/xray/rendered /var/lib/srouter-reality /var/log/xray \
    && chmod 700 /var/lib/srouter-reality \
    && chmod 755 /usr/local/bin/srouter-reality-entrypoint.sh

EXPOSE 443/tcp
VOLUME ["/var/lib/srouter-reality"]

ENTRYPOINT ["/usr/local/bin/srouter-reality-entrypoint.sh"]
CMD ["xray", "run", "-config", "/etc/xray/rendered/config.json"]
