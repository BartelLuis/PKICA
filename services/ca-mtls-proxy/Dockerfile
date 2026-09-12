# Hardened nginx: unprivileged image, non-root user, read-only filesystem
# compatible (all writable paths redirected to /tmp, mounted as tmpfs by
# docker-compose).
FROM nginxinc/nginx-unprivileged:1.29-alpine

USER root
RUN rm -f /etc/nginx/conf.d/default.conf
COPY services/ca-mtls-proxy/nginx.conf /etc/nginx/nginx.conf
USER nginx

EXPOSE 8443
