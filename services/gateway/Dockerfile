# Public-facing hardened nginx reverse proxy / mTLS-optional TLS termination.
FROM nginxinc/nginx-unprivileged:1.27-alpine

USER root
RUN rm -f /etc/nginx/conf.d/default.conf
COPY services/gateway/nginx.conf /etc/nginx/nginx.conf
USER nginx

EXPOSE 8443
