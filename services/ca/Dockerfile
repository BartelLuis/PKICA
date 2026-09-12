# syntax=docker/dockerfile:1.7
# Hardened multi-stage build: compiled in a full Python image, shipped in
# Google's distroless Python runtime (no shell, no package manager, minimal
# libc-only attack surface), running as the built-in unprivileged `nonroot` user.

FROM python:3.14-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libssl-dev pkg-config swig \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY common/pkicore /build/common/pkicore
COPY services/ca/requirements.txt /build/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --target=/deps /build/common/pkicore \
    && pip install --no-cache-dir --target=/deps -r /build/requirements.txt
COPY services/ca/app /build/app
COPY scripts/seed-profiles.py /build/scripts/seed-profiles.py
# Pre-create the software-KMS data dir owned by distroless's nonroot user
# (uid/gid 65532) so it's writable once mounted as a named volume — an
# empty named volume inherits the ownership of the image path it overlays.
RUN mkdir -p /data/software-kms && chown -R 65532:65532 /data

FROM gcr.io/distroless/python3-debian12:nonroot AS runtime
WORKDIR /app
COPY --from=builder /deps /app/deps
COPY --from=builder /build/app /app/app
COPY --from=builder /build/scripts /app/scripts
COPY --from=builder /data /data
ENV PYTHONPATH=/app/deps:/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PKICA_SERVICE_NAME=ca

USER nonroot
EXPOSE 8000
# No TLS here by design: this app is reachable only via the `ca-mtls-proxy`
# sidecar over the private `ca-internal` docker network (see docker-compose.yml).
ENTRYPOINT ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
