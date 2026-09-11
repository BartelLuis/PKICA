# syntax=docker/dockerfile:1.7
FROM python:3.11-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY common/pkicore /build/common/pkicore
COPY services/acme/requirements.txt /build/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --target=/deps /build/common/pkicore \
    && pip install --no-cache-dir --target=/deps -r /build/requirements.txt
COPY services/acme/app /build/app

FROM gcr.io/distroless/python3-debian12:nonroot AS runtime
WORKDIR /app
COPY --from=builder /deps /app/deps
COPY --from=builder /build/app /app/app
ENV PYTHONPATH=/app/deps:/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PKICA_SERVICE_NAME=acme

USER nonroot
EXPOSE 8000
ENTRYPOINT ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
