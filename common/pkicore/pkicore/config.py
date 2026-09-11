"""Central, strongly-typed configuration for every PKICA service.

Values are read exclusively from environment variables / Docker secrets
(files referenced via the `_FILE` suffix convention). Nothing is ever
read from source or build args, so images stay identical across
dev/stage/prod and secrets never end up in an image layer.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _read_secret(value: str | None) -> str | None:
    """Support the `X_FILE=/run/secrets/x` Docker/K8s secret convention."""
    if value and value.startswith("file://"):
        return Path(value[len("file://"):]).read_text(encoding="utf-8").strip()
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PKICA_", extra="ignore")

    service_name: str = Field(default="pkica-service")
    environment: str = Field(default="production")
    log_level: str = Field(default="INFO")
    log_json: bool = Field(default=True)

    # Database (CockroachDB, Postgres wire-compatible)
    database_url: str = Field(default="postgresql+psycopg://root@cockroachdb:26257/pkica?sslmode=verify-full")
    database_pool_size: int = Field(default=10)
    database_ssl_root_cert: str | None = Field(default=None)

    # Internal service-to-service mTLS
    internal_tls_cert: str | None = Field(default=None)
    internal_tls_key: str | None = Field(default=None)
    internal_tls_ca: str | None = Field(default=None)
    require_internal_mtls: bool = Field(default=True)

    # Human auth (OIDC/SSO)
    oidc_issuer: str | None = Field(default=None)
    oidc_audience: str | None = Field(default=None)
    oidc_jwks_url: str | None = Field(default=None)

    # KMS / HSM key custody backend used by the CA service
    ca_key_backend: str = Field(default="software")
    allow_software_kms: bool = Field(default=False)

    # AWS KMS
    aws_region: str | None = Field(default=None)
    aws_kms_key_id: str | None = Field(default=None)

    # Azure Key Vault
    azure_key_vault_url: str | None = Field(default=None)

    # GCP KMS
    gcp_kms_key_ring: str | None = Field(default=None)
    gcp_project_id: str | None = Field(default=None)
    gcp_location: str | None = Field(default=None)

    # HashiCorp Vault Transit
    vault_addr: str | None = Field(default=None)
    vault_token: str | None = Field(default=None)
    vault_transit_mount: str = Field(default="transit")

    # PKCS#11 HSM
    pkcs11_module_path: str | None = Field(default=None)
    pkcs11_slot: int | None = Field(default=None)
    pkcs11_pin: str | None = Field(default=None)
    pkcs11_key_label: str | None = Field(default=None)

    # RA -> CA internal API
    ca_internal_url: str = Field(default="https://ca:8443")
    ra_internal_url: str = Field(default="https://ra:8444")

    # Audit
    audit_hash_chain_secret: str | None = Field(default=None)
    siem_forward_url: str | None = Field(default=None)

    @field_validator(
        "internal_tls_key",
        "vault_token",
        "pkcs11_pin",
        "audit_hash_chain_secret",
        mode="before",
    )
    @classmethod
    def _resolve_secret_files(cls, v: str | None) -> str | None:
        return _read_secret(v)


@lru_cache
def get_settings() -> Settings:
    return Settings()
