"""SQLAlchemy 2.0 models — CockroachDB (Postgres wire protocol) compatible.

All tables use UUID primary keys (CockroachDB-friendly, avoids sequential-key
hotspotting across a distributed cluster) and are designed for multi-region
survivability when the cluster is configured with `REGIONAL BY ROW` tables.
"""
from __future__ import annotations

import datetime as dt
import uuid
from enum import Enum as PyEnum

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Sequence,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


class CAStatus(str, PyEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    PENDING = "pending"


class CertificateAuthority(Base):
    """A Root or Intermediate CA. The private key never lives here — only a
    reference (`kms_key_id`) into the configured KMS/HSM backend."""

    __tablename__ = "certificate_authorities"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    is_root: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("certificate_authorities.id"), nullable=True
    )
    subject_dn: Mapped[str] = mapped_column(Text)
    kms_backend: Mapped[str] = mapped_column(String(64))
    kms_key_id: Mapped[str] = mapped_column(Text)
    signature_algorithm: Mapped[str] = mapped_column(String(64))
    certificate_pem: Mapped[str] = mapped_column(Text)
    subject_key_identifier: Mapped[str] = mapped_column(String(64))
    not_before: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[CAStatus] = mapped_column(Enum(CAStatus), default=CAStatus.ACTIVE)
    crl_number: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=dt.datetime.utcnow)

    children: Mapped[list["CertificateAuthority"]] = relationship(remote_side=[id])


class CertProfile(Base):
    """Issuance policy template (e.g. 'tls-server', 'tls-client', 'code-signing').
    Enforced by the RA before any request reaches the CA."""

    __tablename__ = "cert_profiles"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(128), unique=True)
    issuing_ca_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("certificate_authorities.id"))
    max_validity_days: Mapped[int] = mapped_column(Integer, default=397)
    allowed_key_algorithms: Mapped[str] = mapped_column(String(255), default="RSA_2048,RSA_4096,EC_P256,EC_P384")
    key_usage: Mapped[str] = mapped_column(String(255), default="digital_signature,key_encipherment")
    extended_key_usage: Mapped[str] = mapped_column(String(255), default="server_auth")
    allow_san_dns: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_san_ip: Mapped[bool] = mapped_column(Boolean, default=False)
    require_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    allowed_protocols: Mapped[str] = mapped_column(String(255), default="rest,acme,est,scep")


class RequestStatus(str, PyEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    ISSUED = "issued"
    FAILED = "failed"


class CertificateRequest(Base):
    """RA-side workflow record for every enrollment, regardless of the
    originating protocol (REST/ACME/EST/SCEP)."""

    __tablename__ = "certificate_requests"

    id: Mapped[uuid.UUID] = _uuid_pk()
    profile_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("cert_profiles.id"))
    protocol: Mapped[str] = mapped_column(String(32))
    requester_identity: Mapped[str] = mapped_column(Text)
    csr_pem: Mapped[str] = mapped_column(Text)
    requested_sans: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[RequestStatus] = mapped_column(Enum(RequestStatus), default=RequestStatus.PENDING)
    approver_identity: Mapped[str | None] = mapped_column(Text, nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    issued_serial_number: Mapped[str | None] = mapped_column(String(64), nullable=True)
    issued_certificate_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=dt.datetime.utcnow)
    decided_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    certificate: Mapped["Certificate | None"] = relationship(back_populates="request", uselist=False)


class Certificate(Base):
    __tablename__ = "certificates"
    __table_args__ = (
        UniqueConstraint("issuing_ca_id", "serial_number", name="uq_ca_serial"),
        Index("ix_certificates_not_after", "not_after"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    request_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("certificate_requests.id"), nullable=True
    )
    issuing_ca_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("certificate_authorities.id"))
    serial_number: Mapped[str] = mapped_column(String(64))
    subject_dn: Mapped[str] = mapped_column(Text)
    sans: Mapped[str] = mapped_column(Text, default="")
    certificate_pem: Mapped[str] = mapped_column(Text)
    not_before: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=dt.datetime.utcnow)

    request: Mapped["CertificateRequest | None"] = relationship(back_populates="certificate")


class AuditLogEntry(Base):
    """Append-only, tamper-evident audit trail — each row's `entry_hash`
    covers the previous entry's hash, forming a hash chain. Any deletion or
    modification breaks the chain and is detectable by `pkicore.audit.verify_chain`.
    """

    __tablename__ = "audit_log"

    _seq_sequence = Sequence("audit_log_seq")

    id: Mapped[uuid.UUID] = _uuid_pk()
    seq: Mapped[int] = mapped_column(
        Integer, _seq_sequence, server_default=_seq_sequence.next_value(), unique=True
    )
    timestamp: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=dt.datetime.utcnow)
    # Exact ISO string used when computing entry_hash — kept verbatim (not
    # recomputed from `timestamp`) since round-tripping a DateTime column
    # through the DB can change its string representation (naive vs
    # timezone-aware, precision), which would otherwise break the hash chain.
    timestamp_iso: Mapped[str] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(String(128))
    resource: Mapped[str] = mapped_column(Text)
    details: Mapped[str] = mapped_column(Text, default="{}")
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))


# ---------------------------------------------------------------------------
# ACME (RFC 8555) server-side state — persisted in CockroachDB so any
# replica behind a load balancer can serve any request (required for HA).
# ---------------------------------------------------------------------------

class AcmeAccount(Base):
    __tablename__ = "acme_accounts"

    id: Mapped[uuid.UUID] = _uuid_pk()
    jwk_thumbprint: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    jwk_json: Mapped[str] = mapped_column(Text)
    contact: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="valid")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=dt.datetime.utcnow)


class AcmeOrder(Base):
    __tablename__ = "acme_orders"

    id: Mapped[uuid.UUID] = _uuid_pk()
    account_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("acme_accounts.id"))
    identifiers: Mapped[str] = mapped_column(Text)  # JSON list of {"type":"dns","value":"..."}
    status: Mapped[str] = mapped_column(String(32), default="pending")
    certificate_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=dt.datetime.utcnow)


class AcmeAuthorization(Base):
    __tablename__ = "acme_authorizations"

    id: Mapped[uuid.UUID] = _uuid_pk()
    order_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("acme_orders.id"))
    identifier_type: Mapped[str] = mapped_column(String(16), default="dns")
    identifier_value: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default="pending")
    token: Mapped[str] = mapped_column(String(64))


class AcmeNonce(Base):
    __tablename__ = "acme_nonces"

    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=dt.datetime.utcnow)

