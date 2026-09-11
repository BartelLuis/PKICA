from __future__ import annotations

import uuid

from pydantic import BaseModel, Field


class SubmitRequestBody(BaseModel):
    profile_name: str
    csr_pem: str
    requested_sans: list[str] = Field(default_factory=list)


class RequestView(BaseModel):
    id: uuid.UUID
    status: str
    protocol: str
    requester_identity: str
    issued_serial_number: str | None = None
    issued_certificate_pem: str | None = None

    class Config:
        from_attributes = True


class ApproveBody(BaseModel):
    request_id: uuid.UUID


class RejectBody(BaseModel):
    request_id: uuid.UUID
    reason: str


class RevokeBody(BaseModel):
    serial_number: str
    reason: str = "unspecified"


class InternalIssueBody(BaseModel):
    """Used by the acme/est/scep protocol adapters (mTLS-authenticated)."""

    profile_name: str
    protocol: str
    requester_identity: str
    csr_pem: str
    requested_sans: list[str] = Field(default_factory=list)
