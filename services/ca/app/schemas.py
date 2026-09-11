from __future__ import annotations

from pydantic import BaseModel, Field


class IssueCertificateRequest(BaseModel):
    ca_name: str
    profile_name: str
    csr_pem: str
    requested_sans: list[str] = Field(default_factory=list)
    validity_days: int = 397
    requester_identity: str


class IssueCertificateResponse(BaseModel):
    serial_number: str
    certificate_pem: str
    not_before: str
    not_after: str


class RevokeRequest(BaseModel):
    serial_number: str
    reason: str = "unspecified"
    actor: str


class SignOCSPRequest(BaseModel):
    ca_name: str
    serial_number: str


class CreateRootRequest(BaseModel):
    name: str
    subject: dict[str, str]
    key_algorithm: str = "EC_P384"
    validity_days: int = 7300


class CreateIntermediateRequest(BaseModel):
    name: str
    parent_name: str
    subject: dict[str, str]
    key_algorithm: str = "EC_P384"
    validity_days: int = 3650
    path_len: int = 0
