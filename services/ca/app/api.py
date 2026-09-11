from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from pkicore.auth.mtls import require_mtls_peer
from pkicore.db.models import CertProfile
from pkicore.kms.base import KMSBackend

from app.schemas import (
    CreateIntermediateRequest,
    CreateRootRequest,
    IssueCertificateRequest,
    IssueCertificateResponse,
    RevokeRequest,
    SignOCSPRequest,
)
from app.service import CAService, PolicyViolation

router = APIRouter(prefix="/internal/v1")

# Only these service identities (verified client-cert CN, injected by the
# mTLS-terminating proxy) may ever reach the CA service.
_ISSUANCE_PEERS = {"ra"}
_SIGNING_PEERS = {"ocsp", "crl"}
_ADMIN_PEERS = {"pkica-admin-cli"}


def get_session_dep():  # overridden in main.py via dependency_overrides
    raise RuntimeError("not wired")


def get_kms_dep() -> KMSBackend:  # overridden in main.py
    raise RuntimeError("not wired")


def get_audit_secret_dep() -> str:  # overridden in main.py
    raise RuntimeError("not wired")


def _service(session: Session, kms: KMSBackend, secret: str) -> CAService:
    return CAService(session=session, kms=kms, audit_secret=secret)


@router.post("/ca/root", dependencies=[Depends(require_mtls_peer(_ADMIN_PEERS))])
def create_root(
    req: CreateRootRequest,
    session: Session = Depends(get_session_dep),
    kms: KMSBackend = Depends(get_kms_dep),
    secret: str = Depends(get_audit_secret_dep),
):
    svc = _service(session, kms, secret)
    ca = svc.create_root_ca(
        name=req.name, subject=req.subject, key_algorithm=req.key_algorithm, validity_days=req.validity_days
    )
    return {"name": ca.name, "certificate_pem": ca.certificate_pem}


@router.post("/ca/intermediate", dependencies=[Depends(require_mtls_peer(_ADMIN_PEERS))])
def create_intermediate(
    req: CreateIntermediateRequest,
    session: Session = Depends(get_session_dep),
    kms: KMSBackend = Depends(get_kms_dep),
    secret: str = Depends(get_audit_secret_dep),
):
    svc = _service(session, kms, secret)
    ca = svc.create_intermediate_ca(
        name=req.name, parent_name=req.parent_name, subject=req.subject,
        key_algorithm=req.key_algorithm, validity_days=req.validity_days, path_len=req.path_len,
    )
    return {"name": ca.name, "certificate_pem": ca.certificate_pem}


@router.post("/issue", response_model=IssueCertificateResponse, dependencies=[Depends(require_mtls_peer(_ISSUANCE_PEERS))])
def issue(
    req: IssueCertificateRequest,
    session: Session = Depends(get_session_dep),
    kms: KMSBackend = Depends(get_kms_dep),
    secret: str = Depends(get_audit_secret_dep),
):
    profile = session.scalar(select(CertProfile).where(CertProfile.name == req.profile_name))
    if profile is None:
        raise HTTPException(404, f"Unknown profile {req.profile_name}")
    svc = _service(session, kms, secret)
    try:
        cert = svc.issue_certificate(
            ca_name=req.ca_name, profile=profile, csr_pem=req.csr_pem,
            requested_sans=req.requested_sans, validity_days=req.validity_days,
            requester_identity=req.requester_identity,
        )
    except PolicyViolation as exc:
        raise HTTPException(422, str(exc)) from exc
    return IssueCertificateResponse(
        serial_number=cert.serial_number, certificate_pem=cert.certificate_pem,
        not_before=cert.not_before.isoformat(), not_after=cert.not_after.isoformat(),
    )


@router.post("/revoke", dependencies=[Depends(require_mtls_peer(_ISSUANCE_PEERS))])
def revoke(
    req: RevokeRequest,
    session: Session = Depends(get_session_dep),
    kms: KMSBackend = Depends(get_kms_dep),
    secret: str = Depends(get_audit_secret_dep),
):
    svc = _service(session, kms, secret)
    try:
        cert = svc.revoke_certificate(serial_number=req.serial_number, reason=req.reason, actor=req.actor)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {"serial_number": cert.serial_number, "revoked": True}


@router.get("/crl/{ca_name}", dependencies=[Depends(require_mtls_peer(_SIGNING_PEERS))])
def crl(
    ca_name: str,
    session: Session = Depends(get_session_dep),
    kms: KMSBackend = Depends(get_kms_dep),
    secret: str = Depends(get_audit_secret_dep),
):
    svc = _service(session, kms, secret)
    der = svc.generate_crl(ca_name=ca_name)
    from fastapi.responses import Response

    return Response(content=der, media_type="application/pkix-crl")


@router.post("/ocsp/sign", dependencies=[Depends(require_mtls_peer(_SIGNING_PEERS))])
def sign_ocsp(
    req: SignOCSPRequest,
    session: Session = Depends(get_session_dep),
    kms: KMSBackend = Depends(get_kms_dep),
    secret: str = Depends(get_audit_secret_dep),
):
    svc = _service(session, kms, secret)
    der = svc.sign_ocsp_response(ca_name=req.ca_name, serial_number=req.serial_number)
    from fastapi.responses import Response

    return Response(content=der, media_type="application/ocsp-response")


@router.get("/ca/{ca_name}/certificate")
def get_ca_certificate(ca_name: str, session: Session = Depends(get_session_dep)):
    from pkicore.db.models import CertificateAuthority

    ca = session.scalar(select(CertificateAuthority).where(CertificateAuthority.name == ca_name))
    if ca is None:
        raise HTTPException(404, f"CA {ca_name} not found")
    return {"name": ca.name, "certificate_pem": ca.certificate_pem}


@router.get("/healthz")
def healthz():
    return {"status": "ok"}
