from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from pkicore.auth.mtls import require_mtls_peer
from pkicore.db.models import CertificateRequest

from app.schemas import ApproveBody, InternalIssueBody, RejectBody, RequestView, RevokeBody, SubmitRequestBody
from app.service import PolicyViolation, RAService

router = APIRouter(prefix="/api/v1")
internal_router = APIRouter(prefix="/internal/v1")

_PROTOCOL_ADAPTER_PEERS = {"acme", "est", "scep"}


def get_session_dep():
    raise RuntimeError("not wired")


def get_ra_service_dep() -> RAService:
    raise RuntimeError("not wired")


def get_current_human_dep() -> dict:
    raise RuntimeError("not wired")


def require_role_dep(*roles: str):
    def _inner(claims: dict = Depends(get_current_human_dep)):
        from pkicore.auth.rbac import ROLE_CLAIM

        user_roles = set(claims.get(ROLE_CLAIM, []))
        if not user_roles.intersection(roles):
            raise HTTPException(403, f"Requires one of roles: {roles}")
        return claims

    return _inner


@router.post("/requests", response_model=RequestView)
def submit_request(
    body: SubmitRequestBody,
    claims: dict = Depends(get_current_human_dep),
    svc: RAService = Depends(get_ra_service_dep),
):
    try:
        req = svc.submit_request(
            profile_name=body.profile_name, protocol="rest",
            requester_identity=claims.get("sub", "unknown"),
            csr_pem=body.csr_pem, requested_sans=body.requested_sans,
        )
    except (PolicyViolation, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc
    return req


@router.get("/requests", response_model=list[RequestView])
def list_requests(
    claims: dict = Depends(require_role_dep("pkica-ra-approver", "pkica-admin")),
    session: Session = Depends(get_session_dep),
):
    return session.scalars(select(CertificateRequest).order_by(CertificateRequest.created_at.desc())).all()


@router.post("/requests/approve", response_model=RequestView)
def approve_request(
    body: ApproveBody,
    claims: dict = Depends(require_role_dep("pkica-ra-approver", "pkica-admin")),
    svc: RAService = Depends(get_ra_service_dep),
):
    try:
        return svc.approve_request(request_id=body.request_id, approver_identity=claims.get("sub", "unknown"))
    except (PolicyViolation, LookupError) as exc:
        raise HTTPException(422, str(exc)) from exc


@router.post("/requests/reject", response_model=RequestView)
def reject_request(
    body: RejectBody,
    claims: dict = Depends(require_role_dep("pkica-ra-approver", "pkica-admin")),
    svc: RAService = Depends(get_ra_service_dep),
):
    try:
        return svc.reject_request(
            request_id=body.request_id, approver_identity=claims.get("sub", "unknown"), reason=body.reason
        )
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.post("/revoke")
def revoke(
    body: RevokeBody,
    claims: dict = Depends(require_role_dep("pkica-ra-approver", "pkica-admin")),
    svc: RAService = Depends(get_ra_service_dep),
):
    return svc.revoke(serial_number=body.serial_number, reason=body.reason, actor=claims.get("sub", "unknown"))


@router.get("/healthz")
def healthz():
    return {"status": "ok"}


# ---------------------------------------------------------------------
# Internal API for protocol adapters (ACME/EST/SCEP) — mTLS-authenticated,
# not reachable from the public internet (see docker-compose network layout).
# ---------------------------------------------------------------------
@internal_router.post("/requests", response_model=RequestView, dependencies=[Depends(require_mtls_peer(_PROTOCOL_ADAPTER_PEERS))])
def internal_submit_request(body: InternalIssueBody, svc: RAService = Depends(get_ra_service_dep)):
    try:
        return svc.submit_request(
            profile_name=body.profile_name, protocol=body.protocol,
            requester_identity=body.requester_identity, csr_pem=body.csr_pem,
            requested_sans=body.requested_sans,
        )
    except (PolicyViolation, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc


@internal_router.get("/requests/{request_id}", response_model=RequestView, dependencies=[Depends(require_mtls_peer(_PROTOCOL_ADAPTER_PEERS))])
def internal_get_request(request_id: uuid.UUID, session: Session = Depends(get_session_dep)):
    req = session.get(CertificateRequest, request_id)
    if req is None:
        raise HTTPException(404, "not found")
    return req
