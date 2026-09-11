"""RA policy engine: the single choke point every enrollment protocol
(REST, ACME, EST, SCEP) must pass through before a request reaches the CA."""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from pkicore import audit, crypto
from pkicore.db.models import CertificateRequest, CertProfile, RequestStatus

from pkicore.ca_client import CAClient


class PolicyViolation(Exception):
    pass


class RAService:
    def __init__(self, session: Session, ca_client: CAClient, audit_secret: str):
        self.session = session
        self.ca_client = ca_client
        self.audit_secret = audit_secret

    def submit_request(
        self,
        *,
        profile_name: str,
        protocol: str,
        requester_identity: str,
        csr_pem: str,
        requested_sans: list[str] | None = None,
    ) -> CertificateRequest:
        profile = self.session.scalar(select(CertProfile).where(CertProfile.name == profile_name))
        if profile is None:
            raise PolicyViolation(f"Unknown certificate profile '{profile_name}'")
        if protocol not in profile.allowed_protocols.split(","):
            raise PolicyViolation(f"Protocol '{protocol}' not permitted for profile '{profile_name}'")

        csr = crypto.parse_csr(csr_pem)  # raises ValueError on bad signature
        sans = requested_sans or []

        req = CertificateRequest(
            profile_id=profile.id,
            protocol=protocol,
            requester_identity=requester_identity,
            csr_pem=csr_pem,
            requested_sans=",".join(sans),
            status=RequestStatus.PENDING,
        )
        self.session.add(req)
        self.session.flush()
        audit.record(self.session, secret=self.audit_secret, actor=requester_identity, action="request.submit",
                      resource=f"request:{req.id}", details={"profile": profile_name, "protocol": protocol})

        if not profile.require_approval:
            self._issue(req, profile, sans, actor=requester_identity)
        return req

    def approve_request(self, *, request_id: uuid.UUID, approver_identity: str) -> CertificateRequest:
        req = self._get_request(request_id)
        if req.status != RequestStatus.PENDING:
            raise PolicyViolation(f"Request {request_id} is not pending (status={req.status})")
        profile = self.session.get(CertProfile, req.profile_id)
        sans = req.requested_sans.split(",") if req.requested_sans else []
        self._issue(req, profile, sans, actor=approver_identity)
        req.approver_identity = approver_identity
        return req

    def reject_request(self, *, request_id: uuid.UUID, approver_identity: str, reason: str) -> CertificateRequest:
        req = self._get_request(request_id)
        req.status = RequestStatus.REJECTED
        req.approver_identity = approver_identity
        req.rejection_reason = reason
        self.session.flush()
        audit.record(self.session, secret=self.audit_secret, actor=approver_identity, action="request.reject",
                      resource=f"request:{request_id}", details={"reason": reason})
        return req

    def revoke(self, *, serial_number: str, reason: str, actor: str) -> dict:
        result = self.ca_client.revoke(serial_number=serial_number, reason=reason, actor=actor)
        audit.record(self.session, secret=self.audit_secret, actor=actor, action="cert.revoke.request",
                      resource=f"cert:{serial_number}", details={"reason": reason})
        return result

    # ------------------------------------------------------------------
    def _issue(self, req: CertificateRequest, profile: CertProfile, sans: list[str], *, actor: str) -> None:
        import datetime as dt

        from pkicore.db.models import Certificate, CertificateAuthority

        ca = self.session.get(CertificateAuthority, profile.issuing_ca_id)
        try:
            result = self.ca_client.issue(
                ca_name=ca.name, profile_name=profile.name, csr_pem=req.csr_pem,
                requested_sans=sans, validity_days=profile.max_validity_days,
                requester_identity=req.requester_identity,
            )
        except Exception as exc:  # noqa: BLE001
            req.status = RequestStatus.FAILED
            req.rejection_reason = str(exc)
            self.session.flush()
            audit.record(self.session, secret=self.audit_secret, actor=actor, action="request.issue_failed",
                          resource=f"request:{req.id}", details={"error": str(exc)})
            raise

        req.status = RequestStatus.ISSUED
        req.decided_at = dt.datetime.utcnow()
        req.issued_serial_number = result["serial_number"]
        req.issued_certificate_pem = result["certificate_pem"]
        self.session.flush()
        audit.record(self.session, secret=self.audit_secret, actor=actor, action="request.issued",
                      resource=f"request:{req.id}", details={"serial_number": result["serial_number"]})

    def _get_request(self, request_id: uuid.UUID) -> CertificateRequest:
        req = self.session.get(CertificateRequest, request_id)
        if req is None:
            raise LookupError(f"Request {request_id} not found")
        return req
