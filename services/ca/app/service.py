"""Core CA business logic — the only module in the platform allowed to call
`KMSBackend.sign()` / `create_key()`."""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from pkicore import audit, crypto
from pkicore.db.models import CAStatus, Certificate, CertificateAuthority, CertProfile
from pkicore.kms.base import KeySpec, KMSBackend, SignatureAlgorithm

_ALGO_BY_NAME = {a.value: a for a in SignatureAlgorithm}


class PolicyViolation(Exception):
    pass


class CAService:
    def __init__(self, session: Session, kms: KMSBackend, audit_secret: str):
        self.session = session
        self.kms = kms
        self.audit_secret = audit_secret

    # ------------------------------------------------------------------
    # CA lifecycle
    # ------------------------------------------------------------------
    def create_root_ca(
        self,
        *,
        name: str,
        subject: dict[str, str],
        key_algorithm: str = "EC_P384",
        validity_days: int = 7300,
    ) -> CertificateAuthority:
        key_id = f"root-{name}-{uuid.uuid4().hex[:8]}"
        self.kms.create_key(KeySpec(key_id=key_id, algorithm=key_algorithm, label=f"PKICA root CA {name}"))
        public_key = self.kms.public_key(key_id)
        algorithm = crypto.default_algorithm_for_public_key(public_key)

        subject_name = crypto.name_from_attributes(subject)
        ski = crypto.compute_subject_key_identifier(public_key)
        not_before = dt.datetime.now(dt.timezone.utc)
        not_after = not_before + dt.timedelta(days=validity_days)
        serial = crypto.generate_serial_number()

        extensions = crypto.build_extensions(crypto.ExtensionSpec(
            is_ca=True,
            path_len=None,
            key_usage={"key_cert_sign", "crl_sign"},
            subject_key_id=ski,
            authority_key_id=ski,  # self-signed
        ))
        tbs = crypto.build_tbs_certificate(
            serial_number=serial,
            issuer_name=subject_name,
            subject_name=subject_name,
            subject_public_key=public_key,
            not_before=not_before,
            not_after=not_after,
            extensions=extensions,
            signature_algorithm=algorithm,
        )
        cert_der = crypto.sign_certificate(tbs, self.kms, key_id, algorithm)
        pem = crypto.der_to_pem_certificate(cert_der)

        ca = CertificateAuthority(
            name=name,
            is_root=True,
            subject_dn=subject_name.human_friendly,
            kms_backend=self.kms.name,
            kms_key_id=key_id,
            signature_algorithm=algorithm.value,
            certificate_pem=pem,
            subject_key_identifier=ski.hex(),
            not_before=not_before,
            not_after=not_after,
            status=CAStatus.ACTIVE,
        )
        self.session.add(ca)
        self.session.flush()
        audit.record(self.session, secret=self.audit_secret, actor="system", action="ca.create_root",
                      resource=f"ca:{name}", details={"key_algorithm": key_algorithm})
        return ca

    def create_intermediate_ca(
        self,
        *,
        name: str,
        parent_name: str,
        subject: dict[str, str],
        key_algorithm: str = "EC_P384",
        validity_days: int = 3650,
        path_len: int = 0,
    ) -> CertificateAuthority:
        parent = self._get_ca(parent_name)
        key_id = f"intermediate-{name}-{uuid.uuid4().hex[:8]}"
        self.kms.create_key(KeySpec(key_id=key_id, algorithm=key_algorithm, label=f"PKICA intermediate CA {name}"))
        public_key = self.kms.public_key(key_id)
        algorithm = crypto.default_algorithm_for_public_key(public_key)

        subject_name = crypto.name_from_attributes(subject)
        issuer_name = crypto.name_from_attributes(_dn_string_to_attrs(parent.subject_dn))
        ski = crypto.compute_subject_key_identifier(public_key)
        aki = bytes.fromhex(parent.subject_key_identifier)
        not_before = dt.datetime.now(dt.timezone.utc)
        not_after = min(not_before + dt.timedelta(days=validity_days), parent.not_after)
        serial = crypto.generate_serial_number()

        extensions = crypto.build_extensions(crypto.ExtensionSpec(
            is_ca=True,
            path_len=path_len,
            key_usage={"key_cert_sign", "crl_sign"},
            subject_key_id=ski,
            authority_key_id=aki,
        ))
        tbs = crypto.build_tbs_certificate(
            serial_number=serial,
            issuer_name=issuer_name,
            subject_name=subject_name,
            subject_public_key=public_key,
            not_before=not_before,
            not_after=not_after,
            extensions=extensions,
            signature_algorithm=algorithm,
        )
        parent_algo = _ALGO_BY_NAME[parent.signature_algorithm]
        cert_der = crypto.sign_certificate(tbs, self.kms, parent.kms_key_id, parent_algo)
        pem = crypto.der_to_pem_certificate(cert_der)

        ca = CertificateAuthority(
            name=name,
            is_root=False,
            parent_id=parent.id,
            subject_dn=subject_name.human_friendly,
            kms_backend=self.kms.name,
            kms_key_id=key_id,
            signature_algorithm=algorithm.value,
            certificate_pem=pem,
            subject_key_identifier=ski.hex(),
            not_before=not_before,
            not_after=not_after,
            status=CAStatus.ACTIVE,
        )
        self.session.add(ca)
        self.session.flush()
        audit.record(self.session, secret=self.audit_secret, actor="system", action="ca.create_intermediate",
                      resource=f"ca:{name}", details={"parent": parent_name})
        return ca

    # ------------------------------------------------------------------
    # Issuance / revocation
    # ------------------------------------------------------------------
    def issue_certificate(
        self,
        *,
        ca_name: str,
        profile: CertProfile,
        csr_pem: str,
        requested_sans: list[str],
        validity_days: int,
        requester_identity: str,
    ) -> Certificate:
        ca = self._get_ca(ca_name)
        if ca.status != CAStatus.ACTIVE:
            raise PolicyViolation(f"Issuing CA '{ca_name}' is not active")

        csr = crypto.parse_csr(csr_pem)
        public_key = csr.public_key()
        self._enforce_profile(profile, public_key, requested_sans)

        validity_days = min(validity_days, profile.max_validity_days)
        issuer_name = crypto.name_from_attributes(_dn_string_to_attrs(ca.subject_dn))
        subject_name = _name_from_csr(csr)
        not_before = dt.datetime.now(dt.timezone.utc)
        not_after = min(not_before + dt.timedelta(days=validity_days), ca.not_after)
        serial = crypto.generate_serial_number()
        ski = crypto.compute_subject_key_identifier(public_key)
        aki = bytes.fromhex(ca.subject_key_identifier)

        extensions = crypto.build_extensions(crypto.ExtensionSpec(
            is_ca=False,
            key_usage=set(profile.key_usage.split(",")),
            extended_key_usage=profile.extended_key_usage.split(","),
            subject_alt_names=requested_sans,
            subject_key_id=ski,
            authority_key_id=aki,
        ))
        algorithm = _ALGO_BY_NAME[ca.signature_algorithm]
        tbs = crypto.build_tbs_certificate(
            serial_number=serial,
            issuer_name=issuer_name,
            subject_name=subject_name,
            subject_public_key=public_key,
            not_before=not_before,
            not_after=not_after,
            extensions=extensions,
            signature_algorithm=algorithm,
        )
        cert_der = crypto.sign_certificate(tbs, self.kms, ca.kms_key_id, algorithm)
        pem = crypto.der_to_pem_certificate(cert_der)

        record = Certificate(
            issuing_ca_id=ca.id,
            serial_number=format(serial, "x"),
            subject_dn=subject_name.human_friendly,
            sans=",".join(requested_sans),
            certificate_pem=pem,
            not_before=not_before,
            not_after=not_after,
        )
        self.session.add(record)
        self.session.flush()
        audit.record(self.session, secret=self.audit_secret, actor=requester_identity, action="cert.issue",
                      resource=f"cert:{record.serial_number}", details={"ca": ca_name, "profile": profile.name})
        return record

    def revoke_certificate(self, *, serial_number: str, reason: str, actor: str) -> Certificate:
        cert = self.session.scalar(select(Certificate).where(Certificate.serial_number == serial_number))
        if cert is None:
            raise LookupError(f"Certificate {serial_number} not found")
        cert.revoked = True
        cert.revoked_at = dt.datetime.now(dt.timezone.utc)
        cert.revocation_reason = reason
        self.session.flush()
        audit.record(self.session, secret=self.audit_secret, actor=actor, action="cert.revoke",
                      resource=f"cert:{serial_number}", details={"reason": reason})
        return cert

    # ------------------------------------------------------------------
    # CRL / OCSP signing (called only by the crl/ocsp services, over mTLS)
    # ------------------------------------------------------------------
    def generate_crl(self, *, ca_name: str, validity_hours: int = 24) -> bytes:
        ca = self._get_ca(ca_name)
        revoked_certs = self.session.scalars(
            select(Certificate).where(Certificate.issuing_ca_id == ca.id, Certificate.revoked.is_(True))
        ).all()
        ca.crl_number += 1
        self.session.flush()

        issuer_name = crypto.name_from_attributes(_dn_string_to_attrs(ca.subject_dn))
        now = dt.datetime.now(dt.timezone.utc)
        algorithm = _ALGO_BY_NAME[ca.signature_algorithm]
        crl_der = crypto.build_and_sign_crl(
            issuer_name=issuer_name,
            this_update=now,
            next_update=now + dt.timedelta(hours=validity_hours),
            revoked=[
                (int(c.serial_number, 16), c.revoked_at, c.revocation_reason or "unspecified")
                for c in revoked_certs
            ],
            crl_number=ca.crl_number,
            authority_key_id=bytes.fromhex(ca.subject_key_identifier),
            kms=self.kms,
            key_id=ca.kms_key_id,
            signature_algorithm=algorithm,
        )
        audit.record(self.session, secret=self.audit_secret, actor="system", action="crl.generate",
                      resource=f"ca:{ca_name}", details={"crl_number": ca.crl_number, "revoked_count": len(revoked_certs)})
        return crl_der

    def sign_ocsp_response(self, *, ca_name: str, serial_number: str) -> bytes:
        ca = self._get_ca(ca_name)
        cert = self.session.scalar(select(Certificate).where(Certificate.serial_number == serial_number))
        status = "unknown"
        revoked_at = None
        reason = None
        if cert is not None:
            status = "revoked" if cert.revoked else "good"
            revoked_at = cert.revoked_at
            reason = cert.revocation_reason

        issuer_name = crypto.name_from_attributes(_dn_string_to_attrs(ca.subject_dn))
        public_key = self.kms.public_key(ca.kms_key_id)
        now = dt.datetime.now(dt.timezone.utc)
        algorithm = _ALGO_BY_NAME[ca.signature_algorithm]
        return crypto.build_and_sign_ocsp_response(
            responder_name=issuer_name,
            issuer_public_key=public_key,
            cert_serial=int(serial_number, 16),
            status=status,
            revoked_at=revoked_at,
            revocation_reason=reason,
            this_update=now,
            next_update=now + dt.timedelta(hours=1),
            kms=self.kms,
            key_id=ca.kms_key_id,
            signature_algorithm=algorithm,
        )

    # ------------------------------------------------------------------
    def _get_ca(self, name: str) -> CertificateAuthority:
        ca = self.session.scalar(select(CertificateAuthority).where(CertificateAuthority.name == name))
        if ca is None:
            raise LookupError(f"CA '{name}' not found")
        return ca

    def _enforce_profile(self, profile: CertProfile, public_key, requested_sans: list[str]) -> None:
        allowed_algos = set(profile.allowed_key_algorithms.split(","))
        key_algo = _describe_key_algorithm(public_key)
        if key_algo not in allowed_algos:
            raise PolicyViolation(f"Key algorithm {key_algo} not permitted by profile {profile.name}")
        for san in requested_sans:
            kind = san.split(":", 1)[0]
            if kind == "dns" and not profile.allow_san_dns:
                raise PolicyViolation("DNS SANs not permitted by profile")
            if kind == "ip" and not profile.allow_san_ip:
                raise PolicyViolation("IP SANs not permitted by profile")


def _describe_key_algorithm(public_key) -> str:
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA_{public_key.key_size}"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC_P256" if public_key.curve.name == "secp256r1" else "EC_P384"
    raise PolicyViolation("Unsupported public key algorithm")


def _dn_string_to_attrs(human_friendly_dn: str) -> dict[str, str]:
    """Parse a `cryptography`-style 'CN=x,O=y' human_friendly DN back to attrs."""
    attrs: dict[str, str] = {}
    reverse = {"CN": "cn", "O": "o", "OU": "ou", "C": "c", "ST": "st", "L": "l", "E": "email"}
    for part in human_friendly_dn.split(", "):
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        key = reverse.get(k.strip().upper())
        if key:
            attrs[key] = v.strip()
    return attrs


def _name_from_csr(csr) -> "crypto.a_x509.Name":
    attrs: dict[str, str] = {}
    from cryptography.x509.oid import NameOID

    mapping = {
        NameOID.COMMON_NAME: "cn",
        NameOID.ORGANIZATION_NAME: "o",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "ou",
        NameOID.COUNTRY_NAME: "c",
        NameOID.STATE_OR_PROVINCE_NAME: "st",
        NameOID.LOCALITY_NAME: "l",
    }
    for oid, key in mapping.items():
        values = csr.subject.get_attributes_for_oid(oid)
        if values:
            attrs[key] = values[0].value
    return crypto.name_from_attributes(attrs)
