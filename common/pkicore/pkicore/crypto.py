"""Low-level X.509 construction with externally-signed (KMS/HSM) keys.

`cryptography`'s CertificateBuilder cannot be used here: since v3.5 its
signing path is implemented in Rust and only accepts native OpenSSL-backed
private keys, so a KMS/HSM "sign-only" key cannot be plugged in as a duck-typed
Python object. Instead we build the TBSCertificate ourselves with
`asn1crypto`, ask the KMS backend for a raw signature over the DER bytes,
and assemble the final DER certificate by hand. This is the same technique
used by every serious cloud-KMS-backed CA implementation.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
from dataclasses import dataclass, field

from asn1crypto import algos, core, keys, x509 as a_x509
from cryptography import x509 as c_x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from pkicore.kms.base import KMSBackend, SignatureAlgorithm

_SIGNED_DIGEST_ALGO_ID = {
    SignatureAlgorithm.RSA_PKCS1_SHA256: "sha256_rsa",
    SignatureAlgorithm.RSA_PKCS1_SHA384: "sha384_rsa",
    SignatureAlgorithm.RSA_PSS_SHA256: "sha256_rsa_pss",
    SignatureAlgorithm.ECDSA_SHA256: "sha256_ecdsa",
    SignatureAlgorithm.ECDSA_SHA384: "sha384_ecdsa",
}


def default_algorithm_for_public_key(public_key) -> SignatureAlgorithm:
    if isinstance(public_key, rsa.RSAPublicKey):
        return SignatureAlgorithm.RSA_PKCS1_SHA256 if public_key.key_size <= 3072 else SignatureAlgorithm.RSA_PKCS1_SHA384
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return SignatureAlgorithm.ECDSA_SHA384 if public_key.curve.name == "secp384r1" else SignatureAlgorithm.ECDSA_SHA256
    raise ValueError("Unsupported public key type")


def spki_from_cryptography_public_key(public_key) -> keys.PublicKeyInfo:
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return keys.PublicKeyInfo.load(der)


def raw_public_key_bits(public_key) -> bytes:
    """The raw subjectPublicKey BIT STRING payload (unused-bits count byte
    stripped), independent of RSA-vs-EC-specific ASN.1 parsing quirks."""
    spki = spki_from_cryptography_public_key(public_key)
    contents = spki["public_key"].contents
    return contents[1:]  # first byte is the BIT STRING "unused bits" count (always 0 here)


def compute_subject_key_identifier(public_key) -> bytes:
    """RFC 5280 method 1: SHA-1 of the raw bits of subjectPublicKey (no tag/length)."""
    return c_x509.SubjectKeyIdentifier.from_public_key(public_key).digest


def name_from_attributes(attrs: dict[str, str]) -> a_x509.Name:
    """attrs keys: cn, o, ou, c, st, l, email — insertion order defines RDN order."""
    mapping = {
        "cn": "common_name",
        "o": "organization_name",
        "ou": "organizational_unit_name",
        "c": "country_name",
        "st": "state_or_province_name",
        "l": "locality_name",
        "email": "email_address",
        "serial_number": "serial_number",
    }
    ordered = {mapping[k]: v for k, v in attrs.items() if k in mapping and v}
    return a_x509.Name.build(ordered)


@dataclass
class ExtensionSpec:
    is_ca: bool = False
    path_len: int | None = None
    key_usage: set[str] = field(default_factory=set)
    extended_key_usage: list[str] = field(default_factory=list)
    subject_alt_names: list[str] = field(default_factory=list)  # "dns:x", "ip:1.2.3.4", "email:x"
    crl_distribution_points: list[str] = field(default_factory=list)
    ocsp_urls: list[str] = field(default_factory=list)
    ca_issuer_urls: list[str] = field(default_factory=list)
    subject_key_id: bytes | None = None
    authority_key_id: bytes | None = None


_KEY_USAGE_BITS = [
    "digital_signature", "content_commitment", "key_encipherment",
    "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign",
    "encipher_only", "decipher_only",
]

_EKU_OID = {
    "server_auth": "1.3.6.1.5.5.7.3.1",
    "client_auth": "1.3.6.1.5.5.7.3.2",
    "code_signing": "1.3.6.1.5.5.7.3.3",
    "email_protection": "1.3.6.1.5.5.7.3.4",
    "ocsp_signing": "1.3.6.1.5.5.7.3.9",
}


def _general_names(entries: list[str]) -> a_x509.GeneralNames:
    names = []
    for entry in entries:
        kind, _, value = entry.partition(":")
        if kind == "dns":
            names.append(a_x509.GeneralName({"dns_name": value}))
        elif kind == "ip":
            names.append(a_x509.GeneralName({"ip_address": ipaddress.ip_address(value).packed}))
        elif kind == "email":
            names.append(a_x509.GeneralName({"rfc822_name": value}))
        elif kind == "uri":
            names.append(a_x509.GeneralName({"uniform_resource_identifier": value}))
        else:
            raise ValueError(f"Unsupported SAN entry: {entry}")
    return a_x509.GeneralNames(names)


def build_extensions(spec: ExtensionSpec) -> a_x509.Extensions:
    exts = []

    exts.append(a_x509.Extension({
        "extn_id": "basic_constraints",
        "critical": True,
        "extn_value": a_x509.BasicConstraints({
            "ca": spec.is_ca,
            **({"path_len_constraint": spec.path_len} if spec.path_len is not None else {}),
        }),
    }))

    if spec.key_usage:
        bits = a_x509.KeyUsage(set(spec.key_usage))
        exts.append(a_x509.Extension({"extn_id": "key_usage", "critical": True, "extn_value": bits}))

    if spec.extended_key_usage:
        oids = a_x509.ExtKeyUsageSyntax([_EKU_OID.get(u, u) for u in spec.extended_key_usage])
        exts.append(a_x509.Extension({"extn_id": "extended_key_usage", "critical": False, "extn_value": oids}))

    if spec.subject_alt_names:
        exts.append(a_x509.Extension({
            "extn_id": "subject_alt_name",
            "critical": False,
            "extn_value": _general_names(spec.subject_alt_names),
        }))

    if spec.subject_key_id:
        exts.append(a_x509.Extension({
            "extn_id": "key_identifier",
            "critical": False,
            "extn_value": core.OctetString(spec.subject_key_id),
        }))

    if spec.authority_key_id:
        exts.append(a_x509.Extension({
            "extn_id": "authority_key_identifier",
            "critical": False,
            "extn_value": a_x509.AuthorityKeyIdentifier({"key_identifier": spec.authority_key_id}),
        }))

    if spec.crl_distribution_points:
        points = [
            a_x509.DistributionPoint({
                "distribution_point": a_x509.DistributionPointName(
                    name="full_name", value=_general_names([f"uri:{u}"])
                )
            })
            for u in spec.crl_distribution_points
        ]
        exts.append(a_x509.Extension({
            "extn_id": "crl_distribution_points",
            "critical": False,
            "extn_value": a_x509.CRLDistPoints(points),
        }))

    if spec.ocsp_urls or spec.ca_issuer_urls:
        access = []
        for u in spec.ocsp_urls:
            access.append(a_x509.AccessDescription({
                "access_method": "ocsp",
                "access_location": a_x509.GeneralName({"uniform_resource_identifier": u}),
            }))
        for u in spec.ca_issuer_urls:
            access.append(a_x509.AccessDescription({
                "access_method": "ca_issuers",
                "access_location": a_x509.GeneralName({"uniform_resource_identifier": u}),
            }))
        exts.append(a_x509.Extension({
            "extn_id": "authority_information_access",
            "critical": False,
            "extn_value": a_x509.AuthorityInfoAccessSyntax(access),
        }))

    return a_x509.Extensions(exts)


def build_tbs_certificate(
    *,
    serial_number: int,
    issuer_name: a_x509.Name,
    subject_name: a_x509.Name,
    subject_public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
    not_before: dt.datetime,
    not_after: dt.datetime,
    extensions: a_x509.Extensions,
    signature_algorithm: SignatureAlgorithm,
) -> a_x509.TbsCertificate:
    spki = spki_from_cryptography_public_key(subject_public_key)
    algo_id = algos.SignedDigestAlgorithm({"algorithm": _SIGNED_DIGEST_ALGO_ID[signature_algorithm]})
    return a_x509.TbsCertificate({
        "version": "v3",
        "serial_number": serial_number,
        "signature": algo_id,
        "issuer": issuer_name,
        "validity": {
            "not_before": a_x509.Time({"utc_time": not_before}) if not_before.year < 2050 else a_x509.Time({"general_time": not_before}),
            "not_after": a_x509.Time({"utc_time": not_after}) if not_after.year < 2050 else a_x509.Time({"general_time": not_after}),
        },
        "subject": subject_name,
        "subject_public_key_info": spki,
        "extensions": extensions,
    })


def sign_certificate(
    tbs: a_x509.TbsCertificate,
    kms: KMSBackend,
    key_id: str,
    signature_algorithm: SignatureAlgorithm,
) -> bytes:
    """Sign the TBS with the KMS/HSM backend and return the full DER certificate."""
    tbs_der = tbs.dump()
    signature = kms.sign(key_id, tbs_der, signature_algorithm)
    algo_id = algos.SignedDigestAlgorithm({"algorithm": _SIGNED_DIGEST_ALGO_ID[signature_algorithm]})
    cert = a_x509.Certificate({
        "tbs_certificate": tbs,
        "signature_algorithm": algo_id,
        "signature_value": signature,
    })
    return cert.dump()


def der_to_pem_certificate(der: bytes) -> str:
    return c_x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM).decode()


def load_certificate_der(der: bytes) -> c_x509.Certificate:
    return c_x509.load_der_x509_certificate(der)


def parse_csr(pem: str) -> c_x509.CertificateSigningRequest:
    csr = c_x509.load_pem_x509_csr(pem.encode())
    if not csr.is_signature_valid:
        raise ValueError("CSR signature verification failed")
    return csr


def generate_serial_number() -> int:
    """Cryptographically random 20-byte positive serial (RFC 5280 recommendation
    to make serials unpredictable and prevent CA-prefix collision attacks)."""
    import os

    raw = b"\x00" + os.urandom(19)
    return int.from_bytes(raw, "big")


# ---------------------------------------------------------------------------
# CRL (Certificate Revocation List)
# ---------------------------------------------------------------------------

from asn1crypto import crl as a_crl  # noqa: E402


def build_and_sign_crl(
    *,
    issuer_name: a_x509.Name,
    this_update: dt.datetime,
    next_update: dt.datetime,
    revoked: list[tuple[int, dt.datetime, str]],  # (serial, revoked_at, reason)
    crl_number: int,
    authority_key_id: bytes,
    kms: KMSBackend,
    key_id: str,
    signature_algorithm: SignatureAlgorithm,
) -> bytes:
    revoked_entries = []
    for serial, revoked_at, reason in revoked:
        revoked_entries.append(a_crl.RevokedCertificate({
            "user_certificate": serial,
            "revocation_date": a_crl.Time({"utc_time": revoked_at}),
            "crl_entry_extensions": a_crl.CRLEntryExtensions([
                a_crl.CRLEntryExtension({
                    "extn_id": "crl_reason",
                    "critical": False,
                    "extn_value": a_crl.CRLReason(reason),
                })
            ]),
        }))

    algo_id = algos.SignedDigestAlgorithm({"algorithm": _SIGNED_DIGEST_ALGO_ID[signature_algorithm]})
    tbs = a_crl.TbsCertList({
        "version": "v2",
        "signature": algo_id,
        "issuer": issuer_name,
        "this_update": a_crl.Time({"utc_time": this_update}),
        "next_update": a_crl.Time({"utc_time": next_update}),
        "revoked_certificates": a_crl.RevokedCertificates(revoked_entries),
        "crl_extensions": a_crl.TBSCertListExtensions([
            a_crl.TBSCertListExtension({
                "extn_id": "crl_number",
                "critical": False,
                "extn_value": core.Integer(crl_number),
            }),
            a_crl.TBSCertListExtension({
                "extn_id": "authority_key_identifier",
                "critical": False,
                "extn_value": a_x509.AuthorityKeyIdentifier({"key_identifier": authority_key_id}),
            }),
        ]),
    })
    tbs_der = tbs.dump()
    signature = kms.sign(key_id, tbs_der, signature_algorithm)
    crl_obj = a_crl.CertificateList({
        "tbs_cert_list": tbs,
        "signature_algorithm": algo_id,
        "signature": signature,
    })
    return crl_obj.dump()


# ---------------------------------------------------------------------------
# OCSP (RFC 6960)
# ---------------------------------------------------------------------------

from asn1crypto import ocsp as a_ocsp  # noqa: E402


def build_and_sign_ocsp_response(
    *,
    responder_name: a_x509.Name,
    issuer_public_key,
    cert_serial: int,
    status: str,  # "good" | "revoked" | "unknown"
    revoked_at: dt.datetime | None,
    revocation_reason: str | None,
    this_update: dt.datetime,
    next_update: dt.datetime,
    kms: KMSBackend,
    key_id: str,
    signature_algorithm: SignatureAlgorithm,
) -> bytes:
    if status == "good":
        cert_status = a_ocsp.CertStatus(name="good", value=core.Null())
    elif status == "revoked":
        cert_status = a_ocsp.CertStatus(name="revoked", value=a_ocsp.RevokedInfo({
            "revocation_time": revoked_at,
            "revocation_reason": revocation_reason or "unspecified",
        }))
    else:
        cert_status = a_ocsp.CertStatus(name="unknown", value=core.Null())

    issuer_key_hash = hashlib.sha256(raw_public_key_bits(issuer_public_key)).digest()

    single_response = a_ocsp.SingleResponse({
        "cert_id": a_ocsp.CertId({
            "hash_algorithm": {"algorithm": "sha256"},
            "issuer_name_hash": hashlib.sha256(responder_name.dump()).digest(),
            "issuer_key_hash": issuer_key_hash,
            "serial_number": cert_serial,
        }),
        "cert_status": cert_status,
        "this_update": this_update,
        "next_update": next_update,
    })

    algo_id = algos.SignedDigestAlgorithm({"algorithm": _SIGNED_DIGEST_ALGO_ID[signature_algorithm]})
    tbs_response_data = a_ocsp.ResponseData({
        "responder_id": a_ocsp.ResponderId(name="by_name", value=responder_name),
        "produced_at": dt.datetime.now(dt.timezone.utc),
        "responses": a_ocsp.Responses([single_response]),
    })
    tbs_der = tbs_response_data.dump()
    signature = kms.sign(key_id, tbs_der, signature_algorithm)

    basic_response = a_ocsp.BasicOCSPResponse({
        "tbs_response_data": tbs_response_data,
        "signature_algorithm": algo_id,
        "signature": signature,
    })
    response = a_ocsp.OCSPResponse({
        "response_status": "successful",
        "response_bytes": a_ocsp.ResponseBytes({
            "response_type": "basic_ocsp_response",
            "response": basic_response,
        }),
    })
    return response.dump()
