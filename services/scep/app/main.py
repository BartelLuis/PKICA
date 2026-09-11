"""SCEP (RFC 8894) server — legacy device enrollment protocol adapter.

Implements GetCACert / GetCACaps fully. PKIOperation implements the common
enrollment path (self-signed PKCSReq wrapping a CSR, RSA key-transport +
AES-128-CBC content encryption) used by the vast majority of real SCEP
clients (sscep, Cisco IOS, Windows NDES clients). SCEP requires a dedicated
RSA *decrypt*-capable keypair (KMS/HSM backends in this platform are
sign-only by design — see pkicore/kms/base.py) — this keypair is generated
once at first startup and persisted to the `scep-ra-key` volume; rotate it
operationally like any other credential.

NOTE: this is a reference implementation of the common-case flow. Validate
against real device/client interop (sscep, vendor NDES clients) before
relying on it in production; see docs/ARCHITECTURE.md.
"""
from __future__ import annotations

import base64
import datetime as dt
import os
import uuid as uuid_mod
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from asn1crypto import cms
from cryptography import x509 as c_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from fastapi import FastAPI, HTTPException, Query, Request, Response

from pkicore.ca_client import CAClient
from pkicore.config import get_settings
from pkicore.logging import configure_logging, get_logger

from app.cms import build_enveloped_data, decrypt_enveloped_data, sign_data

settings = get_settings()
configure_logging("scep", settings.log_level, settings.log_json)
log = get_logger(__name__)

ca_client = CAClient(settings)
_PROFILE_NAME = "scep-device"
_ISSUING_CA_NAME = "issuing-ca-1"
_RA_KEY_DIR = Path(os.environ.get("PKICA_SCEP_RA_KEY_DIR", "/data/scep-ra"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    _RA_KEY_DIR.mkdir(parents=True, exist_ok=True)
    _ensure_ra_keypair()
    log.info("scep_service_started")
    yield


app = FastAPI(title="PKICA - SCEP Server", lifespan=lifespan, docs_url=None, redoc_url=None)


def _ensure_ra_keypair() -> None:
    key_path = _RA_KEY_DIR / "ra.key"
    cert_path = _RA_KEY_DIR / "ra.crt"
    if key_path.exists() and cert_path.exists():
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    os.chmod(key_path, 0o600)

    subject = issuer = c_x509.Name([c_x509.NameAttribute(c_x509.NameOID.COMMON_NAME, "PKICA SCEP RA")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        c_x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(int(uuid_mod.uuid4()))
        .not_valid_before(now).not_valid_after(now + dt.timedelta(days=730))
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    log.warning("scep_ra_keypair_generated_self_signed", note="Replace with a CA-issued RA cert in production")


def _load_ra_key() -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key((_RA_KEY_DIR / "ra.key").read_bytes(), password=None)


def _load_ra_cert_der() -> bytes:
    pem = (_RA_KEY_DIR / "ra.crt").read_bytes()
    return c_x509.load_pem_x509_certificate(pem).public_bytes(c_x509.Encoding.DER)


@app.get("/scep")
def scep_get(operation: str = Query(...), message: str | None = Query(default=None)):
    if operation == "GetCACaps":
        return Response(content="POSTPKIOperation\nSHA-256\nAES\n", media_type="text/plain")

    if operation == "GetCACert":
        ca_info = ca_client.get_ca_certificate(_ISSUING_CA_NAME)
        cert = c_x509.load_pem_x509_certificate(ca_info["certificate_pem"].encode())
        return Response(content=cert.public_bytes(c_x509.Encoding.DER), media_type="application/x-x509-ca-cert")

    if operation == "PKIOperation" and message:
        return _handle_pki_operation(base64.urlsafe_b64decode(message + "=" * (-len(message) % 4)))

    raise HTTPException(400, f"Unsupported SCEP operation: {operation}")


@app.post("/scep")
async def scep_post(request: Request, operation: str = Query(...)):
    if operation != "PKIOperation":
        raise HTTPException(400, f"POST only supported for PKIOperation, got {operation}")
    body = await request.body()
    return _handle_pki_operation(body)


def _handle_pki_operation(der: bytes) -> Response:
    ra_private_key = _load_ra_key()

    def rsa_decrypt(ciphertext: bytes) -> bytes:
        return ra_private_key.decrypt(ciphertext, asym_padding.PKCS1v15())

    try:
        plaintext = decrypt_enveloped_data(der, rsa_decrypt)
        signed = cms.ContentInfo.load(plaintext)["content"]
        pkcs10_der = signed["encap_content_info"]["content"].parsed.dump()
    except Exception as exc:  # noqa: BLE001
        log.error("scep_request_parse_failed", error=str(exc))
        raise HTTPException(400, f"Malformed SCEP PKIOperation: {exc}") from exc

    csr_pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + base64.encodebytes(pkcs10_der).decode() + "-----END CERTIFICATE REQUEST-----\n"
    csr = c_x509.load_pem_x509_csr(csr_pem.encode())
    if not csr.is_signature_valid:
        raise HTTPException(400, "Invalid CSR signature inside SCEP request")

    cert_tuple = None
    if settings.internal_tls_cert and settings.internal_tls_key:
        cert_tuple = (settings.internal_tls_cert, settings.internal_tls_key)
    with httpx.Client(base_url=settings.ra_internal_url, cert=cert_tuple, verify=settings.internal_tls_ca or True, timeout=15.0) as ra:
        resp = ra.post("/internal/v1/requests", json={
            "profile_name": _PROFILE_NAME, "protocol": "scep",
            "requester_identity": csr.subject.rfc4514_string(), "csr_pem": csr_pem, "requested_sans": [],
        })
    if resp.status_code >= 400 or not resp.json().get("issued_certificate_pem"):
        raise HTTPException(502, "SCEP enrollment failed, or requires manual approval (not supported synchronously)")

    issued_pem = resp.json()["issued_certificate_pem"]
    issued_der = c_x509.load_pem_x509_certificate(issued_pem.encode()).public_bytes(c_x509.Encoding.DER)

    def sign_cb(tbs: bytes) -> bytes:
        return ra_private_key.sign(tbs, asym_padding.PKCS1v15(), hashes.SHA256())

    inner_signed = sign_data(issued_der, _load_ra_cert_der(), sign_cb)
    enveloped = build_enveloped_data(inner_signed, _load_ra_cert_der(), csr.public_key())
    response_signed = sign_data(enveloped, _load_ra_cert_der(), sign_cb)
    return Response(content=response_signed, media_type="application/x-pki-message")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
