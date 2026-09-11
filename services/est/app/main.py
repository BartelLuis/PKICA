"""RFC 7030 EST server — protocol adapter in front of the RA.

Implements `/cacerts`, `/simpleenroll`, `/simplereenroll`. Initial enrollment
uses HTTP Basic credentials (pluggable validator — wire up your directory
service in `verify_basic_auth`); re-enrollment requires an already-valid
mTLS client certificate (verified by the gateway, forwarded via
`X-Client-Cert-CN`, matched against the CSR's CN).
"""
from __future__ import annotations

import base64
import secrets
from contextlib import asynccontextmanager

import httpx
from cryptography import x509 as c_x509
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from pkicore.ca_client import CAClient
from pkicore.config import get_settings
from pkicore.logging import configure_logging, get_logger

from app.pkcs7 import certs_only_pkcs7

settings = get_settings()
configure_logging("est", settings.log_level, settings.log_json)
log = get_logger(__name__)

ca_client = CAClient(settings)
basic_auth = HTTPBasic()

_PROFILE_NAME = "est-device"
_ISSUING_CA_NAME = "issuing-ca-1"


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("est_service_started")
    yield


app = FastAPI(title="PKICA - EST Server", lifespan=lifespan, docs_url=None, redoc_url=None)


def verify_basic_auth(credentials: HTTPBasicCredentials = Depends(basic_auth)) -> str:
    """Pluggable EST enrollment credential check.

    Reference implementation validates against `PKICA_EST_ENROLLMENT_USERS`
    (comma-separated `user:password` pairs) purely for demo/testing —
    integrate with your enterprise directory (LDAP/AD/RADIUS) here before
    production use.
    """
    import os

    configured = os.environ.get("PKICA_EST_ENROLLMENT_USERS", "")
    valid_pairs = dict(pair.split(":", 1) for pair in configured.split(",") if ":" in pair)
    expected = valid_pairs.get(credentials.username)
    if not expected or not secrets.compare_digest(expected, credentials.password):
        raise HTTPException(401, "Invalid EST enrollment credentials", headers={"WWW-Authenticate": "Basic"})
    return credentials.username


def _ra_submit(*, requester_identity: str, csr_pem: str, sans: list[str]) -> dict:
    cert = None
    if settings.internal_tls_cert and settings.internal_tls_key:
        cert = (settings.internal_tls_cert, settings.internal_tls_key)
    with httpx.Client(base_url=settings.ra_internal_url, cert=cert, verify=settings.internal_tls_ca or True, timeout=15.0) as ra:
        resp = ra.post("/internal/v1/requests", json={
            "profile_name": _PROFILE_NAME, "protocol": "est",
            "requester_identity": requester_identity, "csr_pem": csr_pem, "requested_sans": sans,
        })
    if resp.status_code >= 400:
        raise HTTPException(502, f"RA rejected request: {resp.text}")
    return resp.json()


def _pkcs10_body_to_pem(der_or_b64: bytes) -> str:
    try:
        der = base64.b64decode(der_or_b64, validate=True)
    except Exception:
        der = der_or_b64
    return "-----BEGIN CERTIFICATE REQUEST-----\n" + base64.encodebytes(der).decode() + "-----END CERTIFICATE REQUEST-----\n"


@app.get("/.well-known/est/cacerts")
def cacerts():
    ca_info = ca_client.get_ca_certificate(_ISSUING_CA_NAME)
    cert = c_x509.load_pem_x509_certificate(ca_info["certificate_pem"].encode())
    pkcs7 = certs_only_pkcs7([cert.public_bytes(encoding=c_x509.Encoding.DER)])
    return Response(content=base64.encodebytes(pkcs7), media_type="application/pkcs7-mime")


@app.post("/.well-known/est/simpleenroll")
async def simpleenroll(request: Request, username: str = Depends(verify_basic_auth)):
    body = await request.body()
    csr_pem = _pkcs10_body_to_pem(body)
    csr = c_x509.load_pem_x509_csr(csr_pem.encode())
    if not csr.is_signature_valid:
        raise HTTPException(400, "Invalid CSR signature")

    result = _ra_submit(requester_identity=f"est-user:{username}", csr_pem=csr_pem, sans=[])
    if not result.get("issued_certificate_pem"):
        raise HTTPException(202, "Request pending manual approval")
    cert_der = c_x509.load_pem_x509_certificate(result["issued_certificate_pem"].encode()).public_bytes(c_x509.Encoding.DER)
    pkcs7 = certs_only_pkcs7([cert_der])
    return Response(content=base64.encodebytes(pkcs7), media_type="application/pkcs7-mime")


@app.post("/.well-known/est/simplereenroll")
async def simplereenroll(
    request: Request,
    x_client_cert_verify: str = Header(default="", alias="X-Client-Cert-Verify"),
    x_client_cert_cn: str = Header(default="", alias="X-Client-Cert-CN"),
):
    if x_client_cert_verify.upper() != "SUCCESS":
        raise HTTPException(401, "A valid client certificate is required for EST re-enrollment")

    body = await request.body()
    csr_pem = _pkcs10_body_to_pem(body)
    csr = c_x509.load_pem_x509_csr(csr_pem.encode())
    if not csr.is_signature_valid:
        raise HTTPException(400, "Invalid CSR signature")
    csr_cn = csr.subject.rfc4514_string()
    if x_client_cert_cn not in csr_cn:
        raise HTTPException(403, "CSR subject does not match authenticated client certificate")

    result = _ra_submit(requester_identity=f"est-reenroll:{x_client_cert_cn}", csr_pem=csr_pem, sans=[])
    if not result.get("issued_certificate_pem"):
        raise HTTPException(202, "Request pending manual approval")
    cert_der = c_x509.load_pem_x509_certificate(result["issued_certificate_pem"].encode()).public_bytes(c_x509.Encoding.DER)
    pkcs7 = certs_only_pkcs7([cert_der])
    return Response(content=base64.encodebytes(pkcs7), media_type="application/pkcs7-mime")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
