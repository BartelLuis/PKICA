"""Shared mTLS client for internal calls to the CA service (via ca-mtls-proxy).

Used by the RA (issue/revoke) and by the OCSP/CRL responders (signing
delegation) — every internal caller authenticates with its own client
certificate issued by the platform's internal "infra" CA.
"""
from __future__ import annotations

import re
from urllib.parse import quote

import httpx

from pkicore.config import Settings


_MAX_CA_NAME_LENGTH = 255
_CA_NAME_PATTERN = re.compile(rf"[A-Za-z0-9][A-Za-z0-9._-]{{0,{_MAX_CA_NAME_LENGTH - 1}}}\Z")


def _ca_name_path_segment(client: httpx.Client, ca_name: str, *, request_path: str) -> str:
    if not _CA_NAME_PATTERN.fullmatch(ca_name):
        raise httpx.RequestError("Invalid CA name", request=client.build_request("GET", request_path))
    return quote(ca_name, safe="")


class CAClient:
    def __init__(self, settings: Settings) -> None:
        cert = None
        if settings.internal_tls_cert and settings.internal_tls_key:
            cert = (settings.internal_tls_cert, settings.internal_tls_key)
        self._client = httpx.Client(
            base_url=settings.ca_internal_url,
            cert=cert,
            verify=settings.internal_tls_ca or True,
            timeout=15.0,
        )

    def issue(self, *, ca_name: str, profile_name: str, csr_pem: str, requested_sans: list[str],
              validity_days: int, requester_identity: str) -> dict:
        resp = self._client.post("/internal/v1/issue", json={
            "ca_name": ca_name, "profile_name": profile_name, "csr_pem": csr_pem,
            "requested_sans": requested_sans, "validity_days": validity_days,
            "requester_identity": requester_identity,
        })
        resp.raise_for_status()
        return resp.json()

    def revoke(self, *, serial_number: str, reason: str, actor: str) -> dict:
        resp = self._client.post("/internal/v1/revoke", json={
            "serial_number": serial_number, "reason": reason, "actor": actor,
        })
        resp.raise_for_status()
        return resp.json()

    def get_ca_certificate(self, ca_name: str) -> dict:
        safe_ca_name = _ca_name_path_segment(self._client, ca_name, request_path="/internal/v1/ca/_/certificate")
        resp = self._client.get(f"/internal/v1/ca/{safe_ca_name}/certificate")
        resp.raise_for_status()
        return resp.json()

    def fetch_crl(self, ca_name: str) -> bytes:
        safe_ca_name = _ca_name_path_segment(self._client, ca_name, request_path="/internal/v1/crl/_")
        resp = self._client.get(f"/internal/v1/crl/{safe_ca_name}")
        resp.raise_for_status()
        return resp.content

    def sign_ocsp(self, *, ca_name: str, serial_number: str) -> bytes:
        resp = self._client.post("/internal/v1/ocsp/sign", json={"ca_name": ca_name, "serial_number": serial_number})
        resp.raise_for_status()
        return resp.content
