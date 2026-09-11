"""Mutual TLS enforcement for service-to-service calls.

TLS termination (and client cert verification) happens at the ASGI-server /
nginx layer (`ssl_verify_client on` / uvicorn `--ssl-cert-reqs=2`). This
module extracts the verified client identity forwarded by the proxy
(`X-Client-Cert-CN`, `X-Client-Cert-Verify`) and enforces a strict allow-list
of expected peer identities per endpoint — defense in depth in case the
proxy is ever misconfigured.
"""
from __future__ import annotations

from fastapi import Header, HTTPException, status


def require_mtls_peer(allowed_cns: set[str]):
    async def _dependency(
        x_client_cert_verify: str = Header(default="", alias="X-Client-Cert-Verify"),
        x_client_cert_cn: str = Header(default="", alias="X-Client-Cert-CN"),
    ) -> str:
        if x_client_cert_verify.upper() != "SUCCESS":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "mTLS client certificate verification failed")
        if x_client_cert_cn not in allowed_cns:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Peer '{x_client_cert_cn}' not authorized for this endpoint")
        return x_client_cert_cn

    return _dependency
