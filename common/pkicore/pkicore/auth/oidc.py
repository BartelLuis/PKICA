"""OIDC/SSO authentication for human operators (RA approvals, admin UI/API)."""
from __future__ import annotations

import time

import httpx
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt

from pkicore.config import Settings

_bearer = HTTPBearer(auto_error=True)


class JWKSCache:
    def __init__(self, jwks_url: str, ttl_seconds: int = 300) -> None:
        self._url = jwks_url
        self._ttl = ttl_seconds
        self._jwks: dict | None = None
        self._fetched_at = 0.0

    def get(self) -> dict:
        if self._jwks is None or (time.time() - self._fetched_at) > self._ttl:
            resp = httpx.get(self._url, timeout=5.0)
            resp.raise_for_status()
            self._jwks = resp.json()
            self._fetched_at = time.time()
        return self._jwks


def make_oidc_dependency(settings: Settings):
    if not settings.oidc_jwks_url:
        raise RuntimeError("OIDC_JWKS_URL must be configured to enable human authentication")
    cache = JWKSCache(settings.oidc_jwks_url)

    async def _dependency(creds: HTTPAuthorizationCredentials = Depends(_bearer)) -> dict:
        try:
            claims = jwt.decode(
                creds.credentials,
                cache.get(),
                audience=settings.oidc_audience,
                issuer=settings.oidc_issuer,
                options={"verify_at_hash": False},
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as 401 regardless of cause
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Invalid token: {exc}") from exc
        return claims

    return _dependency
