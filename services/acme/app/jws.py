"""Minimal ACME (RFC 8555) JWS handling: verification + RFC 7638 thumbprints."""
from __future__ import annotations

import base64
import hashlib
import json

from jose import jws as jose_jws
from jose.utils import base64url_decode


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint (base64url, no padding)."""
    kty = jwk["kty"]
    if kty == "RSA":
        canonical = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif kty == "EC":
        canonical = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    else:
        raise ValueError(f"Unsupported JWK kty: {kty}")
    digest = hashlib.sha256(json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def verify_and_decode(flat_jws: dict, jwk: dict) -> tuple[dict, dict]:
    """Verify a flattened-JSON ACME JWS against `jwk`, return (protected_header, payload)."""
    protected_b64 = flat_jws["protected"]
    payload_b64 = flat_jws.get("payload", "")
    signature_b64 = flat_jws["signature"]
    compact = f"{protected_b64}.{payload_b64}.{signature_b64}"

    protected = json.loads(b64url_decode(protected_b64))
    alg = protected["alg"]
    key = _jwk_to_jose_key(jwk, alg)

    jose_jws.verify(compact, key, algorithms=[alg])
    payload = json.loads(b64url_decode(payload_b64)) if payload_b64 else {}
    return protected, payload


def _jwk_to_jose_key(jwk: dict, alg: str) -> dict:
    return jwk
