"""Role-based access control, driven by OIDC group/role claims."""
from __future__ import annotations

from fastapi import Depends, HTTPException, status

ROLE_CLAIM = "pkica_roles"


def require_role(*roles: str):
    async def _dependency(claims: dict = Depends(_current_claims_placeholder)) -> dict:
        user_roles = set(claims.get(ROLE_CLAIM, []))
        if not user_roles.intersection(roles):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Requires one of roles: {roles}")
        return claims

    return _dependency


def _current_claims_placeholder():  # pragma: no cover - overridden per-service
    """Each service overrides this dependency with its concrete OIDC dependency
    via `app.dependency_overrides[_current_claims_placeholder] = oidc_dependency`."""
    raise RuntimeError("RBAC claims dependency not wired up")


# Well-known role names shared across services.
ROLE_ADMIN = "pkica-admin"
ROLE_RA_APPROVER = "pkica-ra-approver"
ROLE_AUDITOR = "pkica-auditor"
ROLE_CA_OPERATOR = "pkica-ca-operator"
