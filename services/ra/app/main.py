from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from pkicore.config import get_settings
from pkicore.db.session import build_engine, init_schema, make_session_factory
from pkicore.logging import configure_logging, get_logger

from pkicore.ca_client import CAClient

from app import api
from app.service import RAService

settings = get_settings()
configure_logging("ra", settings.log_level, settings.log_json)
log = get_logger(__name__)

engine = build_engine(settings)
session_factory = make_session_factory(engine)
ca_client = CAClient(settings)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_schema(engine)
    log.info("ra_service_started")
    yield


app = FastAPI(title="PKICA - Registration Authority Service", lifespan=lifespan, docs_url=None, redoc_url=None)
app.include_router(api.router)
app.include_router(api.internal_router)


def _get_session():
    session = session_factory()
    try:
        yield session
        session.commit()
    finally:
        session.close()


def _get_ra_service(session=None):
    from fastapi import Depends

    def _dep(session=Depends(api.get_session_dep)):
        return RAService(session=session, ca_client=ca_client, audit_secret=settings.audit_hash_chain_secret)

    return _dep


app.dependency_overrides[api.get_session_dep] = _get_session
app.dependency_overrides[api.get_ra_service_dep] = _get_ra_service()

if settings.oidc_jwks_url:
    from pkicore.auth.oidc import make_oidc_dependency

    app.dependency_overrides[api.get_current_human_dep] = make_oidc_dependency(settings)
elif settings.environment == "production":
    raise RuntimeError("PKICA_OIDC_JWKS_URL must be configured when PKICA_ENVIRONMENT=production")
else:
    log.warning("oidc_not_configured_using_dev_identity_stub")

    async def _dev_identity_stub():
        return {"sub": "dev-user", "pkica_roles": ["pkica-admin"]}

    app.dependency_overrides[api.get_current_human_dep] = _dev_identity_stub
