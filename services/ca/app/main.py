from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from pkicore.config import get_settings
from pkicore.db.session import build_engine, init_schema, make_session_factory
from pkicore.kms.factory import build_kms_backend
from pkicore.logging import configure_logging, get_logger

from app import api

settings = get_settings()
configure_logging(settings.service_name or "ca", settings.log_level, settings.log_json)
log = get_logger(__name__)

engine = build_engine(settings)
session_factory = make_session_factory(engine)
kms_backend = build_kms_backend(settings)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_schema(engine)
    log.info("ca_service_started", backend=kms_backend.name)
    yield


app = FastAPI(title="PKICA - Certificate Authority Service", lifespan=lifespan, docs_url=None, redoc_url=None)
app.include_router(api.router)


def _get_session():
    session = session_factory()
    try:
        yield session
        session.commit()
    finally:
        session.close()


app.dependency_overrides[api.get_session_dep] = _get_session
app.dependency_overrides[api.get_kms_dep] = lambda: kms_backend
app.dependency_overrides[api.get_audit_secret_dep] = lambda: settings.audit_hash_chain_secret
