"""Database session management with TLS-enforced CockroachDB connections."""
from __future__ import annotations

from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from pkicore.config import Settings
from pkicore.db.models import Base


def build_engine(settings: Settings):
    connect_args = {}
    if settings.database_ssl_root_cert:
        connect_args["sslrootcert"] = settings.database_ssl_root_cert
        connect_args["sslmode"] = "verify-full"
    return create_engine(
        settings.database_url,
        pool_size=settings.database_pool_size,
        pool_pre_ping=True,
        connect_args=connect_args,
    )


def init_schema(engine) -> None:
    """Create tables if they do not exist. Production deployments should
    manage schema via a migration tool (Alembic) instead — this is provided
    for first-run bootstrap and local development."""
    Base.metadata.create_all(engine)


def make_session_factory(engine) -> sessionmaker:
    return sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


@contextmanager
def session_scope(session_factory: sessionmaker):
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
