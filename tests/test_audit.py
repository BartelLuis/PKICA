"""Unit tests for the tamper-evident audit hash chain (pkicore.audit)."""
from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, delete
from sqlalchemy.orm import sessionmaker

from pkicore import audit
from pkicore.db.models import AuditLogEntry, Base

SECRET = "test-secret"

# The models use the Postgres-specific UUID type, so tests run against a real
# Postgres/CockroachDB-compatible engine rather than SQLite.
_TEST_DATABASE_URL = os.environ.get(
    "PKICA_TEST_DATABASE_URL", "postgresql+psycopg://postgres:test@localhost:15432/pkica_test"
)

_engine = create_engine(_TEST_DATABASE_URL)


@pytest.fixture(scope="session", autouse=True)
def _schema():
    Base.metadata.create_all(_engine)
    yield


@pytest.fixture()
def session():
    session_factory = sessionmaker(bind=_engine)
    session = session_factory()
    session.execute(delete(AuditLogEntry))
    session.commit()
    try:
        yield session
    finally:
        session.close()


def test_chain_verifies_when_untouched(session):
    for i in range(5):
        audit.record(session, secret=SECRET, actor="tester", action="cert.issue", resource=f"cert:{i}")
    session.commit()

    ok, broken_at = audit.verify_chain(session, SECRET)
    assert ok is True
    assert broken_at is None


def test_chain_detects_tampering(session):
    entries = [
        audit.record(session, secret=SECRET, actor="tester", action="cert.issue", resource=f"cert:{i}")
        for i in range(3)
    ]
    session.commit()

    tampered_seq = entries[1].seq
    row = session.query(AuditLogEntry).filter_by(seq=tampered_seq).one()
    row.resource = "cert:tampered"
    session.commit()

    ok, broken_at = audit.verify_chain(session, SECRET)
    assert ok is False
    assert broken_at == tampered_seq


def test_chain_rejects_wrong_secret(session):
    audit.record(session, secret=SECRET, actor="tester", action="cert.issue", resource="cert:0")
    session.commit()

    ok, _ = audit.verify_chain(session, "wrong-secret")
    assert ok is False
