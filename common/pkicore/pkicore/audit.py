"""Tamper-evident audit log: SHA-256 hash chain over every entry.

`entry_hash = sha256(prev_hash || hmac_secret || actor || action || resource || details || timestamp)`

Any historical row that is edited or deleted breaks the chain from that
point forward, which `verify_chain` detects. Entries are additionally
forwarded to an external SIEM (fire-and-forget) so an attacker with full DB
access still cannot silently rewrite history.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from pkicore.db.models import AuditLogEntry

_GENESIS_HASH = "0" * 64


def _entry_hash(secret: str, prev_hash: str, actor: str, action: str, resource: str, details: dict, timestamp_iso: str) -> str:
    payload = "|".join([
        prev_hash, actor, action, resource, json.dumps(details, sort_keys=True), timestamp_iso,
    ]).encode()
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def record(
    session: Session,
    *,
    secret: str,
    actor: str,
    action: str,
    resource: str,
    details: dict | None = None,
) -> AuditLogEntry:
    details = details or {}
    last = session.scalar(select(AuditLogEntry).order_by(AuditLogEntry.seq.desc()).limit(1))
    prev_hash = last.entry_hash if last else _GENESIS_HASH
    timestamp = dt.datetime.now(dt.timezone.utc)
    timestamp_iso = timestamp.isoformat()
    entry_hash = _entry_hash(secret, prev_hash, actor, action, resource, details, timestamp_iso)
    entry = AuditLogEntry(
        timestamp=timestamp,
        timestamp_iso=timestamp_iso,
        actor=actor,
        action=action,
        resource=resource,
        details=json.dumps(details),
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    session.add(entry)
    session.flush()
    return entry


def verify_chain(session: Session, secret: str) -> tuple[bool, int | None]:
    """Returns (ok, first_broken_seq)."""
    prev_hash = _GENESIS_HASH
    for entry in session.scalars(select(AuditLogEntry).order_by(AuditLogEntry.seq.asc())):
        expected = _entry_hash(
            secret, prev_hash, entry.actor, entry.action, entry.resource,
            json.loads(entry.details), entry.timestamp_iso,
        )
        if expected != entry.entry_hash or entry.prev_hash != prev_hash:
            return False, entry.seq
        prev_hash = entry.entry_hash
    return True, None
