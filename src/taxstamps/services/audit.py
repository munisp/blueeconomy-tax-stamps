"""Hash-chained append-only audit.

Each event's hash is SHA-256 over ``prev_hash + "." + JCS(payload-envelope)``;
genesis prev_hash is "0"*64. Serialization uses a PostgreSQL transaction-level
advisory lock so concurrent writers can never fork the chain. UPDATE and
DELETE are rejected by database triggers (migration 0001), so the chain is
append-only even under a compromised application credential.

The chain is asymmetric-trust aligned with the platform: payloads that must
be externally attributable are JWS-signed in the envelope layer; the audit
chain guarantees *ordering and tamper-evidence*, not attribution.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from taxstamps.crypto.jcs import canonicalize_bytes
from taxstamps.models import AuditEvent

GENESIS_HASH = "0" * 64
_ADVISORY_LOCK_KEY = 0x5441_5853_5453_4155  # "TAXSTSAU" namespaced lock


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _chain_hash(prev_hash: str, event_type: str, payload: dict[str, Any], created_iso: str) -> str:
    body = canonicalize_bytes({"eventType": event_type, "payload": payload, "recordedAt": created_iso})
    return hashlib.sha256(prev_hash.encode("ascii") + b"." + body).hexdigest()


async def record(
    session: AsyncSession,
    event_type: str,
    payload: dict[str, Any],
) -> AuditEvent:
    """Append an audit event inside the caller's transaction.

    The row is inserted exactly once (UPDATEs are trigger-rejected): the
    timestamp is assigned application-side so the hash can be computed
    before INSERT.
    """
    await session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _ADVISORY_LOCK_KEY})
    row = (
        await session.execute(text("SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1"))
    ).first()
    prev_hash = row[0] if row else GENESIS_HASH
    from taxstamps.models import utcnow

    now = utcnow()
    created_iso = _iso(now)
    clean_payload = json.loads(json.dumps(payload))
    event = AuditEvent(
        event_type=event_type,
        payload=clean_payload,
        prev_hash=prev_hash,
        hash=_chain_hash(prev_hash, event_type, clean_payload, created_iso),
        created_at=now,
    )
    session.add(event)
    await session.flush()
    return event


@dataclass(frozen=True)
class ChainVerification:
    ok: bool
    events: int
    first_bad_id: int | None = None
    detail: str = ""


async def verify_chain(session: AsyncSession) -> ChainVerification:
    """Full recompute of the chain. O(n); intended for ops/audit endpoints."""
    rows = (
        await session.execute(
            text("SELECT id, prev_hash, hash, event_type, payload, created_at FROM audit_events ORDER BY id")
        )
    ).mappings().all()
    prev = GENESIS_HASH
    for row in rows:
        created_iso = row["created_at"].strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        expected = _chain_hash(prev, row["event_type"], row["payload"], created_iso)
        if row["prev_hash"] != prev:
            return ChainVerification(False, row["id"], row["id"], "prev_hash link broken")
        if row["hash"] != expected:
            return ChainVerification(False, row["id"], row["id"], "hash mismatch: payload tampered")
        prev = row["hash"]
    return ChainVerification(True, len(rows))
