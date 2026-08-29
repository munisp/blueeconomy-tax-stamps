"""Transactional outbox. Domain services enqueue signed envelope-v1.0 events
in the SAME transaction as the state change; a separate publisher process
drains the outbox to Kafka (at-least-once, outbox id as the Kafka key).

When Kafka is unconfigured the messages remain PENDING — fail-closed, never
silently dropped — and the capabilities registry reports the publisher as
unavailable.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from taxstamps.config import PRODUCER, Settings
from taxstamps.crypto.eddsa import SigningKey
from taxstamps.events.envelope import build_envelope, sign_envelope
from taxstamps.models import OutboxMessage

TOPIC_BY_EVENT = {
    "stamps.assessed.v1": "stamps.assessed",
    "stamps.approved.v1": "stamps.approved",
    "stamps.issued.v1": "stamps.issued",
    "stamps.activated.v1": "stamps.activated",
    "stamps.verified.v1": "stamps.verified",
    "stamps.voided.v1": "stamps.voided",
}

_CLASSIFICATION_BY_EVENT = {
    "stamps.assessed.v1": "CONFIDENTIAL",
    "stamps.approved.v1": "CONFIDENTIAL",
    "stamps.issued.v1": "CONFIDENTIAL",
    "stamps.activated.v1": "INTERNAL",
    "stamps.verified.v1": "INTERNAL",
    "stamps.voided.v1": "CONFIDENTIAL",
}


async def enqueue(
    session: AsyncSession,
    *,
    event_type: str,
    resource: dict[str, Any],
    signing_key: SigningKey,
    principal_id: str,
    principal_role: str,
    correlation_id: str | None = None,
) -> OutboxMessage:
    """Build + sign an envelope and persist it in the outbox (caller's tx)."""
    topic = TOPIC_BY_EVENT[event_type]
    envelope = build_envelope(
        event_type=event_type,
        resource=resource,
        producer=PRODUCER,
        classification=_CLASSIFICATION_BY_EVENT[event_type],
        principal_id=principal_id,
        principal_role=principal_role,
        correlation_id=correlation_id,
    )
    signed = sign_envelope(envelope, signing_key)
    msg = OutboxMessage(
        id=uuid.uuid4(),
        topic=topic,
        key=str(resource.get("assessmentId") or resource.get("batchId") or resource.get("serial") or ""),
        envelope=signed,
    )
    session.add(msg)
    await session.flush()
    return msg


def publisher_available(settings: Settings) -> tuple[bool, str]:
    if not settings.kafka_configured:
        return False, "TAXSTAMPS_KAFKA_BOOTSTRAP_SERVERS not configured"
    return True, ""
