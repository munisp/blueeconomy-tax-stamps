"""trade.declarations.v1 Kafka consumer.

Consumes customs declaration events in canonical envelope v1.0 (FHIR message
Bundle wrap, JWS-EdDSA signature verified against the mounted key directory —
fail-closed: rejected envelopes are never persisted), persists the
declaration + line items, dedupes on the envelope eventId, and commits the
Kafka offset only after the database commit.

Subscribed topic is governed by ``kafka_declarations_topic_pattern``
(default ``trade.declarations.v1``, the only real declaration producer in
the platform: blueeconomy-port-interoperability).

Expected primary resource (CustomsDeclarationFiled style), carried as the
FHIR Bundle's single entry resource:

  {"@type": "...CustomsDeclarationFiled", "declarationRef": "...",
   "consigneeTin": "...", "consigneeName": "...",
   "lineItems": [{"hsCode": "...", "description": "...", "quantity": n,
                  "unit": "STICK|LITRE|UNIT", "customsValueKobo": n,
                  "stampsRequired": n}]}
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from sqlalchemy import select

from taxstamps.config import get_settings
from taxstamps.crypto.eddsa import KeyDirectory
from taxstamps.db import dispose_engine, init_engine, session
from taxstamps.events.envelope import EnvelopeError, verify_envelope
from taxstamps.models import Declaration, DeclarationLine, ProcessedEvent, utcnow
from taxstamps.services import audit

log = logging.getLogger("taxstamps.consumer")

_REQUIRED_RESOURCE_FIELDS = {"declarationRef", "consigneeTin", "lineItems"}


def topic_pattern_regex(pattern: str) -> str:
    """Compile a settings topic pattern (``.``-separated, ``*`` wildcard)
    into an anchored regular expression, e.g. ``trade.declarations.v1`` ->
    ``^trade\\.declarations\\.v1$``."""
    return "^" + pattern.replace(".", r"\.").replace("*", ".*") + "$"


async def apply_declaration_envelope(
    envelope: dict[str, Any],
    directory: KeyDirectory,
    db_session: Any = None,
) -> str:
    """Verify + persist one declaration envelope. Returns a disposition:
    'applied' | 'duplicate'. Raises EnvelopeError/ValueError on rejection.

    When ``db_session`` is supplied the caller owns the transaction/commit;
    otherwise a session is opened and committed here (consumer path)."""
    resource = verify_envelope(envelope, directory)
    missing = _REQUIRED_RESOURCE_FIELDS - set(resource)
    if missing:
        raise ValueError(f"declaration resource missing fields {sorted(missing)}")
    if db_session is not None:
        return await _apply(db_session, envelope, resource)
    async with session() as s:
        disposition = await _apply(s, envelope, resource)
        await s.commit()
        return disposition


async def _apply(s: Any, envelope: dict[str, Any], resource: dict[str, Any]) -> str:
    event_id = envelope["eventId"]
    lines = resource["lineItems"]
    if not isinstance(lines, list) or not lines:
        raise ValueError("lineItems must be a non-empty array")
    seen = (
        await s.execute(select(ProcessedEvent).where(ProcessedEvent.event_id == event_id))
    ).scalar_one_or_none()
    if seen is not None:
        return "duplicate"
    declaration = Declaration(
        id=uuid.uuid4(),
        declaration_ref=str(resource["declarationRef"]),
        consignee_tin=str(resource["consigneeTin"]),
        consignee_name=str(resource.get("consigneeName", "")),
        source_event_id=event_id,
        occurred_at=utcnow(),
        envelope=envelope,
    )
    s.add(declaration)
    for raw in lines:
        s.add(
            DeclarationLine(
                id=uuid.uuid4(),
                declaration_id=declaration.id,
                hs_code=str(raw["hsCode"]),
                description=str(raw.get("description", "")),
                quantity=int(raw["quantity"]),
                unit=str(raw["unit"]),
                customs_value_kobo=int(raw.get("customsValueKobo", 0)),
                stamps_required=int(raw.get("stampsRequired", raw["quantity"])),
            )
        )
    s.add(ProcessedEvent(event_id=event_id, event_type=envelope["eventType"]))
    await audit.record(s, "declaration.received", {
        "declarationRef": declaration.declaration_ref,
        "eventId": event_id,
        "producer": envelope.get("producer", ""),
    })
    await s.flush()
    return "applied"


async def consume_forever() -> None:
    settings = get_settings()
    if not settings.kafka_configured:
        raise RuntimeError("TAXSTAMPS_KAFKA_BOOTSTRAP_SERVERS is required for the consumer")
    if not settings.key_directory_path:
        raise RuntimeError("TAXSTAMPS_KEY_DIRECTORY_PATH is required for the consumer")
    if not settings.database_url:
        raise RuntimeError("TAXSTAMPS_DATABASE_URL is required for the consumer")
    from aiokafka import AIOKafkaConsumer

    init_engine(settings.database_url)
    directory = KeyDirectory.load(settings.key_directory_path)
    pattern = topic_pattern_regex(settings.kafka_declarations_topic_pattern)
    consumer = AIOKafkaConsumer(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        group_id=settings.kafka_consumer_group,
        enable_auto_commit=False,
    )
    await consumer.start()
    consumer.subscribe(pattern=pattern)
    log.info("consumer subscribed to %s", pattern)
    try:
        async for msg in consumer:
            try:
                import json

                envelope = json.loads(msg.value.decode("utf-8"))
                disposition = await apply_declaration_envelope(envelope, directory)
                log.info("declaration event %s: %s", envelope.get("eventId"), disposition)
            except (EnvelopeError, ValueError, KeyError) as exc:
                # Rejected envelopes are never persisted; they are logged and
                # the offset is still committed (poison messages must not
                # stall the partition; a dead-letter topic is platform
                # infrastructure outside this repo).
                log.error("rejected declaration envelope: %s", exc)
            await consumer.commit()
    finally:
        await consumer.stop()
        await dispose_engine()


def run_consumer() -> None:
    logging.basicConfig(level=logging.INFO)
    asyncio.run(consume_forever())


if __name__ == "__main__":
    run_consumer()
