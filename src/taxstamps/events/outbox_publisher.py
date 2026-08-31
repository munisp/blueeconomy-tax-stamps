"""Outbox publisher: drains outbox_messages to Kafka, at-least-once.

The Kafka key is the outbox message id (idempotent compaction-friendly key);
published_at is set only after the broker acknowledges. When Kafka is
unconfigured the process refuses to start and messages remain PENDING —
fail-closed, never dropped.
"""

from __future__ import annotations

import asyncio
import json
import logging

from sqlalchemy import select

from taxstamps.config import get_settings
from taxstamps.db import dispose_engine, init_engine, session
from taxstamps.models import OutboxMessage, utcnow

log = logging.getLogger("taxstamps.outbox")

_POLL_SECONDS = 1.0
_BATCH = 100


async def publish_once(producer) -> int:  # type: ignore[no-untyped-def]
    async with session() as s:
        rows = (
            await s.execute(
                select(OutboxMessage)
                .where(OutboxMessage.published_at.is_(None))
                .order_by(OutboxMessage.created_at)
                .limit(_BATCH)
                .with_for_update(skip_locked=True)
            )
        ).scalars().all()
        for msg in rows:
            await producer.send_and_wait(
                msg.topic,
                json.dumps(msg.envelope, separators=(",", ":")).encode("utf-8"),
                key=str(msg.id).encode("ascii"),
            )
            msg.published_at = utcnow()
            msg.attempts += 1
        await s.commit()
        return len(rows)


async def publish_forever() -> None:
    settings = get_settings()
    if not settings.kafka_configured:
        raise RuntimeError("TAXSTAMPS_KAFKA_BOOTSTRAP_SERVERS is required for the outbox publisher")
    if not settings.database_url:
        raise RuntimeError("TAXSTAMPS_DATABASE_URL is required for the outbox publisher")
    from aiokafka import AIOKafkaProducer

    init_engine(settings.database_url)
    producer = AIOKafkaProducer(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        enable_idempotence=True,
        linger_ms=settings.kafka_linger_ms,
        max_batch_size=settings.kafka_max_batch_size,
    )
    await producer.start()
    log.info("outbox publisher started")
    try:
        while True:
            published = await publish_once(producer)
            if published == 0:
                await asyncio.sleep(_POLL_SECONDS)
    finally:
        await producer.stop()
        await dispose_engine()


def run_publisher() -> None:
    logging.basicConfig(level=logging.INFO)
    asyncio.run(publish_forever())


if __name__ == "__main__":
    run_publisher()
