"""API-level integration: capabilities honesty registry, client-total
rejection, envelope-verified consumer intake, Redis nonce/rate-limit."""

import os

import pytest
from sqlalchemy import func, select, text

from taxstamps.crypto.eddsa import KeyDirectory
from taxstamps.events.consumer import apply_declaration_envelope
from taxstamps.events.envelope import build_envelope, sign_envelope
from taxstamps.models import Declaration, ProcessedEvent


def _declaration_envelope(event_id: str):
    return build_envelope(
        event_type="stamps.assessed.v1",  # envelope plumbing; resource carries the declaration
        resource={
            "declarationRef": f"DECL-{event_id}",
            "consigneeTin": "12345678-0001",
            "consigneeName": "Kafka Importer Ltd",
            "lineItems": [
                {"hsCode": "2202.10", "description": "sweetened soda", "quantity": 5000,
                 "unit": "LITRE", "customsValueKobo": 2_000_000, "stampsRequired": 5000},
            ],
        },
        producer="blueeconomy-port-interoperability",
        classification="CONFIDENTIAL",
        principal_id="singlewindow-1",
        principal_role="declaration-producer",
        event_id=event_id,
    )


async def test_consumer_applies_verified_envelope(session, signing_key):
    directory = KeyDirectory({signing_key.kid: signing_key.public_key})
    envelope = sign_envelope(_declaration_envelope("evt-k-1"), signing_key)
    disposition = await apply_declaration_envelope(envelope, directory, db_session=session)
    await session.commit()
    assert disposition == "applied"
    decl = (await session.execute(
        select(Declaration).where(Declaration.declaration_ref == "DECL-evt-k-1")
    )).scalar_one()
    assert decl.consignee_tin == "12345678-0001"
    lines = (await session.execute(text(
        "SELECT count(*) FROM declaration_lines WHERE declaration_id = :d"
    ), {"d": decl.id})).scalar_one()
    assert lines == 1


async def test_consumer_dedupes_replay(session, signing_key):
    directory = KeyDirectory({signing_key.kid: signing_key.public_key})
    envelope = sign_envelope(_declaration_envelope("evt-k-2"), signing_key)
    assert await apply_declaration_envelope(envelope, directory, db_session=session) == "applied"
    await session.commit()
    assert await apply_declaration_envelope(envelope, directory, db_session=session) == "duplicate"
    await session.commit()
    count = (await session.execute(select(func.count()).select_from(ProcessedEvent))).scalar_one()
    assert count == 1


async def test_consumer_rejects_forged_envelope(session, signing_key):
    directory = KeyDirectory({signing_key.kid: signing_key.public_key})
    envelope = _declaration_envelope("evt-k-3")
    envelope["provenance"]["signature"] = "forged"
    from taxstamps.events.envelope import EnvelopeError

    with pytest.raises(EnvelopeError):
        await apply_declaration_envelope(envelope, directory, db_session=session)
    # rejected envelopes are never persisted
    count = (await session.execute(select(func.count()).select_from(Declaration))).scalar_one()
    assert count == 0


async def test_consumer_rejects_tampered_payload(session, signing_key):
    directory = KeyDirectory({signing_key.kid: signing_key.public_key})
    envelope = sign_envelope(_declaration_envelope("evt-k-4"), signing_key)
    envelope["fhir"]["entry"][0]["resource"]["consigneeTin"] = "99999999-9999"
    from taxstamps.events.envelope import EnvelopeError

    with pytest.raises(EnvelopeError) as exc:
        await apply_declaration_envelope(envelope, directory, db_session=session)
    assert exc.value.reason == "payload-mismatch"


# ------------------------------------------------------------ Redis-gated


@pytest.mark.skipif(
    not os.environ.get("TAXSTAMPS_TEST_REDIS_URL"),
    reason="TAXSTAMPS_TEST_REDIS_URL not set",
)
async def test_redis_nonce_replay_and_rate_limit(monkeypatch):
    from taxstamps.config import Settings
    from taxstamps.services import redis_guard

    settings = Settings(
        database_url="postgresql+asyncpg://x/x", signing_key_path="/dev/null",
        issuer_did="did:web:x", policy_dir="policies",
        redis_url=os.environ["TAXSTAMPS_TEST_REDIS_URL"],
        rate_limit_per_minute=5,
    )
    redis_guard.init_redis(settings)
    try:
        await redis_guard.claim_nonce("taxstamps:test:nonce-1", ttl_seconds=60)
        with pytest.raises(ValueError, match="replay"):
            await redis_guard.claim_nonce("taxstamps:test:nonce-1", ttl_seconds=60)
        for _ in range(5):
            await redis_guard.rate_limit("taxstamps:test:bucket", 5)
        with pytest.raises(ValueError, match="rate limit"):
            await redis_guard.rate_limit("taxstamps:test:bucket", 5)
    finally:
        await redis_guard.get_redis().flushdb()
        await redis_guard.close_redis()
