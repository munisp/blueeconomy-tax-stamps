"""Producer-contract pipeline: port-interoperability wire format end to end.

Builds producer-byte-compatible envelope v1.0 messages exactly as
blueeconomy-port-interoperability internal/events emits them (FHIR R4 message
Bundle whose single entry is a ``Basic`` resource carrying the Declaration
JSON as a ``domain-payload`` string extension; provenance JWS EdDSA over the
RFC 8785 JCS canonicalization, kid ``port-interoperability-<epoch>``), drives
them through the consumer normalization, and then runs the full
declaration -> assessment -> approval -> payment -> issuance chain against
the real database.
"""

from __future__ import annotations

import json
import uuid
from datetime import date

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select

from taxstamps.crypto.eddsa import KeyDirectory, SigningKey
from taxstamps.crypto.jcs import canonicalize_bytes
from taxstamps.crypto.eddsa import jws_sign
from taxstamps.events.consumer import apply_declaration_envelope
from taxstamps.events.envelope import EnvelopeError
from taxstamps.models import Assessment, Declaration, Stamp, StampBatch
from taxstamps.services import assessments, issuance
from taxstamps.services.payments import create_intent, record_receipt

_DOMAIN_PAYLOAD_URL = (
    "https://blueeconomy.gov.ng/fhir/StructureDefinition/domain-payload"
)


@pytest.fixture(scope="module")
def producer_key() -> SigningKey:
    return SigningKey(kid="port-interoperability-0", private_key=Ed25519PrivateKey.generate())


def _producer_envelope(event_id: str, payload: dict, key: SigningKey) -> dict:
    """Byte-compatible with port-interoperability events.Message()."""
    envelope = {
        "envelopeVersion": "1.0",
        "eventId": event_id,
        "eventType": "trade.declaration.submitted.v1",
        "occurredAt": "2026-08-01T10:15:30.123456789Z",
        "producer": "s1-port-interoperability",
        "correlationId": event_id,
        "classification": "INTERNAL",
        "fhir": {
            "resourceType": "Bundle",
            "type": "message",
            "timestamp": "2026-08-01T10:15:30.123456789Z",
            "entry": [
                {
                    "fullUrl": f"urn:uuid:{uuid.uuid4()}",
                    "resource": {
                        "resourceType": "Basic",
                        "id": payload["declaration_ref"],
                        "code": {"text": "trade.declaration.submitted.v1"},
                        "extension": [
                            {"url": _DOMAIN_PAYLOAD_URL, "valueString": json.dumps(payload)},
                        ],
                    },
                }
            ],
        },
        "provenance": {
            "principalId": "singlewindow-1",
            "principalRole": "declaration-producer",
            "signature": "",
        },
    }
    unsigned = {**envelope, "provenance": {k: v for k, v in envelope["provenance"].items() if k != "signature"}}
    envelope["provenance"]["signature"] = jws_sign(key, canonicalize_bytes(unsigned))
    return envelope


_WIRE = {
    "declaration_id": "d-" + uuid.uuid4().hex[:8],
    "tenant_id": "tenant-1",
    "request_id": "req-" + uuid.uuid4().hex[:10],
    "declaration_ref": "C" + uuid.uuid4().hex[:10].upper(),
    "revision": 1,
    "trader_id": "trader-1",
    "declaration_type": "IMPORT",
    "status": "SUBMITTED",
    "hs_code": "240220",
    "goods_description": "Cigarettes containing tobacco",
    "country_of_origin": "NG",
    "port_of_entry": "APAPA",
    "gross_weight_kg": 1200,
    "net_weight_kg": 1000,
    "number_of_packages": 120,
    "consignee_id": "12345678-0001",
    "operator_id": "op-1",
    "is_aeo": False,
    "invoice_amount_minor": 5_000_000,
    "freight_amount_minor": 0,
    "insurance_amount_minor": 0,
    "invoice_currency": "NGN",
    "tariff_bps": 2000,
    "vat_bps": 750,
    "levy_bps": 0,
    "excise_bps": 0,
    "created_at": "2026-08-01T10:15:30Z",
    "updated_at": "2026-08-01T10:15:30Z",
    "version": 1,
}


async def test_producer_wire_envelope_applies(session, producer_key):
    directory = KeyDirectory({producer_key.kid: producer_key.public_key})
    envelope = _producer_envelope("evt-pipe-1", dict(_WIRE), producer_key)
    disposition = await apply_declaration_envelope(envelope, directory, db_session=session)
    await session.commit()
    assert disposition == "applied"
    decl = (
        await session.execute(
            select(Declaration).where(Declaration.declaration_ref == _WIRE["declaration_ref"])
        )
    ).scalar_one()
    assert decl.consignee_tin == "12345678-0001"
    assert decl.source_event_id == "evt-pipe-1"


async def test_untrusted_kid_rejected(session, producer_key):
    rogue = SigningKey(kid="rogue-producer-0", private_key=Ed25519PrivateKey.generate())
    directory = KeyDirectory({rogue.kid: rogue.public_key, producer_key.kid: producer_key.public_key})
    envelope = _producer_envelope("evt-pipe-2", dict(_WIRE), rogue)
    with pytest.raises(EnvelopeError) as exc:
        await apply_declaration_envelope(envelope, directory, db_session=session)
    assert exc.value.reason == "untrusted-kid"
    count = (await session.execute(select(func.count()).select_from(Declaration))).scalar_one()
    assert count == 0


async def test_malformed_domain_payload_rejected(session, producer_key):
    directory = KeyDirectory({producer_key.kid: producer_key.public_key})
    bad = dict(_WIRE)
    del bad["hs_code"]
    envelope = _producer_envelope("evt-pipe-3", bad, producer_key)
    with pytest.raises(EnvelopeError) as exc:
        await apply_declaration_envelope(envelope, directory, db_session=session)
    assert exc.value.reason == "normalization-error"
    count = (await session.execute(select(func.count()).select_from(Declaration))).scalar_one()
    assert count == 0


async def test_tampered_wire_payload_rejected(session, producer_key):
    directory = KeyDirectory({producer_key.kid: producer_key.public_key})
    envelope = _producer_envelope("evt-pipe-4", dict(_WIRE), producer_key)
    ext = envelope["fhir"]["entry"][0]["resource"]["extension"][0]
    tampered = json.loads(ext["valueString"])
    tampered["invoice_amount_minor"] = 1
    ext["valueString"] = json.dumps(tampered)
    with pytest.raises(EnvelopeError) as exc:
        await apply_declaration_envelope(envelope, directory, db_session=session)
    assert exc.value.reason == "payload-mismatch"


async def test_full_declaration_to_issuance_pipeline(session, settings, signing_key, producer_key):
    """Producer envelope -> declaration -> assessment -> approval -> payment
    -> stamp issuance, all against the real database."""
    directory = KeyDirectory({producer_key.kid: producer_key.public_key})
    wire = dict(_WIRE, declaration_ref="C" + uuid.uuid4().hex[:10].upper())
    envelope = _producer_envelope(f"evt-pipe-{uuid.uuid4().hex[:6]}", wire, producer_key)
    assert await apply_declaration_envelope(envelope, directory, db_session=session) == "applied"
    await session.commit()
    declaration = (
        await session.execute(
            select(Declaration).where(Declaration.declaration_ref == wire["declaration_ref"])
        )
    ).scalar_one()

    assessment = await assessments.create_assessment(
        session, declaration=declaration, submitted_by="maker-1",
        idempotency_key=f"idem-{uuid.uuid4().hex[:8]}", on_date=date(2026, 8, 1),
    )
    for approver in ("checker-1", "checker-2", "checker-3")[: assessment.approvals_required]:
        assessment = await assessments.record_decision(
            session, assessment_id=assessment.id, principal_sub=approver, decision="APPROVE",
        )
    assert assessment.status == "APPROVED"

    rail_settings = settings.model_copy(update={
        "payment_rail": "cvff-tigerbeetle",
        "financial_controls_endpoint": "https://financial-controls.example",
        "financial_controls_token": "test-fc-token",
    })
    intent = await create_intent(session, settings=rail_settings, assessment=assessment)
    receipt = await record_receipt(
        session, intent=intent, external_reference=f"rem-{uuid.uuid4().hex[:10]}",
        amount_kobo=intent.expected_amount_kobo, currency="NGN",
    )
    assert receipt.status == "APPLIED"
    fresh = (
        await session.execute(select(Assessment).where(Assessment.id == assessment.id))
    ).scalar_one()
    assert fresh.status == "PAID"

    batch = await issuance.create_batch(session, assessment=fresh, settings=settings)
    total = 0
    while True:
        n = await issuance.issue_chunk(
            session, batch=batch, settings=settings, signing_key=signing_key,
            chunk_size=settings.issuance_chunk_size,
        )
        total += n
        if n == 0:
            break
    await session.commit()
    assert batch.status == "ISSUED"
    stamps = (
        await session.execute(select(Stamp).where(Stamp.batch_id == batch.id))
    ).scalars().all()
    assert len(stamps) == total > 0
    batch_row = (
        await session.execute(select(StampBatch).where(StampBatch.id == batch.id))
    ).scalar_one()
    assert batch_row.issued_count == total
