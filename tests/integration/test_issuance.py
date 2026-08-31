"""Chunked crash-safe issuance, atomic serial-block claims, Z1.4 gating,
activation, and per-stamp VC verification."""

import asyncio

import pytest
from sqlalchemy import select, text

from taxstamps.crypto.vc import verify_proof
from taxstamps.domain.quality import plan_for_lot
from taxstamps.models import Stamp, StampBatch
from taxstamps.services import issuance
from taxstamps.services.issuance import IssuanceError, _claim_serial_block
from tests.integration.conftest import make_paid_assessment


async def _paid_batch(session, settings, stamps=250):
    assessment = await make_paid_assessment(session, settings, duty_lines=[
        {"hs_code": "2402.20", "quantity": stamps, "unit": "STICK",
         "customs_value_kobo": 0, "stamps_required": stamps},
    ])
    batch = await issuance.create_batch(session, assessment=assessment, settings=settings)
    await session.commit()
    return assessment, batch


async def test_chunked_issuance_resumes(session, settings, signing_key):
    _, batch = await _paid_batch(session, settings, stamps=250)
    n1 = await issuance.issue_chunk(session, batch=batch, settings=settings,
                                    signing_key=signing_key, chunk_size=100)
    await session.commit()
    assert n1 == 100
    # simulate crash/restart: re-load batch, continue
    fresh = (await session.execute(select(StampBatch).where(StampBatch.id == batch.id))).scalar_one()
    assert fresh.issued_count == 100 and fresh.status == "ISSUING"
    n2 = await issuance.issue_chunk(session, batch=fresh, settings=settings,
                                    signing_key=signing_key, chunk_size=100)
    n3 = await issuance.issue_chunk(session, batch=fresh, settings=settings,
                                    signing_key=signing_key, chunk_size=100)
    n4 = await issuance.issue_chunk(session, batch=fresh, settings=settings,
                                    signing_key=signing_key, chunk_size=100)
    await session.commit()
    assert (n2, n3, n4) == (100, 50, 0)
    assert fresh.status == "ISSUED"
    count = (await session.execute(select(Stamp).where(Stamp.batch_id == batch.id))).scalars().all()
    assert len(count) == 250
    serials = {s.serial for s in count}
    assert len(serials) == 250  # no duplicates


async def test_every_stamp_vc_verifies(session, settings, signing_key):
    _, batch = await _paid_batch(session, settings, stamps=10)
    await issuance.issue_chunk(session, batch=batch, settings=settings,
                               signing_key=signing_key, chunk_size=10)
    await session.commit()
    stamps = (await session.execute(select(Stamp).where(Stamp.batch_id == batch.id))).scalars().all()
    assert len(stamps) == 10
    for stamp in stamps:
        verify_proof(stamp.credential, signing_key.public_key)
        subject = stamp.credential["credentialSubject"]
        assert subject["serial"] == stamp.serial
        assert subject["stampScope"] == "unit"
        assert subject["batchId"] == str(batch.id)
        assert len(stamp.credential["credentialStatus"]) == 3


async def test_unit_stamp_credential_hides_consignment_duty(session, settings, signing_key):
    """TS-1: the public unit credential carries no consignment-duty field;
    consignment duty stays resolvable via the assessment reference only."""
    assessment, batch = await _paid_batch(session, settings, stamps=10)
    await issuance.issue_chunk(session, batch=batch, settings=settings,
                               signing_key=signing_key, chunk_size=10)
    await session.commit()
    stamps = (await session.execute(select(Stamp).where(Stamp.batch_id == batch.id))).scalars().all()
    for stamp in stamps:
        subject = stamp.credential["credentialSubject"]
        assert "dutyPaidKobo" not in subject
        assert "consigneeTin" not in subject
        assert "declarationRef" not in subject
        # unit-scoped references only
        assert subject["assessmentRef"] == str(assessment.id)
    # authorized resolution path: the internal (policy-gated) record still
    # resolves the full assessment with its duty amount
    from taxstamps.models import Assessment

    resolved = (await session.execute(
        select(Assessment).where(Assessment.id == assessment.id)
    )).scalar_one()
    assert resolved.total_duty_kobo > 0
    assert resolved.status in ("ISSUING", "ISSUED")




async def test_finalize_computes_merkle_and_outbox(session, settings, signing_key):
    _, batch = await _paid_batch(session, settings, stamps=5)
    await issuance.issue_chunk(session, batch=batch, settings=settings, signing_key=signing_key)
    batch = await issuance.finalize_batch(session, batch=batch, signing_key=signing_key,
                                          principal_sub="officer-1")
    await session.commit()
    assert len(batch.merkle_root) == 64
    assert batch.status == "READY"
    rows = (await session.execute(text(
        "SELECT topic, envelope FROM outbox_messages WHERE topic = 'stamps.issued'"
    ))).all()
    assert len(rows) == 1
    envelope = rows[0][1]
    assert envelope["eventType"] == "stamps.issued.v1"
    assert envelope["provenance"]["signature"]


async def test_serial_block_claims_never_overlap(session_factory):
    factory = session_factory

    async def claim(n):
        async with factory() as s:
            base = await _claim_serial_block(s, "TBC", 2027, n)
            await s.commit()
            return base

    bases = await asyncio.gather(*[claim(10) for _ in range(8)])
    ranges = [range(b, b + 10) for b in bases]
    seen = set()
    for r in ranges:
        assert not (seen & set(r)), "overlapping serial blocks"
        seen |= set(r)
    assert len(seen) == 80


async def test_inspection_fail_blocks_activation(session, settings, signing_key):
    _, batch = await _paid_batch(session, settings, stamps=250)
    while await issuance.issue_chunk(session, batch=batch, settings=settings, signing_key=signing_key):
        pass
    batch = await issuance.finalize_batch(session, batch=batch, signing_key=signing_key,
                                          principal_sub="officer-1")
    plan = plan_for_lot(250)
    inspection = await issuance.record_inspection(
        session, batch=batch, defectives=plan.reject, inspector_sub="qa-1",
    )
    await session.commit()
    assert inspection.result == "FAIL"
    with pytest.raises(IssuanceError, match="invalid-state"):
        await issuance.activate_batch(session, batch=batch, signing_key=signing_key,
                                      principal_sub="officer-1")
    await session.rollback()


async def test_activation_flow(session, settings, signing_key):
    _, batch = await _paid_batch(session, settings, stamps=250)
    while await issuance.issue_chunk(session, batch=batch, settings=settings, signing_key=signing_key):
        pass
    batch = await issuance.finalize_batch(session, batch=batch, signing_key=signing_key,
                                          principal_sub="officer-1")
    plan = plan_for_lot(250)
    inspection = await issuance.record_inspection(
        session, batch=batch, defectives=plan.accept, inspector_sub="qa-1",
    )
    assert inspection.result == "PASS"
    count = await issuance.activate_batch(session, batch=batch, signing_key=signing_key,
                                          principal_sub="officer-1")
    await session.commit()
    assert count == 250
    active = (await session.execute(
        text("SELECT count(*) FROM stamps WHERE status = 'ACTIVE'")
    )).scalar_one()
    assert active == 250
    rows = (await session.execute(text(
        "SELECT count(*) FROM outbox_messages WHERE topic = 'stamps.activated'"
    ))).scalar_one()
    assert rows == 1


# ------------------------------------------------- lifecycle states (TS-4)


async def test_full_lifecycle_reaches_issued(session, settings, signing_key):
    """TS-4: assessment transitions to ISSUED when its batch reaches READY."""
    assessment, batch = await _paid_batch(session, settings, stamps=10)
    while await issuance.issue_chunk(session, batch=batch, settings=settings, signing_key=signing_key):
        pass
    batch = await issuance.finalize_batch(session, batch=batch, signing_key=signing_key,
                                          principal_sub="officer-1")
    await session.commit()
    assert batch.status == "READY"
    from taxstamps.models import Assessment

    fresh = (await session.execute(
        select(Assessment).where(Assessment.id == assessment.id)
    )).scalar_one()
    assert fresh.status == "ISSUED"


async def test_batch_completes_when_all_stamps_consumed(session, settings, signing_key):
    """TS-4: batch -> COMPLETED once every stamp is in a terminal state."""
    from taxstamps.services import verification

    _, batch = await _paid_batch(session, settings, stamps=4)
    while await issuance.issue_chunk(session, batch=batch, settings=settings, signing_key=signing_key):
        pass
    batch = await issuance.finalize_batch(session, batch=batch, signing_key=signing_key,
                                          principal_sub="officer-1")
    await issuance.record_inspection(session, batch=batch, defectives=0, inspector_sub="qa-1")
    await issuance.activate_batch(session, batch=batch, signing_key=signing_key,
                                  principal_sub="officer-1")
    await session.commit()
    stamps = (await session.execute(select(Stamp).where(Stamp.batch_id == batch.id))).scalars().all()
    for i, stamp in enumerate(stamps):
        r = await verification.verify_stamp(
            session, serial=stamp.serial, verifier_id=f"dev-{i}", public_scan=False,
            settings=settings, signing_key=signing_key,
        )
        assert r["outcome"] == "valid"
    await session.commit()
    fresh = (await session.execute(select(StampBatch).where(StampBatch.id == batch.id))).scalar_one()
    assert fresh.status == "COMPLETED"
    assert fresh.completed_at is not None


async def test_batch_requires_paid(session, settings):
    from datetime import date

    from taxstamps.services import assessments
    from tests.integration.conftest import make_declaration

    declaration = await make_declaration(session)
    assessment = await assessments.create_assessment(
        session, declaration=declaration, submitted_by="m", idempotency_key="idem-b1",
        on_date=date(2026, 8, 1),
    )
    with pytest.raises(IssuanceError, match="invalid-state"):
        await issuance.create_batch(session, assessment=assessment, settings=settings)
    await session.rollback()
