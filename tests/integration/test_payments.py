"""Exact-amount payment matching, quarantine, replay safety, settlement journal."""

from datetime import date

import pytest
from sqlalchemy import select, text

from taxstamps.models import Assessment, PaymentIntent, PaymentReceipt
from taxstamps.services import assessments
from taxstamps.services.payments import PaymentError, create_intent, record_receipt
from tests.integration.conftest import make_declaration


async def _approved_assessment(session, settings, **kw):
    declaration = await make_declaration(session, **kw)
    assessment = await assessments.create_assessment(
        session, declaration=declaration, submitted_by="maker-1",
        idempotency_key=f"idem-{declaration.declaration_ref}", on_date=date(2026, 8, 1),
    )
    assessment = await assessments.record_decision(
        session, assessment_id=assessment.id, principal_sub="checker-1", decision="APPROVE",
    )
    assert assessment.status == "APPROVED"
    return assessment


def _rail_settings(settings):
    return settings.model_copy(update={
        "payment_rail": "cvff-tigerbeetle",
        "financial_controls_endpoint": "https://financial-controls.example",
    })


async def test_intent_requires_rail(session, settings):
    assessment = await _approved_assessment(session, settings)
    with pytest.raises(PaymentError, match="rail-unavailable"):
        await create_intent(session, settings=settings, assessment=assessment)
    await session.rollback()


async def test_exact_amount_match_settles(session, settings):
    settings = _rail_settings(settings)
    assessment = await _approved_assessment(session, settings)
    intent = await create_intent(session, settings=settings, assessment=assessment)
    assert intent.expected_amount_kobo == assessment.total_duty_kobo
    receipt = await record_receipt(
        session, intent=intent, external_reference="rem-001",
        amount_kobo=intent.expected_amount_kobo, currency="NGN",
    )
    await session.commit()
    assert receipt.status == "APPLIED"
    fresh = (await session.execute(select(Assessment).where(Assessment.id == assessment.id))).scalar_one()
    assert fresh.status == "PAID"
    # settlement journal posted and balanced
    rows = (await session.execute(text(
        "SELECT account, debit_kobo, credit_kobo FROM ledger_entries le "
        "JOIN journals j ON j.id = le.journal_id WHERE j.reference = 'excise-settlement:rem-001'"
    ))).all()
    assert len(rows) == 2
    assert sum(r[1] for r in rows) == sum(r[2] for r in rows) == intent.expected_amount_kobo


async def test_underpayment_quarantined(session, settings):
    settings = _rail_settings(settings)
    assessment = await _approved_assessment(session, settings)
    intent = await create_intent(session, settings=settings, assessment=assessment)
    receipt = await record_receipt(
        session, intent=intent, external_reference="rem-002",
        amount_kobo=intent.expected_amount_kobo - 100, currency="NGN",
    )
    await session.commit()
    assert receipt.status == "QUARANTINED"
    assert receipt.payment_intent_id is None
    assert "amount mismatch" in receipt.quarantine_reason
    fresh = (await session.execute(select(Assessment).where(Assessment.id == assessment.id))).scalar_one()
    assert fresh.status == "PAYMENT_PENDING"


async def test_wrong_currency_quarantined(session, settings):
    settings = _rail_settings(settings)
    assessment = await _approved_assessment(session, settings)
    intent = await create_intent(session, settings=settings, assessment=assessment)
    receipt = await record_receipt(
        session, intent=intent, external_reference="rem-003",
        amount_kobo=intent.expected_amount_kobo, currency="USD",
    )
    await session.commit()
    assert receipt.status == "QUARANTINED"


async def test_replay_same_reference_idempotent(session, settings):
    settings = _rail_settings(settings)
    assessment = await _approved_assessment(session, settings)
    intent = await create_intent(session, settings=settings, assessment=assessment)
    r1 = await record_receipt(session, intent=intent, external_reference="rem-004",
                              amount_kobo=intent.expected_amount_kobo, currency="NGN")
    await session.commit()
    r2 = await record_receipt(session, intent=intent, external_reference="rem-004",
                              amount_kobo=intent.expected_amount_kobo, currency="NGN")
    await session.commit()
    assert r1.id == r2.id
    count = (await session.execute(
        select(PaymentReceipt).where(PaymentReceipt.external_reference == "rem-004")
    )).scalars().all()
    assert len(count) == 1


async def test_second_distinct_remittance_quarantined(session, settings):
    settings = _rail_settings(settings)
    assessment = await _approved_assessment(session, settings)
    intent = await create_intent(session, settings=settings, assessment=assessment)
    await record_receipt(session, intent=intent, external_reference="rem-005a",
                         amount_kobo=intent.expected_amount_kobo, currency="NGN")
    await session.commit()
    r2 = await record_receipt(session, intent=intent, external_reference="rem-005b",
                              amount_kobo=intent.expected_amount_kobo, currency="NGN")
    await session.commit()
    assert r2.status == "QUARANTINED"
    assert "already settled" in r2.quarantine_reason


# ---------------------------------------------------------- zero-rated (TS-2)

PHARMA_LINES = [
    {"hs_code": "3004.90", "quantity": 500, "unit": "UNIT",
     "customs_value_kobo": 10_000_000, "stamps_required": 500},
]


async def _zero_rated_assessment(session, settings):
    return await _approved_assessment(session, settings, lines=PHARMA_LINES)


async def test_zero_rated_settles_and_stamps_issue(session, settings, signing_key):
    from taxstamps.services import issuance
    from taxstamps.services.payments import settle_zero_rated

    assessment = await _zero_rated_assessment(session, settings)
    assert assessment.total_duty_kobo == 0
    assert assessment.zero_rated is True
    # no rail receipt involved; rail settings intentionally absent
    intent = await settle_zero_rated(session, assessment=assessment, principal_sub="finance-1")
    await session.commit()
    assert intent.status == "SETTLED"
    assert intent.expected_amount_kobo == 0
    assert intent.zero_rated is True
    fresh = (await session.execute(select(Assessment).where(Assessment.id == assessment.id))).scalar_one()
    assert fresh.status == "PAID"
    # stamps issue end-to-end on the zero-rated assessment
    batch = await issuance.create_batch(session, assessment=fresh, settings=settings)
    issued = 0
    while True:
        n = await issuance.issue_chunk(session, batch=batch, settings=settings, signing_key=signing_key)
        issued += n
        if n == 0:
            break
    await session.commit()
    assert issued == 500


async def test_zero_rated_intent_rejected_on_rail(session, settings):
    settings = _rail_settings(settings)
    assessment = await _zero_rated_assessment(session, settings)
    with pytest.raises(PaymentError, match="zero-rated"):
        await create_intent(session, settings=settings, assessment=assessment)
    await session.rollback()


async def test_positive_assessment_still_requires_real_payment(session, settings):
    from taxstamps.services.payments import settle_zero_rated

    settings = _rail_settings(settings)
    assessment = await _approved_assessment(session, settings)
    assert assessment.total_duty_kobo > 0
    # the zero-rated path refuses positive-amount assessments
    with pytest.raises(PaymentError, match="not-zero-rated"):
        await settle_zero_rated(session, assessment=assessment, principal_sub="finance-1")
    # and only an exact rail receipt settles it
    intent = await create_intent(session, settings=settings, assessment=assessment)
    bad = await record_receipt(session, intent=intent, external_reference="rem-zr-1",
                               amount_kobo=intent.expected_amount_kobo - 1, currency="NGN")
    await session.commit()
    assert bad.status == "QUARANTINED"
    fresh = (await session.execute(select(Assessment).where(Assessment.id == assessment.id))).scalar_one()
    assert fresh.status == "PAYMENT_PENDING"


# ------------------------------------------- quarantine resolution (TS-5)


async def _quarantined(session, settings):
    settings = _rail_settings(settings)
    assessment = await _approved_assessment(session, settings)
    intent = await create_intent(session, settings=settings, assessment=assessment)
    bad = await record_receipt(
        session, intent=intent, external_reference="rem-q-1",
        amount_kobo=intent.expected_amount_kobo - 500, currency="NGN",
    )
    await session.commit()
    assert bad.status == "QUARANTINED"
    return settings, assessment, intent, bad


async def test_quarantine_resolved_by_superseding_settlement(session, settings):
    from taxstamps.services.payments import resolve_quarantine

    settings, assessment, intent, bad = await _quarantined(session, settings)
    fixed = await resolve_quarantine(
        session, intent=intent, resolution="SETTLE",
        external_reference="rem-q-1-fix", supersedes_reference="rem-q-1",
        amount_kobo=intent.expected_amount_kobo, currency="NGN",
        reason="bank corrected the remittance", principal_sub="finance-1",
    )
    await session.commit()
    assert fixed.status == "APPLIED"
    assert fixed.supersedes_reference == "rem-q-1"
    fresh_intent = (await session.execute(
        select(PaymentIntent).where(PaymentIntent.id == intent.id)
    )).scalar_one()
    assert fresh_intent.status == "SETTLED"
    fresh = (await session.execute(select(Assessment).where(Assessment.id == assessment.id))).scalar_one()
    assert fresh.status == "PAID"
    # original receipt untouched: still QUARANTINED, still unapplied
    original = (await session.execute(
        select(PaymentReceipt).where(PaymentReceipt.external_reference == "rem-q-1")
    )).scalar_one()
    assert original.status == "QUARANTINED"
    assert original.payment_intent_id is None
    # settlement journal balanced
    rows = (await session.execute(text(
        "SELECT sum(debit_kobo), sum(credit_kobo) FROM ledger_entries le "
        "JOIN journals j ON j.id = le.journal_id WHERE j.reference = 'excise-settlement:rem-q-1-fix'"
    ))).one()
    assert rows[0] == rows[1] == intent.expected_amount_kobo


async def test_quarantine_resolved_by_failing_intent(session, settings):
    from taxstamps.services.payments import resolve_quarantine

    settings, assessment, intent, bad = await _quarantined(session, settings)
    receipt = await resolve_quarantine(
        session, intent=intent, resolution="FAIL",
        external_reference="rem-q-1-void", supersedes_reference="rem-q-1",
        amount_kobo=bad.amount_kobo, currency="NGN",
        reason="remitter cannot be identified; funds returned", principal_sub="finance-1",
    )
    await session.commit()
    fresh_intent = (await session.execute(
        select(PaymentIntent).where(PaymentIntent.id == intent.id)
    )).scalar_one()
    assert fresh_intent.status == "FAILED"
    # funds never applied; original receipt untouched
    assert receipt.status == "QUARANTINED"
    assert receipt.payment_intent_id is None
    original = (await session.execute(
        select(PaymentReceipt).where(PaymentReceipt.external_reference == "rem-q-1")
    )).scalar_one()
    assert original.status == "QUARANTINED"
    fresh = (await session.execute(select(Assessment).where(Assessment.id == assessment.id))).scalar_one()
    assert fresh.status == "PAYMENT_PENDING"  # never silently PAID


async def test_quarantine_resolution_requires_quarantine_evidence(session, settings):
    from taxstamps.services.payments import resolve_quarantine

    settings = _rail_settings(settings)
    assessment = await _approved_assessment(session, settings)
    intent = await create_intent(session, settings=settings, assessment=assessment)
    await session.commit()
    with pytest.raises(PaymentError, match="no-quarantine"):
        await resolve_quarantine(
            session, intent=intent, resolution="SETTLE",
            external_reference="rem-q-x", supersedes_reference="rem-nonexistent",
            amount_kobo=intent.expected_amount_kobo, currency="NGN",
            reason="fabricated resolution attempt", principal_sub="finance-1",
        )
    await session.rollback()


async def test_receipt_immutable(session, settings):
    settings = _rail_settings(settings)
    assessment = await _approved_assessment(session, settings)
    intent = await create_intent(session, settings=settings, assessment=assessment)
    await record_receipt(session, intent=intent, external_reference="rem-006",
                         amount_kobo=intent.expected_amount_kobo, currency="NGN")
    await session.commit()
    import sqlalchemy.exc

    with pytest.raises(sqlalchemy.exc.DBAPIError):
        await session.execute(text("UPDATE payment_receipts SET amount_kobo = 1"))
    await session.rollback()
