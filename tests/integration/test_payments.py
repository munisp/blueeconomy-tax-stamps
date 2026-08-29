"""Exact-amount payment matching, quarantine, replay safety, settlement journal."""

from datetime import date

import pytest
from sqlalchemy import select, text

from taxstamps.models import Assessment, PaymentReceipt
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
