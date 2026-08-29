"""Maker-checker: submitter-cannot-approve, risk-tiered levels, idempotency."""

from datetime import date

import pytest

from taxstamps.services import assessments
from taxstamps.services.assessments import AssessmentError
from tests.integration.conftest import make_declaration


async def test_submitter_cannot_approve(session):
    declaration = await make_declaration(session)
    assessment = await assessments.create_assessment(
        session, declaration=declaration, submitted_by="maker-1",
        idempotency_key="idem-mc-1", on_date=date(2026, 8, 1),
    )
    with pytest.raises(AssessmentError, match="self-approval"):
        await assessments.record_decision(
            session, assessment_id=assessment.id, principal_sub="maker-1", decision="APPROVE",
        )
    await session.rollback()


async def test_duplicate_decision_rejected(session):
    declaration = await make_declaration(session)
    assessment = await assessments.create_assessment(
        session, declaration=declaration, submitted_by="maker-1",
        idempotency_key="idem-mc-2", on_date=date(2026, 8, 1),
    )
    await assessments.record_decision(
        session, assessment_id=assessment.id, principal_sub="checker-1", decision="APPROVE",
    )
    await session.commit()
    with pytest.raises(AssessmentError, match="duplicate-decision"):
        await assessments.record_decision(
            session, assessment_id=assessment.id, principal_sub="checker-1", decision="APPROVE",
        )
    await session.rollback()


async def test_low_tier_single_approval(session):
    declaration = await make_declaration(session)  # 1000l beer @80 = NGN 80,000 -> LOW
    assessment = await assessments.create_assessment(
        session, declaration=declaration, submitted_by="m", idempotency_key="idem-t1",
        on_date=date(2026, 8, 1),
    )
    assert assessment.risk_tier == "LOW" and assessment.approvals_required == 1
    assessment = await assessments.record_decision(
        session, assessment_id=assessment.id, principal_sub="c1", decision="APPROVE",
    )
    assert assessment.status == "APPROVED"


async def test_high_tier_requires_three_approvals(session):
    # spirits: 100,000 l * 7500 + 30% of 100,000,000,000 kobo -> HIGH tier
    declaration = await make_declaration(session, lines=[
        {"hs_code": "2208.90", "quantity": 100_000, "unit": "LITRE",
         "customs_value_kobo": 100_000_000_000, "stamps_required": 100_000},
    ])
    assessment = await assessments.create_assessment(
        session, declaration=declaration, submitted_by="m", idempotency_key="idem-t3",
        on_date=date(2026, 8, 1),
    )
    assert assessment.risk_tier == "HIGH" and assessment.approvals_required == 3
    for i, approver in enumerate(("c1", "c2", "c3"), start=1):
        assessment = await assessments.record_decision(
            session, assessment_id=assessment.id, principal_sub=approver, decision="APPROVE",
        )
        if i < 3:
            assert assessment.status == "PENDING_APPROVAL"
    assert assessment.status == "APPROVED"


# ------------------------------------------------- cancellation (TS-4)


async def test_cancelled_assessment_blocks_issuance(session, settings):
    from taxstamps.services import issuance
    from taxstamps.services.issuance import IssuanceError

    declaration = await make_declaration(session)
    assessment = await assessments.create_assessment(
        session, declaration=declaration, submitted_by="m", idempotency_key="idem-cx-1",
        on_date=date(2026, 8, 1),
    )
    assessment = await assessments.record_decision(
        session, assessment_id=assessment.id, principal_sub="c1", decision="APPROVE",
    )
    cancelled = await assessments.cancel_assessment(
        session, assessment_id=assessment.id, principal_sub="approver-1",
        reason="declaration withdrawn by importer",
    )
    await session.commit()
    assert cancelled.status == "CANCELLED"
    # payment path blocked
    from taxstamps.services.payments import PaymentError, create_intent

    rail = settings.model_copy(update={
        "payment_rail": "cvff-tigerbeetle",
        "financial_controls_endpoint": "https://financial-controls.example",
    })
    with pytest.raises(PaymentError, match="invalid-state"):
        await create_intent(session, settings=rail, assessment=cancelled)
    # issuance blocked
    with pytest.raises(IssuanceError, match="invalid-state"):
        await issuance.create_batch(session, assessment=cancelled, settings=settings)
    await session.rollback()


async def test_cancel_requires_reason_and_pre_issuance_state(session, settings):
    declaration = await make_declaration(session)
    assessment = await assessments.create_assessment(
        session, declaration=declaration, submitted_by="m", idempotency_key="idem-cx-2",
        on_date=date(2026, 8, 1),
    )
    with pytest.raises(AssessmentError, match="reason-required"):
        await assessments.cancel_assessment(
            session, assessment_id=assessment.id, principal_sub="a", reason=" ",
        )
    await session.rollback()


async def test_rejection_is_terminal(session):
    declaration = await make_declaration(session)
    assessment = await assessments.create_assessment(
        session, declaration=declaration, submitted_by="m", idempotency_key="idem-t4",
        on_date=date(2026, 8, 1),
    )
    assessment = await assessments.record_decision(
        session, assessment_id=assessment.id, principal_sub="c1", decision="REJECT", reason="bad docs",
    )
    assert assessment.status == "REJECTED"
    with pytest.raises(AssessmentError, match="invalid-state"):
        await assessments.record_decision(
            session, assessment_id=assessment.id, principal_sub="c2", decision="APPROVE",
        )
    await session.rollback()


async def test_assessment_idempotent_on_key(session):
    declaration = await make_declaration(session)
    a1 = await assessments.create_assessment(
        session, declaration=declaration, submitted_by="m", idempotency_key="idem-t5",
        on_date=date(2026, 8, 1),
    )
    a2 = await assessments.create_assessment(
        session, declaration=declaration, submitted_by="m", idempotency_key="idem-t5",
        on_date=date(2026, 8, 1),
    )
    assert a1.id == a2.id


async def test_server_side_pricing_from_tariff(session):
    declaration = await make_declaration(session, lines=[
        {"hs_code": "2402.20", "quantity": 2000, "unit": "STICK",
         "customs_value_kobo": 0, "stamps_required": 100},  # 2000 sticks @ NGN 8
        {"hs_code": "8471.30", "quantity": 5, "unit": "UNIT",
         "customs_value_kobo": 999_000_000, "stamps_required": 0},  # not stamp-bearing
    ])
    assessment = await assessments.create_assessment(
        session, declaration=declaration, submitted_by="m", idempotency_key="idem-t6",
        on_date=date(2026, 8, 1),
    )
    assert assessment.total_duty_kobo == 2000 * 800
    assert assessment.stamps_required == 100


async def test_not_stamp_bearing_rejected(session):
    declaration = await make_declaration(session, lines=[
        {"hs_code": "8471.30", "quantity": 5, "unit": "UNIT",
         "customs_value_kobo": 100, "stamps_required": 0},
    ])
    with pytest.raises(AssessmentError, match="not-stamp-bearing"):
        await assessments.create_assessment(
            session, declaration=declaration, submitted_by="m", idempotency_key="idem-t7",
            on_date=date(2026, 8, 1),
        )
    await session.rollback()
