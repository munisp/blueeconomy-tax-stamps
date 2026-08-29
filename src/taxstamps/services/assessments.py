"""TaxStampAssessment lifecycle: intake -> maker-checker -> (payment) -> issuance.

Server-side pricing only: duty is computed from the effective-dated tariff
table; any client-supplied total is rejected by the API schema before this
service runs.

Maker-checker: the submitting principal can never approve (checked here AND
by the unique (assessment_id, principal_sub) constraint with the service
rejecting self-approval explicitly). Risk-tiered approval levels:
- LOW      (<  NGN 1,000,000 duty):       1 approval
- STANDARD (<  NGN 25,000,000 duty):      2 approvals
- HIGH     (>= NGN 25,000,000 duty):      3 approvals (excise-approver chain)
"""

from __future__ import annotations

import uuid
from datetime import date

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from taxstamps.domain.tariff import compute_line_duty
from taxstamps.models import (
    Approval,
    Assessment,
    AssessmentLine,
    Declaration,
    utcnow,
)


class AssessmentError(ValueError):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


LOW_THRESHOLD_KOBO = 1_000_000_00       # NGN 1,000,000
STANDARD_THRESHOLD_KOBO = 25_000_000_00  # NGN 25,000,000


def risk_tier_for(total_duty_kobo: int) -> tuple[str, int]:
    if total_duty_kobo >= STANDARD_THRESHOLD_KOBO:
        return "HIGH", 3
    if total_duty_kobo >= LOW_THRESHOLD_KOBO:
        return "STANDARD", 2
    return "LOW", 1


async def create_assessment(
    session: AsyncSession,
    *,
    declaration: Declaration,
    submitted_by: str,
    idempotency_key: str,
    on_date: date | None = None,
) -> Assessment:
    """Compute the assessment from declaration line items (server-side)."""
    existing = (
        await session.execute(
            select(Assessment).where(Assessment.idempotency_key == idempotency_key)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    from taxstamps.models import DeclarationLine

    lines = (
        await session.execute(
            select(DeclarationLine).where(DeclarationLine.declaration_id == declaration.id)
        )
    ).scalars().all()
    if not lines:
        raise AssessmentError("empty-declaration", "declaration has no line items")
    on = on_date or utcnow().date()
    total = 0
    stamps = 0
    assessment = Assessment(
        id=uuid.uuid4(),
        declaration_id=declaration.id,
        status="PENDING_APPROVAL",
        total_duty_kobo=0,
        stamps_required=0,
        risk_tier="LOW",
        approvals_required=1,
        submitted_by=submitted_by,
        idempotency_key=idempotency_key,
    )
    session.add(assessment)
    saw_stamp_bearing = False
    for line in lines:
        duty = compute_line_duty(line.hs_code, line.quantity, line.customs_value_kobo, on)
        if duty is None:
            continue  # not stamp-bearing
        saw_stamp_bearing = True
        total += duty.total_kobo
        stamps += line.stamps_required
        session.add(
            AssessmentLine(
                id=uuid.uuid4(),
                assessment_id=assessment.id,
                hs_code=line.hs_code,
                category=duty.tariff.category,
                quantity=line.quantity,
                unit=line.unit,
                customs_value_kobo=line.customs_value_kobo,
                specific_duty_kobo=duty.specific_duty_kobo,
                ad_valorem_duty_kobo=duty.ad_valorem_duty_kobo,
                total_duty_kobo=duty.total_kobo,
                statutory_ref=duty.tariff.statutory_ref,
                tariff_effective_from=duty.tariff.effective_from,
            )
        )
    if not saw_stamp_bearing:
        raise AssessmentError("not-stamp-bearing", "no line item maps to a stamp category")
    tier, approvals = risk_tier_for(total)
    assessment.total_duty_kobo = total
    assessment.stamps_required = stamps
    assessment.risk_tier = tier
    assessment.approvals_required = approvals
    await session.flush()
    return assessment


async def record_decision(
    session: AsyncSession,
    *,
    assessment_id: uuid.UUID,
    principal_sub: str,
    decision: str,
    reason: str = "",
) -> Assessment:
    """Maker-checker decision. Submitter-cannot-approve; distinct approvers."""
    assessment = (
        await session.execute(
            select(Assessment).where(Assessment.id == assessment_id).with_for_update()
        )
    ).scalar_one_or_none()
    if assessment is None:
        raise AssessmentError("not-found", "assessment not found")
    if assessment.status != "PENDING_APPROVAL":
        raise AssessmentError("invalid-state", f"assessment is {assessment.status}")
    if decision not in ("APPROVE", "REJECT"):
        raise AssessmentError("invalid-decision", decision)
    if principal_sub == assessment.submitted_by:
        raise AssessmentError("self-approval", "the submitter cannot approve their own assessment")
    already = (
        await session.execute(
            select(func.count()).select_from(Approval).where(
                Approval.assessment_id == assessment_id, Approval.principal_sub == principal_sub
            )
        )
    ).scalar_one()
    if already:
        raise AssessmentError("duplicate-decision", "principal already decided on this assessment")
    level = (
        await session.execute(
            select(func.count()).select_from(Approval).where(Approval.assessment_id == assessment_id)
        )
    ).scalar_one() + 1
    session.add(
        Approval(
            id=uuid.uuid4(),
            assessment_id=assessment_id,
            principal_sub=principal_sub,
            decision=decision,
            level=level,
            reason=reason,
        )
    )
    if decision == "REJECT":
        assessment.status = "REJECTED"
        assessment.decided_at = utcnow()
    else:
        approvals = (
            await session.execute(
                select(func.count()).select_from(Approval).where(
                    Approval.assessment_id == assessment_id, Approval.decision == "APPROVE"
                )
            )
        ).scalar_one()
        # +1 for the decision being recorded in this flush
        if approvals + 1 >= assessment.approvals_required:
            assessment.status = "APPROVED"
            assessment.decided_at = utcnow()
    await session.flush()
    return assessment
