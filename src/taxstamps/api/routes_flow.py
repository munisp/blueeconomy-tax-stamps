"""Declaration intake (API path; the Kafka consumer path is equivalent),
assessment creation, maker-checker decisions, and payment rails."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select

from taxstamps.api import schemas
from taxstamps.api.deps import (
    IdempotencyKey,
    IdentityDep,
    SessionDep,
    SettingsDep,
    idempotent_replay,
    require_policy,
    store_idempotency,
)
from taxstamps.crypto.eddsa import SigningKey
from taxstamps.models import (
    Assessment,
    Declaration,
    DeclarationLine,
    PaymentIntent,
    utcnow,
)
from taxstamps.services import assessments, audit, outbox, payments
from taxstamps.services.payments import PaymentError

router = APIRouter(prefix="/v1")


def _assessment_view(a: Assessment) -> dict:
    return {
        "assessmentId": str(a.id),
        "declarationId": str(a.declaration_id),
        "status": a.status,
        "currency": a.currency,
        "totalDutyKobo": a.total_duty_kobo,
        "stampsRequired": a.stamps_required,
        "riskTier": a.risk_tier,
        "approvalsRequired": a.approvals_required,
        "submittedBy": a.submitted_by,
    }


@router.post("/declarations", status_code=201)
async def create_declaration(
    body: schemas.DeclarationIn,
    request: Request,
    session: SessionDep,
    identity: IdentityDep,
    idem_key: IdempotencyKey,
) -> dict:
    require_policy(request, identity, "assessment", "create", "INTERNAL")
    replay = await idempotent_replay(session, idem_key, identity.subject, body.model_dump())
    if replay is not None:
        return replay.response_body
    existing = (
        await session.execute(
            select(Declaration).where(Declaration.declaration_ref == body.declaration_ref)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=409, detail={"reason": "declaration-exists"})
    declaration = Declaration(
        id=uuid.uuid4(),
        declaration_ref=body.declaration_ref,
        consignee_tin=body.consignee_tin,
        consignee_name=body.consignee_name,
        source_event_id=f"api:{identity.subject}:{body.declaration_ref}",
        occurred_at=utcnow(),
        envelope={"intake": "api"},
    )
    session.add(declaration)
    for line in body.lines:
        session.add(
            DeclarationLine(
                id=uuid.uuid4(),
                declaration_id=declaration.id,
                hs_code=line.hs_code,
                description=line.description,
                quantity=line.quantity,
                unit=line.unit,
                customs_value_kobo=line.customs_value_kobo,
                stamps_required=line.stamps_required,
            )
        )
    await audit.record(session, "declaration.received", {
        "declarationRef": declaration.declaration_ref,
        "consigneeTin": declaration.consignee_tin,
        "principal": identity.subject,
    })
    resp = {"declarationRef": declaration.declaration_ref, "lines": len(body.lines)}
    await store_idempotency(session, idem_key, identity.subject, body.model_dump(), 201, resp)
    await session.commit()
    return resp


@router.post("/assessments", status_code=201)
async def create_assessment(
    body: schemas.AssessmentCreateIn,
    request: Request,
    session: SessionDep,
    identity: IdentityDep,
    idem_key: IdempotencyKey,
) -> dict:
    require_policy(request, identity, "assessment", "create", "CONFIDENTIAL")
    replay = await idempotent_replay(session, idem_key, identity.subject, body.model_dump())
    if replay is not None:
        return replay.response_body
    declaration = (
        await session.execute(
            select(Declaration).where(Declaration.declaration_ref == body.declaration_ref)
        )
    ).scalar_one_or_none()
    if declaration is None:
        raise HTTPException(status_code=404, detail={"reason": "declaration-not-found"})
    key = idem_key or f"auto:{identity.subject}:{declaration.id}"
    try:
        assessment = await assessments.create_assessment(
            session,
            declaration=declaration,
            submitted_by=identity.subject,
            idempotency_key=key,
        )
    except assessments.AssessmentError as exc:
        raise HTTPException(status_code=422, detail={"reason": exc.reason, "detail": str(exc)}) from exc
    key_obj: SigningKey = request.app.state.signing_key
    await audit.record(session, "assessment.created", {
        "assessmentId": str(assessment.id),
        "declarationRef": declaration.declaration_ref,
        "totalDutyKobo": assessment.total_duty_kobo,
        "riskTier": assessment.risk_tier,
        "principal": identity.subject,
    })
    await outbox.enqueue(
        session,
        event_type="stamps.assessed.v1",
        resource={
            "assessmentId": str(assessment.id),
            "declarationRef": declaration.declaration_ref,
            "consigneeTin": declaration.consignee_tin,
            "totalDutyKobo": assessment.total_duty_kobo,
            "stampsRequired": assessment.stamps_required,
            "riskTier": assessment.risk_tier,
        },
        signing_key=key_obj,
        principal_id=identity.subject,
        principal_role="excise-officer",
        correlation_id=declaration.declaration_ref,
    )
    resp = _assessment_view(assessment)
    await store_idempotency(session, idem_key, identity.subject, body.model_dump(), 201, resp)
    await session.commit()
    return resp


@router.get("/assessments/{assessment_id}")
async def get_assessment(
    assessment_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    identity: IdentityDep,
) -> dict:
    require_policy(request, identity, "assessment", "read", "CONFIDENTIAL")
    assessment = (
        await session.execute(select(Assessment).where(Assessment.id == assessment_id))
    ).scalar_one_or_none()
    if assessment is None:
        raise HTTPException(status_code=404, detail={"reason": "assessment-not-found"})
    return _assessment_view(assessment)


@router.post("/assessments/{assessment_id}/decisions")
async def decide_assessment(
    assessment_id: uuid.UUID,
    body: schemas.DecisionIn,
    request: Request,
    session: SessionDep,
    identity: IdentityDep,
) -> dict:
    require_policy(request, identity, "assessment", "approve", "CONFIDENTIAL")
    try:
        assessment = await assessments.record_decision(
            session,
            assessment_id=assessment_id,
            principal_sub=identity.subject,
            decision=body.decision,
            reason=body.reason,
        )
    except assessments.AssessmentError as exc:
        status = 403 if exc.reason in ("self-approval", "duplicate-decision") else 422
        raise HTTPException(status_code=status, detail={"reason": exc.reason, "detail": str(exc)}) from exc
    await audit.record(session, "assessment.decision", {
        "assessmentId": str(assessment_id),
        "decision": body.decision,
        "principal": identity.subject,
        "resultingStatus": assessment.status,
    })
    if assessment.status == "APPROVED":
        await outbox.enqueue(
            session,
            event_type="stamps.approved.v1",
            resource={"assessmentId": str(assessment.id), "approvalsRequired": assessment.approvals_required},
            signing_key=request.app.state.signing_key,
            principal_id=identity.subject,
            principal_role="excise-approver",
            correlation_id=str(assessment.declaration_id),
        )
    await session.commit()
    return _assessment_view(assessment)


@router.post("/assessments/{assessment_id}/payment-intent", status_code=201)
async def create_payment_intent(
    assessment_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    identity: IdentityDep,
) -> dict:
    require_policy(request, identity, "payment", "create", "FIDUCIARY_SEGREGATED")
    assessment = (
        await session.execute(select(Assessment).where(Assessment.id == assessment_id))
    ).scalar_one_or_none()
    if assessment is None:
        raise HTTPException(status_code=404, detail={"reason": "assessment-not-found"})
    try:
        intent = await payments.create_intent(session, settings=settings, assessment=assessment)
    except PaymentError as exc:
        status = 503 if exc.reason == "rail-unavailable" else 422
        raise HTTPException(status_code=status, detail={"reason": exc.reason, "detail": str(exc)}) from exc
    await audit.record(session, "payment.intent-created", {
        "paymentIntentId": str(intent.id),
        "assessmentId": str(assessment_id),
        "expectedAmountKobo": intent.expected_amount_kobo,
        "rail": intent.rail,
    })
    await session.commit()
    return {
        "paymentIntentId": str(intent.id),
        "rail": intent.rail,
        "expectedAmountKobo": intent.expected_amount_kobo,
        "currency": intent.currency,
        "status": intent.status,
    }


@router.post("/payments/receipts", status_code=201)
async def record_payment_receipt(
    body: schemas.ReceiptIn,
    request: Request,
    session: SessionDep,
    identity: IdentityDep,
) -> dict:
    """Rail callback boundary (financial-controls reports the remittance)."""
    require_policy(request, identity, "payment", "settle", "FIDUCIARY_SEGREGATED")
    intent = (
        await session.execute(
            select(PaymentIntent).where(PaymentIntent.id == uuid.UUID(body.payment_intent_id))
        )
    ).scalar_one_or_none()
    if intent is None:
        raise HTTPException(status_code=404, detail={"reason": "intent-not-found"})
    receipt = await payments.record_receipt(
        session,
        intent=intent,
        external_reference=body.external_reference,
        amount_kobo=body.amount_kobo,
        currency=body.currency,
    )
    await audit.record(session, "payment.receipt-recorded", {
        "externalReference": receipt.external_reference,
        "status": receipt.status,
        "amountKobo": receipt.amount_kobo,
        "quarantineReason": receipt.quarantine_reason,
    })
    await session.commit()
    return {
        "receiptId": str(receipt.id),
        "status": receipt.status,
        "quarantineReason": receipt.quarantine_reason,
    }
