"""Batch issuance, Z1.4 inspection, activation, stamp read and void."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select

from taxstamps.api import schemas
from taxstamps.api.deps import IdentityDep, SessionDep, SettingsDep, require_policy
from taxstamps.models import Assessment, Stamp, StampBatch
from taxstamps.services import audit, issuance
from taxstamps.services.verification import VerificationError, approve_void, request_void

router = APIRouter(prefix="/v1")


def _batch_view(b: StampBatch) -> dict[str, Any]:
    return {
        "batchId": str(b.id),
        "assessmentId": str(b.assessment_id),
        "categoryCode": b.category_code,
        "year": b.year,
        "quantity": b.quantity,
        "issuedCount": b.issued_count,
        "status": b.status,
        "merkleRoot": b.merkle_root,
    }


@router.post("/assessments/{assessment_id}/batch", status_code=201)
async def create_batch(
    assessment_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    identity: IdentityDep,
) -> dict[str, Any]:
    require_policy(request, identity, "batch", "issue", "CONFIDENTIAL")
    assessment = (
        await session.execute(select(Assessment).where(Assessment.id == assessment_id))
    ).scalar_one_or_none()
    if assessment is None:
        raise HTTPException(status_code=404, detail={"reason": "assessment-not-found"})
    try:
        batch = await issuance.create_batch(session, assessment=assessment, settings=settings)
    except issuance.IssuanceError as exc:
        raise HTTPException(status_code=422, detail={"reason": exc.reason, "detail": str(exc)}) from exc
    await audit.record(session, "batch.created", {
        "batchId": str(batch.id), "assessmentId": str(assessment_id), "quantity": batch.quantity,
    })
    await session.commit()
    return _batch_view(batch)


@router.post("/batches/{batch_id}/issue")
async def issue_batch(
    batch_id: uuid.UUID,
    body: schemas.IssueIn,
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    identity: IdentityDep,
) -> dict[str, Any]:
    """Issue one chunk, or run to completion (resumable; safe to retry)."""
    require_policy(request, identity, "batch", "issue", "CONFIDENTIAL")
    batch = (
        await session.execute(select(StampBatch).where(StampBatch.id == batch_id))
    ).scalar_one_or_none()
    if batch is None:
        raise HTTPException(status_code=404, detail={"reason": "batch-not-found"})
    signing_key = request.app.state.signing_key
    issued = 0
    while True:
        n = await issuance.issue_chunk(
            session, batch=batch, settings=settings, signing_key=signing_key,
            chunk_size=body.chunk_size,
        )
        issued += n
        if n == 0 or not body.run_to_completion:
            break
        # Each chunk is committed separately: one transaction per chunk is
        # what makes issuance crash-safe and resumable.
        await session.commit()
    await audit.record(session, "batch.issued-chunk", {
        "batchId": str(batch_id), "issuedThisCall": issued,
    })
    await session.commit()
    fresh = (
        await session.execute(select(StampBatch).where(StampBatch.id == batch_id))
    ).scalar_one()
    return {**_batch_view(fresh), "issuedThisCall": issued}


@router.post("/batches/{batch_id}/finalize")
async def finalize_batch(
    batch_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    identity: IdentityDep,
) -> dict[str, Any]:
    require_policy(request, identity, "batch", "issue", "CONFIDENTIAL")
    batch = (
        await session.execute(select(StampBatch).where(StampBatch.id == batch_id))
    ).scalar_one_or_none()
    if batch is None:
        raise HTTPException(status_code=404, detail={"reason": "batch-not-found"})
    try:
        batch = await issuance.finalize_batch(
            session, batch=batch, signing_key=request.app.state.signing_key,
            principal_sub=identity.subject,
        )
    except issuance.IssuanceError as exc:
        raise HTTPException(status_code=422, detail={"reason": exc.reason, "detail": str(exc)}) from exc
    await audit.record(session, "batch.finalized", {
        "batchId": str(batch_id), "merkleRoot": batch.merkle_root,
    })
    await session.commit()
    return _batch_view(batch)


@router.post("/batches/{batch_id}/inspections", status_code=201)
async def inspect_batch(
    batch_id: uuid.UUID,
    body: schemas.InspectionIn,
    request: Request,
    session: SessionDep,
    identity: IdentityDep,
) -> dict[str, Any]:
    require_policy(request, identity, "batch", "inspect", "CONFIDENTIAL")
    batch = (
        await session.execute(select(StampBatch).where(StampBatch.id == batch_id))
    ).scalar_one_or_none()
    if batch is None:
        raise HTTPException(status_code=404, detail={"reason": "batch-not-found"})
    try:
        inspection = await issuance.record_inspection(
            session, batch=batch, defectives=body.defectives, inspector_sub=identity.subject,
        )
    except (issuance.IssuanceError, ValueError) as exc:
        raise HTTPException(status_code=422, detail={"reason": "inspection-rejected", "detail": str(exc)}) from exc
    await audit.record(session, "batch.inspected", {
        "batchId": str(batch_id), "result": inspection.result,
        "defectives": inspection.defectives, "sampleSize": inspection.sample_size,
        "inspector": identity.subject,
    })
    await session.commit()
    return {
        "inspectionId": str(inspection.id),
        "batchId": str(batch_id),
        "result": inspection.result,
        "codeLetter": inspection.code_letter,
        "sampleSize": inspection.sample_size,
        "accept": inspection.accept,
        "reject": inspection.reject,
        "defectives": inspection.defectives,
    }


@router.post("/batches/{batch_id}/activate")
async def activate_batch(
    batch_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    identity: IdentityDep,
) -> dict[str, Any]:
    require_policy(request, identity, "batch", "activate", "CONFIDENTIAL")
    batch = (
        await session.execute(select(StampBatch).where(StampBatch.id == batch_id))
    ).scalar_one_or_none()
    if batch is None:
        raise HTTPException(status_code=404, detail={"reason": "batch-not-found"})
    try:
        count = await issuance.activate_batch(
            session, batch=batch, signing_key=request.app.state.signing_key,
            principal_sub=identity.subject,
        )
    except issuance.IssuanceError as exc:
        raise HTTPException(status_code=422, detail={"reason": exc.reason, "detail": str(exc)}) from exc
    await audit.record(session, "batch.activated", {
        "batchId": str(batch_id), "activatedCount": count, "principal": identity.subject,
    })
    await session.commit()
    return {"batchId": str(batch_id), "activatedCount": count}


@router.get("/stamps/{serial}")
async def get_stamp(
    serial: str,
    request: Request,
    session: SessionDep,
    identity: IdentityDep,
) -> dict[str, Any]:
    require_policy(request, identity, "stamp", "read", "CONFIDENTIAL")
    stamp = (
        await session.execute(select(Stamp).where(Stamp.serial == serial.strip().upper()))
    ).scalar_one_or_none()
    if stamp is None:
        raise HTTPException(status_code=404, detail={"reason": "stamp-not-found"})
    return {
        "serial": stamp.serial,
        "status": stamp.status,
        "batchId": str(stamp.batch_id),
        "hsCode": stamp.hs_code,
        "declarationRef": stamp.declaration_ref,
        "consigneeTin": stamp.consignee_tin,
        "dutyPaidKobo": stamp.duty_paid_kobo,
        "validFrom": stamp.valid_from.isoformat(),
        "validUntil": stamp.valid_until.isoformat(),
        "credential": stamp.credential,
    }


@router.post("/stamps/{serial}/void", status_code=202)
async def request_void_route(
    serial: str,
    body: schemas.VoidIn,
    request: Request,
    session: SessionDep,
    identity: IdentityDep,
) -> dict[str, Any]:
    """Request a stamp void (maker step). The void executes only when a
    DIFFERENT excise-approver approves it via /void/approve."""
    require_policy(request, identity, "stamp", "void", "CONFIDENTIAL")
    try:
        void_request = await request_void(
            session, serial=serial, reason=body.reason, principal_sub=identity.subject,
        )
    except VerificationError as exc:
        status = 404 if exc.reason == "not-found" else 422
        raise HTTPException(status_code=status, detail={"reason": exc.reason, "detail": str(exc)}) from exc
    await audit.record(session, "stamp.void-requested", {
        "serial": void_request.serial, "reason": body.reason, "principal": identity.subject,
    })
    await session.commit()
    return {"serial": void_request.serial, "voidStatus": void_request.status}


@router.post("/stamps/{serial}/void/approve")
async def approve_void_route(
    serial: str,
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    identity: IdentityDep,
) -> dict[str, Any]:
    """Approve a pending void request (checker step). Requester != approver:
    a single-actor void is rejected 409, consistent with assessments."""
    require_policy(request, identity, "stamp", "void", "CONFIDENTIAL")
    try:
        stamp = await approve_void(
            session, serial=serial, principal_sub=identity.subject,
            settings=settings, signing_key=request.app.state.signing_key,
        )
    except VerificationError as exc:
        status = {"not-found": 404, "self-approval": 409}.get(exc.reason, 422)
        raise HTTPException(status_code=status, detail={"reason": exc.reason, "detail": str(exc)}) from exc
    await audit.record(session, "stamp.voided", {
        "serial": stamp.serial, "principal": identity.subject,
    })
    await session.commit()
    return {"serial": stamp.serial, "status": stamp.status}
