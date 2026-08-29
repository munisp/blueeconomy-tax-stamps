"""Serial issuance: chunked, resumable, crash-safe; atomic serial-block claims.

- One batch per PAID assessment; quantity == stamps_required (batch can never
  exceed the paid quantity: CHECK constraint + service check).
- Serial blocks are claimed with INSERT ... ON CONFLICT ... DO UPDATE ...
  RETURNING in ONE transaction per chunk, so concurrent issuers can never
  receive overlapping blocks and a crash mid-chunk leaves the counter
  consistent with the stamps actually inserted (both roll back together).
- Resume: ``issued_count`` in the batch row is the durable cursor; re-running
  issuance continues at the next chunk.
- Every stamp carries its signed W3C VC (the QR payload) at issuance.
- Completion computes the RFC 6962-style Merkle root over serials and emits
  stamps.issued.v1 via the outbox.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from taxstamps.config import Settings
from taxstamps.crypto.eddsa import SigningKey
from taxstamps.crypto.statuslist import status_entry
from taxstamps.crypto.vc import build_stamp_credential, issue_proof
from taxstamps.domain.merkle import merkle_root
from taxstamps.domain.quality import evaluate_sample, plan_for_lot
from taxstamps.domain.serials import CATEGORIES, build_serial
from taxstamps.models import (
    Assessment,
    AssessmentLine,
    Declaration,
    Inspection,
    Stamp,
    StampBatch,
    utcnow,
)
from taxstamps.services import outbox, statuslists


class IssuanceError(ValueError):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


async def _primary_line(session: AsyncSession, assessment_id: uuid.UUID) -> AssessmentLine:
    line = (
        await session.execute(
            select(AssessmentLine)
            .where(AssessmentLine.assessment_id == assessment_id)
            .order_by(AssessmentLine.total_duty_kobo.desc())
            .limit(1)
        )
    ).scalars().first()
    if line is None:
        raise IssuanceError("no-lines", "assessment has no stamp-bearing lines")
    return line


async def create_batch(
    session: AsyncSession,
    *,
    assessment: Assessment,
    settings: Settings,
) -> StampBatch:
    if assessment.status != "PAID":
        raise IssuanceError("invalid-state", f"assessment is {assessment.status}, expected PAID")
    existing = (
        await session.execute(
            select(StampBatch).where(StampBatch.assessment_id == assessment.id)
        )
    ).scalars().first()
    if existing is not None:
        return existing
    if assessment.stamps_required <= 0:
        raise IssuanceError("nothing-to-issue", "assessment requires zero stamps")
    line = await _primary_line(session, assessment.id)
    category_code = CATEGORIES[line.category]
    now = utcnow()
    batch = StampBatch(
        id=uuid.uuid4(),
        assessment_id=assessment.id,
        category_code=category_code,
        year=now.year,
        quantity=assessment.stamps_required,
        status="PENDING",
    )
    assessment.status = "ISSUING"
    session.add(batch)
    await session.flush()
    return batch


async def _claim_serial_block(session: AsyncSession, category_code: str, year: int, count: int) -> int:
    """Atomically claim ``count`` sequences; returns the first sequence."""
    row = (
        await session.execute(
            text(
                """
                INSERT INTO serial_counters (category_code, year, next_sequence)
                VALUES (:cat, :yr, :n)
                ON CONFLICT (category_code, year)
                DO UPDATE SET next_sequence = serial_counters.next_sequence + :n
                RETURNING next_sequence
                """
            ),
            {"cat": category_code, "yr": year, "n": count},
        )
    ).first()
    assert row is not None
    return int(row[0]) - count


async def issue_chunk(
    session: AsyncSession,
    *,
    batch: StampBatch,
    settings: Settings,
    signing_key: SigningKey,
    chunk_size: int | None = None,
) -> int:
    """Issue at most one chunk of stamps. Returns the number issued (0 = done).

    Crash-safe: the serial-block claim, stamp inserts, VC generation and the
    batch cursor update commit or roll back together.
    """
    locked = (
        await session.execute(
            select(StampBatch).where(StampBatch.id == batch.id).with_for_update()
        )
    ).scalar_one()
    if locked.status not in ("PENDING", "ISSUING"):
        return 0
    remaining = locked.quantity - locked.issued_count
    if remaining <= 0:
        locked.status = "ISSUED"
        await session.flush()
        return 0
    size = int(min(chunk_size or settings.issuance_chunk_size, remaining))
    base = await _claim_serial_block(session, locked.category_code, locked.year, size)

    assessment = (
        await session.execute(select(Assessment).where(Assessment.id == locked.assessment_id))
    ).scalar_one()
    declaration = (
        await session.execute(select(Declaration).where(Declaration.id == assessment.declaration_id))
    ).scalar_one()
    line = await _primary_line(session, assessment.id)

    now = datetime.now(UTC)
    valid_until = now + timedelta(days=settings.stamp_validity_days)
    vm = f"{settings.issuer_did}#ed25519-{signing_key.kid}"
    entries = [
        status_entry(statuslists.list_credential_id(settings, p), 0, p) for p in ("void", "expired", "suspect")
    ]
    for i in range(size):
        sequence = base + i
        serial = build_serial(locked.category_code, locked.year, sequence)
        index = await statuslists.allocate_index(session)
        per_stamp_entries = [
            {**e, "id": f"{e['statusListCredential']}#{index}", "statusListIndex": str(index)}
            for e in entries
        ]
        credential_id = f"{settings.issuer_did}/credentials/{serial}"
        doc = build_stamp_credential(
            credential_id=credential_id,
            issuer_did=settings.issuer_did,
            serial=serial,
            hs_code=line.hs_code,
            declaration_ref=declaration.declaration_ref,
            consignee_tin=declaration.consignee_tin,
            duty_paid_kobo=assessment.total_duty_kobo,
            valid_from=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            valid_until=valid_until.strftime("%Y-%m-%dT%H:%M:%SZ"),
            status_entries=per_stamp_entries,
        )
        signed_vc = issue_proof(doc, signing_key, vm)
        session.add(
            Stamp(
                id=uuid.uuid4(),
                batch_id=locked.id,
                serial=serial,
                category_code=locked.category_code,
                year=locked.year,
                sequence=sequence,
                status="ISSUED",
                hs_code=line.hs_code,
                declaration_ref=declaration.declaration_ref,
                consignee_tin=declaration.consignee_tin,
                duty_paid_kobo=assessment.total_duty_kobo,
                status_list_index=index,
                credential=signed_vc,
                valid_from=now,
                valid_until=valid_until,
            )
        )
    locked.issued_count += size
    locked.status = "ISSUING" if locked.issued_count < locked.quantity else "ISSUED"
    await session.flush()
    return size


async def finalize_batch(
    session: AsyncSession,
    *,
    batch: StampBatch,
    signing_key: SigningKey,
    principal_sub: str,
) -> StampBatch:
    """Complete an issued batch: Merkle anchor + stamps.issued.v1 outbox event."""
    locked = (
        await session.execute(
            select(StampBatch).where(StampBatch.id == batch.id).with_for_update()
        )
    ).scalar_one()
    if locked.status != "ISSUED":
        raise IssuanceError("invalid-state", f"batch is {locked.status}, expected ISSUED")
    serials = (
        await session.execute(
            select(Stamp.serial).where(Stamp.batch_id == locked.id).order_by(Stamp.sequence)
        )
    ).scalars().all()
    locked.merkle_root = merkle_root([s.encode("utf-8") for s in serials])
    locked.status = "READY"
    await outbox.enqueue(
        session,
        event_type="stamps.issued.v1",
        resource={
            "batchId": str(locked.id),
            "assessmentId": str(locked.assessment_id),
            "categoryCode": locked.category_code,
            "quantity": locked.quantity,
            "merkleRoot": locked.merkle_root,
        },
        signing_key=signing_key,
        principal_id=principal_sub,
        principal_role="excise-officer",
        correlation_id=str(locked.assessment_id),
    )
    await session.flush()
    return locked


async def record_inspection(
    session: AsyncSession,
    *,
    batch: StampBatch,
    defectives: int,
    inspector_sub: str,
) -> Inspection:
    """ANSI/ASQ Z1.4 GIL-II AQL 0.65% acceptance sampling for the lot."""
    locked = (
        await session.execute(
            select(StampBatch).where(StampBatch.id == batch.id).with_for_update()
        )
    ).scalar_one()
    if locked.status not in ("READY", "ACTIVE"):
        raise IssuanceError("invalid-state", f"batch is {locked.status}, expected READY")
    plan = plan_for_lot(int(locked.quantity))
    passed = evaluate_sample(plan, defectives)
    inspection = Inspection(
        id=uuid.uuid4(),
        batch_id=locked.id,
        lot_size=locked.quantity,
        code_letter=plan.code_letter,
        sample_size=plan.sample_size,
        accept=plan.accept,
        reject=plan.reject,
        defectives=defectives,
        result="PASS" if passed else "FAIL",
        inspector_sub=inspector_sub,
    )
    session.add(inspection)
    if not passed:
        # A failed lot can never be activated; serials stay un-activated and
        # must be voided through the stamp void flow (reason required).
        locked.status = "INSPECTION_FAILED"
    await session.flush()
    return inspection


async def activate_batch(
    session: AsyncSession,
    *,
    batch: StampBatch,
    signing_key: SigningKey,
    principal_sub: str,
) -> int:
    """Activate a READY batch that passed inspection. Returns stamps activated."""
    locked = (
        await session.execute(
            select(StampBatch).where(StampBatch.id == batch.id).with_for_update()
        )
    ).scalar_one()
    if locked.status != "READY":
        raise IssuanceError("invalid-state", f"batch is {locked.status}, expected READY")
    passed = (
        await session.execute(
            select(Inspection).where(
                Inspection.batch_id == locked.id, Inspection.result == "PASS"
            )
        )
    ).scalars().first()
    if passed is None:
        raise IssuanceError("inspection-required", "batch has no passing inspection")
    now = utcnow()
    result = await session.execute(
        text(
            "UPDATE stamps SET status = 'ACTIVE', activated_at = :now "
            "WHERE batch_id = :bid AND status = 'ISSUED'"
        ),
        {"now": now, "bid": locked.id},
    )
    assert isinstance(result, CursorResult)
    locked.status = "ACTIVE"
    await outbox.enqueue(
        session,
        event_type="stamps.activated.v1",
        resource={"batchId": str(locked.id), "activatedCount": result.rowcount},
        signing_key=signing_key,
        principal_id=principal_sub,
        principal_role="excise-officer",
        correlation_id=str(locked.assessment_id),
    )
    await session.flush()
    return int(result.rowcount or 0)
