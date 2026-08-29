"""Payment intents and receipts over financial-controls rails.

The rail adapter boundary (CVFF/TigerBeetle or Mojaloop via
blueeconomy-financial-controls) reports remittances to this service. The
acceptance criteria carried over from the reference design:

- exact amount + currency match against the intent — anything else is
  QUARANTINED as an unapplied receipt, never silently applied;
- the external reference is unique (replay killed at the DB);
- settlement posts a balanced double-entry journal (DB trigger enforced);
- when no payment rail is configured, intents cannot be created: 503 via the
  capabilities registry, never fabricated success.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from taxstamps.config import Settings
from taxstamps.models import (
    Assessment,
    PaymentIntent,
    PaymentReceipt,
    utcnow,
)
from taxstamps.services.journal import post_journal


class PaymentError(ValueError):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


async def create_intent(
    session: AsyncSession,
    *,
    settings: Settings,
    assessment: Assessment,
) -> PaymentIntent:
    if not settings.payment_rail_configured:
        raise PaymentError(
            "rail-unavailable",
            "no payment rail configured (TAXSTAMPS_PAYMENT_RAIL / TAXSTAMPS_FINANCIAL_CONTROLS_ENDPOINT)",
        )
    if assessment.status != "APPROVED":
        raise PaymentError("invalid-state", f"assessment is {assessment.status}, expected APPROVED")
    if assessment.zero_rated or assessment.total_duty_kobo == 0:
        raise PaymentError(
            "zero-rated",
            "zero-rated assessments settle via the zero-rated path, not a payment rail",
        )
    existing = (
        await session.execute(
            select(PaymentIntent).where(PaymentIntent.assessment_id == assessment.id)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    intent = PaymentIntent(
        id=uuid.uuid4(),
        assessment_id=assessment.id,
        rail=settings.payment_rail,
        expected_amount_kobo=assessment.total_duty_kobo,
        currency="NGN",
    )
    assessment.status = "PAYMENT_PENDING"
    session.add(intent)
    await session.flush()
    return intent


async def settle_zero_rated(
    session: AsyncSession,
    *,
    assessment: Assessment,
    principal_sub: str,
) -> PaymentIntent:
    """Settle a zero-rated assessment without a rail receipt.

    Zero-rated goods (e.g. pharmaceuticals) carry no federal excise but still
    require traceability stamps; they must not dead-end on a rail payment of
    zero. This path is policy-gated at the API layer (payment:create,
    FIDUCIARY_SEGREGATED) and audited there; here it creates a settled
    zero-amount intent (rail ``zero-rated``) as the durable settlement record
    and transitions the assessment to PAID. No journal is posted — no funds
    move. Idempotent.
    """
    if not assessment.zero_rated or assessment.total_duty_kobo != 0:
        raise PaymentError(
            "not-zero-rated",
            "assessment is not zero-rated; settlement requires a rail receipt",
        )
    if assessment.status != "APPROVED":
        raise PaymentError("invalid-state", f"assessment is {assessment.status}, expected APPROVED")
    existing = (
        await session.execute(
            select(PaymentIntent).where(PaymentIntent.assessment_id == assessment.id)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    locked = (
        await session.execute(
            select(Assessment).where(Assessment.id == assessment.id).with_for_update()
        )
    ).scalar_one()
    intent = PaymentIntent(
        id=uuid.uuid4(),
        assessment_id=locked.id,
        rail="zero-rated",
        expected_amount_kobo=0,
        currency=locked.currency,
        status="SETTLED",
        zero_rated=True,
        settled_at=utcnow(),
    )
    locked.status = "PAID"
    session.add(intent)
    await session.flush()
    return intent


async def record_receipt(
    session: AsyncSession,
    *,
    intent: PaymentIntent,
    external_reference: str,
    amount_kobo: int,
    currency: str,
) -> PaymentReceipt:
    """Record a remittance. Exact match applies + settles; mismatch quarantines.

    The unique external_reference makes an exact replay idempotent (the same
    receipt row is returned); a conflicting amount under a replayed reference
    cannot occur because the reference is unique and receipts are immutable.
    """
    existing = (
        await session.execute(
            select(PaymentReceipt).where(PaymentReceipt.external_reference == external_reference)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    locked = (
        await session.execute(
            select(PaymentIntent).where(PaymentIntent.id == intent.id).with_for_update()
        )
    ).scalar_one()
    if locked.status == "SETTLED":
        # A second, distinct remittance for an already-settled intent is
        # quarantined; funds are never double-applied.
        receipt = PaymentReceipt(
            id=uuid.uuid4(),
            payment_intent_id=None,
            external_reference=external_reference,
            amount_kobo=amount_kobo,
            currency=currency,
            status="QUARANTINED",
            quarantine_reason="intent already settled",
        )
        session.add(receipt)
        await session.flush()
        return receipt
    exact = amount_kobo == locked.expected_amount_kobo and currency == locked.currency
    if not exact:
        reason = (
            f"amount mismatch: expected {locked.expected_amount_kobo} {locked.currency}, "
            f"received {amount_kobo} {currency}"
        )
        receipt = PaymentReceipt(
            id=uuid.uuid4(),
            payment_intent_id=None,
            external_reference=external_reference,
            amount_kobo=amount_kobo,
            currency=currency,
            status="QUARANTINED",
            quarantine_reason=reason,
        )
        session.add(receipt)
        await session.flush()
        return receipt
    receipt = PaymentReceipt(
        id=uuid.uuid4(),
        payment_intent_id=locked.id,
        external_reference=external_reference,
        amount_kobo=amount_kobo,
        currency=currency,
        status="APPLIED",
    )
    session.add(receipt)
    locked.status = "SETTLED"
    locked.settled_at = utcnow()
    assessment = (
        await session.execute(select(Assessment).where(Assessment.id == locked.assessment_id))
    ).scalar_one()
    assessment.status = "PAID"
    await post_journal(
        session,
        reference=f"excise-settlement:{external_reference}",
        narration=f"Excise duty settlement for assessment {assessment.id}",
        legs=[
            ("assets:financial-controls-clearing", amount_kobo, 0),
            ("revenue:excise-duty-payable", 0, amount_kobo),
        ],
    )
    await session.flush()
    return receipt


async def resolve_quarantine(
    session: AsyncSession,
    *,
    intent: PaymentIntent,
    resolution: str,  # SETTLE | FAIL
    external_reference: str,
    supersedes_reference: str,
    amount_kobo: int,
    currency: str,
    reason: str,
    principal_sub: str,
) -> PaymentReceipt:
    """Controlled resolution of a quarantined remittance.

    Posts a SUPERSEDING receipt (a NEW row — receipts stay immutable) that
    either:
    - SETTLE: applies the corrected remittance (exact amount + currency match
      still REQUIRED) — the intent settles, the assessment goes PAID and the
      balanced settlement journal is posted; or
    - FAIL: records the quarantine evidence superseded and marks the intent
      FAILED with the reason (the funds are never applied).

    ``supersedes_reference`` MUST name an existing QUARANTINED receipt, so a
    resolution can never be fabricated without quarantine evidence. Audited
    at the API layer. Idempotent on the superseding ``external_reference``.
    """
    if resolution not in ("SETTLE", "FAIL"):
        raise PaymentError("invalid-resolution", resolution)
    if not reason or not reason.strip():
        raise PaymentError("reason-required", "quarantine resolution requires a reason")
    existing = (
        await session.execute(
            select(PaymentReceipt).where(PaymentReceipt.external_reference == external_reference)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    quarantined = (
        await session.execute(
            select(PaymentReceipt).where(
                PaymentReceipt.external_reference == supersedes_reference,
                PaymentReceipt.status == "QUARANTINED",
            )
        )
    ).scalar_one_or_none()
    if quarantined is None:
        raise PaymentError(
            "no-quarantine",
            f"no quarantined receipt with reference {supersedes_reference}",
        )
    locked = (
        await session.execute(
            select(PaymentIntent).where(PaymentIntent.id == intent.id).with_for_update()
        )
    ).scalar_one()
    if locked.status != "PENDING":
        raise PaymentError("invalid-state", f"intent is {locked.status}, expected PENDING")
    if resolution == "FAIL":
        receipt = PaymentReceipt(
            id=uuid.uuid4(),
            payment_intent_id=None,
            external_reference=external_reference,
            amount_kobo=amount_kobo,
            currency=currency,
            status="QUARANTINED",
            quarantine_reason=(
                f"supersedes {supersedes_reference}: intent FAILED by resolution — {reason}"
            ),
            supersedes_reference=supersedes_reference,
        )
        locked.status = "FAILED"
        session.add(receipt)
        await session.flush()
        return receipt
    # SETTLE: the corrected remittance must still match exactly.
    if amount_kobo != locked.expected_amount_kobo or currency != locked.currency:
        raise PaymentError(
            "amount-mismatch",
            f"expected {locked.expected_amount_kobo} {locked.currency}, "
            f"received {amount_kobo} {currency}",
        )
    receipt = PaymentReceipt(
        id=uuid.uuid4(),
        payment_intent_id=locked.id,
        external_reference=external_reference,
        amount_kobo=amount_kobo,
        currency=currency,
        status="APPLIED",
        supersedes_reference=supersedes_reference,
    )
    session.add(receipt)
    locked.status = "SETTLED"
    locked.settled_at = utcnow()
    assessment = (
        await session.execute(select(Assessment).where(Assessment.id == locked.assessment_id))
    ).scalar_one()
    assessment.status = "PAID"
    await post_journal(
        session,
        reference=f"excise-settlement:{external_reference}",
        narration=(
            f"Excise duty settlement for assessment {assessment.id} "
            f"(quarantine resolution of {supersedes_reference})"
        ),
        legs=[
            ("assets:financial-controls-clearing", amount_kobo, 0),
            ("revenue:excise-duty-payable", 0, amount_kobo),
        ],
    )
    await session.flush()
    return receipt
