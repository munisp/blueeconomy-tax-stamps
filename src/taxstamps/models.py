"""SQLAlchemy 2.0 models. Invariants that must hold under concurrency live in
the DATABASE (CHECK constraints, unique constraints, triggers in the Alembic
migration), not in application convention.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------- principals


class Principal(Base):
    """Platform identity resolved from a verified OIDC token."""

    __tablename__ = "principals"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    subject: Mapped[str] = mapped_column(String(256), unique=True)  # OIDC sub
    display_name: Mapped[str] = mapped_column(String(256), default="")
    tenant: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class VerifierCredential(Base):
    """Per-verifier credential for the authenticated verification API.

    Only a keyed hash of the bearer credential is stored; there is NO shared
    fleet secret. Each verifier device/operator holds its own credential.
    """

    __tablename__ = "verifier_credentials"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    verifier_id: Mapped[str] = mapped_column(String(128), unique=True)
    credential_hash: Mapped[str] = mapped_column(String(64))  # sha256 hex of presented credential
    display_name: Mapped[str] = mapped_column(String(256), default="")
    tenant: Mapped[str] = mapped_column(String(128), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ------------------------------------------------------------- declarations


class Declaration(Base):
    __tablename__ = "declarations"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    declaration_ref: Mapped[str] = mapped_column(String(64), unique=True)
    consignee_tin: Mapped[str] = mapped_column(String(32))
    consignee_name: Mapped[str] = mapped_column(String(256), default="")
    source_event_id: Mapped[str] = mapped_column(String(128), unique=True)  # envelope eventId dedupe
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    envelope: Mapped[dict[str, Any]] = mapped_column(JSONB)  # full verified envelope v1.0
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DeclarationLine(Base):
    __tablename__ = "declaration_lines"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    declaration_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("declarations.id"), index=True)
    hs_code: Mapped[str] = mapped_column(String(16))
    description: Mapped[str] = mapped_column(Text, default="")
    quantity: Mapped[int] = mapped_column(BigInteger)
    unit: Mapped[str] = mapped_column(String(16))  # STICK | LITRE | UNIT
    customs_value_kobo: Mapped[int] = mapped_column(BigInteger)
    stamps_required: Mapped[int] = mapped_column(BigInteger)
    __table_args__ = (
        CheckConstraint("quantity >= 0", name="ck_decl_line_qty"),
        CheckConstraint("customs_value_kobo >= 0", name="ck_decl_line_value"),
        CheckConstraint("stamps_required >= 0", name="ck_decl_line_stamps"),
    )


# -------------------------------------------------------------- assessments


ASSESSMENT_STATUSES = (
    "PENDING_APPROVAL", "REJECTED", "APPROVED", "PAYMENT_PENDING",
    "PAID", "ISSUING", "ISSUED", "CANCELLED",
)


class Assessment(Base):
    __tablename__ = "assessments"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    declaration_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("declarations.id"), index=True)
    status: Mapped[str] = mapped_column(String(32), default="PENDING_APPROVAL")
    currency: Mapped[str] = mapped_column(String(3), default="NGN")
    total_duty_kobo: Mapped[int] = mapped_column(BigInteger)
    stamps_required: Mapped[int] = mapped_column(BigInteger)
    risk_tier: Mapped[str] = mapped_column(String(16))  # LOW | STANDARD | HIGH
    approvals_required: Mapped[int] = mapped_column(Integer)
    submitted_by: Mapped[str] = mapped_column(String(256))  # principal subject
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True)
    zero_rated: Mapped[bool] = mapped_column(Boolean, default=False)  # e.g. pharmaceuticals
    __table_args__ = (
        CheckConstraint(f"status IN {ASSESSMENT_STATUSES!r}", name="ck_assessment_status"),
        CheckConstraint("total_duty_kobo >= 0", name="ck_assessment_total"),
        CheckConstraint("stamps_required >= 0", name="ck_assessment_stamps"),
        CheckConstraint("approvals_required BETWEEN 1 AND 3", name="ck_assessment_approvals"),
        CheckConstraint("risk_tier IN ('LOW','STANDARD','HIGH')", name="ck_assessment_risk"),
        CheckConstraint("total_duty_kobo > 0 OR zero_rated", name="ck_assessment_zero_rated"),
    )


class AssessmentLine(Base):
    __tablename__ = "assessment_lines"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assessments.id"), index=True)
    hs_code: Mapped[str] = mapped_column(String(16))
    category: Mapped[str] = mapped_column(String(32))
    quantity: Mapped[int] = mapped_column(BigInteger)
    unit: Mapped[str] = mapped_column(String(16))
    customs_value_kobo: Mapped[int] = mapped_column(BigInteger)
    specific_duty_kobo: Mapped[int] = mapped_column(BigInteger)
    ad_valorem_duty_kobo: Mapped[int] = mapped_column(BigInteger)
    total_duty_kobo: Mapped[int] = mapped_column(BigInteger)
    statutory_ref: Mapped[str] = mapped_column(Text)
    tariff_effective_from: Mapped[date] = mapped_column(Date)
    __table_args__ = (
        CheckConstraint("total_duty_kobo = specific_duty_kobo + ad_valorem_duty_kobo", name="ck_asline_total"),
        CheckConstraint("quantity >= 0", name="ck_asline_qty"),
    )


class Approval(Base):
    """Maker-checker record. Immutable (trigger). The submitter can never be
    an approver: enforced in service logic AND by partial unique index
    (assessment_id, principal_sub)."""

    __tablename__ = "approvals"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assessments.id"), index=True)
    principal_sub: Mapped[str] = mapped_column(String(256))
    decision: Mapped[str] = mapped_column(String(8))  # APPROVE | REJECT
    level: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(Text, default="")
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (
        UniqueConstraint("assessment_id", "principal_sub", name="uq_approval_principal"),
        CheckConstraint("decision IN ('APPROVE','REJECT')", name="ck_approval_decision"),
    )


# ----------------------------------------------------------------- payments


class PaymentIntent(Base):
    __tablename__ = "payment_intents"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assessments.id"), unique=True)
    rail: Mapped[str] = mapped_column(String(32))  # cvff-tigerbeetle | mojaloop
    expected_amount_kobo: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3), default="NGN")
    status: Mapped[str] = mapped_column(String(16), default="PENDING")  # PENDING|SETTLED|FAILED
    zero_rated: Mapped[bool] = mapped_column(Boolean, default=False)  # zero-rated settle path
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        CheckConstraint("status IN ('PENDING','SETTLED','FAILED')", name="ck_intent_status"),
        CheckConstraint("expected_amount_kobo >= 0", name="ck_intent_amount"),
        CheckConstraint("expected_amount_kobo > 0 OR zero_rated", name="ck_intent_zero_rated"),
    )


class PaymentReceipt(Base):
    """A remittance reported by the financial-controls rail. Exact amount +
    currency match against the intent is REQUIRED; anything else is
    quarantined as UNAPPLIED and never silently applied."""

    __tablename__ = "payment_receipts"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    payment_intent_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("payment_intents.id"))
    external_reference: Mapped[str] = mapped_column(String(128), unique=True)  # replay killer
    amount_kobo: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3))
    status: Mapped[str] = mapped_column(String(16))  # APPLIED | QUARANTINED
    quarantine_reason: Mapped[str] = mapped_column(Text, default="")
    # Quarantine resolution: a SUPERSEDING receipt references the quarantined
    # receipt it resolves (the original stays immutable).
    supersedes_reference: Mapped[str] = mapped_column(String(128), default="")
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (
        CheckConstraint("status IN ('APPLIED','QUARANTINED')", name="ck_receipt_status"),
        CheckConstraint("amount_kobo >= 0", name="ck_receipt_amount"),
    )


# ------------------------------------------------------------------ journal


class Journal(Base):
    __tablename__ = "journals"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    reference: Mapped[str] = mapped_column(String(128), unique=True)
    narration: Mapped[str] = mapped_column(Text, default="")
    posted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LedgerEntry(Base):
    """Double-entry legs. A deferred constraint trigger rejects COMMIT of any
    journal whose legs do not balance (sum debits == sum credits)."""

    __tablename__ = "ledger_entries"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    journal_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("journals.id"), index=True)
    account: Mapped[str] = mapped_column(String(64))
    debit_kobo: Mapped[int] = mapped_column(BigInteger, default=0)
    credit_kobo: Mapped[int] = mapped_column(BigInteger, default=0)
    __table_args__ = (
        CheckConstraint("debit_kobo >= 0 AND credit_kobo >= 0", name="ck_entry_nonneg"),
        CheckConstraint("NOT (debit_kobo > 0 AND credit_kobo > 0)", name="ck_entry_one_side"),
    )


# ------------------------------------------------------------------- stamps


class SerialCounter(Base):
    """Atomic serial-block claims: INSERT ... ON CONFLICT + UPDATE ...
    RETURNING in one transaction."""

    __tablename__ = "serial_counters"
    category_code: Mapped[str] = mapped_column(String(3), primary_key=True)
    year: Mapped[int] = mapped_column(Integer, primary_key=True)
    next_sequence: Mapped[int] = mapped_column(BigInteger, default=0)


BATCH_STATUSES = (
    "PENDING", "ISSUING", "ISSUED", "INSPECTION_FAILED", "READY",
    "ACTIVE", "COMPLETED", "VOID",
)


class StampBatch(Base):
    __tablename__ = "stamp_batches"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assessments.id"), unique=True)
    category_code: Mapped[str] = mapped_column(String(3))
    year: Mapped[int] = mapped_column(Integer)
    quantity: Mapped[int] = mapped_column(BigInteger)
    issued_count: Mapped[int] = mapped_column(BigInteger, default=0)
    status: Mapped[str] = mapped_column(String(24), default="PENDING")
    merkle_root: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        CheckConstraint(f"status IN {BATCH_STATUSES!r}", name="ck_batch_status"),
        CheckConstraint("quantity > 0", name="ck_batch_qty"),
        CheckConstraint("issued_count >= 0 AND issued_count <= quantity", name="ck_batch_issued"),
    )


STAMP_STATUSES = ("ISSUED", "ACTIVE", "CONSUMED", "VOID", "EXPIRED", "SUSPECT")


class Stamp(Base):
    __tablename__ = "stamps"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    batch_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("stamp_batches.id"), index=True)
    serial: Mapped[str] = mapped_column(String(32), unique=True)
    category_code: Mapped[str] = mapped_column(String(3))
    year: Mapped[int] = mapped_column(Integer)
    sequence: Mapped[int] = mapped_column(BigInteger)
    status: Mapped[str] = mapped_column(String(16), default="ISSUED")
    hs_code: Mapped[str] = mapped_column(String(16))
    declaration_ref: Mapped[str] = mapped_column(String(64))
    consignee_tin: Mapped[str] = mapped_column(String(32))
    duty_paid_kobo: Mapped[int] = mapped_column(BigInteger)
    status_list_index: Mapped[int] = mapped_column(Integer, unique=True)
    credential: Mapped[dict[str, Any]] = mapped_column(JSONB)  # the signed W3C VC (QR payload)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_scan_verifier: Mapped[str] = mapped_column(String(128), default="")
    first_scan_lat_micros: Mapped[int | None] = mapped_column(BigInteger)
    first_scan_long_micros: Mapped[int | None] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (
        CheckConstraint(f"status IN {STAMP_STATUSES!r}", name="ck_stamp_status"),
        UniqueConstraint("category_code", "year", "sequence", name="uq_stamp_cat_year_seq"),
        Index("ix_stamps_first_scan", "first_scan_at"),
    )


VOID_REQUEST_STATUSES = ("PENDING", "EXECUTED", "REJECTED")


class StampVoidRequest(Base):
    """Maker-checker stamp void: the void requester can never be the void
    approver (consistent with the assessment approvals pattern). The void
    itself (status + status-list bit) executes only on approval."""

    __tablename__ = "stamp_void_requests"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    serial: Mapped[str] = mapped_column(String(32), index=True)
    reason: Mapped[str] = mapped_column(Text)
    requested_by: Mapped[str] = mapped_column(String(256))
    approved_by: Mapped[str] = mapped_column(String(256), default="")
    status: Mapped[str] = mapped_column(String(16), default="PENDING")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        CheckConstraint(f"status IN {VOID_REQUEST_STATUSES!r}", name="ck_void_request_status"),
        CheckConstraint("approved_by = '' OR approved_by <> requested_by", name="ck_void_request_not_self"),
    )


class Inspection(Base):
    __tablename__ = "inspections"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    batch_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("stamp_batches.id"), index=True)
    lot_size: Mapped[int] = mapped_column(BigInteger)
    code_letter: Mapped[str] = mapped_column(String(2))
    sample_size: Mapped[int] = mapped_column(Integer)
    accept: Mapped[int] = mapped_column(Integer)
    reject: Mapped[int] = mapped_column(Integer)
    defectives: Mapped[int] = mapped_column(Integer)
    result: Mapped[str] = mapped_column(String(8))  # PASS | FAIL
    inspector_sub: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (
        CheckConstraint("result IN ('PASS','FAIL')", name="ck_inspection_result"),
        CheckConstraint("defectives >= 0 AND defectives <= sample_size", name="ck_inspection_def"),
    )


# ------------------------------------------------------------ verifications


VERIFICATION_OUTCOMES = (
    "valid", "already_verified", "clone_suspect", "unknown_serial",
    "malformed_serial", "not_active", "void", "expired",
)


class Verification(Base):
    """Every verification attempt, success or failure, with device + geo."""

    __tablename__ = "verifications"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    stamp_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("stamps.id"), index=True)
    serial_presented: Mapped[str] = mapped_column(String(64))
    verifier_id: Mapped[str] = mapped_column(String(128), default="")
    public_scan: Mapped[bool] = mapped_column(Boolean, default=False)
    outcome: Mapped[str] = mapped_column(String(24))
    detail: Mapped[str] = mapped_column(Text, default="")
    lat_micros: Mapped[int | None] = mapped_column(BigInteger)
    long_micros: Mapped[int | None] = mapped_column(BigInteger)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (
        CheckConstraint(f"outcome IN {VERIFICATION_OUTCOMES!r}", name="ck_verification_outcome"),
        Index("ix_verifications_stamp_time", "stamp_id", "verified_at"),
    )


# ------------------------------------------------------------------ control


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_records"
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    principal_sub: Mapped[str] = mapped_column(String(256), primary_key=True)
    request_hash: Mapped[str] = mapped_column(String(64))
    response_status: Mapped[int] = mapped_column(Integer)
    response_body: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OutboxMessage(Base):
    __tablename__ = "outbox_messages"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    topic: Mapped[str] = mapped_column(String(128))
    key: Mapped[str] = mapped_column(String(128))
    envelope: Mapped[dict[str, Any]] = mapped_column(JSONB)  # envelope v1.0, JWS-signed
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)


class AuditEvent(Base):
    """Hash-chained append-only audit. UPDATE/DELETE rejected by trigger."""

    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)
    event_type: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class StatusListSnapshot(Base):
    """Latest signed Bitstring Status List credential per purpose."""

    __tablename__ = "status_list_snapshots"
    purpose: Mapped[str] = mapped_column(String(16), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    credential: Mapped[dict[str, Any]] = mapped_column(JSONB)
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ProcessedEvent(Base):
    """Consumer dedupe: envelope eventIds already applied."""

    __tablename__ = "processed_events"
    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(128))
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
