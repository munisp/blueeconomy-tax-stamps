"""Initial schema: domain tables plus DB-enforced invariants.

Invariants enforced by the database, not by application convention:
- append-only audit_events (UPDATE/DELETE rejected by trigger);
- immutable approvals, payment receipts, journals, ledger entries,
  idempotency records and processed events;
- double-entry balance: a DEFERRABLE INITIALLY DEFERRED constraint trigger
  rejects COMMIT of any journal whose legs do not balance.

Revision ID: 0001_initial
Revises:
Create Date: 2026-09-01
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def _uuid() -> sa.types.TypeEngine:
    return sa.Uuid()


def upgrade() -> None:
    op.create_table(
        "principals",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("subject", sa.String(256), nullable=False, unique=True),
        sa.Column("display_name", sa.String(256), nullable=False, server_default=""),
        sa.Column("tenant", sa.String(128), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "verifier_credentials",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("verifier_id", sa.String(128), nullable=False, unique=True),
        sa.Column("credential_hash", sa.String(64), nullable=False),
        sa.Column("display_name", sa.String(256), nullable=False, server_default=""),
        sa.Column("tenant", sa.String(128), nullable=False, server_default=""),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "declarations",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("declaration_ref", sa.String(64), nullable=False, unique=True),
        sa.Column("consignee_tin", sa.String(32), nullable=False),
        sa.Column("consignee_name", sa.String(256), nullable=False, server_default=""),
        sa.Column("source_event_id", sa.String(128), nullable=False, unique=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("envelope", JSONB, nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "declaration_lines",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("declaration_id", _uuid(), sa.ForeignKey("declarations.id"), nullable=False, index=True),
        sa.Column("hs_code", sa.String(16), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("quantity", sa.BigInteger(), nullable=False),
        sa.Column("unit", sa.String(16), nullable=False),
        sa.Column("customs_value_kobo", sa.BigInteger(), nullable=False),
        sa.Column("stamps_required", sa.BigInteger(), nullable=False),
        sa.CheckConstraint("quantity >= 0", name="ck_decl_line_qty"),
        sa.CheckConstraint("customs_value_kobo >= 0", name="ck_decl_line_value"),
        sa.CheckConstraint("stamps_required >= 0", name="ck_decl_line_stamps"),
    )
    op.create_index("ix_declaration_lines_declaration_id", "declaration_lines", ["declaration_id"])
    op.create_table(
        "assessments",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("declaration_id", _uuid(), sa.ForeignKey("declarations.id"), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False, server_default="NGN"),
        sa.Column("total_duty_kobo", sa.BigInteger(), nullable=False),
        sa.Column("stamps_required", sa.BigInteger(), nullable=False),
        sa.Column("risk_tier", sa.String(16), nullable=False),
        sa.Column("approvals_required", sa.Integer(), nullable=False),
        sa.Column("submitted_by", sa.String(256), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.Column("idempotency_key", sa.String(128), nullable=False, unique=True),
        sa.CheckConstraint(
            "status IN ('PENDING_APPROVAL','REJECTED','APPROVED','PAYMENT_PENDING','PAID','ISSUING','ISSUED','CANCELLED')",
            name="ck_assessment_status",
        ),
        sa.CheckConstraint("total_duty_kobo >= 0", name="ck_assessment_total"),
        sa.CheckConstraint("stamps_required >= 0", name="ck_assessment_stamps"),
        sa.CheckConstraint("approvals_required BETWEEN 1 AND 3", name="ck_assessment_approvals"),
        sa.CheckConstraint("risk_tier IN ('LOW','STANDARD','HIGH')", name="ck_assessment_risk"),
    )
    op.create_index("ix_assessments_declaration_id", "assessments", ["declaration_id"])
    op.create_table(
        "assessment_lines",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("assessment_id", _uuid(), sa.ForeignKey("assessments.id"), nullable=False),
        sa.Column("hs_code", sa.String(16), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("quantity", sa.BigInteger(), nullable=False),
        sa.Column("unit", sa.String(16), nullable=False),
        sa.Column("customs_value_kobo", sa.BigInteger(), nullable=False),
        sa.Column("specific_duty_kobo", sa.BigInteger(), nullable=False),
        sa.Column("ad_valorem_duty_kobo", sa.BigInteger(), nullable=False),
        sa.Column("total_duty_kobo", sa.BigInteger(), nullable=False),
        sa.Column("statutory_ref", sa.Text(), nullable=False),
        sa.Column("tariff_effective_from", sa.Date(), nullable=False),
        sa.CheckConstraint("total_duty_kobo = specific_duty_kobo + ad_valorem_duty_kobo", name="ck_asline_total"),
        sa.CheckConstraint("quantity >= 0", name="ck_asline_qty"),
    )
    op.create_index("ix_assessment_lines_assessment_id", "assessment_lines", ["assessment_id"])
    op.create_table(
        "approvals",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("assessment_id", _uuid(), sa.ForeignKey("assessments.id"), nullable=False),
        sa.Column("principal_sub", sa.String(256), nullable=False),
        sa.Column("decision", sa.String(8), nullable=False),
        sa.Column("level", sa.Integer(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("assessment_id", "principal_sub", name="uq_approval_principal"),
        sa.CheckConstraint("decision IN ('APPROVE','REJECT')", name="ck_approval_decision"),
    )
    op.create_index("ix_approvals_assessment_id", "approvals", ["assessment_id"])
    op.create_table(
        "payment_intents",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("assessment_id", _uuid(), sa.ForeignKey("assessments.id"), nullable=False, unique=True),
        sa.Column("rail", sa.String(32), nullable=False),
        sa.Column("expected_amount_kobo", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False, server_default="NGN"),
        sa.Column("status", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("settled_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("status IN ('PENDING','SETTLED','FAILED')", name="ck_intent_status"),
        sa.CheckConstraint("expected_amount_kobo > 0", name="ck_intent_amount"),
    )
    op.create_table(
        "payment_receipts",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("payment_intent_id", _uuid(), sa.ForeignKey("payment_intents.id")),
        sa.Column("external_reference", sa.String(128), nullable=False, unique=True),
        sa.Column("amount_kobo", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("quarantine_reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('APPLIED','QUARANTINED')", name="ck_receipt_status"),
        sa.CheckConstraint("amount_kobo >= 0", name="ck_receipt_amount"),
    )
    op.create_table(
        "journals",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("reference", sa.String(128), nullable=False, unique=True),
        sa.Column("narration", sa.Text(), nullable=False, server_default=""),
        sa.Column("posted_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "ledger_entries",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("journal_id", _uuid(), sa.ForeignKey("journals.id"), nullable=False),
        sa.Column("account", sa.String(64), nullable=False),
        sa.Column("debit_kobo", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("credit_kobo", sa.BigInteger(), nullable=False, server_default="0"),
        sa.CheckConstraint("debit_kobo >= 0 AND credit_kobo >= 0", name="ck_entry_nonneg"),
        sa.CheckConstraint("NOT (debit_kobo > 0 AND credit_kobo > 0)", name="ck_entry_one_side"),
    )
    op.create_index("ix_ledger_entries_journal_id", "ledger_entries", ["journal_id"])
    op.create_table(
        "serial_counters",
        sa.Column("category_code", sa.String(3), primary_key=True),
        sa.Column("year", sa.Integer(), primary_key=True),
        sa.Column("next_sequence", sa.BigInteger(), nullable=False, server_default="0"),
    )
    op.create_table(
        "stamp_batches",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("assessment_id", _uuid(), sa.ForeignKey("assessments.id"), nullable=False, unique=True),
        sa.Column("category_code", sa.String(3), nullable=False),
        sa.Column("year", sa.Integer(), nullable=False),
        sa.Column("quantity", sa.BigInteger(), nullable=False),
        sa.Column("issued_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(24), nullable=False, server_default="PENDING"),
        sa.Column("merkle_root", sa.String(64), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "status IN ('PENDING','ISSUING','ISSUED','INSPECTION_FAILED','READY','ACTIVE','COMPLETED','VOID')",
            name="ck_batch_status",
        ),
        sa.CheckConstraint("quantity > 0", name="ck_batch_qty"),
        sa.CheckConstraint("issued_count >= 0 AND issued_count <= quantity", name="ck_batch_issued"),
    )
    op.create_table(
        "stamps",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("batch_id", _uuid(), sa.ForeignKey("stamp_batches.id"), nullable=False),
        sa.Column("serial", sa.String(32), nullable=False, unique=True),
        sa.Column("category_code", sa.String(3), nullable=False),
        sa.Column("year", sa.Integer(), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="ISSUED"),
        sa.Column("hs_code", sa.String(16), nullable=False),
        sa.Column("declaration_ref", sa.String(64), nullable=False),
        sa.Column("consignee_tin", sa.String(32), nullable=False),
        sa.Column("duty_paid_kobo", sa.BigInteger(), nullable=False),
        sa.Column("status_list_index", sa.Integer(), nullable=False, unique=True),
        sa.Column("credential", JSONB, nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True)),
        sa.Column("first_scan_at", sa.DateTime(timezone=True)),
        sa.Column("first_scan_verifier", sa.String(128), nullable=False, server_default=""),
        sa.Column("first_scan_lat_micros", sa.BigInteger()),
        sa.Column("first_scan_long_micros", sa.BigInteger()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('ISSUED','ACTIVE','CONSUMED','VOID','EXPIRED','SUSPECT')", name="ck_stamp_status"),
        sa.UniqueConstraint("category_code", "year", "sequence", name="uq_stamp_cat_year_seq"),
    )
    op.create_index("ix_stamps_batch_id", "stamps", ["batch_id"])
    op.create_index("ix_stamps_first_scan", "stamps", ["first_scan_at"])
    op.create_table(
        "inspections",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("batch_id", _uuid(), sa.ForeignKey("stamp_batches.id"), nullable=False),
        sa.Column("lot_size", sa.BigInteger(), nullable=False),
        sa.Column("code_letter", sa.String(2), nullable=False),
        sa.Column("sample_size", sa.Integer(), nullable=False),
        sa.Column("accept", sa.Integer(), nullable=False),
        sa.Column("reject", sa.Integer(), nullable=False),
        sa.Column("defectives", sa.Integer(), nullable=False),
        sa.Column("result", sa.String(8), nullable=False),
        sa.Column("inspector_sub", sa.String(256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("result IN ('PASS','FAIL')", name="ck_inspection_result"),
        sa.CheckConstraint("defectives >= 0 AND defectives <= sample_size", name="ck_inspection_def"),
    )
    op.create_index("ix_inspections_batch_id", "inspections", ["batch_id"])
    op.create_table(
        "verifications",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("stamp_id", _uuid(), sa.ForeignKey("stamps.id")),
        sa.Column("serial_presented", sa.String(64), nullable=False),
        sa.Column("verifier_id", sa.String(128), nullable=False, server_default=""),
        sa.Column("public_scan", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("outcome", sa.String(24), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        sa.Column("lat_micros", sa.BigInteger()),
        sa.Column("long_micros", sa.BigInteger()),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "outcome IN ('valid','already_verified','clone_suspect','unknown_serial','malformed_serial','not_active','void','expired')",
            name="ck_verification_outcome",
        ),
    )
    op.create_index("ix_verifications_stamp_id", "verifications", ["stamp_id"])
    op.create_index("ix_verifications_stamp_time", "verifications", ["stamp_id", "verified_at"])
    op.create_table(
        "idempotency_records",
        sa.Column("key", sa.String(128), primary_key=True),
        sa.Column("principal_sub", sa.String(256), primary_key=True),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("response_status", sa.Integer(), nullable=False),
        sa.Column("response_body", JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "outbox_messages",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("topic", sa.String(128), nullable=False),
        sa.Column("key", sa.String(128), nullable=False),
        sa.Column("envelope", JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_outbox_published_at", "outbox_messages", ["published_at"])
    op.create_table(
        "audit_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("hash", sa.String(64), nullable=False, unique=True),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("payload", JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "status_list_snapshots",
        sa.Column("purpose", sa.String(16), primary_key=True),
        sa.Column("version", sa.Integer(), primary_key=True),
        sa.Column("credential", JSONB, nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "processed_events",
        sa.Column("event_id", sa.String(128), primary_key=True),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=False),
    )

    _install_invariant_triggers()


def _install_invariant_triggers() -> None:
    # 1. Generic mutation rejection for append-only / immutable tables.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION reject_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'append-only violation: % on table % is rejected', TG_OP, TG_TABLE_NAME
                USING ERRCODE = 'raise_exception';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    for table in (
        "audit_events",        # hash-chained append-only audit
        "approvals",           # maker-checker decisions are immutable
        "payment_receipts",    # remittance evidence is immutable
        "journals",            # posted journals never change
        "ledger_entries",      # ledger legs never change (reversal = new journal)
        "idempotency_records", # idempotency evidence is immutable
        "processed_events",    # consumer dedupe evidence is immutable
        "inspections",         # inspection records are immutable
        "verifications",       # every attempt is audit substrate, never edited
    ):
        op.execute(
            f"""
            CREATE TRIGGER trg_{table}_append_only
            BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION reject_mutation();
            """
        )

    # 2. Double-entry balance: deferred constraint trigger evaluated at COMMIT.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION check_journal_balanced() RETURNS trigger AS $$
        DECLARE
            j uuid;
            d bigint;
            c bigint;
        BEGIN
            j := COALESCE(NEW.journal_id, OLD.journal_id);
            SELECT COALESCE(SUM(debit_kobo), 0), COALESCE(SUM(credit_kobo), 0)
              INTO d, c
              FROM ledger_entries
             WHERE journal_id = j;
            IF d <> c THEN
                RAISE EXCEPTION 'journal % is not balanced: debits % <> credits %', j, d, c
                    USING ERRCODE = 'integrity_constraint_violation';
            END IF;
            RETURN NULL;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE CONSTRAINT TRIGGER trg_journal_balanced
        AFTER INSERT OR UPDATE OR DELETE ON ledger_entries
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW EXECUTE FUNCTION check_journal_balanced();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_journal_balanced ON ledger_entries")
    op.execute("DROP FUNCTION IF EXISTS check_journal_balanced()")
    for table in (
        "audit_events", "approvals", "payment_receipts", "journals",
        "ledger_entries", "idempotency_records", "processed_events",
        "inspections", "verifications",
    ):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_append_only ON {table}")
    op.execute("DROP FUNCTION IF EXISTS reject_mutation()")
    for table in (
        "processed_events", "status_list_snapshots", "audit_events",
        "outbox_messages", "idempotency_records", "verifications",
        "inspections", "stamps", "stamp_batches", "serial_counters",
        "ledger_entries", "journals", "payment_receipts", "payment_intents",
        "approvals", "assessment_lines", "assessments", "declaration_lines",
        "declarations", "verifier_credentials", "principals",
    ):
        op.drop_table(table)
