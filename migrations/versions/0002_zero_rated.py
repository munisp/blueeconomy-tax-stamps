"""Zero-rated assessments (TS-2 remediation).

Zero-rated stamp categories (e.g. pharmaceuticals, HS ch. 30) carry no
federal excise but still require traceability stamps. The original
``expected_amount_kobo > 0`` invariant made zero-amount assessments
unreachable through the payment flow. This amendment:

- adds a ``zero_rated`` flag to assessments and payment intents;
- relaxes the intent amount invariant to ``>= 0`` and adds a
  zero-rated/category constraint: a zero expected amount is only legal on a
  zero-rated intent (and a zero assessment total only on a zero-rated
  assessment).

Revision ID: 0002_zero_rated
Revises: 0001_initial
Create Date: 2026-09-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_zero_rated"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assessments",
        sa.Column("zero_rated", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_check_constraint(
        "ck_assessment_zero_rated", "assessments", "total_duty_kobo > 0 OR zero_rated"
    )
    op.add_column(
        "payment_intents",
        sa.Column("zero_rated", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.drop_constraint("ck_intent_amount", "payment_intents")
    op.create_check_constraint(
        "ck_intent_amount", "payment_intents", "expected_amount_kobo >= 0"
    )
    op.create_check_constraint(
        "ck_intent_zero_rated", "payment_intents", "expected_amount_kobo > 0 OR zero_rated"
    )


def downgrade() -> None:
    op.drop_constraint("ck_intent_zero_rated", "payment_intents")
    op.drop_constraint("ck_intent_amount", "payment_intents")
    op.create_check_constraint(
        "ck_intent_amount", "payment_intents", "expected_amount_kobo > 0"
    )
    op.drop_column("payment_intents", "zero_rated")
    op.drop_constraint("ck_assessment_zero_rated", "assessments")
    op.drop_column("assessments", "zero_rated")
