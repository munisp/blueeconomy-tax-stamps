"""Quarantine resolution (TS-5 remediation).

Adds ``supersedes_reference`` to payment_receipts: a controlled quarantine
resolution posts a NEW (superseding) receipt referencing the quarantined one
— the original receipt row stays immutable (trigger unchanged).

Revision ID: 0003_quarantine_resolution
Revises: 0002_zero_rated
Create Date: 2026-09-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_quarantine_resolution"
down_revision = "0002_zero_rated"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "payment_receipts",
        sa.Column("supersedes_reference", sa.String(128), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("payment_receipts", "supersedes_reference")
