"""Maker-checker stamp voids (TS-8 remediation).

Raises stamp voiding to the same maker-checker bar as assessments: a void
request (excise-approver tier) must be approved by a DIFFERENT
excise-approver before the stamp's status and status-list bit flip.

- ``stamp_void_requests`` tracks request -> approval;
- a partial unique index guarantees at most one PENDING request per serial;
- a CHECK constraint makes self-approval impossible at the database level.

Revision ID: 0004_void_maker_checker
Revises: 0003_quarantine_resolution
Create Date: 2026-09-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004_void_maker_checker"
down_revision = "0003_quarantine_resolution"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "stamp_void_requests",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("serial", sa.String(32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("requested_by", sa.String(256), nullable=False),
        sa.Column("approved_by", sa.String(256), nullable=False, server_default=""),
        sa.Column("status", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "status IN ('PENDING','EXECUTED','REJECTED')", name="ck_void_request_status"
        ),
        sa.CheckConstraint(
            "approved_by = '' OR approved_by <> requested_by", name="ck_void_request_not_self"
        ),
    )
    op.create_index("ix_stamp_void_requests_serial", "stamp_void_requests", ["serial"])
    op.create_index(
        "uq_stamp_void_requests_pending",
        "stamp_void_requests",
        ["serial"],
        unique=True,
        postgresql_where=sa.text("status = 'PENDING'"),
    )


def downgrade() -> None:
    op.drop_index("uq_stamp_void_requests_pending", table_name="stamp_void_requests")
    op.drop_index("ix_stamp_void_requests_serial", table_name="stamp_void_requests")
    op.drop_table("stamp_void_requests")
