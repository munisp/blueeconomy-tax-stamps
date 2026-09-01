"""Phase 11 performance audit: partial index for the outbox drain query.

The outbox publisher polls:
    WHERE published_at IS NULL ORDER BY created_at LIMIT <batch> FOR UPDATE SKIP LOCKED
The existing ix_outbox_published_at indexes a low-selectivity nullable column;
a partial index over created_at for unpublished rows matches the drain query
exactly and stays tiny (only unpublished rows are indexed).

Revision ID: 0005_perf_indexes
Revises: 0004_void_maker_checker
Create Date: 2026-09-01
"""

from __future__ import annotations

from alembic import op

revision = "0005_perf_indexes"
down_revision = "0004_void_maker_checker"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_outbox_unpublished_created "
        "ON outbox_messages (created_at) WHERE published_at IS NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_outbox_unpublished_created")
