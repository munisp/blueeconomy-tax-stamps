"""H3: admit invalid_credential and active verification outcomes.

The consumption gate (VC proof verified BEFORE consuming) records
``invalid_credential`` attempts; the non-consuming public pre-check records
``active``. Both must be admitted by ck_verification_outcome.

Revision ID: 0002_verification_outcomes_h3
Revises: 0001_initial
"""

from alembic import op

revision = "0002_verification_outcomes_h3"
down_revision = "0001_initial"
branch_labels = None
depends_on = None

_OUTCOMES = (
    "'valid', 'already_verified', 'clone_suspect', 'unknown_serial', "
    "'malformed_serial', 'not_active', 'void', 'expired', "
    "'invalid_credential', 'active'"
)
_OUTCOMES_V1 = (
    "'valid', 'already_verified', 'clone_suspect', 'unknown_serial', "
    "'malformed_serial', 'not_active', 'void', 'expired'"
)


def upgrade() -> None:
    op.drop_constraint("ck_verification_outcome", "verifications", type_="check")
    op.create_check_constraint(
        "ck_verification_outcome", "verifications", f"outcome IN ({_OUTCOMES})"
    )


def downgrade() -> None:
    op.drop_constraint("ck_verification_outcome", "verifications", type_="check")
    op.create_check_constraint(
        "ck_verification_outcome", "verifications", f"outcome IN ({_OUTCOMES_V1})"
    )
