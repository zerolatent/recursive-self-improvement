"""graduation decision ledger

Revision ID: d9c3e7a1f5b8
Revises: b5c7e2a9d4f1
Create Date: 2026-08-29 10:30:00.000000

Deliverable G10 (mutation-class graduation). One append-only table:
`graduation_decisions`, the durable record of every mutation-class
graduation decision — granted or refused. The acceptance criterion is
that graduation without a comparable-risk dossier is refused *by
recorded decision*, so refusals land here exactly like grants.

The trigger is the point, exactly as for the tenant-policy refusal
ledger (G6) and the holdout query ledger (D5): an audit trail that the
application layer alone protects is an audit trail that any migration
script, psql session, or future bug can quietly rewrite. Enforcing
append-only in the database means a graduation decision can be read by
anyone with the right role and rewritten by nobody — including this
service.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

GRADUATION_GUARD_FUNCTION = """
CREATE OR REPLACE FUNCTION evoruntime_reject_graduation_decision_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'graduation_decisions is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;
"""

GRADUATION_GUARD_TRIGGER = """
CREATE TRIGGER trg_graduation_decisions_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON graduation_decisions
FOR EACH STATEMENT EXECUTE FUNCTION evoruntime_reject_graduation_decision_mutation();
"""


# revision identifiers, used by Alembic.
revision: str = "d9c3e7a1f5b8"
down_revision: str | Sequence[str] | None = "b5c7e2a9d4f1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "graduation_decisions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("class_id", sa.String(length=128), nullable=False),
        sa.Column("dossier_digest", sa.String(length=96), nullable=True),
        sa.Column("granted", sa.Boolean(), nullable=False),
        sa.Column("refusal_reason", sa.String(length=64), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("candidate_resolved_tier", sa.Integer(), nullable=False),
        sa.Column("production_resolved_tier", sa.Integer(), nullable=True),
        sa.Column("signature", sa.LargeBinary(length=128), nullable=False),
        sa.Column("signer_public_key", sa.LargeBinary(length=64), nullable=False),
        sa.Column(
            "decided_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_graduation_tenant_class",
        "graduation_decisions",
        ["tenant_id", "class_id"],
        unique=False,
    )
    op.execute(GRADUATION_GUARD_FUNCTION)
    op.execute(GRADUATION_GUARD_TRIGGER)


def downgrade() -> None:
    """Downgrade schema."""
    op.execute(
        "DROP TRIGGER IF EXISTS trg_graduation_decisions_append_only ON graduation_decisions"
    )
    op.execute("DROP FUNCTION IF EXISTS evoruntime_reject_graduation_decision_mutation()")
    op.drop_index("ix_graduation_tenant_class", table_name="graduation_decisions")
    op.drop_table("graduation_decisions")
