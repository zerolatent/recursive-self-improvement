"""tenant policy refusal ledger

Revision ID: a7b3c9d4e2f1
Revises: f9c0de1a7e55
Create Date: 2026-08-29 09:20:00.000000

Deliverable G6 (research-tenant isolation). One append-only table:
`tenant_policy_refusals`, the durable record of every scaffold-mutation
boundary refusal (spec construction, campaign creation, candidate
registration, release activation, recursive-label gate).

The trigger is the point, exactly as for the holdout query ledger (D5):
an audit trail that the application layer alone protects is an audit
trail that any migration script, psql session, or future bug can quietly
rewrite. Enforcing append-only in the database means a refusal record can
be read by anyone with the right role and rewritten by nobody — including
this service.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

REFUSAL_GUARD_FUNCTION = """
CREATE OR REPLACE FUNCTION evoruntime_reject_refusal_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'tenant_policy_refusals is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;
"""

REFUSAL_GUARD_TRIGGER = """
CREATE TRIGGER trg_tenant_policy_refusals_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON tenant_policy_refusals
FOR EACH STATEMENT EXECUTE FUNCTION evoruntime_reject_refusal_mutation();
"""


# revision identifiers, used by Alembic.
revision: str = "a7b3c9d4e2f1"
down_revision: str | Sequence[str] | None = "f9c0de1a7e55"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "tenant_policy_refusals",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column(
            "boundary",
            sa.Enum(
                "spec_construction",
                "campaign_creation",
                "candidate_registration",
                "release_activation",
                "recursive_label",
                name="refusal_boundary",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("reason", sa.String(length=128), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_refusal_tenant_boundary",
        "tenant_policy_refusals",
        ["tenant_id", "boundary"],
        unique=False,
    )
    op.execute(REFUSAL_GUARD_FUNCTION)
    op.execute(REFUSAL_GUARD_TRIGGER)


def downgrade() -> None:
    """Downgrade schema."""
    op.execute(
        "DROP TRIGGER IF EXISTS trg_tenant_policy_refusals_append_only ON tenant_policy_refusals"
    )
    op.execute("DROP FUNCTION IF EXISTS evoruntime_reject_refusal_mutation()")
    op.drop_index("ix_refusal_tenant_boundary", table_name="tenant_policy_refusals")
    op.drop_table("tenant_policy_refusals")
    op.execute("DROP TYPE IF EXISTS refusal_boundary")
