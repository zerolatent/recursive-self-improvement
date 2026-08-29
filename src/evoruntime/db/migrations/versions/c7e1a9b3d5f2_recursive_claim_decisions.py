"""recursive_claim_decisions (H11 append-only claim ledger)

Revision ID: c7e1a9b3d5f2
Revises: a4b7c2d9e1f3
Create Date: 2026-08-29

Phase 4 deliverable H11: the append-only `recursive_claim_decisions`
table for the §12.6 claim-issuance operator path. One row per decision —
a label issued to a satisfied gate, or a refusal recorded when the
evidence does not back the claim. The refusal row is the point: a claim
the evidence does not back is not merely raised as an exception and
forgotten, it is recorded, so the operator path's refusals are as
auditable as its issuances.

The table gets the shared `evoruntime_forbid_mutation` trigger (created
with CREATE OR REPLACE, idempotent alongside the registry and canary
migrations, and NOT dropped in this downgrade — other tables' triggers
still reference it): a claim decision that could be edited after the
fact is not a decision, it is a wish.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "c7e1a9b3d5f2"
down_revision: str | Sequence[str] | None = "a9c4e7b2d6f1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_FORBID_MUTATION_FUNCTION = """
CREATE OR REPLACE FUNCTION evoruntime_forbid_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'append-only table "%" is immutable (attempted %)', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;
"""


def _trigger_name(table_name: str) -> str:
    return f"{table_name}_forbid_mutation"


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "recursive_claim_decisions",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("label", sa.String(), nullable=False),
        sa.Column("issued", sa.Boolean(), nullable=False),
        sa.Column("verdict_satisfied", sa.Boolean(), nullable=False),
        sa.Column("refusal_reason", sa.Text(), nullable=True),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("evidence_digest", sa.String(), nullable=False),
        sa.Column("campaign_id", sa.String(), nullable=True),
        sa.Column("generation1_release_digest", sa.String(), nullable=True),
        sa.Column("generation2_release_digest", sa.String(), nullable=True),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column(
            "decided_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "issued = (label = 'recursive improvement')", name="ck_claim_decisions_label"
        ),
    )
    op.create_index(
        "ix_claim_decisions_tenant_decided",
        "recursive_claim_decisions",
        ["tenant_id", "decided_at"],
        unique=False,
    )
    # Shared append-only guard: CREATE OR REPLACE keeps this idempotent
    # alongside the registry and canary migrations that define the
    # identical body.
    op.execute(_FORBID_MUTATION_FUNCTION)
    op.execute(
        f"CREATE TRIGGER {_trigger_name('recursive_claim_decisions')} "
        "BEFORE UPDATE OR DELETE ON recursive_claim_decisions "
        "FOR EACH ROW EXECUTE FUNCTION evoruntime_forbid_mutation();"
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute(
        f"DROP TRIGGER IF EXISTS {_trigger_name('recursive_claim_decisions')} "
        "ON recursive_claim_decisions;"
    )
    op.drop_index("ix_claim_decisions_tenant_decided", table_name="recursive_claim_decisions")
    op.drop_table("recursive_claim_decisions")
