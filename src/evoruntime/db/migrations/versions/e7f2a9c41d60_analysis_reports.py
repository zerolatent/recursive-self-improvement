"""analysis_reports (F3 static-analysis gate)

Revision ID: e7f2a9c41d60
Revises: c9d4e801a7b3
Create Date: 2026-08-28

Phase 2 deliverable F3: the append-only `analysis_reports` table for
static-analysis verdicts over candidates. A new record type, deliberately
not a new `kind` on `artifact_status_events` — that table's CHECK
constraint enumerates the six status-event kinds and an analysis verdict
is not an artifact status.

The table gets the shared `evoruntime_forbid_mutation` trigger (created
with CREATE OR REPLACE, idempotent alongside the registry migration, and
NOT dropped in this downgrade — other tables' triggers still reference
it), so a verdict that could be edited after the fact would vouch for an
analysis nobody ran. Tamper evidence lives in the row itself:
`verdict_digest` over the report's canonical JSON bytes plus an Ed25519
detached signature over those bytes.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "e7f2a9c41d60"
down_revision: str | Sequence[str] | None = "c9d4e801a7b3"
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
        "analysis_reports",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("report_id", sa.String(), nullable=False),
        sa.Column("campaign_id", sa.String(), nullable=True),
        sa.Column("candidate_digest", sa.String(), nullable=False),
        sa.Column("artifact_type", sa.String(), nullable=False),
        sa.Column("outcome", sa.String(), nullable=False),
        sa.Column("violations", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("verdict_digest", sa.String(), nullable=False),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.Column("signer_public_key", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("outcome IN ('pass', 'block')", name="ck_analysis_reports_outcome"),
        sa.UniqueConstraint(
            "tenant_id", "verdict_digest", name="uq_analysis_reports_tenant_verdict_digest"
        ),
    )
    op.create_index(
        "ix_analysis_reports_tenant_candidate",
        "analysis_reports",
        ["tenant_id", "candidate_digest"],
        unique=False,
    )
    op.create_index("ix_analysis_reports_report_id", "analysis_reports", ["report_id"], unique=True)
    # Shared append-only guard: CREATE OR REPLACE keeps this idempotent
    # alongside the registry migration that defines the identical body.
    op.execute(_FORBID_MUTATION_FUNCTION)
    op.execute(
        f"CREATE TRIGGER {_trigger_name('analysis_reports')} "
        "BEFORE UPDATE OR DELETE ON analysis_reports "
        "FOR EACH ROW EXECUTE FUNCTION evoruntime_forbid_mutation();"
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute(f"DROP TRIGGER IF EXISTS {_trigger_name('analysis_reports')} ON analysis_reports;")
    op.drop_index("ix_analysis_reports_report_id", table_name="analysis_reports")
    op.drop_index("ix_analysis_reports_tenant_candidate", table_name="analysis_reports")
    op.drop_table("analysis_reports")
