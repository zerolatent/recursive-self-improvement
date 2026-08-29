"""canary_runs (H6 canary monitoring service)

Revision ID: a4b7c2d9e1f3
Revises: e1a2b3c4d5e6
Create Date: 2026-08-29

Phase 4 deliverable H6: the append-only `canary_runs` table for the
canary monitoring service. One row per fixed-horizon canary run; the
harness's FR-012 measurements (paired tasks, realized allocation, digest
coverage, p99 convergence, guardrail events) are stored verbatim as
JSONB. A new record type, deliberately not a new `kind` on
`release_activations` — that ledger records what the control plane did
with the pointer, and a canary run is what the harness measured.

The table gets the shared `evoruntime_forbid_mutation` trigger (created
with CREATE OR REPLACE, idempotent alongside the registry migration, and
NOT dropped in this downgrade — other tables' triggers still reference
it): a run whose numbers could be edited after the fact would vouch for
a canary nobody ran.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "a4b7c2d9e1f3"
down_revision: str | Sequence[str] | None = "e1a2b3c4d5e6"
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
        "canary_runs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("manifest_digest", sa.String(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("outcome", sa.String(), nullable=False),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("result", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("started_by", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "outcome IN ('completed', 'rolled_back')", name="ck_canary_runs_outcome"
        ),
        sa.UniqueConstraint("tenant_id", "run_id", name="uq_canary_runs_tenant_run_id"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "manifest_digest"],
            ["release_manifests.tenant_id", "release_manifests.manifest_digest"],
            name="fk_canary_runs_manifest",
        ),
    )
    op.create_index(
        "ix_canary_runs_tenant_manifest",
        "canary_runs",
        ["tenant_id", "manifest_digest"],
        unique=False,
    )
    op.create_index("ix_canary_runs_run_id", "canary_runs", ["run_id"], unique=True)
    # Shared append-only guard: CREATE OR REPLACE keeps this idempotent
    # alongside the registry migration that defines the identical body.
    op.execute(_FORBID_MUTATION_FUNCTION)
    op.execute(
        f"CREATE TRIGGER {_trigger_name('canary_runs')} "
        "BEFORE UPDATE OR DELETE ON canary_runs "
        "FOR EACH ROW EXECUTE FUNCTION evoruntime_forbid_mutation();"
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute(f"DROP TRIGGER IF EXISTS {_trigger_name('canary_runs')} ON canary_runs;")
    op.drop_index("ix_canary_runs_run_id", table_name="canary_runs")
    op.drop_index("ix_canary_runs_tenant_manifest", table_name="canary_runs")
    op.drop_table("canary_runs")
