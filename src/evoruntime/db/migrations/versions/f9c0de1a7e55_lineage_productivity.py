"""lineage_productivity — typed productivity projection (F9 / FR-102)

Revision ID: f9c0de1a7e55
Revises: 03e74a197808
Create Date: 2026-08-29

Phase 2 deliverable F9: productivity-aware lineage selection. A typed
projection over the append-only D4 core — `proposal_records` joined to
`evaluation_attestations` on the proposed digest — with the attestation's
cost metrics lifted from JSONB into typed columns (one per member of the
closed COST_METRIC_KEYS vocabulary).

Deliberately NOT append-only: the projection is derived evidence and can
be dropped and rebuilt (`LineageProductivityService.rebuild`); the D4 core
records it is built from keep their immutability triggers untouched.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f9c0de1a7e55"
down_revision: str | Sequence[str] | None = "03e74a197808"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "lineage_productivity",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("proposal_id", sa.String(), nullable=False),
        sa.Column("artifact_digest", sa.String(), nullable=False),
        sa.Column("parent_digest", sa.String(), nullable=True),
        sa.Column("strategy_id", sa.String(), nullable=False),
        sa.Column("campaign_id", sa.String(), nullable=True),
        sa.Column("attestation_id", sa.String(), nullable=False),
        sa.Column("outcome", sa.String(), nullable=False),
        sa.Column("tokens", sa.Float(), nullable=True),
        sa.Column("total_tokens", sa.Float(), nullable=True),
        sa.Column("mean_total_tokens", sa.Float(), nullable=True),
        sa.Column("cost_usd", sa.Float(), nullable=True),
        sa.Column("wall_clock_s", sa.Float(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("outcome IN ('pass', 'fail')", name="ck_lineage_productivity_outcome"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "proposal_id"],
            ["proposal_records.tenant_id", "proposal_records.proposal_id"],
            name="fk_lineage_productivity_proposal",
        ),
        sa.ForeignKeyConstraint(
            ["attestation_id"],
            ["evaluation_attestations.attestation_id"],
            name="fk_lineage_productivity_attestation",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "artifact_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_lineage_productivity_artifact",
        ),
    )
    op.create_index(
        "ix_lineage_productivity_tenant_artifact",
        "lineage_productivity",
        ["tenant_id", "artifact_digest"],
    )
    op.create_index(
        "ix_lineage_productivity_tenant_proposal",
        "lineage_productivity",
        ["tenant_id", "proposal_id"],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_lineage_productivity_tenant_proposal", table_name="lineage_productivity")
    op.drop_index("ix_lineage_productivity_tenant_artifact", table_name="lineage_productivity")
    op.drop_table("lineage_productivity")
