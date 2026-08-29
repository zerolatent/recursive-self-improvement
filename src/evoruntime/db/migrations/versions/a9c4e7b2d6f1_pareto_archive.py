"""pareto_archive projection (Phase 4, H5)

Revision ID: a9c4e7b2d6f1
Revises: a4b7c2d9e1f3
Create Date: 2026-08-29

A rebuildable projection over the append-only core (proposal records x
evaluation attestations), in the `lineage_productivity` pattern: typed
slice columns (task_type, difficulty, safety_class) and typed attested
cost columns, so slice reporting and Pareto-frontier computation never
re-parse JSONB metric blobs on every query.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "a9c4e7b2d6f1"
down_revision: str | Sequence[str] | None = "a4b7c2d9e1f3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "pareto_archive",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("proposal_id", sa.String(), nullable=False),
        sa.Column("artifact_digest", sa.String(), nullable=False),
        sa.Column("parent_digest", sa.String(), nullable=True),
        sa.Column("strategy_id", sa.String(), nullable=False),
        sa.Column("campaign_id", sa.String(), nullable=True),
        sa.Column("attestation_id", sa.String(), nullable=False),
        sa.Column("outcome", sa.String(), nullable=False),
        sa.Column("task_type", sa.String(), nullable=True),
        sa.Column("difficulty", sa.String(), nullable=True),
        sa.Column("safety_class", sa.String(), nullable=True),
        sa.Column("tokens", sa.Float(), nullable=True),
        sa.Column("total_tokens", sa.Float(), nullable=True),
        sa.Column("mean_total_tokens", sa.Float(), nullable=True),
        sa.Column("cost_usd", sa.Float(), nullable=True),
        sa.Column("wall_clock_s", sa.Float(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint("outcome IN ('pass', 'fail')", name="ck_pareto_archive_outcome"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "proposal_id"],
            ["proposal_records.tenant_id", "proposal_records.proposal_id"],
            name="fk_pareto_archive_proposal",
        ),
        sa.ForeignKeyConstraint(
            ["attestation_id"],
            ["evaluation_attestations.attestation_id"],
            name="fk_pareto_archive_attestation",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "artifact_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_pareto_archive_artifact",
        ),
    )
    op.create_index(
        "ix_pareto_archive_tenant_campaign",
        "pareto_archive",
        ["tenant_id", "campaign_id"],
    )
    op.create_index(
        "ix_pareto_archive_tenant_artifact",
        "pareto_archive",
        ["tenant_id", "artifact_digest"],
    )


def downgrade() -> None:
    op.drop_index("ix_pareto_archive_tenant_artifact", table_name="pareto_archive")
    op.drop_index("ix_pareto_archive_tenant_campaign", table_name="pareto_archive")
    op.drop_table("pareto_archive")
