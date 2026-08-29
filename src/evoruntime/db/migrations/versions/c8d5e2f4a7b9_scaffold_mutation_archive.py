"""scaffold_mutation_archive — rebuildable mutation-archive projection (G9)

Revision ID: c8d5e2f4a7b9
Revises: d9c3e7a1f5b8
Create Date: 2026-08-29

Phase 3 deliverable G9: the harness-mutator's mutation archive. A typed
projection over the append-only D4 core — `proposal_records` (whose
metadata carries each proposal's declared mutation class) joined to
`evaluation_attestations` on the proposed digest — in exactly the
`lineage_productivity` pattern (F9/FR-102): the mutation class lifted
from the proposal metadata into a typed column (the graduation policy's
read surface, G10) and the attested `fitness` metric lifted from JSONB.

Deliberately NOT append-only: the projection is derived evidence and can
be dropped and rebuilt (`MutationArchiveService.rebuild`); the D4 core
records it is built from keep their immutability triggers untouched. The
G9 deliverable introduces no new append-only table, so this migration
ships no trigger — the evidence tables' guards come from the migrations
that created them.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c8d5e2f4a7b9"
down_revision: str | Sequence[str] | None = "d9c3e7a1f5b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "scaffold_mutation_archive",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("proposal_id", sa.String(), nullable=False),
        sa.Column("artifact_digest", sa.String(), nullable=False),
        sa.Column("parent_digest", sa.String(), nullable=True),
        sa.Column("strategy_id", sa.String(), nullable=False),
        sa.Column("campaign_id", sa.String(), nullable=True),
        sa.Column("attestation_id", sa.String(), nullable=False),
        sa.Column("outcome", sa.String(), nullable=False),
        sa.Column("mutation_class", sa.String(), nullable=False),
        sa.Column("fitness", sa.Float(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "outcome IN ('pass', 'fail')", name="ck_scaffold_mutation_archive_outcome"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "proposal_id"],
            ["proposal_records.tenant_id", "proposal_records.proposal_id"],
            name="fk_scaffold_mutation_archive_proposal",
        ),
        sa.ForeignKeyConstraint(
            ["attestation_id"],
            ["evaluation_attestations.attestation_id"],
            name="fk_scaffold_mutation_archive_attestation",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "artifact_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_scaffold_mutation_archive_artifact",
        ),
    )
    op.create_index(
        "ix_scaffold_mutation_archive_tenant_artifact",
        "scaffold_mutation_archive",
        ["tenant_id", "artifact_digest"],
    )
    op.create_index(
        "ix_scaffold_mutation_archive_tenant_class",
        "scaffold_mutation_archive",
        ["tenant_id", "mutation_class"],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(
        "ix_scaffold_mutation_archive_tenant_class", table_name="scaffold_mutation_archive"
    )
    op.drop_index(
        "ix_scaffold_mutation_archive_tenant_artifact", table_name="scaffold_mutation_archive"
    )
    op.drop_table("scaffold_mutation_archive")
