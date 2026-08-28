"""memory entries (E6)

Revision ID: c4f19d8e72a3
Revises: b7c41d92ea05
Create Date: 2026-08-28

Deliverable E6: the `memory_entries` governance table for PRD §9.3
memory hygiene and FR-016 suggestion-first memory.

Deliberately NOT append-only, unlike the E1 registry tables: the entry's
content integrity is the immutable `artifact_content` row it references
(artifact_type `memory_entry`), and its lifecycle audit is the append-only
`artifact_status_events` stream — this row is the mutable projection of
current status plus the scope columns hygiene queries filter on, in the
same mutability class as `tombstones` and `dataset_partitions`.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "c4f19d8e72a3"
down_revision: str | Sequence[str] | None = "b7c41d92ea05"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "memory_entries",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("memory_id", sa.String(), nullable=False),
        sa.Column("artifact_digest", sa.String(), nullable=False),
        sa.Column("semantic_type", sa.String(), nullable=False),
        sa.Column("trust_domain", sa.String(), nullable=False),
        sa.Column("subject", sa.String(), nullable=False),
        sa.Column("environment", sa.String(), nullable=False),
        sa.Column("task_type", sa.String(), nullable=False),
        sa.Column("model_id", sa.String(), nullable=True),
        sa.Column("harness_id", sa.String(), nullable=True),
        sa.Column("claim_key", sa.String(), nullable=False),
        sa.Column("claim_statement", sa.String(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("sensitivity", sa.String(), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("status_reason", sa.String(), nullable=True),
        sa.Column("is_generalized_lesson", sa.Boolean(), nullable=False),
        sa.Column("parent_memory_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("supersedes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("retrieval_count", sa.Integer(), nullable=False),
        sa.Column("last_retrieved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("memory_id", name="uq_memory_entries_memory_id"),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1", name="ck_memory_entries_confidence_range"
        ),
        sa.CheckConstraint(
            "valid_until IS NULL OR valid_until > valid_from",
            name="ck_memory_entries_validity_window",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "artifact_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_memory_entries_artifact",
        ),
    )
    op.create_index("ix_memory_entries_tenant_status", "memory_entries", ["tenant_id", "status"])
    op.create_index("ix_memory_entries_tenant_claim", "memory_entries", ["tenant_id", "claim_key"])
    op.create_index(
        "ix_memory_entries_tenant_scope",
        "memory_entries",
        ["tenant_id", "subject", "environment", "task_type"],
    )
    op.create_index("ix_memory_entries_valid_until", "memory_entries", ["valid_until"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_memory_entries_valid_until", table_name="memory_entries")
    op.drop_index("ix_memory_entries_tenant_scope", table_name="memory_entries")
    op.drop_index("ix_memory_entries_tenant_claim", table_name="memory_entries")
    op.drop_index("ix_memory_entries_tenant_status", table_name="memory_entries")
    op.drop_table("memory_entries")
