"""proposal_members — composite proposal member set (F4)

Revision ID: d5e6f7a8b9c0
Revises: c9d4e801a7b3
Create Date: 2026-08-28

Phase 2 deliverable F4: multi-artifact composite proposals. A composite
proposal is an ordered tuple of typed members; the composite digest (stored
on the `proposal_records` row as `proposed_digest`) is the digest over that
ordered member set. This table carries the member set the digest binds, so
the single-digest single-parent shape of `proposal_records` loses no
information: each member row records its own `parent_digest`, and the
composite's parent set is the union across members (multi-parent lineage
edges, one row per member).

The table is append-only under the same `evoruntime_forbid_mutation`
trigger D4 used by the other registry records — the composite digest is
only meaningful if the member rows cannot be edited after the fact.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "d5e6f7a8b9c0"
down_revision: str | Sequence[str] | None = "e7f2a9c41d60"
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
    return f"trg_{table_name}_forbid_mutation"


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "proposal_members",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("proposal_id", sa.String(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("artifact_type", sa.String(), nullable=False),
        sa.Column("member_digest", sa.String(), nullable=False),
        sa.Column("parent_digest", sa.String(), nullable=True),
        sa.Column("patch", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("declared_executables", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("position >= 0", name="ck_proposal_members_position_nonnegative"),
        sa.CheckConstraint(
            "parent_digest IS NULL OR parent_digest <> member_digest",
            name="ck_proposal_members_no_self_parent",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "proposal_id"],
            ["proposal_records.tenant_id", "proposal_records.proposal_id"],
            name="fk_proposal_members_proposal",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "member_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_proposal_members_member_artifact",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "parent_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_proposal_members_parent_artifact",
        ),
        sa.UniqueConstraint(
            "tenant_id", "proposal_id", "position", name="uq_proposal_members_position"
        ),
    )
    op.create_index("ix_proposal_members_tenant_id", "proposal_members", ["tenant_id"])
    op.create_index(
        "ix_proposal_members_member_digest",
        "proposal_members",
        ["tenant_id", "member_digest"],
    )
    op.create_index(
        "ix_proposal_members_proposal_id",
        "proposal_members",
        ["tenant_id", "proposal_id"],
    )

    # Append-only enforcement, same trigger D4 as the other registry
    # records. The function body is identical to the registry migration's;
    # CREATE OR REPLACE keeps this migration independent of migration
    # order. The function is NOT dropped on downgrade — the other
    # append-only triggers still reference it.
    op.execute(_FORBID_MUTATION_FUNCTION)
    op.execute(
        f"""
        CREATE TRIGGER {_trigger_name("proposal_members")}
        BEFORE UPDATE OR DELETE ON proposal_members
        FOR EACH ROW EXECUTE FUNCTION evoruntime_forbid_mutation();
        """
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute(f"DROP TRIGGER IF EXISTS {_trigger_name('proposal_members')} ON proposal_members;")
    op.drop_index("ix_proposal_members_proposal_id", table_name="proposal_members")
    op.drop_index("ix_proposal_members_member_digest", table_name="proposal_members")
    op.drop_index("ix_proposal_members_tenant_id", table_name="proposal_members")
    op.drop_table("proposal_members")
