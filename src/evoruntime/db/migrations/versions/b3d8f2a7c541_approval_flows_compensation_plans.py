"""approval flow tables + compensation_plans (F10)

Revision ID: b3d8f2a7c541
Revises: e7f2a9c41d60
Create Date: 2026-08-28

Phase 2 deliverable F10: the review-board record types.

- ``approval_requests`` — mutable by design: its ``status`` is a
  projection of the decisions beneath it.
- ``approval_decisions`` — append-only (shared
  ``evoruntime_forbid_mutation`` trigger): a decision that could be
  edited after the fact would vouch for a review nobody made.
- ``admission_records`` — append-only: the signed, read-only outcome of
  an admission (FR-022 privileged admission or tier-3 promotion).
- ``compensation_plans`` — append-only: the F5 record type's signed
  plan of compensating actions; F10 ships the record type and read
  paths, F5 the orchestrator hooks that execute plans.

The forbid-mutation function is CREATE OR REPLACE (idempotent alongside
the registry/analysis migrations) and NOT dropped in this downgrade —
other tables' triggers still reference it.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "b3d8f2a7c541"
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
    return f"{table_name}_forbid_mutation"


def _install_append_only_guard(table_name: str) -> None:
    """Attach the shared append-only guard to one table."""
    op.execute(_FORBID_MUTATION_FUNCTION)
    op.execute(
        f"CREATE TRIGGER {_trigger_name(table_name)} "
        "BEFORE UPDATE OR DELETE ON "  # noqa: S608 - table name is a literal
        f"{table_name} FOR EACH ROW EXECUTE FUNCTION evoruntime_forbid_mutation();"
    )


def _drop_append_only_guard(table_name: str) -> None:
    op.execute(f"DROP TRIGGER IF EXISTS {_trigger_name(table_name)} ON {table_name};")


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "approval_requests",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("request_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("campaign_id", sa.String(), nullable=True),
        sa.Column("proposal_id", sa.String(), nullable=True),
        sa.Column("plugin_id", sa.String(), nullable=True),
        sa.Column("content_digest", sa.String(), nullable=True),
        sa.Column("privileged_role", sa.String(), nullable=True),
        sa.Column("tier", sa.Integer(), nullable=False),
        sa.Column("justification", sa.String(), nullable=False),
        sa.Column("requested_by", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "kind IN ('privileged_admission', 'tier3_promotion')",
            name="ck_approval_requests_kind",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'admitted')",
            name="ck_approval_requests_status",
        ),
    )
    op.create_index(
        "ix_approval_requests_request_id", "approval_requests", ["request_id"], unique=True
    )
    op.create_index(
        "ix_approval_requests_tenant_campaign",
        "approval_requests",
        ["tenant_id", "campaign_id"],
        unique=False,
    )

    op.create_table(
        "approval_decisions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("decision_id", sa.String(), nullable=False),
        sa.Column("request_id", sa.String(), nullable=False),
        sa.Column("decision", sa.String(), nullable=False),
        sa.Column("approver", sa.String(), nullable=False),
        sa.Column("approver_role", sa.String(), nullable=False),
        sa.Column("note", sa.String(), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "decision IN ('approve', 'reject')", name="ck_approval_decisions_decision"
        ),
        sa.UniqueConstraint(
            "tenant_id", "request_id", "approver", name="uq_approval_decisions_request_approver"
        ),
    )
    op.create_index(
        "ix_approval_decisions_decision_id", "approval_decisions", ["decision_id"], unique=True
    )
    op.create_index(
        "ix_approval_decisions_tenant_request",
        "approval_decisions",
        ["tenant_id", "request_id"],
        unique=False,
    )
    _install_append_only_guard("approval_decisions")

    op.create_table(
        "admission_records",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("record_id", sa.String(), nullable=False),
        sa.Column("request_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("decision", sa.String(), nullable=False, server_default="admitted"),
        sa.Column("plugin_id", sa.String(), nullable=True),
        sa.Column("content_digest", sa.String(), nullable=True),
        sa.Column("privileged_role", sa.String(), nullable=True),
        sa.Column("proposal_digest", sa.String(), nullable=True),
        sa.Column("tier", sa.Integer(), nullable=True),
        sa.Column("requested_by", sa.String(), nullable=False),
        sa.Column("request_digest", sa.String(), nullable=True),
        sa.Column("approvals", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.Column("signer_public_key", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "kind IN ('privileged_admission', 'tier3_promotion')",
            name="ck_admission_records_kind",
        ),
    )
    op.create_index(
        "ix_admission_records_record_id", "admission_records", ["record_id"], unique=True
    )
    op.create_index(
        "ix_admission_records_tenant_request",
        "admission_records",
        ["tenant_id", "request_id"],
        unique=False,
    )
    _install_append_only_guard("admission_records")

    op.create_table(
        "compensation_plans",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("plan_id", sa.String(), nullable=False),
        sa.Column("campaign_id", sa.String(), nullable=True),
        sa.Column("manifest_digest", sa.String(), nullable=True),
        sa.Column("actions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("plan_digest", sa.String(), nullable=False),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.Column("signer_public_key", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_compensation_plans_plan_id", "compensation_plans", ["plan_id"], unique=True)
    op.create_index(
        "ix_compensation_plans_tenant_campaign",
        "compensation_plans",
        ["tenant_id", "campaign_id"],
        unique=False,
    )
    _install_append_only_guard("compensation_plans")


def downgrade() -> None:
    """Downgrade schema."""
    _drop_append_only_guard("compensation_plans")
    op.drop_index("ix_compensation_plans_tenant_campaign", table_name="compensation_plans")
    op.drop_index("ix_compensation_plans_plan_id", table_name="compensation_plans")
    op.drop_table("compensation_plans")

    _drop_append_only_guard("admission_records")
    op.drop_index("ix_admission_records_tenant_request", table_name="admission_records")
    op.drop_index("ix_admission_records_record_id", table_name="admission_records")
    op.drop_table("admission_records")

    _drop_append_only_guard("approval_decisions")
    op.drop_index("ix_approval_decisions_tenant_request", table_name="approval_decisions")
    op.drop_index("ix_approval_decisions_decision_id", table_name="approval_decisions")
    op.drop_table("approval_decisions")

    op.drop_index("ix_approval_requests_tenant_campaign", table_name="approval_requests")
    op.drop_index("ix_approval_requests_request_id", table_name="approval_requests")
    op.drop_table("approval_requests")
