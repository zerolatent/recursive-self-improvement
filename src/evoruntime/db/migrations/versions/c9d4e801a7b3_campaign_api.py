"""campaign/lineage API control-plane tables (E9, FR-014)

Revision ID: c9d4e801a7b3
Revises: b7c41d92ea05
Create Date: 2026-08-28

Deliverable E9: the FR-014 control-plane records the campaign API and
dashboard serve — campaigns, campaign_transitions, agent_registrations,
release_activations, evidence_bundles.

`campaign_transitions` gets the same `BEFORE UPDATE OR DELETE` trigger the
registry migration installs on the E1 tables: a campaign whose transition
history could be edited is not reconstructible, and a trigger fires
regardless of role. The other tables are mutable by design (phase is a
projection; activations are a ledger of states) except `evidence_bundles`,
whose rows are immutable once written — evidence that could be edited after
the fact is not evidence.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "c9d4e801a7b3"
down_revision: str | Sequence[str] | None = "b7c41d92ea05"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_APPEND_ONLY_TABLES = ("campaign_transitions", "evidence_bundles")

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


def _install_append_only_triggers() -> None:
    for table_name in _APPEND_ONLY_TABLES:
        op.execute(
            f"CREATE TRIGGER {_trigger_name(table_name)} "
            f"BEFORE UPDATE OR DELETE ON {table_name} "
            "FOR EACH ROW EXECUTE FUNCTION evoruntime_forbid_mutation();"
        )


def _drop_append_only_triggers() -> None:
    for table_name in _APPEND_ONLY_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS {_trigger_name(table_name)} ON {table_name};")


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(_FORBID_MUTATION_FUNCTION)

    op.create_table(
        "campaigns",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("campaign_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("spec_digest", sa.String(), nullable=False),
        sa.Column("spec_canonical", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("spec_signature", sa.LargeBinary(), nullable=False),
        sa.Column("signer_public_key", sa.LargeBinary(), nullable=False),
        sa.Column("phase", sa.String(), nullable=False),
        sa.Column("resume_target", sa.String(), nullable=True),
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
        sa.UniqueConstraint("tenant_id", "campaign_id", name="uq_campaigns_tenant_campaign_id"),
    )
    op.create_index("ix_campaigns_tenant_id", "campaigns", ["tenant_id"], unique=False)

    op.create_table(
        "campaign_transitions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("campaign_id", sa.String(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("from_phase", sa.String(), nullable=False),
        sa.Column("to_phase", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "campaign_id", "sequence", name="uq_campaign_transitions_sequence"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "campaign_id"],
            ["campaigns.tenant_id", "campaigns.campaign_id"],
            name="fk_campaign_transitions_campaign",
        ),
    )
    op.create_index(
        "ix_campaign_transitions_tenant_campaign",
        "campaign_transitions",
        ["tenant_id", "campaign_id"],
        unique=False,
    )

    op.create_table(
        "agent_registrations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("plugin_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("pinned_image", sa.String(), nullable=False),
        sa.Column("artifact_types", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("registered_by", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "agent_id", name="uq_agent_registrations_tenant_agent_id"),
        sa.CheckConstraint("kind IN ('strategy', 'adapter')", name="ck_agent_registrations_kind"),
    )
    op.create_index(
        "ix_agent_registrations_tenant_id", "agent_registrations", ["tenant_id"], unique=False
    )

    op.create_table(
        "release_activations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("manifest_digest", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("prior_manifest_digest", sa.String(), nullable=True),
        sa.Column("activated_by", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "status IN ('canary', 'active', 'rolled_back', 'superseded')",
            name="ck_release_activations_status",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "manifest_digest"],
            ["release_manifests.tenant_id", "release_manifests.manifest_digest"],
            name="fk_release_activations_manifest",
        ),
    )
    op.create_index(
        "ix_release_activations_tenant_manifest",
        "release_activations",
        ["tenant_id", "manifest_digest"],
        unique=False,
    )

    op.create_table(
        "evidence_bundles",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("bundle_id", sa.String(), nullable=False),
        sa.Column("campaign_id", sa.String(), nullable=True),
        sa.Column("artifact_digest", sa.String(), nullable=True),
        sa.Column("redacted_items", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "bundle_id", name="uq_evidence_bundles_tenant_bundle_id"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "artifact_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_evidence_bundles_artifact",
        ),
    )
    op.create_index(
        "ix_evidence_bundles_tenant_campaign",
        "evidence_bundles",
        ["tenant_id", "campaign_id"],
        unique=False,
    )

    _install_append_only_triggers()


def downgrade() -> None:
    """Downgrade schema."""
    _drop_append_only_triggers()
    op.drop_table("evidence_bundles")
    op.drop_table("release_activations")
    op.drop_table("agent_registrations")
    op.drop_table("campaign_transitions")
    op.drop_index("ix_campaigns_tenant_id", table_name="campaigns")
    op.drop_table("campaigns")
