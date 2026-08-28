"""artifact registry (E1)

Revision ID: b7c41d92ea05
Revises: 314039145b57
Create Date: 2026-08-28

Deliverable E1: the PRD §9.2 five-record artifact registry —
artifact_content, proposal_records, evaluation_attestations,
artifact_status_events, release_manifests — plus the
`artifact_current_status` projection view.

All five tables get the same `BEFORE UPDATE OR DELETE` trigger D4 used for
lineage nodes: a record cannot be both content-addressed (or signed) and
mutable, and a trigger fires regardless of role — unlike a REVOKE, which
never applies to a table's owner or a superuser. Current status is a
projection (`artifact_current_status` view, DISTINCT ON the latest event per
artifact), never a stored column, so it can never drift into a digest.

The shared `evoruntime_forbid_mutation` function is created here with
CREATE OR REPLACE (idempotent alongside the lineage migration, which
defines the identical body) but is NOT dropped in this migration's
downgrade — the lineage triggers still reference it.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "b7c41d92ea05"
down_revision: str | Sequence[str] | None = "314039145b57"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_APPEND_ONLY_TABLES = (
    "artifact_content",
    "proposal_records",
    "evaluation_attestations",
    "artifact_status_events",
    "release_manifests",
)

_FORBID_MUTATION_FUNCTION = """
CREATE OR REPLACE FUNCTION evoruntime_forbid_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'append-only table "%" is immutable (attempted %)', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;
"""

_CURRENT_STATUS_VIEW = """
CREATE VIEW artifact_current_status AS
SELECT DISTINCT ON (tenant_id, artifact_digest)
    tenant_id,
    artifact_digest,
    kind AS current_status,
    actor_identity AS last_actor_identity,
    reason AS last_reason,
    created_at AS since,
    event_id AS last_event_id
FROM artifact_status_events
ORDER BY tenant_id, artifact_digest, created_at DESC, event_id DESC;
"""

_DROP_CURRENT_STATUS_VIEW = "DROP VIEW IF EXISTS artifact_current_status;"


def _trigger_name(table_name: str) -> str:
    return f"{table_name}_forbid_mutation"


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "artifact_content",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("artifact_id", sa.String(), nullable=False),
        sa.Column("digest", sa.String(), nullable=False),
        sa.Column("artifact_type", sa.String(), nullable=False),
        sa.Column("canonical_body_digest", sa.String(), nullable=False),
        sa.Column("dependencies", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("capability_requests", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("storage_uri", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "digest", name="uq_artifact_content_tenant_digest"),
        sa.UniqueConstraint(
            "tenant_id", "artifact_id", name="uq_artifact_content_tenant_artifact_id"
        ),
    )
    op.create_index(
        "ix_artifact_content_tenant_id", "artifact_content", ["tenant_id"], unique=False
    )
    op.create_table(
        "proposal_records",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("proposal_id", sa.String(), nullable=False),
        sa.Column("proposed_digest", sa.String(), nullable=False),
        sa.Column("parent_digest", sa.String(), nullable=True),
        sa.Column("strategy_id", sa.String(), nullable=False),
        sa.Column("campaign_id", sa.String(), nullable=True),
        sa.Column("proposal_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("proposal_id", name="uq_proposal_records_proposal_id"),
        sa.CheckConstraint(
            "parent_digest IS NULL OR parent_digest <> proposed_digest",
            name="ck_proposal_records_no_self_parent",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "proposed_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_proposal_records_proposed_artifact",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "parent_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_proposal_records_parent_artifact",
        ),
    )
    op.create_index("ix_proposal_records_tenant_id", "proposal_records", ["tenant_id"])
    op.create_index(
        "ix_proposal_records_proposed_digest",
        "proposal_records",
        ["tenant_id", "proposed_digest"],
    )
    op.create_table(
        "evaluation_attestations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("attestation_id", sa.String(), nullable=False),
        sa.Column("artifact_digest", sa.String(), nullable=False),
        sa.Column("evaluator_subject", sa.String(), nullable=False),
        sa.Column("outcome", sa.String(), nullable=False),
        sa.Column("result_metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("evaluation_payload_digest", sa.String(), nullable=False),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.Column("signer_public_key", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("attestation_id", name="uq_evaluation_attestations_attestation_id"),
        sa.CheckConstraint(
            "outcome IN ('pass', 'fail')", name="ck_evaluation_attestations_outcome"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "artifact_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_evaluation_attestations_artifact",
        ),
    )
    op.create_index(
        "ix_evaluation_attestations_tenant_artifact",
        "evaluation_attestations",
        ["tenant_id", "artifact_digest"],
    )
    op.create_table(
        "artifact_status_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("artifact_digest", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("actor_identity", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id", name="uq_artifact_status_events_event_id"),
        sa.CheckConstraint(
            "kind IN ('nominate', 'reject', 'revoke', 'expire', 'quarantine', 'supersede')",
            name="ck_artifact_status_events_kind",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "artifact_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_artifact_status_events_artifact",
        ),
    )
    op.create_index(
        "ix_artifact_status_events_tenant_artifact",
        "artifact_status_events",
        ["tenant_id", "artifact_digest"],
    )
    op.create_table(
        "release_manifests",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("manifest_id", sa.String(), nullable=False),
        sa.Column("manifest_digest", sa.String(), nullable=False),
        sa.Column("artifact_digests", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("adapter_versions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("model_routes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("policies", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("prior_release_digest", sa.String(), nullable=True),
        sa.Column("storage_uri", sa.String(), nullable=False),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.Column("signer_public_key", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("manifest_id", name="uq_release_manifests_manifest_id"),
        sa.UniqueConstraint(
            "tenant_id", "manifest_digest", name="uq_release_manifests_tenant_digest"
        ),
        sa.CheckConstraint(
            "prior_release_digest IS NULL OR prior_release_digest <> manifest_digest",
            name="ck_release_manifests_no_self_prior",
        ),
    )
    op.create_index("ix_release_manifests_tenant_id", "release_manifests", ["tenant_id"])

    # Append-only enforcement: a trigger, because it fires for every role
    # including the table owner and a superuser, unlike a REVOKE grant.
    # The function body is identical to the lineage migration's; CREATE OR
    # REPLACE keeps this migration independent of migration order. The
    # function is NOT dropped on downgrade — the lineage triggers still
    # reference it.
    op.execute(_FORBID_MUTATION_FUNCTION)
    for table_name in _APPEND_ONLY_TABLES:
        op.execute(
            f"""
            CREATE TRIGGER {_trigger_name(table_name)}
            BEFORE UPDATE OR DELETE ON {table_name}
            FOR EACH ROW EXECUTE FUNCTION evoruntime_forbid_mutation();
            """
        )

    # Current status is a projection over the append-only event stream.
    op.execute(_CURRENT_STATUS_VIEW)


def downgrade() -> None:
    """Downgrade schema."""
    op.execute(_DROP_CURRENT_STATUS_VIEW)

    for table_name in _APPEND_ONLY_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS {_trigger_name(table_name)} ON {table_name};")

    op.drop_index("ix_release_manifests_tenant_id", table_name="release_manifests")
    op.drop_table("release_manifests")
    op.drop_index("ix_artifact_status_events_tenant_artifact", table_name="artifact_status_events")
    op.drop_table("artifact_status_events")
    op.drop_index(
        "ix_evaluation_attestations_tenant_artifact", table_name="evaluation_attestations"
    )
    op.drop_table("evaluation_attestations")
    op.drop_index("ix_proposal_records_proposed_digest", table_name="proposal_records")
    op.drop_index("ix_proposal_records_tenant_id", table_name="proposal_records")
    op.drop_table("proposal_records")
    op.drop_index("ix_artifact_content_tenant_id", table_name="artifact_content")
    op.drop_table("artifact_content")
