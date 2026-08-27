"""lineage store

Revision ID: 8eb27341f4e1
Revises: a2f61fcdb399
Create Date: 2026-08-27 20:32:33.803819

Deliverable D4: lineage_nodes, lineage_edges, payloads, tombstones, and the
derived_data_records fixture table (spec: Data model / storage layout,
Verification D4 row).

`lineage_nodes` and `lineage_edges` get a `BEFORE UPDATE OR DELETE` trigger
that unconditionally raises. This is deliberately a trigger, not a
`REVOKE`: the acceptance test connects as the same role that owns the
tables (mirroring CI's `postgres` superuser), and `GRANT`/`REVOKE` checks
never apply to a table's owner or a superuser — only a trigger fires
regardless of role. `payloads` and `tombstones` are ordinary mutable
tables; the deletion flow updates/deletes rows in them directly.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "8eb27341f4e1"
down_revision: str | Sequence[str] | None = "a2f61fcdb399"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_APPEND_ONLY_TABLES = ("lineage_nodes", "lineage_edges")

_FORBID_MUTATION_FUNCTION = """
CREATE OR REPLACE FUNCTION evoruntime_forbid_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'append-only table "%" is immutable (attempted %)', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;
"""

_DROP_FORBID_MUTATION_FUNCTION = "DROP FUNCTION IF EXISTS evoruntime_forbid_mutation();"


def _trigger_name(table_name: str) -> str:
    return f"{table_name}_forbid_mutation"


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "derived_data_records",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("resource_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("ref", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_derived_data_records_tenant_resource",
        "derived_data_records",
        ["tenant_id", "resource_id"],
        unique=False,
    )
    op.create_table(
        "lineage_nodes",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("node_type", sa.String(), nullable=False),
        sa.Column("external_ref", sa.String(), nullable=False),
        sa.Column("node_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_lineage_nodes_external_ref",
        "lineage_nodes",
        ["tenant_id", "external_ref"],
        unique=False,
    )
    op.create_index("ix_lineage_nodes_tenant_id", "lineage_nodes", ["tenant_id"], unique=False)
    op.create_table(
        "payloads",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("payload_digest", sa.String(), nullable=False),
        sa.Column("data_classification", sa.String(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("encryption_key_id", sa.String(), nullable=False),
        sa.Column("byte_size", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "payload_digest", name="uq_payloads_tenant_digest"),
    )
    op.create_table(
        "tombstones",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("resource_type", sa.String(), nullable=False),
        sa.Column("resource_id", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=True),
        sa.Column("requested_by", sa.String(), nullable=False),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("access_revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("purge_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_tombstones_access_revoked_at", "tombstones", ["access_revoked_at"], unique=False
    )
    op.create_index(
        "ix_tombstones_purge_completed_at", "tombstones", ["purge_completed_at"], unique=False
    )
    op.create_index(
        "ix_tombstones_tenant_resource",
        "tombstones",
        ["tenant_id", "resource_type", "resource_id"],
        unique=False,
    )
    op.create_table(
        "lineage_edges",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("source_node_id", sa.UUID(), nullable=False),
        sa.Column("target_node_id", sa.UUID(), nullable=False),
        sa.Column("edge_type", sa.String(), nullable=False),
        sa.Column("edge_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "source_node_id <> target_node_id", name="ck_lineage_edges_no_self_loop"
        ),
        sa.ForeignKeyConstraint(["source_node_id"], ["lineage_nodes.id"]),
        sa.ForeignKeyConstraint(["target_node_id"], ["lineage_nodes.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_lineage_edges_source_node_id", "lineage_edges", ["source_node_id"], unique=False
    )
    op.create_index(
        "ix_lineage_edges_target_node_id", "lineage_edges", ["target_node_id"], unique=False
    )
    op.create_index("ix_lineage_edges_tenant_id", "lineage_edges", ["tenant_id"], unique=False)

    # Append-only enforcement: a trigger, because it fires for every role
    # including the table owner and a superuser, unlike a REVOKE grant.
    op.execute(_FORBID_MUTATION_FUNCTION)
    for table_name in _APPEND_ONLY_TABLES:
        op.execute(
            f"""
            CREATE TRIGGER {_trigger_name(table_name)}
            BEFORE UPDATE OR DELETE ON {table_name}
            FOR EACH ROW EXECUTE FUNCTION evoruntime_forbid_mutation();
            """
        )


def downgrade() -> None:
    """Downgrade schema."""
    for table_name in _APPEND_ONLY_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS {_trigger_name(table_name)} ON {table_name};")
    op.execute(_DROP_FORBID_MUTATION_FUNCTION)

    op.drop_index("ix_lineage_edges_tenant_id", table_name="lineage_edges")
    op.drop_index("ix_lineage_edges_target_node_id", table_name="lineage_edges")
    op.drop_index("ix_lineage_edges_source_node_id", table_name="lineage_edges")
    op.drop_table("lineage_edges")
    op.drop_index("ix_tombstones_tenant_resource", table_name="tombstones")
    op.drop_index("ix_tombstones_purge_completed_at", table_name="tombstones")
    op.drop_index("ix_tombstones_access_revoked_at", table_name="tombstones")
    op.drop_table("tombstones")
    op.drop_table("payloads")
    op.drop_index("ix_lineage_nodes_tenant_id", table_name="lineage_nodes")
    op.drop_index("ix_lineage_nodes_external_ref", table_name="lineage_nodes")
    op.drop_table("lineage_nodes")
    op.drop_index("ix_derived_data_records_tenant_resource", table_name="derived_data_records")
    op.drop_table("derived_data_records")
