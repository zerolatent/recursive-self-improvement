"""ORM models for the lineage store (deliverable D4).

Four tables, two different mutability contracts:

- `lineage_nodes` / `lineage_edges` are append-only. The migration that
  creates them (`db/migrations/versions/*_lineage_store.py`) attaches a
  `BEFORE UPDATE OR DELETE` trigger that raises on any attempted mutation —
  enforced in the database itself, not just at the ORM layer, so it holds
  even for a superuser connection or a hand-written `UPDATE` (PRD §8.2).
- `payloads` and `tombstones` are ordinary mutable tables: payload rows are
  hard-deleted when access is revoked (see `evoruntime.lineage.deletion`),
  and tombstone rows are updated in place as the deletion flow's SLO
  milestones (`access_revoked_at`, `purge_completed_at`) are reached.

`derived_data_records` is the fixture-shaped table the D4 acceptance
criteria call for: a generic pointer table standing in for the
embeddings/caches/search-index rows a real derived-data subsystem would
register against a payload digest, so the purge sweep has something
concrete to delete within the 24h SLO.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from evoruntime.db.base import Base


class LineageNode(Base):
    """A single provenance node: an artifact, trace, release, dataset
    partition, or any other entity the evolution/evaluation planes want to
    track ancestry for. `node_type` + `external_ref` locate the real entity;
    Phase 0 keeps this decoupled from other deliverables' tables (events,
    dataset partitions) rather than foreign-keying into them, since those
    land in sibling PRs.
    """

    __tablename__ = "lineage_nodes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    node_type: Mapped[str] = mapped_column(nullable=False)
    external_ref: Mapped[str] = mapped_column(nullable=False)
    node_metadata: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("ix_lineage_nodes_tenant_id", "tenant_id"),
        Index("ix_lineage_nodes_external_ref", "tenant_id", "external_ref"),
    )


class LineageEdge(Base):
    """A directed provenance edge between two nodes (e.g. "derived_from",
    "produced_by", "evaluated_by"). Append-only for the same reason nodes
    are: lineage is a historical record, not a mutable graph.
    """

    __tablename__ = "lineage_edges"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    source_node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("lineage_nodes.id"), nullable=False
    )
    target_node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("lineage_nodes.id"), nullable=False
    )
    edge_type: Mapped[str] = mapped_column(nullable=False)
    edge_metadata: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint("source_node_id <> target_node_id", name="ck_lineage_edges_no_self_loop"),
        Index("ix_lineage_edges_tenant_id", "tenant_id"),
        Index("ix_lineage_edges_source_node_id", "source_node_id"),
        Index("ix_lineage_edges_target_node_id", "target_node_id"),
    )


class Payload(Base):
    """Encrypted event/artifact payload content, stored separately from the
    envelope it belongs to (PRD §18.3, spec Data model section). Encrypted
    at rest with a per-tenant key (`evoruntime.lineage.crypto`) so a raw
    table or backup read never exposes plaintext.

    Unlike lineage nodes/edges, this table is NOT append-only: deletion
    requests hard-delete the row (see `evoruntime.lineage.deletion`), which
    is the "access revoked" step of the deletion flow. `payload_digest` is
    the plaintext content digest referenced by the trace event envelope's
    `payload_digest` field (D2); it is what tombstones and derived-data
    records key off of.
    """

    __tablename__ = "payloads"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    payload_digest: Mapped[str] = mapped_column(nullable=False)
    data_classification: Mapped[str] = mapped_column(nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(nullable=False)
    encryption_key_id: Mapped[str] = mapped_column(nullable=False)
    byte_size: Mapped[int] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "payload_digest", name="uq_payloads_tenant_digest"),
    )


class Tombstone(Base):
    """A deletion request and its progress through the deletion flow:
    requested -> access revoked (<=5min SLO) -> derived data purged
    (<=24h SLO). Mutable by design (progress columns are updated in place
    by the sweep functions in `evoruntime.lineage.purge`) — the immutable
    record of *what was requested* is the row's existence plus
    `requested_at`, not a constraint on updating it further.
    """

    __tablename__ = "tombstones"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    resource_type: Mapped[str] = mapped_column(nullable=False)
    resource_id: Mapped[str] = mapped_column(nullable=False)
    reason: Mapped[str | None] = mapped_column(nullable=True)
    requested_by: Mapped[str] = mapped_column(nullable=False)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    access_revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    purge_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Partial indexes on "pending" rows (access_revoked_at/purge_completed_at
    # IS NULL) would speed up the sweep queries in evoruntime.lineage.purge,
    # but referencing sibling columns from inside __table_args__ before the
    # class finishes mapping is unreliable; a plain composite index is
    # enough at Phase 0 volumes and can be replaced with a partial index in
    # a follow-up migration once sweep query plans are actually measured.
    __table_args__ = (
        Index("ix_tombstones_tenant_resource", "tenant_id", "resource_type", "resource_id"),
        Index("ix_tombstones_access_revoked_at", "access_revoked_at"),
        Index("ix_tombstones_purge_completed_at", "purge_completed_at"),
    )


class DerivedDataRecord(Base):
    """A pointer to derived data (an embedding, a cache entry, a search
    index row) computed from a payload. Purged by the 24h derived-purge
    sweep once the owning payload's access has been revoked. In Phase 0
    this table is exercised directly by tests as the "embeddings/caches"
    fixture the D4 acceptance criteria call for; a real embedding/cache
    subsystem in a later phase would insert rows here as it materializes
    derived data, and the purge sweep needs no knowledge of what `kind`
    means beyond "delete rows matching this resource_id".
    """

    __tablename__ = "derived_data_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    resource_id: Mapped[str] = mapped_column(nullable=False)
    kind: Mapped[str] = mapped_column(nullable=False)
    ref: Mapped[str] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (Index("ix_derived_data_records_tenant_resource", "tenant_id", "resource_id"),)
