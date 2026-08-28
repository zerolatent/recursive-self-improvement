"""ORM model for memory entries (deliverable E6, PRD §9.3).

One table, mutable by design — and that is a deliberate contrast with the
E1 registry tables it points at:

- The entry's *content* is the immutable, content-addressed
  `artifact_content` row (artifact_type `memory_entry`) the E1 registry
  stores; its integrity is the registry's digest guarantee, not this
  table's.
- The entry's *lifecycle audit* is the append-only
  `artifact_status_events` stream (quarantine/revoke/expire/supersede are
  already E1 status kinds) read through the `artifact_current_status`
  projection.
- What remains for this row is the *queryable governance state*: current
  status, the reason for it, scope columns conflict detection matches on,
  and observed retrieval utility. All of it changes over the entry's
  life, so the row is mutable like `tombstones` or `dataset_partitions` —
  the immutability that matters lives one join away.

`parent_memory_ids` is the generalized-lesson link (§9.3): lessons cite
the evidence entries they were distilled from, which is what lets
revocation propagate to derived lessons while leaving unrelated evidence
untouched.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKeyConstraint,
    Index,
    Integer,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from evoruntime.db.base import Base
from evoruntime.memory.schemas import MemoryStatus


def _string_enum(enum_type: type[StrEnum], name: str) -> Enum:
    """VARCHAR + CHECK rather than a native PostgreSQL ENUM, so adding a
    status later is a constraint change, not a type migration (same choice
    the dataset models made)."""
    return Enum(
        enum_type,
        name=name,
        native_enum=False,
        length=16,
        values_callable=lambda members: [member.value for member in members],
    )


class MemoryEntryRow(Base):
    """Governance row for one §9.3 memory entry."""

    __tablename__ = "memory_entries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    memory_id: Mapped[str] = mapped_column(nullable=False, unique=True)
    artifact_digest: Mapped[str] = mapped_column(nullable=False)
    """Digest of the immutable canonical body in `artifact_content`."""

    # §9.3 declared fields, flattened for querying. The authoritative copy
    # of the full declared body is the artifact's canonical bytes; these
    # columns exist so hygiene queries (conflict detection, TTL sweep,
    # scope routing) do not have to decrypt every payload to run.
    semantic_type: Mapped[str] = mapped_column(nullable=False)
    trust_domain: Mapped[str] = mapped_column(nullable=False)
    subject: Mapped[str] = mapped_column(nullable=False)
    environment: Mapped[str] = mapped_column(nullable=False)
    task_type: Mapped[str] = mapped_column(nullable=False)
    model_id: Mapped[str | None] = mapped_column(nullable=True)
    harness_id: Mapped[str | None] = mapped_column(nullable=True)
    claim_key: Mapped[str] = mapped_column(nullable=False)
    claim_statement: Mapped[str] = mapped_column(nullable=False)
    confidence: Mapped[float] = mapped_column(nullable=False)
    sensitivity: Mapped[str] = mapped_column(nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Lifecycle state (mutable; the audit trail is the registry's
    # append-only status events).
    status: Mapped[MemoryStatus] = mapped_column(
        _string_enum(MemoryStatus, "memory_status"), nullable=False
    )
    status_reason: Mapped[str | None] = mapped_column(nullable=True)

    is_generalized_lesson: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    parent_memory_ids: Mapped[list[object]] = mapped_column(JSONB, nullable=False, default=list)
    supersedes: Mapped[list[object]] = mapped_column(JSONB, nullable=False, default=list)

    # Observed retrieval utility (runtime state; the declared prior is in
    # the canonical body).
    retrieval_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_retrieved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1", name="ck_memory_entries_confidence_range"
        ),
        CheckConstraint(
            "valid_until IS NULL OR valid_until > valid_from",
            name="ck_memory_entries_validity_window",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "artifact_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_memory_entries_artifact",
        ),
        Index("ix_memory_entries_tenant_status", "tenant_id", "status"),
        Index("ix_memory_entries_tenant_claim", "tenant_id", "claim_key"),
        Index("ix_memory_entries_tenant_scope", "tenant_id", "subject", "environment", "task_type"),
        Index("ix_memory_entries_valid_until", "valid_until"),
    )
