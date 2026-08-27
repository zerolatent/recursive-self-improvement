"""ORM models for dataset partitions, sealed holdout handles, and the query ledger.

Three invariants are enforced here in the database rather than only in
Python, because the service layer is not the only thing that will ever
hold a connection:

1. A holdout partition may only carry the evaluation-plane storage
   identity (`ck_partition_holdout_storage_identity`).
2. Alpha spend can never exceed the declared budget
   (`ck_handle_alpha_within_budget`).
3. The query ledger is append-only — enforced by a trigger installed in
   the migration, so `UPDATE`/`DELETE` fail even for a direct psql session.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from evoruntime.core.identity import Role, StorageIdentity
from evoruntime.core.ids import new_id
from evoruntime.datasets.errors import DenialReason
from evoruntime.datasets.partitions import PartitionKind
from evoruntime.db.base import Base

ALPHA_PRECISION = Numeric(12, 6)
"""Alpha budgets are exact decimals — float drift must never grant a free query."""


def _string_enum(enum_type: type[StrEnum], name: str) -> Enum:
    """Map a `StrEnum` to a checked VARCHAR column.

    Non-native (VARCHAR + CHECK) rather than a PostgreSQL ENUM type:
    adding a partition kind or denial reason later becomes an ordinary
    constraint change instead of a type migration, and downgrade stays
    clean because there is no orphan type to drop.
    """
    return Enum(
        enum_type,
        name=name,
        native_enum=False,
        length=32,
        values_callable=lambda members: [member.value for member in members],
    )


class LedgerOutcome(StrEnum):
    """Whether a ledger row records a successful resolution or a refusal."""

    GRANTED = "granted"
    DENIED = "denied"


class DatasetPartition(Base):
    """One partition of a dataset (PRD §12.2).

    Content itself lives in object storage under `content_locator`; this
    row is the governance record that says who owns it, which storage
    identity holds it, and what it currently contains.
    """

    __tablename__ = "dataset_partitions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("dsp"))
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    dataset_id: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[PartitionKind] = mapped_column(
        _string_enum(PartitionKind, "partition_kind"), nullable=False
    )
    storage_identity: Mapped[StorageIdentity] = mapped_column(
        _string_enum(StorageIdentity, "storage_identity"), nullable=False
    )
    owner: Mapped[str] = mapped_column(String(128), nullable=False)
    content_locator: Mapped[str] = mapped_column(String(512), nullable=False)
    content_digest: Mapped[str] = mapped_column(String(128), nullable=False)
    item_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    handles: Mapped[list[HoldoutHandle]] = relationship(
        back_populates="partition", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "dataset_id", "kind", "name", name="uq_partition_tenant_dataset_kind_name"
        ),
        CheckConstraint(
            f"kind <> '{PartitionKind.HOLDOUT.value}'"
            f" OR storage_identity = '{StorageIdentity.EVALUATION_PLANE.value}'",
            name="ck_partition_holdout_storage_identity",
        ),
        Index("ix_partition_tenant_dataset", "tenant_id", "dataset_id"),
    )


class HoldoutHandle(Base):
    """An opaque, rotatable capability pointing at a sealed partition.

    Only the SHA-256 digest of the token is stored. A database dump
    therefore yields no usable handles, and rotation is a digest swap that
    never touches `DatasetPartition.content_locator` — the content does
    not move when the token changes.
    """

    __tablename__ = "holdout_handles"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("hho"))
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    partition_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("dataset_partitions.id", ondelete="CASCADE"), nullable=False
    )
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    token_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    owner: Mapped[str] = mapped_column(String(128), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    freshness_window_days: Mapped[int] = mapped_column(Integer, nullable=False)
    rotation_plan: Mapped[str] = mapped_column(String(512), nullable=False)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rotation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    contamination_audit: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    alpha_budget_total: Mapped[Decimal] = mapped_column(ALPHA_PRECISION, nullable=False)
    alpha_spent: Mapped[Decimal] = mapped_column(
        ALPHA_PRECISION, nullable=False, default=Decimal("0")
    )
    alpha_per_query: Mapped[Decimal] = mapped_column(ALPHA_PRECISION, nullable=False)

    partition: Mapped[DatasetPartition] = relationship(back_populates="handles")

    __table_args__ = (
        CheckConstraint("alpha_spent <= alpha_budget_total", name="ck_handle_alpha_within_budget"),
        CheckConstraint("alpha_budget_total >= 0 AND alpha_per_query > 0", name="ck_handle_alpha_positive"),
        Index("ix_handle_partition", "partition_id"),
    )

    @property
    def alpha_remaining(self) -> Decimal:
        """Statistical budget left before this holdout stops being trustworthy."""
        return self.alpha_budget_total - self.alpha_spent


class HoldoutQueryLedgerEntry(Base):
    """One append-only record of an attempt to resolve a holdout handle.

    Both grants and denials are recorded: the ledger is the contamination
    audit trail *and* the IAM-denial evidence. Rows are immutable — the
    migration installs a trigger that raises on `UPDATE`/`DELETE`.
    """

    __tablename__ = "holdout_query_ledger"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("hql"))
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    handle_id: Mapped[str] = mapped_column(String(64), nullable=False)
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    partition_id: Mapped[str] = mapped_column(String(64), nullable=False)

    caller_identity: Mapped[str] = mapped_column(String(128), nullable=False)
    caller_role: Mapped[Role] = mapped_column(_string_enum(Role, "caller_role"), nullable=False)
    purpose: Mapped[str] = mapped_column(String(512), nullable=False)

    outcome: Mapped[LedgerOutcome] = mapped_column(
        _string_enum(LedgerOutcome, "ledger_outcome"), nullable=False
    )
    denial_reason: Mapped[DenialReason | None] = mapped_column(
        _string_enum(DenialReason, "denial_reason"), nullable=True
    )

    alpha_spent: Mapped[Decimal] = mapped_column(ALPHA_PRECISION, nullable=False)
    alpha_remaining: Mapped[Decimal] = mapped_column(ALPHA_PRECISION, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            f"(outcome = '{LedgerOutcome.GRANTED.value}' AND denial_reason IS NULL)"
            f" OR (outcome = '{LedgerOutcome.DENIED.value}' AND denial_reason IS NOT NULL)",
            name="ck_ledger_denial_reason_matches_outcome",
        ),
        Index("ix_ledger_handle_occurred", "handle_id", "occurred_at"),
        Index("ix_ledger_caller", "tenant_id", "caller_identity"),
    )
