"""ORM model for the Pareto archive projection (Phase 4, H5).

A *projection*, not a record: `pareto_archive` is derived, row for row,
from `proposal_records` joined to `evaluation_attestations` on the
proposed digest — exactly the `lineage_productivity` pattern (F9/FR-102),
extended with the slice annotations (H7's task_type/difficulty manifest
annotations plus the declared safety class) and the attested cost metrics
the slice reporting needs.

Deliberately NOT append-only: the append-only core (proposals,
attestations) is untouched and remains the evidence; this table can be
dropped and rebuilt from those records at any time, which is what
`ParetoArchiveService.rebuild` does and what `reconcile` verifies. The
Pareto frontier itself is *computed, never stored* — like the
productivity score, storing it would pin an unpinned dominance rule.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKeyConstraint,
    Index,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from evoruntime.db.base import Base


class ParetoArchiveProjection(Base):
    """One proposal × attestation pair with slice keys and attested costs
    lifted from JSONB into typed columns.

    Slice columns are NULL when the pair carries no annotation for that
    dimension; cost columns are NULL when that metric was not attested.
    Both nullabilities are load-bearing: a missing slice is "unknown
    slice membership", not the empty string, and a missing cost is
    "never attested", not zero.
    """

    __tablename__ = "pareto_archive"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    proposal_id: Mapped[str] = mapped_column(nullable=False)
    artifact_digest: Mapped[str] = mapped_column(nullable=False)
    parent_digest: Mapped[str | None] = mapped_column(nullable=True)
    strategy_id: Mapped[str] = mapped_column(nullable=False)
    campaign_id: Mapped[str | None] = mapped_column(nullable=True)
    attestation_id: Mapped[str] = mapped_column(nullable=False)
    outcome: Mapped[str] = mapped_column(nullable=False)
    #: Typed slice columns — one per member of the closed SLICE_DIMENSIONS
    #: vocabulary. NULL when the pair declares no value for the dimension.
    task_type: Mapped[str | None] = mapped_column(String, nullable=True)
    difficulty: Mapped[str | None] = mapped_column(String, nullable=True)
    safety_class: Mapped[str | None] = mapped_column(String, nullable=True)
    #: Typed cost columns — one per member of the closed COST_METRIC_KEYS
    #: vocabulary. NULL when that metric was not attested for the pair.
    tokens: Mapped[float | None] = mapped_column(Float, nullable=True)
    total_tokens: Mapped[float | None] = mapped_column(Float, nullable=True)
    mean_total_tokens: Mapped[float | None] = mapped_column(Float, nullable=True)
    cost_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
    wall_clock_s: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint("outcome IN ('pass', 'fail')", name="ck_pareto_archive_outcome"),
        ForeignKeyConstraint(
            ["tenant_id", "proposal_id"],
            ["proposal_records.tenant_id", "proposal_records.proposal_id"],
            name="fk_pareto_archive_proposal",
        ),
        ForeignKeyConstraint(
            ["attestation_id"],
            ["evaluation_attestations.attestation_id"],
            name="fk_pareto_archive_attestation",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "artifact_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_pareto_archive_artifact",
        ),
        Index("ix_pareto_archive_tenant_campaign", "tenant_id", "campaign_id"),
        Index("ix_pareto_archive_tenant_artifact", "tenant_id", "artifact_digest"),
    )
