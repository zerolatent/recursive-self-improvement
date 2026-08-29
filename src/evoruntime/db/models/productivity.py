"""ORM model for the lineage-productivity projection (Phase 2, F9 / FR-102).

A *projection*, not a record: `lineage_productivity` is derived, row for
row, from `proposal_records` joined to `evaluation_attestations` on the
proposed digest. It exists so the selection plane can rank candidates by
attested cost without re-parsing JSONB metric blobs on every query — the
cost metrics get typed columns instead.

Deliberately NOT append-only: the D4 append-only core (proposals,
attestations, lineage nodes/edges) is untouched and remains the evidence;
this table can be dropped and rebuilt from those records at any time,
which is exactly what `LineageProductivityService.rebuild` does and what
`reconcile` verifies. A projection that claimed immutability would just be
a second, weaker copy of the evidence.
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
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from evoruntime.db.base import Base


class LineageProductivityProjection(Base):
    """One proposal × attestation pair, with the attestation's cost metrics
    lifted from JSONB into typed columns.

    `productivity_score` itself is *not* stored: it is
    `selection_score / normalized cost`, and both inputs are preregistered
    (the rule pins the metric and normalization at spec time). Storing a
    score computed under an unpinned normalization would be the post-hoc
    move FR-102 exists to prevent.
    """

    __tablename__ = "lineage_productivity"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    proposal_id: Mapped[str] = mapped_column(nullable=False)
    artifact_digest: Mapped[str] = mapped_column(nullable=False)
    parent_digest: Mapped[str | None] = mapped_column(nullable=True)
    strategy_id: Mapped[str] = mapped_column(nullable=False)
    campaign_id: Mapped[str | None] = mapped_column(nullable=True)
    attestation_id: Mapped[str] = mapped_column(nullable=False)
    outcome: Mapped[str] = mapped_column(nullable=False)
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
        CheckConstraint("outcome IN ('pass', 'fail')", name="ck_lineage_productivity_outcome"),
        ForeignKeyConstraint(
            ["tenant_id", "proposal_id"],
            ["proposal_records.tenant_id", "proposal_records.proposal_id"],
            name="fk_lineage_productivity_proposal",
        ),
        ForeignKeyConstraint(
            ["attestation_id"],
            ["evaluation_attestations.attestation_id"],
            name="fk_lineage_productivity_attestation",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "artifact_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_lineage_productivity_artifact",
        ),
        Index("ix_lineage_productivity_tenant_artifact", "tenant_id", "artifact_digest"),
        Index("ix_lineage_productivity_tenant_proposal", "tenant_id", "proposal_id"),
    )
