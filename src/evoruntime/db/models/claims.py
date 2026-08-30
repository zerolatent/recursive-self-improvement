"""ORM model for the recursive-claim decision ledger (Phase 4, H11).

One append-only record of a §12.6 claim-label decision — issued, or
refused with the reason. The refusal row is the point of the table: a
claim the evidence does not back is not merely raised as an exception and
forgotten, it is *recorded*, so the operator path's refusals are as
auditable as its issuances. Rows are immutable — the migration installs a
trigger that raises on `UPDATE`/`DELETE`/`TRUNCATE`, the same guarantee
the tenancy-refusal and holdout-query ledgers carry: an audit trail the
application layer alone protects is an audit trail any psql session can
quietly rewrite.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from evoruntime.core.ids import new_id
from evoruntime.db.base import Base


class RecursiveClaimDecision(Base):
    """One append-only claim-label decision for one tenant."""

    __tablename__ = "recursive_claim_decisions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("rcd"))
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    issued: Mapped[bool] = mapped_column(Boolean, nullable=False)
    verdict_satisfied: Mapped[bool] = mapped_column(Boolean, nullable=False)
    refusal_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    evidence_digest: Mapped[str] = mapped_column(String(96), nullable=False)
    campaign_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    generation1_release_digest: Mapped[str | None] = mapped_column(String(96), nullable=True)
    generation2_release_digest: Mapped[str | None] = mapped_column(String(96), nullable=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


__all__ = ["RecursiveClaimDecision"]
