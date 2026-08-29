"""ORM model for the graduation-decision ledger (Phase 3, G10).

One append-only record of a mutation-class graduation decision — granted
or refused. The signed canonical payload travels in ``detail`` so
``verify_graduation_decision`` can re-derive the signed bytes from the
row alone. Rows are immutable: the migration installs a trigger that
raises on ``UPDATE``/``DELETE``/``TRUNCATE``, the same guarantee the
tenant-policy refusal ledger (G6) carries — a decision trail the
application layer alone protects is a trail any psql session can
quietly rewrite.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from evoruntime.core.ids import new_id
from evoruntime.db.base import Base


class GraduationDecision(Base):
    """One append-only record of a mutation-class graduation decision."""

    __tablename__ = "graduation_decisions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("grd"))
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    class_id: Mapped[str] = mapped_column(String(128), nullable=False)
    dossier_digest: Mapped[str | None] = mapped_column(String(96), nullable=True)
    granted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    refusal_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    """The canonical signed payload (tenant included) — the bytes the
    signature covers, stored so verification needs nothing else."""
    candidate_resolved_tier: Mapped[int] = mapped_column(Integer, nullable=False)
    production_resolved_tier: Mapped[int | None] = mapped_column(Integer, nullable=True)
    signature: Mapped[bytes] = mapped_column(nullable=False)
    signer_public_key: Mapped[bytes] = mapped_column(nullable=False)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


__all__ = ["GraduationDecision"]
