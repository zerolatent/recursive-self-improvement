"""ORM model for the tenant-policy refusal ledger (Phase 3, G6).

One append-only record of a scaffold-mutation boundary refusal. Both the
refusal's boundary and its machine-readable reason are recorded so the
four-boundary refusal matrix is queryable after the fact. Rows are
immutable — the migration installs a trigger that raises on
`UPDATE`/`DELETE`/`TRUNCATE`, the same guarantee the holdout query ledger
carries: an audit trail the application layer alone protects is an audit
trail any psql session can quietly rewrite.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, DateTime, Enum, String, func
from sqlalchemy.orm import Mapped, mapped_column

from evoruntime.core.ids import new_id
from evoruntime.db.base import Base
from evoruntime.tenancy.boundaries import RefusalBoundary


def _string_enum(enum_type: type[StrEnum], name: str) -> Enum:
    """Map a `StrEnum` to a checked VARCHAR column (non-native, like D5)."""
    return Enum(
        enum_type,
        name=name,
        native_enum=False,
        length=32,
        values_callable=lambda members: [member.value for member in members],
    )


class TenantPolicyRefusal(Base):
    """One append-only record of a refused scaffold-mutation boundary."""

    __tablename__ = "tenant_policy_refusals"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("tpr"))
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    boundary: Mapped[RefusalBoundary] = mapped_column(
        _string_enum(RefusalBoundary, "refusal_boundary"), nullable=False
    )
    reason: Mapped[str] = mapped_column(String(128), nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    actor: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


__all__ = ["TenantPolicyRefusal"]
