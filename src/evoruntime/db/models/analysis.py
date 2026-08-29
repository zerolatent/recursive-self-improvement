"""ORM model for the `analysis_reports` table (Phase 2, F3).

One row per static-analysis verdict over a candidate, appended when the
gate runs on the PROPOSE→DEV_EVALUATE edge. This is a *new* record type,
deliberately not a new `kind` on `artifact_status_events`: that table's
CHECK constraint enumerates the six status-event kinds (nominate/reject/
revoke/expire/quarantine/supersede) and an analysis verdict is not an
artifact status — overloading the constraint would blur two different
audit streams.

Tamper evidence follows the evaluation-attestation pattern: the row
stores the verdict's content digest (`verdict_digest` over the report's
canonical JSON bytes) plus an Ed25519 detached signature over those same
bytes, so a verdict whose bytes no longer hash to their digest — or whose
signature no longer verifies — is detectable, not trusted. Append-only
for the same reason a signed record is: a verdict that could be edited
afterwards would vouch for an analysis nobody ran.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Index, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from evoruntime.db.base import Base


class AnalysisReport(Base):
    """A static-analysis verdict over one candidate, append-only and signed.

    `violations` is the serialized violation list (code, severity, path,
    detail, line per entry); `outcome` is the derived persistence verdict
    (`block` when any blocker violation is present, `pass` otherwise).
    """

    __tablename__ = "analysis_reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    report_id: Mapped[str] = mapped_column(nullable=False, unique=True)
    campaign_id: Mapped[str | None] = mapped_column(nullable=True)
    candidate_digest: Mapped[str] = mapped_column(nullable=False)
    artifact_type: Mapped[str] = mapped_column(nullable=False)
    outcome: Mapped[str] = mapped_column(nullable=False)
    violations: Mapped[list[object]] = mapped_column(JSONB, nullable=False, default=list)
    verdict_digest: Mapped[str] = mapped_column(nullable=False)
    signature: Mapped[bytes] = mapped_column(nullable=False)
    signer_public_key: Mapped[bytes] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint("outcome IN ('pass', 'block')", name="ck_analysis_reports_outcome"),
        UniqueConstraint(
            "tenant_id", "verdict_digest", name="uq_analysis_reports_tenant_verdict_digest"
        ),
        Index("ix_analysis_reports_tenant_candidate", "tenant_id", "candidate_digest"),
    )
