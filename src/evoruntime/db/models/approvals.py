"""ORM models for the approval workflow (Phase 2, F10).

Four record types back the review-board API:

- ``approval_requests`` — a tier-3/4 promotion or privileged-admission
  request awaiting review-board decisions. The row is *mutable* on
  purpose: its ``status`` is a projection of the decisions beneath it,
  not a tamper-evident record. The tamper-evident artifacts are the
  decision rows and the signed admission record minted from them.
- ``approval_decisions`` — one row per approver decision, append-only
  (mutation-forbidden trigger). The approver identity is the verified
  workload identity of the caller, never a request field.
- ``admission_records`` — the signed, read-only outcome of an admission:
  either an FR-022 privileged-plugin admission (signature produced by
  :func:`evoruntime.plugins.privileged.admit_privileged`) or a tier-3/4
  promotion attestation signed by the evaluation plane's key (tier 4 is
  G7's scaffold-class promotion kind, judged on the full evidence chain).
- ``compensation_plans`` — the F5 record type's read surface: a signed,
  append-only plan of per-artifact compensating actions (CAS or
  requires-execution) that gates promotion. F10 ships the record type
  and its read paths; the orchestrator hooks that execute plans are F5.

Append-only tables carry the shared ``evoruntime_forbid_mutation``
trigger (installed by the migration), so a decision or signed record
that could be edited after the fact would vouch for a review nobody
made.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Index, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from evoruntime.db.base import Base

#: Request kinds. A privileged-admission request targets a plugin at a
#: pinned digest (FR-022); a tier3-promotion request targets a campaign
#: candidate whose resolved tier the E4 engine computed at creation; a
#: tier4-promotion request (G7) targets a scaffold-class candidate and
#: additionally records the human_signoff / manually_initiated evidence
#: legs its admission is judged on.
REQUEST_KINDS = ("privileged_admission", "tier3_promotion", "tier4_promotion")

#: The promotion request kinds that target a campaign candidate (as
#: opposed to the plugin-targeting privileged_admission kind).
PROMOTION_REQUEST_KINDS = ("tier3_promotion", "tier4_promotion")

#: Request lifecycle. ``approved`` means two distinct verified approvals
#: are on record; ``admitted`` means the signed record has been minted.
REQUEST_STATUSES = ("pending", "approved", "rejected", "admitted")

#: Decision vocabulary. Approvals accumulate; a single rejection ends
#: the review.
DECISION_KINDS = ("approve", "reject")

#: Compensation-action execution modes (F5 record shape).
COMPENSATION_MODES = ("cas", "requires_execution")


class ApprovalRequest(Base):
    """A review-board request for a tier-3/4 promotion or privileged
    plugin admission."""

    __tablename__ = "approval_requests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    request_id: Mapped[str] = mapped_column(nullable=False, unique=True)
    kind: Mapped[str] = mapped_column(nullable=False)
    campaign_id: Mapped[str | None] = mapped_column(nullable=True)
    proposal_id: Mapped[str | None] = mapped_column(nullable=True)
    plugin_id: Mapped[str | None] = mapped_column(nullable=True)
    content_digest: Mapped[str | None] = mapped_column(nullable=True)
    privileged_role: Mapped[str | None] = mapped_column(nullable=True)
    tier: Mapped[int] = mapped_column(nullable=False)
    justification: Mapped[str] = mapped_column(nullable=False)
    requested_by: Mapped[str] = mapped_column(nullable=False)
    human_signoff: Mapped[bool] = mapped_column(nullable=False, default=False)
    """G7 tier-4 evidence leg: explicit human sign-off was recorded when
    the request was opened. Immutable after creation (the migration's
    evidence guard trigger refuses any UPDATE that touches it)."""
    manually_initiated: Mapped[bool] = mapped_column(nullable=False, default=False)
    """G7 tier-4 evidence leg: a human, not production automation, opened
    this request. Immutable after creation, like ``human_signoff``."""
    status: Mapped[str] = mapped_column(nullable=False, default="pending")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "kind IN ('privileged_admission', 'tier3_promotion', 'tier4_promotion')",
            name="ck_approval_requests_kind",
        ),
        CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'admitted')",
            name="ck_approval_requests_status",
        ),
        Index("ix_approval_requests_tenant_campaign", "tenant_id", "campaign_id"),
    )


class ApprovalDecision(Base):
    """One verified approver's decision on a request — append-only.

    ``approver`` is the caller's authenticated workload identity, taken
    from the request's principal, never from the request body: an
    approver identity a caller types into a payload is not verified.
    """

    __tablename__ = "approval_decisions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    decision_id: Mapped[str] = mapped_column(nullable=False, unique=True)
    request_id: Mapped[str] = mapped_column(nullable=False)
    decision: Mapped[str] = mapped_column(nullable=False)
    approver: Mapped[str] = mapped_column(nullable=False)
    approver_role: Mapped[str] = mapped_column(nullable=False)
    note: Mapped[str] = mapped_column(nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint("decision IN ('approve', 'reject')", name="ck_approval_decisions_decision"),
        # One decision per approver per request: a second decision by the
        # same identity cannot change the review's outcome, so it is
        # refused at the service boundary and backed by this constraint.
        UniqueConstraint(
            "tenant_id", "request_id", "approver", name="uq_approval_decisions_request_approver"
        ),
        Index("ix_approval_decisions_tenant_request", "tenant_id", "request_id"),
    )


class AdmissionRecord(Base):
    """The signed, read-only outcome of an approval flow.

    For ``privileged_admission`` the signature is the FR-022 record's
    Ed25519 detached signature (stored as raw bytes; the base64 forms
    are re-derived on read). For ``tier3_promotion`` the signature covers
    the canonical promotion body built by the approval service. Either
    way, a record whose signature no longer verifies is treated as if no
    admission happened.
    """

    __tablename__ = "admission_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    record_id: Mapped[str] = mapped_column(nullable=False, unique=True)
    request_id: Mapped[str] = mapped_column(nullable=False)
    kind: Mapped[str] = mapped_column(nullable=False)
    decision: Mapped[str] = mapped_column(nullable=False, default="admitted")
    plugin_id: Mapped[str | None] = mapped_column(nullable=True)
    content_digest: Mapped[str | None] = mapped_column(nullable=True)
    privileged_role: Mapped[str | None] = mapped_column(nullable=True)
    proposal_digest: Mapped[str | None] = mapped_column(nullable=True)
    tier: Mapped[int | None] = mapped_column(nullable=True)
    requested_by: Mapped[str] = mapped_column(nullable=False)
    request_digest: Mapped[str | None] = mapped_column(nullable=True)
    approvals: Mapped[list[object]] = mapped_column(JSONB, nullable=False, default=list)
    signature: Mapped[bytes] = mapped_column(nullable=False)
    signer_public_key: Mapped[bytes] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "kind IN ('privileged_admission', 'tier3_promotion', 'tier4_promotion')",
            name="ck_admission_records_kind",
        ),
        Index("ix_admission_records_tenant_request", "tenant_id", "request_id"),
    )


class CompensationPlan(Base):
    """A signed compensation plan (F5 record type): per-artifact
    compensating actions, each CAS or requires-execution, appended
    before promotion and consulted by the release plane."""

    __tablename__ = "compensation_plans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    plan_id: Mapped[str] = mapped_column(nullable=False, unique=True)
    campaign_id: Mapped[str | None] = mapped_column(nullable=True)
    manifest_digest: Mapped[str | None] = mapped_column(nullable=True)
    actions: Mapped[list[object]] = mapped_column(JSONB, nullable=False, default=list)
    plan_digest: Mapped[str] = mapped_column(nullable=False)
    signature: Mapped[bytes] = mapped_column(nullable=False)
    signer_public_key: Mapped[bytes] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (Index("ix_compensation_plans_tenant_campaign", "tenant_id", "campaign_id"),)
